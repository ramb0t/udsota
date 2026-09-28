"""End-to-end over a virtual CAN bus: the real `udsota` command (SocketCAN, the kernel's ISO-TP socket) flashes
tools/linux_server's udsota_demo_server on vcan0 (or $UDSOTA_VCAN). Skipped unless the demo is built, the
interface exists and the kernel serves CAN_ISOTP sockets; CI's e2e job sets both up. $UDSOTA_VCAN must name a
vcan interface (vcan0, vcan1, ...): the test never drives a real bus."""
import os
import signal
import socket
import subprocess
import sys
import time

import pytest

from .demo_server import LABEL, MASTER, ROOT, binary_or_skip, build_image

IFACE = os.environ.get("UDSOTA_VCAN", "vcan0")
CLI_TIMEOUT_S = 240


# The demo binary, or a skip naming what is missing: a vcan name, the interface or the kernel's ISO-TP module.
def vcan_or_skip():
    if not IFACE.startswith("vcan"):
        pytest.skip("UDSOTA_VCAN=%s is not a vcan interface name; this test only runs on vcan" % IFACE)
    binary = binary_or_skip()
    if not os.path.exists("/sys/class/net/%s" % IFACE):
        pytest.skip("no %s: modprobe vcan && ip link add dev %s type vcan && ip link set up %s" % (IFACE, IFACE, IFACE))
    try:
        socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, socket.CAN_ISOTP).close()
    except (OSError, AttributeError) as e:
        pytest.skip("no kernel ISO-TP (modprobe can-isotp): %s" % e)
    return binary


# Starts the demo on the interface (fresh temporary slots) and stops it with SIGTERM after the test.
@pytest.fixture
def vcan_demo(tmp_path):
    binary = vcan_or_skip()
    procs = []

    def start(*args):
        log = tmp_path / ("demo%d.log" % len(procs))
        p = subprocess.Popen([binary, "--socketcan", IFACE, *args], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=open(log, "wb"))
        procs.append(p)
        deadline = time.monotonic() + 5
        while "boot 1:" not in log.read_text() and time.monotonic() < deadline:
            assert p.poll() is None, log.read_text()
            time.sleep(0.05)
        p.log = log
        return p

    yield start
    for p in procs:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


# Runs `python -m udsota args...` on this checkout's client; returns the completed process.
def udsota(*args):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "client"))
    return subprocess.run([sys.executable, "-m", "udsota", *args], env=env, capture_output=True, text=True,
                          timeout=CLI_TIMEOUT_S)


# Check `udsota --profile example --interface vcan0 flash` runs the whole update against the demo, `info` then
# reads the new version, and a second flash is a no-op.
def test_cli_flash_over_vcan(vcan_demo, tmp_path):
    demo = vcan_demo()
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    r = udsota("--profile", "example", "--interface", IFACE, "flash", str(image))
    assert r.returncode == 0, r.stdout + r.stderr + demo.log.read_text()
    assert "confirmed: running slot 1 VALID" in r.stdout
    r = udsota("--profile", "example", "--interface", IFACE, "info")
    assert r.returncode == 0 and "F189 version: v0.2.0" in r.stdout, r.stdout + r.stderr
    r = udsota("--profile", "example", "--interface", IFACE, "flash", str(image))
    assert r.returncode == 0 and "already runs this image" in r.stdout, r.stdout + r.stderr


# Check the keyed update over vcan: the client's key for the demo's label, master and device ID unlocks.
def test_cli_flash_with_security_over_vcan(vcan_demo, tmp_path):
    master = tmp_path / "master.bin"
    master.write_bytes(MASTER)
    demo = vcan_demo("--label", LABEL, "--master", str(master), "--skip-boot-delay")
    prof = tmp_path / "secured.toml"
    prof.write_text('[can]\nreq_id = 0x710\nresp_id = 0x718\n\n[security]\nlabel = "%s"\nmaster_file = "%s"\n\n'
                    '[image]\nproduct = "example"\nhw_ids = [1]\nlayout_id = 1\n' % (LABEL, master))
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    r = udsota("--profile", str(prof), "--interface", IFACE, "flash", str(image))
    assert r.returncode == 0, r.stdout + r.stderr + demo.log.read_text()
