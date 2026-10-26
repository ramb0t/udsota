"""End-to-end over a virtual CAN bus: udsota_lite_server runs on vcan0 (or $UDSOTA_VCAN) through its CAN_RAW socket
(--can), and the client flashes it two ways: over can-isotp's Python ISO-TP stack on a python-can SocketCAN bus, which
needs only the vcan module (CI's e2e job runs this on GitHub's hosted runners), and as the real `udsota` command over
the kernel's ISO-TP socket, which also needs can-isotp; a delta download goes the first way too, against a server built
with -DUDSOTA_DELTA=ON. Each skips when what it needs is missing, except that a missing vcan, server or delta build
fails instead when $UDSOTA_VCAN is set, as CI sets it, so a broken setup cannot pass as skips. $UDSOTA_VCAN must name a
vcan interface (vcan0, vcan1, ...), and the server refuses any other, as a test checks on lo: the tests never drive a
real bus. The server is $UDSOTA_LITE_SERVER or build/udsota_lite_server, as for test_e2e_lite.py, built where
linux/can/raw.h is."""
import importlib.util
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time

import can
import pytest

from udsota import update

from .demo_server import (EXAMPLE, LABEL, MASTER, SECURED, build_image, delta_pair, elf_sha, image_file, read_state,
                          run_cli, serves_delta)

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILT = ROOT / "build" / "udsota_lite_server"
IFACE = os.environ.get("UDSOTA_VCAN", "vcan0")
IFACE_REQUIRED = "UDSOTA_VCAN" in os.environ   # set (as in CI): a missing vcan or server fails
CLI_TIMEOUT_S = 240
VALID = 3                                      # F1F0 running_state


# A skip naming what is missing, or a failure when IFACE_REQUIRED.
def missing(reason):
    if IFACE_REQUIRED:
        pytest.fail("UDSOTA_VCAN is set but " + reason, pytrace=False)
    pytest.skip(reason)


# The server binary, or a skip when it is not built (a failure when IFACE_REQUIRED, or when $UDSOTA_LITE_SERVER
# names no executable).
def server_or_skip():
    binary = os.environ.get("UDSOTA_LITE_SERVER")
    if binary and not os.access(binary, os.X_OK):
        pytest.fail("UDSOTA_LITE_SERVER=%s is not an executable file" % binary)
    if not binary:
        if not os.access(BUILT, os.X_OK):
            missing("udsota_lite_server is not built: cmake -S . -B build && cmake --build build --target "
                    "udsota_lite_server (or set UDSOTA_LITE_SERVER)")
        binary = str(BUILT)
    return binary


# The server binary, or a skip (a failure when IFACE_REQUIRED, or when $UDSOTA_LITE_SERVER names no executable)
# naming what is missing: a vcan name, the server or the interface.
def vcan_or_skip():
    if not IFACE.startswith("vcan"):
        missing("UDSOTA_VCAN=%s is not a vcan interface name; this test only runs on vcan" % IFACE)
    binary = server_or_skip()
    if not os.path.exists("/sys/class/net/%s" % IFACE):
        missing("no %s: modprobe vcan && ip link add dev %s type vcan && ip link set up %s" % (IFACE, IFACE, IFACE))
    return binary


# A skip unless the kernel serves CAN_ISOTP sockets, which the `udsota` command needs.
def kernel_isotp_or_skip():
    try:
        socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, socket.CAN_ISOTP).close()
    except (OSError, AttributeError) as e:
        pytest.skip("no kernel ISO-TP (modprobe can-isotp): %s" % e)


# The vcan interface as a DemoServer-like frame source for PipeTransport: a python-can SocketCAN bus that hears
# only the response ID. PipeTransport then runs the client's guarded bus, pre-flight, monitor and Uds layer over
# can-isotp's Python stack on it, as over the pipe, but through real CAN_RAW sockets and the server's.
class VcanLink:
    # Open a raw socket on the interface, filtered to resp_id.
    def __init__(self, resp_id):
        self.bus = can.Bus(interface="socketcan", channel=IFACE,
                           can_filters=[{"can_id": resp_id, "can_mask": 0x7FF, "extended": False}])

    # Send one frame.
    def send(self, msg):
        self.bus.send(msg)

    # Receive one frame or None after timeout seconds.
    def recv(self, timeout=None):
        return self.bus.recv(timeout)

    # Drop every frame not read yet.
    def drain(self):
        while self.bus.recv(0) is not None:
            pass

    # Close the socket.
    def close(self):
        self.bus.shutdown()


# A VcanLink for the example profile's response ID, closed after the test.
@pytest.fixture
def link():
    vcan_or_skip()
    lk = VcanLink(EXAMPLE.resp_id)
    yield lk
    lk.close()


# Starts servers on the interface, each with slot 0 running v0.1.0 (or image), and returns once each is past
# iso14229's 1 s 0x27 delay after boot, so that no unlock waits out a 0x37. After the test each is stopped with
# SIGTERM and must exit 0, so a sanitizer report fails the test.
@pytest.fixture
def vcan_lite(tmp_path):
    binary = vcan_or_skip()
    procs = []

    def start(*args, image=None):
        n = len(procs)
        log = tmp_path / ("server%d.log" % n)
        image = image_file(tmp_path, build_image("v0.1.0") if image is None else image, "running%d.bin" % n)
        with open(log, "wb") as err:                      # the child keeps its own descriptor
            p = subprocess.Popen([binary, "--image", image, "--can", IFACE, *args], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=err)
        procs.append(p)
        deadline = time.monotonic() + 5
        while "boot 1:" not in log.read_text() and time.monotonic() < deadline:
            assert p.poll() is None, log.read_text()
            time.sleep(0.05)
        time.sleep(1.1)
        p.log = log
        return p

    yield start
    for p in procs:
        p.send_signal(signal.SIGTERM)
        try:
            assert p.wait(timeout=5) == 0, p.log.read_text()
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            pytest.fail("udsota_lite_server ignored SIGTERM: " + p.log.read_text())


# The path of SECURED written under tmp_path, with MASTER as its master file: udsota_lite_server always has the key.
def secured(tmp_path):
    master, path = tmp_path / "master.bin", tmp_path / "secured.toml"
    master.write_bytes(MASTER)
    path.write_text(SECURED % (LABEL, master))
    return str(path)


# Runs `python -m udsota args...` on this checkout's client; returns the completed process. A run past timeout_s
# fails the test (subprocess.TimeoutExpired).
def udsota(*args, timeout_s=CLI_TIMEOUT_S):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "client"))
    return subprocess.run([sys.executable, "-m", "udsota", *args], env=env, capture_output=True, text=True,
                          timeout=timeout_s)


# Check the client's whole keyed update over vcan with the Python ISO-TP stack: the server's CAN_RAW socket, framing,
# padding and flow control on a real (virtual) bus. The new image then runs confirmed, and a second flash is a no-op.
def test_flash_over_vcan_with_python_isotp(vcan_lite, link, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.5)
    s = vcan_lite()
    image = image_file(tmp_path, build_image("v0.2.0"), "v0.2.0.bin")
    argv = ["--profile", secured(tmp_path), "--interface", IFACE, "flash", image]
    assert run_cli(link, argv) == 0, s.log.read_text()
    status, _, version = read_state(link)
    assert (status["running_slot"], status["running_state"], version) == (1, VALID, "v0.2.0")
    assert run_cli(link, argv) == 0
    assert "already runs this image" in capsys.readouterr().out


# Check a delta download over vcan with the Python ISO-TP stack: the server runs delta_pair's base, and flash
# --diff-from sends DFI 0x30, a patch of a few hundred bytes, from which the server rebuilds the new image, which then
# runs confirmed. Needs detools and a server built with -DUDSOTA_DELTA=ON (else a skip, or a failure when
# UDSOTA_VCAN is set).
def test_flash_delta_over_vcan(vcan_lite, link, tmp_path, monkeypatch, capsys):
    if importlib.util.find_spec("detools") is None:
        missing('flash --diff-from needs detools: pip install "./client[diff]"')
    if not serves_delta(server_or_skip(), tmp_path):
        missing("udsota_lite_server serves no delta downloads: build it with cmake -DUDSOTA_DELTA=ON")
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.5)
    base, new = delta_pair(payload=48 * 1024)
    s = vcan_lite(image=base)
    base_path, new_path = image_file(tmp_path, base, "base.bin"), image_file(tmp_path, new, "new.bin")
    argv = ["--profile", secured(tmp_path), "--interface", IFACE, "flash", new_path, "--diff-from", base_path]
    assert run_cli(link, argv) == 0, s.log.read_text()
    out = capsys.readouterr().out
    assert "delta, DFI 0x30" in out and "delta bytes in" in out and "confirmed" in out
    assert "not running the base" not in out                 # no fallback to the full image
    status, sha, version = read_state(link)
    assert (status["running_slot"], status["running_state"], version, sha) == (1, VALID, "v0.3.0", elf_sha(new))


# Check the server refuses --can on an interface that is not a vcan, here lo, before it opens a socket: it exits 2
# naming the refusal, which a failed bind on lo would not print. Needs no vcan.
def test_server_refuses_an_interface_that_is_not_a_vcan(tmp_path):
    binary = server_or_skip()
    image = image_file(tmp_path, build_image("v0.1.0"), "running.bin")
    r = subprocess.run([binary, "--image", image, "--can", "lo"], stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=10)
    if "built without SocketCAN" in r.stderr:
        pytest.skip("udsota_lite_server was built without SocketCAN")
    assert r.returncode == 2 and "lo is not a vcan interface" in r.stderr, r.stderr


# Check `udsota --profile secured.toml --interface vcan0 flash` runs the whole keyed update against the server,
# `info` then reads the new version, and a second flash is a no-op.
def test_cli_flash_over_vcan(vcan_lite, tmp_path):
    kernel_isotp_or_skip()
    s = vcan_lite()
    prof = secured(tmp_path)
    image = image_file(tmp_path, build_image("v0.2.0"), "v0.2.0.bin")
    r = udsota("--profile", prof, "--interface", IFACE, "flash", image)
    assert r.returncode == 0, r.stdout + r.stderr + s.log.read_text()
    assert "confirmed: running slot 1 VALID" in r.stdout
    r = udsota("--profile", prof, "--interface", IFACE, "info")
    assert r.returncode == 0 and "F189 version: v0.2.0" in r.stdout, r.stdout + r.stderr
    r = udsota("--profile", prof, "--interface", IFACE, "flash", image)
    assert r.returncode == 0 and "already runs this image" in r.stdout, r.stdout + r.stderr


# Check one FC lost on the bus is resent by the kernel stack's N_Bs error and the update completes over the socket.
def test_cli_flash_resends_after_a_lost_flow_control(vcan_lite, tmp_path):
    kernel_isotp_or_skip()
    s = vcan_lite("--drop-fc-after", "64")
    image = image_file(tmp_path, build_image("v0.2.0"), "v0.2.0.bin")
    r = udsota("--profile", secured(tmp_path), "--interface", IFACE, "flash", image, timeout_s=60)
    assert r.returncode == 0, r.stdout + r.stderr + s.log.read_text()
    assert "--drop-fc-after: losing the FC" in s.log.read_text()
