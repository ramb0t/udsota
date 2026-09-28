"""End-to-end over a virtual CAN bus: tools/linux_server's udsota_demo_server runs on vcan0 (or $UDSOTA_VCAN)
through its SocketCAN backend, and the client flashes it two ways:
- over can-isotp's Python ISO-TP stack on a python-can SocketCAN bus, which needs only the vcan module (CI's e2e
  job runs these on GitHub's hosted runners, whose kernel has no ISO-TP module);
- as the real `udsota` command over the kernel's ISO-TP socket, which also needs can-isotp (a local Linux box).
Each skips when what it needs is missing, except that the Python-stack tests fail instead when $UDSOTA_VCAN is set,
as CI sets it, so a broken setup cannot pass as skips. $UDSOTA_VCAN must name a vcan interface (vcan0, vcan1,
...): the tests never drive a real bus."""
import os
import signal
import socket
import subprocess
import sys
import time

import can
import pytest

from udsota import cli, profile, wire

from .demo_server import LABEL, MASTER, ROOT, PipeTransport, binary_or_skip, build_image

IFACE = os.environ.get("UDSOTA_VCAN", "vcan0")
CLI_TIMEOUT_S = 240


IFACE_REQUIRED = "UDSOTA_VCAN" in os.environ   # set (as in CI): a missing vcan, demo or python-can fails


# A skip naming what is missing, or a failure when IFACE_REQUIRED.
def missing(reason):
    if IFACE_REQUIRED:
        pytest.fail("UDSOTA_VCAN is set but " + reason, pytrace=False)
    pytest.skip(reason)


# The demo binary, or a skip (a failure when IFACE_REQUIRED) naming what is missing: a vcan name, the demo or the
# interface.
def vcan_or_skip():
    if not IFACE.startswith("vcan"):
        missing("UDSOTA_VCAN=%s is not a vcan interface name; this test only runs on vcan" % IFACE)
    try:
        binary = binary_or_skip()
    except pytest.skip.Exception as e:
        reason = str(e)
    else:
        reason = None
    if reason is not None:
        missing(reason)
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
# can-isotp's Python stack on it, as over the pipe, but through real CAN_RAW sockets and the demo's SocketCAN side.
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
    lk = VcanLink(profile.load("example").resp_id)
    yield lk
    lk.close()


# Runs cli.main over link (the Python ISO-TP stack on vcan) and returns its exit code.
def run_cli(link, argv):
    return cli.main(argv, transport=lambda prof, interface: PipeTransport(prof, link))


# Reads F1F0 and F189 over link.
def read_state(link):
    with PipeTransport(profile.load("example"), link) as t:
        uds = t.uds()
        return wire.decode_status(uds.read_did(wire.DID_STATUS)), wire.cstr(uds.read_did(wire.DID_VERSION))


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


# Runs `python -m udsota args...` on this checkout's client; returns the completed process. A run past timeout_s
# fails the test (subprocess.TimeoutExpired).
def udsota(*args, timeout_s=CLI_TIMEOUT_S):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "client"))
    return subprocess.run([sys.executable, "-m", "udsota", *args], env=env, capture_output=True, text=True,
                          timeout=timeout_s)


# Check the client's whole update over vcan with the Python ISO-TP stack: the demo's SocketCAN backend, CAN_RAW
# framing, padding and flow control on a real (virtual) bus. The new image then runs confirmed, and a second
# flash is a no-op.
def test_flash_over_vcan_with_python_isotp(vcan_demo, link, tmp_path):
    demo = vcan_demo()
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    argv = ["--profile", "example", "--interface", IFACE, "flash", str(image)]
    assert run_cli(link, argv) == 0, demo.log.read_text()
    status, version = read_state(link)
    assert (status["running_slot"], status["running_state"], version) == (1, 3, "v0.2.0")
    assert run_cli(link, argv) == 0


# Check the keyed update over vcan with the Python ISO-TP stack: the key for the demo's label, master and device
# ID unlocks.
def test_flash_with_security_over_vcan_with_python_isotp(vcan_demo, link, tmp_path):
    master = tmp_path / "master.bin"
    master.write_bytes(MASTER)
    demo = vcan_demo("--label", LABEL, "--master", str(master), "--skip-boot-delay")
    prof = tmp_path / "secured.toml"
    prof.write_text('[can]\nreq_id = 0x710\nresp_id = 0x718\n\n[security]\nlabel = "%s"\nmaster_file = "%s"\n\n'
                    '[image]\nproduct = "example"\nhw_ids = [1]\nlayout_id = 1\n' % (LABEL, master))
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    assert run_cli(link, ["--profile", str(prof), "--interface", IFACE, "flash", str(image)]) == 0, \
        demo.log.read_text()


# Check `udsota --profile example --interface vcan0 flash` runs the whole update against the demo, `info` then
# reads the new version, and a second flash is a no-op.
def test_cli_flash_over_vcan(vcan_demo, tmp_path):
    kernel_isotp_or_skip()
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
    kernel_isotp_or_skip()
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


# Check a server that withholds the FC after the first block of CFs of block 1, then ignores the resent FF (the
# refused-download hang): the `udsota` command exits 1 within seconds, naming the block and F1F1's DL_ABORTED. The
# hang itself is a thread race this run rarely hits; test_rx_thread_wakeup_without_data_does_not_block_close forces it.
def test_cli_flash_exits_1_when_the_server_withholds_flow_control(vcan_demo, tmp_path):
    kernel_isotp_or_skip()
    demo = vcan_demo("--withhold-fc-after", "64")
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    t0 = time.monotonic()
    r = udsota("--profile", "example", "--interface", IFACE, "flash", str(image), timeout_s=30)
    assert r.returncode == 1 and time.monotonic() - t0 < 15.0, r.stdout + r.stderr + demo.log.read_text()
    assert "block 1:" in r.stderr and "F1F1 reads DL_ABORTED" in r.stderr, r.stderr


# Check one FC lost on the bus is resent by the kernel stack's N_Bs error and the update completes over the socket.
def test_cli_flash_resends_after_a_lost_flow_control(vcan_demo, tmp_path):
    kernel_isotp_or_skip()
    demo = vcan_demo("--drop-fc-after", "64")
    image = tmp_path / "v0.2.0.bin"
    image.write_bytes(build_image("v0.2.0"))
    r = udsota("--profile", "example", "--interface", IFACE, "flash", str(image), timeout_s=60)
    assert r.returncode == 0, r.stdout + r.stderr + demo.log.read_text()
    assert "--drop-fc-after: losing the FC" in demo.log.read_text()
