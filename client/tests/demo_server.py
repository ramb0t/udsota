"""Helpers for the end-to-end tests against tools/linux_server's udsota_demo_server: finding the binary,
building images as its engine (fake_engine) does, running it in pipe mode, and a client transport over that
pipe that stands in for transport.Transport (can-isotp's Python ISO-TP stack instead of the kernel's)."""
import errno
import hashlib
import os
import pathlib
import queue
import random
import re
import shutil
import struct
import subprocess
import threading

import can
import isotp
import pytest
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection

from udsota import transport
from udsota.uds import Uds

ROOT = pathlib.Path(__file__).resolve().parents[2]
BINARY_NAME = "udsota_demo_server"
MASTER = bytes(range(32))                # the master the key tests use (udsota_keys.c's KAT master)
LABEL = "udsota-example"

# can-isotp parameters matching the kernel socket transport.isotp_connection() opens: 0xAA padding to DLC 8,
# the server's STmin and BS, and a send that returns once the last CF is out (so P2 starts after it).
ISOTP_PARAMS = {"tx_padding": transport.PAD, "tx_data_min_length": 8, "blocking_send": True,
                "stmin": 0, "blocksize": 0, "rx_flowcontrol_timeout": 1000, "rx_consecutive_frame_timeout": 1000}

# PipeTransport's default P2, in place of the client's 150 ms (transport.P2_S). A shared CI runner can stall the
# demo or the client's threads past 150 ms, and the late answer then fails the next request too. A test of the
# timeout path itself (a lost answer) passes p2_s=transport.P2_S.
PIPE_P2_S = 1.0


# The demo server binary: $UDSOTA_DEMO_SERVER, else build/tools/linux_server/ or the PATH; None when absent.
def find_binary():
    env = os.environ.get("UDSOTA_DEMO_SERVER")
    if env:
        return env if os.access(env, os.X_OK) else None
    built = ROOT / "build" / "tools" / "linux_server" / BINARY_NAME
    if os.access(built, os.X_OK):
        return str(built)
    return shutil.which(BINARY_NAME)


# The binary, or a pytest skip naming how to build it.
def binary_or_skip():
    path = find_binary()
    if path is None:
        pytest.skip("%s is not built: cmake -S . -B build && cmake --build build --target %s "
                    "(or set UDSOTA_DEMO_SERVER)" % (BINARY_NAME, BINARY_NAME))
    return path


# True for a clean tag, the ESP32 port's release rule ^v?[0-9]+\.[0-9]+\.[0-9]+$ (fake_engine's is_clean_tag).
def is_release(version):
    return re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", version) is not None


# An image the demo accepts, byte for byte what `udsota_demo_server --make-image` writes (unless noise: a segment
# of pseudo-random text that compresses about as well as a real app): fake_ota_build_image's
# one-segment ESP32-S3 image (esp_app_desc_t at 32, the udsota descriptor at 288, app_elf_sha256 = SHA-256 of the
# version, checksum byte, appended SHA-256) with this product, layout and IDs.
def build_image(version="v0.2.0", product="example", hw_id=1, layout=1, ids=(0x710, 0x718), payload=8192,
                release=None, noise=False):
    unpadded = 32 + payload
    padded = (unpadded + 1 + 15) & ~15
    img = bytearray(padded + 32)
    img[0], img[1], img[2], img[8], img[12], img[23] = 0xE9, 1, 2, 0xEE, 0x09, 1   # magic, 1 segment, DIO, S3
    struct.pack_into("<I", img, 4, 0x40378000)                                  # entry_addr
    struct.pack_into("<II", img, 24, 0x3C000020, payload)                       # segment 0: DROM, payload bytes
    struct.pack_into("<I", img, 32, 0xABCD5432)                                 # esp_app_desc_t magic
    v, p = version.encode(), product.encode()
    img[48:48 + len(v)] = v
    img[80:80 + len(p)] = p
    img[144:148] = b"v6.1"
    img[176:208] = hashlib.sha256(v).digest()                                   # app_elf_sha256
    flags = int(is_release(version) if release is None else release)
    struct.pack_into("<IHBBHHB", img, 288, 0x5544534F, 1, hw_id, layout, ids[0], ids[1], flags)
    rnd, i = random.Random(len(v) + payload), 320
    while i < unpadded:   # noise: repeats of earlier runs and fresh bytes, which DEFLATE shrinks about as an app's
        if not noise:
            img[i], i = (i * 7 + 13) & 0xFF, i + 1
        elif rnd.random() < 0.12 and i > 2000:
            src, n = i - rnd.randrange(8, 2000), min(rnd.randrange(4, 16), unpadded - i)
            img[i:i + n], i = img[src:src + n], i + n
        else:
            img[i], i = rnd.randrange(256), i + 1
    x = 0xEF
    for b in img[32:unpadded]:
        x ^= b
    img[padded - 1] = x
    img[padded:] = hashlib.sha256(img[:padded]).digest()
    return bytes(img)


# The app_elf_sha256 an image carries (what F1F3 answers once it runs).
def elf_sha(image):
    return image[176:208]


# One pipe line `<id>#<hex>` as a python-can message.
def parse_line(line):
    ident, _, data = line.strip().partition("#")
    return can.Message(arbitration_id=int(ident, 16), data=bytes.fromhex(data.replace(".", "")),
                       is_extended_id=len(ident) == 8)


# udsota_demo_server in pipe mode: frames in on its stdin, out on its stdout, its log in log_path. For fault
# injection, drop(msg) -> True keeps a response frame from the client (kept in dropped; release() hands one on
# later), tap(msg) sees every frame the client sends before the server does, and drop_tx(msg) -> True keeps one
# from the server (kept in dropped_tx). Every frame the server sent is kept in sent.
class DemoServer:
    # Start binary with args; the log goes to log_path.
    def __init__(self, binary, args, log_path):
        self.log_path = pathlib.Path(log_path)
        self._log = open(self.log_path, "wb")
        self.proc = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self._log, bufsize=0)
        self.rx = queue.Queue()
        self.sent, self.dropped, self.drop, self.tap = [], [], None, None
        self.dropped_tx, self.drop_tx = [], None
        self._wlock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    # Reader thread: every stdout line becomes a frame for the client, unless drop() takes it.
    def _read(self):
        for raw in self.proc.stdout:
            msg = parse_line(raw.decode())
            self.sent.append(msg)
            if self.drop is not None and self.drop(msg):
                self.dropped.append(msg)
                continue
            self.rx.put(msg)

    # Write one frame to the server, after tap() has seen it.
    def send(self, msg):
        if self.tap is not None:
            self.tap(msg)
        if self.drop_tx is not None and self.drop_tx(msg):
            self.dropped_tx.append(msg)
            return
        line = "%03X#%s\n" % (msg.arbitration_id, bytes(msg.data).hex().upper())
        with self._wlock:
            self.proc.stdin.write(line.encode())
            self.proc.stdin.flush()

    # Hand a dropped frame to the client after all, as if it had been delayed.
    def release(self, msg):
        self.rx.put(msg)

    # The next frame from the server, or None after timeout seconds.
    def recv(self, timeout=None):
        try:
            return self.rx.get(timeout=timeout)
        except queue.Empty:
            return None

    # Drop every frame not read yet (a new transport starts on a quiet bus, as a new socket does).
    def drain(self):
        while self.recv(timeout=0) is not None:
            pass

    # The server's log so far.
    def log(self):
        self._log.flush()
        return self.log_path.read_text(errors="replace")

    # Close stdin (the server stops at EOF) and wait; kill it if it lingers. Returns its exit code.
    def stop(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
                self.proc.wait()
        self._reader.join(timeout=2)
        self._log.close()
        return self.proc.returncode


# A python-can-like bus over a DemoServer, for transport.GuardedBus, the pre-flight and the pre-roll.
class PipeBus:
    # Wrap server.
    def __init__(self, server):
        self.server = server

    # Send one frame.
    def send(self, msg, timeout=None):
        self.server.send(msg)

    # Receive one frame or None after timeout seconds.
    def recv(self, timeout=None):
        return self.server.recv(timeout)

    # Nothing to close: the server outlives the transport.
    def shutdown(self):
        pass


# udsoncan's connection over can-isotp's TransportLayer, raising OSError for a failed blocking send (no FC in
# N_Bs) as the kernel socket does, so Uds.send_resending treats both alike.
class PipeIsoTpConnection(PythonIsoTpConnection):
    # Send one request; a send the peer never flow-controlled is an OSError.
    def specific_send(self, payload, timeout=None):
        try:
            PythonIsoTpConnection.specific_send(self, payload, timeout=transport.REQUEST_TIMEOUT_S)
        except isotp.BlockingSendFailure as e:
            raise OSError(errno.ECOMM, "ISO-TP send failed: %s" % e) from e


# transport.Transport over a DemoServer: the same guarded bus, pre-flight, pre-roll, second-tester monitor and
# udsoncan client config, with can-isotp's Python stack in place of the kernel ISO-TP socket.
class PipeTransport:
    # Open the transport for profile on server with client P2 p2_s (unread frames from an earlier transport are
    # dropped).
    def __init__(self, profile, server, listen_s=0.3, p2_s=PIPE_P2_S):
        server.drain()
        self.profile, self.server, self.listen_s, self.p2_s = profile, server, listen_s, p2_s
        self.raw = transport.GuardedBus(PipeBus(server), profile)
        self.monitor = transport.SecondTesterMonitor(profile.resp_id)
        self.layer = self.client = None

    # Listen (briefly: the pipe carries no other node), stop on another tester, pre-roll a quiet bus.
    def preflight(self):
        return transport.preflight(self.raw, self.profile, listen_s=self.listen_s)

    # The profile's pre-roll on the raw bus.
    def preroll(self):
        transport.send_preroll(self.raw, self.profile)

    # can-isotp rxfn: the next response frame, shown to the second-tester monitor first.
    def _rxfn(self, timeout):
        m = self.raw.recv(timeout)
        if m is None:
            return None
        self.monitor.on_frame(m)
        return isotp.CanMessage(arbitration_id=m.arbitration_id, dlc=len(m.data), data=bytes(m.data),
                                extended_id=m.is_extended_id)

    # can-isotp txfn: through the guarded bus, so only the request ID can go out.
    def _txfn(self, msg):
        self.raw.send(can.Message(arbitration_id=msg.arbitration_id, data=bytes(msg.data),
                                  is_extended_id=msg.is_extended_id))

    # Start the ISO-TP stack and open the UDS client on it.
    def uds(self):
        self.layer = isotp.TransportLayer(rxfn=self._rxfn, txfn=self._txfn,
                                          address=transport.isotp_address(self.profile), params=ISOTP_PARAMS)
        conn = transport.GuardedConnection(PipeIsoTpConnection(self.layer), self.monitor)
        self.client = Client(conn, config=dict(transport.client_config(), p2_timeout=self.p2_s))
        self.client.open()
        return Uds(self.client)

    # Enter the with-block.
    def __enter__(self):
        return self

    # Close the client (which stops the ISO-TP stack's thread).
    def __exit__(self, *exc):
        if self.client is not None:
            self.client.close()
