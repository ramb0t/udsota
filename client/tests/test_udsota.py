"""Tests for the udsota client: key vectors, the update sequence against a scripted server, the pre-flight
guard and pre-roll, the TX-ID hard limit, profiles, and a run with a minimal profile. No kernel ISO-TP socket
and no vcan: the UDS layer runs over a stub udsoncan connection, the pre-flight over python-can virtual buses.
Most tests run with FULL (P), a profile that turns every optional feature on."""
import errno
import hashlib
import os
import pathlib
import re
import socket
import stat
import struct
import threading
import time
import tomllib
from collections import deque

import can
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from udsoncan.client import Client
from udsoncan.connections import BaseConnection, IsoTPSocketConnection
from udsoncan.exceptions import TimeoutException

from udsota import cli, errors, keys, profile, transport, update, wire
from udsota.image import parse_image
from udsota.uds import BUSY_BACKOFF_S, KEEPALIVE_S, SA_DELAY_S, Uds

# Every optional table on, with the example IDs, label, product and board; a deny list and three boards so
# the deny-list and board checks have something to refuse.
FULL = """
[can]
interface = "vcan0"
req_id = 0x710
resp_id = 0x718
deny_tx = [0x7DF, 0x7E0, 0x7E8, 0x123]

[security]
label = "udsota-example"
master_file = "master.bin"
device_id_did = 0xF18C

[image]
product = "example"
hw_ids = [1, 2, 3]
layout_id = 1

[board]
did = 0xF191
names = { 1 = "devkit", 2 = "devkit-two", 3 = "devkit-three" }

[busy]
id = 0x100
byte = 1
values = [2, 3]

[preroll]
tester_present_frames = 5

[dids]
"0xF191" = { name = "board", decode = "ascii" }
"0xF1B1" = { name = "api version", decode = "version3" }
"0xF1B0" = { name = "serial", decode = "hex" }
"0x0200-0x02FF" = { name = "calibration", decode = "hex" }
"""
P = profile.from_dict("full", tomllib.loads(FULL))
BUSY_ID = 0x100
# FULL with [security] in the ecdsa mode, and a tester key pair made for this run (FakeServer holds the public half).
FULL_ECDSA = FULL.replace('label = "udsota-example"\nmaster_file = "master.bin"\n',
                          'mode = "ecdsa"\nprivate_key_file = "udsota_private.pem"\n')
PE = profile.from_dict("full-ecdsa", tomllib.loads(FULL_ECDSA))
TESTER_KEY = ec.generate_private_key(ec.SECP256R1())
TESTER_PUB = TESTER_KEY.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)


# Another node on a virtual channel: sends msg every 20 ms from a thread until stop is set.
def chatter(channel, msg, stop):
    tx = can.Bus(interface="virtual", channel=channel)
    while not stop.wait(0.02):
        tx.send(msg)
    tx.shutdown()


MASTER = bytes(range(32))                      # master 0..31: the udsota-example vectors below and udsota_keys.c's KAT
MAC = bytes.fromhex("020000000001")
SEED = bytes(range(0x10, 0x20))
KEYS = {0x01: bytes.fromhex("5de67156ccb30a17846a4cac31c9db8f"),
        0x03: bytes.fromhex("b2344840011fcfaca2e74724e9c6ef0c")}
OLD_SHA = bytes([0x11]) * 32
NEW_SHA = bytes(range(0xA0, 0xC0))
STATUS_FIXTURE = bytes([0x01, 0x02, 0x01, 0x03, 0x00, 0x02, 0x07,
                    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0x05])


# The ecdsa mode's known answers, pinned in udsota_keys.c (KAT_SIG_*) and test/test_udsota_keys.c too: the
# message for SEED, level 0x03 and MAC, its SHA-256, and the test key (private scalar 01 02 .. 20) with its
# signature over that message.
SIG_MSG_L3 = bytes.fromhex("7564736f74612d32372d65636473612d7631101112131415161718191a1b1c1d1e1f0306020000000001")
SIG_DIGEST_L3 = "af914ba6ad030d8ac102fe70ba98255a9e50ad7c45373941db3d4aaac246b4ce"
KAT_SCALAR = int.from_bytes(bytes(range(1, 33)), "big")
KAT_PUB = bytes.fromhex("04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
                        "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354")
KAT_SIG_L3 = bytes.fromhex("34435c645a77fbc22fc53e78ec4f579c9c794563d939912466bbea9a74287c1f"
                           "e332925181f319e2fab67568815c93c4751d8223ec8ca3359e6815bc2f65d5a8")


# True when sig (r || s) is a valid P-256 ECDSA signature over SHA-256(msg) under the 65-byte point pub, as the
# device's PSA verify decides.
def ecdsa_valid(pub, sig, msg):
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(pub))
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        key.verify(der, bytes(msg), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# A synthetic signed-image prefix: 0xE9 header, esp_app_desc_t at 32, udsota_image_desc_t at 288.
def make_image(size=4800, hw_id=1, project=b"example", sha=NEW_SHA, desc_magic=0x5544534F,
               ids=(0x710, 0x718), app_magic=0xABCD5432, first=0xE9, layout=1):
    img = bytearray(i & 0xFF for i in range(size))
    img[0] = first
    struct.pack_into("<I", img, 32, app_magic)
    img[48:80] = b"0.3.0".ljust(32, b"\0")
    img[80:112] = project.ljust(32, b"\0")
    img[176:208] = sha
    struct.pack_into("<IHBBHH", img, 288, desc_magic, 1, hw_id, layout, *ids)
    img[300:320] = bytes(20)
    return bytes(img)


# Deterministic time: sleep() advances clock() and is recorded.
class FakeTime:
    # Start at t = 0.
    def __init__(self):
        self.t, self.sleeps = 0.0, []

    # Current fake time in seconds.
    def clock(self):
        return self.t

    # Record s and advance the clock by it.
    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


# UDS-payload stand-in for a udsota server (components/udsota/udsota_server.c):
# answers the update sequence and logs (sid, sub-function / DID / RID / block counter) per request. It
# models S3 (5 s without a request drops to the default session and relocks), refuses the keyed
# services outside their sessions, and keeps the server's download state: 0x37 closes the transfer,
# FF01 verifies it once (a repeat after a pass answers 00), F001 needs a verified slot (else 0x24),
# and 10 02 is refused (0x22) while the boot slot is not the running one.
class FakeServer:
    # Knobs select the faults and states each test needs.
    def __init__(self, max_block=18, boot_silence=2, confirm_refusals=2, running_state=3, sha=OLD_SHA,
                 board=b"devkit", other_state=0, other_sha=bytes(32), lose_76_once=None, mute_block=None,
                 nrc_once=None, activate_refusals=0, ff01_status=0, config=None, lose_77_once=False,
                 lose_ff01_once=False, activate_nrcs=None, activate_fail=None, no_fc=None, security=True,
                 pubkey=None):
        self.max_block, self.boot_silence, self.confirm_refusals = max_block, boot_silence, confirm_refusals
        self.running_state, self.sha, self.board = running_state, sha, board
        self.other_state, self.other_sha = other_state, other_sha
        self.lose_76_once, self.mute_block = lose_76_once, mute_block
        self.nrc_once = dict(nrc_once or {})
        self.ff01_status = ff01_status
        self.activate_nrcs = list(activate_nrcs or []) + [0x22] * activate_refusals
        self.activate_fail = activate_fail      # None, "set_boot" (landed, 90 s cap ended the session) or "clean"
        self.lose_77_once, self.lose_ff01_once = lose_77_once, lose_ff01_once
        self.no_fc = dict(no_fc or {})          # {(sid, arg): n}: the next n sends get no FC (kernel ECOMM)
        self.config = {} if config is None else config
        self.security = security
        self.pubkey = pubkey                    # a P-256 public key: the ecdsa mode, 64-byte signed keys
        self.log, self.written, self.writes = [], bytearray(), 0
        self.silence, self.announced, self.next_bsc, self.last_bsc = 0, None, 1, None
        self.session, self.unlocked, self.last_t, self.clock = 1, 0, 0.0, lambda: 0.0
        self.dl_open, self.dl_complete, self.verified = False, False, other_state == 3
        self.last_dl = (0, 0)                   # F1F1: (reason, bytes received)
        self.boot_pending = None                # the sha set_boot selected, until the restart

    # Answer one request payload with a list of response payloads ([] = no answer).
    def handle(self, req):
        sid = req[0]
        arg = {0x10: lambda: req[1], 0x11: lambda: req[1], 0x27: lambda: req[1], 0x36: lambda: req[1],
               0x3E: lambda: req[1], 0x22: lambda: int.from_bytes(req[1:3], "big"),
               0x31: lambda: int.from_bytes(req[2:4], "big")}.get(sid, lambda: None)()
        if self.no_fc.get((sid, arg)):
            self.no_fc[(sid, arg)] -= 1         # FF seen, FC dropped: the request never arrives
            raise OSError(errno.ECOMM, os.strerror(errno.ECOMM))
        self.log.append((sid, arg))
        now = self.clock()
        if self.session != 1 and now - self.last_t > 5.0:
            self.session, self.unlocked = 1, 0          # S3 expired
        self.last_t = now
        if self.silence:
            self.silence -= 1
            return []
        if (sid, arg) in self.nrc_once:
            return self.nrc(sid, self.nrc_once.pop((sid, arg)))
        if self.session == 1 and sid in (0x11, 0x27, 0x31, 0x34, 0x36, 0x37):
            return self.nrc(sid, 0x7F)                  # serviceNotSupportedInActiveSession
        if self.security and sid in (0x34, 0x36, 0x37) and self.unlocked != 3:
            return self.nrc(sid, 0x33)
        return getattr(self, "s%02x" % sid)(req, arg)

    # Negative response helper.
    @staticmethod
    def nrc(sid, code):
        return [bytes([0x7F, sid, code])]

    # The restart after F001 or 11 01: boots the image set_boot selected, if any, as PENDING_VERIFY.
    def restart(self):
        if self.boot_pending is not None:
            self.sha, self.running_state, self.boot_pending = self.boot_pending, 2, None
        self.silence = self.boot_silence
        self.session, self.unlocked, self.verified, self.dl_open, self.dl_complete = 1, 0, False, False, False

    # 0x10 DiagnosticSessionControl: 50 ss 00 32 01 F4; every session change relocks. 10 02 is
    # refused (0x22) while the boot slot is not the running one, as slots_settled() does.
    def s10(self, req, sub):
        if sub == 2 and self.boot_pending is not None:
            return self.nrc(0x10, 0x22)
        self.session, self.unlocked = sub, 0
        return [bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])]

    # 0x3E TesterPresent: 7E 00 (keeps S3 alive through handle()).
    def s3e(self, req, sub):
        return [bytes([0x7E, sub])]

    # 0x22 ReadDataByIdentifier; F1F0's boot slot moves (1 -> 0) once set_boot lands, and F1F1 is the last
    # download's reason and bytes received.
    def s22(self, req, did):
        boot_slot = 0 if self.boot_pending is not None else 1
        status = (bytes([1, self.running_state, boot_slot, self.other_state, 0, 3, 0]) + self.other_sha[:8]
                + bytes([1]))
        result = bytes([self.last_dl[0]]) + self.last_dl[1].to_bytes(4, "big")
        records = {0xF186: b"\x01", 0xF189: b"v0.2.9-3-gabc", 0xF18C: MAC, 0xF191: self.board,
                   0xF1B0: bytes(32), 0xF1F0: status, 0xF1B1: b"\x01\x02\x03", 0xF1F3: self.sha,
                   0xF1F1: result, 0xF1F2: bytes(16), **self.config}
        if did not in records:
            return self.nrc(0x22, 0x31)
        return [b"\x62" + did.to_bytes(2, "big") + records[did]]

    # 0x27 SecurityAccess: fixed seed; the key must match the udsota-example vector (KEYS) for the level, or with
    # a pubkey be exactly a 64-byte signature under it over the seed, level and MAC (the ecdsa mode).
    def s27(self, req, sub):
        if not self.security:
            return self.nrc(0x27, 0x11)
        if sub & 1:
            return [bytes([0x67, sub]) + SEED]
        if self.pubkey is not None:
            if len(req) != 2 + keys.SIG_LEN:
                return self.nrc(0x27, 0x13)
            if not ecdsa_valid(self.pubkey, req[2:], keys.sig_message(SEED, sub - 1, MAC)):
                return self.nrc(0x27, 0x35)
        elif req[2:] != KEYS[sub - 1]:
            return self.nrc(0x27, 0x35)
        self.unlocked = sub - 1
        return [bytes([0x67, sub])]

    # 0x34 RequestDownload: DFI 00, ALFID 44, address 0; answers 74 20 <max_block> and starts a fresh
    # download, which also ends any earlier FF01 pass.
    def s34(self, req, _):
        if req[1:3] != b"\x00\x44" or req[3:7] != bytes(4):
            return self.nrc(0x34, 0x31)
        self.announced = int.from_bytes(req[7:11], "big")
        self.written, self.next_bsc, self.last_bsc = bytearray(), 1, None
        self.dl_open, self.dl_complete, self.verified, self.last_dl = True, False, False, (0, 0)
        return [b"\x74\x20" + self.max_block.to_bytes(2, "big")]

    # 0x36 TransferData: repeat of the last counter answers without writing; a wrong one gets 0x73.
    def s36(self, req, bsc):
        if not self.dl_open:
            return self.nrc(0x36, 0x24)
        if bsc == self.mute_block:
            return []
        if bsc == self.last_bsc:
            return [bytes([0x76, bsc])]
        if bsc != self.next_bsc:
            return self.nrc(0x36, 0x73)
        self.written += req[2:]
        self.writes += 1
        self.last_dl = (0, len(self.written))
        self.last_bsc, self.next_bsc = bsc, (bsc + 1) & 0xFF
        if self.writes == self.lose_76_once:
            self.lose_76_once = None
            return []
        first = [bytes([0x7F, 0x36, 0x78])] if self.writes == 1 else []   # the erase runs under 0x78
        return first + [bytes([0x76, bsc])]

    # 0x37 RequestTransferExit: an open transfer holding every announced byte closes (77), else 0x24.
    def s37(self, req, _):
        if not self.dl_open or len(self.written) != self.announced:
            return self.nrc(0x37, 0x24)
        self.dl_open, self.dl_complete = False, True
        if self.lose_77_once:
            self.lose_77_once = False
            return []
        return [b"\x77"]

    # 0x31 RoutineControl: FF01 status, ActivateImage (then a restart), ConfirmImage after refusals.
    def s31(self, req, rid):
        echo = b"\x71\x01" + rid.to_bytes(2, "big")
        if rid == 0xFF01:
            if self.verified and not self.dl_complete:
                return [echo + b"\x00"]                 # passed, no new download since: repeat 00
            if not self.dl_complete:
                return self.nrc(0x31, 0x24)
            self.dl_complete, self.verified = False, self.ff01_status == 0
            self.last_dl = (self.ff01_status, len(self.written))
            if self.lose_ff01_once:
                self.lose_ff01_once = False
                return []
            return [echo + bytes([self.ff01_status])]
        if rid == 0xF001:
            if self.activate_nrcs:
                return self.nrc(0x31, self.activate_nrcs.pop(0))
            if not self.verified:
                return self.nrc(0x31, 0x24)
            new_sha = bytes(self.written[176:208]) if self.written else self.other_sha
            fail, self.activate_fail = self.activate_fail, None
            if fail == "clean":                         # set_boot failed: the slot needs FF01 again
                self.verified = False
                return self.nrc(0x31, 0x72)
            self.boot_pending = new_sha
            if fail == "set_boot":                      # the 90 s cap: set_boot landed, no restart
                self.session, self.unlocked = 1, 0
                return self.nrc(0x31, 0x72)
            self.restart()
            return [echo]
        if rid == 0xF002:
            if self.confirm_refusals:
                self.confirm_refusals -= 1
                return self.nrc(0x31, 0x22)
            self.running_state = 3
            return [echo]
        return self.nrc(0x31, 0x31)

    # 0x11 ECUReset: keyed (either level unlocked), then the restart.
    def s11(self, req, sub):
        if self.security and not self.unlocked:
            return self.nrc(0x11, 0x33)
        self.restart()
        return [bytes([0x51, sub])]


# udsoncan connection that hands each request to a FakeServer and queues its answers.
class StubConnection(BaseConnection):
    # Wrap a FakeServer.
    def __init__(self, server):
        BaseConnection.__init__(self, "stub")
        self.server, self.queue, self.opened = server, deque(), False

    # Mark open.
    def open(self):
        self.opened = True
        return self

    # Mark closed.
    def close(self):
        self.opened = False

    # True once opened.
    def is_open(self):
        return self.opened

    # Drop queued answers.
    def empty_rxqueue(self):
        self.queue.clear()

    # Queue the server's answers to payload.
    def specific_send(self, payload, timeout=None):
        self.queue.extend(self.server.handle(bytes(payload)))

    # Next queued answer, or a timeout at once when there is none.
    def specific_wait_frame(self, timeout=None):
        if not self.queue:
            raise TimeoutException("stub: no answer")
        return self.queue.popleft()


# A Uds over a StubConnection (optionally wrapped by a GuardedConnection with monitor).
def uds_for(server, ft, monitor=None):
    server.clock = ft.clock
    conn = StubConnection(server)
    if monitor is not None:
        conn = transport.GuardedConnection(conn, monitor)
    client = Client(conn, config=transport.client_config())
    client.open()
    return Uds(client, sleep=ft.sleep)


# Run flash against server with fake time; returns (rc, fake time, pre-roll count).
def run_flash(server, image=None, prof=P, master=MASTER, **kw):
    ft, prerolls = FakeTime(), []
    rc = update.flash(uds_for(server, ft), prof, make_image() if image is None else image, master,
                  preroll=lambda: prerolls.append(1), sleep=ft.sleep, clock=ft.clock, log=lambda *a: None, **kw)
    return rc, ft, len(prerolls)


PRECHECK = [(0x22, 0xF1F0), (0x22, 0xF1F3), (0x22, 0xF191), (0x22, 0xF18C)]
UNLOCK_PROG = [(0x10, 2), (0x27, 3), (0x27, 4)]
DOWNLOAD_TAIL = [(0x37, None), (0x31, 0xFF01), (0x31, 0xF001)]
AFTER_ACTIVATE = [(0x22, 0xF1F3)] * 3 + [(0x10, 3)] + [(0x31, 0xF002)] * 3 + [(0x22, 0xF1F0)]


# Expected 0x36 log for a 4800-byte image in 16-byte blocks: 300 blocks, counter wrapping 0xFF -> 0x00.
def blocks(repeat=None):
    out = []
    for n in range(1, 301):
        out.append((0x36, n & 0xFF))
        if n == repeat:
            out.append((0x36, n & 0xFF))
    return out


# ---- keys: the udsota-example vectors and the core's KAT ----

# Check HMAC-SHA256 against RFC 4231 test case 2.
def test_hmac_rfc4231_tc2():
    assert keys.hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


# Check K_dev = HMAC(master, 'udsota-example' || MAC) for master 0..31 and MAC 02:00:00:00:00:01.
def test_k_dev_vector():
    assert keys.derive_k_dev(MASTER, P.security.label, MAC).hex() == \
        "cbe10490e36487e3ea9805288ac4bcead717aafdcefa30cd1f4668e9fa1cfa52"


# Check the level-1 and level-3 keys for seed 0x10..0x1F.
@pytest.mark.parametrize("level", [0x01, 0x03])
def test_seed_key_vectors(level):
    assert keys.seed_key(keys.derive_k_dev(MASTER, P.security.label, MAC), SEED, level, MAC) == KEYS[level]


# Check the core's known-answer test (udsota_keys.c, KAT_*): label udsota-kat, master 0..31, ID 02:00:00:00:00:01,
# seed 0x10..0x1F. The C self-test and test/test_udsota_keys.c pin the same bytes.
def test_core_kat_vectors():
    k_dev = keys.derive_k_dev(MASTER, b"udsota-kat", MAC)
    assert k_dev.hex() == "7bac00ce789369a8fb6f3ce1d1fbe7fea02cd3cdbed02a23a0a48a9d1a268757"
    dk = keys.DeviceKeys(MASTER, b"udsota-kat", MAC)
    assert dk.key(SEED, 0x01).hex() == "1532ad0243f9aa100424aa24a0d28319"
    assert dk.key(SEED, 0x03).hex() == "27e891cd8c86ac41a7882a4f81d666f3"


# Check the master loads as 32 raw bytes.
def test_load_master_reads_raw_bytes(tmp_path):
    p = tmp_path / "master.bin"
    p.write_bytes(MASTER)
    assert keys.load_master(p) == MASTER


# Check a missing file, a short one and a hex text file are refused.
@pytest.mark.parametrize("content", [None, b"\x01" * 16, (MASTER.hex() + "\n").encode()])
def test_load_master_refuses_anything_else(tmp_path, content):
    p = tmp_path / "master.bin"
    if content is not None:
        p.write_bytes(content)
    with pytest.raises(errors.Refused):
        keys.load_master(p)


# ---- keys: the ecdsa mode ----

# Check the signed message and its SHA-256 against the bytes udsota_keys.c builds (test/test_udsota_keys.c pins them).
def test_sig_message_known_answer():
    m = keys.sig_message(SEED, 0x03, MAC)
    assert m == SIG_MSG_L3 and hashlib.sha256(m).hexdigest() == SIG_DIGEST_L3
    assert keys.sig_message(SEED, 0x01, MAC) == SIG_MSG_L3[:34] + b"\x01" + SIG_MSG_L3[35:]
    assert keys.sig_message(SEED, 0x03, b"") == SIG_MSG_L3[:35] + b"\x00"


# Check a seed that is not 16 bytes or a device ID over 16 bytes builds no message.
@pytest.mark.parametrize("seed,device_id", [(SEED[:15], MAC), (SEED, bytes(17))])
def test_sig_message_refuses_bad_input(seed, device_id):
    with pytest.raises(errors.UpdateFailed):
        keys.sig_message(seed, 0x03, device_id)


# Check the device's ECDSA self-test vector (udsota_keys.c KAT_SIG_*): the test scalar's public point, and a
# signature that verifies over the level-3 message and not over the level-1 one.
def test_sig_self_test_vector():
    assert keys.public_point(ec.derive_private_key(KAT_SCALAR, ec.SECP256R1())) == KAT_PUB
    assert ecdsa_valid(KAT_PUB, KAT_SIG_L3, SIG_MSG_L3)
    assert not ecdsa_valid(KAT_PUB, KAT_SIG_L3, keys.sig_message(SEED, 0x01, MAC))


# Check a signature is 64 bytes of r || s that verifies under the public point, only for its own seed, level
# and device ID, and that SigningKeys signs with the ID it was given.
def test_sign_verify_roundtrip():
    sig = keys.sign_seed(TESTER_KEY, SEED, 0x03, MAC)
    assert len(sig) == keys.SIG_LEN and ecdsa_valid(TESTER_PUB, sig, SIG_MSG_L3)
    for other in (keys.sig_message(SEED, 0x01, MAC), keys.sig_message(bytes(16), 0x03, MAC),
                  keys.sig_message(SEED, 0x03, bytes.fromhex("020000000002"))):
        assert not ecdsa_valid(TESTER_PUB, sig, other)
    sk = keys.SigningKeys(TESTER_KEY, MAC)
    assert ecdsa_valid(TESTER_PUB, sk.key(SEED, 0x01), keys.sig_message(SEED, 0x01, MAC))
    assert len(keys.public_point(TESTER_KEY)) == keys.PUBKEY_LEN and TESTER_PUB[0] == 0x04


# Check SigningKeys refuses an empty or a 17-byte device ID, as the server never reports one.
@pytest.mark.parametrize("device_id", [b"", bytes(17)])
def test_signing_keys_refuse_bad_device_ids(device_id):
    with pytest.raises(errors.UpdateFailed):
        keys.SigningKeys(TESTER_KEY, device_id)


# Check the private key loads from an unencrypted P-256 PEM, and a missing file, a raw master, an encrypted PEM
# and a P-384 key are refused.
def test_load_private_key(tmp_path):
    good = tmp_path / "good.pem"
    good.write_bytes(TESTER_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    assert keys.public_point(keys.load_private_key(good)) == TESTER_PUB
    enc = tmp_path / "enc.pem"
    enc.write_bytes(TESTER_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.BestAvailableEncryption(b"pw")))
    p384 = tmp_path / "p384.pem"
    p384.write_bytes(ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    raw = tmp_path / "master.bin"
    raw.write_bytes(MASTER)
    for path, why in ((tmp_path / "absent.pem", "cannot read"), (raw, "not a PEM"), (enc, "encrypted"),
                      (p384, "not a P-256")):
        with pytest.raises(errors.Refused, match=why):
            keys.load_private_key(path)


# Check keygen writes an owner-only PEM and a header holding its 65-byte public point, and never overwrites.
def test_keygen_writes_a_matching_pair(tmp_path):
    private, header = keys.keygen(tmp_path / "keys")
    assert (private.name, header.name) == ("udsota_private.pem", "udsota_pubkey.h")
    assert stat.S_IMODE(os.stat(private).st_mode) == 0o600
    text = header.read_text()
    assert "static const uint8_t udsota_pubkey[65] = {" in text and "never in a" in text
    point = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", text.split("{", 1)[1]))
    assert point == keys.public_point(keys.load_private_key(private))
    with pytest.raises(errors.Refused, match="never overwrites"):
        keys.keygen(tmp_path / "keys")
    private.unlink()
    with pytest.raises(errors.Refused, match="udsota_pubkey.h exists"):
        keys.keygen(tmp_path / "keys")                      # the header alone blocks a new pair too


# ---- TX-ID hard limit ----

# Check every ID but standard 0x710 is refused, and the hard-limit IDs say so.
@pytest.mark.parametrize("can_id", [0x7DF, 0x7E0, 0x123, 0x7E8, 0x718, 0x711, BUSY_ID, 0x000])
def test_check_tx_id_refuses_all_but_request_id(can_id):
    with pytest.raises(errors.Refused) as e:
        transport.check_tx_id(P, can_id)
    if can_id in (0x7DF, 0x7E0, 0x7E8, 0x123):
        assert "hard limit" in str(e.value)


# Check 0x710 passes as a standard frame and is refused as an extended one.
def test_check_tx_id_allows_only_standard_request_id():
    transport.check_tx_id(P, 0x710)
    with pytest.raises(errors.Refused):
        transport.check_tx_id(P, 0x710, extended=True)


# Check GuardedBus never forwards a frame for 0x7DF or 0x7E0 to the bus.
@pytest.mark.parametrize("can_id", [0x7DF, 0x7E0])
def test_guarded_bus_blocks_forbidden_ids(can_id):
    sent = []

    # Records every frame that reaches it; must stay empty.
    class FakeBus:
        # Record the frame.
        def send(self, m, timeout=None):
            sent.append(m)

    with pytest.raises(errors.Refused):
        transport.GuardedBus(FakeBus(), P).send(can.Message(arbitration_id=can_id, is_extended_id=False, data=bytes(8)))
    assert sent == []


FUNCTIONAL = """
[can]
req_id = 0x710
resp_id = 0x718
deny_tx = [0x7E0]

[functional]
id = 0x7DF
quiet_bus = true
"""
PF = profile.from_dict("functional", tomllib.loads(FUNCTIONAL))


# Check [functional] parses, and that its id may not be the request or response ID or a deny_tx ID.
@pytest.mark.parametrize("fid", [0x710, 0x718, 0x7E0])
def test_functional_profile(fid):
    assert (PF.func_id, PF.quiet_bus) == (0x7DF, True)
    assert (P.func_id, P.quiet_bus) == (None, False)
    with pytest.raises(errors.Refused):
        profile.from_dict("bad", tomllib.loads(FUNCTIONAL.replace("id = 0x7DF", "id = 0x%03X" % fid)))
    with pytest.raises(errors.Refused):
        profile.from_dict("bad", tomllib.loads(FUNCTIONAL.replace("quiet_bus = true", "quiet_bus = 1")))


# Check the TX guard allows the [functional] id as a standard frame only, and still nothing else.
def test_check_tx_id_allows_the_functional_id():
    transport.check_tx_id(PF, 0x7DF)
    transport.check_tx_id(PF, 0x710)
    for can_id, ext in ((0x7DF, True), (0x7E0, False), (0x718, False)):
        with pytest.raises(errors.Refused):
            transport.check_tx_id(PF, can_id, extended=ext)
    with pytest.raises(errors.Refused):
        transport.check_tx_id(P, 0x7DF)


# Records every frame the guard lets through.
class RecordingBus:
    # An empty log.
    def __init__(self):
        self.sent = []

    # Record the frame.
    def send(self, m, timeout=None):
        self.sent.append(m)


# Check QuietBus sends the quieting burst, a functional 3E 80 while held, and the release burst, all padded
# single frames on 0x7DF, and that the monitor counts each burst as a request of ours.
def test_quiet_bus_bursts_and_keepalive():
    raw = RecordingBus()
    mon = transport.SecondTesterMonitor(0x718)
    with transport.QuietBus(transport.GuardedBus(raw, PF), PF, mon, period_s=0.02, sleep=lambda s: None):
        time.sleep(0.15)
    frames = [bytes(m.data) for m in raw.sent]
    assert all(m.arbitration_id == 0x7DF and not m.is_extended_id and m.dlc == 8 for m in raw.sent)
    pad = lambda b: bytes([len(b)]) + b + bytes([0xAA] * (7 - len(b)))
    assert frames[:3] == [pad(b"\x10\x83"), pad(b"\x85\x82"), pad(b"\x28\x83\x03")]
    assert frames[-3:] == [pad(b"\x28\x80\x03"), pad(b"\x85\x81"), pad(b"\x10\x81")]
    assert len(frames) >= 8 and set(frames[3:-3]) == {pad(b"\x3E\x80")}
    assert mon.alarm is None and not mon._busy


# Check flash enters quiet() once an update is needed and holds it to the end; a no-op flash never enters it.
def test_flash_holds_quiet_for_the_update_only():
    events = []

    # Records enter and exit, and the server log length at each.
    class Quiet:
        # Record the entry.
        def __enter__(self):
            events.append(("enter", len(d.log)))

        # Record the exit.
        def __exit__(self, *exc):
            events.append(("exit", len(d.log)))

    d = FakeServer()
    assert run_flash(d, quiet=Quiet)[0] == 0
    assert events == [("enter", len(PRECHECK)), ("exit", len(d.log))]
    events.clear()
    d = FakeServer(sha=NEW_SHA)
    assert run_flash(d, quiet=Quiet)[0] == 0
    assert events == []


# Check the ISO-TP address builder refuses a deny_tx pair before touching can-isotp.
def test_isotp_address_refuses_deny_tx_ids():
    with pytest.raises(errors.Refused):
        transport.isotp_address(P, 0x7E0, 0x7E8)


# Check the kernel socket is blocking, WAIT_TX_DONE, padded 0xAA and never forces STmin (no real socket).
def test_isotp_connection_socket_options(monkeypatch):
    import isotp
    made = []

    # Records the constructor timeout and the options; never opens an AF_CAN socket.
    class FakeSocket:
        # Record the constructor arguments.
        def __init__(self, *args, **kwargs):
            self.args, self.kwargs, self.opts = args, kwargs, None
            made.append(self)

        # Record the general options.
        def set_opts(self, **kwargs):
            self.opts = kwargs

    FakeSocket.flags = isotp.socket.flags
    monkeypatch.setattr(isotp, "socket", FakeSocket)
    conn = transport.isotp_connection(P, "vcan0")
    (sock,) = made
    assert isinstance(conn, transport.RxResilientIsoTPConnection)
    assert conn.tpsock is sock and conn.interface == "vcan0"
    assert sock.args == () and sock.kwargs.get("timeout") is None
    assert sock.opts == {"optflag": isotp.socket.flags.WAIT_TX_DONE, "txpad": 0xAA}
    assert (conn.address.get_tx_arbitration_id(), conn.address.get_rx_arbitration_id()) == (0x710, 0x718)


# A kernel ISO-TP socket stand-in over a local datagram pair: recv() raises ECOMM (a TX timeout's error) errors
# times first, then returns what the peer sent. select() sees a real descriptor.
class EcommSocket:
    # A bound socket whose first `errors` reads fail.
    def __init__(self, errors=1):
        self._socket, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.errors, self.bound, self.closed = errors, True, False

    # Nothing to bind: the pair is already connected.
    def bind(self, interface, address):
        pass

    # Fail with ECOMM while errors remain (leaving the datagram queued), then read one datagram.
    def recv(self):
        if self.errors:
            self.errors -= 1
            raise OSError(errno.ECOMM, os.strerror(errno.ECOMM))
        return self._socket.recv(4095)

    # Close both ends.
    def close(self):
        self.closed, self.bound = True, False
        self._socket.close()
        self.peer.close()


# Open cls (a udsoncan ISO-TP socket connection) over an EcommSocket and send payload from the peer.
def open_over_ecomm(cls, payload):
    import isotp
    sock = EcommSocket()
    conn = cls("vcan0", isotp.Address(isotp.AddressingMode.Normal_11bits, txid=0x710, rxid=0x718), tpsock=sock)
    conn.open()
    sock.peer.send(payload)
    return conn, sock


# Check the receive thread survives a socket error (a TX timeout's ECOMM): the answer after it still reaches the
# queue, and close() ends the thread promptly. udsoncan's own class goes deaf on the same input.
def test_rx_thread_survives_a_socket_error():
    conn, sock = open_over_ecomm(transport.RxResilientIsoTPConnection, b"\x76\x2f")
    try:
        assert conn.rxqueue.get(timeout=1.0) == b"\x76\x2f" and sock.errors == 0
    finally:
        t0 = time.monotonic()
        conn.close()
        assert time.monotonic() - t0 < 1.0 and not conn.rxthread.is_alive()
    stock, sock = open_over_ecomm(IsoTPSocketConnection, b"\x76\x2f")
    try:
        stock.rxthread.join(timeout=1.0)
        assert not stock.rxthread.is_alive() and stock.rxqueue.empty() and sock.errors == 0
    finally:
        stock.close()


# ---- pre-flight: listen, busy guard, pre-roll ----

# Run preflight on channel with an optional chatter frame; returns (result or exception, request-ID frames seen).
def run_preflight(channel, chatter_msg=None, listen_s=0.3, prof=P):
    rx = can.Bus(interface="virtual", channel=channel)
    stop = threading.Event()
    th = None
    if chatter_msg is not None:
        th = threading.Thread(target=chatter, args=(channel, chatter_msg, stop))
        th.start()
    bus = transport.GuardedBus(can.Bus(interface="virtual", channel=channel), prof)
    try:
        result = transport.preflight(bus, prof, listen_s=listen_s)
    except errors.ToolError as e:
        result = e
    finally:
        stop.set()
        if th is not None:
            th.join()
        bus.shutdown()
    seen = []
    while (m := rx.recv(timeout=0.05)) is not None:
        if m.arbitration_id == prof.req_id:
            seen.append(bytes(m.data))
    rx.shutdown()
    return result, seen


# Busy-detector frame with the given state byte.
def busy_frame(state):
    return can.Message(arbitration_id=BUSY_ID, is_extended_id=False, data=bytes([0, state, 0, 0, 0, 0, 0, 0]))


# Check a server in the extended (2) or programming (3) session stops the tool before it sends anything.
@pytest.mark.parametrize("state", [2, 3])
def test_preflight_stops_on_busy_server(state):
    result, seen = run_preflight("uds_pf_busy%d" % state, busy_frame(state))
    assert isinstance(result, errors.Busy)
    assert seen == []


# Check a 0x718 frame heard before sending is treated as a second tester.
def test_preflight_stops_on_foreign_response():
    msg = can.Message(arbitration_id=0x718, is_extended_id=False, data=bytes([0x02, 0x7E, 0x00] + [0xAA] * 5))
    result, seen = run_preflight("uds_pf_resp", msg)
    assert isinstance(result, errors.SecondTester)
    assert seen == []


# Check a quiet bus gets exactly five 02 3E 80 AA.. frames on 0x710.
def test_preflight_prerolls_on_quiet_bus():
    result, seen = run_preflight("uds_pf_quiet")
    assert result == 0
    assert seen == [bytes.fromhex("023E80AAAAAAAAAA")] * 5


# Check a bus with traffic and a server in state 1 gets no pre-roll.
def test_preflight_no_preroll_on_busy_bus():
    result, seen = run_preflight("uds_pf_traffic", busy_frame(1))
    assert result >= 5
    assert seen == []


# ---- second-tester monitor ----

# 0x718 frame.
def resp_frame():
    return can.Message(arbitration_id=0x718, is_extended_id=False, data=bytes(8))


# Check 0x718 frames during a request or within the grace time are ours, and later ones raise the alarm.
def test_monitor_flags_only_unsolicited_frames():
    ft = FakeTime()
    mon = transport.SecondTesterMonitor(0x718, clock=ft.clock)
    mon.begin()
    mon.on_frame(resp_frame())
    mon.end()
    ft.sleep(0.1)
    mon.on_frame(resp_frame())
    mon.on_frame(can.Message(arbitration_id=0x101, is_extended_id=False, data=bytes(8)))
    assert mon.alarm is None
    ft.sleep(1.0)
    mon.on_frame(resp_frame())
    assert mon.alarm
    with pytest.raises(errors.SecondTester):
        mon.check()


# Check a raised alarm stops the next request before it reaches the server.
def test_second_tester_alarm_aborts_before_sending():
    ft, d = FakeTime(), FakeServer()
    mon = transport.SecondTesterMonitor(0x718, clock=ft.clock)
    uds = uds_for(d, ft, monitor=mon)
    uds.read_did(0xF1F3)
    ft.sleep(1.0)
    mon.on_frame(resp_frame())
    with pytest.raises(errors.SecondTester):
        uds.read_did(0xF1F0)
    assert d.log == [(0x22, 0xF1F3)]


# Check a late answer to our own timed-out request (within P2*) is not taken for a second tester.
def test_late_answer_after_timeout_is_not_a_second_tester():
    ft, d = FakeTime(), FakeServer()
    mon = transport.SecondTesterMonitor(0x718, clock=ft.clock)
    uds = uds_for(d, ft, monitor=mon)
    d.silence = 1
    with pytest.raises(errors.NoResponse):
        uds.read_did(0xF1F3)
    ft.sleep(1.0)
    mon.on_frame(resp_frame())
    assert mon.alarm is None
    ft.sleep(5.0)
    mon.on_frame(resp_frame())
    assert mon.alarm


# Check a quick answer after a timed-out request does not shorten that request's P2* window.
def test_quick_answer_keeps_the_p2_star_window_of_a_timed_out_request():
    ft, d = FakeTime(), FakeServer()
    mon = transport.SecondTesterMonitor(0x718, clock=ft.clock)
    uds = uds_for(d, ft, monitor=mon)
    d.silence = 1
    with pytest.raises(errors.NoResponse):
        uds.read_did(0xF1F3)
    uds.read_did(0xF1F3)
    ft.sleep(2.0)
    mon.on_frame(resp_frame())
    assert mon.alarm is None


# ---- image parsing ----

# Check a well-formed image parses to its version, board and app_elf_sha256.
def test_parse_image_reads_headers():
    info = parse_image(P, make_image(hw_id=2))
    assert (info.version, info.project, info.elf_sha, info.hw_id, info.size) == ("0.3.0", "example", NEW_SHA, 2, 4800)


# Check each malformed or foreign image is refused before any transmit.
@pytest.mark.parametrize("image", [
    make_image(first=0x00), make_image(app_magic=0), make_image(project=b"other"), make_image(desc_magic=0),
    make_image(ids=(0x720, 0x728)), make_image(hw_id=9), make_image(layout=2), make_image()[:100],
    make_image(size=0x400000 + 1),
    make_image(desc_magic=0x4F534455),   # "UDSO" byte-swapped: a descriptor written big-endian
])
def test_parse_image_refuses_bad_images(image):
    with pytest.raises(errors.Refused):
        parse_image(P, image)


# ---- DID decoding ----

# Check F1F0 decodes the fixture (slot 1 PENDING_VERIFY, other VERIFIED v0.2.7, flags 0x05).
def test_decode_status_fixture():
    s = wire.decode_status(STATUS_FIXTURE)
    assert (s["running_slot"], s["running_state"], s["boot_slot"], s["other_state"]) == (1, 2, 1, 3)
    assert s["other_version"] == (0, 2, 7) and s["other_sha_prefix"] == bytes(range(0xA1, 0xA9))
    text = wire.describe_status(s)
    assert "PENDING_VERIFY" in text and "VERIFIED v0.2.7" in text and "signature-checked" in text
    assert "flags signature-checked,0x04" in text        # 0x04 has no UDSOTA_STATUS_* name, so it shows as hex


# Check F1F1 and F1F2 decode big-endian.
def test_decode_result_counters():
    assert wire.decode_result(bytes.fromhex("080014F2A0")) == ("DL_VERIFY_FAILED", 0x0014F2A0)
    counters = wire.decode_counters(bytes(range(1, 17)))
    assert counters["seq_errors"] == 0x0102 and counters["resp_frames_dropped"] == 0x0F10


WIRE_H = pathlib.Path(__file__).resolve().parents[2] / "components" / "udsota" / "include" / "udsota_wire.h"
# The #defines wire.py mirrors, by the name wire.py gives each.
WIRE_DEFINES = {"UDSOTA_DID_ACTIVE_SESSION": "DID_SESSION", "UDSOTA_DID_SW_VERSION": "DID_VERSION",
                "UDSOTA_DID_SERIAL": "DID_DEVICE_ID", "UDSOTA_DID_STATUS": "DID_STATUS",
                "UDSOTA_DID_RESULT": "DID_RESULT", "UDSOTA_DID_COUNTERS": "DID_COUNTERS",
                "UDSOTA_DID_RUNNING_SHA": "DID_RUNNING_SHA", "UDSOTA_RID_CHECK_PROG_DEPS": "RID_CHECK_DEPS",
                "UDSOTA_RID_ACTIVATE_IMAGE": "RID_ACTIVATE", "UDSOTA_RID_CONFIRM_IMAGE": "RID_CONFIRM",
                "UDSOTA_DL_DFI": "DL_DFI", "UDSOTA_DL_ALFID": "DL_ALFID", "UDSOTA_NRC_BUSY_REPEAT": "NRC_BUSY",
                "UDSOTA_NRC_CONDITIONS_NOT_CORRECT": "NRC_CONDITIONS",
                "UDSOTA_NRC_REQUEST_SEQUENCE_ERROR": "NRC_SEQUENCE",
                "UDSOTA_NRC_REQUEST_OUT_OF_RANGE": "NRC_OUT_OF_RANGE",
                "UDSOTA_NRC_TIME_DELAY_NOT_EXPIRED": "NRC_TIME_DELAY",
                "UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE": "NRC_PROGRAMMING_FAILURE"}


# udsota_wire.h without comments, or a skip when the checkout has no components/ (a wheel-only install).
def wire_header():
    if not WIRE_H.is_file():
        pytest.skip("no %s (not a repo checkout)" % WIRE_H)
    return re.sub(r"/\*.*?\*/", "", WIRE_H.read_text(), flags=re.S)


# Check wire.py's reason names match udsota_reason_t in udsota_wire.h, by name and value.
def test_reason_names_match_udsota_wire():
    body = re.search(r"typedef enum \{([^}]*)\} udsota_reason_t;", wire_header()).group(1)
    names, value = [], -1
    for item in (x.strip() for x in body.split(",") if x.strip()):
        m = re.fullmatch(r"UDSOTA_(\w+)(?:\s*=\s*(\w+))?", item)
        value = int(m[2], 0) if m[2] else value + 1
        names.append((m[1], value))
    assert names[-1] == ("DL_REASON_COUNT", len(wire.DL_REASONS))
    assert [(wire.reason_name(v), v) for _, v in names[:-1]] == names[:-1]
    assert wire.reason_name(len(wire.DL_REASONS)) == "reason 0x%02X" % len(wire.DL_REASONS)


# Check the DIDs, RIDs, NRCs, download format and status flags wire.py mirrors match udsota_wire.h's #defines.
def test_wire_numbers_match_udsota_wire():
    defines = {m[1]: int(m[2], 0) for m in re.finditer(r"#define\s+(UDSOTA_\w+)\s+(0x[0-9A-Fa-f]+|\d+)u?\b",
                                                      wire_header())}
    assert {c: defines[c] for c in WIRE_DEFINES} == {c: getattr(wire, py) for c, py in WIRE_DEFINES.items()}
    assert defines["UDSOTA_DL_MAX_BLOCK_LEN"] - 2 == wire.DL_MAX_DATA
    flags = {v for k, v in defines.items() if k.startswith("UDSOTA_STATUS_") and k != "UDSOTA_STATUS_LEN"}
    assert flags == set(wire.STATUS_FLAGS)


# ---- the update sequence ----

# Check flash runs precheck, programming unlock, download, FF01, ActivateImage, the reboot wait and ConfirmImage in order.
def test_flash_runs_the_update_sequence_in_order():
    d = FakeServer()
    rc, ft, prerolls = run_flash(d)
    assert rc == 0
    assert d.log == (PRECHECK + UNLOCK_PROG + [(0x34, None)] + blocks()
                     + [(0x37, None), (0x31, 0xFF01), (0x31, 0xF001)]
                     + [(0x22, 0xF1F3)] * 3 + [(0x10, 3)] + [(0x31, 0xF002)] * 3 + [(0x22, 0xF1F0)])
    assert bytes(d.written) == make_image() and d.writes == 300
    assert prerolls == 3
    assert ft.sleeps[0] == update.REBOOT_WAIT_S and ft.sleeps.count(update.CONFIRM_RETRY_S) == 2


# Check --drop-76 resends that block once, and the server writes it once.
def test_drop_76_resends_one_block_without_rewrite():
    d = FakeServer()
    assert run_flash(d, drop_76=2)[0] == 0
    assert [e for e in d.log if e[0] == 0x36] == blocks(repeat=2)
    assert d.writes == 300 and bytes(d.written) == make_image()


# Check a lost 76 (plain timeout) makes the tool resend that block once, without a second write.
def test_lost_76_is_resent_once():
    d = FakeServer(lose_76_once=3)
    assert run_flash(d)[0] == 0
    assert [e for e in d.log if e[0] == 0x36] == blocks(repeat=3)
    assert d.writes == 300 and bytes(d.written) == make_image()


# Check a block that times out twice stops the update before 0x37.
def test_second_timeout_stops_the_transfer():
    d = FakeServer(mute_block=5)
    with pytest.raises(errors.NoResponse):
        run_flash(d)
    assert d.log.count((0x36, 5)) == 2 and (0x37, None) not in d.log


# Check one ISO-TP send error (no FC for the multi-frame 27 04 key, kernel ECOMM) is resent once and the update completes.
def test_send_error_on_key_is_resent_once():
    d = FakeServer(no_fc={(0x27, 4): 1})
    rc, _, _ = run_flash(d)
    assert rc == 0 and d.no_fc[(0x27, 4)] == 0
    assert d.log[:len(PRECHECK) + 3] == PRECHECK + UNLOCK_PROG and d.sha == NEW_SHA


# Check two send errors in a row stop with "the server ended the transfer", exit 1, before any download.
def test_second_send_error_stops_with_no_flow_control():
    d = FakeServer(no_fc={(0x27, 4): 2})
    with pytest.raises(errors.UpdateFailed) as e:
        run_flash(d)
    assert str(e.value) == "service 0x27: the server ended the transfer (no flow control)"
    assert e.value.exit_code == 1 and not isinstance(e.value, errors.NoResponse)
    assert d.no_fc[(0x27, 4)] == 0 and (0x34, None) not in d.log


# Check a send error on a 0x36 block is resent inside the request, so send_block adds no third send.
def test_send_errors_on_a_block_send_it_twice_only():
    d = FakeServer(no_fc={(0x36, 5): 3})
    with pytest.raises(errors.SendFailed):
        run_flash(d)
    assert d.no_fc[(0x36, 5)] == 1 and (0x36, 5) not in d.log


# Check the reboot wait after ActivateImage keeps polling through send errors, as through timeouts.
def test_wait_for_image_polls_through_send_errors():
    ft = FakeTime()

    # A server that is restarting: its reads fail, then it answers.
    class Rebooting:
        # read_did fails the way a rebooting server does, then answers the new sha.
        def __init__(self):
            self.errors = [errors.SendFailed("send failed"), errors.NoResponse("no answer"),
                           errors.SendFailed("send failed")]

        # Raise the next queued error, then return the new image's sha.
        def read_did(self, did):
            if self.errors:
                raise self.errors.pop(0)
            return NEW_SHA

    update.wait_for_image(Rebooting(), NEW_SHA, lambda: None, sleep=ft.sleep, clock=ft.clock)
    assert ft.sleeps == [update.REBOOT_WAIT_S] + [update.BOOT_POLL_S] * 3


# Check NRC 0x21 is retried after the first backoff step.
def test_busy_nrc_is_retried_with_backoff():
    d = FakeServer(nrc_once={(0x22, 0xF1F0): 0x21})
    rc, ft, _ = run_flash(d)
    assert rc == 0
    assert d.log[:2] == [(0x22, 0xF1F0), (0x22, 0xF1F0)]   # the backoff is listened out, not slept


# Check NRC 0x37 to the seed request (the post-boot delay) is waited out once, with 3E 00 keeping S3 alive.
def test_security_delay_is_waited_out():
    d = FakeServer(nrc_once={(0x27, 3): 0x37})
    rc, ft, _ = run_flash(d)
    assert rc == 0
    assert d.log[4:12] == [(0x10, 2), (0x27, 3)] + [(0x3E, 0)] * 5 + [(0x27, 3)]
    assert d.log[12] == (0x27, 4) and ft.sleeps[:5] == [KEEPALIVE_S] * 5


# Check flash in the ecdsa mode runs the same sequence, and its programming unlock is a signature the server
# verifies under the tester's public key.
def test_flash_ecdsa_unlocks_with_a_signature():
    d = FakeServer(pubkey=TESTER_PUB)
    rc, _, _ = run_flash(d, prof=PE, master=TESTER_KEY)
    assert rc == 0 and d.log[:len(PRECHECK) + len(UNLOCK_PROG) + 1] == PRECHECK + UNLOCK_PROG + [(0x34, None)]
    assert bytes(d.written) == make_image() and d.sha == NEW_SHA and d.running_state == 3


# Check a private key whose public half the server does not hold is refused (0x35) before any download.
def test_flash_ecdsa_other_key_is_refused():
    d = FakeServer(pubkey=TESTER_PUB)
    with pytest.raises(errors.Nrc) as e:
        run_flash(d, prof=PE, master=ec.generate_private_key(ec.SECP256R1()))
    assert e.value.code == 0x35 and d.log[-1] == (0x27, 4) and (0x34, None) not in d.log


# Check the modes do not mix: an hmac profile's 16-byte key to an ecdsa server is the wrong length (0x13).
def test_hmac_key_to_an_ecdsa_server_is_the_wrong_length():
    d = FakeServer(pubkey=TESTER_PUB)
    with pytest.raises(errors.Nrc) as e:
        run_flash(d)
    assert e.value.code == 0x13 and (0x34, None) not in d.log


# Check the precheck stops before 10 02 on an unconfirmed running image or the wrong board.
@pytest.mark.parametrize("server,image", [
    (FakeServer(running_state=2), make_image()),
    (FakeServer(), make_image(hw_id=3)),
])
def test_precheck_refuses(server, image):
    with pytest.raises(errors.Refused):
        run_flash(server, image=image)
    assert server.log == PRECHECK


# Check an image the server already runs ends after the precheck with success.
def test_precheck_already_running_is_a_no_op():
    d = FakeServer(sha=NEW_SHA)
    assert run_flash(d)[0] == 0 and d.log == PRECHECK


# Check the no-op and confirm-only paths derive no key: an empty F18C and no master still end in exit 0.
@pytest.mark.parametrize("running_state", [3, 2])
def test_precheck_no_op_and_confirm_need_no_device_key(running_state):
    d = FakeServer(sha=NEW_SHA, running_state=running_state, config={0xF18C: b""})
    assert run_flash(d, master=None)[0] == 0 and d.log[:len(PRECHECK)] == PRECHECK
    assert d.running_state == 3


# Check a rerun after an interrupted confirm (same image, PENDING_VERIFY) goes to step 8 and exits 0
# only once ConfirmImage succeeds.
def test_precheck_same_image_unconfirmed_confirms_it():
    d = FakeServer(sha=NEW_SHA, running_state=2)
    assert run_flash(d)[0] == 0
    assert d.log == PRECHECK + [(0x10, 3)] + [(0x31, 0xF002)] * 3 + [(0x22, 0xF1F0)]
    assert d.running_state == 3
    d = FakeServer(sha=NEW_SHA, running_state=2, confirm_refusals=10 ** 6)
    with pytest.raises(errors.Nrc):
        run_flash(d)
    assert d.running_state == 2 and (0x10, 2) not in d.log


# Check a device without F1F0 (NRC 0x31: no udsota server) stops the precheck with exit 2, before any other
# read or session change.
def test_precheck_on_a_device_without_f1f0_is_refused():
    d = FakeServer()
    d.s22 = lambda req, did: FakeServer.nrc(0x22, 0x31) if did == 0xF1F0 else FakeServer.s22(d, req, did)
    with pytest.raises(errors.Refused, match=r"does not serve the udsota status DID F1F0; is it running a udsota"):
        run_flash(d)
    assert d.log == [(0x22, 0xF1F0)]


# Check an unconfirmed running image with a different SHA is still refused before any session change.
def test_precheck_other_image_unconfirmed_is_refused():
    d = FakeServer(sha=OLD_SHA, running_state=2)
    with pytest.raises(errors.Refused, match="unconfirmed"):
        run_flash(d)
    assert d.log == PRECHECK


# Check --drop-76 past the last block is refused after 0x34 and before any 0x36.
def test_drop_76_past_the_last_block_is_refused():
    d = FakeServer()
    with pytest.raises(errors.Refused, match="300 blocks"):
        run_flash(d, drop_76=301)
    assert d.log[-1] == (0x34, None) and not any(e[0] == 0x36 for e in d.log)


# Check a verified copy in the other slot skips straight to ActivateImage.
def test_verified_other_slot_skips_to_activate():
    d = FakeServer(other_state=3, other_sha=NEW_SHA)
    assert run_flash(d)[0] == 0
    assert d.log[:8] == PRECHECK + UNLOCK_PROG + [(0x31, 0xF001)]
    assert not any(e[0] in (0x34, 0x36, 0x37) for e in d.log)


# Check a failed FF01 stops before ActivateImage and names the reason.
def test_ff01_failure_stops_before_activate():
    d = FakeServer(ff01_status=9)
    with pytest.raises(errors.UpdateFailed, match="DL_SIG_FAILED"):
        run_flash(d)
    assert d.log[-1] == (0x31, 0xFF01)


# A FakeServer that never gets the first ActivateImage request: no answer, and nothing activated.
class LostActivateRequest(FakeServer):
    # Swallow the first F001 unanswered and unserved; everything else as FakeServer.
    def handle(self, req):
        if bytes(req[:4]) == b"\x31\x01\xF0\x01" and not getattr(self, "lost", False):
            self.lost = True
            self.log.append((0x31, 0xF001))
            return []
        return super().handle(req)


# Check no answer to ActivateImage from a server that answers F1F0 with the boot slot unchanged: the request was
# lost, so it is sent once more (with no new download) and the update completes.
def test_lost_activate_request_is_resent_once():
    d = LostActivateRequest()
    rc, _, _ = run_flash(d)
    assert rc == 0
    i = d.log.index((0x31, 0xF001))
    assert d.log[i:i + 3] == [(0x31, 0xF001), (0x22, 0xF1F0), (0x31, 0xF001)]
    assert d.writes == 300


# Check ActivateImage refused with 0x22 stops with the conditions-not-met message.
def test_activate_conditions_not_met_stops():
    d = FakeServer(activate_refusals=1)
    with pytest.raises(errors.UpdateFailed, match="conditions are not met"):
        run_flash(d)
    assert d.log[-1] == (0x31, 0xF001)


# ---- recovery from lost answers and activation failures ----

# Check a lost 77 is resent, and its 0x24 plus F1F1 (DL_OK, every byte) lets FF01 follow.
def test_lost_77_resend_reads_result_and_continues():
    d = FakeServer(lose_77_once=True)
    assert run_flash(d)[0] == 0
    tail = [(0x37, None), (0x37, None), (0x22, 0xF1F1), (0x31, 0xFF01), (0x31, 0xF001)]
    assert d.log[len(PRECHECK + UNLOCK_PROG) + 1 + 300:][:5] == tail
    assert d.sha == NEW_SHA and d.running_state == 3


# Check a lost 77 whose F1F1 is not (DL_OK, image size) stops before FF01.
def test_lost_77_with_other_result_stops():
    d = FakeServer(lose_77_once=True, config={0xF1F1: bytes([11, 0, 0, 0x12, 0xC0])})
    with pytest.raises(errors.Nrc):
        run_flash(d)
    assert d.log[-3:] == [(0x37, None), (0x37, None), (0x22, 0xF1F1)]


# Check a lost FF01 answer is resent once and the repeat's 00 lets ActivateImage follow.
def test_lost_ff01_answer_is_resent():
    d = FakeServer(lose_ff01_once=True)
    assert run_flash(d)[0] == 0
    assert d.log.count((0x31, 0xFF01)) == 2
    assert d.log[len(PRECHECK + UNLOCK_PROG) + 1 + 300:][:4] == [(0x37, None), (0x31, 0xFF01), (0x31, 0xFF01),
                                                                (0x31, 0xF001)]
    assert d.writes == 300 and d.sha == NEW_SHA


# Check a lost answer to a failed FF01 is resent, and the resend's 0x24 names the F1F1 reason.
def test_lost_ff01_failure_names_the_result_reason():
    d = FakeServer(lose_ff01_once=True, ff01_status=8)
    with pytest.raises(errors.UpdateFailed, match="DL_VERIFY_FAILED"):
        run_flash(d)
    assert d.log[-3:] == [(0x31, 0xFF01), (0x31, 0xFF01), (0x22, 0xF1F1)]


# Check 0x24 to ActivateImage downloads again from 0x34 in the same session, once.
def test_activate_sequence_error_downloads_again():
    d = FakeServer(activate_nrcs=[0x24])
    assert run_flash(d, drop_76=2)[0] == 0
    once = [(0x34, None)] + blocks() + DOWNLOAD_TAIL
    assert d.log == (PRECHECK + UNLOCK_PROG + [(0x34, None)] + blocks(repeat=2) + DOWNLOAD_TAIL
                     + once + AFTER_ACTIVATE)
    assert d.writes == 600 and d.sha == NEW_SHA


# Check a verified other slot that ActivateImage no longer accepts (0x24) is downloaded after all.
def test_activate_sequence_error_on_the_skip_path_downloads():
    d = FakeServer(other_state=3, other_sha=NEW_SHA, activate_nrcs=[0x24])
    assert run_flash(d)[0] == 0
    assert d.log == (PRECHECK + UNLOCK_PROG + [(0x31, 0xF001), (0x34, None)] + blocks() + DOWNLOAD_TAIL
                     + AFTER_ACTIVATE)


# Check a second 0x24 to ActivateImage stops: the tool recovers once per run.
def test_activate_sequence_error_twice_stops():
    d = FakeServer(activate_nrcs=[0x24, 0x24])
    with pytest.raises(errors.Nrc) as e:
        run_flash(d)
    assert e.value.code == 0x24 and d.log.count((0x34, None)) == 2 and d.log[-1] == (0x31, 0xF001)


# Check 0x72 to ActivateImage with F1F0 showing the boot slot moved (set_boot landed): keyed 11 01 from
# extended, then the post-restart F1F3 check and ConfirmImage.
def test_activate_failure_with_set_boot_landed_resets_and_confirms():
    d = FakeServer(activate_fail="set_boot")
    rc, _, prerolls = run_flash(d)
    assert rc == 0
    assert d.log == (PRECHECK + UNLOCK_PROG + [(0x34, None)] + blocks() + DOWNLOAD_TAIL
                     + [(0x22, 0xF1F0), (0x10, 3), (0x27, 1), (0x27, 2), (0x11, 1)] + AFTER_ACTIVATE)
    assert d.sha == NEW_SHA and d.running_state == 3 and prerolls == 3


# Check 0x72 to ActivateImage with F1F0 showing the boot slot unchanged stops, with no 11 01 and no re-download.
def test_activate_failure_not_landed_stops():
    d = FakeServer(activate_fail="clean")
    with pytest.raises(errors.UpdateFailed, match="did not land"):
        run_flash(d)
    assert d.log == PRECHECK + UNLOCK_PROG + [(0x34, None)] + blocks() + DOWNLOAD_TAIL + [(0x22, 0xF1F0)]
    assert d.sha == OLD_SHA


# Check the keyed reset after a 0x72 stops, with its explanation, when 11 01 is refused with 0x22.
def test_activate_failure_reset_refused_stops():
    d = FakeServer(activate_fail="set_boot", nrc_once={(0x11, 1): 0x22})
    with pytest.raises(errors.UpdateFailed, match="confirm"):
        run_flash(d)
    assert d.log[-1] == (0x11, 1)


# ---- confirm, reset, info ----

# Check confirm retries 0x22 then confirms, and does nothing for a VALID image.
def test_confirm_command():
    ft, d = FakeTime(), FakeServer(running_state=2)
    assert update.confirm_cmd(uds_for(d, ft), sleep=ft.sleep, clock=ft.clock, log=lambda *a: None) == 0
    assert d.log == [(0x22, 0xF1F0), (0x10, 3)] + [(0x31, 0xF002)] * 3 + [(0x22, 0xF1F0)]
    ft, d = FakeTime(), FakeServer(running_state=3)
    assert update.confirm_cmd(uds_for(d, ft), sleep=ft.sleep, clock=ft.clock, log=lambda *a: None) == 0
    assert d.log == [(0x22, 0xF1F0)]


# Check confirm gives up once its deadline passes.
def test_confirm_gives_up_after_timeout():
    ft, d = FakeTime(), FakeServer(running_state=2, confirm_refusals=10 ** 6)
    with pytest.raises(errors.Nrc):
        update.confirm_cmd(uds_for(d, ft), sleep=ft.sleep, clock=ft.clock, log=lambda *a: None)
    assert ft.t >= update.CONFIRM_TIMEOUT_S


# Check reset unlocks level 01/02 in the extended session with the vector key, then sends 11 01.
def test_reset_is_keyed():
    ft, d = FakeTime(), FakeServer()
    assert update.reset(uds_for(d, ft), P, MASTER, log=lambda *a: None) == 0
    assert d.log == [(0x22, 0xF18C), (0x10, 3), (0x27, 1), (0x27, 2), (0x11, 1)]


# Check reset just after a boot waits out the server's 10 s 0x27 delay (NRC 0x37) instead of failing.
def test_reset_waits_out_the_post_boot_delay():
    ft, d = FakeTime(), FakeServer(nrc_once={(0x27, 1): 0x37})
    assert update.reset(uds_for(d, ft), P, MASTER, log=lambda *a: None) == 0
    assert d.log == ([(0x22, 0xF18C), (0x10, 3), (0x27, 1)] + [(0x3E, 0)] * 5
                     + [(0x27, 1), (0x27, 2), (0x11, 1)])
    assert ft.t >= SA_DELAY_S


# Check reset in the ecdsa mode unlocks level 01/02 with a signature over the F18C bytes, then sends 11 01.
def test_reset_ecdsa_is_keyed():
    ft, d = FakeTime(), FakeServer(pubkey=TESTER_PUB)
    assert update.reset(uds_for(d, ft), PE, TESTER_KEY, log=lambda *a: None) == 0
    assert d.log == [(0x22, 0xF18C), (0x10, 3), (0x27, 1), (0x27, 2), (0x11, 1)]


# Check info reads the identity DIDs and config DIDs up to the first absent one, without a session change.
def test_info_reads_identity_and_config():
    ft, lines = FakeTime(), []
    d = FakeServer(config={0x0200: b"\x00", 0x0201: b"\x01", 0x0202: b"\x09\xc4"})
    assert update.info(uds_for(d, ft), P, log=lines.append) == 0
    order = (0xF186, 0xF189, 0xF18C, 0xF1F3, 0xF1F0, 0xF1F1, 0xF1F2, 0xF191, 0xF1B1, 0xF1B0)
    assert d.log == [(0x22, did) for did in order] + [(0x22, 0x0200 + i) for i in range(4)]
    assert "F18C device ID: 02:00:00:00:00:01" in lines and "0202 calibration: 09 c4" in lines
    assert "F1B1 api version: 1.2.3" in lines


# ---- main ----

# Transport stand-in: no bus; preflight is a no-op and uds() talks to a FakeServer.
class FakeTransport:
    # Remember the server and interface.
    def __init__(self, server, interface):
        self.server, self.interface = server, interface

    # Enter the with-block.
    def __enter__(self):
        return self

    # Nothing to close.
    def __exit__(self, *exc):
        pass

    # No bus to listen on.
    def preflight(self):
        return 5

    # No bus, so nothing to pre-roll.
    def preroll(self):
        pass

    # A Uds over the FakeServer.
    def uds(self):
        return uds_for(self.server, FakeTime())


# A transport factory that fails the test if called: the refusal must come before any bus opens.
def no_transport(profile, interface):
    raise AssertionError("transport opened")


# FULL written to tmp_path/full.toml, for the tests that pass --profile to main.
@pytest.fixture
def full_path(tmp_path):
    p = tmp_path / "full.toml"
    p.write_text(FULL)
    return str(p)


# Check a bad image, a missing master or --drop-76 0 is refused (exit 2) before any bus opens.
def test_main_refuses_before_opening_the_bus(tmp_path, full_path):
    good, bad = tmp_path / "good.bin", tmp_path / "bad.bin"
    good.write_bytes(make_image())
    bad.write_bytes(b"\x00" * 400)
    master = tmp_path / "m.bin"
    master.write_bytes(MASTER)
    assert cli.main(["--profile", full_path, "--master", str(master), "flash", str(bad)], transport=no_transport) == 2
    assert cli.main(["--profile", full_path, "--master", str(tmp_path / "absent"), "reset"],
                    transport=no_transport) == 2
    assert cli.main(["--profile", full_path, "--master", str(master), "flash", str(good), "--drop-76", "0"],
                    transport=no_transport) == 2


# Check `info` runs end to end through main with the built-in example profile and exits 0.
def test_main_info_end_to_end(capsys):
    d = FakeServer(security=False)
    assert cli.main(["--profile", "example", "--interface", "vcan0", "info"],
                    transport=lambda p, i: FakeTransport(d, i)) == 0
    assert "F191 board: devkit" in capsys.readouterr().out


# Check a short DID record or an answer for another service ends in exit 1 with a message, not a traceback.
def test_main_maps_malformed_answers_to_exit_1(capsys):
    d = FakeServer(config={0xF1F0: b"\x01"})     # F1F0 too short for its 16-byte layout
    assert cli.main(["--profile", "example", "info"], transport=lambda p, i: FakeTransport(d, i)) == 1
    assert "F1F0 is 1 bytes" in capsys.readouterr().err
    d = FakeServer()
    d.s22 = lambda req, did: [b"\x51\x01"]        # an ECUReset answer to a ReadDataByIdentifier
    assert cli.main(["--profile", "example", "info"], transport=lambda p, i: FakeTransport(d, i)) == 1
    assert "unexpected answer" in capsys.readouterr().err


# Check a python-can error from the real Transport (CanOperationError is not an OSError) exits 1 with a message.
def test_main_maps_can_errors_to_exit_1(monkeypatch, capsys):
    # A raw bus whose receive fails the way a downed SocketCAN interface does; it never sends.
    class FailingBus:
        # Accept the socketcan arguments.
        def __init__(self, *args, **kwargs):
            pass

        # Fail as python-can does on a read error.
        def recv(self, timeout=None):
            raise can.CanOperationError("Error receiving: Network is down")

        # Nothing to close.
        def shutdown(self):
            pass

    monkeypatch.setattr(can, "Bus", FailingBus)
    assert cli.main(["--profile", "example", "--interface", "vcan0", "info"]) == 1
    assert "udsota: Error receiving: Network is down" in capsys.readouterr().err


# ---- profiles ----

# Check the built-in example profile: the example IDs and identity, one board, and security, busy and pre-roll off.
def test_example_profile_values():
    e = profile.load("example")
    assert (e.name, e.interface, e.req_id, e.resp_id, e.deny_tx) == ("example", "can0", 0x710, 0x718, frozenset())
    assert (e.product, e.hw_ids, e.layout_id, e.slot_size) == ("example", (1,), 1, 0x1E0000)
    assert (e.board_did, e.board_names) == (0xF191, {1: "devkit"})
    assert e.security is None and e.busy is None and e.preroll_frames == 0
    assert [(d.first, d.last, d.name, d.decode) for d in e.dids] == [(0xF191, 0xF191, "board", "ascii")]


# Check FULL carries its IDs, deny list, key label, image identity, busy detector, pre-roll and DIDs.
def test_full_profile_values():
    assert (P.name, P.interface, P.req_id, P.resp_id) == ("full", "vcan0", 0x710, 0x718)
    assert P.deny_tx == {0x7DF, 0x7E0, 0x7E8, 0x123}
    s = P.security
    assert (s.label, s.master_file, s.device_id_did) == (b"udsota-example", "master.bin", 0xF18C)
    assert (s.level_extended, s.level_programming) == (0x01, 0x03)
    assert (s.mode, s.private_key_file) == ("hmac", None)                 # hmac is the default mode
    assert (P.product, P.hw_ids, P.layout_id, P.slot_size) == ("example", (1, 2, 3), 1, 0x400000)
    assert (P.board_did, P.board_names) == (0xF191, {1: "devkit", 2: "devkit-two", 3: "devkit-three"})
    assert (P.busy.id, P.busy.byte, P.busy.values, P.preroll_frames) == (BUSY_ID, 1, (2, 3), 5)
    assert [(e.first, e.last, e.name, e.decode) for e in P.dids] == [
        (0xF191, 0xF191, "board", "ascii"), (0xF1B1, 0xF1B1, "api version", "version3"),
        (0xF1B0, 0xF1B0, "serial", "hex"), (0x0200, 0x02FF, "calibration", "hex")]


# Check FULL_ECDSA's [security]: the ecdsa mode with its private key file, no label or master, the default levels.
def test_ecdsa_profile_values():
    s = PE.security
    assert (s.mode, s.private_key_file, s.label, s.master_file) == ("ecdsa", "udsota_private.pem", None, None)
    assert (s.device_id_did, s.level_extended, s.level_programming) == (0xF18C, 0x01, 0x03)


# A profile with a minimal [security], for the level cases, and its [can] alone for the mode cases.
CAN = "[can]\nreq_id = 0x710\nresp_id = 0x718\n"
SEC = CAN + "[security]\nlabel = \"x\"\nmaster_file = \"m\"\n"
SEC_E = CAN + "[security]\nmode = \"ecdsa\"\n"


# Check a broken profile is refused with its reason: each case breaks one rule.
@pytest.mark.parametrize("text,why", [
    ("[can]\nresp_id = 0x718\n", "missing req_id"),
    ("[can]\nreq_id = 0x7E0\nresp_id = 0x7E8\ndeny_tx = [0x7E0]\n", "is in deny_tx"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x710\n", "both 0x710"),
    ("[can]\nreq_id = 0x800\nresp_id = 0x718\n", "req_id must be"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\ndeny = [0x7DF]\n", "unknown key deny in \\[can\\]"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\n[secrity]\nlabel = \"x\"\n", "unknown table \\[secrity\\]"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\n[security]\nlabel = \"x\"\n", "missing master_file"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\n[dids]\n\"0xF1B0\" = { name = \"h\", decode = \"b64\" }\n",
     "decode must be one of"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\n[dids]\n\"F1B0\" = { name = \"h\", decode = \"hex\" }\n",
     "is not 0xNNNN"),
    ("[can\n", "not valid TOML"),
    ("[can]\nreq_id = 0x710\nresp_id = 0x718\n[security]\nlabel = \"udsota-\u00e9\"\nmaster_file = \"m\"\n",
     "label must be ASCII"),
    (b"[can]\nreq_id = 0x710\nresp_id = 0x718\n# \xff\n", "not valid TOML"),
    (SEC + "level_extended = 0x02\n", "level_extended must be odd"),
    (SEC + "level_programming = 0x00\n", "level_programming must be an integer from 0x1 to 0x7D"),
    (SEC + "level_programming = 0x7F\n", "level_programming must be an integer from 0x1 to 0x7D"),
    (CAN + "[security]\nmode = \"rsa\"\nlabel = \"x\"\nmaster_file = \"m\"\n", "mode must be one of hmac, ecdsa"),
    (SEC_E, "missing private_key_file"),
    (SEC_E + "private_key_file = \"k.pem\"\nmaster_file = \"m\"\n", "master_file is for mode = \"hmac\""),
    (SEC_E + "private_key_file = \"k.pem\"\nlabel = \"x\"\n", "label is for mode = \"hmac\""),
    (SEC + "private_key_file = \"k.pem\"\n", "private_key_file is for mode = \"ecdsa\", not \"hmac\""),
])
def test_bad_profiles_are_refused(tmp_path, text, why):
    p = tmp_path / "bad.toml"
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    with pytest.raises(errors.Refused, match=why):
        profile.load(str(p))


# Check the odd requestSeed levels at both ends of the range load.
def test_security_levels_accept_odd_values_to_0x7d(tmp_path):
    p = tmp_path / "levels.toml"
    p.write_text(SEC + "level_extended = 0x01\nlevel_programming = 0x7D\n")
    s = profile.load(str(p)).security
    assert (s.level_extended, s.level_programming) == (0x01, 0x7D)


# Check a profile without [can] interface loads, and main then refuses with exit 2 unless --interface names one.
def test_profile_without_interface_needs_the_option(tmp_path, capsys):
    p = tmp_path / "noif.toml"
    p.write_text("[can]\nreq_id = 0x6F0\nresp_id = 0x6F8\n")
    assert profile.load(str(p)).interface is None
    assert cli.main(["--profile", str(p), "info"], transport=no_transport) == 2
    assert "names no CAN interface: pass --interface" in capsys.readouterr().err
    d, opened = FakeServer(security=False), []
    assert cli.main(["--profile", str(p), "--interface", "vcan3", "info"],
                    transport=lambda prof, i: opened.append(i) or FakeTransport(d, i)) == 0
    assert opened == ["vcan3"]


# Check a missing or broken profile ends main with exit 2 before any bus opens.
def test_main_refuses_a_bad_profile(tmp_path, capsys):
    assert cli.main(["--profile", "nosuch", "info"], transport=no_transport) == 2
    assert "built-in profiles: example" in capsys.readouterr().err
    bad = tmp_path / "bad.toml"
    bad.write_text("[can]\nreq_id = 0x7DF\nresp_id = 0x7E8\ndeny_tx = [0x7DF]\n")
    assert cli.main(["--profile", str(bad), "info"], transport=no_transport) == 2


# Check every command but keygen still needs --profile (argparse's exit 2).
def test_main_needs_a_profile(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["info"], transport=no_transport)
    assert e.value.code == 2 and "--profile" in capsys.readouterr().err


# Check keygen runs with no profile and no bus, says where the private key belongs, and a second run into the
# same directory is refused (exit 2).
def test_main_keygen(tmp_path, capsys):
    out = tmp_path / "keys"
    assert cli.main(["keygen", "--out", str(out)], transport=no_transport) == 0
    assert "never commit it" in capsys.readouterr().out
    assert (out / "udsota_private.pem").exists() and (out / "udsota_pubkey.h").exists()
    assert cli.main(["keygen", "--out", str(out)], transport=no_transport) == 2


# Check main runs reset with an ecdsa profile and --private-key end to end, and a missing key file exits 2 before
# the bus opens.
def test_main_ecdsa_reset(tmp_path):
    p = tmp_path / "ecdsa.toml"
    p.write_text(FULL_ECDSA)
    private, _ = keys.keygen(tmp_path / "keys")
    d = FakeServer(pubkey=keys.public_point(keys.load_private_key(private)))
    assert cli.main(["--profile", str(p), "--private-key", str(private), "reset"],
                    transport=lambda prof, i: FakeTransport(d, i)) == 0
    assert d.log == [(0x22, 0xF18C), (0x10, 3), (0x27, 1), (0x27, 2), (0x11, 1)]
    assert cli.main(["--profile", str(p), "--private-key", str(tmp_path / "absent.pem"), "reset"],
                    transport=no_transport) == 2


# ---- a generic profile: other IDs, no busy detector, no pre-roll, no [security], another image identity ----

GENERIC = """
[can]
interface = "vcan1"
req_id = 0x6F0
resp_id = 0x6F8

[image]
product = "widget"
hw_ids = [7]
layout_id = 2
"""


# The generic profile, loaded from tmp_path/widget.toml.
@pytest.fixture
def generic(tmp_path):
    p = tmp_path / "widget.toml"
    p.write_text(GENERIC)
    return profile.load(str(p))


# An image for the generic profile: project widget, hw_id 7, layout 2, IDs 0x6F0/0x6F8; kw overrides any of them.
def widget_image(**kw):
    return make_image(**{"project": b"widget", "hw_id": 7, "layout": 2, "ids": (0x6F0, 0x6F8), **kw})


# Check the generic profile loads with every optional feature off.
def test_generic_profile_loads(generic):
    assert (generic.name, generic.interface, generic.req_id, generic.resp_id) == ("widget", "vcan1", 0x6F0, 0x6F8)
    assert generic.deny_tx == frozenset() and generic.security is None and generic.busy is None
    assert generic.preroll_frames == 0 and generic.board_did is None and generic.dids == ()


# Check the TX guard follows the profile: only 0x6F0 passes under it, FULL's 0x710 is refused, and the
# ISO-TP binding is 0x6F0/0x6F8; FULL still refuses 0x6F0.
def test_generic_tx_guard(generic):
    transport.check_tx_id(generic, 0x6F0)
    for can_id in (0x710, 0x6F8, 0x7DF):
        with pytest.raises(errors.Refused):
            transport.check_tx_id(generic, can_id)
    with pytest.raises(errors.Refused):
        transport.check_tx_id(generic, 0x6F0, extended=True)
    with pytest.raises(errors.Refused):
        transport.check_tx_id(P, 0x6F0)
    addr = transport.isotp_address(generic)
    assert (addr.get_tx_arbitration_id(), addr.get_rx_arbitration_id()) == (0x6F0, 0x6F8)


# Check the generic pre-flight ignores FULL's busy frame in state 2, sends no pre-roll on a quiet bus,
# and still stops on a frame on its own response ID.
def test_generic_preflight(generic):
    result, seen = run_preflight("uds_pf_gen_hb", busy_frame(2), prof=generic)
    assert result >= 1 and seen == []
    result, seen = run_preflight("uds_pf_gen_quiet", prof=generic)
    assert result == 0 and seen == []
    resp = can.Message(arbitration_id=0x6F8, is_extended_id=False, data=bytes(8))
    result, seen = run_preflight("uds_pf_gen_resp", resp, prof=generic)
    assert isinstance(result, errors.SecondTester) and seen == []


# Check image identity follows the profile: a widget image passes the generic profile and not FULL,
# and an example image or a widget image with any one field wrong is refused under the generic profile.
def test_generic_image_identity(generic):
    info = parse_image(generic, widget_image())
    assert (info.project, info.hw_id, info.layout_id) == ("widget", 7, 2)
    with pytest.raises(errors.Refused):
        parse_image(P, widget_image())
    for bad in (make_image(), widget_image(project=b"example"), widget_image(hw_id=1), widget_image(layout=1),
                widget_image(ids=(0x710, 0x718))):
        with pytest.raises(errors.Refused):
            parse_image(generic, bad)


# Check flash with the generic profile and no master: the precheck reads only the status and running SHA,
# no 0x27 and no board or device-ID read anywhere, and the same download, activate and confirm order.
def test_generic_flash_has_no_security(generic):
    d = FakeServer(security=False)
    rc, _, prerolls = run_flash(d, image=widget_image(), prof=generic, master=None)
    assert rc == 0
    assert d.log == ([(0x22, 0xF1F0), (0x22, 0xF1F3), (0x10, 2), (0x34, None)] + blocks()
                     + [(0x37, None), (0x31, 0xFF01), (0x31, 0xF001)]
                     + [(0x22, 0xF1F3)] * 3 + [(0x10, 3)] + [(0x31, 0xF002)] * 3 + [(0x22, 0xF1F0)])
    assert bytes(d.written) == widget_image() and d.sha == NEW_SHA and d.running_state == 3


# Check a capped activate recovers without security: 0x72 with the boot slot moved gets 10 03 and 11 01, no 0x27.
def test_generic_activate_failure_resets_without_a_key(generic):
    d = FakeServer(security=False, activate_fail="set_boot")
    assert run_flash(d, image=widget_image(), prof=generic, master=None)[0] == 0
    tail = [(0x31, 0xF001), (0x22, 0xF1F0), (0x10, 3), (0x11, 1), (0x22, 0xF1F3)]
    i = d.log.index((0x31, 0xF001))
    assert d.log[i:i + 5] == tail and not any(e[0] == 0x27 for e in d.log)


# Check reset with the generic profile sends 10 03 and 11 01 with no 0x27 and no device-ID read.
def test_generic_reset_has_no_security(generic):
    ft, d = FakeTime(), FakeServer(security=False)
    assert update.reset(uds_for(d, ft), generic, None, log=lambda *a: None) == 0
    assert d.log == [(0x10, 3), (0x11, 1)]


# Check info with the generic profile reads only the server-owned DIDs, in order.
def test_generic_info_reads_core_dids_only(generic):
    ft, lines = FakeTime(), []
    d = FakeServer(security=False, config={0x0200: b"\x00"})
    assert update.info(uds_for(d, ft), generic, log=lines.append) == 0
    assert d.log == [(0x22, did) for did in (0xF186, 0xF189, 0xF18C, 0xF1F3, 0xF1F0, 0xF1F1, 0xF1F2)]


# Check main runs flash end to end with the generic profile: its interface, no master file, exit 0, no 0x27.
def test_main_generic_flash_end_to_end(generic, tmp_path, monkeypatch):
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.0)
    img = tmp_path / "widget.bin"
    img.write_bytes(widget_image())
    d, opened = FakeServer(security=False, boot_silence=0, confirm_refusals=0), []

    # A FakeTransport factory that records the profile and interface main opened it with.
    def fake(prof, interface):
        opened.append((prof.name, interface))
        return FakeTransport(d, interface)

    assert cli.main(["--profile", str(tmp_path / "widget.toml"), "flash", str(img)], transport=fake) == 0
    assert opened == [("widget", "vcan1")] and not any(e[0] == 0x27 for e in d.log)
    assert d.sha == NEW_SHA and d.running_state == 3
