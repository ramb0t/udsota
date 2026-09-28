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
import zlib
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

from udsota import cli, config, errors, keys, profile, transport, update, wire
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
CFG_COMMIT_RID, CFG_HASH_DID, CFG_STATUS_DID = 0x1234, 0xF1B0, 0xF1B2   # CONF's commit routine, hash and status DIDs
CFG_VALUES = {0x0200: b"\x01", 0x0201: b"\x07\xd0", 0x0202: b"\xaa\xbb", 0x0205: b"\x2a"}   # 0x0203 is absent


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
# With cfg_keys it serves config writes: 0x2E stages a value, the commit routine CFG_COMMIT_RID stores the staged
# set (answering 0x78 first), a restart serves the stored values, a session change drops the staged set, and
# CFG_HASH_DID and CFG_STATUS_DID answer the config hash and status. Without cfg_keys, 0x2E answers 0x11.
class FakeServer:
    # Knobs select the faults and states each test needs.
    def __init__(self, max_block=18, boot_silence=2, confirm_refusals=2, running_state=3, sha=OLD_SHA,
                 board=b"devkit", other_state=0, other_sha=bytes(32), lose_76_once=None, mute_block=None,
                 nrc_once=None, activate_refusals=0, ff01_status=0, config=None, lose_77_once=False,
                 lose_ff01_once=False, activate_nrcs=None, activate_fail=None, no_fc=None, security=True,
                 pubkey=None, cfg_keys=None, commit_status=0, compress=False, z_nomem=False):
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
        self.cfg_keys = None if cfg_keys is None else dict(cfg_keys)   # {DID: running value}; None: no config writes
        self.nvs = None if cfg_keys is None else dict(cfg_keys)        # the stored values a restart serves
        self.staged, self.commit_status, self.last_commit = {}, commit_status, 0
        self.compress = compress                # serves DFI 0x10: the blocks carry raw DEFLATE, inflated at 37
        self.z_nomem = z_nomem                  # a DFI 0x10 34 finds no memory: 0x22, F1F1 DL_NO_MEMORY
        self.dfi, self.zin = 0x00, bytearray()  # the open download's format, and its compressed bytes
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
               0x2E: lambda: int.from_bytes(req[1:3], "big"),
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
        if self.nvs is not None:
            self.cfg_keys = dict(self.nvs)
        self.staged = {}

    # 0x10 DiagnosticSessionControl: 50 ss 00 32 01 F4; every session change relocks. 10 02 is
    # refused (0x22) while the boot slot is not the running one, as slots_settled() does.
    def s10(self, req, sub):
        if sub == 2 and self.boot_pending is not None:
            return self.nrc(0x10, 0x22)
        self.session, self.unlocked = sub, 0
        self.staged = {}                                # a session change drops the staged set (the epoch rule)
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
                   0xF1F1: result, 0xF1F2: bytes(16), **(self.cfg_keys or {}), **self.cfg_records(), **self.config}
        if did not in records:
            return self.nrc(0x22, 0x31)
        return [b"\x62" + did.to_bytes(2, "big") + records[did]]

    # The config hash (schema 1, then DID BE16, length and value per key, ascending) and status (staged count,
    # last commit) records when the server has config keys; none otherwise.
    def cfg_records(self):
        if self.cfg_keys is None:
            return {}
        enc = bytes([1]) + b"".join(did.to_bytes(2, "big") + bytes([len(v)]) + v
                                    for did, v in sorted(self.cfg_keys.items()))
        return {CFG_HASH_DID: hashlib.sha256(enc).digest(),
                CFG_STATUS_DID: bytes([len(self.staged), self.last_commit])}

    # 0x2E WriteDataByIdentifier: 0x11 without config keys; else 0x7F in the default session and 0x13 under 4 bytes
    # (the core), then 0x31 outside the extended session or for a DID that is no key, 0x33 without the level-1
    # unlock and 0x13 for a wrong length (the app); stages the value and answers 6E <did>.
    def s2e(self, req, did):
        if self.cfg_keys is None:
            return self.nrc(0x2E, 0x11)
        if self.session == 1:
            return self.nrc(0x2E, 0x7F)
        if len(req) < 4:
            return self.nrc(0x2E, 0x13)
        if self.session != 3 or did not in self.cfg_keys:
            return self.nrc(0x2E, 0x31)
        if self.security and self.unlocked != 1:
            return self.nrc(0x2E, 0x33)
        if len(req) - 3 != len(self.cfg_keys[did]):
            return self.nrc(0x2E, 0x13)
        self.staged[did] = bytes(req[3:])
        return [b"\x6E" + req[1:3]]

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

    # 0x34 RequestDownload: DFI 00 (or 10 with compress), ALFID 44, address 0; answers 74 20 <max_block> and starts
    # a fresh download, which also ends any earlier FF01 pass.
    def s34(self, req, _):
        if req[1] not in ((0x00, 0x10) if self.compress else (0x00,)) or req[2] != 0x44 or req[3:7] != bytes(4):
            return self.nrc(0x34, 0x31)
        if req[1] == 0x10 and self.z_nomem:
            self.last_dl = (14, 0)                      # DL_NO_MEMORY
            return self.nrc(0x34, 0x22)
        self.dfi, self.zin = req[1], bytearray()
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
        if self.dfi == 0x10:
            self.zin += req[2:]
        else:
            self.written += req[2:]
        self.writes += 1
        self.last_dl = (0, len(self.zin) if self.dfi == 0x10 else len(self.written))
        self.last_bsc, self.next_bsc = bsc, (bsc + 1) & 0xFF
        if self.writes == self.lose_76_once:
            self.lose_76_once = None
            return []
        first = [bytes([0x7F, 0x36, 0x78])] if self.writes == 1 else []   # the erase runs under 0x78
        return first + [bytes([0x76, bsc])]

    # 0x37 RequestTransferExit: an open transfer holding every announced byte closes (77), else 0x24.
    def s37(self, req, _):
        if self.dl_open and self.dfi == 0x10:
            z = zlib.decompressobj(-15)
            try:
                out = z.decompress(bytes(self.zin))
            except zlib.error:
                out = b""
            if not z.eof or z.unused_data or len(out) != self.announced:
                self.dl_open, self.last_dl = False, (13, len(self.zin))    # DL_BAD_STREAM
                return self.nrc(0x37, 0x72)
            self.written = bytearray(out)
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
        if rid == CFG_COMMIT_RID and self.cfg_keys is not None:
            if self.security and self.unlocked != 1:
                return self.nrc(0x31, 0x33)
            if not self.staged:
                return self.nrc(0x31, 0x24)
            if self.commit_status:                      # a cross-key rule refused the set: positive, status N
                self.staged = {}
                return [echo + bytes([self.commit_status])]
            self.nvs.update(self.staged)
            self.staged, self.last_commit = {}, 1
            return [bytes([0x7F, 0x31, 0x78]), echo + b"\x00"]   # the write runs under 0x78
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


# A RecordingBus whose nth send raises CanError.
class FailingNthBus(RecordingBus):
    # Fail the send numbered n (1-based).
    def __init__(self, n):
        super().__init__()
        self.n = n

    # Record, or raise on the nth send.
    def send(self, m, timeout=None):
        if len(self.sent) + 1 == self.n:
            self.n = None
            raise can.CanError("tx queue full")
        super().send(m, timeout)


# Check a send that fails in the quieting burst releases what went out and raises; and that a release that fails
# after the update failed never hides the update's error.
def test_quiet_bus_cleans_up_on_send_errors():
    raw = FailingNthBus(3)
    with pytest.raises(can.CanError):
        with transport.QuietBus(transport.GuardedBus(raw, PF), PF, period_s=10, sleep=lambda s: None):
            pass
    assert [bytes(m.data[1:3]) for m in raw.sent] == [b"\x10\x83", b"\x85\x82", b"\x28\x80", b"\x85\x81",
                                                       b"\x10\x81"]
    raw = FailingNthBus(4)
    with pytest.raises(errors.UpdateFailed):
        with transport.QuietBus(transport.GuardedBus(raw, PF), PF, period_s=10, sleep=lambda s: None):
            raise errors.UpdateFailed("the update's own error")


# Check a key flag for the other 0x27 mode is refused, not silently ignored.
def test_key_flag_for_the_other_mode_is_refused():
    import argparse
    hmac_args = argparse.Namespace(master=None, private_key="k.pem")
    with pytest.raises(errors.Refused, match="--private-key is for mode ecdsa"):
        cli.load_secret(P, hmac_args)


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
                "UDSOTA_DL_DFI": "DL_DFI", "UDSOTA_DL_DFI_DEFLATE": "DL_DFI_DEFLATE",
                "UDSOTA_DL_ALFID": "DL_ALFID", "UDSOTA_NRC_BUSY_REPEAT": "NRC_BUSY",
                "UDSOTA_NRC_SERVICE_NOT_SUPPORTED": "NRC_NOT_SUPPORTED",
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
    assert d.log[i:i + 4] == [(0x31, 0xF001), (0x22, 0xF1F3), (0x22, 0xF1F0), (0x31, 0xF001)]
    assert d.writes == 300


# A FakeServer whose first ActivateImage answer is lost after it has activated and, booting at once, restarted.
class LostActivateAnswerFastBoot(FakeServer):
    # Serve the first F001 but drop its answer; everything else as FakeServer.
    def handle(self, req):
        answer = super().handle(req)
        if bytes(req[:4]) == b"\x31\x01\xF0\x01" and not getattr(self, "lost", False):
            self.lost = True
            return []
        return answer


# Check no answer to ActivateImage from a server already running the new image (boot slot == running slot, but
# the new image): it is not sent again, and the update goes on to ConfirmImage.
def test_lost_activate_answer_after_a_fast_restart_is_not_resent():
    d = LostActivateAnswerFastBoot(boot_silence=0)
    rc, _, _ = run_flash(d)
    assert rc == 0
    assert d.log.count((0x31, 0xF001)) == 1 and (0x31, 0xF002) in d.log


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


# ---- config writes: profile ----

# The [security] table of CONF: the udsota-example label, so FakeServer's key vectors unlock it.
CONF_SECURITY = '[security]\nlabel = "udsota-example"\nmaster_file = "master.bin"\n'
# A profile with config writes: four writable keys (u8 with a max only, u16 with a range, a blob, and one u8 the fake
# server does not serve), a read-only u8 DID, a range overlapping them all, and [config] with a status DID and the
# hash over 0x0200-0x020F.
CONF = ('[can]\ninterface = "vcan0"\nreq_id = 0x710\nresp_id = 0x718\n' + CONF_SECURITY + """
[dids]
"0x0200" = { name = "mode", decode = "u8", type = "u8", writable = true, max = 2 }
"0x0201" = { name = "timeout_ms", decode = "u16", type = "u16", writable = true, min = 1000, max = 5000 }
"0x0202" = { name = "tag", decode = "hex", type = "blob", writable = true }
"0x0203" = { name = "spare", decode = "u8", type = "u8", writable = true }
"0x0205" = { name = "limit", decode = "u8" }
"0x0200-0x020F" = { name = "settings", decode = "hex" }

[config]
commit_rid = 0x1234
status_did = 0xF1B2
hash = { did = 0xF1B0, first = 0x0200, last = 0x020F, schema = 1 }
""")
C = profile.from_dict("conf", tomllib.loads(CONF))
# The start of a one-key [dids] table after CAN (the [can] table above): the base of the refusal cases.
KEY = '[dids]\n"0x0200" = { name = "mode", decode = "u8", '


# Check CONF's typed entries (an absent min or max stays None), the overlapping range, and its [config]; FULL has
# no config and no typed DID.
def test_config_profile_values():
    assert [(e.first, e.last, e.name, e.decode, e.type, e.writable, e.min, e.max) for e in C.dids] == [
        (0x0200, 0x0200, "mode", "u8", "u8", True, None, 2),
        (0x0201, 0x0201, "timeout_ms", "u16", "u16", True, 1000, 5000),
        (0x0202, 0x0202, "tag", "hex", "blob", True, None, None),
        (0x0203, 0x0203, "spare", "u8", "u8", True, None, None),
        (0x0205, 0x0205, "limit", "u8", None, False, None, None),
        (0x0200, 0x020F, "settings", "hex", None, False, None, None)]
    assert C.config == profile.ConfigSpec(0x1234, 0xF1B2, profile.HashSpec(0xF1B0, 0x0200, 0x020F, 1))
    assert P.config is None and not any(e.writable or e.type for e in P.dids)


# Check a broken [config] or typed [dids] entry is refused with its reason: each case breaks one rule.
@pytest.mark.parametrize("text,why", [
    (CAN + "[config]\ncommit_rid = 0x1234\nrid = 1\n", r"unknown key rid in \[config\]"),
    (CAN + "[config]\nstatus_did = 0xF1B2\n", "missing commit_rid"),
    (CAN + "[config]\ncommit_rid = 0x1234\nhash = { did = 0xF1B0, first = 0x0200, last = 0x020F, schema = 1, "
           "size = 2 }\n", "hash must be"),
    (CAN + "[config]\ncommit_rid = 0x1234\nhash = { did = 0xF1B0, first = 0x0200, last = 0x020F }\n",
     "missing schema"),
    (CAN + "[config]\ncommit_rid = 0x1234\nhash = { did = 0xF1B0, first = 0x0210, last = 0x020F, schema = 1 }\n",
     "first 0x0210 is above last 0x020F"),
    (CAN + KEY + 'type = "u8", writable = true, size = 1 }\n', r"must be \{ name"),
    (CAN + '[dids]\n"0x0200-0x0203" = { name = "mode", decode = "u8", type = "u8", writable = true }\n',
     "a writable entry is one DID"),
    (CAN + KEY + "writable = true }\n", "needs a type"),
    (CAN + KEY + 'type = "u32" }\n', "type must be one of"),
    (CAN + KEY + 'type = "u8", writable = 1 }\n', "writable must be true or false"),
    (CAN + KEY + 'type = "blob", writable = true, min = 1 }\n', "min and max need type u8 or u16"),
    (CAN + KEY + 'type = "u8", writable = true, min = 9, max = 2 }\n', "min 9 is above max 2"),
    (CAN + KEY + 'type = "u8", writable = true, max = 0x100 }\n', "max must be an integer from 0x0 to 0xFF"),
    (CAN + '[dids]\n"0x0200" = { name = "a b", decode = "u8", type = "u8", writable = true }\n',
     "letters, digits and _"),
    (CAN + KEY + 'type = "u8", writable = true }\n"0x0201" = { name = "mode", decode = "u8", type = "u8", '
                 "writable = true }\n", "two writable keys are named mode"),
    (CAN + "[config]\ncommit_rid = 0x10000\n", "commit_rid must be an integer from 0x0 to 0xFFFF"),
    (CAN + "[config]\ncommit_rid = 0x1234\nstatus_did = 0x10000\n", "status_did must be an integer from 0x0 to 0xFFFF"),
    (CAN + KEY.replace('"u8", ', '"u16", ') + 'type = "u16", writable = true, max = 0x10000 }\n',
     "max must be an integer from 0x0 to 0xFFFF"),
    (CAN + "[config]\ncommit_rid = 0x1234\nhash = { did = 0x0205, first = 0x0200, last = 0x020F, schema = 1 }\n",
     "hash did 0x0205 is inside first..last"),
    (CAN + "[config]\ncommit_rid = 0x1234\nstatus_did = 0x020F\n"
           "hash = { did = 0xF1B0, first = 0x0200, last = 0x020F, schema = 1 }\n",
     r"status_did 0x020F is inside the hash range 0x0200\.\.0x020F"),
])
def test_bad_config_profiles_are_refused(text, why):
    with pytest.raises(errors.Refused, match=why):
        profile.from_dict("bad", tomllib.loads(text))


# Check the example's commented writable DIDs and [config] load once uncommented, so the syntax it documents is valid.
def test_example_config_comments_load():
    text = (profile.PROFILE_DIR / "example.toml").read_text()
    live = re.sub(r'(?m)^# (?=(?:"0x020[01]" |\[config\]$|commit_rid |status_did |hash ))', "", text)
    e = profile.from_dict("example", tomllib.loads(live))
    assert [(d.name, d.type, d.min, d.max) for d in e.dids if d.writable] == [("mode", "u8", None, 2),
                                                                            ("timeout_ms", "u16", 1000, 5000)]
    assert e.config == profile.ConfigSpec(0x1234, 0xF1B2, profile.HashSpec(0xF1B0, 0x0200, 0x02FF, 1))


# ---- config writes: decoders ----

# Check u8 and u16 print as decimal, and a record of another length falls back to hex.
def test_u8_u16_decoders():
    assert (update.DECODE["u8"](b"\x2a"), update.DECODE["u16"](b"\x0b\xb8")) == ("42", "3000")
    assert (update.DECODE["u8"](b"\x01\x02"), update.DECODE["u16"](b"\x05")) == ("01 02", "05")


# Check info decodes CONF's u8 and u16 DIDs as decimal, a blob as hex, and reports the key the server lacks.
def test_info_decodes_u8_and_u16():
    ft, lines = FakeTime(), []
    d = FakeServer(cfg_keys=CFG_VALUES)
    assert update.info(uds_for(d, ft), C, log=lines.append) == 0
    assert {"0200 mode: 1", "0201 timeout_ms: 2000", "0202 tag: aa bb", "0203 spare: not supported",
            "0205 limit: 42"} <= set(lines)


# ---- config writes: set and show ----

UNLOCK_EXT = [(0x22, 0xF18C), (0x10, 3), (0x27, 1), (0x27, 2)]
HASH_READS = [(0x22, did) for did in range(0x0200, 0x0210)] + [(0x22, CFG_HASH_DID)]


# Run config set on server with profile C (or prof) and fake time; returns (rc, log lines, fake time).
def run_config_set(server, args, prof=C, master=MASTER, commit=True, reset=True):
    ft, lines = FakeTime(), []
    writes = config.parse_writes(prof, args, commit, reset)
    rc = config.config_set(uds_for(server, ft), prof, writes, master, commit=commit, reset=reset,
                           sleep=ft.sleep, clock=ft.clock, log=lines.append)
    return rc, lines, ft


# Check config set's values encode by type (u8 one byte; u16 big-endian, decimal or 0x hex; blob from hex digits),
# in argument order.
def test_parse_writes_encodes_each_type():
    writes = config.parse_writes(C, ["timeout_ms=0xBB8", "mode=2", "tag=0A1b"], commit=True, reset=True)
    assert [(e.name, v) for e, v in writes] == [("timeout_ms", b"\x0b\xb8"), ("mode", b"\x02"), ("tag", b"\x0a\x1b")]


# Check each bad argument is refused with its reason: an unknown, malformed or read-only name, a value that is no
# integer, one outside the write range, bad hex, and a repeated name.
@pytest.mark.parametrize("args,why", [
    (["nosuch=1"], "is not NAME=VALUE for a writable key"),
    (["mode"], "is not NAME=VALUE"),
    (["limit=1"], "is not NAME=VALUE"),
    (["mode=x"], "mode takes an integer"),
    (["mode=3"], r"mode = 3 is outside 0\.\.2"),
    (["timeout_ms=999"], r"timeout_ms = 999 is outside 1000\.\.5000"),
    (["tag=0g"], "tag takes hex bytes"),
    (["mode=1", "mode=2"], "mode is given twice"),
])
def test_parse_writes_refuses(args, why):
    with pytest.raises(errors.Refused, match=why):
        config.parse_writes(C, args, commit=False, reset=False)


# Check set --commit --reset: device ID, 10 03 and the level-1 unlock, a 2E per key in argument order, the commit
# (0x78, then 00), keyed 11 01, the restart poll, the read-back and the hash over 0x0200-0x020F, which skips the
# absent DIDs and includes 0x0205, a DID the profile does not mark writable. The device hash is a pinned vector.
def test_config_set_commit_reset_reads_back_and_checks_the_hash():
    d = FakeServer(cfg_keys=CFG_VALUES)
    rc, lines, ft = run_config_set(d, ["timeout_ms=3000", "mode=2"])
    assert rc == 0
    assert d.log == (UNLOCK_EXT + [(0x2E, 0x0201), (0x2E, 0x0200), (0x31, CFG_COMMIT_RID), (0x11, 1)]
                     + [(0x22, 0xF1F3)] * 3 + [(0x22, 0x0201), (0x22, 0x0200)] + HASH_READS)
    assert d.cfg_keys == {**CFG_VALUES, 0x0200: b"\x02", 0x0201: b"\x0b\xb8"}
    assert ft.sleeps == [update.REBOOT_WAIT_S] + [update.BOOT_POLL_S] * 2
    assert lines == ["staged timeout_ms = 3000", "staged mode = 2", "committed; the server restarts",
                     "0201 timeout_ms: 3000", "0200 mode: 2",
                     "F1B0 config hash: a96b56dc2467c1fd56c8c5a22018142e9bbd5453f8b8ecb6d0dd5d901a8bc6d6 matches "
                     "the values read"]


# Check the recomputed hash against a pinned vector: SHA-256 of 01 | 0200 01 01 | 0201 02 07d0 | 0202 02 aabb |
# 0205 01 2a, the DIDs the server answers in 0x0200-0x020F. The scan reads past the gap at 0x0203.
def test_config_hash_matches_a_pinned_vector():
    ft, d = FakeTime(), FakeServer(cfg_keys=CFG_VALUES)
    assert config.compute_hash(uds_for(d, ft), C.config.hash).hex() == \
        "15bb680574feb9237e6d462886579533df0de8f18d62e71b6489a3e7bf8aebc3"
    assert d.log == HASH_READS[:-1]


# Check set without --commit only stages: nothing is stored, and the tool says the values die with the session.
def test_config_set_without_commit_only_stages():
    d = FakeServer(cfg_keys=CFG_VALUES)
    rc, lines, _ = run_config_set(d, ["mode=2"], commit=False, reset=False)
    assert rc == 0 and d.log == UNLOCK_EXT + [(0x2E, 0x0200)]
    assert d.staged == {0x0200: b"\x02"} and d.nvs == CFG_VALUES
    assert lines[-1] == "not committed: the staged values are dropped when the session ends"


# Check set --commit without --reset stores the values (the commit answers 0x78, then 00) and sends no 11 01; the
# server runs the old values until it restarts.
def test_config_set_commit_without_reset():
    d = FakeServer(cfg_keys=CFG_VALUES)
    rc, lines, _ = run_config_set(d, ["mode=2"], reset=False)
    assert rc == 0 and d.log == UNLOCK_EXT + [(0x2E, 0x0200), (0x31, CFG_COMMIT_RID)]
    assert d.nvs[0x0200] == b"\x02" and d.cfg_keys[0x0200] == b"\x01"
    assert lines[-1] == "committed: the new values apply at the next restart"


# Check a commit reporting status 3 exits 1 naming the status, after reading the status DID; nothing is stored.
def test_config_set_commit_status_fails():
    d = FakeServer(cfg_keys=CFG_VALUES, commit_status=3)
    with pytest.raises(errors.UpdateFailed, match="reported status 3") as e:
        run_config_set(d, ["mode=2"])
    assert e.value.exit_code == 1 and d.nvs == CFG_VALUES
    assert d.log[-2:] == [(0x31, CFG_COMMIT_RID), (0x22, CFG_STATUS_DID)]


# Check 0x72 to the commit exits 1 after reading the status DID, which says whether the write landed. A status
# read that fails too (here 0x22) does not mask the commit's 0x72.
def test_config_set_commit_programming_failure():
    d = FakeServer(cfg_keys=CFG_VALUES, nrc_once={(0x31, CFG_COMMIT_RID): 0x72, (0x22, CFG_STATUS_DID): 0x22})
    with pytest.raises(errors.UpdateFailed, match="answered NRC 0x72") as e:
        run_config_set(d, ["mode=2"])
    assert e.value.exit_code == 1 and d.log[-2:] == [(0x31, CFG_COMMIT_RID), (0x22, CFG_STATUS_DID)]


# Check a keyed 11 01 refused with 0x22 exits 1, saying the values are committed and apply at the next restart.
def test_config_set_reset_refused():
    d = FakeServer(cfg_keys=CFG_VALUES, nrc_once={(0x11, 1): 0x22})
    with pytest.raises(errors.UpdateFailed, match="committed, but the reset was refused"):
        run_config_set(d, ["mode=2"])
    assert d.nvs[0x0200] == b"\x02" and d.log[-1] == (0x11, 1)


# Check a key that reads back other than written after the restart exits 1 naming it, before the hash is read.
def test_config_set_read_back_mismatch():
    d = FakeServer(cfg_keys=CFG_VALUES, config={0x0201: b"\x07\xd0"})   # 0x0201 keeps serving 2000
    with pytest.raises(errors.UpdateFailed, match="timeout_ms reads 2000, not 3000"):
        run_config_set(d, ["timeout_ms=3000"])
    assert d.log[-1] == (0x22, 0x0201)


# Check a device hash that differs from the one recomputed from the DIDs read exits 1 with both.
def test_config_set_hash_mismatch():
    d = FakeServer(cfg_keys=CFG_VALUES, config={CFG_HASH_DID: bytes(32)})
    with pytest.raises(errors.UpdateFailed, match="config hash F1B0 reads 0{64} but the values read hash to a96b56dc"):
        run_config_set(d, ["timeout_ms=3000", "mode=2"])


# Check a key the server refuses with 0x31 exits 1 naming it, not 2: that server does serve 0x2E.
def test_config_set_key_refused_by_the_server():
    d = FakeServer(cfg_keys=CFG_VALUES)
    with pytest.raises(errors.UpdateFailed, match=r"writing spare \(0x0203\) answered NRC 0x31") as e:
        run_config_set(d, ["mode=2", "spare=1"])
    assert e.value.exit_code == 1 and d.log[-1] == (0x2E, 0x0203) and d.nvs == CFG_VALUES


# Check set with a profile without [security]: 10 03 with no device-ID read and no 0x27, then the 2E and the commit.
def test_config_set_without_security():
    nosec = profile.from_dict("nosec", tomllib.loads(CONF.replace(CONF_SECURITY, "")))
    d = FakeServer(security=False, cfg_keys=CFG_VALUES)
    rc, _, _ = run_config_set(d, ["mode=2"], prof=nosec, master=None, reset=False)
    assert rc == 0 and d.log == [(0x10, 3), (0x2E, 0x0200), (0x31, CFG_COMMIT_RID)] and d.nvs[0x0200] == b"\x02"


# Check config show reads each writable key with its range, the status DID and the hash check, with no session change.
def test_config_show():
    ft, lines = FakeTime(), []
    d = FakeServer(cfg_keys=CFG_VALUES)
    assert config.config_show(uds_for(d, ft), C, log=lines.append) == 0
    assert d.log == [(0x22, did) for did in (0x0200, 0x0201, 0x0202, 0x0203, CFG_STATUS_DID)] + HASH_READS
    assert lines == ["0200 mode: 1 (0..2)", "0201 timeout_ms: 2000 (1000..5000)", "0202 tag: aa bb",
                     "0203 spare: not supported (0..255)", "F1B2 config status: 00 00",
                     "F1B0 config hash: 15bb680574feb9237e6d462886579533df0de8f18d62e71b6489a3e7bf8aebc3 "
                     "(matches the values read)"]


# ---- config writes: main ----

# CONF and the master key in tmp_path, for the tests that pass --profile to main; returns the profile path.
@pytest.fixture
def conf_path(tmp_path):
    (tmp_path / "master.bin").write_bytes(MASTER)
    p = tmp_path / "conf.toml"
    p.write_text(CONF)
    return str(p)


# Check a config set whose arguments break the profile is refused (exit 2) before any bus opens.
@pytest.mark.parametrize("args,why", [
    (["nosuch=1"], "is not NAME=VALUE"),
    (["mode=x"], "mode takes an integer"),
    (["timeout_ms=6000"], r"outside 1000\.\.5000"),
    (["mode=1", "--reset"], "--reset needs --commit"),
])
def test_main_config_set_refuses_before_opening_the_bus(conf_path, capsys, args, why):
    master = str(pathlib.Path(conf_path).parent / "master.bin")
    assert cli.main(["--profile", conf_path, "--master", master, "config", "set"] + args,
                    transport=no_transport) == 2
    assert re.search(why, capsys.readouterr().err)


# Check --commit without [config], a missing master for set, and show on a profile with no writable DID are refused
# (exit 2) before any bus opens.
def test_main_config_refusals(tmp_path, conf_path, capsys):
    noconf = tmp_path / "noconf.toml"
    noconf.write_text(CONF.split("[config]")[0])
    assert cli.main(["--profile", str(noconf), "--master", str(tmp_path / "master.bin"), "config", "set", "mode=1",
                     "--commit"], transport=no_transport) == 2
    assert "--commit needs a [config] table" in capsys.readouterr().err
    assert cli.main(["--profile", conf_path, "--master", str(tmp_path / "absent"), "config", "set", "mode=1"],
                    transport=no_transport) == 2
    assert "cannot read the master key" in capsys.readouterr().err
    widget = tmp_path / "widget.toml"
    widget.write_text(GENERIC)
    assert cli.main(["--profile", str(widget), "config", "show"], transport=no_transport) == 2
    assert "has no writable [dids] entry" in capsys.readouterr().err


# Check main's exit code for config set against three servers. A 2E answered 0x11, or a commit routine answered
# 0x31, means the firmware has no config writes (exit 2). A 2E refused with 0x31 is the server refusing a key (exit 1).
@pytest.mark.parametrize("server_kw,args,rc,text,last", [
    ({}, ["mode=1", "--commit"], 2, "this firmware has no config writes", (0x2E, 0x0200)),
    ({"cfg_keys": CFG_VALUES, "nrc_once": {(0x31, CFG_COMMIT_RID): 0x31}}, ["mode=1", "--commit"], 2,
     "this firmware has no config writes", (0x31, CFG_COMMIT_RID)),
    ({"cfg_keys": CFG_VALUES}, ["spare=1", "--commit"], 1, r"writing spare \(0x0203\) answered NRC 0x31",
     (0x2E, 0x0203)),
])
def test_main_config_set_exit_codes(conf_path, capsys, server_kw, args, rc, text, last):
    d = FakeServer(**server_kw)
    master = str(pathlib.Path(conf_path).parent / "master.bin")
    assert cli.main(["--profile", conf_path, "--master", master, "config", "set"] + args,
                    transport=lambda p, i: FakeTransport(d, i)) == rc
    assert re.search(text, capsys.readouterr().err) and d.log[-1] == last
    assert d.nvs is None or d.nvs == CFG_VALUES


# Check config show runs end to end through main without any master file and exits 0.
def test_main_config_show_end_to_end(conf_path, capsys):
    d = FakeServer(cfg_keys=CFG_VALUES)
    assert cli.main(["--profile", conf_path, "config", "show"], transport=lambda p, i: FakeTransport(d, i)) == 0
    assert "0201 timeout_ms: 2000 (1000..5000)" in capsys.readouterr().out



# ---- config writes: review follow-ups ----

# CONF with [security] in the ecdsa mode.
CONF_ECDSA = CONF.replace(CONF_SECURITY, '[security]\nmode = "ecdsa"\nprivate_key_file = "udsota_private.pem"\n')


# Check main runs config set --commit with an ecdsa profile and --private-key (the value is stored), and that
# --master on that profile is refused (exit 2) before the bus opens.
def test_main_ecdsa_config_set(tmp_path, capsys):
    p = tmp_path / "conf-ecdsa.toml"
    p.write_text(CONF_ECDSA)
    private, _ = keys.keygen(tmp_path / "keys")
    d = FakeServer(pubkey=keys.public_point(keys.load_private_key(private)), cfg_keys=CFG_VALUES)
    assert cli.main(["--profile", str(p), "--private-key", str(private), "config", "set", "mode=2", "--commit"],
                    transport=lambda prof, i: FakeTransport(d, i)) == 0
    assert d.nvs[0x0200] == b"\x02" and d.log[:4] == UNLOCK_EXT
    master = tmp_path / "master.bin"
    master.write_bytes(MASTER)
    assert cli.main(["--profile", str(p), "--master", str(master), "config", "set", "mode=2", "--commit"],
                    transport=no_transport) == 2
    assert "--master is for mode hmac" in capsys.readouterr().err


# Check config show on firmware without config writes (every key answers 0x31) exits 2 as set does, after reading
# the keys only. The fake still serves F1B0 (CONF's hash DID) from its base records, so the refusal must come from
# the keys, not from a failed hash or status read.
def test_main_config_show_without_config_writes(conf_path, capsys):
    d = FakeServer()
    assert cli.main(["--profile", conf_path, "config", "show"], transport=lambda p, i: FakeTransport(d, i)) == 2
    assert "this firmware has no config writes" in capsys.readouterr().err
    assert d.log == [(0x22, did) for did in (0x0200, 0x0201, 0x0202, 0x0203)]


# Check the boot wait's timeout names what restarted the server: ActivateImage for flash, the reset for config set.
def test_boot_wait_timeouts_name_their_cause():
    ft = FakeTime()

    # A server that never answers again.
    class Gone:
        # Every read times out.
        def read_did(self, did):
            raise errors.NoResponse("no answer")

    with pytest.raises(errors.UpdateFailed, match="did not answer within 60 s of ActivateImage$"):
        update.wait_for_image(Gone(), NEW_SHA, lambda: None, sleep=ft.sleep, clock=ft.clock)
    d = FakeServer(cfg_keys=CFG_VALUES, boot_silence=10 ** 6)
    with pytest.raises(errors.UpdateFailed, match="did not answer within 60 s of the reset$"):
        run_config_set(d, ["mode=2"])
    assert d.nvs[0x0200] == b"\x02"


# Check main hands the transport's pre-roll to config set --reset: once per poll of the restarting server. main
# waits in real time, so the boot waits are zeroed.
def test_main_config_set_prerolls_the_restart(conf_path, monkeypatch):
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0)
    monkeypatch.setattr(update, "BOOT_POLL_S", 0)
    d, prerolls = FakeServer(cfg_keys=CFG_VALUES), []

    # FakeTransport that counts its pre-rolls.
    class Counting(FakeTransport):
        # Record one pre-roll.
        def preroll(self):
            prerolls.append(1)

    master = str(pathlib.Path(conf_path).parent / "master.bin")
    assert cli.main(["--profile", conf_path, "--master", master, "config", "set", "mode=2", "--commit", "--reset"],
                    transport=lambda p, i: Counting(d, i)) == 0
    assert len(prerolls) == 3 and d.cfg_keys[0x0200] == b"\x02"


# Check the write range's ends: min and max themselves are accepted, and a u16 without max takes 0..0xFFFF.
def test_parse_writes_accepts_the_range_ends():
    writes = config.parse_writes(C, ["timeout_ms=1000", "mode=0"], commit=False, reset=False)
    assert [v for _, v in writes] == [b"\x03\xe8", b"\x00"]
    assert config.parse_writes(C, ["timeout_ms=5000"], commit=False, reset=False)[0][1] == b"\x13\x88"
    wide = profile.from_dict("wide", tomllib.loads(
        CAN + '[dids]\n"0x0200" = { name = "w", decode = "u16", type = "u16", writable = true }\n'))
    assert config.parse_writes(wide, ["w=0xFFFF"], commit=False, reset=False)[0][1] == b"\xff\xff"
    with pytest.raises(errors.Refused, match=r"w = 65536 is outside 0\.\.65535"):
        config.parse_writes(wide, ["w=0x10000"], commit=False, reset=False)


# Check a 6E answer echoing another DID fails the write (exit 1).
def test_write_echo_for_another_did_fails():
    d = FakeServer(cfg_keys=CFG_VALUES)
    d.s2e = lambda req, did: [b"\x6E\x02\x01"]
    with pytest.raises(errors.UpdateFailed, match="write echo 0201 does not match 0x0200"):
        run_config_set(d, ["mode=2"])


# Check a commit refused with 0x24 (a session change dropped the staged set) exits 1 and says to run set again.
def test_config_set_commit_sequence_error():
    d = FakeServer(cfg_keys=CFG_VALUES, nrc_once={(0x31, CFG_COMMIT_RID): 0x24})
    with pytest.raises(errors.UpdateFailed, match=r"answered NRC 0x24: the staged values were dropped \(the session "
                                                  r"changed\); run config set again") as e:
        run_config_set(d, ["mode=2"])
    assert e.value.exit_code == 1 and d.nvs == CFG_VALUES

# ---- compressed downloads (DFI 0x10) ----

# The raw DEFLATE stream at level 9, made here rather than by update.deflate, so a change of level there shows.
def deflate9(image):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(image) + c.flush()


# Check flash with compress "deflate" sends 34 10 44 announcing the image's own size, then the level-9 raw DEFLATE
# stream in fewer blocks, counting progress in compressed bytes, and the server's slot ends up holding the image.
def test_flash_compressed_sends_a_deflate_stream():
    d, lines = FakeServer(compress=True), []
    ft = FakeTime()
    rc = update.flash(uds_for(d, ft), P, make_image(), MASTER, sleep=ft.sleep, clock=ft.clock, log=lines.append,
                      compress="deflate")
    z = deflate9(make_image())
    assert rc == 0 and d.dfi == 0x10 and d.announced == 4800
    assert bytes(d.zin) == z
    assert bytes(d.written) == make_image() and d.writes == (len(z) + 15) // 16 < 300
    assert "sent %d of %d bytes" % (len(z), len(z)) in lines
    assert not any("of 4800 bytes" in ln for ln in lines)


# Check the ratio line and the time-saved line, exactly, over a download that took 2 s by the clock.
def test_compressed_download_reports_ratio_and_time_saved():
    d, lines = FakeServer(compress=True, security=False), []
    uds = uds_for(d, FakeTime())
    uds.session(2)
    update.download(uds, make_image(), log=lines.append, compress="deflate", clock=iter([100.0, 102.0]).__next__)
    z = len(deflate9(make_image()))
    assert lines[0] == "compressed with raw DEFLATE: 4800 -> %d bytes (%.0f%%)" % (z, 100.0 * z / 4800)
    assert lines[-1] == ("sent %d compressed bytes in 2.0 s; the 4800-byte image would take about %.1f s, so about "
                         "%.1f s saved" % (z, 2.0 * 4800 / z, 2.0 * (4800 - z) / z))
    assert 2.0 * (4800 - z) / z > 0


# Check a lost 77 on a compressed download: the resent 37 meets 0x24, F1F1 reads DL_OK with every compressed byte,
# and the update completes.
def test_compressed_lost_77_resend_reads_result_and_continues():
    d = FakeServer(compress=True, lose_77_once=True)
    assert run_flash(d, compress="deflate")[0] == 0
    assert [e for e in d.log if e[0] == 0x37] == [(0x37, None)] * 2
    assert bytes(d.written) == make_image()


# Check "deflate" against a server without compressed downloads stops before any 0x36, naming both causes a 0x31 can
# have (Refused: exit 2).
def test_compress_on_a_server_without_it_is_refused():
    d = FakeServer()
    with pytest.raises(errors.Refused, match="the server has no compressed downloads, or the image is larger than its "
                                             "slot"):
        run_flash(d, compress="deflate")
    assert not any(e[0] == 0x36 for e in d.log)


# Check "auto" against a server without compressed downloads falls back to the uncompressed download, says why, and
# prints no ratio for a stream it never sent.
def test_compress_auto_falls_back_to_uncompressed():
    d, lines = FakeServer(), []
    ft = FakeTime()
    assert update.flash(uds_for(d, ft), P, make_image(), MASTER, sleep=ft.sleep, clock=ft.clock, log=lines.append,
                        compress="auto") == 0
    assert [e for e in d.log if e[0] == 0x34] == [(0x34, None)] * 2
    assert bytes(d.written) == make_image() and d.writes == 300
    assert ("the server has no compressed downloads, or the image is larger than its slot: sending the image "
            "uncompressed") in lines
    assert not any(ln.startswith("compressed with raw DEFLATE") for ln in lines)


# Check a 0x22 at the compressed 34 with F1F1 DL_NO_MEMORY: "deflate" stops naming it and hinting at a plain flash,
# and "auto" falls back to the uncompressed download.
def test_compressed_34_without_memory():
    d = FakeServer(compress=True, z_nomem=True)
    with pytest.raises(errors.UpdateFailed, match="0x22, F1F1 DL_NO_MEMORY.*a plain flash"):
        run_flash(d, compress="deflate")
    assert not any(e[0] == 0x36 for e in d.log)
    d, lines = FakeServer(compress=True, z_nomem=True), []
    ft = FakeTime()
    assert update.flash(uds_for(d, ft), P, make_image(), MASTER, sleep=ft.sleep, clock=ft.clock, log=lines.append,
                        compress="auto") == 0
    assert d.dfi == 0x00 and bytes(d.written) == make_image()
    assert "the server has no memory for a compressed download now: sending the image uncompressed" in lines


# Check "auto" falls back only for those refusals: a gate's 0x22 at the compressed 34 (F1F1 not DL_NO_MEMORY) stops
# the run with that NRC.
def test_compress_auto_does_not_fall_back_on_other_refusals():
    d = FakeServer(compress=True, nrc_once={(0x34, None): 0x22})
    with pytest.raises(errors.Nrc) as e:
        run_flash(d, compress="auto")
    assert (e.value.sid, e.value.code) == (0x34, 0x22)
    assert [x for x in d.log if x[0] == 0x34] == [(0x34, None)]


# Check a lost 76 mid-stream is resent once and the server takes the repeat without adding it to the stream.
def test_compressed_lost_76_is_resent_once():
    d = FakeServer(compress=True, lose_76_once=3)
    assert run_flash(d, compress="deflate")[0] == 0
    assert [e for e in d.log if e[0] == 0x36].count((0x36, 3)) == 2
    assert bytes(d.written) == make_image()


# Check --drop-76 past the last compressed block is refused naming the download's block count, not the image's.
def test_compressed_drop_76_past_the_last_block_is_refused():
    d = FakeServer(compress=True)
    blocks_ = (len(deflate9(make_image())) + 15) // 16
    with pytest.raises(errors.Refused, match="the download is only %d blocks of 16 bytes" % blocks_):
        run_flash(d, compress="deflate", drop_76=blocks_ + 1)


# Check a stream the server cannot inflate to the announced size fails at 37 (0x72), and the error names F1F1's reason.
def test_compressed_stream_failure_names_the_reason(monkeypatch):
    monkeypatch.setattr(update, "deflate", lambda image: zlib.compress(image)[2:-10])   # cut short
    d = FakeServer(compress=True)
    with pytest.raises(errors.UpdateFailed, match="0x72.*DL_BAD_STREAM"):
        run_flash(d, compress="deflate")


# Check the profile's [image] compression picks the mode when no flag is given, and --no-compress's "none" wins.
def test_profile_compression_is_the_default(tmp_path):
    prof = profile.from_dict("z", tomllib.loads(FULL.replace("[image]\n", '[image]\ncompression = "deflate"\n')))
    assert prof.compression == "deflate"
    d = FakeServer(compress=True)
    assert run_flash(d, prof=prof)[0] == 0 and d.dfi == 0x10
    d = FakeServer(compress=True)
    assert run_flash(d, prof=prof, compress="none")[0] == 0 and d.dfi == 0x00
    auto = profile.from_dict("a", tomllib.loads(FULL.replace("[image]\n", '[image]\ncompression = "auto"\n')))
    assert auto.compression == "auto" and P.compression == "none"
    with pytest.raises(errors.Refused, match="compression must be one of none, deflate, auto"):
        profile.from_dict("b", tomllib.loads(FULL.replace("[image]\n", '[image]\ncompression = "on"\n')))


# Check the flags: --compress, --compress-auto and --no-compress give deflate, auto and none, none of them takes the
# file name as its value, and without one the profile decides (None).
@pytest.mark.parametrize("argv, mode", [(["flash", "x.bin"], None),
                                        (["flash", "--compress", "x.bin"], "deflate"),
                                        (["flash", "x.bin", "--compress"], "deflate"),
                                        (["flash", "--compress-auto", "x.bin"], "auto"),
                                        (["flash", "--no-compress", "x.bin"], "none")])
def test_compress_flags(argv, mode):
    args = cli.parse_args(["--profile", "example", *argv])
    assert (args.compress, str(args.file)) == (mode, "x.bin")


# Check the three flags exclude each other.
def test_compress_flags_exclude_each_other(capsys):
    with pytest.raises(SystemExit):
        cli.parse_args(["--profile", "example", "flash", "x.bin", "--compress", "--no-compress"])
    assert "not allowed with" in capsys.readouterr().err


# Check main exits 2 with the server's missing compression named when --compress meets a server without it.
def test_main_compress_on_a_server_without_it_exits_2(tmp_path, full_path, capsys):
    img, master = tmp_path / "i.bin", tmp_path / "m.bin"
    img.write_bytes(make_image())
    master.write_bytes(MASTER)
    d = FakeServer()
    rc = cli.main(["--profile", full_path, "--master", str(master), "flash", "--compress", str(img)],
                  transport=lambda prof, interface: FakeTransport(d, interface))
    assert rc == 2 and "the server has no compressed downloads" in capsys.readouterr().err
