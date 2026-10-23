"""End-to-end tests: the client (cli.main, update's steps and the Uds layer, over can-isotp's Python ISO-TP stack)
against udsota_lite_server, which runs udsota on unmodified iso14229 as an app does, its CAN frames on its stdin and
stdout. The top-level CMakeLists.txt builds it. $UDSOTA_LITE_SERVER names the binary, and then a missing one fails;
without it, build/udsota_lite_server runs when it is built, and the module skips when it is not."""
import hashlib
import importlib.util
import json
import os
import pathlib
import random
import time

import pytest
from udsoncan.BaseService import BaseService

from udsota import cli, delta, pack, profile, uds, update, wire
from udsota.errors import NoResponse, Nrc

from .demo_server import (EXAMPLE, LABEL, MASTER, SECURED, DemoServer, PipeTransport, build_image, elf_sha,
                          image_file, read_state, run_cli)

BUILT = pathlib.Path(__file__).resolve().parents[2] / "build" / "udsota_lite_server"
OLD = "v0.1.0"                     # the image slot 0 runs when the server starts
VALID, PENDING, ROLLED_BACK = 3, wire.IMG_PENDING_VERIFY, 4   # F1F0 running_state VALID, other_slot_state INVALID
SOAK_MS = 7000                     # the app's soak before F002 passes: longer than iso14229's S3 (5.1 s)
# SECURED with the app's config keys and [config], as the example profile's commented ones, but the hash over
# 0x0200-0x020F, so its check reads 16 DIDs rather than 256.
CONFIG = SECURED + """
[dids]
"0x0200" = { name = "mode", decode = "u8", type = "u8", writable = true, max = 2 }
"0x0201" = { name = "timeout_ms", decode = "u16", type = "u16", writable = true, min = 1000, max = 5000 }

[config]
commit_rid = 0x1234
status_did = 0xF1B2
hash = { did = 0xF1B0, first = 0x0200, last = 0x020F, schema = 1 }
"""


# The server: $UDSOTA_LITE_SERVER, which must then be there; else build/udsota_lite_server; else a skip.
@pytest.fixture(scope="module")
def binary():
    env = os.environ.get("UDSOTA_LITE_SERVER")
    if env:
        if not os.access(env, os.X_OK):
            pytest.fail("UDSOTA_LITE_SERVER=%s is not an executable file" % env)
        return env
    if not os.access(BUILT, os.X_OK):
        pytest.skip("udsota_lite_server is not built: cmake -S . -B build && cmake --build build --target "
                    "udsota_lite_server (or set UDSOTA_LITE_SERVER)")
    return str(BUILT)


# Starts servers for a test, each with slot 0 running OLD, and stops them after it; each must exit 0, so a sanitizer
# report fails the test. The client's waits follow the server's pace: a restart takes it 0.3 s (the client waits
# 0.5 s, not 3 s), and a 0x37 is waited out for one keepalive period, not 10 s.
@pytest.fixture
def lite(binary, tmp_path, monkeypatch):
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.5)
    monkeypatch.setattr(uds, "SA_DELAY_S", uds.KEEPALIVE_S)
    servers = []

    def start(*args):
        n = len(servers)
        image = image_file(tmp_path, build_image(OLD), "running%d.bin" % n)
        servers.append(DemoServer(binary, ["--image", image, *args], tmp_path / ("server%d.log" % n)))
        return servers[-1]

    yield start
    for s in servers:
        assert s.stop() == 0, s.log()


# The path of profile text (SECURED or CONFIG) written under tmp_path, with MASTER as its master file.
def secured(tmp_path, text=SECURED):
    master, path = tmp_path / "master.bin", tmp_path / "secured.toml"
    master.write_bytes(MASTER)
    path.write_text(text % (LABEL, master))
    return str(path)


# cli.main `flash path *args` with the profile at prof, over the pipe to server.
def flash(server, prof, path, *args):
    return run_cli(server, ["--profile", prof, "--interface", "pipe", "flash", path, *args])


# True for a single-frame negative response to sid with nrc.
def is_nrc(msg, sid, nrc):
    return bytes(msg.data[:4]) == bytes([0x03, 0x7F, sid, nrc])


# Returns once server is past iso14229's 1 s 0x27 delay after boot: an answer shows it has booted.
def past_boot_delay(server):
    with PipeTransport(EXAMPLE, server) as t:
        t.uds().read_did(wire.DID_SESSION)
    time.sleep(1.1)


# Check a secured flash end to end: 10 02 and the programming unlock, which iso14229's 1 s delay after boot answers
# 0x37 first (the client waits it out, keeping the session with 3E), 34, the 36s and 37, FF01, F001 and the restart
# into the new image pending verify, then 10 03 and F002. Flash jobs answer 0x78 first. The new image runs confirmed
# from slot 1 with the old one in slot 0, and a second flash finds nothing to do.
def test_secured_flash(lite, tmp_path, capsys):
    s = lite()
    image = build_image("v0.2.0")
    path, prof = image_file(tmp_path, image), secured(tmp_path)
    assert flash(s, prof, path) == 0
    assert any(is_nrc(m, 0x27, wire.NRC_TIME_DELAY) for m in s.sent), "the unlock came over 1 s after the boot"
    assert all(any(is_nrc(m, sid, wire.NRC_PENDING) for m in s.sent) for sid in (0x36, 0x31))
    status, sha, version = read_state(s)
    assert (status["running_slot"], status["running_state"], status["boot_slot"]) == (1, VALID, 1)
    assert sha == elf_sha(image) and version == "v0.2.0" and tuple(status["other_version"]) == (0, 1, 0)
    assert "boot 2: slot 1 runs v0.2.0 (pending verify)" in s.log()
    assert "confirmed" in capsys.readouterr().out
    assert flash(s, prof, path) == 0
    assert "already runs this image" in capsys.readouterr().out


# flash of v0.2.0, secured, on a server whose app refuses F002 (0x22) for SOAK_MS after each boot, begun once the
# 0x27 delay after boot has passed so that the unlock never waits; returns the server and flash's exit code.
def soak_flash(lite, tmp_path):
    s = lite("--soak-ms", str(SOAK_MS))
    past_boot_delay(s)
    return s, flash(s, secured(tmp_path), image_file(tmp_path, build_image("v0.2.0")))


# Check ConfirmImage outlasts a soak longer than S3: F002 answers 0x22 for 7 s after the restart, the client retries
# it every 2 s with a 3E first that keeps the extended session, and it then passes.
def test_confirm_outlasts_a_soak_longer_than_s3(lite, tmp_path):
    s, rc = soak_flash(lite, tmp_path)
    assert rc == 0
    assert sum(is_nrc(m, 0x31, wire.NRC_CONDITIONS) for m in s.sent) >= 3
    assert read_state(s)[0]["running_state"] == VALID


# The control for the test above: the same flow with the keepalive off. S3 ends the extended session during the soak,
# so the next F002 answers 0x7F and flash fails with the image unconfirmed. Were the session kept by anything but the
# 3E, this would flash, and the test above would show nothing about the keepalive.
def test_control_without_the_keepalive_s3_ends_the_session(lite, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(uds, "KEEPALIVE_S", 1e9)
    s, rc = soak_flash(lite, tmp_path)
    assert rc == 1
    assert "service 0x31 answered NRC 0x7F" in capsys.readouterr().err
    status, _, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, PENDING, "v0.2.0")


# Check config set end to end: 10 03 and the extended unlock, a 2E per key, which the app stages, its commit routine,
# the keyed 11 01 and the restart, then each key read back and the app's config hash checked against them; config
# show then reads the new values, with nothing staged or pending.
def test_config_set(lite, tmp_path, capsys):
    s = lite()
    prof = secured(tmp_path, CONFIG)
    assert run_cli(s, ["--profile", prof, "--interface", "pipe", "config", "set", "mode=2", "timeout_ms=3000",
                       "--commit", "--reset"]) == 0
    out = capsys.readouterr().out
    assert "0200 mode: 2" in out and "0201 timeout_ms: 3000" in out
    assert "F1B0 config hash:" in out and "matches the values read" in out
    assert [bytes(m.data[:4]) for m in s.sent if bytes(m.data[:2]) == b"\x03\x6E"] == [b"\x03\x6E\x02\x00",
                                                                                       b"\x03\x6E\x02\x01"]
    assert run_cli(s, ["--profile", prof, "--interface", "pipe", "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "0201 timeout_ms: 3000 (1000..5000)" in out and "F1B2 config status: 00" in out


# Check a seed request while already unlocked: iso14229 answers it itself with a 2-byte zero seed (67 01 00 00), and
# the client takes that as unlocked and sends no second key. The level holds: the app's keyed 2E is accepted.
def test_seed_while_unlocked(lite, tmp_path):
    s = lite()
    sent = []
    s.tap = sent.append
    prof = profile.load(secured(tmp_path))
    past_boot_delay(s)
    with PipeTransport(prof, s) as t:
        u = t.uds()
        keys = update.device_keys(u, prof, MASTER)
        u.session(wire.SESSION_EXTENDED)
        u.unlock(prof.security.level_extended, keys)
        u.unlock(prof.security.level_extended, keys)
        u.write_did(0x0200, b"\x01")
    assert any(bytes(m.data[:5]) == b"\x04\x67\x01\x00\x00" for m in s.sent)
    assert sum(m.data[0] >> 4 == 1 and bytes(m.data[2:4]) == b"\x27\x02" for m in sent) == 1   # one key's FF


# Check rollback: an image activated but never confirmed runs pending verify after the restart, and the keyed 11 01
# boots the old image again. F189 reads the old version, and F1F0 reports the new one rolled back.
def test_unconfirmed_image_rolls_back(lite, tmp_path):
    s = lite()
    prof = profile.load(secured(tmp_path))
    image = build_image("v0.2.0")
    with PipeTransport(prof, s) as t:
        u = t.uds()
        keys = update.device_keys(u, prof, MASTER)
        update.enter_programming(u, prof, keys)
        update.download(u, image, log=lambda *a: None)
        update.check_image(u)
        try:
            u.routine(wire.RID_ACTIVATE)
        except NoResponse:   # a slow runner can miss P2 as the server restarts; flash tolerates it too
            assert update.activation_landed(u, elf_sha(image), log=lambda *a: None)
        update.wait_for_image(u, elf_sha(image), t.preroll)
        status = wire.decode_status(u.read_did(wire.DID_STATUS))
        assert (status["running_slot"], status["running_state"]) == (1, PENDING)
        update.keyed_reset(u, prof, keys)
    with PipeTransport(prof, s) as t:
        update.wait_for_image(t.uds(), elf_sha(build_image(OLD)), t.preroll)
    status, _, version = read_state(s)
    assert (status["running_slot"], status["running_state"], status["other_state"]) == (0, VALID, ROLLED_BACK)
    assert tuple(status["other_version"]) == (0, 2, 0) and version == OLD


# Check flash --diff-from on lite, which has no delta downloads: the client builds patches from the running image,
# both delta 34s (DFI 0x20 and 0x30) answer 0x31, and it sends the full image instead, which runs confirmed.
def test_diff_from_falls_back_to_a_full_image(lite, tmp_path, capsys):
    if importlib.util.find_spec("detools") is None:
        why = 'flash --diff-from needs detools: pip install "./client[diff]"'
        if os.environ.get("UDSOTA_LITE_SERVER"):
            pytest.fail(why)
        pytest.skip(why)
    s = lite()
    base = image_file(tmp_path, build_image(OLD), "base.bin")
    assert flash(s, secured(tmp_path), image_file(tmp_path, build_image("v0.2.0")), "--diff-from", base) == 0
    out = capsys.readouterr().out
    assert "delta base: %s" % base in out
    for dfi in (0x20, 0x30):
        assert "no delta downloads for DFI 0x%02X (RequestDownload answered 0x31)" % dfi in out
    assert read_state(s)[2] == "v0.2.0"


# ---- info, the key and the image rules ----

# Check `info` reads udsota's DIDs and the app's board DID from the server.
def test_info_reads_the_server_dids(lite, capsys):
    s = lite()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "info"]) == 0
    out = capsys.readouterr().out
    assert "F186 active session: 01" in out
    assert "F189 version: %s" % OLD in out
    assert "F18C device ID: 02:00:00:00:00:01" in out
    assert "F1F3 running app_elf_sha256: %s" % elf_sha(build_image(OLD)).hex(" ") in out
    assert "F1F0 update status: running slot 0 VALID, boot slot 0, other slot EMPTY" in out
    assert "F1F1 last download: DL_OK, 0 bytes received" in out
    assert "F191 board: devkit" in out


# Check a wrong master: the programming unlock's key is refused with 0x35 before anything is written, and once
# iso14229's 1 s delay after a refused key has passed (a 27 answers 0x36 until then), the right one flashes.
def test_flash_with_a_wrong_master(lite, tmp_path, capsys):
    s = lite()
    bad = tmp_path / "wrong.bin"
    bad.write_bytes(bytes(32))
    prof, image = secured(tmp_path), image_file(tmp_path, build_image("v0.2.0"))
    assert run_cli(s, ["--profile", prof, "--interface", "pipe", "--master", str(bad), "flash", image]) == 1
    assert "0x35" in capsys.readouterr().err
    status, _, version = read_state(s)
    assert (status["other_state"], version) == (0, OLD)                  # nothing written
    time.sleep(1.1)
    assert flash(s, prof, image) == 0
    assert read_state(s)[2] == "v0.2.0"


# Check the key is needed: in the programming session without an unlock, RequestDownload is refused with 0x33.
def test_download_needs_the_key(lite):
    s = lite()
    with PipeTransport(EXAMPLE, s) as t:
        u = t.uds()
        u.session(wire.SESSION_PROGRAMMING)
        with pytest.raises(Nrc) as e:
            u.request_download(4096)
        assert e.value.code == 0x33


# Opens the programming session on server with the unlock and sends image's first block; returns the transport, the
# Uds and the Nrc the block raised.
def first_block_refused(server, prof, image):
    t = PipeTransport(prof, server)
    u = t.uds()
    update.enter_programming(u, prof, update.device_keys(u, prof, MASTER))
    max_data = u.request_download(len(image))
    with pytest.raises(Nrc) as e:
        u.transfer(1, image[:max_data])
    return t, u, e.value


# Check each first-block rule: the image is refused with 0x31 before anything is erased, and F1F1 names the reason.
@pytest.mark.parametrize("image, reason", [
    (build_image("v0.2.0", product="widget"), "DL_BAD_PROJECT"),
    (build_image("v0.2.0", hw_id=2), "DL_BAD_BOARD"),
    (build_image("v0.2.0", layout=2), "DL_BAD_LAYOUT"),
    (build_image("v0.2.0", ids=(0x720, 0x728)), "DL_BAD_DIAG_IDS"),
    (build_image("v0.0.9"), "DL_NOT_NEWER"),
    (build_image("v0.2.0", release=False), "DL_BAD_HEADER"),        # a release flag that disagrees with the tag
    (b"\xE8" + build_image("v0.2.0")[1:], "DL_BAD_HEADER"),        # not an ESP image
], ids=["product", "hw_id", "layout", "diag_ids", "older", "flag", "magic"])
def test_first_block_rules_refuse(lite, tmp_path, image, reason):
    s = lite()
    t, u, nrc = first_block_refused(s, profile.load(secured(tmp_path)), image)
    with t:
        assert nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(u.read_did(wire.DID_RESULT)) == (reason, 0)
        assert wire.decode_status(u.read_did(wire.DID_STATUS))["other_state"] == 0   # never erased


# Check `flash` with a profile that checks nothing but the IDs and the key: udsota refuses the wrong product itself,
# the client exits 1 naming 0x31, and F1F1 reads DL_BAD_PROJECT.
def test_flash_of_a_wrong_product_is_refused_by_the_server(lite, tmp_path, capsys):
    s = lite()
    master = tmp_path / "master.bin"
    master.write_bytes(MASTER)
    path = tmp_path / "ids.toml"
    path.write_text('[can]\nreq_id = 0x710\nresp_id = 0x718\n\n[security]\nlabel = "%s"\nmaster_file = "%s"\n'
                    % (LABEL, master))
    image = image_file(tmp_path, build_image("v0.2.0", product="widget"))
    assert run_cli(s, ["--profile", str(path), "--interface", "pipe", "flash", image]) == 1
    assert "0x31" in capsys.readouterr().err
    with PipeTransport(EXAMPLE, s) as t:
        assert wire.decode_result(t.uds().read_did(wire.DID_RESULT)) == ("DL_BAD_PROJECT", 0)


# Check a corrupted image passes the first block but fails FF01's check (reason 8): `flash` exits 1 and the old image
# still runs.
def test_corrupt_image_fails_ff01(lite, tmp_path, capsys):
    s = lite()
    image = bytearray(build_image("v0.2.0"))
    image[5000] ^= 0x01
    assert flash(s, secured(tmp_path), image_file(tmp_path, image)) == 1
    assert "DL_VERIFY_FAILED" in capsys.readouterr().err
    status, _, version = read_state(s)
    assert (status["running_slot"], version) == (0, OLD)


# ---- lost frames and answers (fault injection in the pipe) ----

# Check a resent block: --drop-76 2 sends block 2 again as if its 76 were lost, and iso14229 answers the repeat
# 0x24, since its counter is not the next one, which ends the transfer. flash exits 1 naming the 0x24, F1F1 reads
# DL_ABORTED with the old image running, and the next flash sends the image again from its first byte.
def test_drop_76_ends_the_transfer(lite, tmp_path, capsys):
    s = lite()
    prof, path = secured(tmp_path), image_file(tmp_path, build_image("v0.2.0"))
    assert flash(s, prof, path, "--drop-76", "2") == 1
    assert [bytes(m.data[:3]) for m in s.sent].count(b"\x02\x76\x02") == 1
    assert "service 0x36 answered NRC 0x24" in capsys.readouterr().err
    with PipeTransport(EXAMPLE, s) as t:
        assert wire.decode_result(t.uds().read_did(wire.DID_RESULT))[0] == "DL_ABORTED"
    assert read_state(s)[2] == OLD
    assert flash(s, prof, path) == 0
    assert read_state(s)[2] == "v0.2.0"


# Check one FC lost on the bus (the one after the 64th CF of block 1): the client's N_Bs timeout (1 s) resends the block
# from a new FF, which isotp-c, its receive long since dropped by N_Cr (100 ms), takes as a new message, and the update
# completes.
def test_lost_flow_control_is_resent_and_the_update_completes(lite, tmp_path):
    s = lite()
    cfs = {"n": None}                             # CFs of block 1's first send so far

    def tap(m):
        if m.data[0] >> 4 == 1:
            cfs["n"] = 0 if m.data[2:4] == bytes([0x36, 0x01]) and not s.dropped else None
        elif m.data[0] >> 4 == 2 and cfs["n"] is not None:
            cfs["n"] += 1

    s.tap = tap
    s.drop = lambda m: m.data[0] >> 4 == 3 and cfs["n"] == 64 and not s.dropped
    assert flash(s, secured(tmp_path), image_file(tmp_path, build_image("v0.2.0"))) == 0
    assert len(s.dropped) == 1
    assert read_state(s)[2] == "v0.2.0"


# True for the positive ActivateImage answer 71 01 F0 01 as a single frame.
def is_activate_answer(msg):
    return bytes(msg.data[:5]) == bytes([0x04, 0x71, 0x01, 0xF0, 0x01])


# Check a lost ActivateImage answer: the server has activated and restarts into the new image, and the client, seeing
# only a timeout, finds it restarting, waits for the new image and confirms it.
def test_lost_activate_answer_still_confirms(lite, tmp_path):
    s = lite()
    s.drop = lambda m: is_activate_answer(m) and not s.dropped
    assert flash(s, secured(tmp_path), image_file(tmp_path, build_image("v0.2.0"))) == 0
    assert len(s.dropped) == 1
    status, _, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, VALID, "v0.2.0")


# ---- compressed downloads (DFI 0x10) ----

# An image that compresses about as a real app does: 48 KB of build_image's noise in segment 0.
def z_image(version="v0.2.0", **kw):
    return build_image(version, payload=48 * 1024, noise=True, **kw)


# True for the first frame of a 34 the client sends with dataFormatIdentifier dfi.
def is_34(msg, dfi):
    return msg.data[0] >> 4 == 1 and msg.data[2:4] == bytes([0x34, dfi])


# Check `flash --compress` runs the whole sequence with a raw DEFLATE stream: 34 announces DFI 0x10, fewer blocks go
# out, the new image runs, and the output gives the ratio and the time saved.
def test_flash_compressed_runs_the_whole_sequence(lite, tmp_path, capsys):
    s = lite()
    sent = []
    s.tap = sent.append
    image = z_image()
    zlen = len(delta.deflate(image))
    assert zlen < 0.7 * len(image)
    assert flash(s, secured(tmp_path), image_file(tmp_path, image), "--compress") == 0
    assert any(is_34(m, wire.DL_DFI_DEFLATE) for m in sent) and not any(is_34(m, wire.DL_DFI) for m in sent)
    out = capsys.readouterr().out
    assert "compressed with raw DEFLATE: %d -> %d bytes" % (len(image), zlen) in out and "s saved" in out
    status, sha, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, VALID, "v0.2.0")
    assert sha == elf_sha(image)


# Check a profile's [image] compression = "deflate" compresses without the flag.
def test_profile_compression(lite, tmp_path):
    s = lite()
    sent = []
    s.tap = sent.append
    prof = secured(tmp_path, SECURED.replace("[image]\n", '[image]\ncompression = "deflate"\n'))
    assert flash(s, prof, image_file(tmp_path, z_image())) == 0
    assert any(is_34(m, wire.DL_DFI_DEFLATE) for m in sent)


# Check a resent block mid-stream: --drop-76 3 sends block 3 of the compressed stream again, and iso14229 answers
# the repeat 0x24, ending the transfer, so flash exits 1 with the old image running.
def test_compressed_drop_76_ends_the_transfer(lite, tmp_path, capsys):
    s = lite()
    assert flash(s, secured(tmp_path), image_file(tmp_path, z_image()), "--compress", "--drop-76", "3") == 1
    assert [bytes(m.data[:3]) for m in s.sent].count(b"\x02\x76\x03") == 1
    err = capsys.readouterr().err
    assert "service 0x36 answered NRC 0x24" in err and "F1F1 reads DL_ABORTED" in err, err
    assert read_state(s)[2] == OLD


# Fault injection mid-stream: one consecutive frame of block 4 never reaches the server, whose ISO-TP receive drops
# the message; the client, with no answer, resends the block and the stream carries on intact.
def test_compressed_lost_frame_mid_stream(lite, tmp_path):
    s = lite()
    state = {"in_block_4": False}

    def drop_tx(m):
        if m.data[0] >> 4 == 1:                   # a first frame: note whether it opens block 4
            state["in_block_4"] = m.data[2:4] == bytes([0x36, 0x04])
            return False
        return state["in_block_4"] and m.data[0] >> 4 == 2 and not s.dropped_tx and m.data[0] & 0x0F == 5

    s.drop_tx = drop_tx
    assert flash(s, secured(tmp_path), image_file(tmp_path, z_image()), "--compress") == 0
    assert len(s.dropped_tx) == 1
    assert read_state(s)[2] == "v0.2.0"


# Opens a compressed download of image on server with the unlock and sends payload in blocks; returns the transport,
# the Uds and the Nrc a block raised (None if all were taken).
def send_stream(server, prof, image, payload):
    t = PipeTransport(prof, server)
    u = t.uds()
    update.enter_programming(u, prof, update.device_keys(u, prof, MASTER))
    max_data = u.request_download(len(image), wire.DL_DFI_DEFLATE)
    for n, off in enumerate(range(0, len(payload), max_data), 1):
        try:
            u.transfer(n & 0xFF, payload[off:off + max_data])
        except Nrc as e:
            return t, u, e
    return t, u, None


# Check a stream with 64 random bytes spliced in mid-way is refused at the block that trips the inflater: a 36
# answers 0x31 with F1F1 DL_BAD_STREAM, and FF01 has nothing to verify (0x24).
def test_corrupt_stream_is_refused(lite, tmp_path):
    s = lite()
    image = z_image()
    z = bytearray(delta.deflate(image))
    z[len(z) // 2:len(z) // 2 + 64] = random.Random(7).randbytes(64)
    t, u, nrc = send_stream(s, profile.load(secured(tmp_path)), image, z)
    with t:
        assert nrc is not None and nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(u.read_did(wire.DID_RESULT))[0] == "DL_BAD_STREAM"
        with pytest.raises(Nrc) as e:
            u.routine(wire.RID_CHECK_DEPS)
        assert e.value.code == wire.NRC_SEQUENCE


# Check a stream cut short passes every block but fails 37 with 0x72 and F1F1 DL_BAD_STREAM, and FF01 then has
# nothing to verify.
def test_truncated_stream_fails_transfer_exit(lite, tmp_path):
    s = lite()
    image = z_image()
    t, u, nrc = send_stream(s, profile.load(secured(tmp_path)), image, delta.deflate(image)[:-20])
    with t:
        assert nrc is None
        with pytest.raises(Nrc) as e:
            u.transfer_exit()
        assert e.value.code == wire.NRC_PROGRAMMING_FAILURE
        assert wire.decode_result(u.read_did(wire.DID_RESULT))[0] == "DL_BAD_STREAM"
        with pytest.raises(Nrc) as e:
            u.routine(wire.RID_CHECK_DEPS)
        assert e.value.code == wire.NRC_SEQUENCE


# Check the first-block rules run on the inflated bytes: a compressed image for another product is refused with 0x31
# and DL_BAD_PROJECT before anything is erased.
def test_compressed_first_block_rules_refuse(lite, tmp_path):
    s = lite()
    image = z_image(product="widget")
    t, u, nrc = send_stream(s, profile.load(secured(tmp_path)), image, delta.deflate(image))
    with t:
        assert nrc is not None and nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(u.read_did(wire.DID_RESULT)) == ("DL_BAD_PROJECT", 0)
        assert wire.decode_status(u.read_did(wire.DID_STATUS))["other_state"] == 0


# ---- pack: another flasher, from the payloads and manifest alone ----

# `udsota pack new --out tmp_path/pack *args`; returns the output directory and the manifest.
def packed(tmp_path, new, *args):
    out = tmp_path / "pack"
    assert cli.main(["--profile", "example", "pack", new, "--out", str(out), *args]) == 0
    return out, json.loads((out / (pathlib.Path(new).stem + ".manifest.json")).read_text())


# A flasher that is not this client, as docs/wire.md's "Flashing without the client" has it: it knows only the
# manifest, the payload files and the key, and makes the Uds calls flash makes. The precheck, 10 02 and the
# programming unlock, then each full payload in manifest order until one is taken (0x31, or 0x22 with DL_NO_MEMORY,
# at the 34 moves on to the next); F1F1 after the 37 must count every payload byte. Then FF01, ActivateImage, F1F3
# showing the new image, ConfirmImage. Returns the DFIs whose 34 was sent, and the F1F1 reasons that moved it on.
def flash_packed(server, prof, out, manifest):
    tried, why, first = [], [], manifest["payloads"][0]
    with PipeTransport(prof, server) as t:
        u = t.uds()
        reason = lambda: wire.decode_result(u.read_did(wire.DID_RESULT))[0]
        state = wire.decode_status(u.read_did(wire.DID_STATUS))
        assert u.read_did(wire.DID_RUNNING_SHA).hex() != first["image_elf_sha256"]
        assert state["running_state"] != PENDING
        if first["board_did"] is not None:
            assert wire.cstr(u.read_did(first["board_did"])) == first["board"]
        update.enter_programming(u, prof, update.device_keys(u, prof, MASTER))
        for e in manifest["payloads"]:
            data = (out / e["file"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == e["payload_sha256"]
            tried.append(e["dfi"])
            try:
                max_data = u.request_download(e["memory_size"], e["dfi"])
            except Nrc as x:
                if x.code == wire.NRC_OUT_OF_RANGE or (x.code == wire.NRC_CONDITIONS and reason() == "DL_NO_MEMORY"):
                    why.append(reason())
                    continue
                raise
            for n, off in enumerate(range(0, len(data), max_data), 1):
                u.transfer(n & 0xFF, data[off:off + max_data])
            u.transfer_exit()
            assert wire.decode_result(u.read_did(wire.DID_RESULT)) == ("DL_OK", e["payload_size"])
            break
        else:
            raise AssertionError("the device took none of the payloads: %s" % why)
        assert u.routine(wire.RID_CHECK_DEPS)[:1] == b"\x00"
        u.routine(wire.RID_ACTIVATE)
        update.wait_for_image(u, bytes.fromhex(e["image_elf_sha256"]), t.preroll)
        update.confirm(u, log=lambda *_: None)
    return tried, why


# Check each full mode pack writes, sent by the flasher above, takes the server where `flash` of the same image in that
# mode does: one 34, with that DFI, and the new image running and confirmed.
@pytest.mark.parametrize("dfi", [wire.DL_DFI, wire.DL_DFI_DEFLATE])
def test_packed_payload_updates_as_flash_does(lite, tmp_path, dfi):
    by_flash, by_pack = lite(), lite()
    prof = secured(tmp_path)
    new = image_file(tmp_path, z_image("v0.3.0"), "new.bin")
    out, manifest = packed(tmp_path, new, "--dfi", "0x%02x" % dfi)
    assert flash_packed(by_pack, profile.load(prof), out, manifest) == ([dfi], [])
    sent = []
    by_flash.tap = sent.append
    assert flash(by_flash, prof, new, {wire.DL_DFI: "--no-compress", wire.DL_DFI_DEFLATE: "--compress"}[dfi]) == 0
    assert [d for d in pack.DFIS for m in sent if is_34(m, d)] == [dfi]
    state = read_state(by_pack)
    assert state == read_state(by_flash)
    assert (state[0]["running_state"], state[1], state[2]) == (VALID, elf_sha(z_image("v0.3.0")), "v0.3.0")


# ---- services udsota and the app don't serve ----

# Check the DTC commands against an app that serves no DTCs, as udsota_lite_server's doesn't: show, show --ext and
# clear all exit 2, saying the firmware has no DTC services.
def test_dtc_commands_without_dtc_services(lite, capsys):
    s = lite()
    for args in (["show"], ["show", "--ext", "U0073"], ["clear"]):
        rc = run_cli(s, ["--profile", "example", "--interface", "pipe", "dtc", *args])
        out, err = capsys.readouterr()
        assert (rc, out) == (2, "") and "this firmware has no DTC services" in err, args


# A SID nobody serves.
class Unserved(BaseService):
    _sid = 0xBB
    _use_subfunction = False
    supported_negative_response = []


# Check a SID nobody serves answers 0x11, and a 34 in the default session answers 0x7F (udsota's, not the app's).
def test_unknown_sid_and_34_in_the_default_session(lite):
    s = lite()
    with PipeTransport(EXAMPLE, s) as t:
        u = t.uds()
        with pytest.raises(Nrc) as unserved:
            u.request(Unserved)
        with pytest.raises(Nrc) as download:
            u.request_download(4096)
    assert (unserved.value.code, download.value.code) == (0x11, 0x7F)
