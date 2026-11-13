"""End-to-end tests of the bootloader flow: the client (cli.main, update's steps and the Uds layer, over can-isotp's
Python ISO-TP stack) against udsota_boot_server, which runs the bootloader core (boot/) on unmodified iso14229 with a
stand-in app, its CAN frames on its stdin and stdout. The top-level CMakeLists.txt builds it. $UDSOTA_BOOT_SERVER names
the binary, and then a missing one fails; without it, build/udsota_boot_server runs when it is built, and the module
skips when it is not. Every image is stamped by the client's own stamp()."""
import os
import pathlib
import struct
import time

import pytest

from udsota import __version__, image, profile, update, wire
from udsota.errors import NoResponse, Nrc, UpdateFailed

from .demo_server import DemoServer, PipeTransport, bare_id, build_bare_image, image_file, run_cli

BUILT = pathlib.Path(__file__).resolve().parents[2] / "build" / "udsota_boot_server"
VALID = 3                          # F1F0 running_state while the unit holds a valid app
DID_BOOT_VERSION = 0xF180          # UDSOTA_DID_BOOT_VERSION: a bootloader unit's, which the client never reads
# udsota's example identity, the server's defaults: IDs, product, hw_id, layout, slot size and header offset.
EXAMPLE = {"req": 0x710, "resp": 0x718, "product": "example", "hw": 1, "layout": 1, "slot": 0x20000, "offset": 0x100}
PROFILE = """
[can]
req_id = 0x%(req)03X
resp_id = 0x%(resp)03X

[image]
format = "bare"
header_offset = 0x%(offset)X
product = "%(product)s"
hw_ids = [%(hw)d]
layout_id = %(layout)d
slot_size = 0x%(slot)X

[update]
flow = "bootloader"
start_timeout_s = 30
"""


# The server: $UDSOTA_BOOT_SERVER, which must then be there; else build/udsota_boot_server; else a skip.
@pytest.fixture(scope="module")
def binary():
    env = os.environ.get("UDSOTA_BOOT_SERVER")
    if env:
        if not os.access(env, os.X_OK):
            pytest.fail("UDSOTA_BOOT_SERVER=%s is not an executable file" % env)
        return env
    if not os.access(BUILT, os.X_OK):
        pytest.skip("udsota_boot_server is not built: cmake -S . -B build && cmake --build build --target "
                    "udsota_boot_server (or set UDSOTA_BOOT_SERVER)")
    return str(BUILT)


# Starts servers for a test, with args and the image installed (none: an empty slot), and stops them after it; each
# must exit 0, so a sanitizer report or a breach of the port's contract fails the test. The client's waits follow the
# server's pace: a restart takes it 0.3 s, so the client waits 0.5 s, not 3 s, and polls F1F4 every 0.2 s.
@pytest.fixture
def boot(binary, tmp_path, monkeypatch):
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.5)
    monkeypatch.setattr(update, "BOOT_POLL_S", 0.2)
    servers = []

    def start(*args, image=None):
        n = len(servers)
        slot = [] if image is None else ["--image", image_file(tmp_path, image, "installed%d.bin" % n)]
        servers.append(DemoServer(binary, [*slot, *args], tmp_path / ("server%d.log" % n)))
        return servers[-1]

    yield start
    for s in servers:
        assert s.stop() == 0, s.log()


# The path of a bootloader-flow profile for identity (EXAMPLE's keys) under tmp_path.
def profile_file(tmp_path, identity=EXAMPLE):
    path = tmp_path / "boot.toml"
    path.write_text(PROFILE % identity)
    return str(path)


# A stamped bare image of version for the example identity, 5000 bytes: four full blocks and a short one.
def bare(version, **kw):
    return build_bare_image(header_offset=EXAMPLE["offset"], size=5000, version=version, product="example", **kw)


# cli.main `flash path *args` with the profile at prof, over the pipe to server.
def flash(server, prof, path, *args):
    return run_cli(server, ["--profile", prof, "--interface", "pipe", "flash", path, *args])


# A fresh transport on server for the profile at prof.
def pipe(server, prof):
    return PipeTransport(profile.load(prof), server)


# F1F4 from the unit's app once it answers, polled for up to timeout seconds; None if it never does.
def app_prefix(server, prof, timeout=15.0):
    deadline = time.monotonic() + timeout
    with PipeTransport(profile.load(prof), server, p2_s=0.3) as t:
        u = t.uds()
        while time.monotonic() < deadline:
            try:
                return u.read_did(wire.DID_IMAGE_PREFIX)
            except (NoResponse, Nrc, UpdateFailed):
                time.sleep(0.1)
    return None


# True for the app's answer to 10 02, 7F 10 78, as a single frame.
def is_pending_10(msg):
    return bytes(msg.data[:4]) == b"\x03\x7f\x10\x78"


# Check a full flash into an empty slot and then over the valid app it installed: the bootloader answers the first
# 10 02 itself, the app hands the second over with 7F 10 78, and each new app answers F1F4 with its image's prefix.
def test_flash_from_an_empty_slot_then_over_a_valid_app(boot, tmp_path, capsys):
    s = boot()
    prof = profile_file(tmp_path)
    first, second = bare("1.0.0"), bare("1.1.0")
    assert flash(s, prof, image_file(tmp_path, first, "first.bin")) == 0
    out = capsys.readouterr().out
    assert "the app runs the new image (F1F4 %s) and reports healthy" % bare_id(first)[:4].hex() in out
    assert not any(is_pending_10(m) for m in s.sent)
    assert flash(s, prof, image_file(tmp_path, second, "second.bin")) == 0
    assert any(is_pending_10(m) for m in s.sent) and "boot (other reset): HANDOVER" in s.log()
    assert app_prefix(s, prof) == bare_id(second)[:4]


# Check flash of the image the healthy app already runs ends at the F1F4 read: no 10 02 goes out and the app is never
# restarted.
def test_an_installed_image_is_left_running(boot, tmp_path, capsys):
    installed = bare("1.0.0")
    s = boot(image=installed)
    prof = profile_file(tmp_path)
    assert app_prefix(s, prof) == bare_id(installed)[:4]
    sent = []
    s.tap = sent.append
    assert flash(s, prof, image_file(tmp_path, installed)) == 0
    assert "already runs this image" in capsys.readouterr().out
    assert not any(bytes(m.data[:3]) == b"\x02\x10\x02" for m in sent)
    assert s.log().count("the app starts") == 1


# Check a rerun after a tester that stopped two blocks into a download: the first erase took the old app, so F1F0
# reads no valid app, and the rerun, starting with 10 02, flashes the image.
def test_rerun_after_an_interrupted_download(boot, tmp_path):
    new = bare("1.1.0")
    s = boot(image=bare("1.0.0"))
    prof = profile_file(tmp_path)
    with pipe(s, prof) as t:
        u = t.uds()
        u.session(wire.SESSION_PROGRAMMING)
        max_data = u.request_download(len(new))
        u.transfer(1, new[:max_data])
        u.transfer(2, new[max_data:2 * max_data])
    with pipe(s, prof) as t:
        assert wire.decode_status(t.uds().read_did(wire.DID_STATUS))["running_state"] == 0
    assert flash(s, prof, image_file(tmp_path, new)) == 0
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check `info` hands the app over and reads the bootloader's DIDs, and `reset` (10 02, 11 01) returns to the app.
def test_info_and_reset(boot, tmp_path, capsys):
    installed = bare("1.0.0")
    s = boot(image=installed)
    prof = profile_file(tmp_path)
    assert app_prefix(s, prof) == bare_id(installed)[:4]
    assert run_cli(s, ["--profile", prof, "--interface", "pipe", "info"]) == 0
    out = capsys.readouterr().out
    assert "F186 active session: 02" in out and "F189 version: 1.0.0" in out
    assert "F18C device ID: d0:d1:d2:d3:d4:d5:d6:d7:d8:d9:da:db" in out
    assert "F1F3 running image ID: %s" % bare_id(installed).hex(" ") in out
    assert "F1F0 update status: running slot 0 VALID, boot slot 0, other slot EMPTY" in out
    assert "F1F1 last download: DL_OK, 0 bytes received" in out
    with pipe(s, prof) as t:
        assert t.uds().read_did(DID_BOOT_VERSION) == ("1.0.0 udsota/%s" % __version__).encode()
    assert run_cli(s, ["--profile", prof, "--interface", "pipe", "reset"]) == 0
    assert "reset accepted" in capsys.readouterr().out
    assert app_prefix(s, prof) == bare_id(installed)[:4]
    assert s.log().count("the app starts") == 2


# bare(version) with value packed at offset by fmt (16 bits, little-endian, by default) after stamping.
def patched(version, offset, value, fmt="<H"):
    img = bytearray(bare(version))
    struct.pack_into(fmt, img, offset, value)
    return bytes(img)


HDR = EXAMPLE["offset"]
LENGTH = HDR + image.BARE_HDR_LENGTH_OFFSET


# Check each first-block rule, which the client's own checks would stop before sending, by sending the image's first
# block by hand (the whole block, or for short_block one that ends inside the header): it is refused with 0x31 and
# F1F1 names the reason, nothing is erased, F1F0 still reads a valid app, and after 11 01 the old app starts.
@pytest.mark.parametrize("bad, block, reason", [
    (bare("2.0.0", hdr_magic=0x12345678), None, "DL_BAD_HEADER"),
    (bare("2.0.0", hdr_version=0), None, "DL_BAD_HEADER"),
    (patched("2.0.0", HDR + 6, 0x0100), None, "DL_BAD_HEADER"),                 # a high-byte flag
    (patched("2.0.0", LENGTH, EXAMPLE["slot"] + 4, "<I"), None, "DL_TOO_BIG"),
    (patched("2.0.0", LENGTH, 5004, "<I"), None, "DL_BAD_HEADER"),              # not the 34's memorySize
    (bare("2.0.0"), HDR + 100, "DL_BAD_HEADER"),
    (build_bare_image(header_offset=HDR, size=5000, version="2.0.0", product="widget"), None, "DL_BAD_PROJECT"),
    (bare("2.0.0", hw_id=2), None, "DL_BAD_BOARD"),
    (bare("2.0.0", magic=0), None, "DL_BAD_BOARD"),
    (bare("2.0.0", desc_version=0), None, "DL_BAD_BOARD"),
    (bare("2.0.0", layout=2), None, "DL_BAD_LAYOUT"),
    (bare("2.0.0", ids=(0x720, 0x728)), None, "DL_BAD_DIAG_IDS"),
], ids=["magic", "header_version", "flags", "too_big", "length", "short_block", "product", "hw_id", "desc_magic",
        "desc_version", "layout", "diag_ids"])
def test_first_block_rules_refuse(boot, tmp_path, bad, block, reason):
    installed = bare("1.0.0")
    s = boot(image=installed)
    prof = profile_file(tmp_path)
    with pipe(s, prof) as t:
        u = t.uds()
        u.session(wire.SESSION_PROGRAMMING)
        max_data = u.request_download(len(bad))
        with pytest.raises(Nrc) as e:
            u.transfer(1, bad[:block or max_data])
        assert e.value.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(u.read_did(wire.DID_RESULT)) == (reason, 0)
        assert wire.decode_status(u.read_did(wire.DID_STATUS))["running_state"] == VALID
        u.ecu_reset()
    assert app_prefix(s, prof) == bare_id(installed)[:4]
    assert "erase 0x" not in s.log()


# Check an image corrupted after stamping, which the client would refuse, sent by hand: every block is taken, FF01
# fails with reason 8 (also F1F1's, with the byte count), F001 then answers 0x24, and the next flash recovers.
def test_corrupt_image_fails_ff01_and_the_next_flash_recovers(boot, tmp_path):
    new = bare("1.1.0")
    corrupt = bytearray(new)
    corrupt[3000] ^= 0x01
    s = boot(image=bare("1.0.0"))
    prof = profile_file(tmp_path)
    with pipe(s, prof) as t:
        u = t.uds()
        u.session(wire.SESSION_PROGRAMMING)
        update.download(u, bytes(corrupt), log=lambda *a: None)
        with pytest.raises(UpdateFailed, match="DL_VERIFY_FAILED"):
            update.check_image(u)
        assert wire.decode_result(u.read_did(wire.DID_RESULT)) == ("DL_VERIFY_FAILED", len(corrupt))
        with pytest.raises(Nrc) as e:
            u.routine(wire.RID_ACTIVATE)
        assert e.value.code == wire.NRC_SEQUENCE
    assert flash(s, prof, image_file(tmp_path, new)) == 0
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check a lost answer to a 36, block 2's 76 dropped on the way to the client: after P2 the client resends block 2,
# iso14229 refuses the repeat with 0x24, which ends the transfer, so the block is written once and flash stops naming
# the 0x24; F1F1 reads DL_ABORTED, and the rerun flashes the image.
def test_dropped_36_answer_ends_the_run_and_the_rerun_succeeds(boot, tmp_path, capsys):
    new = bare("1.1.0")
    s = boot(image=bare("1.0.0"))
    s.drop = lambda m: bytes(m.data[:3]) == b"\x02\x76\x02" and not s.dropped
    prof, path = profile_file(tmp_path), image_file(tmp_path, new)
    assert flash(s, prof, path) == 1
    assert "service 0x36 answered NRC 0x24" in capsys.readouterr().err
    assert len(s.dropped) == 1 and s.log().count("program 0x400 bytes at 0x400") == 1
    with pipe(s, prof) as t:
        assert wire.decode_result(t.uds().read_did(wire.DID_RESULT))[0] == "DL_ABORTED"
    assert flash(s, prof, path) == 0
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check one flow control lost on the bus, the one after the 64th CF of block 1: the client's N_Bs timeout resends the
# block from a new FF, which isotp-c takes as a new message, and the update completes with each block written once.
def test_lost_flow_control_is_resent_and_the_update_completes(boot, tmp_path):
    new = bare("1.1.0")
    s = boot(image=bare("1.0.0"))
    cfs = {"n": None}                             # CFs of block 1's first send so far

    def tap(m):
        if m.data[0] >> 4 == 1:
            cfs["n"] = 0 if m.data[2:4] == bytes([0x36, 0x01]) and not s.dropped else None
        elif m.data[0] >> 4 == 2 and cfs["n"] is not None:
            cfs["n"] += 1

    s.tap = tap
    s.drop = lambda m: m.data[0] >> 4 == 3 and cfs["n"] == 64 and not s.dropped
    prof = profile_file(tmp_path)
    assert flash(s, prof, image_file(tmp_path, new)) == 0
    assert len(s.dropped) == 1 and s.log().count("program 0x400 bytes at 0x0\n") == 1
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check a 34 in the default session, to a unit with no app (so in its bootloader), answers 0x7F and leaves F1F1 alone.
def test_34_in_the_default_session(boot, tmp_path):
    s = boot()
    with pipe(s, profile_file(tmp_path)) as t:
        u = t.uds()
        with pytest.raises(Nrc) as e:
            u.request_download(4096)
        assert e.value.code == 0x7F
        assert wire.decode_result(u.read_did(wire.DID_RESULT)) == ("DL_OK", 0)


# Check a failed erase (--fail-erase 1): the first 36 answers 0x72 with F1F1 DL_FLASH_ERROR, and the next flash
# recovers.
def test_failed_erase_then_the_next_flash_recovers(boot, tmp_path, capsys):
    new = bare("1.1.0")
    s = boot("--fail-erase", "1", image=bare("1.0.0"))
    prof, path = profile_file(tmp_path), image_file(tmp_path, new)
    assert flash(s, prof, path) == 1
    assert "service 0x36 answered NRC 0x72" in capsys.readouterr().err
    with pipe(s, prof) as t:
        assert wire.decode_result(t.uds().read_did(wire.DID_RESULT))[0] == "DL_FLASH_ERROR"
    assert flash(s, prof, path) == 0
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check an app that hangs (--hang with its image's prefix): after F001 the watchdog resets it at each of its five
# starts, the unit is held, and flash fails on F1F4's 0x31 quoting F1F0's held flag. F1F4 keeps answering 0x31 with
# F1F0 flag 0x04 and a valid app, and a reflash of a good image releases the unit.
def test_hung_app_ends_held_and_a_reflash_recovers_it(boot, tmp_path, capsys):
    good, hangs = bare("1.0.0"), bare("1.1.0")
    s = boot("--hang", bare_id(hangs)[:4].hex(), image=good)
    prof = profile_file(tmp_path)
    assert flash(s, prof, image_file(tmp_path, hangs, "hangs.bin")) == 1
    err = capsys.readouterr().err
    assert "the unit is back in its bootloader (F1F4 answered 0x31)" in err and "held-in-bootloader" in err, err
    assert s.log().count("the watchdog resets the hung app") == 5 and "): HELD" in s.log()
    with pipe(s, prof) as t:
        u = t.uds()
        with pytest.raises(Nrc) as e:
            u.read_did(wire.DID_IMAGE_PREFIX)
        assert e.value.code == wire.NRC_OUT_OF_RANGE
        status = wire.decode_status(u.read_did(wire.DID_STATUS))
        assert status["flags"] & wire.STATUS_BOOT_HELD and status["running_state"] == VALID
    assert flash(s, prof, image_file(tmp_path, good, "good.bin")) == 0
    assert "the unit is held in its bootloader" in capsys.readouterr().out
    assert app_prefix(s, prof) == bare_id(good)[:4]


# Check --wait-for-unit on a unit whose app answers 7F 10 78 but cannot hand over (--no-handover): the first 10 02
# goes unanswered, the client asks for a power-cycle and repeats 10 02, the second one the app takes power-cycles the
# unit (--power-cycle-after 2), the bootloader's power-up window catches a 10 02, and the update completes.
def test_wait_for_unit_catches_the_power_up_window(boot, tmp_path, capsys):
    new = bare("1.1.0")
    s = boot("--no-handover", "--power-cycle-after", "2", image=bare("1.0.0"))
    prof = profile_file(tmp_path)
    assert app_prefix(s, prof) is not None
    assert flash(s, prof, image_file(tmp_path, new), "--wait-for-unit", "30") == 0
    out = capsys.readouterr().out
    assert "power-cycle it now" in out and "10 02 answered after" in out
    assert "the unit is power-cycled" in s.log() and s.log().count("boot (power-on reset): WINDOW") == 2
    assert app_prefix(s, prof) == bare_id(new)[:4]


# Check an image that was never stamped is refused by the client before it opens the bus: nothing reaches the unit.
def test_unstamped_image_is_refused_before_anything_is_sent(boot, tmp_path, capsys):
    s = boot()
    sent = []
    s.tap = sent.append
    unstamped = build_bare_image(header_offset=EXAMPLE["offset"], size=5000, product="example", stamped=False)
    assert flash(s, profile_file(tmp_path), image_file(tmp_path, unstamped)) == 2
    assert "not stamped" in capsys.readouterr().err
    assert sent == [] and s.sent == []


# Check a unit with another identity and geometry, all passed as arguments, flashed with a profile and an image for
# it: F180 carries the bootloader version given, and the last block, 908 bytes, is padded to the write unit of 8.
def test_identity_passed_as_arguments(boot, tmp_path):
    other = {"req": 0x7A0, "resp": 0x7A8, "product": "widget", "hw": 7, "layout": 3, "slot": 0x30000, "offset": 0x180}
    s = boot("--req-id", "0x7A0", "--resp-id", "0x7A8", "--product", "widget", "--hw-id", "7", "--layout-id", "3",
             "--slot-size", "0x30000", "--header-offset", "0x180", "--write-unit", "8", "--boot-version", "2.3.4")
    prof = profile_file(tmp_path, other)
    new = build_bare_image(header_offset=0x180, size=5004, version="3.0.0", product="widget", hw_id=7, layout=3,
                           ids=(0x7A0, 0x7A8))
    with pipe(s, prof) as t:
        u = t.uds()
        assert u.read_did(DID_BOOT_VERSION) == ("2.3.4 udsota/%s" % __version__).encode()
        u.session(wire.SESSION_PROGRAMMING)
        with pytest.raises(Nrc) as e:
            u.request_download(0x30004)                  # past this slot
        assert e.value.code == wire.NRC_OUT_OF_RANGE
        u.request_download(0x2F000)                      # past the default slot, within this one
    assert flash(s, prof, image_file(tmp_path, new)) == 0
    assert "program 0x390 bytes at 0x1000" in s.log()
    assert app_prefix(s, prof) == bare_id(new, 0x180)[:4]
