"""End-to-end tests: the client (cli.main, update's steps and the Uds layer, over can-isotp's Python ISO-TP stack)
against udsota_lite_server, which runs udsota on unmodified iso14229 as an app does, its CAN frames on its stdin and
stdout. The top-level CMakeLists.txt builds it. $UDSOTA_LITE_SERVER names the binary, and then a missing one fails;
without it, build/udsota_lite_server runs when it is built, and the module skips when it is not."""
import importlib.util
import os
import pathlib
import time

import pytest

from udsota import profile, uds, update, wire
from udsota.errors import NoResponse

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
