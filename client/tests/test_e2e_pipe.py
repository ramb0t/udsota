"""End-to-end tests: the client (cli.main, update.flash and the Uds layer, over can-isotp's Python ISO-TP stack)
against the real server core in tools/linux_server's udsota_demo_server, whose frames travel over its stdin and
stdout. No vcan or kernel ISO-TP needed; skipped when the demo is not built."""
import random
import subprocess
import threading
import time
import tomllib

import pytest

from udsota import cli, profile, transport, update, wire
from udsota.errors import NoResponse, Nrc

from .demo_server import (LABEL, MASTER, PIPE_P2_S, DemoServer, PipeTransport, binary_or_skip, build_image,
                          delta_pair, elf_sha, reseal)

EXAMPLE = profile.load("example")
OLD = "v0.1.0"                     # the demo's seeded running image
VALID, PENDING, ROLLED_BACK = 3, wire.IMG_PENDING_VERIFY, 4   # F1F0 running_state VALID, other_slot_state INVALID
FAST = ["--stmin-us", "200", "--boot-ms", "300"]   # frames 200 us apart; a 0.3 s restart


# Starts demo servers for a test (pipe mode, fresh temporary slots) and stops them after it.
@pytest.fixture
def demo(tmp_path, monkeypatch):
    binary = binary_or_skip()
    monkeypatch.setattr(update, "REBOOT_WAIT_S", 0.5)   # the demo restarts in 0.3 s, not a real boot's 3 s
    servers = []

    def start(*args):
        s = DemoServer(binary, [*FAST, *args], tmp_path / ("demo%d.log" % len(servers)))
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.stop()


# A profile from TOML text, and its file under tmp_path for --profile.
def write_profile(tmp_path, text, name="e2e"):
    p = tmp_path / ("%s.toml" % name)
    p.write_text(text)
    return profile.from_dict(name, tomllib.loads(text)), str(p)


# cli.main with argv, its transport the pipe to server with client P2 p2_s.
def run_cli(server, argv, p2_s=PIPE_P2_S):
    return cli.main(argv, transport=lambda prof, interface: PipeTransport(prof, server, p2_s=p2_s))


# An image file under tmp_path.
def image_file(tmp_path, data, name="image.bin"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# Reads status, running SHA and version from server over a fresh transport.
def read_state(server, prof=EXAMPLE):
    with PipeTransport(prof, server) as t:
        uds = t.uds()
        return (wire.decode_status(uds.read_did(wire.DID_STATUS)), uds.read_did(wire.DID_RUNNING_SHA),
                wire.cstr(uds.read_did(wire.DID_VERSION)))


# True for a single-frame negative response to sid with nrc.
def is_nrc(msg, sid, nrc):
    return bytes(msg.data[:4]) == bytes([0x03, 0x7F, sid, nrc])


# ---- the demo and its images ----

# Check the test's image builder and the demo's --make-image write the same bytes, so the tests build what
# the server's engine checks.
def test_image_builder_matches_the_demo(tmp_path):
    binary = binary_or_skip()
    out = tmp_path / "made.bin"
    subprocess.run([binary, "--make-image", str(out), "--version", "v1.2.3", "--product", "widget", "--hw-id", "7",
                    "--layout-id", "3", "--req-id", "0x6A0", "--resp-id", "0x6A8", "--payload", "1024"], check=True)
    assert out.read_bytes() == build_image("v1.2.3", "widget", 7, 3, (0x6A0, 0x6A8), payload=1024)


# ---- info ----

# Check `info` reads every server-owned DID and the example profile's board DID from the real server.
def test_info_reads_the_server_dids(demo, capsys):
    s = demo()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "info"]) == 0
    out = capsys.readouterr().out
    assert "F186 active session: 01" in out
    assert "F189 version: %s" % OLD in out
    assert "F18C device ID: 02:00:00:00:00:01" in out
    assert "F1F3 running app_elf_sha256: %s" % elf_sha(build_image(OLD)).hex(" ") in out
    assert "F1F0 update status: running slot 0 VALID, boot slot 0, other slot EMPTY" in out
    assert "F1F1 last download: DL_OK, 0 bytes received" in out
    assert "F191 board: devkit" in out


# ---- flash ----

# Check `flash` runs the whole sequence against the real server: precheck, 10 02, 34/36/37, FF01, F001, the
# emulated restart into the new image (pending verify), the wait on F1F3, 10 03 and F002; then the new image
# runs valid from slot 1, and a second flash is a no-op.
def test_flash_runs_the_whole_sequence(demo, tmp_path, capsys):
    s = demo()
    image = build_image("v0.2.0")
    path = image_file(tmp_path, image)
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", path]) == 0
    status, sha, version = read_state(s)
    assert (status["running_slot"], status["running_state"], status["boot_slot"]) == (1, VALID, 1)
    assert sha == elf_sha(image) and version == "v0.2.0"
    assert "boot 2: slot 1 runs v0.2.0 (pending verify)" in s.log()
    assert "confirmed" in capsys.readouterr().out
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", path]) == 0
    assert "already runs this image" in capsys.readouterr().out


# The example profile's [can], [image] and [board] with [security] on: the demo's label and a master file.
SECURED = """
[can]
req_id = 0x710
resp_id = 0x718

[security]
label = "%s"
master_file = "%s"

[image]
product = "example"
hw_ids = [1]
layout_id = 1
slot_size = 0x1E0000

[board]
did = 0xF191
names = { 1 = "devkit" }
"""


# Check `flash` with security on: the programming unlock uses the key udsota_keys.c derives on the server
# (host HMAC) from the same master, label and F18C; a wrong master is refused with 0x35 before anything is written.
def test_flash_with_security(demo, tmp_path, capsys):
    good, bad = tmp_path / "master.bin", tmp_path / "wrong.bin"
    good.write_bytes(MASTER)
    bad.write_bytes(bytes(32))
    s = demo("--label", LABEL, "--master", str(good), "--skip-boot-delay")
    _, path = write_profile(tmp_path, SECURED % (LABEL, good))
    image = image_file(tmp_path, build_image("v0.2.0"))
    assert run_cli(s, ["--profile", path, "--interface", "pipe", "--master", str(bad), "flash", image]) == 1
    assert "0x35" in capsys.readouterr().err
    status, _, version = read_state(s)
    assert (status["other_state"], version) == (0, OLD)                  # nothing written
    assert run_cli(s, ["--profile", path, "--interface", "pipe", "flash", image]) == 0
    assert read_state(s)[2] == "v0.2.0"


# Check the key is needed: without an unlock, RequestDownload is refused with 0x33.
def test_download_needs_the_key(demo):
    s = demo("--label", LABEL, "--skip-boot-delay")
    with PipeTransport(EXAMPLE, s) as t:
        uds = t.uds()
        uds.session(wire.SESSION_PROGRAMMING)
        with pytest.raises(Nrc) as e:
            uds.request_download(4096)
        assert e.value.code == 0x33


# Opens the programming session on server and sends image's first block; returns the transport, the Uds and the
# Nrc the block raised.
def first_block_refused(server, image):
    t = PipeTransport(EXAMPLE, server)
    uds = t.uds()
    uds.session(wire.SESSION_PROGRAMMING)
    max_data = uds.request_download(len(image))
    with pytest.raises(Nrc) as e:
        uds.transfer(1, image[:max_data])
    return t, uds, e.value


# Check each first-block rule on the real server: the image is refused with 0x31 before anything is erased,
# and F1F1 names the reason.
@pytest.mark.parametrize("image, reason", [
    (build_image("v0.2.0", product="widget"), "DL_BAD_PROJECT"),
    (build_image("v0.2.0", hw_id=2), "DL_BAD_BOARD"),
    (build_image("v0.2.0", layout=2), "DL_BAD_LAYOUT"),
    (build_image("v0.2.0", ids=(0x720, 0x728)), "DL_BAD_DIAG_IDS"),
    (build_image("v0.0.9"), "DL_NOT_NEWER"),
    (build_image("v0.2.0", release=False), "DL_BAD_HEADER"),        # a release flag that disagrees with the tag
    (b"\xE8" + build_image("v0.2.0")[1:], "DL_BAD_HEADER"),        # not an ESP image
], ids=["product", "hw_id", "layout", "diag_ids", "older", "flag", "magic"])
def test_first_block_rules_refuse(demo, image, reason):
    s = demo()
    t, uds, nrc = first_block_refused(s, image)
    with t:
        assert nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(uds.read_did(wire.DID_RESULT)) == (reason, 0)
        assert wire.decode_status(uds.read_did(wire.DID_STATUS))["other_state"] == 0   # never erased


# Check `flash` with a profile that checks nothing but the IDs: the server refuses the wrong product itself,
# the client exits 1 naming 0x31, and F1F1 reads DL_BAD_PROJECT.
def test_flash_of_a_wrong_product_is_refused_by_the_server(demo, tmp_path, capsys):
    s = demo()
    _, path = write_profile(tmp_path, "[can]\nreq_id = 0x710\nresp_id = 0x718\n")
    image = image_file(tmp_path, build_image("v0.2.0", product="widget"))
    assert run_cli(s, ["--profile", path, "--interface", "pipe", "flash", image]) == 1
    assert "0x31" in capsys.readouterr().err
    with PipeTransport(EXAMPLE, s) as t:
        assert wire.decode_result(t.uds().read_did(wire.DID_RESULT)) == ("DL_BAD_PROJECT", 0)


# Check a corrupted image passes the first block but fails FF01's SHA-256 (reason 8): `flash` exits 1 and the
# old image still runs.
def test_corrupt_image_fails_ff01(demo, tmp_path, capsys):
    s = demo()
    image = bytearray(build_image("v0.2.0"))
    image[5000] ^= 0x01
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, image)]) == 1
    assert "DL_VERIFY_FAILED" in capsys.readouterr().err
    status, _, version = read_state(s)
    assert (status["running_slot"], version) == (0, OLD)


# read_state once the server has restarted into the image with app_elf_sha256 sha.
def read_state_after_restart(server, sha):
    with PipeTransport(EXAMPLE, server) as t:
        update.wait_for_image(t.uds(), sha, t.preroll)
    return read_state(server)


# Check rollback: an image activated but never confirmed runs PENDING_VERIFY after the restart, and an 11 01
# then boots the old image again, with the new one reported rolled back in F1F0.
def test_unconfirmed_image_rolls_back(demo):
    s = demo()
    image = build_image("v0.2.0")
    with PipeTransport(EXAMPLE, s) as t:
        uds = t.uds()
        update.enter_programming(uds, EXAMPLE, None)
        update.download(uds, image, log=lambda *a: None)
        update.check_image(uds)
        try:
            uds.routine(wire.RID_ACTIVATE)
        except NoResponse:   # a slow runner can miss P2 as the server restarts; flash tolerates it too
            assert update.activation_landed(uds, elf_sha(image), log=lambda *a: None)
        update.wait_for_image(uds, elf_sha(image), t.preroll)
        status = wire.decode_status(uds.read_did(wire.DID_STATUS))
        assert (status["running_slot"], status["running_state"]) == (1, PENDING)
        update.keyed_reset(uds, EXAMPLE, None)
    status, _, version = read_state_after_restart(s, elf_sha(build_image(OLD)))
    assert (status["running_slot"], status["running_state"], status["other_state"]) == (0, VALID, ROLLED_BACK)
    assert tuple(status["other_version"]) == (0, 2, 0) and version == OLD


# Check ConfirmImage waits out the app's soak: the gate answers 0x22 for 3 s after the restart and the client
# retries every 2 s until it passes.
def test_confirm_retries_through_the_soak(demo, tmp_path):
    s = demo("--soak-ms", "3000")
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0
    assert any(is_nrc(m, 0x31, wire.NRC_CONDITIONS) for m in s.sent)
    assert read_state(s)[0]["running_state"] == VALID


# Check slow flash jobs: with every erase, verify, activate and confirm taking 300 ms, the server answers 0x78
# first and the client waits for the final answer.
def test_slow_jobs_answer_response_pending(demo, tmp_path):
    s = demo("--job-ms", "300")
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0
    assert {m.data[2] for m in s.sent if m.data[1] == 0x7F and m.data[3] == 0x78} == {0x36, 0x31}
    assert read_state(s)[2] == "v0.2.0"


# Check --drop-76: the resent block is answered again (without a rewrite: the image still verifies), and the
# update completes. F1F2's repeated_blocks is RAM, so the restart clears it; the answers show the repeat.
def test_drop_76_resends_one_block(demo, tmp_path):
    s = demo()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0")), "--drop-76", "2"]) == 0
    answers = [bytes(m.data[:3]) for m in s.sent if m.data[1] == 0x76]
    assert answers.count(b"\x02\x76\x02") == 2
    assert read_state(s)[2] == "v0.2.0"


# Check a server that withholds the FC after the first block of CFs of block 1, then ignores the resent FF: `flash`
# exits 1 within seconds, naming the block and the server's own reason from F1F1 (DL_ABORTED), and the old image
# still runs.
def test_withheld_flow_control_exits_1_with_the_servers_reason(demo, tmp_path, capsys):
    s = demo("--withhold-fc-after", "64")
    t0 = time.monotonic()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 1
    assert time.monotonic() - t0 < 15.0
    err = capsys.readouterr().err
    assert "block 1:" in err and "F1F1 reads DL_ABORTED" in err, err
    assert read_state(s)[2] == OLD


# Check one FC lost on the bus (after the first block of CFs of block 1): the client's N_Bs timeout resends the block
# from a new FF, the server takes it in place of the message it was still receiving, and the update completes.
def test_lost_flow_control_is_resent_and_the_update_completes(demo, tmp_path):
    s = demo("--drop-fc-after", "64")
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0
    assert "--drop-fc-after: losing the FC" in s.log()
    assert read_state(s)[2] == "v0.2.0"


# Check a platform without rollback: the activated image boots UNDEFINED, and ConfirmImage answers positive at once.
def test_flash_without_rollback(demo, tmp_path):
    s = demo("--no-rollback")
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0
    status, _, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, 0, "v0.2.0")


# ---- lost answers (fault injection in the pipe) ----

# True for the positive ActivateImage answer 71 01 F0 01 as a single frame.
def is_activate_answer(msg):
    return bytes(msg.data[:5]) == bytes([0x04, 0x71, 0x01, 0xF0, 0x01])


# Check a lost ActivateImage answer: the server has activated and restarts into the new image, and the client,
# seeing only a timeout, finds it restarting, waits for the new image and confirms it.
def test_lost_activate_answer_still_confirms(demo, tmp_path):
    s = demo()
    s.drop = lambda m: is_activate_answer(m) and not s.dropped
    image = build_image("v0.2.0")
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, image)]) == 0
    assert len(s.dropped) == 1
    status, _, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, VALID, "v0.2.0")


# True for a single-frame 76 <bsc>.
def is_block_answer(msg, bsc):
    return bytes(msg.data[:3]) == bytes([0x02, 0x76, bsc])


# True for the first frame of a 36 <bsc> the client sends.
def is_block_request(msg, bsc):
    return msg.data[0] >> 4 == 1 and msg.data[2:4] == bytes([0x36, bsc])


# Check the 0x21 path on a short job: with the first block's 0x78 and its final 76 both lost, the client's P2
# timeout resends the block, the server answers 0x21 while the 1 s erase runs, and within the client's 0x21
# backoff (3.15 s in all) a resend gets the repeat's 76 and the update completes. (With only the 0x78 lost, the
# original's 76 also arrives, and the outcome depends on timing: see test_late_answer_is_not_the_next_blocks.)
def test_busy_resends_outlast_a_short_job(demo, tmp_path):
    s = demo("--job-ms", "1000")
    s.drop = lambda m: (is_nrc(m, 0x36, 0x78) or is_block_answer(m, 1)) and len(s.dropped) < 2
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))], p2_s=transport.P2_S) == 0
    assert any(is_nrc(m, 0x36, wire.NRC_BUSY) for m in s.sent)
    assert len(s.dropped) == 2 and is_block_answer(s.dropped[1], 1)


# Found by these tests, and fixed: an answer that arrives after P2 is not stale-proof. Block 1's 76 is delayed until the
# client has resent the block, so it answers the resend; the server's answer to the repeat then arrives while
# the client sends block 2, and the client takes "76 01" as block 2's answer and stops ("block 2 answered with
# counter 01") instead of discarding it and waiting for 76 02. It now passes over a 76 with the previous
# block's counter. A lost 0x78 on a short job hits the same race.
def test_late_answer_is_not_the_next_blocks(demo, tmp_path):
    s = demo()
    held, sent, lock = [], [], threading.Lock()

    def drop(m):                                  # hold block 1's answers until the client has moved past them
        with lock:
            if is_block_answer(m, 1) and not any(is_block_request(x, 2) for x in sent):
                held.append(m)
                return True
            return False

    def tap(m):                                   # release them during the resend, then during block 2's send
        with lock:
            resend = is_block_request(m, 1) and any(is_block_request(x, 1) for x in sent)
            sent.append(m)
            if resend or is_block_request(m, 2):
                while held:
                    s.release(held.pop(0))

    s.drop, s.tap = drop, tap
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0


# Suspected in the client audit, confirmed here, and fixed: when the first 0x78 of a job longer than the 0x21
# backoff (an erase of 8 s) is lost, every resend answered 0x21 until the client gave up, because the 0x78s the
# server repeats every 1.5 s arrived while the client slept between retries. The client now listens out each
# backoff, takes the next 0x78 and waits for the original request's answer.
def test_lost_response_pending_on_a_long_job(demo, tmp_path):
    s = demo("--job-ms", "8000")
    s.drop = lambda m: is_nrc(m, 0x36, 0x78) and not s.dropped
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash",
                       image_file(tmp_path, build_image("v0.2.0"))]) == 0


# ---- compressed downloads (DFI 0x10) ----

# The demo's arguments and an image that compresses about as a real app does, 48 KB of segment 0.
def z_image(version="v0.2.0", **kw):
    return build_image(version, payload=48 * 1024, noise=True, **kw)


# True for the first frame of a 34 the client sends with dataFormatIdentifier dfi.
def is_34(msg, dfi):
    return msg.data[0] >> 4 == 1 and msg.data[2:4] == bytes([0x34, dfi])


# Check `flash --compress` runs the whole sequence with a raw DEFLATE stream: 34 announces DFI 0x10, fewer blocks
# go out, the new image runs, F1F1 counted the compressed bytes, and the output gives the ratio and the time saved.
def test_flash_compressed_runs_the_whole_sequence(demo, tmp_path, capsys):
    s = demo()
    sent = []
    s.tap = sent.append
    image = z_image()
    zlen = len(update.deflate(image))
    assert zlen < 0.7 * len(image)
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, image),
                       "--compress"]) == 0
    assert any(is_34(m, wire.DL_DFI_DEFLATE) for m in sent) and not any(is_34(m, wire.DL_DFI) for m in sent)
    out = capsys.readouterr().out
    assert "compressed with raw DEFLATE: %d -> %d bytes" % (len(image), zlen) in out and "s saved" in out
    status, sha, version = read_state(s)
    assert (status["running_slot"], status["running_state"], version) == (1, VALID, "v0.2.0")
    assert sha == elf_sha(image)


# Check `--compress` against a server built without a decompressor stops with exit 2 and the cause, having written
# nothing; `--compress-auto` falls back to the uncompressed download and completes.
def test_compress_on_a_server_without_it(demo, tmp_path, capsys):
    s = demo("--no-compress")
    path = image_file(tmp_path, z_image())
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", path, "--compress"]) == 2
    assert "the server has no compressed downloads" in capsys.readouterr().err
    assert read_state(s)[0]["other_state"] == 0
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", path, "--compress-auto"]) == 0
    assert "sending the image uncompressed" in capsys.readouterr().out
    assert read_state(s)[2] == "v0.2.0"


# Check a profile's [image] compression = "deflate" compresses without the flag.
def test_profile_compression(demo, tmp_path):
    s = demo()
    text = (profile.PROFILE_DIR / "example.toml").read_text().replace("[image]\n", '[image]\ncompression = "deflate"\n')
    _, path = write_profile(tmp_path, text)
    sent = []
    s.tap = sent.append
    assert run_cli(s, ["--profile", path, "--interface", "pipe", "flash", image_file(tmp_path, z_image())]) == 0
    assert any(is_34(m, wire.DL_DFI_DEFLATE) for m in sent)


# Fault injection mid-stream: --drop-76 resends block 3 of the compressed stream, which the server answers again
# without inflating it twice, and the image still verifies.
def test_compressed_drop_76_mid_stream(demo, tmp_path):
    s = demo()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, z_image()),
                       "--compress", "--drop-76", "3"]) == 0
    assert [bytes(m.data[:3]) for m in s.sent].count(b"\x02\x76\x03") == 2
    assert read_state(s)[2] == "v0.2.0"


# Fault injection mid-stream: one consecutive frame of block 4 never reaches the server, whose ISO-TP receive times
# out; the client, with no answer, resends the block and the stream carries on intact.
def test_compressed_lost_frame_mid_stream(demo, tmp_path):
    s = demo()
    state = {"in_block_4": False}

    def drop_tx(m):
        if m.data[0] >> 4 == 1:                   # a first frame: note whether it opens block 4
            state["in_block_4"] = m.data[2:4] == bytes([0x36, 0x04])
            return False
        return state["in_block_4"] and m.data[0] >> 4 == 2 and not s.dropped_tx and m.data[0] & 0x0F == 5

    s.drop_tx = drop_tx
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, z_image()),
                       "--compress"]) == 0
    assert len(s.dropped_tx) == 1
    assert read_state(s)[2] == "v0.2.0"


# Fault injection mid-stream: with slow worker jobs, block 2's 0x78 and 76 are lost; the client's resend meets 0x21
# while the job runs, then the repeat's 76, and the update completes.
def test_compressed_lost_answers_on_a_slow_job(demo, tmp_path):
    s = demo("--job-ms", "1000")
    s.drop = lambda m: (is_nrc(m, 0x36, 0x78) or is_block_answer(m, 2)) and len(s.dropped) < 2 and \
        any(is_block_answer(x, 1) for x in s.sent)
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, z_image()),
                       "--compress"], p2_s=transport.P2_S) == 0
    assert len(s.dropped) == 2
    assert read_state(s)[2] == "v0.2.0"


# Opens a compressed download of image on server and sends payload in blocks; returns the transport, the Uds and the
# Nrc a block raised (None if all were taken).
def send_stream(server, image, payload):
    t = PipeTransport(EXAMPLE, server)
    uds = t.uds()
    uds.session(wire.SESSION_PROGRAMMING)
    max_data = uds.request_download(len(image), wire.DL_DFI_DEFLATE)
    for n, off in enumerate(range(0, len(payload), max_data), 1):
        try:
            uds.transfer(n & 0xFF, payload[off:off + max_data])
        except Nrc as e:
            return t, uds, e
    return t, uds, None


# Check a stream with 64 random bytes spliced in mid-way is refused at the block that trips the inflater: with this seed
# the stream inflates past the announced size, so a 36 answers 0x31 with F1F1 DL_BAD_STREAM, and FF01 has nothing to
# verify.
def test_corrupt_stream_is_refused(demo):
    s = demo()
    image = z_image()
    z = bytearray(update.deflate(image))
    z[len(z) // 2:len(z) // 2 + 64] = random.Random(7).randbytes(64)
    t, uds, nrc = send_stream(s, image, z)
    with t:
        assert nrc is not None and nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(uds.read_did(wire.DID_RESULT))[0] == "DL_BAD_STREAM"
        with pytest.raises(Nrc) as e:
            uds.routine(wire.RID_CHECK_DEPS)
        assert e.value.code == wire.NRC_SEQUENCE


# Check a stream cut short passes every block but fails 37 with 0x72 and F1F1 DL_BAD_STREAM, and FF01 then has
# nothing to verify.
def test_truncated_stream_fails_transfer_exit(demo):
    s = demo()
    image = z_image()
    t, uds, nrc = send_stream(s, image, update.deflate(image)[:-20])
    with t:
        assert nrc is None
        with pytest.raises(Nrc) as e:
            uds.transfer_exit()
        assert e.value.code == wire.NRC_PROGRAMMING_FAILURE
        assert wire.decode_result(uds.read_did(wire.DID_RESULT))[0] == "DL_BAD_STREAM"
        with pytest.raises(Nrc) as e:
            uds.routine(wire.RID_CHECK_DEPS)
        assert e.value.code == wire.NRC_SEQUENCE


# Check the first-block rules run on the inflated bytes: a compressed image for another product is refused with
# 0x31 and DL_BAD_PROJECT before anything is erased.
def test_compressed_first_block_rules_refuse(demo):
    s = demo()
    image = z_image(product="widget")
    t, uds, nrc = send_stream(s, image, update.deflate(image))
    with t:
        assert nrc is not None and nrc.code == wire.NRC_OUT_OF_RANGE
        assert wire.decode_result(uds.read_did(wire.DID_RESULT)) == ("DL_BAD_PROJECT", 0)
        assert wire.decode_status(uds.read_did(wire.DID_STATUS))["other_state"] == 0


# ---- delta downloads (DFI 0x20, 0x30) ----

# Flashes base with a full download, so the server runs it; then returns the base and new of delta_pair's 48 KB pair
# with their files under tmp_path.
def running_base(server, tmp_path):
    pytest.importorskip("detools")
    base, new = delta_pair(payload=48 * 1024)
    assert run_cli(server, ["--profile", "example", "--interface", "pipe", "flash", image_file(tmp_path, base, "base.bin"),
                            "--compress"]) == 0
    return base, new, str(tmp_path / "base.bin"), image_file(tmp_path, new, "new.bin")


# Check `flash --diff-from` against the real server: it rebuilds the new image from the one it runs, from a patch of
# a few hundred bytes. By default 0x30 goes (the smaller mode), and --diff-format heatshrink sends 0x20; either way
# the new image runs and confirms.
@pytest.mark.parametrize("args, dfi", [([], wire.DL_DFI_DELTA_DEFLATE),
                                       (["--diff-format", "heatshrink"], wire.DL_DFI_DELTA)])
def test_flash_delta_runs_the_whole_sequence(demo, tmp_path, capsys, args, dfi):
    s = demo()
    base, new, base_path, new_path = running_base(s, tmp_path)
    capsys.readouterr()
    sent = []
    s.tap = sent.append
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", new_path, "--diff-from", base_path,
                       *args]) == 0
    assert any(is_34(m, dfi) for m in sent)
    assert not any(is_34(m, d) for m in sent for d in (wire.DL_DFI, wire.DL_DFI_DEFLATE))
    out = capsys.readouterr().out
    assert "delta, DFI 0x%02X" % dfi in out and "confirmed" in out
    status, sha, version = read_state(s)
    assert (status["running_state"], version, sha) == (VALID, "v0.3.0", elf_sha(new))


# Check a base with the running app_elf_sha256 but other bytes (a re-signed build of the same source) is refused by
# the server before anything is erased, with F1F1 DL_BAD_BASE, and the client then sends the full download.
def test_flash_delta_from_a_wrong_base_falls_back(demo, tmp_path, capsys):
    s = demo()
    base, new, _, new_path = running_base(s, tmp_path)
    other = bytearray(base)
    other[1000] ^= 0xFF
    wrong = image_file(tmp_path, reseal(other), "resigned.bin")
    capsys.readouterr()
    sent = []
    s.tap = sent.append
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", new_path, "--diff-from", wrong]) == 0
    assert any(is_34(m, wire.DL_DFI_DELTA_DEFLATE) for m in sent) and any(is_34(m, wire.DL_DFI) for m in sent)
    assert not any(is_34(m, wire.DL_DFI_DELTA) for m in sent)          # the base is wrong for every delta mode
    assert "not running the base this patch was made from" in capsys.readouterr().out
    assert read_state(s)[2] == "v0.3.0"


# Check a server without delta downloads answers each delta mode's 34 with 0x31, and the client tries the next, then
# the full download.
def test_flash_delta_on_a_server_without_it(demo, tmp_path, capsys):
    s = demo("--no-delta")
    base, new, base_path, new_path = running_base(s, tmp_path)
    capsys.readouterr()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", new_path, "--diff-from", base_path]) == 0
    out = capsys.readouterr().out
    assert "no delta downloads for DFI 0x30" in out and "no delta downloads for DFI 0x20" in out
    assert read_state(s)[2] == "v0.3.0"


# Check a delta download on a server whose flash jobs are slow, as the ESP32 port's worker is: the 37 runs as a job
# too and answers 0x78 before its 77, and the update completes.
def test_flash_delta_on_slow_jobs(demo, tmp_path):
    s = demo("--job-ms", "300")
    base, new, base_path, new_path = running_base(s, tmp_path)
    s.sent.clear()
    assert run_cli(s, ["--profile", "example", "--interface", "pipe", "flash", new_path, "--diff-from", base_path]) == 0
    assert 0x37 in {m.data[2] for m in s.sent if m.data[1] == 0x7F and m.data[3] == 0x78}
    assert read_state(s)[2] == "v0.3.0"
