"""The commands: info, the flash sequence (precheck to ConfirmImage, with its recovery paths), confirm and
the keyed reset, and under [update] flow = "bootloader" a single-slot bootloader unit's flash, info and reset. Every
product-specific step comes from the profile."""
import contextlib
import time

from .delta import validation_hash
from .errors import NoResponse, Nrc, Refused, SendFailed, UpdateFailed
from .image import parse_image
from .keys import DeviceKeys, SigningKeys
from .pack import build_patch, encode, rank_deltas, refuse_bare_delta
from .wire import (DID_COUNTERS, DID_DEVICE_ID, DID_IMAGE_PREFIX, DID_RESULT, DID_RUNNING_SHA, DID_SESSION,
                   DID_STATUS, DID_VERSION, DL_DFI, DL_DFI_DEFLATE, DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE,
                   IMG_PENDING_VERIFY, IMG_STATES, NRC_CONDITIONS, NRC_NOT_ACCEPTED, NRC_OUT_OF_RANGE,
                   NRC_PROGRAMMING_FAILURE, NRC_SEQUENCE, OTHER_VERIFIED, RID_ACTIVATE, RID_CHECK_DEPS, RID_CONFIRM,
                   SESSION_EXTENDED, SESSION_PROGRAMMING, STATUS_BOOT_HELD, DECODE, cstr, decode_counters,
                   decode_result, decode_status, describe_result, describe_status, reason_name)

REBOOT_WAIT_S = 3.0
BOOT_TIMEOUT_S = 60.0
BOOT_POLL_S = 1.0
CONFIRM_RETRY_S = 2.0    # between ConfirmImage tries; Uds's 3E 00 keepalive holds the extended session meanwhile
CONFIRM_TIMEOUT_S = 120.0   # a product's soak plus its health check, with margin
WAIT_RETRY_S = 0.05      # flash --wait-for-unit: the next 10 02 at most this long after the last went unanswered,
                         # so that one lands in a bootloader's power-up window (about 200 ms)
WAIT_SETTLE_S = 0.25     # then the answers to earlier 10 02s, which a unit sends a P2 (50 ms) apart, are passed
WAIT_DRAIN_S = 2.0       # over until none comes for WAIT_SETTLE_S, or for WAIT_DRAIN_S at most
# flash's diff_format (--diff-format): the delta DFIs it may try; and each delta DFI's name in the log.
DIFF_DFIS = {"auto": (DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE), "heatshrink": (DL_DFI_DELTA,),
             "deflate": (DL_DFI_DELTA_DEFLATE,)}
DELTA_NAMES = {DL_DFI_DELTA: "heatshrink patch", DL_DFI_DELTA_DEFLATE: "patch as raw DEFLATE"}

# The server-owned DIDs `info` reads first, with their labels and renderers; F1F3's label names the image's ID as
# the profile's image format does (id_name).
CORE_DIDS = ((DID_SESSION, "active session", DECODE["hex"]),
             (DID_VERSION, "version", cstr),
             (DID_DEVICE_ID, "device ID", lambda d: ":".join("%02x" % b for b in d)),
             (DID_RUNNING_SHA, "running %s", DECODE["hex"]),
             (DID_STATUS, "update status", lambda d: describe_status(decode_status(d))),
             (DID_RESULT, "last download", describe_result),
             (DID_COUNTERS, "ISO-TP/UDS counters",
              lambda d: " ".join("%s=%d" % kv for kv in decode_counters(d).items())))
NOT_UDSOTA = "the device does not serve the udsota status DID F1F0; is it running a udsota server?"
ACTIVATE_CONDITIONS = ("ActivateImage refused (0x22): the server's conditions are not met. The image stays verified "
                       "until the server restarts; run flash again when they are")
# What a bootloader-flow refusal after the 10 02 adds: where it leaves the unit.
LEFT_IN_BOOTLOADER = ("The unit is in its bootloader and returns to its app when its programming session times "
                      "out, unless it is held there")
WAIT_NEEDS_BOOTLOADER = '--wait-for-unit is for [update] flow = "bootloader"'
# What a --wait-for-unit that gives up adds: 10 02s the CAN adapter could not send while the unit was off stay queued.
WAIT_QUEUED = ("If the unit is off, 10 02s still queued in the CAN adapter will hold it in its bootloader for about "
               "5 s at its next power-up, once; taking the interface down and up clears them")


# What F1F3 holds for profile's images: an ESP-IDF image's app_elf_sha256, or a bare image's image ID.
def id_name(profile):
    return "image ID" if profile.image_format == "bare" else "app_elf_sha256"


# One DID's record, or None when the server answers 0x31 (it does not serve that DID).
def read_record(uds, did):
    try:
        return uds.read_did(did)
    except Nrc as e:
        if e.code != NRC_OUT_OF_RANGE:
            raise
        return None


# `info`: the server-owned DIDs, then the profile's [dids] in file order; a range stops at its first absent DID.
# Under flow "bootloader" it enters the programming session first, since the unit's app answers no reads, and sends
# no reset after.
def info(uds, profile, log=print):
    bootloader = profile.flow == "bootloader"
    if bootloader:
        uds.session(SESSION_PROGRAMMING)
    for did, name, render in CORE_DIDS:
        d = read_record(uds, did)
        name = name % id_name(profile) if did == DID_RUNNING_SHA else name
        log("%04X %s: %s" % (did, name, "not supported" if d is None else render(d)))
    for entry in profile.dids:
        for did in range(entry.first, entry.last + 1):
            d = read_record(uds, did)
            if d is None:
                if entry.first == entry.last:
                    log("%04X %s: not supported" % (did, entry.name))
                break
            log("%04X %s: %s" % (did, entry.name, DECODE[entry.decode](d)))
    if bootloader:
        log("the unit stays in its bootloader until its programming session times out")
    return 0


# Send one 0x36 block; resend it once after a plain timeout (the block-counter rule makes that safe).
def send_block(uds, bsc, chunk):
    try:
        uds.transfer(bsc, chunk)
    except NoResponse:
        uds.transfer(bsc, chunk)


# F1F1 as an error quotes it, or that it could not be read, so a failed read never hides the error being reported.
def last_result(uds):
    try:
        return "the last-result DID F1F1 reads %s" % describe_result(uds.read_did(DID_RESULT))
    except UpdateFailed:
        return "the last-result DID F1F1 could not be read"


# F1F1's reason name, or None when it cannot be read.
def last_reason(uds):
    try:
        return decode_result(uds.read_did(DID_RESULT))[0]
    except UpdateFailed:
        return None


# Block n's failure e as the same error naming the block. After a send the server stopped (SendFailed), with F1F1:
# a server that withheld flow control has ended the download (DL_ABORTED). After no answer the download may still
# be open, so F1F1 would describe the previous one; it is not read.
def block_failed(uds, n, e):
    if isinstance(e, SendFailed):
        return type(e)("block %d: %s; %s" % (n, e, last_result(uds)))
    return type(e)("block %d: %s" % (n, e))


# Why the server refused a compressed RequestDownload with nrc: (reason, the error a "deflate" run raises). 0x31 is a
# server without compressed downloads, or an image larger than its slot, which the same check refuses; 0x22 with F1F1
# DL_NO_MEMORY is one without memory for the inflater now. None for any other refusal, which is not about compression,
# or when F1F1 cannot be read: the caller then raises the 34's own NRC, not the F1F1 read's.
def compressed_refusal(uds, nrc):
    if nrc.code == NRC_OUT_OF_RANGE:
        why = "the server has no compressed downloads, or the image is larger than its slot"
        return why, Refused("%s (RequestDownload with DFI 0x10 answered 0x31); flash without --compress, or with "
                            "--compress-auto" % why)
    if nrc.code == NRC_CONDITIONS and last_reason(uds) == "DL_NO_MEMORY":
        why = "the server has no memory for a compressed download now"
        return why, UpdateFailed("%s (RequestDownload with DFI 0x10 answered 0x22, F1F1 DL_NO_MEMORY); a plain flash, "
                                 "without --compress, may work" % why)
    return None


# RequestDownload for image, compressed unless compress is "none": returns (payload, max_data), payload being what the
# 0x36 blocks carry. The 34 announces the image's own size either way. A compressed 34 the server refuses for a reason
# compressed_refusal names stops a "deflate" run there, and an "auto" run sends the image uncompressed instead.
def open_download(uds, image, compress, log=print):
    if compress == "none":
        return image, uds.request_download(len(image))
    payload = encode(image, DL_DFI_DEFLATE)
    try:
        max_data = uds.request_download(len(image), DL_DFI_DEFLATE)
    except Nrc as e:
        refusal = compressed_refusal(uds, e)
        if refusal is None:
            raise
        if compress != "auto":
            raise refusal[1] from e
        log("%s: sending the image uncompressed" % refusal[0])
        return image, uds.request_download(len(image), DL_DFI)
    log("compressed with raw DEFLATE: %d -> %d bytes (%.0f%%)" % (len(image), len(payload),
                                                                 100.0 * len(payload) / len(image)))
    return payload, max_data


# RequestDownload, every 0x36 block (counter from 1, wrapping 0xFF -> 0x00) and RequestTransferExit: first each
# delta in deltas ((dfi, payload) pairs, plan_deltas) in turn, then the image compressed per compress
# (open_download). A delta DFI the server answers 0x31, or 0x22 for memory, moves on to the next; a delta refused
# for its base (send_payload) skips the rest and sends the image, after reenter() (enter_programming) when the
# programming session has ended meanwhile: on a server on iso14229, whose S3 (5.1 s) restarts only on 10 and 3E, it
# ends while the client waits P2* (5.5 s) for a lost answer. drop_76 = N resends block N once as if its 76 were
# lost; an N past the last block is refused before any 0x36 (the CLI refuses it with deltas, whose size it can't
# know before the 34).
def download(uds, image, drop_76=None, log=print, compress="none", clock=time.monotonic, deltas=(), reenter=None):
    for dfi, patch in deltas:
        try:
            max_data = uds.request_download(len(image), dfi)
        except Nrc as e:
            if e.code == NRC_OUT_OF_RANGE:
                log("the device has no delta downloads for DFI 0x%02X (RequestDownload answered 0x31): trying the "
                    "next mode" % dfi)
                continue
            if e.code == NRC_CONDITIONS and last_reason(uds) == "DL_NO_MEMORY":
                log("the device has no memory for DFI 0x%02X now (RequestDownload answered 0x22, F1F1 "
                    "DL_NO_MEMORY): trying the next mode" % dfi)
                continue
            raise
        log("delta, DFI 0x%02X (%s): %d -> %d bytes (%.0f%%)" % (dfi, DELTA_NAMES[dfi], len(image), len(patch),
                                                                100.0 * len(patch) / len(image)))
        if send_payload(uds, image, patch, max_data, "delta", drop_76=drop_76, log=log, clock=clock):
            return
        log("the device is not running the base this patch was made from (0x36 answered 0x31, F1F1 DL_BAD_BASE; "
            "for example a rebuild of the same source that is not byte-identical): sending a full download")
        if reenter is not None and uds.read_did(DID_SESSION)[:1] != bytes([SESSION_PROGRAMMING]):
            log("the programming session ended while the answer was awaited: entering it again")
            reenter()
        break
    payload, max_data = open_download(uds, image, compress, log=log)
    send_payload(uds, image, payload, max_data, None if payload is image else "compressed", drop_76=drop_76,
                 log=log, clock=clock)


# The 0x36 blocks and the 0x37 of an open download of image carrying payload: the image itself (kind None), or it
# coded as kind ("compressed" or "delta"), which ends with the bytes sent and, compressed, the time saved; a delta's
# time is mostly the server rebuilding and writing the image, not the bus, so it gives no full download's time. True
# when done; False when a delta's 36 was refused with F1F1 DL_BAD_BASE, which ends the download on the server: 0x31,
# or, when that answer was lost, a refused resend of the block: 0x70 from a server on iso14229, which has no transfer
# open, 0x24 from a v0.14.x one, or for a block over 256 bytes a resend a v0.14.x server's ISO-TP refuses.
def send_payload(uds, image, payload, max_data, kind, drop_76=None, log=print, clock=time.monotonic):
    total = (len(payload) + max_data - 1) // max_data
    if drop_76 is not None and drop_76 > total:
        raise Refused("--drop-76 %d: the download is only %d blocks of %d bytes" % (drop_76, total, max_data))
    start = clock()
    try:
        for n in range(1, total + 1):
            chunk = payload[(n - 1) * max_data:n * max_data]
            try:
                send_block(uds, n & 0xFF, chunk)
                if n == drop_76:
                    log("--drop-76: resending block %d as if its 76 were lost" % n)
                    send_block(uds, n & 0xFF, chunk)
            except (NoResponse, SendFailed) as e:
                if kind == "delta" and isinstance(e, SendFailed) and last_reason(uds) == "DL_BAD_BASE":
                    return False
                raise block_failed(uds, n, e) from e
            if n % 32 == 0 or n == total:
                log("sent %d of %d bytes" % (min(n * max_data, len(payload)), len(payload)))
        transfer_exit(uds, len(payload), log=log)
    except Nrc as e:
        if kind is None:
            raise
        # 0x70 or 0x24: the server's 0x31 was lost and the resent block found the download it had already ended.
        if (kind == "delta" and e.sid == 0x36 and e.code in (NRC_OUT_OF_RANGE, NRC_NOT_ACCEPTED, NRC_SEQUENCE)
                and last_reason(uds) == "DL_BAD_BASE"):
            return False
        raise UpdateFailed("%s; %s" % (e, last_result(uds))) from e
    took = clock() - start
    if kind == "compressed":
        log("sent %d %s bytes in %.1f s; the %d-byte image would take about %.1f s, so about %.1f s saved"
            % (len(payload), kind, took, len(image), took * len(image) / len(payload),
               took * (len(image) - len(payload)) / len(payload)))
    elif kind == "delta":
        log("sent %d delta bytes in %.1f s in place of the %d-byte image" % (len(payload), took, len(image)))
    return True


# The one base in bases ((name, bytes) pairs) whose app_elf_sha256 is running_sha, the running image's; None, saying
# why, when no file or several different ones match, when it is image itself, or when it has no appended SHA-256.
def choose_base(bases, image, running_sha, log=print):
    found = {}
    for name, data in bases:
        if bytes(data[176:208]) == running_sha:
            found.setdefault(bytes(data), name)
    if not found:
        log("no delta: none of the %d base files has the running app_elf_sha256 %s"
            % (len(bases), running_sha[:8].hex()))
        return None
    if len(found) > 1:
        log("no delta: %d different base files have the running app_elf_sha256 %s: %s"
            % (len(found), running_sha[:8].hex(), ", ".join(found.values())))
        return None
    (base, name), = found.items()
    if base == bytes(image):
        log("no delta: the base %s is the new image itself" % name)
        return None
    if validation_hash(base) is None:
        log("no delta: the base %s has no valid appended SHA-256, which the device checks it against" % name)
        return None
    log("delta base: %s" % name)
    return base


# The delta downloads worth trying for image, as (dfi, payload) pairs smallest first: the modes diff_format allows
# (DIFF_DFIS) but 0x30 without deflate_ok (default: compress is not "none"), each only when its payload is smaller
# than what the full path would send (the image, raw DEFLATE unless compress is "none"). Empty when bases hold no
# usable base (choose_base).
def plan_deltas(bases, image, running_sha, compress, diff_format, log=print, deflate_ok=None):
    base = choose_base(bases, image, running_sha, log=log)
    if base is None:
        return []
    deflate_ok = compress != "none" if deflate_ok is None else deflate_ok
    dfis = [d for d in DIFF_DFIS[diff_format] if deflate_ok or d != DL_DFI_DELTA_DEFLATE]
    if not dfis:
        log("no delta: DFI 0x30 is raw DEFLATE, which --no-compress rules out")
        return []
    full = len(encode(image, DL_DFI if compress == "none" else DL_DFI_DEFLATE))
    payloads = {dfi: build_patch(image, dfi, base) for dfi in dfis}
    worth, rest = rank_deltas({d: len(p) for d, p in payloads.items()}, full)
    for dfi in rest:
        log("no delta over DFI 0x%02X: its %d bytes are no fewer than the full download's %d"
            % (dfi, len(payloads[dfi]), full))
    return [(dfi, payloads[dfi]) for dfi in worth]


# RequestTransferExit, resent once after a plain timeout. A resend refused with 0x24 means the first 0x37
# closed the transfer and only its 77 was lost when the last-result DID reads (DL_OK, every byte); else it stops.
def transfer_exit(uds, size, log=print):
    try:
        uds.transfer_exit()
        return
    except NoResponse:
        log("no answer to 0x37: resending it")
    try:
        uds.transfer_exit()
    except Nrc as e:
        if e.code != NRC_SEQUENCE:
            raise
        reason, received = decode_result(uds.read_did(DID_RESULT))
        if (reason, received) != ("DL_OK", size):
            log("last result after the resent 0x37: %s, %d of %d bytes received" % (reason, received, size))
            raise
        log("the first 0x37 closed the transfer (its 77 was lost): last result DL_OK, %d bytes" % size)


# CheckProgrammingDependencies (FF01), resent once after a plain timeout: after a pass the server
# repeats status 00. A resend refused with 0x24 means the first run failed; the last-result DID names why.
def check_image(uds, log=print):
    try:
        status = uds.routine(RID_CHECK_DEPS)
    except NoResponse:
        log("no answer to FF01: resending it")
        try:
            status = uds.routine(RID_CHECK_DEPS)
        except Nrc as e:
            if e.code != NRC_SEQUENCE:
                raise
            reason, _ = decode_result(uds.read_did(DID_RESULT))
            raise UpdateFailed("CheckProgrammingDependencies failed: %s (its answer was lost; read from F1F1)"
                               % reason) from e
    if not status or status[0] != 0:
        raise UpdateFailed("CheckProgrammingDependencies failed: %s"
                           % (reason_name(status[0]) if status else "no status"))


# Wait for a restarting server: pre-roll and poll the running SHA until it answers, and return it. after names what
# restarted it, for the timeout message. The server comes back in the default session, so no 3E 00 precedes a poll.
def wait_for_boot(uds, preroll, after, sleep=time.sleep, clock=time.monotonic):
    uds.restarted()
    sleep(REBOOT_WAIT_S)
    deadline = clock() + BOOT_TIMEOUT_S
    while True:
        preroll()
        try:
            return uds.read_did(DID_RUNNING_SHA)
        except (NoResponse, SendFailed):   # a rebooting server answers nothing, or leaves a send unacknowledged
            if clock() >= deadline:
                raise UpdateFailed("the server did not answer within %d s of %s" % (BOOT_TIMEOUT_S, after))
            sleep(BOOT_POLL_S)


# After ActivateImage: wait for the restart, then check the server runs the new image sha.
def wait_for_image(uds, sha, preroll, sleep=time.sleep, clock=time.monotonic):
    running = wait_for_boot(uds, preroll, "ActivateImage", sleep=sleep, clock=clock)
    if running != sha:
        raise UpdateFailed("the server runs %s, not the new image %s: it reverted or never switched; "
                           "read F1F0 with `info`" % (running[:8].hex(), sha[:8].hex()))


# ConfirmImage in the extended session, retrying NRC 0x22 until the product's soak and health check pass.
def confirm(uds, sleep=time.sleep, clock=time.monotonic, log=print):
    uds.session(SESSION_EXTENDED)
    deadline = clock() + CONFIRM_TIMEOUT_S
    while True:
        try:
            uds.routine(RID_CONFIRM)
            break
        except Nrc as e:
            if e.code != NRC_CONDITIONS or clock() >= deadline:
                raise
            sleep(CONFIRM_RETRY_S)
    log("confirmed: %s" % describe_status(decode_status(uds.read_did(DID_STATUS))))
    return 0


# `confirm`: confirm the running image if it is PENDING_VERIFY, else report there is nothing to do.
def confirm_cmd(uds, sleep=time.sleep, clock=time.monotonic, log=print):
    state = decode_status(uds.read_did(DID_STATUS))
    if state["running_state"] != IMG_PENDING_VERIFY:
        log("the running image is %s: nothing to confirm" % IMG_STATES.get(state["running_state"], "?"))
        return 0
    return confirm(uds, sleep=sleep, clock=clock, log=log)


# The server's device ID (the profile's device_id_did); None when the profile has no [security].
def read_device_id(uds, profile):
    return None if profile.security is None else uds.read_did(profile.security.device_id_did)


# The keys for device_id: DeviceKeys from the master key (mode hmac) or SigningKeys from the private key (mode
# ecdsa), secret being that key; None when the profile has no [security].
def make_keys(profile, secret, device_id):
    if profile.security is None:
        return None
    if profile.security.mode == "ecdsa":
        return SigningKeys(secret, device_id)
    return DeviceKeys(secret, profile.security.label, device_id)


# The keys for this server, reading its device ID; None when the profile has no [security].
def device_keys(uds, profile, secret):
    return make_keys(profile, secret, read_device_id(uds, profile))


# `flash`: precheck, programming session (and unlock), download, FF01, ActivateImage, the restart and
# ConfirmImage. Returns 0 or raises ToolError. secret is the master or private key (make_keys), unused when the
# profile has no [security]. quiet() is entered once an update is needed and held until the end (the transport's
# bus quieting). compress is "none", "deflate" or "auto" (download); None takes the profile's [image] compression.
# bases, (name, bytes) pairs, offers a delta download from the one the server runs, in the modes diff_format
# allows (plan_deltas); its patches are built before the programming session opens. Only an explicit "none"
# (--no-compress) rules out the DEFLATE delta, 0x30: a server with delta downloads has compressed ones too, and one
# without answers 0x31. Under the profile's [update] flow = "bootloader", flash_bootloader runs instead, and
# wait_for_unit (seconds, --wait-for-unit), which that flow alone takes, has it catch the unit's power-up window.
def flash(uds, profile, image, secret, drop_76=None, preroll=lambda: None, sleep=time.sleep,
          clock=time.monotonic, log=print, quiet=contextlib.nullcontext, compress=None, bases=None,
          diff_format="auto", wait_for_unit=None):
    if wait_for_unit is not None and profile.flow != "bootloader":
        raise Refused(WAIT_NEEDS_BOOTLOADER)
    if bases is not None and drop_76 is not None:
        raise Refused("--drop-76 is for full and compressed downloads, not with --diff-from")
    if bases is not None:
        refuse_bare_delta(profile)
    deflate_ok = compress != "none"             # before the profile's default: see the comment above
    compress = profile.compression if compress is None else compress
    img = parse_image(profile, image)
    board_of = profile.board_names.get(img.hw_id, "hw_id %d" % img.hw_id)
    log("image %s for %s, %d bytes, %s %s" % (img.version, board_of, img.size, id_name(profile),
                                              img.elf_sha[:8].hex()))
    if profile.flow == "bootloader":
        return flash_bootloader(uds, profile, image, img, secret, drop_76=drop_76, preroll=preroll, sleep=sleep,
                                clock=clock, log=log, quiet=quiet, compress=compress, bases=bases,
                                diff_format=diff_format, deflate_ok=deflate_ok, wait_for_unit=wait_for_unit)
    status = read_record(uds, DID_STATUS)
    if status is None:                        # 0x31: no udsota status DID, so no udsota server
        raise Refused(NOT_UDSOTA)
    state = decode_status(status)
    running_sha = uds.read_did(DID_RUNNING_SHA)
    board = None if profile.board_did is None else cstr(uds.read_did(profile.board_did))
    device_id = read_device_id(uds, profile)   # read in the precheck, used only once an update is needed
    if running_sha == img.elf_sha:
        if state["running_state"] == IMG_PENDING_VERIFY:   # an earlier run stopped before ConfirmImage
            log("the server runs this image (%s) unconfirmed: confirming" % img.elf_sha[:8].hex())
            return confirm(uds, sleep=sleep, clock=clock, log=log)
        log("the server already runs this image (%s): nothing to do" % img.elf_sha[:8].hex())
        return 0
    if state["running_state"] == IMG_PENDING_VERIFY:
        raise Refused("the running image is unconfirmed: run `confirm`, or `reset` to roll it back")
    if board is not None and board != profile.board_names.get(img.hw_id):
        raise Refused("image is for %s but the server is %s" % (board_of, board))
    verified = state["other_state"] == OTHER_VERIFIED and state["other_sha_prefix"] == img.elf_sha[:8]
    keys = make_keys(profile, secret, device_id)
    deltas = []
    if bases is not None and not verified:
        deltas = plan_deltas(bases, image, running_sha, compress, diff_format, log=log, deflate_ok=deflate_ok)
    with quiet():                             # [functional] quiet_bus: the other nodes stay quiet until the end
        enter_programming(uds, profile, keys)
        if verified:
            log("the other slot already holds this image, verified: skipping to ActivateImage")
        need_download, recovered, resent = not verified, False, False
        while True:
            if need_download:
                download(uds, image, drop_76=drop_76, log=log, compress=compress, clock=clock, deltas=deltas,
                         reenter=lambda: enter_programming(uds, profile, keys))
                check_image(uds, log=log)
                need_download, drop_76 = False, None   # the fault injection applies to the first download only
            try:
                uds.routine(RID_ACTIVATE)
                break
            except NoResponse:
                if activation_landed(uds, img.elf_sha, log=log):
                    break
                if resent:
                    raise
                resent = True                     # the request itself was lost: send it once more
            except Nrc as e:
                if e.code == NRC_CONDITIONS:
                    raise UpdateFailed(ACTIVATE_CONDITIONS) from e
                if e.code == NRC_PROGRAMMING_FAILURE:
                    activation_failed(uds, profile, keys, e, log=log)
                    break
                if recovered or e.code != NRC_SEQUENCE:
                    raise
                log("ActivateImage answered 0x24 (the slot is not verified): downloading again")
                recovered = need_download = True   # one re-download per run
        log("activated; waiting for the server to restart")
        wait_for_image(uds, img.elf_sha, preroll, sleep=sleep, clock=clock)
        log("the server runs %s; confirming" % img.version)
        return confirm(uds, sleep=sleep, clock=clock, log=log)


# `flash` under [update] flow = "bootloader", for a single-slot unit whose resident bootloader is its only UDS server
# (docs/wire.md#bootloader-flow); img is image parsed, the other arguments flash's. First one F1F4 read in the default
# session: an app already running this image and healthy needs nothing, so it is left running. Then 10 02: the app
# answers 7F 10 78 and resets into the bootloader, which sends the 50 02; a late answer to an F1F4 read that went
# unanswered, such as a bootloader's 7F 22 31 to one the adapter held, is passed over ahead of it (Uds.exchange).
# Then, all in the programming session, the precheck reads, the unlock, download, FF01, ActivateImage and
# wait_for_start, the proof of life; no ConfirmImage. An image the unit already holds gets 11 01 and the same proof.
# quiet() is held from the 10 02, which stops the app.
# With wait_for_unit, wait_for_power_up sends the 10 02.
def flash_bootloader(uds, profile, image, img, secret, drop_76=None, preroll=lambda: None, sleep=time.sleep,
                     clock=time.monotonic, log=print, quiet=contextlib.nullcontext, compress="none", bases=None,
                     diff_format="auto", deflate_ok=True, wait_for_unit=None):
    try:
        prefix = uds.read_did(DID_IMAGE_PREFIX)
    except (Nrc, NoResponse, SendFailed):    # 0x31 from the bootloader, or an app that is not healthy
        prefix = None
    if prefix == img.elf_sha[:4]:
        log("the unit's app already runs this image (F1F4 %s) and reports healthy: nothing to do" % prefix.hex())
        return 0
    with quiet():
        if wait_for_unit is None:
            uds.session(SESSION_PROGRAMMING)
        else:
            wait_for_power_up(uds, wait_for_unit, log=log, clock=clock)
        status = read_record(uds, DID_STATUS)
        if status is None:
            raise Refused("%s %s" % (NOT_UDSOTA, LEFT_IN_BOOTLOADER))
        state = decode_status(status)
        running_sha = uds.read_did(DID_RUNNING_SHA)
        board = None if profile.board_did is None else cstr(uds.read_did(profile.board_did))
        keys = device_keys(uds, profile, secret)
        unlock_programming(uds, profile, keys)
        held = state["flags"] & STATUS_BOOT_HELD
        if held:
            log("the unit is held in its bootloader: its app failed to start")
        if running_sha == img.elf_sha:
            log("the unit already holds this image (%s)%s: resetting into it" % (
                img.elf_sha[:8].hex(), "; the reset releases it for another try" if held else ""))
            uds.ecu_reset()
            return wait_for_start(uds, profile, img.elf_sha, preroll, sleep=sleep, clock=clock, log=log)
        board_of = profile.board_names.get(img.hw_id, "hw_id %d" % img.hw_id)
        if board is not None and board != profile.board_names.get(img.hw_id):
            raise Refused("image is for %s but the server is %s. %s" % (board_of, board, LEFT_IN_BOOTLOADER))
        verified = state["other_state"] == OTHER_VERIFIED and state["other_sha_prefix"] == img.elf_sha[:8]
        deltas = []
        if bases is not None and not verified:
            deltas = plan_deltas(bases, image, running_sha, compress, diff_format, log=log, deflate_ok=deflate_ok)
            enter_programming(uds, profile, keys)   # building the patches, used or not, may have outlasted S3
        if verified:
            log("the other slot already holds this image, verified: skipping to ActivateImage")
        need_download, recovered, resent, activated = not verified, False, False, True
        while True:
            if need_download:
                download(uds, image, drop_76=drop_76, log=log, compress=compress, clock=clock, deltas=deltas,
                         reenter=lambda: enter_programming(uds, profile, keys))
                check_image(uds, log=log)
                need_download, drop_76 = False, None   # the fault injection applies to the first download only
            try:
                uds.routine(RID_ACTIVATE)
                log("activated; waiting for the app to start")
                break
            except NoResponse:
                # F1F3 already reads the new ID after FF01, so it can't tell whether F001 landed: F1F4 decides.
                if resent:
                    log("no answer to ActivateImage again: waiting for the app to start, which decides")
                    activated = False
                    break
                log("no answer to ActivateImage: sending it again")
                resent = True
            except Nrc as e:
                if resent:                    # the app, if the first F001 started it, refuses a routine: F1F4 decides
                    log("ActivateImage sent again answered 0x%02X: waiting for the app to start, which decides"
                        % e.code)
                    activated = False
                    break
                if e.code == NRC_CONDITIONS:
                    raise UpdateFailed(ACTIVATE_CONDITIONS) from e
                if e.code == NRC_PROGRAMMING_FAILURE:
                    raise UpdateFailed("ActivateImage failed (0x72); read F1F0 with `info`") from e
                if recovered or e.code != NRC_SEQUENCE:
                    raise
                log("ActivateImage answered 0x24 (the image is not verified): downloading again")
                recovered = need_download = True   # one re-download per run
        return wait_for_start(uds, profile, img.elf_sha, preroll, sleep=sleep, clock=clock, log=log,
                              activated=activated)


# The bootloader flow's 10 02 under --wait-for-unit, for a unit whose app runs but cannot hand over. The first 10 02
# goes as without the option, a live app's 7F 10 78 waited out for its 50 02 as for any request, and once it is
# answered the flow goes on. Otherwise the operator is told to power-cycle the unit, whose bootloader also takes a
# 10 02 in its power-up window, while 10 02 goes out again, the next at most WAIT_RETRY_S after the last went
# unanswered, was refused or failed to send (Uds.try_session, which waits no longer than that after a 0x78 or 0x21
# either), until one is answered 50 02; UpdateFailed once seconds have passed since the prompt, saying what the 10 02s
# still queued then do (WAIT_QUEUED), as a wait the operator interrupts also logs. A failed send, as while the unit
# is off and nothing acknowledges the frame, is a try like any other. The unit answers every 10 02 it gets, the ones
# the kernel still held unacknowledged among them,
# so 50 02s can follow the first; they are passed over until the unit goes quiet (Uds.drain), the monitor counting
# that as ours, before the next request goes. Dropping them is not enough, though udsoncan empties the receive queue
# before each send: one that comes after that send is taken for its answer, and the request itself can reach the unit
# while it is still answering 10 02s.
def wait_for_power_up(uds, seconds, log=print, clock=time.monotonic):
    try:
        uds.session(SESSION_PROGRAMMING)
        return
    except (Nrc, NoResponse, SendFailed):
        pass
    log("waiting up to %d s for the unit: power-cycle it now" % seconds)
    start, tries = clock(), 1
    try:
        while True:
            tries += 1
            if uds.try_session(SESSION_PROGRAMMING, WAIT_RETRY_S):
                break
            if clock() - start >= seconds:
                raise UpdateFailed("no 10 02 was answered within %d s (%d tries). %s" % (seconds, tries, WAIT_QUEUED))
    except KeyboardInterrupt:
        log(WAIT_QUEUED)
        raise
    took = clock() - start
    late = uds.drain(WAIT_SETTLE_S, WAIT_DRAIN_S)
    passed = "; passed over %d later answers" % late if late else ""
    log("10 02 answered after %.1f s, at try %d%s" % (took, tries, passed))


# The bootloader flow's proof of life after ActivateImage or 11 01: wait REBOOT_WAIT_S, then poll F1F4 until the
# unit's app answers it, which it does once healthy, for up to the profile's start_timeout_s, and check it is the first
# 4 bytes of sha. Returns 0, or raises UpdateFailed: another prefix (the app runs another image), 0x31 (the bootloader
# answers: the app did not start, F1F0 saying whether the unit holds itself there; or, when activated is False because
# no F001 was answered, perhaps never activated), or nothing within the timeout. Silence is never success.
def wait_for_start(uds, profile, sha, preroll, sleep=time.sleep, clock=time.monotonic, log=print, activated=True):
    uds.restarted()
    sleep(REBOOT_WAIT_S)
    deadline = clock() + profile.start_timeout_s
    while True:
        preroll()
        try:
            prefix = uds.read_did(DID_IMAGE_PREFIX)
        except (NoResponse, SendFailed):   # the unit is restarting, or its app is not healthy yet
            if clock() >= deadline:
                raise UpdateFailed("nothing answered F1F4 in %d s of polling after the restart, so the app has not "
                                   "reported healthy" % profile.start_timeout_s)
            sleep(BOOT_POLL_S)
            continue
        except Nrc as e:
            if e.code != NRC_OUT_OF_RANGE:
                raise
            if not activated:
                raise UpdateFailed("ActivateImage got no answer and the unit is still in its bootloader (F1F4 "
                                   "answered 0x31): run flash again; %s" % unit_status(uds)) from e
            raise UpdateFailed("the unit is back in its bootloader (F1F4 answered 0x31): the app did not start; %s"
                               % unit_status(uds)) from e
        if prefix != sha[:4]:
            raise UpdateFailed("the app runs another image: F1F4 reads %s, not the new image's %s"
                               % (prefix.hex(), sha[:4].hex()))
        log("the app runs the new image (F1F4 %s) and reports healthy" % prefix.hex())
        return 0


# F1F0 as an error quotes it, or that it could not be read, so a failed read never hides the error being reported.
def unit_status(uds):
    try:
        return "F1F0: %s" % describe_status(decode_status(uds.read_did(DID_STATUS)))
    except UpdateFailed:
        return "F1F0 could not be read"


# After no answer to ActivateImage: True when the server activated anyway, so its answer, not the request, was
# lost. A server that answers nothing is restarting, one that already runs the new image (sha) has restarted, and
# one whose boot slot is not its running slot has switched and restarts next. False when it answers, runs the old
# image and has not switched: the request itself was lost.
def activation_landed(uds, sha, log=print):
    try:
        running = uds.read_did(DID_RUNNING_SHA)
        state = decode_status(uds.read_did(DID_STATUS))
    except (NoResponse, SendFailed):
        log("no answer to ActivateImage, and none since: the server is restarting")
        return True
    if running == sha:
        log("no answer to ActivateImage, but the server already runs the new image")
        return True
    if state["boot_slot"] != state["running_slot"]:
        log("no answer to ActivateImage, but the boot slot has switched")
        return True
    log("no answer to ActivateImage and the boot slot has not switched: sending it again")
    return False


# After 0x72 to ActivateImage: the status DID shows whether set_boot landed (boot slot != running slot). If it
# did, a (keyed) 11 01 restarts the server into the new image and the caller continues; else it stops.
def activation_failed(uds, profile, keys, nrc, log=print):
    state = decode_status(uds.read_did(DID_STATUS))
    if state["boot_slot"] == state["running_slot"]:
        raise UpdateFailed("ActivateImage failed (0x72) and the activation did not land yet (F1F0: %s); if the "
                           "90 s cap ended the job it may still land: run `info` and check the boot slot before "
                           "retrying" % describe_status(state)) from nrc
    log("ActivateImage failed (0x72) but set_boot landed (boot slot %d, running slot %d): resetting"
        % (state["boot_slot"], state["running_slot"]))
    try:
        keyed_reset(uds, profile, keys)
    except Nrc as e:
        if e.code != NRC_CONDITIONS:
            raise
        raise UpdateFailed("set_boot landed but the reset was refused (0x22): the server's flash job may still "
                           "be running, or the product's conditions are not met. Run `reset` when they are, "
                           "then `confirm`") from e


# 10 02, then the programming unlock when the profile has [security]: download, FF01 and ActivateImage need it.
def enter_programming(uds, profile, keys):
    uds.session(SESSION_PROGRAMMING)
    unlock_programming(uds, profile, keys)


# The programming unlock with keys; nothing when the profile has no [security] (keys None).
def unlock_programming(uds, profile, keys):
    if keys is not None:
        uds.unlock(profile.security.level_programming, keys)


# 10 03, the extended unlock when the profile has [security], and 11 01: the server answers, then restarts
# (an unconfirmed image rolls back).
def keyed_reset(uds, profile, keys):
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)
    uds.ecu_reset()


# `reset`: ECUReset from the extended session, keyed when the profile has [security]. Under flow "bootloader", from
# the programming session instead (10 02, the device ID, the programming unlock, 11 01): the unit leaves its
# bootloader for its app.
def reset(uds, profile, secret, log=print):
    if profile.flow == "bootloader":
        uds.session(SESSION_PROGRAMMING)
        unlock_programming(uds, profile, device_keys(uds, profile, secret))
        uds.ecu_reset()
        log("reset accepted: the unit leaves its bootloader for its app")
        return 0
    keyed_reset(uds, profile, device_keys(uds, profile, secret))
    log("reset accepted: the server restarts")
    return 0
