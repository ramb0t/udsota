"""The commands: info, the flash sequence (precheck to ConfirmImage, with its recovery paths), confirm and
the keyed reset. Every product-specific step comes from the profile."""
import contextlib
import time

from .errors import NoResponse, Nrc, Refused, SendFailed, UpdateFailed
from .image import parse_image
from .keys import DeviceKeys
from .wire import (DID_COUNTERS, DID_DEVICE_ID, DID_RESULT, DID_RUNNING_SHA, DID_SESSION, DID_STATUS, DID_VERSION,
                   IMG_PENDING_VERIFY, IMG_STATES, NRC_CONDITIONS, NRC_OUT_OF_RANGE, NRC_PROGRAMMING_FAILURE,
                   NRC_SEQUENCE, OTHER_VERIFIED, RID_ACTIVATE, RID_CHECK_DEPS, RID_CONFIRM, SESSION_EXTENDED,
                   SESSION_PROGRAMMING, cstr, decode_counters, decode_result, decode_status, describe_status,
                   reason_name)

REBOOT_WAIT_S = 3.0
BOOT_TIMEOUT_S = 60.0
BOOT_POLL_S = 1.0
CONFIRM_RETRY_S = 2.0    # under S3 (5 s), so the retries keep the extended session open
CONFIRM_TIMEOUT_S = 120.0   # a product's soak plus its health check, with margin

# The server-owned DIDs `info` reads first, with their labels and renderers.
CORE_DIDS = ((DID_SESSION, "active session", lambda d: d.hex(" ")),
             (DID_VERSION, "version", cstr),
             (DID_DEVICE_ID, "device ID", lambda d: ":".join("%02x" % b for b in d)),
             (DID_RUNNING_SHA, "running app_elf_sha256", lambda d: d.hex(" ")),
             (DID_STATUS, "update status", lambda d: describe_status(decode_status(d))),
             (DID_RESULT, "last download", lambda d: "%s, %d bytes received" % decode_result(d)),
             (DID_COUNTERS, "ISO-TP/UDS counters",
              lambda d: " ".join("%s=%d" % kv for kv in decode_counters(d).items())))
DECODE = {"hex": lambda d: d.hex(" "), "ascii": cstr,
          "version3": lambda d: "%d.%d.%d" % tuple(d) if len(d) == 3 else d.hex(" ")}


# `info`: the server-owned DIDs, then the profile's [dids] in file order; a range stops at its first absent DID.
def info(uds, profile, log=print):
    for did, name, render in CORE_DIDS:
        try:
            log("%04X %s: %s" % (did, name, render(uds.read_did(did))))
        except Nrc as e:
            if e.code != NRC_OUT_OF_RANGE:
                raise
            log("%04X %s: not supported" % (did, name))
    for entry in profile.dids:
        for did in range(entry.first, entry.last + 1):
            try:
                d = uds.read_did(did)
            except Nrc as e:
                if e.code != NRC_OUT_OF_RANGE:
                    raise
                if entry.first == entry.last:
                    log("%04X %s: not supported" % (did, entry.name))
                break
            log("%04X %s: %s" % (did, entry.name, DECODE[entry.decode](d)))
    return 0


# Send one 0x36 block; resend it once after a plain timeout (the block-counter rule makes that safe).
def send_block(uds, bsc, chunk):
    try:
        uds.transfer(bsc, chunk)
    except NoResponse:
        uds.transfer(bsc, chunk)


# RequestDownload, every 0x36 block (counter from 1, wrapping 0xFF -> 0x00) and RequestTransferExit.
# drop_76 = N resends block N once as if its 76 were lost; an N past the last block is refused before any 0x36.
def download(uds, image, drop_76=None, log=print):
    max_data = uds.request_download(len(image))
    total = (len(image) + max_data - 1) // max_data
    if drop_76 is not None and drop_76 > total:
        raise Refused("--drop-76 %d: the image is only %d blocks of %d bytes" % (drop_76, total, max_data))
    for n in range(1, total + 1):
        chunk = image[(n - 1) * max_data:n * max_data]
        send_block(uds, n & 0xFF, chunk)
        if n == drop_76:
            log("--drop-76: resending block %d as if its 76 were lost" % n)
            send_block(uds, n & 0xFF, chunk)
        if n % 32 == 0 or n == total:
            log("sent %d of %d bytes" % (min(n * max_data, len(image)), len(image)))
    transfer_exit(uds, len(image), log=log)


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


# After ActivateImage: wait for the restart, pre-rolling and polling the running SHA until the server answers.
def wait_for_image(uds, sha, preroll, sleep=time.sleep, clock=time.monotonic):
    sleep(REBOOT_WAIT_S)
    deadline = clock() + BOOT_TIMEOUT_S
    while True:
        preroll()
        try:
            running = uds.read_did(DID_RUNNING_SHA)
            break
        except (NoResponse, SendFailed):   # a rebooting server answers nothing, or leaves a send unacknowledged
            if clock() >= deadline:
                raise UpdateFailed("the server did not answer within %d s of ActivateImage" % BOOT_TIMEOUT_S)
            sleep(BOOT_POLL_S)
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


# The DeviceKeys for device_id; None when the profile has no [security].
def make_keys(profile, master, device_id):
    return None if profile.security is None else DeviceKeys(master, profile.security.label, device_id)


# The DeviceKeys for this server, reading its device ID; None when the profile has no [security].
def device_keys(uds, profile, master):
    return make_keys(profile, master, read_device_id(uds, profile))


# The precheck's F1F0 read; NRC 0x31 means the device does not serve udsota's status DID, so it is no udsota server.
def read_status_precheck(uds):
    try:
        return uds.read_did(DID_STATUS)
    except Nrc as e:
        if e.code != NRC_OUT_OF_RANGE:
            raise
        raise Refused("the device does not serve the udsota status DID F1F0; is it running a udsota server?") from e


# `flash`: precheck, programming session (and unlock), download, FF01, ActivateImage, the restart and
# ConfirmImage. Returns 0 or raises ToolError. master is unused when the profile has no [security]. quiet() is
# entered once an update is needed and held until the end (the transport's bus quieting).
def flash(uds, profile, image, master, drop_76=None, preroll=lambda: None, sleep=time.sleep,
          clock=time.monotonic, log=print, quiet=contextlib.nullcontext):
    img = parse_image(profile, image)
    board_of = profile.board_names.get(img.hw_id, "hw_id %d" % img.hw_id)
    log("image %s for %s, %d bytes, app_elf_sha256 %s" % (img.version, board_of, img.size, img.elf_sha[:8].hex()))
    state = decode_status(read_status_precheck(uds))
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
    keys = make_keys(profile, master, device_id)
    with quiet():                             # [functional] quiet_bus: the other nodes stay quiet until the end
        enter_programming(uds, profile, keys)
        if verified:
            log("the other slot already holds this image, verified: skipping to ActivateImage")
        need_download, recovered, resent = not verified, False, False
        while True:
            if need_download:
                download(uds, image, drop_76=drop_76, log=log)
                check_image(uds, log=log)
                drop_76 = None                    # the fault injection applies to the first download only
            try:
                uds.routine(RID_ACTIVATE)
                break
            except NoResponse:
                if activation_landed(uds, log=log):
                    break
                if resent:
                    raise
                resent, need_download = True, False   # the request itself was lost: send it once more
                continue
            except Nrc as e:
                if e.code == NRC_CONDITIONS:
                    raise UpdateFailed("ActivateImage refused (0x22): the server's conditions are not met. The image "
                                       "stays verified until the server restarts; run flash again when they are") from e
                if e.code == NRC_PROGRAMMING_FAILURE:
                    activation_failed(uds, profile, keys, e, log=log)
                    break
                if recovered or e.code != NRC_SEQUENCE:
                    raise
                recovered = True                  # one re-download per run
            log("ActivateImage answered 0x24 (the slot is not verified): downloading again")
            need_download = True
        log("activated; waiting for the server to restart")
        wait_for_image(uds, img.elf_sha, preroll, sleep=sleep, clock=clock)
        log("the server runs %s; confirming" % img.version)
        return confirm(uds, sleep=sleep, clock=clock, log=log)


# After no answer to ActivateImage: True when the server activated anyway, so its answer, not the request, was
# lost. A server that answers nothing is restarting; one whose boot slot is not its running slot has switched and
# restarts next. False when it answers and has not switched: the request itself was lost.
def activation_landed(uds, log=print):
    try:
        state = decode_status(uds.read_did(DID_STATUS))
    except (NoResponse, SendFailed):
        log("no answer to ActivateImage, and none since: the server is restarting")
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
    if keys is not None:
        uds.unlock(profile.security.level_programming, keys)


# 10 03, the extended unlock when the profile has [security], and 11 01: the server answers, then restarts
# (an unconfirmed image rolls back).
def keyed_reset(uds, profile, keys):
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)
    uds.ecu_reset()


# `reset`: ECUReset from the extended session, keyed when the profile has [security].
def reset(uds, profile, master, log=print):
    keyed_reset(uds, profile, device_keys(uds, profile, master))
    log("reset accepted: the server restarts")
    return 0
