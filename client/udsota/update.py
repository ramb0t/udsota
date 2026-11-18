"""The commands: info, flash, confirm and reset. The profile's [update] flow picks what flash, info and reset do:
"app", an A/B unit whose server updates it (flash_app: precheck to ConfirmImage, with recovery paths for lost
answers), or "bootloader", a single-slot unit whose resident bootloader is its only UDS server (flash_bootloader:
10 02 into the bootloader, and F1F4 as the proof of life, with no ConfirmImage). Every product-specific step comes
from the profile."""
import contextlib

import can

# The download moved to download.py; the names flash does not use stay importable from here.
from .download import (DELTA_NAMES, DIFF_DFIS, block_failed, check_image, choose_base, compressed_refusal,   # noqa: F401
                       download, last_reason, last_result, open_download, plan_deltas, send_block, send_payload,
                       transfer_exit)
from .errors import NoResponse, Nrc, Refused, SendFailed, UpdateFailed
from .image import parse_image, update_buses
from .keys import DeviceKeys, SigningKeys
from .pack import refuse_bare_delta
from .wire import (DID_COUNTERS, DID_DEVICE_ID, DID_IMAGE_PREFIX, DID_PROJECT, DID_RESULT, DID_RUNNING_SHA, DID_SESSION,
                   DID_STATUS, DID_VERSION, IMG_PENDING_VERIFY, IMG_STATES, NRC_CONDITIONS, NRC_OUT_OF_RANGE,
                   NRC_PROGRAMMING_FAILURE, NRC_SEQUENCE, OTHER_VERIFIED, RID_ACTIVATE, RID_CONFIRM,
                   SESSION_EXTENDED, SESSION_PROGRAMMING, STATUS_BOOT_HELD, DECODE, cstr, decode_counters,
                   decode_status, describe_result, describe_status)

REBOOT_WAIT_S = 3.0
BOOT_TIMEOUT_S = 60.0
BOOT_POLL_S = 1.0
CONFIRM_RETRY_S = 2.0    # between ConfirmImage tries; Uds's 3E 00 keepalive holds the extended session meanwhile
CONFIRM_TIMEOUT_S = 120.0   # a product's soak plus its health check, with margin
NRC_SERVICE_IN_SESSION = 0x7F   # serviceNotSupportedInActiveSession: ConfirmImage met the default session (S3 lapsed)
UNCONFIRMED = ("the new image is not confirmed and rolls back at the unit's next reset; run \"udsota confirm\" "
               "before then to finish it")
WAIT_RETRY_S = 0.05      # flash --wait-for-unit: the next 10 02 at most this long after the last went unanswered,
                         # so that one lands in a bootloader's power-up window (100 ms in udsota's examples)
WAIT_SETTLE_S = 0.25     # then the answers to earlier 10 02s, which a unit sends a P2 (50 ms) apart, are passed
WAIT_DRAIN_S = 2.0       # over until none comes for WAIT_SETTLE_S, or for WAIT_DRAIN_S at most

# The server-owned DIDs `info` reads first, with their labels and renderers; F1F3's label names the image's ID as
# the profile's image format does (id_name). F1F2, the counters, is a 0.14.x server's: 0.15+ shows it unsupported.
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
PRODUCT_NEEDS_BOOTLOADER = '--allow-product-change is for [update] flow = "bootloader"'
DROP_76_WITH_BASES = "--drop-76 is for full and compressed downloads, not with --diff-from"
# What a --wait-for-unit that gives up adds: 10 02s the CAN adapter could not send while the unit was off stay queued.
WAIT_QUEUED = ("If the unit is off, 10 02s still queued in the CAN adapter will hold it in its bootloader for about "
               "5 s at its next power-up, once; taking the interface down and up clears them")
# What a silent F1F4 may also mean when the image does not take updates on every bus (its header's update_buses).
CLOSED_BUS = (". Or it has, and this is a bus the image closes: its update_buses is 0x%04X, and on a bus that does not "
              "name, the app runs but answers nothing")


# Refuses a compressed download under [update] flow = "bootloader", where the boot core takes only DFI 0x00 and would
# answer the 34 with 0x31 once the app has been reset into it: compress, flash's argument, or the profile's [image]
# compression when it is None, must be "none".
def refuse_bootloader_compression(profile, compress):
    if profile.flow == "bootloader" and (profile.compression if compress is None else compress) != "none":
        raise Refused("profile %s: compressed downloads (--compress, --compress-auto, [image] compression) are for "
                      "flow = \"app\": the boot core takes only DFI 0x00" % profile.name)


# What F1F3 holds for profile's images: an ESP-IDF image's app_elf_sha256, or a bare image's image ID.
def id_name(profile):
    return "image ID" if profile.image_format == "bare" else "app_elf_sha256"


# What the precheck reads of the unit, in the order the flows send it: (F1F0's state, F1F3's running SHA, the installed
# project, the board DID's name). The state is None when F1F0 answers 0x31, and nothing else is read. The installed
# project is F1F5, a bootloader-flow read, in a 22 of its own: a request for several DIDs fails whole; None otherwise.
# The board is None when the profile names no board DID.
def read_unit(uds, profile, project=False):
    status = read_record(uds, DID_STATUS)
    if status is None:
        return None, None, None, None
    state = decode_status(status)
    running_sha = uds.read_did(DID_RUNNING_SHA)
    installed = installed_project(uds) if project else None
    board = None if profile.board_did is None else cstr(uds.read_did(profile.board_did))
    return state, running_sha, installed, board


# What names img's board: the profile's [board] name for its hw_id, else the hw_id.
def board_name(profile, img):
    return profile.board_names.get(img.hw_id, "hw_id %d" % img.hw_id)


# "image is for X but the server is Y" when the unit's board DID names another board than the image's, else None.
def wrong_board(profile, img, board):
    if board is not None and board != profile.board_names.get(img.hw_id):
        return "image is for %s but the server is %s" % (board_name(profile, img), board)
    return None


# `flash`: the update from the precheck to a running image, confirmed under flow "app"; returns 0 or raises ToolError.
# secret is the master or private key (make_keys), unused without [security]. quiet() is held from the point an update
# is needed to the end (the transport's bus quieting). compress is "none", "deflate" or "auto"; None takes the
# profile's. bases, (name, bytes) pairs, offers a delta from the one the server runs (plan_deltas). The profile's flow
# picks flash_app or flash_bootloader; wait_for_unit and allow_product_change are the bootloader flow's alone.
def flash(uds, profile, image, secret, drop_76=None, preroll=lambda: None, log=print,
          quiet=contextlib.nullcontext, compress=None, bases=None, diff_format="auto", wait_for_unit=None,
          allow_product_change=False):
    if wait_for_unit is not None and profile.flow != "bootloader":
        raise Refused(WAIT_NEEDS_BOOTLOADER)
    if allow_product_change and profile.flow != "bootloader":
        raise Refused(PRODUCT_NEEDS_BOOTLOADER)
    if bases is not None and drop_76 is not None:
        raise Refused(DROP_76_WITH_BASES)
    if bases is not None:
        refuse_bare_delta(profile)
    refuse_bootloader_compression(profile, compress)
    # Only an explicit --no-compress rules out the DEFLATE delta, 0x30: a server with delta downloads has compressed
    # ones too, and one without answers 0x31. So this is decided before the profile's default applies.
    deflate_ok = compress != "none"
    compress = profile.compression if compress is None else compress
    img = parse_image(profile, image)
    log("image %s for %s, %d bytes, %s %s" % (img.version, board_name(profile, img), img.size, id_name(profile),
                                              img.elf_sha[:8].hex()))
    if profile.flow == "bootloader":
        return flash_bootloader(uds, profile, image, img, drop_76=drop_76, preroll=preroll, log=log, quiet=quiet,
                                compress=compress, wait_for_unit=wait_for_unit,
                                allow_product_change=allow_product_change)
    return flash_app(uds, profile, image, img, secret, drop_76=drop_76, preroll=preroll, log=log, quiet=quiet,
                     compress=compress, bases=bases, diff_format=diff_format, deflate_ok=deflate_ok)


# `flash` on an A/B unit (docs/wire.md): the precheck, the programming session and unlock, the download, FF01 and
# ActivateImage, then the restart and ConfirmImage; img is image parsed, the other arguments flash's. An image the
# other slot already holds verified skips the download. The patches of a delta are built before the programming
# session opens.
def flash_app(uds, profile, image, img, secret, drop_76, preroll, log, quiet, compress, bases, diff_format,
              deflate_ok):
    state, running_sha, _, board = read_unit(uds, profile)
    if state is None:                         # 0x31: no udsota status DID, so no udsota server
        raise Refused(NOT_UDSOTA)
    device_id = read_device_id(uds, profile)   # read in the precheck, used only once an update is needed
    if running_sha == img.elf_sha:
        if state["running_state"] == IMG_PENDING_VERIFY:   # an earlier run stopped before ConfirmImage
            log("the server runs this image (%s) unconfirmed: confirming" % img.elf_sha[:8].hex())
            return confirm(uds, log=log)
        log("the server already runs this image (%s): nothing to do" % img.elf_sha[:8].hex())
        return 0
    if state["running_state"] == IMG_PENDING_VERIFY:
        raise Refused("the running image is unconfirmed: run `confirm`, or `reset` to roll it back")
    if (why := wrong_board(profile, img, board)) is not None:
        raise Refused(why)
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
                download(uds, image, drop_76=drop_76, log=log, compress=compress, deltas=deltas,
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
                if e.code == NRC_PROGRAMMING_FAILURE:
                    activation_failed(uds, profile, keys, e, log=log)
                    break
                redownload_or_raise(e, recovered, "slot", log)
                recovered = need_download = True   # one re-download per run
        log("activated; waiting for the server to restart")
        wait_for_image(uds, img.elf_sha, preroll)
        log("the server runs %s; confirming" % img.version)
        return confirm(uds, log=log)


# The NRC e to ActivateImage, apart from 0x72 and a resend's answer, which each flow reads its own way: 0x22 ends the
# run, and the first 0x24 says what is not verified (what: "slot" or "image") and returns, for the caller to download
# again; a second 0x24, or any other NRC, is raised as it came.
def redownload_or_raise(e, recovered, what, log):
    if e.code == NRC_CONDITIONS:
        raise UpdateFailed(ACTIVATE_CONDITIONS) from e
    if recovered or e.code != NRC_SEQUENCE:
        raise e
    log("ActivateImage answered 0x24 (the %s is not verified): downloading again" % what)


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


# After ActivateImage: wait for the restart, then check the server runs the new image sha.
def wait_for_image(uds, sha, preroll):
    running = wait_for_boot(uds, preroll, "ActivateImage")
    if running != sha:
        raise UpdateFailed("the server runs %s, not the new image %s: it reverted or never switched; "
                           "read F1F0 with `info`" % (running[:8].hex(), sha[:8].hex()))


# Wait for a restarting server and return its running SHA. after names what restarted it, for the timeout message.
def wait_for_boot(uds, preroll, after):
    gave_up = "the server did not answer within %d s of %s" % (BOOT_TIMEOUT_S, after)
    return poll_restarted(uds, DID_RUNNING_SHA, BOOT_TIMEOUT_S, gave_up, preroll)


# Wait for a restarting unit: REBOOT_WAIT_S, then pre-roll and read did every BOOT_POLL_S until it answers, and return
# the record; UpdateFailed(gave_up) once timeout_s has passed without one. The unit comes back in the default session,
# so no 3E 00 precedes a poll. Other errors (an NRC) are the caller's to read.
def poll_restarted(uds, did, timeout_s, gave_up, preroll):
    uds.restarted()
    uds.sleep(REBOOT_WAIT_S)
    deadline = uds.clock() + timeout_s
    while True:
        try_preroll(preroll)
        try:
            return uds.read_did(did)
        except (NoResponse, SendFailed):   # a restarting unit answers nothing, or leaves a send unacknowledged
            if uds.clock() >= deadline:
                raise UpdateFailed(gave_up)
            uds.sleep(BOOT_POLL_S)


# One pre-roll while a unit restarts. A send the adapter cannot make (python-can raises CanOperationError, or OSError,
# when nothing on the bus acknowledges and its queue fills) is not the wait's failure: the poll that follows decides.
def try_preroll(preroll):
    try:
        preroll()
    except (OSError, can.CanError):
        pass


# ConfirmImage in the extended session, retrying NRC 0x22 until the product's soak and health check pass, and a
# request or answer that is lost: the server answers positive at once for an image already valid, so a repeat is safe.
def confirm(uds, log=print):
    uds.session(SESSION_EXTENDED)
    deadline = uds.clock() + CONFIRM_TIMEOUT_S
    lost = False                                # a send or an answer was lost: S3 may have lapsed since
    while True:
        try:
            uds.routine(RID_CONFIRM)
            break
        except Nrc as e:
            if e.code == NRC_CONDITIONS and uds.clock() < deadline:
                uds.sleep(CONFIRM_RETRY_S)
                continue
            if e.code != NRC_CONDITIONS and (lost or e.code == NRC_SERVICE_IN_SESSION):
                raise Nrc(e.sid, e.code, UNCONFIRMED) from e
            raise
        except (NoResponse, SendFailed) as e:   # a failed send never reached the server
            lost = True
            if uds.clock() >= deadline:
                raise type(e)("ConfirmImage got no answer in %d s: %s" % (CONFIRM_TIMEOUT_S, UNCONFIRMED)) from e
            uds.sleep(CONFIRM_RETRY_S)
    log("confirmed: %s" % describe_status(decode_status(uds.read_did(DID_STATUS))))
    return 0


# The installed app's project as the bootloader's F1F5 gives it, or None: any negative answer means no valid app (or
# no project in it), or a bootloader that does not know the DID or denies reads before the unlock.
def installed_project(uds):
    try:
        d = uds.read_did(DID_PROJECT)
    except Nrc:
        return None
    return cstr(d) if d else None


# `flash` on a single-slot unit (docs/wire.md#bootloader-flow); img is image parsed, the other arguments flash's. One
# F1F4 read in the default session first: an app already running this image and healthy is left running. Then 10 02
# (with wait_for_unit, wait_for_power_up sends it): the app answers 7F 10 78 and resets into the bootloader, which
# sends the 50 02; a late answer to an F1F4 read that went unanswered, such as a bootloader's 7F 22 31 to one the
# adapter held, is passed over ahead of it (Uds.exchange). Then, all in the programming session, the precheck reads
# (no unlock: a profile with [security] is refused under this flow), download, FF01 and ActivateImage;
# wait_for_start is the proof of life, with no ConfirmImage. An image the unit already holds gets 11 01 and the same
# proof. quiet() is held from the 10 02, which stops the app. An image of another project than F1F5 reports is
# refused, with the unit left in its bootloader, unless allow_product_change (--allow-product-change), which logs
# both names and goes on; any negative answer to F1F5 goes on too: nothing is installed, or the bootloader does not
# know the DID.
def flash_bootloader(uds, profile, image, img, drop_76=None, preroll=lambda: None, log=print,
                     quiet=contextlib.nullcontext, compress="none", wait_for_unit=None, allow_product_change=False):
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
            wait_for_power_up(uds, wait_for_unit, log=log)
        state, running_sha, installed, board = read_unit(uds, profile, project=True)
        if state is None:
            raise Refused("%s %s" % (NOT_UDSOTA, LEFT_IN_BOOTLOADER))
        if installed is not None and installed != img.project:
            if not allow_product_change:
                raise Refused("the unit runs project %r and the image is project %r: pass --allow-product-change to "
                              "replace one with the other. %s" % (installed, img.project, LEFT_IN_BOOTLOADER))
            log("changing the unit's project from %r to %r (--allow-product-change)" % (installed, img.project))
        held = state["flags"] & STATUS_BOOT_HELD
        if held:
            log("the unit is held in its bootloader: its app failed to start")
        if running_sha == img.elf_sha:
            log("the unit already holds this image (%s)%s: resetting into it" % (
                img.elf_sha[:8].hex(), "; the reset releases it for another try" if held else ""))
            uds.ecu_reset()
            return wait_for_start(uds, profile, img.elf_sha, preroll, log=log, buses=update_buses(profile, image))
        if (why := wrong_board(profile, img, board)) is not None:
            raise Refused("%s. %s" % (why, LEFT_IN_BOOTLOADER))
        verified = state["other_state"] == OTHER_VERIFIED and state["other_sha_prefix"] == img.elf_sha[:8]
        if verified:
            log("the other slot already holds this image, verified: skipping to ActivateImage")
        need_download, recovered, resent, activated = not verified, False, False, True
        while True:
            if need_download:
                download(uds, image, drop_76=drop_76, log=log, compress=compress)
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
                if e.code == NRC_PROGRAMMING_FAILURE:
                    raise UpdateFailed("ActivateImage failed (0x72); read F1F0 with `info`") from e
                redownload_or_raise(e, recovered, "image", log)
                recovered = need_download = True   # one re-download per run
        return wait_for_start(uds, profile, img.elf_sha, preroll, log=log, activated=activated,
                              buses=update_buses(profile, image))


# The bootloader flow's 10 02 under --wait-for-unit, for a unit whose app runs but cannot hand over. The first 10 02
# goes as without the option, a live app's 7F 10 78 waited out for its 50 02 as for any request, and once it is
# answered the flow goes on. Otherwise the operator is told to power-cycle the unit, whose bootloader also takes a
# 10 02 in its power-up window, while 10 02 goes out again, the next at most WAIT_RETRY_S after the last went
# unanswered, was refused or failed to send (Uds.try_session, which waits no longer than that after a 0x78 or 0x21
# either), until one is answered 50 02; UpdateFailed once seconds have passed since the prompt, saying what the 10 02s
# still queued then do (WAIT_QUEUED), as a wait the operator interrupts also logs. A failed send, as while the unit
# is off and nothing acknowledges the frame, is a try like any other.
# The unit answers every 10 02 it gets, the ones the kernel still held unacknowledged among them, so 50 02s can
# follow the first. They are passed over until the unit goes quiet (Uds.drain), the monitor counting that as ours,
# before the next request goes: dropping them is not enough, though udsoncan empties the receive queue before each
# send, since one that comes after that send is taken for its answer, and the request itself can reach the unit while
# it is still answering 10 02s.
def wait_for_power_up(uds, seconds, log=print):
    try:
        uds.session(SESSION_PROGRAMMING)
        return
    except (Nrc, NoResponse, SendFailed):
        pass
    log("waiting up to %d s for the unit: power-cycle it now" % seconds)
    start, tries = uds.clock(), 1
    try:
        while True:
            tries += 1
            if uds.try_session(SESSION_PROGRAMMING, WAIT_RETRY_S):
                break
            if uds.clock() - start >= seconds:
                raise UpdateFailed("no 10 02 was answered within %d s (%d tries). %s" % (seconds, tries, WAIT_QUEUED))
    except KeyboardInterrupt:
        log(WAIT_QUEUED)
        raise
    took = uds.clock() - start
    late = uds.drain(WAIT_SETTLE_S, WAIT_DRAIN_S)
    passed = "; passed over %d later answers" % late if late else ""
    log("10 02 answered after %.1f s, at try %d%s" % (took, tries, passed))


# The bootloader flow's proof of life after ActivateImage or 11 01: wait REBOOT_WAIT_S, then poll F1F4 until the
# unit's app answers it, which it does once healthy, for up to the profile's start_timeout_s, and check it is the first
# 4 bytes of sha. Returns 0, or raises UpdateFailed: another prefix (the app runs another image), 0x31 (the bootloader
# answers: the app did not start, F1F0 saying whether the unit holds itself there; or, when activated is False because
# no F001 was answered, perhaps never activated), or nothing within the timeout. Silence is never success.
def wait_for_start(uds, profile, sha, preroll, log=print, activated=True, buses=0xFFFF):
    gave_up = ("nothing answered F1F4 in %d s of polling after the restart, so the app has not reported healthy%s"
               % (profile.start_timeout_s, CLOSED_BUS % buses if buses != 0xFFFF else ""))
    try:
        prefix = poll_restarted(uds, DID_IMAGE_PREFIX, profile.start_timeout_s, gave_up, preroll)
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


# `confirm`: confirm the running image if it is PENDING_VERIFY, else report there is nothing to do.
def confirm_cmd(uds, log=print):
    state = decode_status(uds.read_did(DID_STATUS))
    if state["running_state"] != IMG_PENDING_VERIFY:
        log("the running image is %s: nothing to confirm" % IMG_STATES.get(state["running_state"], "?"))
        return 0
    return confirm(uds, log=log)


# `reset`: ECUReset from the extended session, keyed when the profile has [security]. Under flow "bootloader", from
# the programming session instead (10 02, 11 01, with no unlock): the unit leaves its bootloader for its app.
def reset(uds, profile, secret, log=print):
    if profile.flow == "bootloader":
        uds.session(SESSION_PROGRAMMING)
        uds.ecu_reset()
        log("reset accepted: the unit leaves its bootloader for its app")
        return 0
    keyed_reset(uds, profile, device_keys(uds, profile, secret))
    log("reset accepted: the server restarts")
    return 0


# `info`: the server-owned DIDs, then the profile's [dids] in file order; a range stops at its first absent DID.
# Under flow "bootloader" it enters the programming session first, since the unit's app answers no reads, reads F1F5
# after the server-owned DIDs, and sends no reset after.
def info(uds, profile, log=print):
    bootloader = profile.flow == "bootloader"
    if bootloader:
        uds.session(SESSION_PROGRAMMING)
    for did, name, render in CORE_DIDS:
        d = read_record(uds, did)
        name = name % id_name(profile) if did == DID_RUNNING_SHA else name
        log("%04X %s: %s" % (did, name, "not supported" if d is None else render(d)))
    if bootloader:
        project = installed_project(uds)
        log("%04X installed project: %s" % (DID_PROJECT, "none (no valid app, or the bootloader does not report it)"
                                            if project is None else project))
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


# 10 02, then the programming unlock when the profile has [security]: download, FF01 and ActivateImage need it.
def enter_programming(uds, profile, keys):
    uds.session(SESSION_PROGRAMMING)
    unlock_programming(uds, profile, keys)


# The programming unlock with keys; nothing when the profile has no [security] (keys None).
def unlock_programming(uds, profile, keys):
    if keys is not None:
        uds.unlock(profile.security.level_programming, keys)


# 10 03, then the extended unlock when the profile has [security]: reset, config set and dtc clear need it.
def enter_extended(uds, profile, keys):
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)


# 11 01 in the extended session: the server answers, then restarts (an unconfirmed image rolls back).
def keyed_reset(uds, profile, keys):
    enter_extended(uds, profile, keys)
    uds.ecu_reset()


# The keys for this server, reading its device ID; None when the profile has no [security].
def device_keys(uds, profile, secret):
    return make_keys(profile, secret, read_device_id(uds, profile))


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


# One DID's record, or None when the server answers 0x31 (it does not serve that DID).
def read_record(uds, did):
    try:
        return uds.read_did(did)
    except Nrc as e:
        if e.code != NRC_OUT_OF_RANGE:
            raise
        return None
