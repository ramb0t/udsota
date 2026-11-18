"""Getting the image into the unit and verified: RequestDownload (34), the 0x36 blocks, RequestTransferExit (37) and
CheckProgrammingDependencies (FF01), as a full, compressed or delta download, with the recoveries for lost answers.
Both flash flows call download and then check_image."""

from .delta import validation_hash
from .errors import NoResponse, Nrc, Refused, SendFailed, UpdateFailed
from .image import APP_ELF_SHA
from .pack import build_patch, encode, rank_deltas
from .wire import (DID_RESULT, DID_SESSION, DL_DFI, DL_DFI_DEFLATE, DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE, NRC_CONDITIONS,
                   NRC_NOT_ACCEPTED, NRC_OUT_OF_RANGE, NRC_SEQUENCE, RID_CHECK_DEPS, SESSION_PROGRAMMING,
                   decode_result, describe_result, reason_name)

# flash's diff_format (--diff-format): the delta DFIs it may try; and each delta DFI's name in the log. DFI 0x20
# (heatshrink) is taken by 0.14.x servers only; 0.15+ answers it 0x31.
DIFF_DFIS = {"auto": (DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE), "heatshrink": (DL_DFI_DELTA,),
             "deflate": (DL_DFI_DELTA_DEFLATE,)}
DELTA_NAMES = {DL_DFI_DELTA: "heatshrink patch", DL_DFI_DELTA_DEFLATE: "patch as raw DEFLATE"}


# RequestDownload, every 0x36 block (counter from 1, wrapping 0xFF -> 0x00) and RequestTransferExit: first each
# delta in deltas ((dfi, payload) pairs, plan_deltas) in turn, then the image compressed per compress
# (open_download). A delta DFI the server answers 0x31, or 0x22 for memory, moves on to the next; a delta refused
# for its base (send_payload) skips the rest and sends the image, after reenter() (the flow's way back into the
# programming session) when that session has ended meanwhile: on a server on iso14229, whose S3 (5.1 s) restarts only
# on 10 and 3E, it ends while the client waits P2* (5.5 s) for a lost answer. drop_76 = N resends block N once as if
# its 76 were lost; an N past the last block is refused before any 0x36 (the CLI refuses it with deltas, whose size it
# can't know before the 34).
def download(uds, image, drop_76=None, log=print, compress="none", deltas=(), reenter=None):
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
        if send_payload(uds, image, patch, max_data, "delta", drop_76=drop_76, log=log):
            return
        log("the device is not running the base this patch was made from (0x36 answered 0x31, F1F1 DL_BAD_BASE; "
            "for example a rebuild of the same source that is not byte-identical): sending a full download")
        if reenter is not None and uds.read_did(DID_SESSION)[:1] != bytes([SESSION_PROGRAMMING]):
            log("the programming session ended while the answer was awaited: entering it again")
            reenter()
        break
    payload, max_data = open_download(uds, image, compress, log=log)
    send_payload(uds, image, payload, max_data, None if payload is image else "compressed", drop_76=drop_76,
                 log=log)


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


# The 0x36 blocks and the 0x37 of an open download of image carrying payload: the image itself (kind None), or it
# coded as kind ("compressed" or "delta"), which ends with the bytes sent and, compressed, the time saved; a delta's
# time is mostly the server rebuilding and writing the image, not the bus, so it gives no full download's time. True
# when done; False when a delta's 36 was refused with F1F1 DL_BAD_BASE, which ends the download on the server: 0x31,
# or, when that answer was lost, a refused resend of the block: 0x70 from a server on iso14229, which has no transfer
# open, 0x24 from a v0.14.x one, or for a block over 256 bytes a resend a v0.14.x server's ISO-TP refuses.
def send_payload(uds, image, payload, max_data, kind, drop_76=None, log=print):
    total = (len(payload) + max_data - 1) // max_data
    if drop_76 is not None and drop_76 > total:
        raise Refused("--drop-76 %d: the download is only %d blocks of %d bytes" % (drop_76, total, max_data))
    start = uds.clock()
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
    took = uds.clock() - start
    if kind == "compressed":
        log("sent %d %s bytes in %.1f s; the %d-byte image would take about %.1f s, so about %.1f s saved"
            % (len(payload), kind, took, len(image), took * len(image) / len(payload),
               took * (len(image) - len(payload)) / len(payload)))
    elif kind == "delta":
        log("sent %d delta bytes in %.1f s in place of the %d-byte image" % (len(payload), took, len(image)))
    return True


# Send one 0x36 block; resend it once after a plain timeout (the block-counter rule makes that safe). Only a 0.14.x
# server answers a repeated block, so the resend recovers a lost answer there; on 0.15+ it recovers a block the server
# never got, and a lost answer fails the run (0x24).
def send_block(uds, bsc, chunk):
    try:
        uds.transfer(bsc, chunk)
    except NoResponse:
        uds.transfer(bsc, chunk)


# RequestTransferExit, resent once after a plain timeout. A resend refused with 0x24 means the first 0x37
# closed the transfer and only its 77 was lost when the last-result DID reads (DL_OK, every byte); else it stops.
# The 0x24 recovery is for 0.14.x: a 0.15+ server answers a resent 0x37 with 0x70, which stops the run.
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


# The one base in bases ((name, bytes) pairs) whose app_elf_sha256 is running_sha, the running image's; None, saying
# why, when no file or several different ones match, when it is image itself, or when it has no appended SHA-256.
def choose_base(bases, image, running_sha, log=print):
    found = {}
    for name, data in bases:
        if bytes(data[APP_ELF_SHA]) == running_sha:
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
