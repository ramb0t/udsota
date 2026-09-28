"""The udsota wire contract (components/udsota/include/udsota_wire.h): sessions, server-owned DIDs,
routines, NRCs, the download format and the status, result and counter layouts."""
import struct

from .errors import UpdateFailed

SESSION_PROGRAMMING, SESSION_EXTENDED = 0x02, 0x03
DID_SESSION, DID_VERSION, DID_DEVICE_ID = 0xF186, 0xF189, 0xF18C
DID_STATUS, DID_RESULT, DID_COUNTERS, DID_RUNNING_SHA = 0xF1F0, 0xF1F1, 0xF1F2, 0xF1F3
RID_CHECK_DEPS, RID_ACTIVATE, RID_CONFIRM = 0xFF01, 0xF001, 0xF002
NRC_NOT_SUPPORTED, NRC_BUSY, NRC_CONDITIONS, NRC_SEQUENCE = 0x11, 0x21, 0x22, 0x24   # 0x11: e.g. 0x2E, no config writes
NRC_OUT_OF_RANGE, NRC_TIME_DELAY = 0x31, 0x37
NRC_PROGRAMMING_FAILURE = 0x72   # generalProgrammingFailure: a flash job failed or passed the 90 s cap
DL_DFI, DL_ALFID, DL_MAX_DATA = 0x00, 0x44, 4093
DL_DFI_DEFLATE = 0x10            # dataFormatIdentifier: raw DEFLATE (RFC 1951), memorySize still the image's size
DL_DFI_DELTA = 0x20              # a delta patch from the running image (delta.py), heatshrink inside
DL_DFI_DELTA_DEFLATE = 0x30      # the same with its patch uncompressed, all of it raw DEFLATE

IMG_STATES = {0: "UNDEFINED", 1: "NEW", 2: "PENDING_VERIFY", 3: "VALID", 4: "INVALID", 5: "ABORTED"}
OTHER_STATES = {0: "EMPTY", 1: "UNVERIFIED", 2: "WRITING", 3: "VERIFIED", 4: "INVALID"}
IMG_PENDING_VERIFY, OTHER_VERIFIED = 2, 3
STATUS_FLAGS = {0x01: "signature-checked", 0x02: "boot-ignored-config"}
DL_REASONS = ("DL_OK", "DL_BAD_HEADER", "DL_BAD_PROJECT", "DL_BAD_BOARD", "DL_BAD_LAYOUT",
              "DL_BAD_DIAG_IDS", "DL_NOT_NEWER", "DL_TOO_BIG", "DL_VERIFY_FAILED", "DL_SIG_FAILED",
              "DL_WORKER_TIMEOUT", "DL_ABORTED", "DL_FLASH_ERROR", "DL_BAD_STREAM",
              "DL_NO_MEMORY", "DL_BAD_BASE")   # udsota_reason_t (udsota_wire.h)
# 9 (DL_SIG_FAILED) is reserved and not emitted by IDF v6.1: esp_ota_end returns one code for a hash or a
# signature failure, so FF01 reports both as 8 (DL_VERIFY_FAILED).
COUNTER_NAMES = ("seq_errors", "ncr_timeouts", "repeated_blocks", "aborts", "withheld_fcs",
                 "stmin_violations", "resp_pending_caps", "resp_frames_dropped")


# NUL-terminated ASCII field to str.
def cstr(field):
    return bytes(field).split(b"\0", 1)[0].decode("ascii", "replace")


# The status DID's 16 bytes (udsota_status_t) as a dict.
def decode_status(d):
    if len(d) < 16:
        raise UpdateFailed("status DID F1F0 is %d bytes, expected 16" % len(d))
    return {"running_slot": d[0], "running_state": d[1], "boot_slot": d[2], "other_state": d[3],
            "other_version": tuple(d[4:7]), "other_sha_prefix": bytes(d[7:15]), "flags": d[15]}


# One-line summary of a decoded status; flag bits without a name show as hex.
def describe_status(s):
    flags = [STATUS_FLAGS.get(1 << b, "0x%02X" % (1 << b)) for b in range(8) if s["flags"] & (1 << b)] or ["none"]
    return ("running slot %d %s, boot slot %d, other slot %s v%d.%d.%d sha %s, flags %s" % (
        s["running_slot"], IMG_STATES.get(s["running_state"], "?"), s["boot_slot"],
        OTHER_STATES.get(s["other_state"], "?"), *s["other_version"], s["other_sha_prefix"].hex(),
        ",".join(flags)))


# Name of a download reason code (last-result DID, FF01 status).
def reason_name(code):
    return DL_REASONS[code] if code < len(DL_REASONS) else "reason 0x%02X" % code


# The last-result DID (udsota_result_t) as (reason name, bytes received).
def decode_result(d):
    if len(d) < 5:
        raise UpdateFailed("last-result DID F1F1 is %d bytes, expected 5" % len(d))
    return reason_name(d[0]), int.from_bytes(d[1:5], "big")


# F1F1's value d as `info` and the errors show it: "DL_ABORTED, 0 bytes received".
def describe_result(d):
    return "%s, %d bytes received" % decode_result(d)


# A [dids] entry's decode, by the name the profile gives it, as its renderer.
DECODE = {"hex": lambda d: d.hex(" "), "ascii": cstr,
          "version3": lambda d: "%d.%d.%d" % tuple(d) if len(d) == 3 else d.hex(" "),
          "u8": lambda d: "%d" % d[0] if len(d) == 1 else d.hex(" "),
          "u16": lambda d: "%d" % int.from_bytes(d, "big") if len(d) == 2 else d.hex(" ")}


# The counters DID (udsota_counters_t) as {counter name: value}.
def decode_counters(d):
    if len(d) < 16:
        raise UpdateFailed("counters DID F1F2 is %d bytes, expected 16" % len(d))
    return dict(zip(COUNTER_NAMES, struct.unpack(">8H", bytes(d[:16]))))
