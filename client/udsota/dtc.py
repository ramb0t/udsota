"""The dtc commands. `dtc show` reads the device's DTCs with ReadDTCInformation (0x19) in the default session: 19 01 FF
for the DTC format, then 19 02 FF for every DTC with a status bit set, or with --ext 19 06 for one DTC's extended data.
`dtc clear` sends 14 FF FF FF in the extended session, unlocked as `config set` is. The profile's optional [dtcs]
gives each code its description."""
import re

from .errors import Nrc, Refused, UpdateFailed
from .update import device_keys
from .wire import (DTC_GROUP_ALL, DTC_RECORD_ALL, DTC_STATUS_BITS, NRC_NOT_SUPPORTED, NRC_OUT_OF_RANGE,
                   NRC_RESPONSE_TOO_LONG, NRC_SUBFUNCTION_NOT_SUPPORTED, RDTC_BY_MASK, RDTC_COUNT_BY_MASK,
                   RDTC_EXT_DATA, SESSION_EXTENDED)

NO_DTC_SERVICES = "this firmware has no DTC services"
SAE_FORMATS = (0x00, 0x04)   # DTCFormatIdentifiers whose DTC is a 2-byte SAE J2012 code and a failure-type byte
SAE_LETTERS = "PCBU"         # an SAE code's first letter, by the code's top two bits
CODE = re.compile(r"([PCBU])([0-3])([0-9A-F]{3})(?:-([0-9A-F]{2}))?|0X([0-9A-F]{1,6})", re.IGNORECASE)
CODE_FORMS = "U0073, U0073-1C or 0xC07300"
# What an NRC to a 19 means, as (error, reason): 0x11 is firmware without DTC services (exit 2), 0x14 a list longer
# than the device's answer buffer (exit 1). Any other NRC is named alone (exit 1).
READ_NRCS = {NRC_NOT_SUPPORTED: (Refused, NO_DTC_SERVICES),
             NRC_RESPONSE_TOO_LONG: (UpdateFailed, "more DTCs than the device can send in one answer")}


# A DTC as text names it, in either case: an SAE J2012 code (U0073), one with its failure-type byte (U0073-1C), or
# the 24-bit DTC (0xC07300). Returns (dtc, any_ftb), any_ftb True for a code without a failure-type byte: FTB 00 on
# the wire, every FTB of that code in [dtcs]. None when text is none of these.
def parse_code(text):
    m = CODE.fullmatch(text)
    if m is None:
        return None
    if m[5] is not None:
        return int(m[5], 16), False
    code = SAE_LETTERS.index(m[1].upper()) << 14 | int(m[2]) << 12 | int(m[3], 16)
    return code << 8 | int(m[4] or "00", 16), m[4] is None


# --ext's CODE as the 24-bit DTC; Refused (exit 2, before the bus opens) when it is not a code.
def ext_code(text):
    dtc = parse_code(text)
    if dtc is None:
        raise Refused("--ext %r is not a DTC: give %s" % (text, CODE_FORMS))
    return dtc[0]


# dtc as a device with DTCFormatIdentifier fmt means it: in an SAE format the J2012 code, with -XX when the
# failure-type byte isn't 00 (U0073, U0073-1C); in any other, 0x and 6 hex digits.
def code_name(dtc, fmt):
    if fmt not in SAE_FORMATS:
        return "0x%06X" % dtc
    code, ftb = dtc >> 8, dtc & 0xFF
    name = "%s%d%03X" % (SAE_LETTERS[code >> 14], code >> 12 & 3, code & 0xFFF)
    return name if ftb == 0 else "%s-%02X" % (name, ftb)


# A statusOfDTC with its set bits named: "0x28 (confirmedDTC, testFailedSinceLastClear)".
def describe_dtc_status(status):
    return "0x%02X (%s)" % (status, ", ".join(n for b, n in enumerate(DTC_STATUS_BITS) if status >> b & 1) or "none")


# The profile's description of dtc: the [dtcs] key with its own failure-type byte, else the one for its code with
# any; None when [dtcs] has neither.
def description(profile, dtc):
    return profile.dtcs.get((dtc, False), profile.dtcs.get((dtc & 0xFFFF00, True)))


# One DTC's line: its code, its status with the bits named, and its description when the profile has one.
def dtc_line(profile, dtc, status, fmt):
    line = "%s  status %s" % (code_name(dtc, fmt), describe_dtc_status(status))
    text = description(profile, dtc)
    return line if text is None else "%s  %s" % (line, text)


# 19 sub with data (Uds.read_dtc); an NRC raises the error nrcs gives it, else UpdateFailed naming the request.
def read(uds, sub, data, nrcs=READ_NRCS):
    try:
        return uds.read_dtc(sub, data)
    except Nrc as e:
        error, why = nrcs.get(e.code, (UpdateFailed, None))
        said = "19 %02X answered NRC 0x%02X" % (sub, e.code)
        raise error(said if why is None else "%s (%s)" % (why, said)) from e


# 19 01 FF's answer, <availability> <format> <count u16>, for the DTC format.
def read_format(uds):
    d = read(uds, RDTC_COUNT_BY_MASK, b"\xff")
    if len(d) != 4:
        raise UpdateFailed("19 01 answered %s, not <availability> <format> <count>" % (d.hex(" ") or "nothing"))
    return d[1]


# `dtc show`: 19 01 FF for the format, then 19 02 FF, and a line per DTC (dtc_line) under their count, or that none
# match. Reads only, in the default session.
def dtc_show(uds, profile, log=print):
    fmt = read_format(uds)
    d = read(uds, RDTC_BY_MASK, b"\xff")
    if not d or (len(d) - 1) % 4:
        raise UpdateFailed("19 02 answered %s, not <availability> and 4 bytes per DTC" % (d.hex(" ") or "nothing"))
    avail, dtcs = d[0], [d[i:i + 4] for i in range(1, len(d), 4)]
    if not dtcs:
        log("no DTCs match (availability 0x%02X)" % avail)
        return 0
    log("%d DTC%s (availability 0x%02X, format 0x%02X)" % (len(dtcs), "" if len(dtcs) == 1 else "s", avail, fmt))
    for r in dtcs:
        log(dtc_line(profile, int.from_bytes(r[:3], "big"), r[3], fmt))
    return 0


# `dtc show --ext CODE`: 19 01 FF for the format, then 19 06 <dtc> FF, and the DTC's line and its extended data
# records as hex; their lengths are the product's, so the client doesn't split them. code is CODE as given. 0x12 is
# firmware without extended data (exit 2); 0x31 a DTC the device doesn't report and 0x14 records past its answer
# buffer (exit 1).
def dtc_ext(uds, profile, dtc, code, log=print):
    fmt = read_format(uds)
    nrcs = {**READ_NRCS, NRC_SUBFUNCTION_NOT_SUPPORTED: (Refused, "this firmware has no DTC extended data"),
            NRC_OUT_OF_RANGE: (UpdateFailed, "%s is not a DTC the device supports" % code),
            NRC_RESPONSE_TOO_LONG: (UpdateFailed, "%s's extended data is more than the device can send in one "
                                                  "answer" % code)}
    d = read(uds, RDTC_EXT_DATA, dtc.to_bytes(3, "big") + bytes([DTC_RECORD_ALL]), nrcs)
    if len(d) < 4 or int.from_bytes(d[:3], "big") != dtc:
        raise UpdateFailed("19 06 answered %s, not DTC %06X and its status" % (d.hex(" ") or "nothing", dtc))
    log(dtc_line(profile, dtc, d[3], fmt))
    log("extended data: %s" % d[4:].hex(" ") if len(d) > 4 else "no extended data stored")
    return 0


# `dtc clear`: 10 03 and the extended unlock (when the profile has [security]), then 14 FF FF FF. secret is the
# master or private key (update.make_keys), unused without [security]. The session is left to expire, as config
# set's is. NRC 0x11 is firmware without DTC services (exit 2); any other is named (exit 1).
def dtc_clear(uds, profile, secret, log=print):
    keys = device_keys(uds, profile, secret)
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)
    try:
        uds.clear_dtc(DTC_GROUP_ALL)
    except Nrc as e:
        if e.code == NRC_NOT_SUPPORTED:
            raise Refused("%s (14 FF FF FF answered NRC 0x11)" % NO_DTC_SERVICES) from e
        raise UpdateFailed("clearing every DTC (14 FF FF FF) answered NRC 0x%02X" % e.code) from e
    log("cleared every DTC")
    return 0
