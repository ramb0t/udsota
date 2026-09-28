"""The config commands. `config show` reads the profile's writable DIDs, its status DID and its hash check.
`config set` stages new values with 0x2E in the extended session, commits them with the profile's routine, and
after a keyed reset reads them back and checks the device's config hash. Everything product-specific comes from
the profile's [dids] and [config]."""
import hashlib
import time

from .errors import Nrc, Refused, ToolError, UpdateFailed
from .profile import TYPES
from .update import DECODE, device_keys, wait_for_boot
from .wire import NRC_CONDITIONS, NRC_NOT_SUPPORTED, NRC_OUT_OF_RANGE, NRC_SEQUENCE, SESSION_EXTENDED

NO_CONFIG_WRITES = "this firmware has no config writes"


# A u8 or u16 entry's write range (lo, hi): the profile's min and max, each defaulting to the type's bounds.
def write_range(entry):
    top = TYPES[entry.type]
    return (0 if entry.min is None else entry.min), (top if entry.max is None else entry.max)


# The profile's writable [dids] entries in file order; Refused (exit 2) when it has none.
def writable_keys(profile):
    keys = [e for e in profile.dids if e.writable]
    if not keys:
        raise Refused("profile %s has no writable [dids] entry" % profile.name)
    return keys


# text as entry's wire bytes: u8 and u16 as an integer (decimal or 0x hex) in min..max, big-endian; blob as hex digits.
def encode_value(entry, text):
    if entry.type == "blob":
        try:
            data = bytes.fromhex(text)
        except ValueError:
            data = b""
        if not data:
            raise Refused("%s takes hex bytes, e.g. 0a1b; got %r" % (entry.name, text))
        return data
    try:
        v = int(text, 0)
    except ValueError:
        raise Refused("%s takes an integer; got %r" % (entry.name, text)) from None
    lo, hi = write_range(entry)
    if not lo <= v <= hi:
        raise Refused("%s = %d is outside %d..%d" % (entry.name, v, lo, hi))
    return v.to_bytes(1 if entry.type == "u8" else 2, "big")


# config set's NAME=VALUE arguments checked against the profile before the bus opens, as [(entry, bytes)] in argument
# order. Refused (exit 2) on an unknown or repeated name, a bad value, --commit without [config], or --reset
# without --commit.
def parse_writes(profile, assignments, commit, reset):
    keys = {e.name: e for e in writable_keys(profile)}
    if commit and profile.config is None:
        raise Refused("--commit needs a [config] table in profile %s" % profile.name)
    if reset and not commit:
        raise Refused("--reset needs --commit: staged values are dropped at the reset")
    writes, seen = [], set()
    for a in assignments:
        name, sep, text = a.partition("=")
        if not sep or name not in keys:
            raise Refused("%r is not NAME=VALUE for a writable key (%s)" % (a, ", ".join(keys)))
        if name in seen:
            raise Refused("%s is given twice" % name)
        seen.add(name)
        writes.append((keys[name], encode_value(keys[name], text)))
    return writes


# One DID's record, or None when the server answers 0x31 (it does not serve that DID).
def read_record(uds, did):
    try:
        return uds.read_did(did)
    except Nrc as e:
        if e.code != NRC_OUT_OF_RANGE:
            raise
        return None


# One DID's record decoded with decode, or "not supported" when the server answers 0x31.
def read_value(uds, did, decode):
    d = read_record(uds, did)
    return "not supported" if d is None else DECODE[decode](d)


# SHA-256 of schema || (did BE16, len, value)* over every DID in first..last the server answers (0x31: absent,
# skipped; the scan does not stop at a gap), ascending: the config hash recomputed from what the server serves.
def compute_hash(uds, spec):
    enc = bytearray([spec.schema])
    for did in range(spec.first, spec.last + 1):
        v = read_record(uds, did)
        if v is None:
            continue
        if len(v) > 0xFF:
            raise UpdateFailed("DID 0x%04X is %d bytes; the hash encoding holds at most 255" % (did, len(v)))
        enc += did.to_bytes(2, "big") + bytes([len(v)]) + v
    return hashlib.sha256(enc).digest()


# The server's config hash must equal the one recomputed from the DIDs it serves; UpdateFailed (exit 1) shows both.
def check_hash(uds, spec, log=print):
    computed = compute_hash(uds, spec)
    device = uds.read_did(spec.did)
    if device != computed:
        raise UpdateFailed("config hash %04X reads %s but the values read hash to %s"
                           % (spec.did, device.hex(), computed.hex()))
    log("%04X config hash: %s matches the values read" % (spec.did, device.hex()))


# `config show`: each writable key's DID, name, value and write range, then the status DID and the hash check when
# the profile has them. Reads only, in the default session. A server that serves none of the keys (0x31 to each)
# has no config writes: Refused (exit 2), as config set.
def config_show(uds, profile, log=print):
    keys = writable_keys(profile)
    records = [read_record(uds, e.first) for e in keys]
    if all(r is None for r in records):
        raise Refused("%s (every writable DID answered NRC 0x31)" % NO_CONFIG_WRITES)
    for e, r in zip(keys, records):
        limits = "" if e.type == "blob" else " (%d..%d)" % write_range(e)
        log("%04X %s: %s%s" % (e.first, e.name, "not supported" if r is None else DECODE[e.decode](r), limits))
    cfg = profile.config
    if cfg is not None and cfg.status_did is not None:
        log("%04X config status: %s" % (cfg.status_did, read_value(uds, cfg.status_did, "hex")))
    if cfg is not None and cfg.hash is not None:
        computed = compute_hash(uds, cfg.hash)
        device = uds.read_did(cfg.hash.did)
        verdict = "matches the values read" if device == computed else "the values read hash to " + computed.hex()
        log("%04X config hash: %s (%s)" % (cfg.hash.did, device.hex(), verdict))
    return 0


# 2E one key. NRC 0x11 means the firmware has no config writes (Refused, exit 2); any other NRC names the key (exit 1).
def stage(uds, entry, data):
    try:
        uds.write_did(entry.first, data)
    except Nrc as e:
        if e.code == NRC_NOT_SUPPORTED:
            raise Refused("%s (0x2E answered NRC 0x11)" % NO_CONFIG_WRITES) from e
        raise UpdateFailed("writing %s (0x%04X) answered NRC 0x%02X" % (entry.name, entry.first, e.code)) from e


# After a failed commit, log the status DID (when the profile names one) to show what landed. A failed read is
# logged, never raised, so the tool still reports the commit's own error.
def report_status(uds, cfg, log=print):
    if cfg.status_did is None:
        return
    try:
        log("%04X config status: %s" % (cfg.status_did, read_value(uds, cfg.status_did, "hex")))
    except ToolError as e:
        log("%04X config status: unreadable (%s)" % (cfg.status_did, e))


# The commit routine; status 00 is success. NRC 0x31 means the firmware has no config writes (Refused, exit 2). Any
# other NRC or status fails (exit 1) after report_status; 0x24 means a session change dropped the staged values.
def commit_config(uds, cfg, log=print):
    try:
        status = uds.routine(cfg.commit_rid)
    except Nrc as e:
        if e.code == NRC_OUT_OF_RANGE:
            raise Refused("%s (routine 0x%04X answered NRC 0x31)" % (NO_CONFIG_WRITES, cfg.commit_rid)) from e
        report_status(uds, cfg, log)
        why = ": the staged values were dropped (the session changed); run config set again" \
            if e.code == NRC_SEQUENCE else ""
        raise UpdateFailed("the commit (routine 0x%04X) answered NRC 0x%02X%s" % (cfg.commit_rid, e.code, why)) from e
    if not status or status[0] != 0:
        report_status(uds, cfg, log)
        raise UpdateFailed("the commit (routine 0x%04X) reported status %s"
                           % (cfg.commit_rid, status[0] if status else "none"))


# After the restart, read every written key back; UpdateFailed (exit 1) lists each key whose value differs.
def read_back(uds, writes, log=print):
    wrong = []
    for entry, data in writes:
        got, show = uds.read_did(entry.first), DECODE[entry.decode]
        if got != data:
            wrong.append("%s reads %s, not %s" % (entry.name, show(got), show(data)))
        else:
            log("%04X %s: %s" % (entry.first, entry.name, show(got)))
    if wrong:
        raise UpdateFailed("after the restart " + "; ".join(wrong))


# `config set`: 10 03 and the extended unlock (when the profile has [security]), a 2E per key; with commit the
# commit routine; with reset the keyed 11 01, the restart, the read-back and the hash check. writes comes from
# parse_writes, and secret is the master or private key (update.make_keys), unused without [security]. Returns 0
# or raises ToolError.
def config_set(uds, profile, writes, secret, commit=False, reset=False, preroll=lambda: None,
               sleep=time.sleep, clock=time.monotonic, log=print):
    keys = device_keys(uds, profile, secret)
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)
    for entry, data in writes:
        stage(uds, entry, data)
        log("staged %s = %s" % (entry.name, DECODE[entry.decode](data)))
    if not commit:
        log("not committed: the staged values are dropped when the session ends")
        return 0
    commit_config(uds, profile.config, log=log)
    if not reset:
        log("committed: the new values apply at the next restart")
        return 0
    try:
        uds.ecu_reset()                  # still in the extended session, still unlocked: the keyed 11 01
    except Nrc as e:
        if e.code != NRC_CONDITIONS:
            raise
        raise UpdateFailed("committed, but the reset was refused (0x22): the new values apply at the next "
                           "restart; run `reset` when the server allows it") from e
    log("committed; the server restarts")
    wait_for_boot(uds, preroll, "the reset", sleep=sleep, clock=clock)
    read_back(uds, writes, log=log)
    if profile.config.hash is not None:
        check_hash(uds, profile.config.hash, log=log)
    return 0
