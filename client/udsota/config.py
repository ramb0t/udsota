"""The config commands. `config show` reads the profile's writable DIDs, its status DID and its hash check.
`config set` stages new values with 0x2E in the extended session, commits them with the profile's routine (one
commit per [config] group), and after a keyed reset reads them back and checks the device's config hash. Everything
product-specific comes from the profile's [dids] and [config]."""
import hashlib
import time

from .errors import NoResponse, Nrc, Refused, SecondTester, ToolError, UpdateFailed
from .update import device_keys, read_record, wait_for_boot
from .wire import DECODE, NRC_CONDITIONS, NRC_NOT_SUPPORTED, NRC_OUT_OF_RANGE, NRC_SEQUENCE, SESSION_EXTENDED

NO_CONFIG_WRITES = "this firmware has no config writes"


# The profile's writable [dids] entries in file order; Refused (exit 2) when it has none.
def writable_keys(profile):
    keys = [e for e in profile.dids if e.writable]
    if not keys:
        raise Refused("profile %s has no writable [dids] entry" % profile.name)
    return keys


# text as entry's wire bytes: u8 and u16 as an integer (decimal or 0x hex) in min..max, big-endian; blob as hex digits,
# exactly len bytes when the entry has a len.
def encode_value(entry, text):
    if entry.type == "blob":
        try:
            data = bytes.fromhex(text)
        except ValueError:
            data = b""
        if not data:
            raise Refused("%s takes hex bytes, e.g. 0a1b; got %r" % (entry.name, text))
        if entry.len is not None and len(data) != entry.len:
            raise Refused("%s takes %d bytes; got %d" % (entry.name, entry.len, len(data)))
        return data
    try:
        v = int(text, 0)
    except ValueError:
        raise Refused("%s takes an integer; got %r" % (entry.name, text)) from None
    if not entry.min <= v <= entry.max:
        raise Refused("%s = %d is outside %d..%d" % (entry.name, v, entry.min, entry.max))
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


# parse_writes' writes split by the profile's [config] groups, as [(group name, [(entry, bytes)])]: groups in profile
# order, keys in argument order, and no group without a write. Without groups it is [(None, writes)]. No writes, or
# without commit writes in two groups, are Refused (exit 2): the device takes one group per staged set, and staged
# values are dropped at the session's end.
def group_writes(profile, writes, commit=True):
    if not writes:
        raise Refused("config set needs at least one NAME=VALUE")
    groups = () if profile.config is None else profile.config.groups
    if not groups:
        return [(None, list(writes))]
    out = [(g.name, [w for w in writes if g.first <= w[0].first <= g.last]) for g in groups]
    out = [(n, ws) for n, ws in out if ws]
    if not commit and len(out) > 1:
        raise Refused("without --commit, one call stages one group: %s"
                      % ", ".join("%s is in %s" % (ws[0][0].name, n) for n, ws in out))
    return out


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
        limits = "" if e.type == "blob" else " (%d..%d)" % (e.min, e.max)
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


# A failure in group index i of groups after earlier ones committed, naming the groups committed and those not:
# UpdateFailed (exit 1), or SecondTester (exit 4) when another tester appeared mid-call. A commit that got no answer
# (at_commit and NoResponse) may still have landed after its 0x78s, so group i is named as that, not as not committed.
def later_group_failed(groups, i, e, at_commit):
    names = [n for n, _ in groups]
    msg = "%s; committed %s (the values apply at the next restart)" % (e, ", ".join(names[:i]))
    if at_commit and isinstance(e, NoResponse):
        msg += "; %s got no answer to its commit and may have committed" % names[i]
        i += 1
    if names[i:]:
        msg += "; not committed: %s" % ", ".join(names[i:])
    return SecondTester(msg) if isinstance(e, SecondTester) else UpdateFailed(msg)


# `config set`: 10 03 and the extended unlock (when the profile has [security]), a 2E per key; with commit the
# commit routine, once per [config] group in turn (group_writes); with reset, after the last commit, the keyed
# 11 01, the restart, the read-back and the hash check. A group after the first that fails raises naming what
# landed, with no reset and no retry: the device keeps a failed commit's set staged. writes comes from parse_writes,
# and secret is the master or private key (update.make_keys), unused without [security]. Returns 0 or raises
# ToolError.
def config_set(uds, profile, writes, secret, commit=False, reset=False, preroll=lambda: None,
               sleep=time.sleep, clock=time.monotonic, log=print):
    groups = group_writes(profile, writes, commit)
    keys = device_keys(uds, profile, secret)
    uds.session(SESSION_EXTENDED)
    if keys is not None:
        uds.unlock(profile.security.level_extended, keys)
    for i, (name, group) in enumerate(groups):
        at_commit = False
        try:
            for entry, data in group:
                stage(uds, entry, data)
                log("staged %s = %s" % (entry.name, DECODE[entry.decode](data)))
            if not commit:
                log("not committed: the staged values are dropped when the session ends")
                return 0
            at_commit = True
            commit_config(uds, profile.config, log=log)
        except ToolError as e:
            if i == 0:
                raise
            raise later_group_failed(groups, i, e, at_commit) from e
        if name is not None:
            log("committed %s: %d key(s)" % (name, len(group)))
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
