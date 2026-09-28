"""Client profiles: everything product-specific (CAN IDs, deny list, key derivation, image identity,
busy detector, pre-roll, extra DIDs, writable config DIDs and their commit), read from a TOML file."""
import pathlib
import re
import tomllib
from dataclasses import dataclass

from .errors import Refused

PROFILE_DIR = pathlib.Path(__file__).resolve().parent / "profiles"
DECODERS = ("hex", "ascii", "version3", "u8", "u16")
TYPES = {"u8": 0xFF, "u16": 0xFFFF, "blob": None}   # a typed DID's value type and its largest value (blob: bytes)
KEY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")    # a writable DID's name, as `config set NAME=VALUE` takes it
SLOT_SIZE_DEFAULT = 0x400000   # UDSOTA_SLOT_SIZE_DEFAULT
KEYS = {"can": {"interface", "req_id", "resp_id", "deny_tx"},
        "security": {"mode", "label", "master_file", "private_key_file", "device_id_did", "level_extended",
                     "level_programming"},
        "image": {"product", "hw_ids", "layout_id", "slot_size"},
        "board": {"did", "names"},
        "busy": {"id", "byte", "values"},
        "preroll": {"tester_present_frames"},
        "functional": {"id", "quiet_bus"},
        "dids": None,
        "config": {"commit_rid", "status_did", "hash"}}
DID_KEYS = {"name", "decode", "type", "writable", "min", "max"}
HASH_KEYS = {"did", "first", "last", "schema"}


SECURITY_MODES = {"hmac": ("label", "master_file"), "ecdsa": ("private_key_file",)}   # mode: its required keys


# [security]: the 0x27 keys and the seed levels. Mode "hmac" (the default) derives the keys, K_dev = HMAC(master,
# label || device ID), and has label and master_file; mode "ecdsa" signs each seed with private_key_file. The
# other mode's fields are None.
@dataclass(frozen=True)
class Security:
    label: bytes | None
    master_file: str | None
    device_id_did: int
    level_extended: int
    level_programming: int
    mode: str = "hmac"
    private_key_file: str | None = None


# [busy]: a frame whose byte `byte` in `values` means another tester holds a session.
@dataclass(frozen=True)
class BusyDetector:
    id: int
    byte: int
    values: tuple


# One [dids] entry: DIDs first..last (equal for a single DID), shown as name and decoded with decode. A writable
# entry is one DID config set can write: type u8, u16 or blob, and for u8 and u16 the write range min..max.
@dataclass(frozen=True)
class DidEntry:
    first: int
    last: int
    name: str
    decode: str
    type: str | None = None
    writable: bool = False
    min: int | None = None
    max: int | None = None


# [config] hash: SHA-256 of schema || (did BE16, len, value)* over every DID in first..last the device answers,
# ascending, compared with DID did's record.
@dataclass(frozen=True)
class HashSpec:
    did: int
    first: int
    last: int
    schema: int


# [config]: the routine that commits staged writes, an optional status DID and an optional hash check.
@dataclass(frozen=True)
class ConfigSpec:
    commit_rid: int
    status_did: int | None
    hash: HashSpec | None


# A loaded profile. None or empty means the feature is off; interface None means --interface must name one.
@dataclass(frozen=True)
class Profile:
    name: str
    interface: str | None
    req_id: int
    resp_id: int
    deny_tx: frozenset
    product: str | None
    hw_ids: tuple
    layout_id: int | None
    slot_size: int
    security: Security | None
    board_did: int | None
    board_names: dict
    busy: BusyDetector | None
    preroll_frames: int
    dids: tuple
    func_id: int | None = None      # [functional] id: the only other ID the tool may transmit on
    quiet_bus: bool = False         # [functional] quiet_bus: silence the bus's other nodes while flashing
    config: ConfigSpec | None = None   # [config]: config set's commit routine, status DID and hash check


# Raise Refused naming the profile and the problem.
def _bad(name, why):
    raise Refused("profile %s: %s" % (name, why))


# t[key] as an int in lo..hi, or default when absent (a missing required key passes default=None, required=True).
def _int(name, t, key, lo, hi, default=None, required=False):
    if key not in t:
        if required:
            _bad(name, "missing %s" % key)
        return default
    v = t[key]
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        _bad(name, "%s must be an integer from 0x%X to 0x%X" % (key, lo, hi))
    return v


# t[key] as a requestSeed level: odd, 0x01 to 0x7D (sendKey is level + 1, still under the suppress bit).
def _level(name, t, key, default):
    v = _int(name, t, key, 0x01, 0x7D, default=default)
    if v % 2 == 0:
        _bad(name, "%s must be odd (a requestSeed level)" % key)
    return v


# t[key] as a tuple of ints in lo..hi (empty when absent).
def _ints(name, t, key, lo, hi):
    v = t.get(key, [])
    if not isinstance(v, list) or any(not isinstance(x, int) or isinstance(x, bool) or not lo <= x <= hi for x in v):
        _bad(name, "%s must be a list of integers from 0x%X to 0x%X" % (key, lo, hi))
    return tuple(v)


# t[key] as a non-empty str, or None when absent and not required.
def _str(name, t, key, required=False):
    if key not in t:
        if required:
            _bad(name, "missing %s" % key)
        return None
    if not isinstance(t[key], str) or not t[key]:
        _bad(name, "%s must be a non-empty string" % key)
    return t[key]


# t[key] as a bool, or default when absent.
def _bool(name, t, key, default):
    v = t.get(key, default)
    if not isinstance(v, bool):
        _bad(name, "%s must be true or false" % key)
    return v


# "0xF191" or "0x0200-0x02FF" to (first, last).
def _did_range(name, key):
    m = re.fullmatch(r"0x([0-9A-Fa-f]{1,4})(?:-0x([0-9A-Fa-f]{1,4}))?", key)
    if m is None:
        _bad(name, "[dids] key %r is not 0xNNNN or 0xNNNN-0xNNNN" % key)
    first, last = int(m[1], 16), int(m[2] or m[1], 16)
    if first > last:
        _bad(name, "[dids] key %r runs backwards" % key)
    return first, last


# One [dids] entry from its key and table: name and decode, and for a typed entry its type, writable flag and
# write range (u8 and u16 only; min and max stay None when absent, meaning the type's bounds). A writable entry is
# one DID with a type and a plain name. Entries may overlap (a range plus keys inside it).
def _did_entry(name, key, entry):
    first, last = _did_range(name, key)
    if not isinstance(entry, dict) or set(entry) - DID_KEYS:
        _bad(name, "[dids] %s must be { name = \"...\", decode = \"hex\" }" % key)
    decode = _str(name, entry, "decode", required=True)
    if decode not in DECODERS:
        _bad(name, "[dids] %s decode must be one of %s" % (key, ", ".join(DECODERS)))
    label = _str(name, entry, "name", required=True)
    vtype = _str(name, entry, "type")
    if vtype is not None and vtype not in TYPES:
        _bad(name, "[dids] %s type must be one of %s" % (key, ", ".join(TYPES)))
    writable = entry.get("writable", False)
    if not isinstance(writable, bool):
        _bad(name, "[dids] %s writable must be true or false" % key)
    if writable and first != last:
        _bad(name, "[dids] %s is a range: a writable entry is one DID" % key)
    if writable and vtype is None:
        _bad(name, "[dids] %s is writable and needs a type (u8, u16 or blob)" % key)
    if writable and KEY_NAME.fullmatch(label) is None:
        _bad(name, "[dids] %s name %r: a writable key's name is letters, digits and _" % (key, label))
    top, lo, hi = TYPES.get(vtype), None, None
    if top is None and ("min" in entry or "max" in entry):
        _bad(name, "[dids] %s min and max need type u8 or u16" % key)
    if top is not None:
        lo, hi = _int(name, entry, "min", 0, top), _int(name, entry, "max", 0, top)
        lo_eff, hi_eff = (0 if lo is None else lo), (top if hi is None else hi)
        if lo_eff > hi_eff:
            _bad(name, "[dids] %s min %d is above max %d" % (key, lo_eff, hi_eff))
    return DidEntry(first, last, label, decode, vtype, writable, lo, hi)


# [config] as a ConfigSpec (None when absent): commit_rid, the optional status_did and hash = { did, first, last,
# schema }, all four required in the hash.
def _config(name, t):
    if t is None:
        return None
    spec, h = None, t.get("hash")
    if h is not None:
        if not isinstance(h, dict) or set(h) - HASH_KEYS:
            _bad(name, "[config] hash must be { did = 0x..., first = 0x..., last = 0x..., schema = 1 }")
        spec = HashSpec(_int(name, h, "did", 0, 0xFFFF, required=True),
                        _int(name, h, "first", 0, 0xFFFF, required=True),
                        _int(name, h, "last", 0, 0xFFFF, required=True),
                        _int(name, h, "schema", 0, 0xFF, required=True))
        if spec.first > spec.last:
            _bad(name, "[config] hash first 0x%04X is above last 0x%04X" % (spec.first, spec.last))
    return ConfigSpec(_int(name, t, "commit_rid", 0, 0xFFFF, required=True), _int(name, t, "status_did", 0, 0xFFFF),
                      spec)


# Build a Profile from parsed TOML; every problem raises Refused (exit 2, nothing sent).
def from_dict(name, d):
    for table, value in d.items():
        if table not in KEYS or not isinstance(value, dict):
            _bad(name, "unknown table [%s]" % table)
        if KEYS[table] is not None and set(value) - KEYS[table]:
            _bad(name, "unknown key %s in [%s]" % (sorted(set(value) - KEYS[table])[0], table))
    can_t = d.get("can", {})
    req_id = _int(name, can_t, "req_id", 0, 0x7FF, required=True)
    resp_id = _int(name, can_t, "resp_id", 0, 0x7FF, required=True)
    deny_tx = frozenset(_ints(name, can_t, "deny_tx", 0, 0x7FF))
    if req_id in deny_tx:
        _bad(name, "req_id 0x%03X is in deny_tx" % req_id)
    if req_id == resp_id:
        _bad(name, "req_id and resp_id are both 0x%03X" % req_id)
    func_t, func_id = d.get("functional"), None
    if func_t is not None:
        func_id = _int(name, func_t, "id", 0, 0x7FF, required=True)
        if func_id in deny_tx or func_id in (req_id, resp_id):
            _bad(name, "[functional] id 0x%03X is the request or response ID, or in deny_tx" % func_id)
    sec_t, security = d.get("security"), None
    if sec_t is not None:
        mode = _str(name, sec_t, "mode") or "hmac"
        if mode not in SECURITY_MODES:
            _bad(name, "[security] mode must be one of %s" % ", ".join(SECURITY_MODES))
        for other, keys in SECURITY_MODES.items():
            for key in keys:
                if other != mode and key in sec_t:
                    _bad(name, "[security] %s is for mode = \"%s\", not \"%s\"" % (key, other, mode))
        label = _str(name, sec_t, "label", required=True) if mode == "hmac" else None
        if label is not None and not label.isascii():
            _bad(name, "[security] label must be ASCII")
        security = Security(None if label is None else label.encode("ascii"),
                            _str(name, sec_t, "master_file", required=mode == "hmac"),
                            _int(name, sec_t, "device_id_did", 0, 0xFFFF, default=0xF18C),
                            _level(name, sec_t, "level_extended", 0x01),
                            _level(name, sec_t, "level_programming", 0x03),
                            mode=mode,
                            private_key_file=_str(name, sec_t, "private_key_file", required=mode == "ecdsa"))
    img_t, board_t, busy_t = d.get("image", {}), d.get("board"), d.get("busy")
    board_names = {}
    if board_t is not None:
        names = board_t.get("names", {})
        if not isinstance(names, dict) or not all(k.isdigit() and isinstance(v, str) for k, v in names.items()):
            _bad(name, "[board] names must map hw_id numbers to board names")
        board_names = {int(k): v for k, v in names.items()}
    busy = None
    if busy_t is not None:
        busy = BusyDetector(_int(name, busy_t, "id", 0, 0x7FF, required=True),
                            _int(name, busy_t, "byte", 0, 7, required=True), _ints(name, busy_t, "values", 0, 0xFF))
    dids = tuple(_did_entry(name, key, entry) for key, entry in d.get("dids", {}).items())
    names = [e.name for e in dids if e.writable]
    for n in names:
        if names.count(n) > 1:
            _bad(name, "[dids] two writable keys are named %s" % n)
    return Profile(name=name, interface=_str(name, can_t, "interface"), req_id=req_id, resp_id=resp_id,
                   deny_tx=deny_tx, product=_str(name, img_t, "product"), hw_ids=_ints(name, img_t, "hw_ids", 0, 0xFF),
                   layout_id=_int(name, img_t, "layout_id", 0, 0xFF),
                   slot_size=_int(name, img_t, "slot_size", 1, 0xFFFFFFFF, default=SLOT_SIZE_DEFAULT),
                   security=security,
                   board_did=None if board_t is None else _int(name, board_t, "did", 0, 0xFFFF, required=True),
                   board_names=board_names, busy=busy,
                   preroll_frames=_int(name, d.get("preroll", {}), "tester_present_frames", 0, 64, default=0),
                   dids=dids, func_id=func_id,
                   quiet_bus=func_t is not None and _bool(name, func_t, "quiet_bus", False),
                   config=_config(name, d.get("config")))


# Load a profile by name (a file in udsota/profiles) or by path (anything with a / or ending .toml).
def load(spec):
    path = pathlib.Path(spec) if ("/" in spec or spec.endswith(".toml")) else PROFILE_DIR / (spec + ".toml")
    try:
        with open(path, "rb") as f:
            d = tomllib.load(f)
    except OSError as e:
        known = ", ".join(sorted(p.stem for p in PROFILE_DIR.glob("*.toml")))
        raise Refused("cannot read profile %s (%s; built-in profiles: %s)" % (path, e.strerror, known))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise Refused("profile %s is not valid TOML: %s" % (path, e))
    return from_dict(path.stem, d)
