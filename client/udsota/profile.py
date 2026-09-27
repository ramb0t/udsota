"""Client profiles: everything product-specific (CAN IDs, deny list, key derivation, image identity,
busy detector, pre-roll, extra DIDs), read from a TOML file."""
import pathlib
import re
import tomllib
from dataclasses import dataclass

from .errors import Refused

PROFILE_DIR = pathlib.Path(__file__).resolve().parent / "profiles"
DECODERS = ("hex", "ascii", "version3")
SLOT_SIZE_DEFAULT = 0x400000   # UDSOTA_SLOT_SIZE_DEFAULT
KEYS = {"can": {"interface", "req_id", "resp_id", "deny_tx"},
        "security": {"mode", "label", "master_file", "private_key_file", "device_id_did", "level_extended",
                     "level_programming"},
        "image": {"product", "hw_ids", "layout_id", "slot_size"},
        "board": {"did", "names"},
        "busy": {"id", "byte", "values"},
        "preroll": {"tester_present_frames"},
        "dids": None}


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


# One [dids] entry: DIDs first..last (equal for a single DID), shown as name and decoded with decode.
@dataclass(frozen=True)
class DidEntry:
    first: int
    last: int
    name: str
    decode: str


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


# "0xF191" or "0x0200-0x02FF" to (first, last).
def _did_range(name, key):
    m = re.fullmatch(r"0x([0-9A-Fa-f]{1,4})(?:-0x([0-9A-Fa-f]{1,4}))?", key)
    if m is None:
        _bad(name, "[dids] key %r is not 0xNNNN or 0xNNNN-0xNNNN" % key)
    first, last = int(m[1], 16), int(m[2] or m[1], 16)
    if first > last:
        _bad(name, "[dids] key %r runs backwards" % key)
    return first, last


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
    dids = []
    for key, entry in d.get("dids", {}).items():
        first, last = _did_range(name, key)
        if not isinstance(entry, dict) or set(entry) - {"name", "decode"}:
            _bad(name, "[dids] %s must be { name = \"...\", decode = \"hex\" }" % key)
        decode = _str(name, entry, "decode", required=True)
        if decode not in DECODERS:
            _bad(name, "[dids] %s decode must be one of %s" % (key, ", ".join(DECODERS)))
        dids.append(DidEntry(first, last, _str(name, entry, "name", required=True), decode))
    return Profile(name=name, interface=_str(name, can_t, "interface"), req_id=req_id, resp_id=resp_id,
                   deny_tx=deny_tx, product=_str(name, img_t, "product"), hw_ids=_ints(name, img_t, "hw_ids", 0, 0xFF),
                   layout_id=_int(name, img_t, "layout_id", 0, 0xFF),
                   slot_size=_int(name, img_t, "slot_size", 1, 0xFFFFFFFF, default=SLOT_SIZE_DEFAULT),
                   security=security,
                   board_did=None if board_t is None else _int(name, board_t, "did", 0, 0xFFFF, required=True),
                   board_names=board_names, busy=busy,
                   preroll_frames=_int(name, d.get("preroll", {}), "tester_present_frames", 0, 64, default=0),
                   dids=tuple(dids))


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
