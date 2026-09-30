"""udsota: firmware update client for a udsota server, UDS over ISO-TP (Linux: SocketCAN, kernel ISO-TP).

Commands: info (identity, update state, the profile's DIDs), flash FILE (precheck to ConfirmImage),
confirm (ConfirmImage after an update), reset (11 01, keyed when the profile has [security]), config show /
config set NAME=VALUE... (the profile's writable DIDs: stage with 0x2E, --commit, --reset to apply and check),
dtc show [--ext CODE] / dtc clear (the device's DTCs: 0x19, and 0x14 unlocked as config set is), pack FILE (the
payloads flash would send, with a manifest, for another flasher; no bus) and keygen (a key pair for the ecdsa mode;
it needs no profile and no bus).
The profile (--profile NAME or a .toml path) holds everything product-specific. Every frame goes out on
the profile's req_id only, never on a deny_tx ID. Before sending, the tool listens LISTEN_S seconds and
stops on the profile's busy value or on any resp_id frame, then pre-rolls a quiet bus if the profile asks.
"""
import argparse
import contextlib
import logging
import pathlib
import sys

import can

from .profile import load as load_profile
from .errors import Refused, ToolError
from .config import config_set, config_show, group_writes, parse_writes, writable_keys
from .dtc import dtc_clear, dtc_ext, dtc_show, ext_code
from .image import parse_image
from .keys import keygen, load_master, load_private_key
from .transport import Transport
from .delta import DETOOLS_HINT
from .pack import DFIS, pack
from .update import DIFF_DFIS, confirm_cmd, flash, info, reset


# A --dfi value: one of pack's DFIs, written 0x00, 0x10, 0x20 or 0x30.
def dfi_arg(text):
    try:
        dfi = int(text, 16)
    except ValueError:
        dfi = None
    if dfi not in DFIS:
        raise argparse.ArgumentTypeError("%s is not one of %s" % (text, ", ".join("0x%02X" % d for d in DFIS)))
    return dfi


# Command-line arguments; every command but keygen needs --profile.
def parse_args(argv):
    p = argparse.ArgumentParser(prog="udsota", description=__doc__.splitlines()[0])
    p.add_argument("--profile", help="product profile: a built-in name (example) or a .toml path")
    p.add_argument("--interface", help="SocketCAN interface (default: the profile's [can] interface)")
    p.add_argument("--master", help="master key file, mode hmac (default: the profile's security.master_file)")
    p.add_argument("--private-key", help="private key PEM, mode ecdsa (default: the profile's "
                                         "security.private_key_file)")
    p.add_argument("-v", "--verbose", action="store_true", help="log every UDS request and response")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="identity DIDs, update state and the profile's DIDs")
    f = sub.add_parser("flash", help="download, verify, activate and confirm FILE (a signed app image)")
    f.add_argument("file", type=pathlib.Path)
    f.add_argument("--drop-76", type=int, metavar="N",
                   help="fault test: resend block N as if its 76 response were lost")
    z = f.add_mutually_exclusive_group()
    z.add_argument("--compress", dest="compress", action="store_const", const="deflate",
                   help="send the image as raw DEFLATE (DFI 0x10); stop on a server without compressed downloads "
                        "(default: the profile's [image] compression, else none)")
    z.add_argument("--compress-auto", dest="compress", action="store_const", const="auto",
                   help="as --compress, but send the image uncompressed to a server without compressed downloads")
    z.add_argument("--no-compress", dest="compress", action="store_const", const="none",
                   help="send the image uncompressed, whatever the profile says")
    f.add_argument("--diff-from", type=pathlib.Path, metavar="PATH",
                   help="offer a delta download from the image the server runs: PATH is that .bin, or a directory "
                        "of .bin files to find it in (needs detools: pip install \"./client[diff]\")")
    f.add_argument("--diff-format", choices=tuple(DIFF_DFIS),
                   help="with --diff-from, the delta modes to try: heatshrink (DFI 0x20), deflate (DFI 0x30) or "
                        "both (default auto)")
    sub.add_parser("confirm", help="ConfirmImage for a PENDING_VERIFY image")
    sub.add_parser("reset", help="ECUReset (rolls back an unconfirmed image)")
    c = sub.add_parser("config", help="show or set the profile's writable DIDs")
    csub = c.add_subparsers(dest="config_cmd", required=True)
    csub.add_parser("show", help="each writable DID's value, the config status and the hash check")
    s = csub.add_parser("set", help="stage NAME=VALUE for writable DIDs (0x2E); --commit stores, --reset applies")
    s.add_argument("assignments", nargs="+", metavar="NAME=VALUE")
    s.add_argument("--commit", action="store_true", help="run the profile's commit routine after staging")
    s.add_argument("--reset", action="store_true",
                   help="with --commit: keyed 11 01, then read every key back and check the config hash")
    dt = sub.add_parser("dtc", help="read or clear the device's DTCs (0x19, 0x14)")
    dsub = dt.add_subparsers(dest="dtc_cmd", required=True)
    ds = dsub.add_parser("show", help="every DTC with a status bit set (19 02 FF), with the profile's descriptions")
    ds.add_argument("--ext", metavar="CODE", help="one DTC's status and extended data records instead (19 06 CODE FF); "
                                                  "CODE is U0073, U0073-1C or 0xC07300")
    dsub.add_parser("clear", help="clear every DTC (14 FF FF FF) in the extended session, unlocked as config set is")
    pk = sub.add_parser("pack", help="write the download payloads for FILE and a JSON manifest, for a flasher that "
                                     "is not this client")
    pk.add_argument("file", type=pathlib.Path)
    pk.add_argument("--out", type=pathlib.Path, required=True, metavar="DIR", help="directory to write them in")
    pk.add_argument("--dfi", type=dfi_arg, action="append", metavar="DFI",
                    help="a download mode to write: 0x00 (plain), 0x10 (raw DEFLATE), 0x20 or 0x30 (delta, with "
                         "--diff-from); repeat for several (default: every mode the arguments allow)")
    pk.add_argument("--diff-from", type=pathlib.Path, metavar="PATH",
                    help="the image the device runs, for DFI 0x20 and 0x30 (needs detools: pip install "
                         "\"./client[diff]\")")
    k = sub.add_parser("keygen", help="write a new ecdsa-mode key pair: udsota_private.pem and udsota_pubkey.h")
    k.add_argument("--out", type=pathlib.Path, required=True, metavar="DIR", help="directory to write them in")
    args = p.parse_args(argv)
    if args.cmd != "keygen" and args.profile is None:
        p.error("the following arguments are required: --profile")
    return args


# The profile's 0x27 secret for flash, reset, config set and dtc clear: the master key (mode hmac) or the private key
# (mode ecdsa).
def load_secret(prof, args):
    if prof.security.mode == "ecdsa":
        if args.master:
            raise Refused("--master is for mode hmac; profile %s uses mode ecdsa (--private-key)" % prof.name)
        return load_private_key(args.private_key or prof.security.private_key_file)
    if args.private_key:
        raise Refused("--private-key is for mode ecdsa; profile %s uses mode hmac (--master)" % prof.name)
    return load_master(args.master or prof.security.master_file)


# The base images --diff-from names, as (name, bytes) pairs: path itself, or every *.bin directly in a directory.
# Refuses when detools, which builds the patches, is not installed.
def load_bases(path):
    try:
        import detools   # noqa: F401  (only checked here; delta.make_patch imports it)
    except ImportError:
        raise Refused(DETOOLS_HINT) from None
    files = sorted(f for f in path.glob("*.bin") if f.is_file()) if path.is_dir() else [path]
    if not files:
        raise Refused("--diff-from %s: the directory holds no .bin files" % path)
    try:
        return [(str(f), f.read_bytes()) for f in files]
    except OSError as e:
        raise Refused("cannot read %s: %s" % (e.filename, e.strerror))


# `keygen`: writes the key pair and says where the private key belongs.
def keygen_cmd(out):
    private, header = keygen(out)
    print("wrote %s and %s" % (private, header))
    print("%s is the fleet's unlock key: move it into your signing service or HSM, and never commit it or "
          "build it into an image. %s is public: build it into the app as cfg.key_pubkey." % (private, header))
    return 0


# `pack`: reads FILE and the --diff-from base, and writes the payloads and manifest (pack.pack).
def pack_cmd(prof, args):
    if args.diff_from is not None and args.diff_from.is_dir():
        raise Refused("pack --diff-from takes one base file, the image the devices run: with no device to ask, it "
                      "cannot choose from a directory as flash does")
    try:
        image = args.file.read_bytes()
        base = None if args.diff_from is None else args.diff_from.read_bytes()
    except OSError as e:
        raise Refused("cannot read %s: %s" % (e.filename, e.strerror))
    pack(prof, image, args.file.stem, args.out, dfis=None if args.dfi is None else tuple(dict.fromkeys(args.dfi)),
         base=base)
    return 0


# Entry point; returns the exit code (0 ok, 1 failed, 2 refused, 3 server busy, 4 second tester).
def main(argv=None, transport=Transport):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.cmd in ("keygen", "pack"):   # no bus, so any platform
        try:
            return keygen_cmd(args.out) if args.cmd == "keygen" else pack_cmd(load_profile(args.profile), args)
        except ToolError as e:
            print("udsota: %s" % e, file=sys.stderr)
            return e.exit_code
    if not sys.platform.startswith("linux"):
        print("udsota: refusing: Linux only (SocketCAN, kernel ISO-TP)", file=sys.stderr)
        return 2
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    try:
        prof = load_profile(args.profile)
        interface = args.interface or prof.interface
        if interface is None:
            raise Refused("profile %s names no CAN interface: pass --interface" % prof.name)
        image = secret = writes = bases = ext = None
        if args.cmd == "flash":
            try:
                image = args.file.read_bytes()
            except OSError as e:
                raise Refused("cannot read %s: %s" % (args.file, e.strerror))
            parse_image(prof, image)
            if args.drop_76 is not None and args.drop_76 < 1:
                raise Refused("--drop-76 takes a block number from 1")
            if args.diff_format is not None and args.diff_from is None:
                raise Refused("--diff-format needs --diff-from")
            if args.diff_from is not None:
                if args.drop_76 is not None:            # flash refuses it too; here before any key or bus
                    raise Refused("--drop-76 is for full and compressed downloads, not with --diff-from")
                bases = load_bases(args.diff_from)
        if args.cmd == "config" and args.config_cmd == "set":
            writes = parse_writes(prof, args.assignments, args.commit, args.reset)
            group_writes(prof, writes, args.commit)     # stage-only across groups: refused here
        elif args.cmd == "config":
            writable_keys(prof)
        if args.cmd == "dtc" and args.dtc_cmd == "show" and args.ext is not None:
            ext = ext_code(args.ext)
        keyed = args.cmd in ("flash", "reset") or writes is not None or (args.cmd == "dtc" and args.dtc_cmd == "clear")
        if keyed and prof.security is not None:
            secret = load_secret(prof, args)
        with transport(prof, interface) as t:
            t.preflight()
            uds = t.uds()
            if args.cmd == "info":
                return info(uds, prof)
            if args.cmd == "flash":
                return flash(uds, prof, image, secret, drop_76=args.drop_76, preroll=t.preroll,
                             quiet=getattr(t, "quiet", contextlib.nullcontext), compress=args.compress,
                             bases=bases, diff_format=args.diff_format or "auto")
            if args.cmd == "confirm":
                return confirm_cmd(uds)
            if args.cmd == "config":
                if writes is None:
                    return config_show(uds, prof)
                return config_set(uds, prof, writes, secret, commit=args.commit, reset=args.reset,
                                  preroll=t.preroll)
            if args.cmd == "dtc":
                if args.dtc_cmd == "clear":
                    return dtc_clear(uds, prof, secret)
                return dtc_show(uds, prof) if ext is None else dtc_ext(uds, prof, ext, args.ext)
            return reset(uds, prof, secret)
    except ToolError as e:
        print("udsota: %s" % e, file=sys.stderr)
        return e.exit_code
    except (OSError, can.CanError) as e:   # the interface is missing or down, or the kernel lacks can-isotp
        print("udsota: %s" % e, file=sys.stderr)
        return 1
