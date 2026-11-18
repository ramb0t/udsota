"""udsota: firmware update client for a udsota server, UDS over ISO-TP (Linux: SocketCAN, kernel ISO-TP).

Commands: info (identity, update state, the profile's DIDs), flash FILE (precheck to ConfirmImage),
confirm (ConfirmImage after an update), reset (11 01, keyed when the profile has [security]), config show /
config set NAME=VALUE... (the profile's writable DIDs: stage with 0x2E, --commit, --reset to apply and check),
dtc show [--ext CODE] / dtc clear (the device's DTCs: 0x19, and 0x14 unlocked as config set is), pack FILE (the
payloads flash would send, with a manifest, for another flasher; no bus), stamp FILE (a bare image's header, after its
build; no bus) and keygen (a key pair for the ecdsa mode; it needs no profile and no bus).
The profile (--profile NAME or a .toml path) holds everything product-specific. Every frame goes out on
the profile's req_id, and on its [functional] id when it has one (quiet_bus), never on a deny_tx ID. Before
sending, the tool listens LISTEN_S seconds and stops on the profile's busy value or on any resp_id frame, then
pre-rolls a quiet bus if the profile asks.
"""
import argparse
import contextlib
import logging
import os
import pathlib
import sys

import can

from . import delta
from .profile import load as load_profile
from .errors import Refused, ToolError
from .config import config_set, config_show, group_writes, parse_writes, writable_keys
from .dtc import dtc_clear, dtc_ext, dtc_show, ext_code
from .image import BARE_HDR_CRC_OFFSET, parse_image, stamp
from .keys import keygen, load_master, load_private_key
from .transport import Transport
from .delta import DETOOLS_HINT
from .download import DIFF_DFIS
from .pack import DFIS, pack, refuse_bare_delta
from .update import (DROP_76_WITH_BASES, PRODUCT_NEEDS_BOOTLOADER, WAIT_NEEDS_BOOTLOADER, confirm_cmd, flash, info,
                     refuse_bootloader_compression, reset)


# A --dfi value: one of pack's DFIs, written 0x00, 0x10, 0x20 or 0x30.
def dfi_arg(text):
    try:
        dfi = int(text, 16)
    except ValueError:
        dfi = None
    if dfi not in DFIS:
        raise argparse.ArgumentTypeError("%s is not one of %s" % (text, ", ".join("0x%02X" % d for d in DFIS)))
    return dfi


# A --wait-for-unit value: whole seconds from 1 to 600.
def wait_arg(text):
    try:
        seconds = int(text)
    except ValueError:
        seconds = None
    if seconds is None or not 1 <= seconds <= 600:
        raise argparse.ArgumentTypeError("%s is not a whole number of seconds from 1 to 600" % text)
    return seconds


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
    f.add_argument("--wait-for-unit", type=wait_arg, metavar="SECONDS",
                   help="[update] flow = \"bootloader\" only, for a unit whose app cannot hand over: if the first "
                        "10 02 is not answered, power-cycle the unit when told, while 10 02 goes out again, each at "
                        "most 50 ms after the last went unanswered, for up to SECONDS (1 to 600) to catch its "
                        "bootloader's power-up window")
    f.add_argument("--allow-product-change", action="store_true",
                   help="[update] flow = \"bootloader\" only: flash an image of another project than the one the unit "
                        "reports as installed (F1F5), which is refused without this")
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
    st = sub.add_parser("stamp", help="fill a bare image's header (length, image ID, CRC) after its build, and check "
                                      "the result against the profile")
    st.add_argument("file", type=pathlib.Path)
    st.add_argument("--out", type=pathlib.Path, metavar="OUT", help="file to write (default: FILE, in place)")
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


# load_secret when the profile has [security], else None (nothing to unlock).
def secret_for(prof, args):
    return load_secret(prof, args) if prof.security is not None else None


# path's bytes; Refused (exit 2) when it cannot be read.
def read_file(path):
    try:
        return path.read_bytes()
    except OSError as e:
        raise Refused("cannot read %s: %s" % (path, e.strerror))


# The base images --diff-from names, as (name, bytes) pairs: path itself, or every *.bin directly in a directory.
# Refuses when detools, which builds the patches, is not installed.
def load_bases(path):
    try:
        delta.import_detools()   # only checked here; delta.make_patch imports it
    except ImportError:
        raise Refused(DETOOLS_HINT) from None
    files = sorted(f for f in path.glob("*.bin") if f.is_file()) if path.is_dir() else [path]
    if not files:
        raise Refused("--diff-from %s: the directory holds no .bin files" % path)
    return [(str(f), read_file(f)) for f in files]


# Write data to out through a temporary file in the same directory, then replace the target, so a failure leaves the
# target as it was; an existing target keeps its permissions. A symlink is written through to its target, and a hard
# link is split.
def replace_file(out, data):
    dest = out.resolve()
    if not dest.name or dest.is_dir():
        raise Refused("cannot write %s: it is a directory" % out)
    part = dest.with_name(".%s.%d.part" % (dest.name, os.getpid()))
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if dest.exists():
                os.chmod(part, dest.stat().st_mode & 0o7777)
            os.replace(part, dest)
        except BaseException:
            with contextlib.suppress(OSError):
                part.unlink()
            raise
    except OSError as e:
        raise Refused("cannot write %s: %s" % (out, e.strerror)) from None


# `keygen`: writes the key pair and says where the private key belongs.
def keygen_cmd(out):
    private, header = keygen(out)
    print("wrote %s and %s" % (private, header))
    print("%s is the fleet's unlock key: move it into your signing service or HSM, and never commit it or "
          "build it into an image. %s is public: build it into the app as cfg.key_pubkey." % (private, header))
    return 0


# `pack`: reads FILE and the --diff-from base, and writes the payloads and manifest (pack.pack).
def pack_cmd(prof, args):
    if args.diff_from is not None:
        refuse_bare_delta(prof)
    if args.diff_from is not None and args.diff_from.is_dir():
        raise Refused("pack --diff-from takes one base file, the image the devices run: with no device to ask, it "
                      "cannot choose from a directory as flash does")
    image = read_file(args.file)
    base = None if args.diff_from is None else read_file(args.diff_from)
    pack(prof, image, args.file.stem, args.out, dfis=None if args.dfi is None else tuple(dict.fromkeys(args.dfi)),
         base=base)
    return 0


# `stamp`: FILE stamped (image.stamp) at the profile's header_offset and checked against the profile, written to
# --out or in place (replace_file).
def stamp_cmd(prof, args, log=print):
    if prof.image_format != "bare":
        raise Refused("profile %s: stamp is for [image] format = \"bare\", and its format is \"%s\""
                      % (prof.name, prof.image_format))
    img = stamp(read_file(args.file), prof.header_offset)
    stamped = parse_image(prof, img)
    out = args.out or args.file
    replace_file(out, img)
    at = prof.header_offset + BARE_HDR_CRC_OFFSET
    crc = int.from_bytes(img[at:at + 4], "little")
    log("stamped %s: %d bytes, crc32 0x%08X, image ID %s..." % (out, len(img), crc, stamped.elf_sha[:4].hex()))
    return 0


# The bus commands. Each prepare_* takes the loaded profile and the arguments, makes the command's refusals before
# any key is read or the bus opens, loads the 0x27 secret last when the command is keyed and the profile has
# [security], and returns run(uds, t), which runs the command on the open bus (t is the transport).
def prepare_info(prof, args):
    return lambda uds, t: info(uds, prof)


def prepare_flash(prof, args):
    image = read_file(args.file)
    parse_image(prof, image)
    if args.drop_76 is not None and args.drop_76 < 1:
        raise Refused("--drop-76 takes a block number from 1")
    if args.diff_format is not None and args.diff_from is None:
        raise Refused("--diff-format needs --diff-from")
    refuse_bootloader_compression(prof, args.compress)
    if args.wait_for_unit is not None and prof.flow != "bootloader":   # flash refuses it too
        raise Refused("profile %s: %s" % (prof.name, WAIT_NEEDS_BOOTLOADER))
    if args.allow_product_change and prof.flow != "bootloader":
        raise Refused("profile %s: %s" % (prof.name, PRODUCT_NEEDS_BOOTLOADER))
    bases = None
    if args.diff_from is not None:
        if args.drop_76 is not None:            # flash refuses it too; here before any key or bus
            raise Refused(DROP_76_WITH_BASES)
        refuse_bare_delta(prof)
        bases = load_bases(args.diff_from)
    secret = secret_for(prof, args)
    return lambda uds, t: flash(uds, prof, image, secret, drop_76=args.drop_76, preroll=t.preroll,
                                quiet=getattr(t, "quiet", contextlib.nullcontext), compress=args.compress,
                                bases=bases, diff_format=args.diff_format or "auto",
                                wait_for_unit=args.wait_for_unit, allow_product_change=args.allow_product_change)


def prepare_confirm(prof, args):
    if prof.flow == "bootloader":
        raise Refused("profile %s: [update] flow = \"bootloader\" has no ConfirmImage; flash ends once the app "
                      "reports healthy" % prof.name)
    return lambda uds, t: confirm_cmd(uds)


def prepare_reset(prof, args):
    secret = secret_for(prof, args)
    return lambda uds, t: reset(uds, prof, secret)


# config and dtc are for a unit whose app serves UDS, which a bootloader-flow unit's does not.
def refuse_bootloader_flow(prof, cmd):
    if prof.flow == "bootloader":
        raise Refused("profile %s: [update] flow = \"bootloader\" has no %s: the unit's app serves no UDS"
                      % (prof.name, cmd))


def prepare_config(prof, args):
    refuse_bootloader_flow(prof, "config")
    if args.config_cmd == "show":
        writable_keys(prof)
        return lambda uds, t: config_show(uds, prof)
    writes = parse_writes(prof, args.assignments, args.commit, args.reset)
    group_writes(prof, writes, args.commit)     # stage-only across groups: refused here
    secret = secret_for(prof, args)
    return lambda uds, t: config_set(uds, prof, writes, secret, commit=args.commit, reset=args.reset,
                                     preroll=t.preroll)


def prepare_dtc(prof, args):
    refuse_bootloader_flow(prof, "dtc")
    if args.dtc_cmd == "clear":
        secret = secret_for(prof, args)
        return lambda uds, t: dtc_clear(uds, prof, secret)
    if args.ext is None:
        return lambda uds, t: dtc_show(uds, prof)
    ext = ext_code(args.ext)
    return lambda uds, t: dtc_ext(uds, prof, ext, args.ext)


PREPARE = {"info": prepare_info, "flash": prepare_flash, "confirm": prepare_confirm, "reset": prepare_reset,
           "config": prepare_config, "dtc": prepare_dtc}


# Entry point; returns the exit code (0 ok, 1 failed, 2 refused, 3 server busy, 4 second tester).
def main(argv=None, transport=Transport):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.cmd in ("keygen", "pack", "stamp"):   # no bus, so any platform
        try:
            if args.cmd == "keygen":
                return keygen_cmd(args.out)
            return (pack_cmd if args.cmd == "pack" else stamp_cmd)(load_profile(args.profile), args)
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
        run = PREPARE[args.cmd](prof, args)
        with transport(prof, interface) as t:
            t.preflight()
            return run(t.uds(), t)
    except ToolError as e:
        print("udsota: %s" % e, file=sys.stderr)
        return e.exit_code
    except (OSError, can.CanError) as e:   # the interface is missing or down, or the kernel lacks can-isotp
        print("udsota: %s" % e, file=sys.stderr)
        return 1
