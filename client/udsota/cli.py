"""udsota: firmware update client for a udsota server, UDS over ISO-TP (Linux: SocketCAN, kernel ISO-TP).

Commands: info (identity, update state, the profile's DIDs), flash FILE (precheck to ConfirmImage),
confirm (ConfirmImage after an update) and reset (11 01, keyed when the profile has [security]).
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
from .image import parse_image
from .keys import load_master
from .transport import Transport
from .update import confirm_cmd, flash, info, reset


# Command-line arguments.
def parse_args(argv):
    p = argparse.ArgumentParser(prog="udsota", description=__doc__.splitlines()[0])
    p.add_argument("--profile", required=True, help="product profile: a built-in name (example) or a .toml path")
    p.add_argument("--interface", help="SocketCAN interface (default: the profile's [can] interface)")
    p.add_argument("--master", help="master key file (default: the profile's security.master_file)")
    p.add_argument("-v", "--verbose", action="store_true", help="log every UDS request and response")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="identity DIDs, update state and the profile's DIDs")
    f = sub.add_parser("flash", help="download, verify, activate and confirm FILE (a signed app image)")
    f.add_argument("file", type=pathlib.Path)
    f.add_argument("--drop-76", type=int, metavar="N",
                   help="fault test: resend block N as if its 76 response were lost")
    sub.add_parser("confirm", help="ConfirmImage for a PENDING_VERIFY image")
    sub.add_parser("reset", help="ECUReset (rolls back an unconfirmed image)")
    return p.parse_args(argv)


# Entry point; returns the exit code (0 ok, 1 failed, 2 refused, 3 server busy, 4 second tester).
def main(argv=None, transport=Transport):
    args = parse_args(sys.argv[1:] if argv is None else argv)
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
        image = master = None
        if args.cmd == "flash":
            try:
                image = args.file.read_bytes()
            except OSError as e:
                raise Refused("cannot read %s: %s" % (args.file, e.strerror))
            parse_image(prof, image)
            if args.drop_76 is not None and args.drop_76 < 1:
                raise Refused("--drop-76 takes a block number from 1")
        if args.cmd in ("flash", "reset") and prof.security is not None:
            master = load_master(args.master or prof.security.master_file)
        with transport(prof, interface) as t:
            t.preflight()
            uds = t.uds()
            if args.cmd == "info":
                return info(uds, prof)
            if args.cmd == "flash":
                return flash(uds, prof, image, master, drop_76=args.drop_76, preroll=t.preroll,
                             quiet=getattr(t, "quiet", contextlib.nullcontext))
            if args.cmd == "confirm":
                return confirm_cmd(uds)
            return reset(uds, prof, master)
    except ToolError as e:
        print("udsota: %s" % e, file=sys.stderr)
        return e.exit_code
    except (OSError, can.CanError) as e:   # the interface is missing or down, or the kernel lacks can-isotp
        print("udsota: %s" % e, file=sys.stderr)
        return 1
