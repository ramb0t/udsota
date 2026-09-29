"""Release checks, release notes and version bumps, from CHANGELOG.md, the client's __version__ and udsota.h's
UDSOTA_VERSION macros (see RELEASING.md).

  python tools/release.py check v0.4.0    # the tag, CHANGELOG heading, client/udsota/__init__.py and udsota.h agree
  python tools/release.py notes v0.4.0    # the CHANGELOG section for 0.4.0, for the GitHub Release
  python tools/release.py bump minor --latest v0.4.0   # date [Unreleased] as 0.5.0, set __version__ and udsota.h

--changelog, --init and --header read other files, as the release workflow does for a tagged commit (git show)."""
import argparse
import datetime
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = "https://github.com/ramb0t/udsota"
TAG = re.compile(r"v(\d+\.\d+\.\d+)")
HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\] - (?P<date>.+)$", re.M)
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
CLIENT_VERSION = re.compile(r'^__version__ = "([^"]+)"', re.M)
HEADER = "components/udsota/include/udsota.h"
HEADER_VERSION = re.compile(r'^(#define UDSOTA_VERSION[ \t]+)"([^"]*)"', re.M)
HEADER_PARTS = [re.compile(r"^(#define UDSOTA_VERSION_%s[ \t]+)(\d+)" % p, re.M) for p in ("MAJOR", "MINOR", "PATCH")]
RELATIVE_LINK = re.compile(r"\]\((?![a-z][a-z0-9+.-]*:)([^)\s]+)\)")
UNRELEASED = re.compile(r"^## \[Unreleased\]\n(?P<body>.*?)(?=^## \[|\Z)", re.M | re.S)


# The X.Y.Z of a vX.Y.Z tag; ValueError for anything else.
def version_of(tag):
    m = TAG.fullmatch(tag)
    if m is None:
        raise ValueError("tag %r is not vX.Y.Z" % tag)
    return m[1]


# The CHANGELOG section for version: (date, body without its heading); ValueError when there is none.
def section(changelog, version):
    headings = list(HEADING.finditer(changelog))
    for i, h in enumerate(headings):
        if h["version"] == version:
            end = headings[i + 1].start() if i + 1 < len(headings) else len(changelog)
            return h["date"].strip(), changelog[h.end():end].strip()
    raise ValueError("CHANGELOG.md has no ## [%s] section" % version)


# Every way the header's UDSOTA_VERSION and UDSOTA_VERSION_MAJOR, _MINOR and _PATCH disagree with version.
def header_problems(header, version):
    found = []
    m = HEADER_VERSION.search(header)
    if m is None:
        found.append("%s defines no UDSOTA_VERSION" % HEADER)
    elif m[2] != version:
        found.append("%s has UDSOTA_VERSION %r, not %r" % (HEADER, m[2], version))
    parts = [p.search(header) for p in HEADER_PARTS]
    if None in parts:
        found.append("%s defines no UDSOTA_VERSION_MAJOR, _MINOR and _PATCH" % HEADER)
    else:
        numbers = ".".join(str(int(p[2])) for p in parts)
        if numbers != version:
            found.append("%s has UDSOTA_VERSION_MAJOR, _MINOR and _PATCH %s, not %s" % (HEADER, numbers, version))
    return found


# header with UDSOTA_VERSION and its three numbers set to version (X.Y.Z).
def set_header_version(header, version):
    header = HEADER_VERSION.sub(lambda m: '%s"%s"' % (m[1], version), header)
    for p, n in zip(HEADER_PARTS, version.split(".")):
        header = p.sub(lambda m: m[1] + n, header)
    return header


# Every way tag disagrees with the CHANGELOG, the client's __version__ and the header's UDSOTA_VERSION macros (empty
# when they agree).
def problems(tag, changelog, client_init, header):
    try:
        version = version_of(tag)
    except ValueError as e:
        return [str(e)]
    found = []
    try:
        date, body = section(changelog, version)
        if not DATE.fullmatch(date):
            found.append("CHANGELOG.md's ## [%s] is dated %r, not YYYY-MM-DD" % (version, date))
        if not body:
            found.append("CHANGELOG.md's ## [%s] section is empty" % version)
    except ValueError as e:
        found.append(str(e))
    m = CLIENT_VERSION.search(client_init)
    if m is None:
        found.append("client/udsota/__init__.py sets no __version__")
    elif m[1] != version:
        found.append("client/udsota/__init__.py has __version__ %r, not %r" % (m[1], version))
    return found + header_problems(header, version)


# text with each relative Markdown link made absolute at tag, so it still works on a Release page; a bare
# #anchor is one in CHANGELOG.md.
def absolute_links(text, tag):
    def link(m):
        target = m[1]
        if target.startswith("#"):
            target = "CHANGELOG.md" + target
        return "](%s/blob/%s/%s)" % (REPO, tag, target.removeprefix("./"))
    return RELATIVE_LINK.sub(link, text)


# The GitHub Release body for tag: its CHANGELOG section, with links that work outside the repository.
def notes(tag, changelog):
    version = version_of(tag)
    date, body = section(changelog, version)
    return absolute_links("%s\n\nReleased %s. The full history is in [CHANGELOG.md](CHANGELOG.md).\n"
                          % (body, date), tag)


# The version after latest (X.Y.Z): part is "minor" (X.Y+1.0) or "patch" (X.Y.Z+1).
def next_version(latest, part):
    major, minor, patch = (int(n) for n in latest.split("."))
    if part == "minor":
        return "%d.%d.0" % (major, minor + 1)
    if part == "patch":
        return "%d.%d.%d" % (major, minor, patch + 1)
    raise ValueError("bump %r is not minor or patch" % part)


# changelog with [Unreleased]'s entries under a new ## [version] - date heading, and an empty [Unreleased] above
# it; ValueError when [Unreleased] is missing or empty, or version already has a section.
def cut(changelog, version, date):
    m = UNRELEASED.search(changelog)
    if m is None:
        raise ValueError("CHANGELOG.md has no ## [Unreleased] section")
    if not m["body"].strip():
        raise ValueError("CHANGELOG.md's ## [Unreleased] is empty: nothing to release")
    if any(h["version"] == version for h in HEADING.finditer(changelog)):
        raise ValueError("CHANGELOG.md already has a ## [%s] section" % version)
    return "%s## [Unreleased]\n\n## [%s] - %s\n%s%s" % (changelog[:m.start()], version, date, m["body"],
                                                       changelog[m.end():])


# Date [Unreleased] as the version after the latest tag and set __version__ and the header's macros to it, once the
# latest tag agrees with all three files; returns (changelog, client_init, header, version).
def bump(part, latest_tag, changelog, client_init, header, date):
    found = problems(latest_tag, changelog, client_init, header)
    if found:
        raise ValueError("the files don't match %s: %s" % (latest_tag, "; ".join(found)))
    version = next_version(version_of(latest_tag), part)
    return (cut(changelog, version, date), CLIENT_VERSION.sub('__version__ = "%s"' % version, client_init),
            set_header_version(header, version), version)


# Parse the arguments and run check, notes or bump; returns the exit code.
def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("cmd", choices=("check", "notes", "bump"))
    p.add_argument("tag", help="the release tag, vX.Y.Z; for bump, minor or patch")
    p.add_argument("--latest", help="bump: the latest release tag, vX.Y.Z")
    p.add_argument("--date", default=datetime.date.today().isoformat(), help="bump: the release date")
    p.add_argument("--changelog", type=pathlib.Path, default=ROOT / "CHANGELOG.md")
    p.add_argument("--init", type=pathlib.Path, default=ROOT / "client" / "udsota" / "__init__.py")
    p.add_argument("--header", type=pathlib.Path, default=ROOT / HEADER)
    args = p.parse_args(argv)
    changelog = args.changelog.read_text(encoding="utf-8")
    try:
        if args.cmd == "bump":
            if args.latest is None:
                p.error("bump needs --latest")
            changelog, client_init, header, version = bump(args.tag, args.latest, changelog,
                                                           args.init.read_text(encoding="utf-8"),
                                                           args.header.read_text(encoding="utf-8"), args.date)
            args.changelog.write_text(changelog, encoding="utf-8")
            args.init.write_text(client_init, encoding="utf-8")
            args.header.write_text(header, encoding="utf-8")
            print(version)
            return 0
        if args.cmd == "notes":
            sys.stdout.write(notes(args.tag, changelog))
            return 0
        found = problems(args.tag, changelog, args.init.read_text(encoding="utf-8"),
                         args.header.read_text(encoding="utf-8"))
    except ValueError as e:
        found = [str(e)]
    for f in found:
        print("release: %s" % f, file=sys.stderr)
    if not found:
        print("release: %s matches CHANGELOG.md, the client's __version__ and udsota.h" % args.tag)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
