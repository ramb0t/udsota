# Releasing udsota

How udsota is versioned and released. After a user-visible merge, run **Actions → cut release** with minor or patch; the rest explains what that does and the by-hand paths.

## Version numbers

udsota uses [semantic versioning](https://semver.org). While it is 0.x:

| Change | Bump | Example |
|---|---|---|
| Anything new or breaking: a new feature, a new member in a public struct, a new or changed function, macro or hook, any change to the wire protocol (a SID, NRC, DID, RID or byte layout), a profile key or a CLI flag | minor | 0.3.0 → 0.4.0 |
| A fix, and nothing else | patch | 0.3.0 → 0.3.1 |

From 1.0 the usual rules apply: major for breaking, minor for additive, patch for fixes.

**One version, in three places that agree:** the tag `vX.Y.Z`, the dated CHANGELOG heading `## [X.Y.Z] - YYYY-MM-DD`, and `__version__` in `client/udsota/__init__.py`. `python tools/release.py check vX.Y.Z` checks all three, and the release workflow runs it before it publishes anything.

The example's `PROJECT_VER` in `examples/esp32/CMakeLists.txt` is something else: the firmware image's version, which the device's anti-downgrade rule compares. It does not follow the library's version.

## Every pull request

Add a line to `## [Unreleased]` in `CHANGELOG.md` for anything a user would notice, and say whether it is breaking.

## Making a release

**Right after merging, run Actions → cut release → Run workflow** on `main`, with **minor** or **patch** from the table above. It takes the next version from the latest tag, moves `[Unreleased]`'s entries under `## [X.Y.Z] - today` with a new empty `[Unreleased]` above them, sets `__version__`, commits that to `main` as "Release X.Y.Z", and pushes an annotated tag. It refuses when `[Unreleased]` is empty or `main`'s CI hasn't passed on the commit. Release after each user-visible merge, or after several.

It then runs the [release workflow](.github/workflows/release.yml) on the tag. That checks the tag, builds the client's wheel and sdist and the example's app image for esp32 and esp32s3 at the tag, and publishes a GitHub Release. The notes are the version's CHANGELOG section, with its links made absolute at the tag. Releases are not marked as pre-releases, even at 0.x, so the newest one is GitHub's Latest and `/releases/latest` finds it.

The cut pushes to `main` directly. That works while `main` has no branch protection; with protection on, it needs a bypass, or a release PR instead.

To release by hand instead, merge a PR that makes the same two edits (`python tools/release.py bump minor --latest <latest tag>` makes them), then tag its merge commit with `git tag -a vX.Y.Z -m "udsota X.Y.Z"` and push the tag. The tag push runs the release workflow. If its check fails, nothing is published: fix `main` and release the next patch version.

## Rules

- Tag only commits on `main` whose CI is green. The cut's own commit changes only the CHANGELOG and `__version__`, on top of one whose CI passed.
- Never move or delete a published tag, or replace a published Release's files. Fix a bad release with a new patch release.

## Releasing an older tag

For a version tagged before the workflow existed, run the workflow by hand: **Actions → release → Run workflow**, with the tag and, for an older commit whose CHANGELOG may still say "unreleased", **backfill** on. Backfill skips the version check and takes the notes from `main`'s CHANGELOG. The tag must already exist on `main` and be annotated; the workflow never creates one.

A Release attaches the client only when the tagged client's `__version__` is the Release's version, which is why `v0.2.0`'s has none.
