# Releasing udsota

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

1. **Open a release PR against `main`:**
   - rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and start a new, empty `## [Unreleased]` above it;
   - set `__version__ = "X.Y.Z"` in `client/udsota/__init__.py`;
   - run `python tools/release.py check vX.Y.Z` locally.
2. **Merge it once CI is green.**
3. **Tag the merge commit on `main`** with an annotated tag, and push it:

   ```sh
   git checkout main && git pull
   git tag -a vX.Y.Z -m "udsota X.Y.Z"
   git push origin vX.Y.Z
   ```

4. **The [release workflow](.github/workflows/release.yml) does the rest.** It checks the tag, builds the client's wheel and sdist and the example's app image for esp32 and esp32s3 at the tag, and publishes a GitHub Release. The notes are the version's CHANGELOG section, with its links made absolute at the tag. Releases are not marked as pre-releases, even at 0.x, so the newest one is GitHub's Latest and `/releases/latest` finds it.

If the check fails, nothing is published: fix `main` and tag a new patch version.

## Rules

- Tag only commits on `main` whose CI is green.
- Tags are annotated and named `vX.Y.Z`.
- Never move or delete a published tag, or replace a published Release's files. Fix a bad release with a new patch release.

## Releasing an older tag

For a version tagged before the workflow existed, run the workflow by hand: **Actions → release → Run workflow**, with the tag and, for an older commit whose CHANGELOG may still say "unreleased", **backfill** on. Backfill skips the version check and takes the notes from `main`'s CHANGELOG. The tag must already exist on `main` and be annotated; the workflow never creates one.

The Releases this repository needed when the workflow was added, run in this order:

| Tag | Commit | backfill |
|---|---|---|
| `v0.1.0` | `da16abf`, the initial import | on |
| `v0.2.0` | `8e8d0fe` | on |
| `v0.3.0` | `1183863` | off |

A Release attaches the client only when the tagged client's `__version__` is the Release's version. `v0.2.0`'s has none: its client was unchanged and still reports 0.1.0.
