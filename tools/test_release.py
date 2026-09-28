"""Tests for tools/release.py: python -m pytest tools/test_release.py"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import release  # noqa: E402

CHANGELOG = """# Changelog

## [Unreleased]

Work in progress.

## [0.4.0] - 2026-10-01

Added progress.

## [0.3.0] - 2026-09-28

Functional addressing.

## [0.1.0] - unreleased

First.
"""
INIT = '"""udsota."""\n__version__ = "0.4.0"\n'


# Check a tag that matches its dated CHANGELOG section and __version__ passes.
def test_matching_release_passes():
    assert release.problems("v0.4.0", CHANGELOG, INIT) == []


# Check each way a release can disagree is named.
@pytest.mark.parametrize("tag, init, want", [
    ("0.4.0", INIT, "not vX.Y.Z"),
    ("v0.4", INIT, "not vX.Y.Z"),
    ("v0.5.0", INIT.replace("0.4.0", "0.5.0"), "no ## [0.5.0] section"),
    ("v0.3.0", INIT, "__version__ '0.4.0', not '0.3.0'"),
    ("v0.1.0", INIT.replace("0.4.0", "0.1.0"), "dated 'unreleased'"),
    ("v0.4.0", '"""no version"""\n', "sets no __version__"),
])
def test_mismatches_are_named(tag, init, want):
    found = release.problems(tag, CHANGELOG, init)
    assert found and any(want in f for f in found), found


# Check the notes are the version's section alone, with its date, and stop at the next heading.
def test_notes_are_the_versions_section():
    text = release.notes("v0.3.0", CHANGELOG)
    assert text.startswith("Functional addressing.") and "Released 2026-09-28." in text
    assert "progress" not in text and "First." not in text


# Check relative links, which are dead on a Release page, point into the repository at the tag, and others don't
# change.
def test_notes_links_are_absolute_at_the_tag():
    cl = CHANGELOG.replace("Added progress.", "See [the policy](RELEASING.md), [CI](./.github/workflows/ci.yml), "
                           "[0.3.0](#030---2026-09-28) and [semver](https://semver.org).")
    text = release.notes("v0.4.0", cl)
    blob = "https://github.com/ramb0t/udsota/blob/v0.4.0/"
    assert "[the policy](%sRELEASING.md)" % blob in text
    assert "[CI](%s.github/workflows/ci.yml)" % blob in text
    assert "[0.3.0](%sCHANGELOG.md#030---2026-09-28)" % blob in text
    assert "[semver](https://semver.org)" in text
    assert "[CHANGELOG.md](%sCHANGELOG.md)" % blob in text


# Check the repository's own CHANGELOG has a dated section for the client's current version, so a tag for it
# would pass.
def test_repository_current_version_is_released():
    root = pathlib.Path(release.ROOT)
    init = (root / "client" / "udsota" / "__init__.py").read_text()
    version = release.CLIENT_VERSION.search(init)[1]
    assert release.problems("v" + version, (root / "CHANGELOG.md").read_text(), init) == []


# Check the command line: check exits 0 or 1, notes prints the section.
def test_main(tmp_path, capsys):
    cl, ini = tmp_path / "CHANGELOG.md", tmp_path / "__init__.py"
    cl.write_text(CHANGELOG)
    ini.write_text(INIT)
    assert release.main(["check", "v0.4.0", "--changelog", str(cl), "--init", str(ini)]) == 0
    assert release.main(["check", "v0.3.0", "--changelog", str(cl), "--init", str(ini)]) == 1
    assert "not '0.3.0'" in capsys.readouterr().err
    assert release.main(["notes", "v0.4.0", "--changelog", str(cl)]) == 0
    assert capsys.readouterr().out.startswith("Added progress.")
