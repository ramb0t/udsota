# Run from the repository root, `import detools` finds udsota's vendored C sources in detools/ as an empty namespace
# package, so pytest.importorskip("detools") and find_spec("detools") pass without the diff extra and the delta cases
# fail where they should skip. Without the real package, mark detools missing for the whole run.
import sys

try:
    import detools
except ImportError:
    pass
else:
    if not hasattr(detools, "create_patch"):
        sys.modules["detools"] = None
