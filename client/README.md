# udsota client

`udsota` is udsota's PC client, copied unchanged from udsota release v0.14.2. It reads a device's identity, update state and fault codes and installs firmware over UDS on ISO-TP, on Linux with SocketCAN and the kernel's ISO-TP module. Its reference (every command, the profile's tables and the exit codes) is [the client README at v0.14.2](https://github.com/ramb0t/udsota/blob/v0.14.2/client/README.md); this page covers only what is different on lite.

```sh
pip install ./client                                  # Python 3.11 or newer; the udsota command
udsota --profile my.toml info                         # identity and update state
udsota --profile my.toml flash --compress app.bin     # precheck, download, verify, activate, confirm
```

Against lite, the client meets iso14229's server, which it already handles. Outside the default session it sends `3E 00` before any request or 0x21 retry that comes over 2 s after the last `10` or `3E`, and a `3E` that gets no answer doesn't fail the request after it. It takes iso14229's 2-byte zero seed as already unlocked. It waits up to 2 s for the answer to a signed key. Two things work differently. A lost answer to a `36` or `37` fails the run instead of being recovered, so run `flash` again. And lite has no delta downloads, so `flash --diff-from` gets 0x31 to each delta `34` and sends the full image, and the delta payloads `pack --diff-from` writes are ones lite refuses.

## What is copied

The `udsota` package, `pyproject.toml`, `LICENSE` and `tests/test_udsota.py` are udsota's, copied unchanged from a release; copy them again from each release and update the release named above. `tests/test_e2e_lite.py`, `tests/demo_server.py` (a subset of main's) and this README are lite's own.

## Tests

`python -m pytest client/tests` runs the unit tests, on virtual buses with no CAN interface, and the end-to-end test. Three unit tests skip here, because the files they check against (`udsota_wire.h` and a delta fixture) are main's, and without the `diff` extra the delta tests skip too.

The end-to-end test, `tests/test_e2e_lite.py`, drives `udsota_lite_server` over a frame pipe: a secured flash, a confirm that outlasts S3, a control run without the keepalive in which S3 ends the session, `config set`, a seed asked for while unlocked, an unconfirmed image that rolls back, and `--diff-from` falling back to the full image, which needs the `diff` extra. `$UDSOTA_LITE_SERVER` names the server; otherwise it is `build/udsota_lite_server`, which the top-level build makes, and the test skips when that is not built.
