# udsota client

`udsota` is udsota's PC client, unchanged since v0.14.2. It reads a device's identity, update state and fault codes and installs firmware over UDS on ISO-TP, on Linux with SocketCAN and the kernel's ISO-TP module. Its reference (every command, the profile's tables and the exit codes) is [the client README at v0.14.2](https://github.com/ramb0t/udsota/blob/v0.14.2/client/README.md); this page covers only what is different against this repo's server.

```sh
pip install ./client                                  # Python 3.11 or newer; the udsota command
udsota --profile my.toml info                         # identity and update state
udsota --profile my.toml flash --compress app.bin     # precheck, download, verify, activate, confirm
```

From 0.15 udsota answers inside the app's iso14229 server, which the client handles. Outside the default session it sends `3E 00` before any request or 0x21 retry that comes over 2 s after the last `10` or `3E`, and a `3E` that gets no answer doesn't fail the request after it. It takes iso14229's 2-byte zero seed as already unlocked. It waits up to 2 s for the answer to a signed key. Two things work differently from udsota 0.14's own server, which the client still updates. A lost answer to a `36` or `37` fails the run instead of being recovered, so run `flash` again. And there are no delta downloads, so `flash --diff-from` gets 0x31 to each delta `34` and sends the full image, and the delta payloads `pack --diff-from` writes are refused.

## Wire contract

`tests/test_udsota.py` checks the client's wire numbers against two contracts. Against `udsota.h`'s "Wire contract" block, with the NRCs and sessions it takes from `iso14229.h`, the numbers in `udsota/wire.py`, `keys.py` and `image.py` and the profile's default levels must match what this server answers. Against v0.14.2's wire headers, frozen in `test/fixtures/wire-v0.14/`, `wire.py`'s must match what units still on a v0.14.x server answer, so the client keeps updating those, and the block's few numbers the client never uses (F000 and its status, the seed lifetime, the DEFLATE overrun bound) must match them too. A number changed on either side fails the test, and so does a new `udsota.h` wire number the test doesn't map.

## Tests

`python -m pytest client/tests` runs the unit tests, on virtual buses with no CAN interface, and the end-to-end test. Without the `diff` extra the delta tests skip.

The end-to-end test, `tests/test_e2e_lite.py`, drives `udsota_lite_server` over a frame pipe, which can lose or delay any frame. It covers `info`, a secured flash plain and compressed, a wrong master, a download without the key, each first-block refusal with its F1F1 reason, an FF01 failure, corrupt and truncated streams, a confirm that outlasts S3 and a control run without the keepalive in which S3 ends the session, `config set`, a seed asked for while unlocked, and an unconfirmed image that rolls back. Through the pipe's faults it covers a resent block ending the transfer with 0x24, a lost flow control, a lost request frame and a lost ActivateImage answer. It also sends `pack`'s payloads as another flasher would, runs `dtc` against an app that serves no DTCs, and has `--diff-from` fall back to the full image, which needs the `diff` extra. `$UDSOTA_LITE_SERVER` names the server; otherwise it is `build/udsota_lite_server`, which the top-level build makes, and the test skips when that is not built.
