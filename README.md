# udsota

udsota installs firmware over CAN. It is a UDS (ISO 14229) server on ISO-TP that writes a new image into the device's inactive A/B slot, plus a PC client that drives it. With rollback on, the device keeps the new image only once the client confirms it has come up healthy.

It exists so that any product with a CAN bus can take field updates from a standard UDS tester, while the product itself decides when an update is safe. Every hook is optional and defaults to allow: udsota enforces the protocol, and the integrator enforces the policy.

## What's here

| Path | What it is |
|---|---|
| [`components/udsota`](components/udsota/README.md) | The portable C11 core: ISO-TP adapter, UDS server, image rules, key derivation, boot-loop counter. It has no platform headers. Its README is the integration guide and the wire reference. |
| [`components/udsota_esp32`](components/udsota_esp32/README.md) | The ESP-IDF v6.1 port: an update engine on `esp_ota_*` with A/B slots and rollback, PSA keys, and a diag task and flash worker. |
| [`components/isotp`](components/isotp) | Vendored isotp-c v1.9.3 (MIT), plus the shim that gives each link its own block size and STmin. |
| [`examples/esp32`](examples/esp32/README.md) | A minimal app that serves updates over the on-chip TWAI controller, all in one `main.c`. |
| [`client`](client/README.md) | The `udsota` command (Python 3.11+, Linux SocketCAN). Product specifics live in TOML profiles. |
| `test`, `tools` | Host unit tests and the portability probes (the request-parser fuzz harness is in `components/udsota/test`), plus `tools/image_check`, which runs the port's first-block check on a built image. |
| [`tools/linux_server`](tools/linux_server/README.md) | A Linux demo server: the core over SocketCAN or a stdin/stdout frame pipe, with file-backed A/B slots and emulated rollback, for testing the client end to end. |

## Quick start

You need ESP-IDF v6.1 for the port and the example, and Python 3.11+ on Linux with SocketCAN and the kernel's ISO-TP module for the client. To build the example and install it on a board over CAN:

```sh
idf.py -C examples/esp32 set-target esp32s3 build flash      # first install over serial
pip install ./client
udsota --profile example --interface can0 info
udsota --profile example --interface can0 flash examples/esp32/build/example.bin
```

The example has security off and no gate, so any node on the bus can reprogram it. Before a real product ships, add a gate and a key (the ECDSA mode, whose image holds only a public key), as the core README describes. The example builds as a dev image (`0.1.0-dev`), which installs over any image whose version core is the same or lower. A release build must be newer than the running image, and the client skips an image the unit already runs.

To run the host tests (they fetch Unity):

```sh
cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
python -m pytest client/tests
```

## Status

udsota is at 0.1.0. It was developed and bench-tested on an ESP32-S3 inside a CAN-connected product, then extracted here. The limits and future work are listed in the core README under "Known limits". MIT licence; the third-party code is listed in [THIRD_PARTY.md](THIRD_PARTY.md).
