# udsota Linux demo server

`udsota_demo_server` runs the portable core on Linux, so the client can be tested end to end without a board. The real UDS server (`udsota_server.c`) and ISO-TP adapter (`udsota_isotp.c`) serve one request/response pair over SocketCAN or over a frame pipe on stdin and stdout. Behind them is an update engine on two file-backed A/B slots (`components/udsota/test/fake_engine.c`), which runs the ESP32 port's first-block check and the core's `udsota_image_check` rules, and checks a real SHA-256 in FF01. It serves compressed and delta downloads (DFI 0x10, 0x20 and 0x30) through `udsota_coded`, on the vendored tinfl and detools, so `flash --compress` and `flash --diff-from` work against it too.

Rollback is emulated. ActivateImage and 11 01 end in the reset hook, and the process then "reboots" without exiting. The engine runs the boot slot, the bus stays silent for `--boot-ms`, and a fresh server starts. An activated image therefore boots PENDING_VERIFY and stays there until ConfirmImage. If it restarts before that, the old image runs again and F1F0 reports the new one as rolled back. The client's whole `flash` sequence completes against it, from the precheck to ConfirmImage.

By default it matches the client's built-in `example` profile: IDs 0x710 and 0x718, product `example`, hw_id 1, layout 1, board `devkit` on F191, and 1.875 MB slots. A fresh slot 0 is seeded with a valid `v0.1.0` release image. Security is off.

## Build

It is built from the root `CMakeLists.txt` on Linux only:

```sh
cmake -S . -B build && cmake --build build --target udsota_demo_server
```

The binary is `build/tools/linux_server/udsota_demo_server`. ctest checks its host HMAC against `udsota_keys.c`'s known answers, runs one request over the pipe, runs an image from `--make-image` through `tools/image_check`, and checks that `--socketcan` refuses an interface that is not vcan.

## Run it on vcan

```sh
sudo modprobe vcan && sudo modprobe can-isotp
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
build/tools/linux_server/udsota_demo_server --socketcan vcan0 &
build/tools/linux_server/udsota_demo_server --make-image v0.2.0.bin --version v0.2.0
udsota --profile example --interface vcan0 flash v0.2.0.bin
udsota --profile example --interface vcan0 info
```

The server logs its boots and phase changes on stderr, and `-v` logs every frame too. It stops on SIGINT or SIGTERM. Without `--state-dir` it keeps the slots in a temporary directory that it removes at exit. With `--state-dir DIR` the slots persist, so a restart of the process acts as a power cycle, which also rolls back an unconfirmed image. `--fresh` wipes them first.

## The frame pipe

Without `--socketcan`, frames arrive on stdin and leave on stdout, one per line, in can-utils' compact form `<id>#<data>`. The ID is 3 hex digits, or 8 for an extended frame, which is never a request. The data is 0 to 8 bytes as hex pairs, which `.` may separate: `710#0322F186`. Blank lines are skipped, and malformed ones are reported on stderr and dropped. Every frame the server sends is one line with all 8 bytes, padded with 0xAA: `718#0462F18601AAAAAA`. It stops at stdin's EOF.

```sh
printf '710#0322F186\n' | build/tools/linux_server/udsota_demo_server    # prints 718#0462F18601AAAAAA
```

A pipe carries no timing, so each frame's arrival stamp is the time the server read it. `--stmin-monitor` means something only on SocketCAN.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--socketcan IFACE` | the pipe | serve on a SocketCAN interface through a CAN_RAW socket that receives only the request ID. Only a vcan interface is accepted, by its rtnetlink link kind |
| `--allow-real-bus` | off | let `--socketcan` open a real CAN interface. The demo then answers every tester on that bus |
| `--req-id`, `--resp-id` | 0x710, 0x718 | the ID pair (11-bit) |
| `--product`, `--hw-id`, `--layout-id` | example, 1, 1 | the identity the image rules expect (`cfg.product`, `cfg.hw_id`, `cfg.layout_id`) |
| `--board NAME` | devkit | the board name F191 answers, which the example profile's precheck reads |
| `--chip-id N` | 0x0009 | the `esp_image_header_t` chip ID an image must carry (ESP32-S3) |
| `--state-dir DIR`, `--fresh` | a temporary directory | where the slots live, and whether to wipe them first |
| `--slot-size N` | 0x1E0000 | bytes per slot, a multiple of 4,096 |
| `--running-version V` | v0.1.0 | the version of the image seeded into an empty running slot |
| `--no-compress` | off | a build without coded downloads: a 34 with DFI 0x10, 0x20 or 0x30 answers 0x31 |
| `--no-delta` | off | a build without delta downloads: 0x20 and 0x30 answer 0x31, and 0x10 is still served |
| `--no-rollback` | off | a build without rollback: an activated image boots UNDEFINED and ConfirmImage changes nothing |
| `--label LABEL`, `--master FILE` | off | security on: `udsota_keys.c`'s derivation over the host HMAC-SHA256 with this label and the 32-byte master. A label without a master keeps security on and refuses every key, as the ESP32 port does |
| `--device-id HEX` | 02:00:00:00:00:01 | F18C, and the device ID the keys are derived from |
| `--skip-boot-delay` | off | starts each boot's clock at 10 s, so 0x27 answers without the post-boot 0x37 delay; a lockout still delays |
| `--boot-ms N` | 500 | how long a restart stays silent |
| `--job-ms N` | 0 | erase, FF01, ActivateImage, ConfirmImage and a coded download's 36s and 37 run as a worker job this long, so the server answers 0x78 first |
| `--soak-ms N` | 0 | the gate refuses CONFIRM with 0x22 for this long after each boot, like an app's soak |
| `--stmin-us`, `--block-size`, `--stmin-monitor` | 2000, 64, off | the flow control the server sends, and the STmin monitor |
| `--withhold-fc-after N` | off | once: the gate refuses the FC point after a message's Nth CF (so the FC is withheld and the download ends), and the next FF is then ignored, as by a server on an erroring bus. N should be a multiple of the block size |
| `--drop-fc-after N` | off | once: the FC sent after a message's Nth CF is lost, as on the bus, while the server keeps receiving |
| `--make-image OUT --version V [--payload N]` | | writes an image for the configured product, hw_id, layout and IDs (segment 0 of N bytes, default 8,192) and exits |
| `--self-test` | | runs `udsota_keys_self_test` on the host HMAC and exits |

Exit codes: 0 at EOF or on a signal, 1 on a runtime error, such as a missing interface or unreadable slots, and 2 on a bad option.

## Images

The engine checks what an ESP-IDF build would carry, but it does not run a real app. An image is `fake_ota_build_image`'s one-segment ESP32-S3 image. It holds `esp_app_desc_t` at offset 32 and the udsota descriptor at 288, with the release flag set exactly when the version is a clean `[v]X.Y.Z`. Its `app_elf_sha256` is the SHA-256 of the version string, then come the checksum byte and the appended SHA-256 over the image. `--make-image` builds it with the configured product, hw_id, layout and IDs. `client/tests/demo_server.py` builds the same bytes in Python. There is no signature check, so F1F0 flag 0x01 stays clear.

## Tests

`client/tests/test_e2e_pipe.py` starts the demo in pipe mode and drives it with the client itself. The client's `cli.main`, `update` and `Uds` run over can-isotp's pure-Python ISO-TP stack, behind the same guarded bus, pre-flight and second-tester monitor that `transport.Transport` uses. They cover `info`, a full `flash`, a keyed `flash`, each first-block refusal with its F1F1 reason, an FF01 failure, rollback, the confirm soak, 0x78 on slow jobs, `--drop-76`, answers the pipe drops or delays, a withheld flow control (exit 1 with F1F1's reason) and a lost one (resent). For compressed downloads they cover `flash --compress` and the profile's `compression`, `--compress` and `--compress-auto` against the demo's `--no-compress`, a resent block, a request frame lost and answers lost mid-stream, and corrupt, truncated and refused streams. For delta downloads they cover `flash --diff-from` under both DFIs, a wrong base falling back to a full download, a server without delta, and a 37 answering 0x78. `client/tests/test_e2e_vcan.py` runs the demo on vcan0 (or `$UDSOTA_VCAN`) through its SocketCAN backend and flashes it two ways. The client over can-isotp's Python stack on a python-can SocketCAN bus needs only the `vcan` module, so these run on GitHub's hosted runners, whose kernel has no ISO-TP module. The installed `udsota` command over the kernel's ISO-TP socket also needs `can-isotp`, so those run on a Linux machine that has it. Each skips without what it needs. Both skip when the binary is not built, and they find it in `build/` or through `$UDSOTA_DEMO_SERVER`.
