# udsota

[![ci](https://github.com/ramb0t/udsota/actions/workflows/ci.yml/badge.svg)](https://github.com/ramb0t/udsota/actions/workflows/ci.yml)

udsota updates firmware over UDS on CAN: any UDS tester can send an image, and the device checks it before it erases anything, verifies it before it boots and, on an A/B unit, rolls it back if it is never confirmed. It is three parts on one [wire contract](docs/wire.md), so a product takes the part its hardware needs and updates every unit with the same client.

| Part | What it is | Status |
|---|---|---|
| The ESP-IDF component: `udsota.c` with `udsota.h`, `udsota_wire.h` and `udsota_image.h`, on the vendored [iso14229](https://github.com/driftregion/iso14229) | Safe A/B updates, served inside the app's own UDS server | Released |
| [`boot/`](boot/README.md), with `udsota_app.h` | A resident bootloader core for a microcontroller with one app slot, which a product completes with a port of a few flash, CAN and reset functions | Experimental, outside the 1.0 promise until a product has run on it |
| [`client/`](client/README.md) | `udsota`, the command for Linux with SocketCAN | Released; it also updates units still on a 0.14.x server |

## Start

**Without hardware**, build and run the tests; the second line runs the client against udsota as a Linux process:

```sh
cmake -S . -B build && cmake --build build -j && ctest --test-dir build   # the host tests and the fuzzer; also builds both servers
pip install "./client[diff]" pytest && python -m pytest client/tests      # the client's tests, and the end-to-end tests
```

**An ESP32 app.** `examples/esp32` is the smallest complete app ([its page](examples/esp32/README.md)); `examples/candash_ws43` is a product's ([its page](examples/candash_ws43/README.md)). Your own app makes two calls into the iso14229 server it already owns:

```c
#include "udsota.h"

UDSOTA_IMAGE_DESC(1, 1, 0x7E6, 0x7EE);           // hw_id, partition layout, request ID, response ID

void app_main(void)
{
    udsota_init(&(udsota_cfg_t){ .key_pubkey = pubkey, .key_pubkey_len = sizeof pubkey });
    // ... start iso14229 as before: UDSServerInit, the transport, and the task that calls UDSServerPoll,
    //     with udsota_poll(&srv) after each UDSServerPoll
}

static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg)   // iso14229's fn
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        return rc;                                // an update's event: udsota answered it
    }
    // ... your own services: DTCs, config writes, DIDs, routines
}
```

Link or copy this directory into your project's `components/` as `udsota` and add `udsota` to `main`'s requirements. Call `udsota_poll(srv)` after every `UDSServerPoll`, on the server's task: it is mandatory, because without it iso14229's timers wrap after 24.86 days. Set `s_srv.p2_ms = 5` right after `UDSServerInit`, as both examples do: at iso14229's 50 ms default, its gap between answers can push a multi-frame answer past the client's P2. Place `UDSOTA_IMAGE_DESC` once, since it is this image's identity and every image you send must carry a matching one. Set `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` and give the partition table two OTA slots. Pick the 0x27 keys: with `key_pubkey` the tester signs each seed and the device holds only the public key (`udsota keygen` makes the pair), with `key_label` and `key_master` each device's key derives from a master that every image carries, and with neither 0x27 is the app's and any node on the bus can update the unit. Turn on ESP-IDF's app signing too, so the verify step refuses an image you did not sign. [MIGRATING.md](MIGRATING.md) takes an app on udsota 0.14's own server to this API.

A version is `PROJECT_VER`. A clean `X.Y.Z` is a release, which a device takes only when it is newer than the one it runs; anything with a suffix is a dev build, taken when its `X.Y.Z` is at least the running one's. `cfg.allow_downgrade` lifts this rule alone, for a dev unit; leave it off in a release build.

udsota answers only an update's requests (`10 01/02/03`, `11 01`, `27`, DIDs F186, F189, F18C, F1F0, F1F1 and F1F3, routines FF01 and F000–F002, a `34` to address 0 and its `36`s and `37`) and passes every other service back to the app. An accepted `10 01/02/03` relocks every level and ends any transfer, the app's included, because iso14229 on its own keeps both across a `10`. A `10` to one of the app's own sessions is the app's, and so is any relock it needs. `udsota.h` documents the hooks an app most often needs: `udsota_busy()`, the `gate` callback that refuses an update's steps, for example while the vehicle moves, and `udsota_end_session()`.

An update runs `10 02`, `27 03/04`, `34`, `36`…, `37`, `31 01 FF01` (verify) and `31 01 F001` (activate; the device restarts), then `10 03` and `31 01 F002` (confirm); `udsota flash` does all of it. The first block is held until its product, board, partition layout, CAN IDs, version and chip match this device, and only then does the slot start to fill. Blocks carry the image as it is (DFI 00) or as raw DEFLATE (DFI 10), and a build that defines `UDSOTA_DELTA=1` with `cfg.allow_delta` set also takes a patch from the running image (DFI 30). [docs/wire.md](docs/wire.md) has every byte, and the sequence for a flasher other than the client; [docs/iso14229.md](docs/iso14229.md) shows how udsota sits in the server.

**A single-slot microcontroller.** Its resident bootloader is its UDS server, which [`boot/README.md`](boot/README.md) shows how to build; the client drives it with `[update] flow = "bootloader"`.

**The client.** `pip install ./client`, then `udsota --profile my.toml info` and `udsota --profile my.toml flash --compress app.bin`. The [client page](client/README.md) has the commands and the profile.

## Known limits

No download resumes: one that is cut off starts again from its `34`, and a lost positive answer to a `36` or `37` fails the run, so run `flash` again. A delta download needs the base to be the very `.bin` that was flashed, so keep the signed `.bin` exactly as flashed ([why](docs/wire.md#delta-downloads)). Delta has run on a ws43b with CANDash and the example ([bench results](examples/candash_ws43/BENCH.md#bench-results-2026-10-26)); no run has used flash encryption, which CANDash can't build with, and with it each base read goes through a temporary map of the running slot, correct by ESP-IDF's source but slower. The bootloader core is experimental.

A unit that boots its factory app takes no download until an OTA slot boots, and says so in its log. A `27` seed comes from the hardware RNG as it stands: true random while Wi-Fi or Bluetooth runs, or after the app calls `bootloader_random_enable()` (which an app using the ADC, or I2S on an ESP32, must not), and otherwise mixed only from the chip's secondary entropy source, which an ESP32 lacks.

The rest come from using iso14229 as it is, each a candidate for an upstream fix, and [docs/iso14229.md](docs/iso14229.md) has them in full. Build `iso14229.c` with `-fwrapv`, which the component does and an app with its own copy of iso14229 must too, or a transfer fails every 71.6 minutes of uptime. A tester keeps a session with `3E`, which the client does. While any job answers 0x78, iso14229 reads no other request, and only the last one sent meanwhile is answered.

## Where everything is

| Path | What it is |
|---|---|
| `udsota.c`, `udsota.h`, `udsota_wire.h`, `udsota_image.h` | The updater and its ESP-IDF platform. `udsota.h`, which includes the other two, ends with the platform functions a port to another MCU would supply; `udsota_wire.h` is the wire contract with no `#include`, for a bootloader or tester to take alone, and `udsota_image.h` the image descriptor and the bare header as C types |
| `udsota_app.h` | The app's side of a [`boot/`](boot/README.md) bootloader, header-only: the handover, the F1F4 answer and the healthy mark |
| [`boot/`](boot/README.md) | The bootloader core and its porting guide |
| `iso14229/`, `detools/` | The vendored libraries, unmodified, each with its licence and a `SHA256SUMS` that CI checks; their versions are in [THIRD_PARTY.md](THIRD_PARTY.md). detools compiles only in a build that defines `UDSOTA_DELTA=1` |
| `CMakeLists.txt` | The ESP-IDF component, or on a host the tests, whose comments say what each target covers |
| [`examples/esp32`](examples/esp32/README.md) | The smallest app, for any ESP32 with TWAI; its image is the one a release carries |
| [`examples/candash_ws43`](examples/candash_ws43/README.md) | An app on the CANDash ws43 or ws43b (ESP32-S3) with CANDash's identity, so updates go both ways |
| `test/` | The host tests, among them `test_isotp_wrap.c`, isotp-c's timers across its 2³¹ µs point, built at -O2, which fails without the component's `-fwrapv` on `iso14229.c`; the fuzzer, the bootloader core's tests, and the two servers the client's end-to-end tests drive: `udsota_lite_server` (udsota and iso14229 as a Linux process) and `udsota_boot_server` (the bootloader core and a stand-in app) |
| `tools/` | `release.py` ([RELEASING.md](RELEASING.md)), `image_check.c` (udsota's image rules run on a built image, which CI runs on every example image), the fixture writers and the Cortex-M3 size gate |
| [`client/`](client/README.md) | The `udsota` command and its tests |
| [`docs/`](docs/wire.md) | `wire.md`, the wire contract: services, DIDs, routines, NRCs, reasons, timing, the descriptor, the 0x27 keys and flashing without the client; `iso14229.md`, udsota inside the server |

## Build and test

The commands under Start build and test everything on a host. `udsota_lite_server` is built with delta downloads, which `-DUDSOTA_DELTA=OFF` leaves out, and the client's end-to-end tests skip a case whose server, vcan or kernel ISO-TP module is missing (`pytest -rs` says which). [`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the full list: it adds clang, the end-to-end tests on a vcan, the ESP-IDF builds of both examples with every warning an error, and the Cortex-M3 size gate on the bootloader core (`cmake --build build --target udsota_boot_arm_size`, with arm-none-eabi-gcc installed).

What changed in each release is in the [changelog](CHANGELOG.md), and [MIGRATING.md](MIGRATING.md) says what a product must do to move between them. MIT licence.
