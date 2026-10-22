# udsota ESP32 example

A minimal ESP-IDF v6.1 app that serves udsota updates over the on-chip TWAI controller, on any ESP32 that has one. It shows the whole integration in one file, `main/main.c`, and its build is the app image each release carries.

It answers on request ID 0x710 and response ID 0x718 at 500 kbit/s, and accepts images whose project name is `example`, with hw_id 1 and layout 1. That matches the client's `example.toml` profile, whose flash precheck reads the board name `devkit` from DID F191, the one DID the app serves itself. The TX and RX GPIOs (default 4 and 5) and the bit rate are set in `menuconfig` under "udsota example". Security is off, there is no gate, images are not signed, and rollback is on, so the client's ConfirmImage keeps a new image. The comments in `main.c` say where a real app adds its gate, its own services, a 0x27 key (an ECDSA public key, or an HMAC master) and signed updates; `udsota.h` and the [top-level README](../../README.md) cover each.

`components/udsota` is a link to the repository root, which is the component. Like every app on iso14229, this one owns the server: its task feeds request frames to isotp-c, then calls `UDSServerPoll` and `udsota_poll`, and its event callback hands each event to `udsota_event()` first. It sets `s_srv.p2_ms = 5` right after `UDSServerInit`, for the reason under Known limits in the top-level README.

## Build

```sh
idf.py -C examples/esp32 set-target esp32s3 build
```

Plain `esp32` builds the same way; `sdkconfig.defaults` names no target. The image is `examples/esp32/build/example.bin`, and `udsota --profile example flash examples/esp32/build/example.bin` sends it (add `--compress` to send it as raw DEFLATE).

`PROJECT_VER` is pinned to `0.1.0-dev` in `CMakeLists.txt`, which makes the image a dev build. Set a clean `X.Y.Z` to build a release, which the unit accepts only when its version is newer than the running one.

`partitions.csv` gives two 1.875 MB OTA slots and otadata on 4 MB flash, the profile's `slot_size`. There is no factory app, so a serial flash boots `ota_0`. If you move a partition, bump `EXAMPLE_LAYOUT_ID` in `main.c`.
