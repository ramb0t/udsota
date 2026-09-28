# udsota ESP32 example

A minimal ESP-IDF v6.1 app that serves udsota updates over the on-chip TWAI controller. It shows the whole integration in one file, `main/main.c`, and proves that the port builds on its own.

It answers on request ID 0x710 and response ID 0x718 at 500 kbit/s, and accepts images whose project name is `example`, with hw_id 1 and layout 1. It matches the client's `example.toml` profile, whose flash precheck reads the board name `devkit` from DID F191; that is the one hook the app registers. The TX and RX GPIOs (default 4 and 5) and the bit rate are set in `menuconfig` under "udsota example". Security is off, there is no gate, and rollback is on, so the client's ConfirmImage keeps a new image. The comments in `main.c` say where a real app adds its gate, its settings, a 0x27 key (an ECDSA public key, or an HMAC master) and signed updates; the port's [README](../../components/udsota_esp32/README.md) and the core's [README](../../components/udsota/README.md) cover each in full.

## Build

```sh
idf.py -C examples/esp32 set-target esp32s3 build
```

Plain `esp32` builds too. To take compressed downloads (`udsota flash --compress`), build with `sdkconfig.compression` added to the defaults:

```sh
idf.py -C examples/esp32 -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.compression" set-target esp32s3 build
```

`PROJECT_VER` is pinned to `0.1.0-dev` in `CMakeLists.txt`, which makes the image a dev build. Set a clean `X.Y.Z` to build a release, which the unit accepts only when its version is newer than the running one.

`partitions.csv` gives two 1.875 MB OTA slots and otadata on 4 MB flash. There is no factory app, so a serial flash boots `ota_0`. If you move a partition, bump `EXAMPLE_LAYOUT_ID` in `main.c`.
