# CANDash ws43 example

udsota and iso14229 in one ESP-IDF app for the CANDash ws43 (Waveshare ESP32-S3-Touch-LCD-4.3) or ws43b (the 4.3B). It carries CANDash's image identity (project `candash`, hw_id 1 or 2, layout 1, CAN IDs 0x7E6/0x7EE), so CANDash's own updater installs it and it installs CANDash back. The [top-level README](../../README.md) explains how the pieces fit.

`components/udsota` is a link to the repository root, which is the component. Besides the integration, `main/main.c` sets up the board's CAN: TWAI at 250 kbit/s, on the ws43 on GPIO20/19 with the CH422G expander's EXIO5 set to select CAN (the transceiver shares those pins with USB), on the ws43b on GPIO15/16.

## Build and run

Link or copy CANDash's git-ignored `secrets/` here: the signing key, and the 0x27 master (without it, 0x27 is off). Then, with the [client](../../client/README.md) installed:

```sh
idf.py -B build build                                   # version 0.5.0-lite.1
idf.py -B build-2 -DPOC_VER=0.5.0-lite.2 build          # a second image to update to
udsota --profile <CANDash>/tools/udsota-candash.toml flash --compress build/candash.bin
```

For `-O2`, as CANDash ships, add `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.o2"` and give the build its own `-DSDKCONFIG=<build dir>/sdkconfig`, since the project's sdkconfig keeps `-Og`. For the ws43b, add `-DPOC_BOARD=ws43b`; its sdkconfig stays in its build directory, because its console is native USB. Don't power a ws43b with its DI0/DI1 inputs wired: the example drives them high as CANDash does, and CANDash warns that this may damage the CH422G or the optocoupler.

The version keeps CANDash's `0.5.0` core, because a device takes a dev build only when its `X.Y.Z` is at least the running one's. For ECDSA 0x27 instead of CANDash's HMAC master, add `-DPOC_PUBKEY_DIR=<dir>` with the `udsota_pubkey.h` that `udsota keygen` writes, and give the client a profile whose `[security]` has `mode = "ecdsa"` and the private key. `-DPOC_ALLOW_DOWNGRADE=1` sets `cfg.allow_downgrade`, so the image also takes an older one. `-DPOC_DELTA=1` defines `UDSOTA_DELTA=1` build-wide and sets `cfg.allow_delta`.

## Results

On a ws43b over CAN at 250 kbit/s, a 15 KB delta took CANDash's next dev build over in 18.4 s, where its full image takes about 9 minutes at CANDash's STmin of 5 ms, and DEFLATE sent a 200 KB image in about 21 s. Every row, with the commit, build and client of each run, is in [BENCH.md](BENCH.md).
