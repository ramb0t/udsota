# CANDash ws43 example

This is udsota's updater and iso14229's server in one ESP-IDF project, for the CANDash ws43 (Waveshare ESP32-S3-Touch-LCD-4.3). It uses CANDash's image identity: project `candash`, hw_id 1, layout 1, CAN IDs 0x7E6/0x7EE. So CANDash's own updater installs it, and it installs CANDash back. The [top-level README](../../README.md) explains how the pieces fit.

Besides the integration, `main/main.c` sets up the board's CAN. It runs TWAI on GPIO20/19 at 250 kbit/s, and the CAN transceiver shares those pins with USB, so it sets the CH422G expander's EXIO5 to select CAN.

## Bench results (2026-09-30)

These ran over PCAN at 250 kbit/s, using the unchanged udsota 0.10 client and CANDash's profile (HMAC 0x27, signed images, rollback on):

| Update | Server that took it | Result |
|---|---|---|
| CANDash v0.4.1-16 → this example (.1), DEFLATE | udsota's own, in CANDash | Installed. The iso14229 server answered F1F3 and F1F0, and F002 confirmed the image |
| .1 → .2, DEFLATE | iso14229 | 207 KB in 23.4 s, activated, restarted, confirmed |
| `info`, and a keyed `reset` (10 03, 27 01/02, 11 01) | iso14229 | Served; the device restarted |
| .2 → .1, plain (DFI 00) | iso14229 | Activated, confirmed |
| .1 → CANDash v0.4.1-16, DEFLATE | iso14229 | 689 KB in 77.6 s. CANDash confirmed, and its config hash was unchanged |

After a review, the same round trip ran again with the fixed binding (.3 and .4, then a keyed reset, then CANDash restored). Delta downloads were not run, because the client's `--diff-from` needs `detools` and the bench host doesn't have it. The host end-to-end test covers the rest.

## Build and run

Link or copy CANDash's git-ignored `secrets/` here: the signing key and the 0x27 master. Without the master, 0x27 is off. Then:

```sh
git submodule update --init
idf.py -B build build                                    # version 0.4.1-iso14229.1
idf.py -B build-v2 -DPOC_VER=0.4.1-iso14229.2 build      # a second image to update to
python -m udsota --profile <CANDash>/tools/udsota-candash.toml flash build/candash.bin
```

On the bench, CANDash installed the first image over CAN. The version keeps CANDash's `0.4.1` core because a device takes a dev build only when its core is at least the running one's.
