# CANDash ws43 example

udsota-lite and iso14229 in one ESP-IDF app for the CANDash ws43 (Waveshare ESP32-S3-Touch-LCD-4.3). It carries CANDash's image identity (project `candash`, hw_id 1, layout 1, CAN IDs 0x7E6/0x7EE), so CANDash's own updater installs it and it installs CANDash back. The [top-level README](../../README.md) explains how the pieces fit.

`components/udsota` is a link to the repository root, which is the component. Besides the integration, `main/main.c` sets up the board's CAN: TWAI on GPIO20/19 at 250 kbit/s, with the CH422G expander's EXIO5 set to select CAN, because the transceiver shares those pins with USB.

## Build and run

Link or copy CANDash's git-ignored `secrets/` here: the signing key, and the 0x27 master (without it, 0x27 is off). Then, with the [client](../../client/README.md) installed:

```sh
idf.py -B build build                                   # version 0.5.0-lite.1
idf.py -B build-2 -DPOC_VER=0.5.0-lite.2 build          # a second image to update to
udsota --profile <CANDash>/tools/udsota-candash.toml flash --compress build/candash.bin
```

The version keeps CANDash's `0.5.0` core, because a device takes a dev build only when its `X.Y.Z` is at least the running one's. For ECDSA 0x27 instead of CANDash's HMAC master, add `-DPOC_PUBKEY_DIR=<dir>` with the `udsota_pubkey.h` that `udsota keygen` writes, and give the client a profile whose `[security]` has `mode = "ecdsa"` and the private key.

## Bench results (2026-09-30)

Nothing after fa70d8d has run on hardware: not the relock on every `10 01/02/03` (8051f15), `allow_downgrade` (9b9b3e6), the image descriptor kept in every build (a362e5c), the server's P2* in the `10` answer and `udsota_end_session` (632078e), `udsota_poll` and `-fwrapv` on iso14229.c (727b5c3), nor main's client (d2a2262 on).

Over PCAN at 250 kbit/s, with the branch's own client of the day and CANDash's profile (HMAC 0x27, signed images, rollback on), on 14a1785:

| Update | Server that took it | Result |
|---|---|---|
| CANDash v0.4.1-21 → lite.1, DEFLATE | udsota's own, in CANDash | 198 KB in 61.4 s; lite answered F1F0 and F002 confirmed it |
| lite.1 → lite.2, plain (DFI 00) | lite on iso14229 | 332 KB, activated, restarted, confirmed |
| lite.2 → lite.1, DEFLATE | lite | 198 KB in 23.6 s, confirmed |
| `info`, and a keyed `reset` (10 03, 27 01/02, 11 01) | lite | Served; the device restarted |
| lite.1 → CANDash v0.4.1-21 (rebuilt), DEFLATE | lite | 1.25 MB as 692 KB in 83.2 s. CANDash confirmed, and its config hash was unchanged |

Then on fa70d8d, with an image built for ECDSA 0x27 and CANDash v0.5.0 on the bench:

| Test | Result |
|---|---|
| CANDash v0.5.0 → lite.3 (ECDSA key), DEFLATE | Installed by CANDash's updater, confirmed |
| lite.3 → lite.4, unlocked with a signed seed | Installed, confirmed. The sendKey answer took 442 ms: the ESP32-S3 checks P-256 in software |
| A key signed by another private key | 7F 27 35; nothing changed |
| lite.4 → lite.3 left unconfirmed, then a keyed reset (ECDSA) | lite.3 ran PENDING_VERIFY; the reset rolled back to lite.4, and F1F0 reported the other slot INVALID |
| lite.4 → CANDash v0.5.0 (rebuilt), DEFLATE, ECDSA unlock | Installed, confirmed, config hash unchanged |
