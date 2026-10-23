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

The version keeps CANDash's `0.5.0` core, because a device takes a dev build only when its `X.Y.Z` is at least the running one's. For ECDSA 0x27 instead of CANDash's HMAC master, add `-DPOC_PUBKEY_DIR=<dir>` with the `udsota_pubkey.h` that `udsota keygen` writes, and give the client a profile whose `[security]` has `mode = "ecdsa"` and the private key.

## Bench results (2026-10-19)

Everything since fa70d8d that a bench can show passed on a ws43b, on 5f67e56 with this board option, at `-O2` (a defaults file with CONFIG_COMPILER_OPTIMIZATION_PERF=y added to `-DSDKCONFIG_DEFAULTS`, as CANDash builds; the example's own default is `-Og`), with v0.14.2's client and CANDash's profile over PCAN at 250 kbit/s. The run started and ended on CANDash v0.5.0-39. Its `info` afterwards matched the start except F1F0: CANDash runs from the other slot, and lite.7 fills the one its previous image was in.

| Test | Result |
|---|---|
| CANDash v0.5.0-39 → lite.8, DEFLATE | CANDash's updater, 199 KB in 61.7 s, confirmed. Lite answers 10 with `50 01/02/03 00 96 01 F4`: iso14229's P2 of 150 ms, P2* raised to 5000 ms |
| 0.4.9-lite.1 onto lite.8, plain and DEFLATE | Refused at the first block, `7F 36 31`; F1F1 DL_NOT_NEWER; nothing changed |
| Unlocked, then `10 01`, `10 02` or `10 03` (8051f15) | The level is gone after each: a keyed routine answers `7F 31 33`, and `27` gives a fresh seed. After `10 03`, `11 01` answers `7F 11 33` |
| A wrong key; a `27 01` straight after a reset | `7F 27 35`, then `7F 27 36` until 1.02 s after it; `7F 27 37` until 1 s after UDSServerInit, by the device's clock (the probe script printed FAIL: its first frame got through 0.9 s into the delay) |
| A late 7E (a 3E 00 sent with a 20 ms P2) | The client reads past it |
| One block sent twice (`--drop-76 1`); a download left to S3 | `7F 36 24` and DL_ABORTED; the session back to 01 and DL_ABORTED |
| Multi-frame `22`s across isotp-c's 2^31 µs, from images whose isotp clock starts 90 s short (727b5c3) | Without `-fwrapv`, one transfer broke at the crossing; with it, none of 1178 did |
| lite → lite, DEFLATE, three times | 199 KB in 23.8 s each |
| lite → lite.7 (ECDSA), unlocked before ConfirmImage | The unlock took 0.49 s; confirmed |
| lite.7 → CANDash v0.5.0-39, plain, ECDSA unlock | 1.25 MB in 306 blocks, so the block counter wrapped; 145 s of transfer, 180 s for the whole flash |

Not shown on hardware: `udsota_end_session` (this example never calls it), `udsota_poll`'s 24.86-day case, and `allow_downgrade` set. a362e5c changes nothing in this example's image.

## Bench results (2026-09-30)

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
