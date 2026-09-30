# udsota on iso14229: proof of concept

This branch reduces udsota to its firmware updater and runs it on [iso14229](https://github.com/driftregion/iso14229)'s UDS server in place of udsota's own. This example is a CANDash ws43 image: CANDash's own updater installs it over CAN, and it installs CANDash back. An iso14229 user adopts the updater by calling `udsota_iso14229_event()` first from the event callback they already have.

## What ran on the bench (2026-09-30)

On a CANDash ws43 over PCAN at 250 kbit/s, with the unmodified udsota 0.10 client and CANDash's profile (HMAC 0x27, signed images, rollback on):

| Step | Server | Result |
|---|---|---|
| CANDash v0.4.1-16 → PoC .1, DEFLATE | udsota's own (CANDash) | installed; the PoC's iso14229 server answered F1F3 and F1F0 and confirmed with F002 |
| PoC .1 → PoC .2, DEFLATE | iso14229 | 207 KB in 23.4 s, activated, restarted, confirmed |
| `info`, keyed `reset` (10 03, 27 01/02, 11 01) | iso14229 | served; restarted |
| PoC .2 → PoC .1, plain (DFI 00) | iso14229 | activated, confirmed |
| PoC .1 → CANDash v0.4.1-16, DEFLATE | iso14229 | 689 KB in 77.6 s; CANDash confirmed, its config hash unchanged |

Delta downloads (DFI 0x20/0x30) were not run: the client's `--diff-from` needs `detools`, which the bench host lacks.

## How it fits together

`components/iso14229` is the upstream amalgamation as a submodule. `components/udsota_iso14229` maps iso14229's events onto the updater (`udsota_update.h`, which no longer knows any server) and adds what iso14229 leaves to the app: relock and abort on every session change, the 10 02 slot rule, the 0x27 key check, and S3 restarted by every request. `components/udsota_esp32` keeps the engine, security and boot-loop counter, and `udsota_esp32_updater_start()` hands them to the binding. `main/main.c` owns the TWAI node, the server task and the callback, as any iso14229 app does.

## What a tester sees that differs from udsota's own server

Every 36 answers 7F 36 78 before 76, since a queued flash write is iso14229's pending case. A resent 36 whose 76 was lost gets 0x24 and the transfer ends, where udsota answered 76 again, and any NRC to a 36 or 37 ends the transfer. The 0x27 boot delay is 1 s and each wrong key costs 1 s, in place of 10 s and a lockout after three. F1F2's counters, the STmin monitor, functional addressing and the app hooks (19, 14, 28, 85, 2E, app routines) are gone; an app serves those in its own callback. The binding papers over three iso14229 gaps: its S3 restarts only on 10 and 3E, its 10 xx answer carries its client's P2 defaults, and it keeps the security level across a session change.

## Build and run

Link or copy CANDash's git-ignored `secrets/` here (the signing key and the 0x27 master), then:

```sh
git submodule update --init
idf.py -B build build                                    # PoC 0.4.1-iso14229.1
idf.py -B build-v2 -DPOC_VER=0.4.1-iso14229.2 build      # a second image to update to
python -m udsota --profile <CANDash>/tools/udsota-candash.toml flash build/candash.bin
```
