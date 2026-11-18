# udsota client

`udsota` is udsota's command-line client: it reads a unit's identity, update state and fault codes and installs firmware over UDS on ISO-TP. Everything product-specific lives in a TOML profile, so one tool serves every product that embeds udsota, whether the unit is an A/B app on udsota 0.15 or later, a unit still on a 0.14.x server, or a single-slot unit with a bootloader.

It needs Linux with SocketCAN and the kernel's ISO-TP module (`can-isotp`) and Python 3.11 or newer; `pack`, `stamp` and `keygen` open no bus and run anywhere. The wire is in [docs/wire.md](../docs/wire.md), not here.

## Install

```sh
pip install ./client            # the udsota command; pins python-can, can-isotp and udsoncan, and takes cryptography 42 or newer
pip install "./client[diff]"    # also detools, for delta downloads; PyPI has only its source, so this needs a C and C++ compiler
```

## Commands

```
udsota --profile example info                       # identity, update state, the profile's DIDs
udsota --profile example flash build/example.bin    # precheck, download, verify, activate, confirm
udsota --profile example flash --compress build/example.bin              # the same, as raw DEFLATE
udsota --profile example flash --diff-from releases/ build/example.bin   # a patch from the running image, if one fits
udsota --profile example confirm                    # ConfirmImage for an image left unconfirmed
udsota --profile example reset                      # 11 01; an unconfirmed image rolls back
udsota --profile my.toml config show                # the writable DIDs, the config status and hash
udsota --profile my.toml config set timeout_ms=3000 --commit --reset   # write, commit, restart, check
udsota --profile example dtc show [--ext U0073]     # the DTCs with a status bit set, or one DTC's extended data
udsota --profile example dtc clear                  # 14 FF FF FF, unlocked as config set is
udsota --profile example pack build/example.bin --out dist --diff-from releases/v1.bin   # payloads for another flasher
udsota --profile my.toml stamp build/app.bin        # a bare image's header, after its build
udsota keygen --out keys                            # a new ecdsa-mode key pair
```

`--profile` is required by every command but `keygen`: a built-in name (`example`, in `client/udsota/profiles/`) or a path to a `.toml` file. `config`, `dtc clear` and `stamp` refuse `example`, which has no writable `[dids]`, no `[config]` and an ESP-IDF image format; they need a profile of your own (`my.toml`) with those. `--interface` overrides the profile's SocketCAN interface and is required when the profile names none, `--master` and `--private-key` override its key file (modes hmac and ecdsa), and `-v` logs every request and response. `udsota --help` and `udsota COMMAND --help` list every option.

The tool transmits only on the profile's `req_id` (and the `[functional]` ID), never on a `deny_tx` ID. Before its first frame it listens for 2 s and stops if it hears the response ID or the profile's busy value, and during a run it stops if a response arrives that it did not ask for.

### flash

`flash` checks the image against the profile before it opens the bus, and reads the unit before it writes anything. It does nothing when the unit already runs the image, confirms it if an earlier run stopped short of that, and refuses while a different image is still unconfirmed. After ActivateImage it waits for the restart and retries ConfirmImage for up to 120 s, so the app's own post-update checks can pass. No download resumes: a new run starts from the first byte.

`--compress` sends the image as a raw DEFLATE stream (DFI 0x10), which usually takes an update to 50 to 65 % of its time on the bus; the RequestDownload still announces the image's own size. A unit without compressed downloads answers 0x31, and one with no memory for the inflater 0x22 with F1F1 reading `DL_NO_MEMORY`; `--compress` then stops before anything is written (exit 2 for the first, 1 for the second), while `--compress-auto` sends the image uncompressed instead. `[image] compression` in the profile sets the default, which `--compress`, `--compress-auto` and `--no-compress` override.

`--diff-from PATH` offers a patch from the image the unit runs, so a small change costs kilobytes on the bus. `PATH` is one base `.bin`, or a directory of them such as past releases, from which the client takes the one that carries the unit's F1F3. It needs the `diff` extra and a unit built to serve delta downloads. The base must be the very `.bin` that was flashed ([docs/wire.md](../docs/wire.md#delta-downloads)): with no matching file, several different ones, or one without an appended SHA-256, the client says why and sends the full image. It tries each delta smaller than the full download, smallest first, and a 34 answered 0x31, as 0x20 always is and 0x30 is on any unit without delta, or 0x22 for memory, moves on to the next, the full image last. `--diff-format heatshrink` or `--no-compress` leave only the full image on a unit on udsota 0.15 or later. `--drop-76 N` is a fault test that resends block N as if its answer were lost, and does not combine with `--diff-from`. After a delta, `flash` prints its size and time and the image's size; unlike a compressed download's, a delta's time is mostly the device rebuilding and writing the image, so it gives no time saved.

### config and dtc

`config set NAME=VALUE ...` writes the profile's writable DIDs. It checks every value against the profile before it opens the bus, then opens the extended session, unlocks at `level_extended` and stages each value with 0x2E. `--commit` runs the profile's commit routine, which must answer status 00; `--reset` needs `--commit` and sends the keyed `11 01`, waits for the restart as `flash` does, reads back every key it wrote and checks the config hash when the profile has one. Staged values that are never committed are dropped when the session ends. With `[config] groups` the client stages and commits each group in turn and resets once after the last; without `--commit` a call may touch only one group, and a failure after the first group names the groups already committed. Firmware that answers the first 0x2E with NRC 0x11, or the commit with 0x31, has no config writes: exit 2. `config show` reads the keys, the status DID and the hash check without changing session.

`dtc show` reads the unit's fault codes with 0x19 in the default session, with no key: it prints each DTC whose status has a bit set, its status bits named, and its description when the profile's `[dtcs]` has one. `--ext CODE` sends 19 06 instead and prints that DTC's extended data records as hex, which the client doesn't split because their layout is the product's; CODE is written as the codes print (`U0073`, `U0073-1C` or `0xC07300`). `dtc clear` sends `14 FF FF FF` in the extended session, unlocked as `config set` is. Firmware that answers 0x19 or 0x14 with NRC 0x11 has no DTC services, and one that answers 19 06 with 0x12 has no extended data: exit 2.

### pack

`pack FILE --out DIR` writes the payloads `flash` sends, byte for byte, for a flasher that is not this client, such as an edge device that gets its updates from a server; the sequence it follows is [Flashing without the client](../docs/wire.md#flashing-without-the-client). It needs no bus. It checks FILE against the profile, then writes one payload per mode: 0x10 and 0x00 by default, plus 0x20 and 0x30 from the one base `--diff-from` names (a file, since there is no unit to choose by); `--dfi`, repeatable, writes only the modes named. Of the delta payloads, only 0x30's can be taken by a unit on udsota 0.15 or later. Each payload is `<stem>.dfiXX.bin`, and `<stem>.manifest.json` lists them in the order `flash --compress-auto` tries them: the deltas smaller than the 0x10 payload, smallest first, then 0x10, then any delta no smaller than it (with `smaller_than_dfi_10` false), then 0x00. `pack` never overwrites, so give each image and base its own `--out`. The manifest records the client's `udsota_version` and the `profile`, and each entry has:

| Field | For |
|---|---|
| `dfi`, `memory_size` | the 34: the mode, and the new image's size, which every mode announces |
| `file`, `payload_size`, `payload_sha256` | the payload file, and a check that it arrived whole |
| `req_id`, `resp_id`, `board_did`, `board`, `image_elf_sha256`, `image_version`, `hw_id` | the IDs to talk on, the precheck, and F1F3 after the restart |
| `base_elf_sha256`, `base_validation_sha256` (deltas) | send a delta only when F1F3 reads the first; the second is the hash its header names, which the unit checks (`DL_BAD_BASE`) |

The 0x27 key is not in the manifest: in the ECDSA mode the flasher asks the product's signing service to sign each seed.

### stamp and keygen

`stamp FILE` fills in a bare image's header after its build, in place or to `--out`: it pads the file, writes the length, image ID and CRC, checks the result against the profile as `flash` would, and leaves the file as it was if anything fails. A post-build script can call `udsota.image.stamp(data, header_offset)` instead, which needs no profile. `stamp` is refused by a profile whose `[image] format` is `"esp-idf"`.

`keygen --out DIR` writes a new P-256 key pair for the ecdsa mode: `udsota_private.pem` (unencrypted PKCS#8, mode 0600) and `udsota_pubkey.h`, the public point as a C array for `cfg.key_pubkey`. It never overwrites either file. The header is public and belongs in the app's source; the private key unlocks every unit built with that header, so move it into a signing service or HSM and never commit it or build it into an image. The client signs with a PEM file for the bench or a signing host, and does not read encrypted PEMs.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | the unit refused or failed a step, or the interface is missing or down |
| 2 | refused with nothing erased: a bad profile, image, key file, `config set` value or `dtc show --ext` code; a precheck stop (an image for another board, a running image still unconfirmed, a unit that does not serve F1F0); firmware without config writes or DTC services; `flash --compress` on a unit without compressed downloads; `--diff-from` without detools; an option the profile's flow refuses; a bus command off Linux |
| 3 | another tester holds a session (the profile's `[busy]`) |
| 4 | a second tester is on the bus |

## Profiles

Start from [`example.toml`](udsota/profiles/example.toml), which comments every key. Every table but `[can]` is optional, and an absent table turns its feature off. A profile error exits 2 before anything is sent. Defaults are in parentheses.

| Table | Keys | Meaning |
|---|---|---|
| `[can]` | `interface`, `req_id`, `resp_id`, `deny_tx` | the SocketCAN interface, the 11-bit ID pair, and IDs the tool must never send on |
| `[security]` | `mode` (`"hmac"`), `label`, `master_file`, `private_key_file`, `device_id_did` (0xF18C), `level_extended` (0x01), `level_programming` (0x03) | the 0x27 keys and the requestSeed levels (odd, 0x01 to 0x7D); without it the tool never unlocks. Mode `hmac` derives each key from `master_file` (32 raw bytes) and `label`; mode `ecdsa` signs each seed with `private_key_file` (a P-256 PEM) and takes neither. The mode must match the unit's ([Keys](../docs/wire.md#keys)). Refused with `flow = "bootloader"` |
| `[image]` | `product`, `hw_ids`, `layout_id`, `slot_size` (0x400000), `compression` (`"none"`), `format` (`"esp-idf"`), `header_offset` | the identity `flash` checks before sending; `"deflate"` as `--compress`, `"auto"` as `--compress-auto`, `"none"` as `--no-compress`; `format = "bare"` takes images that are not ESP-IDF apps and requires `header_offset`, which the default format refuses |
| `[board]` | `did`, `names` | a DID naming the unit's board, and the board name for each `hw_id`, so `flash` refuses an image for another board |
| `[update]` | `flow` (`"app"`), `start_timeout_s` (60) | `"bootloader"` selects the single-slot flow; `start_timeout_s` (1 to 600) is the flow's wait for the new app and is refused with `"app"` |
| `[busy]` | `id`, `byte`, `values` | a frame whose byte at `byte` holds one of `values` means another tester has a session |
| `[preroll]` | `tester_present_frames` | TesterPresent frames (0 to 64) sent first on a quiet bus, for a unit whose CAN driver waits to hear traffic |
| `[functional]` | `id`, `quiet_bus` (false) | the functional ID, the only ID besides `req_id` the tool may send on. With `quiet_bus`, `flash` first sends 10 83, 85 82 and 28 83 03 to every node, holds them there with 3E 80 every 2 s, and afterwards releases them, whether or not the update succeeded. Only on a bus where every node may stop its normal messages, never on a vehicle in use |
| `[dids]` | `"0xNNNN"` or `"0xNNNN-0xNNNN"` = `{ name, decode, type, writable, min, max, len }` | extra DIDs `info` reads after the unit's own, decoded as `hex`, `ascii`, `version3`, `u8` or `u16`; a range stops at its first absent DID. `writable = true` makes one DID a key for `config set`, with a `type` (`u8`, `u16` or `blob`), a `name` of letters, digits and `_`, and for u8 and u16 a range `min`..`max` (the whole type). A blob's `len` is the exact length a write must have, 1 to 4092 bytes |
| `[config]` | `commit_rid`, `status_did`, `hash = { did, first, last, schema }`, `groups = [{ name, first, last }]` | the routine `config set --commit` runs; a DID shown as hex by `config show`; and the hash check: SHA-256 of `schema`, then each DID from `first` to `last` the unit answers as DID (big-endian), length and value, compared with DID `did`, which with `status_did` must lie outside `first`..`last`. `groups` splits the writable keys into disjoint DID ranges that `config set` commits one at a time, in file order |
| `[dtcs]` | `"U0073"`, `"U0073-1C"` or `"0xC07300"` = `"text"` | the description `dtc show` prints. A code without a failure-type byte covers all of that code's, and a key with the DTC's own byte wins over it |

## The three kinds of unit

**An A/B unit on udsota 0.15 or later** answers inside the app's iso14229 server, which the client handles. Outside the default session it sends `3E 00` before any request or 0x21 retry that comes over 2 s after the last `10` or `3E`, and a `3E` that gets no answer doesn't fail the request after it. It takes iso14229's 2-byte zero seed as already unlocked, and waits up to 2 s for the answer to a signed key. Unlike udsota 0.14's own server, which the client still updates, a lost answer to a `36` or `37` fails the run instead of being recovered, so run `flash` again ([why](../docs/iso14229.md#limits)).

Delta downloads also differ: they come only as DFI 0x30, from a unit built with `UDSOTA_DELTA=1` and `cfg.allow_delta` set. A 36 refused with DL_BAD_BASE (a base other than the image the unit runs) still sends the full image next. A base that was signed again after its build is not refused there: signing leaves the appended SHA-256 unchanged, so the base passes, FF01 fails with reason 8 (VERIFY_FAILED) and the run stops. Keep the signed .bin exactly as flashed ([Known limits](../README.md#known-limits)). When that refusal's answer is lost, the resent block gets 0x70 here, where a 0.14 server answered 0x24, and the client takes it the same way when F1F1 reads DL_BAD_BASE; if S3 has ended the programming session meanwhile, it enters that session and unlocks again first.

**A unit on a 0.14.x server** takes the same commands. The client recovers a lost answer to a `36` or `37` itself, `info` also prints F1F2's ISO-TP counters, and delta downloads also come as DFI 0x20, an Espressif `esp_delta_ota` patch compressed with heatshrink.

**A single-slot unit with a bootloader** is updated with `[update] flow = "bootloader"` ([the wire](../docs/wire.md#bootloader-flow)), and a profile that sets `[image] format = "bare"` takes its images, which carry udsota's 224-byte header at `header_offset` ([the header](../docs/wire.md#image-descriptor)). Bare images need `stamp` after the build. `flash` and `pack` refuse an image whose length, CRC or image ID does not match, then check its descriptor as they check an ESP-IDF image's, with `desc_version` 1 or later. Plain and compressed downloads and `pack` work as for ESP-IDF images, with the image ID as the manifest's `image_elf_sha256`; delta downloads need ESP-IDF's appended SHA-256, so `--diff-from` is refused.

In the bootloader flow, `flash` first reads F1F4 once, and stops with nothing to do if the app already runs the image and reports healthy. Otherwise it sends `10 02`, which resets the app into the bootloader, makes the precheck and the download there, waits 3 s for the restart, then polls F1F4 until the new app reports healthy with the image ID's first 4 bytes, for up to `start_timeout_s` more. It fails if the app runs another image, if the bootloader answers instead because the app did not start, or if nothing answers in time. For a unit whose app runs but cannot hand over, `flash --wait-for-unit SECONDS` (1 to 600) catches the bootloader's power-up window: when the first `10 02` goes unanswered it says to power-cycle the unit and keeps sending `10 02` until one is answered, for up to SECONDS after that prompt ([the mechanics](../docs/wire.md#bootloader-flow)). The precheck includes F1F5, the project of the installed app: an image of another project is refused, naming both, with the unit left in its bootloader, unless `flash --allow-product-change` is given; a unit with nothing installed, or a bootloader that does not serve F1F5, is flashed as before. `info` prints the installed project, and enters the bootloader to do it, which stops the app until its session times out. There is no ConfirmImage, so `confirm` is refused, and the app serves no UDS, so `config` and `dtc` are refused; so is a profile with `[security]`, since the boot core serves no 0x27, and a compressed download (`--compress`, `--compress-auto` or `[image] compression`), since it takes only DFI 0x00. `reset` sends `10 02` and `11 01`.

## Tests

`python -m pytest client/tests` runs everything the machine allows, and a case whose server, vcan, kernel ISO-TP module or delta build is missing is skipped (`-rs` lists them). Install the `diff` extra first when running from the repository root: there the vendored `detools/` directory shadows the missing package, so the delta cases fail instead of skipping. Run from `client/`, they skip.

`test_udsota.py` holds the unit tests, on virtual buses with no CAN interface, and checks the client's wire numbers (`udsota/wire.py`, `keys.py`, `image.py` and the profile's default levels) against `udsota_wire.h` and against v0.14.2's wire headers, frozen in `test/fixtures/wire-v0.14/`: a number changed on either side, or a new `udsota_wire.h` number the test doesn't map, fails it. `test_e2e_lite.py` drives `udsota_lite_server` over a frame pipe that can lose or delay any frame, `test_e2e_lite_vcan.py` the same server on a vcan, and `test_e2e_boot.py` drives `udsota_boot_server` over a pipe. The top-level build makes both servers in `build/`, with delta downloads unless it has `-DUDSOTA_DELTA=OFF`, which skips the delta cases. `$UDSOTA_LITE_SERVER`, `$UDSOTA_BOOT_SERVER` and `$UDSOTA_VCAN` (a vcan interface) name others, and when one is set, as CI sets them, a missing server, vcan or delta build fails instead of skipping.
