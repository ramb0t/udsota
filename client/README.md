# udsota client

`udsota` is the PC client for a [udsota](../components/udsota/README.md) server. It reads a device's identity and update state and installs firmware over UDS on ISO-TP. Everything product-specific lives in a TOML profile, so one tool serves every product that embeds udsota.

It runs on Linux with SocketCAN and the kernel's ISO-TP module, on Python 3.11 or newer. `pip install ./client` installs the `udsota` command, pins python-can, can-isotp and udsoncan, and installs cryptography 42 or newer for the ecdsa mode. The unit tests run on virtual buses and open no CAN interface: `python -m pytest client/tests`. The end-to-end tests drive the [Linux demo server](../tools/linux_server/README.md) once it is built: over a frame pipe, and over vcan0 with the kernel's ISO-TP module when both are there. Otherwise they skip.

## Commands

```
udsota --profile example info                    # identity, update state, the profile's DIDs
udsota --profile example flash build/example.bin # precheck, download, verify, activate, confirm
udsota --profile example flash --compress build/example.bin   # the same, sending the image as raw DEFLATE
udsota --profile example flash --diff-from releases/ build/example.bin   # a patch from the running image, if one fits
udsota --profile example confirm                 # ConfirmImage for an image left unconfirmed
udsota --profile example reset                   # 11 01; an unconfirmed image rolls back
udsota --profile example config show             # the writable DIDs, the config status and hash
udsota --profile example config set timeout_ms=3000 --commit --reset   # write, commit, restart, check
udsota keygen --out keys                         # a new ecdsa-mode key pair; no profile, no bus
```

`--profile` is required by every command but `keygen`. It takes a built-in name (profiles ship in `client/udsota/profiles/`) or a path to a `.toml` file. `--interface` overrides the profile's SocketCAN interface and is required when the profile names none. `--master` overrides its master-key file (mode hmac), `--private-key` its private-key file (mode ecdsa), and `-v` logs every request and response.

`keygen --out DIR` writes a new P-256 key pair for the ecdsa mode: `udsota_private.pem` (unencrypted PKCS#8, mode 0600) and `udsota_pubkey.h`, the 65-byte public point as a C array for `cfg.key_pubkey`. It never overwrites either file. The header is public and belongs in the app's source. The private key unlocks every device built with that header, so move it into an HSM or a signing service, and never commit it or build it into an image; the repository's `.gitignore` already ignores `*.pem` and `keys/`. The client signs with a PEM file, for the bench or a signing host; it does not read encrypted PEMs.

`flash` checks the image against the profile before it opens the bus, and reads the device before it writes anything. It does nothing when the device already runs the image, confirms it if an earlier run stopped short of that, and refuses while a different image is still unconfirmed. After ActivateImage it waits for the restart and retries ConfirmImage for up to 120 s, so the application's own post-update checks can pass.

`config set NAME=VALUE ...` writes the profile's writable DIDs (the example's are commented out). It checks every value against the profile before it opens the bus. Then it opens the extended session, unlocks at `level_extended`, and stages each value with WriteDataByIdentifier (0x2E). `--commit` runs the profile's commit routine, which must answer status 00. `--reset` needs `--commit`. It sends the keyed 11 01, waits for the restart as `flash` does, reads back every key it wrote, and checks the device's config hash when the profile has one. Staged values that are never committed are dropped when the session ends. Firmware that answers 0x2E with NRC 0x11, or the commit routine with 0x31, has no config writes, and the tool stops with exit code 2. `config show` reads the keys, the status DID and the hash check without changing session, and stops the same way when the device serves none of the keys.

`flash --compress` sends the image as a raw DEFLATE stream (Python's `zlib`, level 9, no header), which usually takes an update to 50–65 % of its time on the bus. The RequestDownload still announces the image's own size, and the device writes the same bytes. Once the device takes the compressed download, the tool prints the ratio, and after it the time saved. A device answers 0x31 when it has no compressed downloads, or when the image is larger than its slot, and 0x22 with F1F1 reading `DL_NO_MEMORY` when it has no memory for the inflater now. `--compress` then stops before anything is written: exit code 2 for the first, 1 for the second, whose message says a plain flash may work. `--compress-auto` sends the image uncompressed in both cases instead. `[image] compression` in the profile sets the default, `"deflate"`, `"auto"` or `"none"`, which `--compress`, `--compress-auto` and `--no-compress` override. No download resumes, compressed or not: a new run starts from the first byte.

`flash --diff-from PATH` sends only a patch from the image the device runs, so a small code change costs kilobytes on the bus instead of the whole image. It needs a device that serves delta downloads (the ESP32 port with `UDSOTA_ESP32_DELTA`) and detools, the optional extra `diff` (`pip install "./client[diff]"` from the repository, quoted for the shell); PyPI has only detools' source distribution, so installing it needs a C and C++ compiler. `PATH` is one base `.bin` or a directory of them, such as past release images, and the tool uses the one file carrying the device's running app_elf_sha256 (F1F3). The base must be the very `.bin` that was flashed: a rebuild of the same source generally differs, and the device checks the patch against its image's appended SHA-256. With no matching file, several different ones, or one without an appended SHA-256, the tool says why and sends the full download.

A delta goes as DFI 0x20, an Espressif `esp_delta_ota` patch compressed with heatshrink, or DFI 0x30, the same patch uncompressed and then raw DEFLATE, which is usually much smaller. The tool tries each mode whose patch is smaller than the full download, smallest first; `--no-compress` rules out 0x30, and `--diff-format heatshrink` or `deflate` allows only 0x20 or only 0x30 (default `auto`). A device that answers 0x31 to one mode, or 0x22 for lack of memory, gets the next. `--drop-76` does not combine with `--diff-from`. A device running another build with the same app_elf_sha256, a re-signed one for example, refuses the patch before it erases anything (F1F1 `DL_BAD_BASE`), and the tool then sends the full download.

The tool transmits only on the profile's request ID and never on a `deny_tx` ID. Before its first frame it listens for 2 s and stops if it hears the response ID or the profile's busy value. During a run it stops if a response arrives that it did not ask for.

The exit code says why it stopped:

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | the device refused or failed a step |
| 2 | refused with nothing written: a bad profile, image, key file or `config set` value, a precheck stop (an image for another board, a running image still unconfirmed, a device that does not serve the udsota status DID F1F0), firmware without config writes, `flash --compress` on a server without compressed downloads, or `--diff-from` without detools installed |
| 3 | another tester holds a session |
| 4 | a second tester is on the bus |

## Profiles

Start from [`example.toml`](udsota/profiles/example.toml), which comments every key and shows the optional tables. Every table but `[can]` is optional, and an absent table turns its feature off. A profile error exits with code 2 before anything is sent.

| Table | Keys | Meaning |
|---|---|---|
| `[can]` | `interface`, `req_id`, `resp_id`, `deny_tx` | the SocketCAN interface, the ID pair, and IDs the tool must never send on |
| `[security]` | `mode` (`"hmac"`), `label`, `master_file`, `private_key_file`, `device_id_did` (0xF18C), `level_extended` (0x01), `level_programming` (0x03) | the 0x27 keys and the requestSeed levels (odd, 0x01 to 0x7D); without it the tool never unlocks. Mode `hmac` derives each key from `master_file` (32 raw bytes) and `label`; mode `ecdsa` signs each seed with `private_key_file` (a P-256 PEM) and takes no `label` or `master_file`. The mode must match the server's; the core README's Security section explains both and why ecdsa suits a product |
| `[image]` | `product`, `hw_ids`, `layout_id`, `slot_size` (0x400000), `compression` (`"none"`) | the image identity `flash` checks before sending, and whether it sends the image compressed: `"deflate"` as `--compress`, `"auto"` as `--compress-auto`, `"none"` as `--no-compress` |
| `[board]` | `did`, `names` | a DID naming the device's board, and the board name for each `hw_id`, so `flash` refuses an image for another board |
| `[busy]` | `id`, `byte`, `values` | a frame whose byte at `byte` holds one of `values` means another tester has a session |
| `[preroll]` | `tester_present_frames` | TesterPresent frames sent first on a quiet bus, for a device whose CAN driver waits to hear traffic |
| `[functional]` | `id`, `quiet_bus` (false) | the functional ID (0x7DF on most buses), the only ID besides `req_id` the tool may send on. With `quiet_bus`, `flash` first sends 10 83, 85 82 and 28 83 03 to every node, holds them there with 3E 80 every 2 s, and afterwards sends 28 80 03, 85 81 and 10 81, whether or not the update succeeded. Turn it on only on a bus where every node may stop its normal messages while you flash, never on a vehicle that is in use |
| `[dids]` | `"0xNNNN"` or `"0xNNNN-0xNNNN"` = `{ name, decode, type, writable, min, max }` | extra DIDs `info` reads after the server's own, decoded as `hex`, `ascii`, `version3`, `u8` or `u16` (decimal); a range stops at its first absent DID. `writable = true` makes one DID a key for `config set`, with a `type` (`u8`, `u16` or `blob`), a `name` of letters, digits and `_`, and for u8 and u16 a write range `min`..`max` (default the whole type) |
| `[config]` | `commit_rid`, `status_did`, `hash = { did, first, last, schema }` | the routine `config set --commit` runs; a DID shown as hex by `config show` and after a failed commit; and the hash check: SHA-256 of `schema`, then DID (big-endian), length and value for every DID from `first` to `last` the device answers, compared with DID `did`. `did` and `status_did` must lie outside `first`..`last` |

## Limits

The ISO-TP padding byte is fixed at 0xAA. Like the server, the tool speaks 11-bit IDs only.
