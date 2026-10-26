# Wire reference

What a tester sees from a unit that runs udsota 0.15 or later inside its app's iso14229 server, byte for byte, and the sequence a flasher other than the client follows. Units still on a 0.14.x server answer as [v0.14.2's wire reference](https://github.com/ramb0t/udsota/blob/v0.14.2/components/udsota/README.md#wire-reference) says, and the client updates both.

The numbers are `udsota.h`'s "Wire contract" block and `udsota_reason_t`; the NRCs and sessions are iso14229's `UDS_NRC_*` and `UDS_LEV_DS_*`. `client/tests/test_udsota.py` checks the client against all of them.

## Services

udsota answers the requests of an update. iso14229 frames every request and answers some itself; everything else is the app's, through its event callback, with whatever NRC the app picks.

| SID | Accepts | Session | Key |
|---|---|---|---|
| 10 | 01, 02, 03; answers `50 xx 00 96 01 F4` (P2 150 ms, P2* 5000 ms). Other session types are the app's | any | – |
| 11 | 01 hardReset: answers `51 01`, then restarts about 60 ms later. Other reset types are the app's | extended, programming | either level |
| 22 | F186, F189, F18C, F1F0, F1F1, F1F3; one request may carry several DIDs, and every other DID is the app's | any | – |
| 27 | with keys set, 01/02 in extended and 03/04 in programming; a requestSeed with no data, and a sendKey of exactly 16 bytes (HMAC) or 64 (ECDSA). Other levels, and every 27 without keys, are the app's | extended, programming | – |
| 31 | 01 startRoutine on FF01, F000, F001 and F002; every other RID is the app's | per routine | per routine |
| 34 | to address 0: DFI 00 (the image), 10 (raw DEFLATE, RFC 1951) or, where the unit serves [delta downloads](#delta-downloads), 30 (a patch from the running image, as raw DEFLATE), an ALFID whose nibbles are each 1–4 (the client sends 44), 0 < memorySize ≤ the slot, memorySize being the image's size in every case; answers `74 20 0F FF`. A 34 to any other address is the app's | programming | programming |
| 36 | in udsota's download: the block counter from 01, wrapping FF to 00, and 1 to 4093 data bytes | programming | programming |
| 37 | in udsota's download, with no data: once every announced byte has arrived, or after DFI 10 or 30 once the stream has ended at exactly memorySize bytes of image | programming | programming |
| 3E | 00, or 80 with no answer; iso14229 answers it and restarts S3 | any | – |

The key column applies with keys set; with none, no step needs a key and 27 is the app's. An accepted 10 01, 02 or 03 relocks, ends any transfer (the app's too) and discards the seed.

iso14229 answers these itself, before udsota or the app sees them: 0x13 to a request too short to parse; 0x70 to a 36 or 37 with no transfer open; 0x24 to a 36 whose counter is not the next one, a repeat of the last included, which ends the transfer; 0x71 to a 36 past the transfer's size; 0x22 to a 34 while a transfer is open; 0x31 to a 31 with control type 00 or 04–7F; 0x37 to any 27 within 1 s of `UDSServerInit` and 0x36 within 1 s of any refused sendKey; `67 xx 00 00` to a requestSeed for the level already unlocked; and 0x14 to a 22 whose answer would pass 4095 bytes.

## Delta downloads

A unit built with `UDSOTA_DELTA=1` and `cfg.allow_delta` set also takes DFI 30, a patch from the image it runs, and rebuilds the new image from its running slot, so a small change costs kilobytes on the bus instead of the whole image. Any other unit answers a DFI 30 34 with 0x31, and every unit so answers DFI 20, the heatshrink form 0.14 also served. F1F0 doesn't say whether a unit serves delta: send the 34 and fall back on 0x31.

The 34's memorySize is the rebuilt image's size, and the 36s may carry up to `UDSOTA_DL_Z_BOUND` of it, as for DFI 10. They carry one raw DEFLATE stream that inflates to a 64-byte header and then a detools 0.53.0 sequential patch, uncompressed, from the running image to the new one; `udsota pack --diff-from` and `flash --diff-from` write it (`client/udsota/delta.py`). The header is the magic 0xFCCDDE10, little-endian (`10 DE CD FC`), the base's SHA-256, and 28 reserved bytes, which the client writes as zeros. The base's SHA-256 is the 32 bytes ESP-IDF appends to the image, not F1F3's `app_elf_sha256`, so the base must be the very `.bin` that was flashed: a rebuild of the same source that is not byte-identical names another base. Signing an image again leaves that hash as it was, since the signature sector comes after it, so a re-signed copy passes the base check, and its patch rebuilds the new image with the wrong signature sector, which FF01 refuses with reason 8.

The unit checks the header in the 36 that completes it, before any patch byte is used, so before the image rules and the erase. A wrong magic is reason 13. A base hash other than the running image's, or a running image with none, is reason 15. Either answers that 36 0x31 and ends the download with nothing erased; a full download still works in the same session. The patch reads only the running slot, anywhere up to the slot's end. The rebuilt image's first 320 bytes then pass the image rules as any image's, and FF01, activate and confirm are unchanged. The 37 passes once the stream and the patch have both ended, with exactly memorySize bytes rebuilt and nothing after either.

A delta's flash work comes with the 36 that carries its patch bytes, and a short patch can rebuild most of an image in one 36, whose job erases and writes it under 0x78s up to the 90 s cap. Like every download here, a delta can't resume.

## Routines

| RID | Routine | Session, key | Does |
|---|---|---|---|
| FF01 | CheckProgrammingDependencies | programming, programming | after a 37, verifies the image in flash (its hash, its signature when the build checks signatures, and the image rules again) and answers `71 01 FF 01 <status>`, 00 or a reason. A pass marks the slot verified until the next 34 or restart, and a repeat after a pass answers 00 again. Without a finished download, 0x24 |
| F000 | GetResumePoint | programming, programming | answers status FF: downloads never resume |
| F001 | ActivateImage | programming, programming | needs a passing FF01 (else 0x24); makes the slot the boot slot, answers, and restarts about 60 ms later, reading requests until then |
| F002 | ConfirmImage | extended, none | needs the running image to be the boot image (else 0x22); confirms a pending-verify image, answers positive at once for one already valid or with rollback off, and 0x22 otherwise |

The checks run in this order: 0x7F in the default session, 0x12 for sub-function 02 or 03, 0x31 in the other non-default session, 0x33 while locked, 0x13 for an option record, then each routine's own: its sequence (0x24), then its conditions (0x22) and the gate, which F002 asks first.

## Data identifiers

| DID | Content |
|---|---|
| F186 | the active session, 1 byte |
| F189 | the running image's version string, without its NUL |
| F18C | the device ID the keys bind to: `cfg.device_id` (1–16 bytes), or the 6-byte base MAC |
| F1F0 | update status, 16 bytes |
| F1F1 | last download, 5 bytes |
| F1F3 | the running image's `app_elf_sha256`, 32 bytes |

**F1F0** is laid out as in 0.14, less its flag 0x02:

| Byte | Field | Values |
|---|---|---|
| 0 | `running_slot` | 00 ota_0, 01 ota_1, FF factory or unknown |
| 1 | `running_state` | 0 undefined, 1 new, 2 pending verify, 3 valid, 4 invalid, 5 aborted; never 2 with rollback off |
| 2 | `boot_slot` | as byte 0: the slot the next boot runs |
| 3 | `other_slot_state` | 0 empty, 1 holds an unverified image, 2 being written, 3 verified since boot (ActivateImage may use it), 4 rolled back |
| 4–6 | `other_version` | major, minor, patch; 0.0.0 when empty or being written |
| 7–14 | `other_elf_sha_prefix` | the first 8 bytes of the other slot's `app_elf_sha256` |
| 15 | `flags` | 0x01 updates are signature-checked (`UDSOTA_STATUS_SIG_CHECKED`); other bits 0 |

**F1F1** is the [reason](#reasons) in byte 0 and, in bytes 1–4, big-endian, the data bytes the 36s carried, coded bytes after DFI 10 or 30. While FF01 runs it reads reason 10 until the verdict.

## Negative responses

Those udsota sends; the app's own services send theirs.

| NRC | udsota sends it for |
|---|---|
| 0x12 | 31 02 or 03 on udsota's RIDs |
| 0x13 | a requestSeed with data, a sendKey of the wrong length (the seed stays), an option record on udsota's RIDs, a 36 with no data or over 4093, a 37 with data |
| 0x22 | 10 02 or 34 while the slots are unsettled (an activated image waiting for its restart, or a running image still pending verify), a flash job runs or a download is open; 11 01, 27 or F001 while a flash job runs; 27 when no seed can be drawn or no key checked (keys unusable, or the app holds the PSA lock past 40 ms); a 34 with no inactive slot (F1F1 12) or no memory for the inflater or a delta's patch state (F1F1 14); F002 when the running image is not the boot image, or is neither valid nor pending verify; the gate's choice |
| 0x24 | a sendKey with no live seed (none, another level's, or older than 30 s), a 37 before every byte of a DFI 00 download (which ends it), FF01 with no finished download, F001 before a passing FF01 |
| 0x31 | a 34 with another DFI (DFI 20 always, DFI 30 where the unit serves no delta), size 0 or past the slot; a first block the [image rules](#reasons) refuse; a DEFLATE block that is corrupt or inflates past memorySize; a delta block whose patch is for another base (F1F1 15) or is corrupt (F1F1 13); one of udsota's RIDs in the wrong non-default session |
| 0x33 | 11 01 locked; 34, 36, 37, FF01, F000 or F001 without level 03 |
| 0x35 | a wrong key |
| 0x71 | a 36 past memorySize, or after DFI 10 or 30 past `UDSOTA_DL_Z_BOUND` of it (an eighth plus 1024 bytes over); the download ends |
| 0x72 | a failed erase, write, activate or confirm, a DEFLATE or delta 37 that fails (F1F1 names why), or a flash job past 90 s, which also ends the session |
| 0x78 | a flash job still running: a 36's write, a DEFLATE or delta 37, FF01, F001 or F002 |
| 0x7E | a 27 level that belongs to the other session |
| 0x7F | 11 01, 27 or udsota's RIDs in the default session; 34, 36 or 37 outside programming |

Any NRC to a 36 or 37 ends the transfer, and F1F1 reads ABORTED unless it names another reason. A gate refusal of a 36 with anything but 0x21 also ends the session.

## Reasons

F1F1 byte 0 and FF01's status byte. The first-block rules (1–7) run on the image's first 320 bytes before anything is erased, and FF01 runs them again on the bytes in flash.

| Code | Name | Meaning |
|---|---|---|
| 0 | `UDSOTA_DL_OK` | success |
| 1 | `UDSOTA_DL_BAD_HEADER` | not an ESP-IDF image for this chip (image magic, segment count, SPI mode, chip ID, segment 0's length, app-descriptor magic), a chip revision or flash mode ESP-IDF refuses, a version that doesn't parse or a release flag that disagrees with it, or a DEFLATE stream or delta patch that ends before 320 bytes of image |
| 2 | `UDSOTA_DL_BAD_PROJECT` | a project name other than `cfg.product`, or than this image's own when it is NULL |
| 3 | `UDSOTA_DL_BAD_BOARD` | no descriptor (magic), descriptor version 0, or another `hw_id` |
| 4 | `UDSOTA_DL_BAD_LAYOUT` | another `partition_layout_id` |
| 5 | `UDSOTA_DL_BAD_DIAG_IDS` | the image would answer on other CAN IDs |
| 6 | `UDSOTA_DL_NOT_NEWER` | a release not newer than the running image (a running dev build with the same X.Y.Z takes it), or a dev build whose X.Y.Z is older; `cfg.allow_downgrade` lifts this rule alone |
| 7 | `UDSOTA_DL_TOO_BIG` | larger than the slot; a 34 that announces it answers 0x31 first and leaves F1F1 as it was |
| 8 | `UDSOTA_DL_VERIFY_FAILED` | FF01's hash or signature check failed, or it could not read the slot back. FF01's image-rule failures report 1–6, and a failed F001 answers 0x72 and leaves F1F1 as it was |
| 9 | `UDSOTA_DL_SIG_FAILED` | reserved: ESP-IDF reports a bad signature as 8 |
| 10 | `UDSOTA_DL_WORKER_TIMEOUT` | a flash job passed 90 s, or its session ended while it ran |
| 11 | `UDSOTA_DL_ABORTED` | ended early: a session change, S3, the gate, an overrun, an early 37, a block-counter mismatch, or any other NRC that ended iso14229's transfer |
| 12 | `UDSOTA_DL_FLASH_ERROR` | an erase or write failed, no inactive slot, or the flash worker could not take the job |
| 13 | `UDSOTA_DL_BAD_STREAM` | a DEFLATE stream that is corrupt, inflates past memorySize, or at the 37 has not ended at exactly memorySize or has bytes after its end; and for a delta, a header without the patch magic, a patch that is corrupt, is for an image of another size, reads outside the running slot or has bytes after its end, or at the 37 has not ended |
| 14 | `UDSOTA_DL_NO_MEMORY` | no memory for the inflater, or a delta's patch state, at the 34 |
| 15 | `UDSOTA_DL_BAD_BASE` | a delta patch made from another image than the running one, or a running image with no appended SHA-256 to compare; refused at the 36 before anything is erased |

## Timing

The 10 answer carries iso14229's client defaults with P2* raised to the server's: P2 150 ms, P2* 5000 ms. iso14229 holds every answer until at least `srv->p2_ms` after the previous one: 50 ms by default, 5 ms as the examples set it, which every app should do ([Known limits](../README.md#known-limits)). A flash job answers 0x78 at once and every 1.5 s (0.3 × P2*) until it ends, and its final answer comes `p2_ms` after that; at 90 s it answers 0x72 and the session ends. While any 0x78 job runs, iso14229 reads no other request, and only the last one sent meanwhile is answered, after the job. A 27 gets no 0x78: an ECDSA check takes about 0.45 s on an ESP32-S3, so the client waits up to 2 s for a 64-byte key's answer.

S3 is 5100 ms (iso14229's default), restarted only by 10 and 3E, and by udsota while its own flash job runs; its expiry returns to the default session, relocks and ends a download. A seed is single-use and lives 30 s.

ISO-TP is iso14229's isotp-c with its defaults unless the app defines others build-wide: frames not padded, flow control with BS 8 and STmin 0, N_Bs and N_Cr 100 ms. CANDash, for one, sets `ISO_TP_FRAME_PADDING`, `ISO_TP_FRAME_PADDING_VALUE=0xAA`, `ISO_TP_DEFAULT_BLOCK_SIZE=64`, `ISO_TP_DEFAULT_ST_MIN_US=5000` and `ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US=1000000`. A message is at most 4095 bytes either way, and the 34's maxNumberOfBlockLength of 4095 (`UDSOTA_DL_MAX_BLOCK_LEN`) leaves 4093 data bytes per 36.

## Image descriptor

32 bytes, little-endian, at image offset 288 (`UDSOTA_IMG_DESC_OFFSET`): after the ESP image header (24 bytes), the first segment header (8) and `esp_app_desc_t` (256), so a DFI 00 download's first 36 carries at least 320 bytes.

| Offset | Field | Value |
|---|---|---|
| 0 | `magic` | 0x5544534F ("UDSO"); a hex dump of flash shows `4F 53 44 55` |
| 4 | `desc_version` | 1 (16-bit) |
| 6 | `hw_id` | the board |
| 7 | `partition_layout_id` | the partition table |
| 8 | `diag_request_id` | request CAN ID (16-bit) |
| 10 | `diag_response_id` | response CAN ID (16-bit) |
| 12 | `flags` | bit 0: a release build (a clean `[v]X.Y.Z` version); other bits 0 |
| 13 | `reserved` | 19 zero bytes |

## Keys

With keys set, 27 01/02 unlocks 11 01 in the extended session, and 27 03/04 unlocks 34, 36, 37, FF01, F000, F001 and 11 01 in the programming session. ConfirmImage needs no key, since it can only keep an image that passed FF01 and ActivateImage. Each 16-byte seed takes one sendKey of the right length, right or wrong. Below, `level` is the requestSeed sub-function (01 or 03) and `device_id` the bytes F18C returns.

In the ECDSA mode (`cfg.key_pubkey`, a 65-byte 04 ‖ X ‖ Y P-256 point) the key is a 64-byte signature, r ‖ s with 32 big-endian bytes each, over SHA-256("udsota-27-ecdsa-v1" ‖ seed ‖ level ‖ id_len ‖ device_id), where `id_len` is one byte. In the HMAC mode (`cfg.key_label` and `cfg.key_master`) the key is the first 16 bytes of HMAC-SHA256(K_dev, seed ‖ level ‖ device_id), where K_dev = HMAC-SHA256(key_master, key_label ‖ device_id).

## Flashing without the client

A flasher that is not the client, such as an edge device that fetches updates from a server, sends the payloads `udsota pack` writes ([client README at v0.14.2](https://github.com/ramb0t/udsota/blob/v0.14.2/client/README.md)) in this sequence, with every value it needs in their manifest. The client's `update.flash` is the reference implementation. The 0x27 key is not in the manifest: in the ECDSA mode the flasher sends each seed, the level and the F18C device ID to the product's signing service and sends back the 64-byte signature it returns; in the HMAC mode it needs the master key.

**Keep the session.** S3 restarts only on 10 and 3E, so outside the default session send 3E 00 before any request that comes 2 s or more after the last 10 or 3E: between the 36s of a long download, while the signing service answers, and between ConfirmImage retries. Send nothing while a request waits on 0x78s.

**Precheck**, in the default session. If F1F3 already reads the manifest's `image_elf_sha256`, there is nothing to send, or only ConfirmImage when F1F0 says the running image is pending verify. Any other pending-verify image must be confirmed or rolled back first. The board DID (`board_did`) must read `board`. If F1F0's other slot is verified since the last boot and its SHA prefix is the first 8 bytes of `image_elf_sha256`, skip the payloads and FF01: after 10 02 and the unlock, go straight to ActivateImage.

**Download.** 10 02 and the programming unlock, then the payloads in manifest order until one is taken. Each goes as a 34 with the entry's `dfi`, ALFID 44, address 0 and `memory_size`; then 36 blocks of 4093 bytes, the counter from 01 wrapping FF to 00; then a 37. Skip a delta entry whose `base_elf_sha256` is not what F1F3 reads: the unit runs another image than its base and would refuse it with reason 15. A 34 answered 0x31, as every DFI 20 entry is and every DFI 30 entry where the unit serves no delta, or 0x22 with F1F1 reason 14, means the device can't take that payload now: try the next entry. A delta's 36 answered 0x31 with F1F1 reason 15 means the unit runs another image than the patch's base: skip the other delta entries and send the first full one, in the same session. Any other refusal stops the update, and F1F1 names why.

**Lost answers.** Nothing in the download may be resent. A resent 36 answers 0x24 and ends the transfer, and a resent 37 answers 0x70, even when the first copy succeeded. So when a 36 or 37 gets no answer, start the download again from its 34, in the same session and unlock if they still hold. When a delta's 36 gets no answer and F1F1 then reads reason 15, the lost answer was the base refusal: go on to the first full entry instead. Waiting out P2* for a lost answer can outlast S3 (5.1 s), so read F186 first and, if the session is no longer programming, enter it and unlock again. A resent FF01 answers 00 again after a pass, and 0x24 after a failure, which F1F1 names.

**Verify, activate, confirm.** FF01 must answer status 00. ActivateImage (F001) answers and restarts the device, so wait about 3 s, then poll F1F3 until the device answers (the client allows 60 s). Any value but `image_elf_sha256` means it rolled back or never switched: stop. Finally 10 03 and ConfirmImage (F002), sent again every 2 s while it answers 0x22 and the product's own checks run; the client allows 120 s.
