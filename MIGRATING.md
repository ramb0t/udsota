# Migrating to udsota 0.15 and later

How to move an ESP-IDF app from udsota 0.14 or earlier, where udsota was the UDS server, to 0.15, where `udsota.c` answers updates inside the app's own iso14229 server. An app on 0.15.x needs only [0.15.x to 0.16.0](#015x-to-0160), and one on lite-v0.1.0 only [From lite-v0.1.0](#from-lite-v010).

The app now owns the server. It builds iso14229 from this component, starts the server, the ISO-TP transport and their task itself, and hands every event to `udsota_event` first. Each piece of 0.14's `udsota_esp32_start` and its hooks becomes a field of `udsota_cfg_t`, an iso14229 event the app serves, or state the app keeps; the sections below map every one. [`examples/esp32/main/main.c`](examples/esp32/main/main.c) is the whole integration in one file, and [`examples/candash_ws43`](examples/candash_ws43/README.md) a product's.

The port goes best in two commits that each build and pass their tests. First, still on 0.14, move the app's pure code onto UDS types of its own, mapped to udsota's in one glue file with a `_Static_assert` on each value, and move the boot-loop breaker into the app ([below](#the-boot-loop-breaker)). Then switch the build, the start-up and the hooks to 0.15, which then touches only the glue and the code around the server.

## Build

The repository root is the component `udsota`: `udsota.c`, `udsota.h` and `iso14229/`, which it builds with `-fwrapv` (README, Known limits). Point `EXTRA_COMPONENT_DIRS` at the checkout itself, not its old `components/`, and check for `udsota.h` where you checked for `components/udsota_esp32/project_include.cmake`; a submodule that tracks a branch tracks `main`. A warning-flag loop that matched udsota's components now matches the root, so it also applies to `iso14229.c`, which builds clean under `-Werror=extra`. An app with its own copy of iso14229 drops it.

`PRIV_REQUIRES udsota udsota_esp32` becomes `udsota`, which also brings `iso14229.h`. Delete `udsota_esp32_image_desc(${COMPONENT_LIB})`: the component sets `UDSOTA_IMG_RELEASE` publicly from `PROJECT_VER` and links `-u udsota_image_desc` itself. Delete every `CONFIG_UDSOTA_ESP32_*` line from `sdkconfig.defaults`: there is no Kconfig, DEFLATE downloads are always on, and `CONFIG_UDSOTA_ESP32_DELTA` becomes the build define `UDSOTA_DELTA=1` with `cfg.allow_delta`, for DFI 30 only, from 0.16 ([0.15.x to 0.16.0](#015x-to-0160)). The inflater's 43 KB come from plain `malloc` at the 34 and are freed at the 37, where 0.14 put them in PSRAM by default: with SPIRAM malloc on, the 32 KB window goes to PSRAM and the 11 KB decompressor, under `CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL`'s 16 KB default, to internal RAM. udsota also holds 8 KB of static buffers in internal RAM.

iso14229's ISO-TP defaults are unpadded frames, BS 8, STmin 0 and 100 ms N_Bs and N_Cr. An app whose CAN layer sends or accepts only DLC 8 needs padding, and 0.14 gave every app padding with 0xAA, BS 64, 2 ms STmin and a 1 s N_Cr. Set them build-wide, before `project()`, so `iso14229.c` inside the component gets them; `idf.py -D` sets CMake variables, not these. Give the host tests the same list.

```cmake
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(COMPILE_DEFINITIONS "ISO_TP_FRAME_PADDING;ISO_TP_FRAME_PADDING_VALUE=0xAA;ISO_TP_DEFAULT_BLOCK_SIZE=64;ISO_TP_DEFAULT_ST_MIN_US=2000;ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US=1000000" APPEND)
project(my_product)
```

A product's CI can also check what the build relies on: `sha256sum -c iso14229/SHA256SUMS` in the checkout, and `-fwrapv` on `iso14229.c`'s line in `compile_commands.json`.

## The image descriptor and the ID rule

In the file that places the descriptor, `UDSOTA_ESP32_IMG_RELEASE` becomes `UDSOTA_IMG_RELEASE`, `udsota_esp32.h` becomes `udsota.h`, and `UDSOTA_ESP32_IMAGE_DESC` becomes `UDSOTA_IMAGE_DESC` with the same arguments. A guard that `#error`s when the release flag is undefined still works before the include, since the component defines it.

Nothing checks the IDs any more, where 0.14's start refused IDs above 0x7FF and a request ID equal to the response ID. Now the descriptor is this unit's identity, and its IDs must equal the ones the app gives the transport, both 11-bit. Take both from one set of defines and `_Static_assert` that each is at most 0x7FF.

## Start-up

`udsota_esp32_start` becomes this sequence, with the server task the app's own:

```c
udsota_init(&cfg);                     // reads the descriptor, starts the flash worker and the keys
UDSServerInit(&s_srv);
s_srv.p2_ms = 5;                       // README, Known limits: iso14229's 50 ms spacing clips the client's P2
UDSServerTpISOTpCInit(&s_tp, REQ_ID, RESP_ID, UDS_TP_NOOP_ADDR);
s_srv.tp = &s_tp.hdl;
s_srv.fn = on_event;                   // udsota_event first, then the app's own services

for (;;) {                             // the server task: a pass at least every tick
    if (xQueueReceive(rxq, &f, pdMS_TO_TICKS(1)) == pdTRUE) {
        do { isotp_on_can_message(&s_tp.phys_link, f.data, f.dlc); } while (xQueueReceive(rxq, &f, 0) == pdTRUE);
    }
    UDSServerPoll(&s_srv);
    udsota_poll(&s_srv);               // mandatory, after every UDSServerPoll
}
```

The 1 ms wait needs `CONFIG_FREERTOS_HZ=1000`, as both examples' `sdkconfig.defaults` set. At ESP-IDF's default 100 Hz `pdMS_TO_TICKS(1)` is 0, so the task never blocks and starves every lower-priority task on its core, udsota's flash worker included; 0.14's port warned of this, and nothing does now.

`udsota_poll` was the port's to call; now it is the app's, and without it iso14229's timers wrap after 24.86 days of uptime. `udsota_esp32_on_frame` becomes the app's receive path queuing the request ID's standard frames for that task; there is no receive timestamp. `udsota_esp32_can_t` becomes the three functions isotp-c calls: `isotp_user_send_can`, `isotp_user_get_us` and `isotp_user_debug`. Return `ISOTP_RET_NOSPACE` from the send for no room now, which isotp-c retries on its next poll for a consecutive frame. It never resends a single, first or flow-control frame, so the send itself retries those for what was `fc_retry_ms`, two token intervals of the app's rate cap, before it gives up. `tx_dropped` has no use (F1F2 is gone).

`cfg.reset` NULL used to restart once the answer had left the driver; now it calls `esp_restart()` at once. Set `reset` to a function that waits, bounded, for the CAN driver's queue to drain and then restarts, as the examples' `do_reset` does. It must not return.

## Configuration

`udsota_config_t` field by field:

| 0.14 | 0.15 |
|---|---|
| `req_id`, `resp_id` | `UDSServerTpISOTpCInit`'s, and the descriptor's |
| `func_id` | gone: no functional addressing |
| `p2_ms` (50) | `s_srv.p2_ms = 5` after `UDSServerInit`. It is now the least gap between two answers, not a deadline; the 10 answer always says 150 ms |
| `p2star_ms`, `s3_ms` | `s_srv.p2_star_ms` and `s_srv.s3_ms`, iso14229's 5000 and 5100 by default |
| `p2_prog_ms`, `p2star_prog_ms` | gone: one P2 and P2* for every session |
| `max_block_len` | fixed at 4095 (`UDSOTA_DL_MAX_BLOCK_LEN`) |
| `stmin_us`, and `hooks.stmin_us` per First Frame | `ISO_TP_DEFAULT_ST_MIN_US` at build time, one STmin for every message |
| `block_size` | `ISO_TP_DEFAULT_BLOCK_SIZE` |
| `fc_retry_ms` | the app's `isotp_user_send_can` ([Start-up](#start-up)) |
| `stmin_monitor` | gone, with rxwatch and its median rule |
| `level_extended`, `level_programming` | fixed at 01 and 03 (`UDSOTA_SA_SEED_EXTENDED`, `_PROGRAMMING`) |
| `hw_id`, `layout_id` | the running image's descriptor; log `udsota_image_desc.hw_id` |
| `key_label`, `key_master`, `key_master_len`, `key_pubkey`, `key_pubkey_len`, `device_id`, `device_id_len` | `udsota_cfg_t`, same meaning. A malformed key now leaves security on with no key that matches, where 0.14 refused to start. Nor is PSA self-tested first: 0.14 turned 0x27 off when its HMAC or ECDSA known-answer test failed, and 0.15 has no such test |
| `product` | `udsota_cfg_t.product`; NULL now means this image's own project name, where 0.14 skipped the check |
| `allow_downgrade` | `udsota_cfg_t.allow_downgrade` |
| `dtc_availability_mask`, `dtc_format` | gone: 0x19 is the app's `UDS_EVT_ReadDTCInformation` |

`udsota_init` checks no field. Its -1 for no inactive slot or no memory for the worker is not fatal: udsota still answers and refuses downloads, so start the server anyway. It also returns -1 for a second call or a missing descriptor.

## Hooks and events

`hooks.gate`, `hooks.progress`, `hooks.reset` and `hooks.ctx` move into `udsota_cfg_t`. The gate keeps its ops and returns `UDS_NRC_*` values, but it is asked once per 36, not at the flow-control points inside one, and any refusal of a 36 ends the transfer, 0x21 included. The rest:

| 0.14 | 0.15 |
|---|---|
| `phase`, `udsota_phase_t` | gone. The session is `srv->sessionType`, TRANSFERRING becomes `cfg.progress`'s ERASING and WRITING stages, and ACTIVATING its stage of the same name. A baseline taken at TRANSFERRING moves to the gate's allowed START_DOWNLOAD (the 34 can still be refused after it) |
| `did_read`, `did_read_ex` | `UDS_EVT_ReadDataByIdent`: answer `a->copy(srv, buf, n)`, or `UDS_NRC_RequestOutOfRange` for a DID the app doesn't serve |
| `did_write` | `UDS_EVT_WriteDataByIdent`. iso14229 answers 0x13 under 4 bytes in every session; the app adds 0.14's 0x7F in the default session and its own checks |
| `routine`, `routine_ex`, `routine_poll`, `UDSOTA_PENDING` | `UDS_EVT_RoutineCtrl`, for every RID udsota doesn't own, in every session. Pending work returns `UDS_NRC_RequestCorrectlyReceived_ResponsePending`, and iso14229 then re-sends the same event every poll until another answer, so the handler is its own poll. iso14229 gives an app job no S3 hold and no cap: restart `srv->s3_session_timeout_timer` on each pass, and end a job that runs too long (0.14 sent 0x10 at 90 s) |
| `request`, `UDSOTA_NO_ANSWER` | `UDS_EVT_Custom` for a SID iso14229 has no handler for; 14, 19, 23, 28, 2C, 2F, 35, 38, 3D, 85 and 87 arrive as their own events |
| `comm_control`, `dtc_setting` | `UDS_EVT_CommCtrl`, `UDS_EVT_ControlDTCSetting`; the app undoes 28 and 85 itself when the session ends, as 0.14 did through the hooks |
| `dtc_get`, `dtc_ext_data`, `dtc_clear` | `UDS_EVT_ReadDTCInformation`, `UDS_EVT_ClearDiagnosticInfo` |
| `udsota_access_t` | gone: `session` is `srv->sessionType`, `unlocked_level` is `srv->securityLevel` (01 or 03, 0 locked), and the app counts its own epoch |
| `UDSOTA_NRC_*`, `UDSOTA_SESSION_*` | iso14229's `UDS_NRC_*` and `UDS_LEV_DS_DS`, `_PRGS`, `_EXTDS` |

iso14229 sends whatever the callback returns, so return an NRC for every event the app doesn't serve, as the examples' `on_event` does. `udsota.h`'s `UDSOTA_PENDING` is now the platform's job code, never a hook's.

The session ends in three ways an app may need to see, to drop staged state, bump its epoch or undo 28 and 85: a positive `UDS_EVT_DiagSessCtrl` (udsota answers it, so check for it when `udsota_event` returns true), `UDS_EVT_SessionTimeout` (udsota passes it on), and a change udsota makes with no event, by `udsota_end_session`, a refused 36 or its 90 s job cap. Compare `srv->sessionType` after each poll to catch the last.

## Reads from other tasks

| 0.14, any task | 0.15 |
|---|---|
| `udsota_esp32_phase()` | gone: derive it on the server task after each poll, from `srv->sessionType` and the progress stage, into an atomic the other tasks read |
| `udsota_esp32_progress()` | `udsota_progress()` is the server task's only: keep `cfg.progress`'s last report under a lock for the other tasks |
| `udsota_esp32_incoming_version()`, `UDSOTA_ESP32_VERSION_MAX` | gone: the incoming image's version has no source |
| `udsota_esp32_image_unconfirmed()` | `udsota_unconfirmed()`, any task |
| `udsota_esp32_status()` | `udsota_plat_status()`, any task, the same `udsota_status_t` |
| `udsota_esp32_engine_busy()` | `udsota_busy()`, any task. It is also true while a download is open, so a rule that refuses work while busy now refuses it for a whole transfer |
| `udsota_esp32_end_session()` | `udsota_end_session(srv)`, on the server task between polls only: another task sets a flag, and the server task calls it after each poll until it returns true |
| `udsota_esp32_psa_lock()`, `_unlock()`, `UDSOTA_ESP32_PSA_WAIT_FOREVER` | `udsota_psa_lock()`, `udsota_psa_unlock()`, `UDSOTA_PSA_WAIT_FOREVER`, the same shape. udsota's 0x27 check waits 40 ms for it and answers 0x22 past that; its worker waits as long as it takes |
| `udsota_esp32_device_id()` | gone: F18C is `cfg.device_id`, or `esp_read_mac(ESP_MAC_BASE)`'s 6 bytes |
| `udsota_esp32_engine()`, `udsota_esp32_security()`, `_security_ecdsa()`, `udsota_core_init()` | gone |

## The boot-loop breaker

`udsota_esp32_bootloop_init`, `_config_ignored` and `_mark_healthy` have no replacement, and F1F0 flag 0x02 is never set. Copy v0.14.2's portable breaker ([`components/udsota/bootloop/`](https://github.com/ramb0t/udsota/tree/v0.14.2/components/udsota/bootloop)) and its RTC storage ([`components/udsota_esp32/bootloop/`](https://github.com/ramb0t/udsota/tree/v0.14.2/components/udsota_esp32/bootloop)) into the app, keeping the RTC layout and threshold so a unit keeps its count across the update.

## Headers and names

`udsota_wire.h`, `udsota_esp32.h`, `udsota_server.h` and every other udsota header become `udsota.h`, which includes `iso14229.h`. `udsota_status_t`, `udsota_progress_t`, `udsota_stage_t`, `udsota_reason_t`, `udsota_op_t`, `udsota_image_desc_t` and the `UDSOTA_SLOT_*`, `UDSOTA_IMG_*`, `UDSOTA_OTHER_*` and reason values keep their names and numbers, and so does every name in `udsota.h`'s wire block. The rest of `udsota_wire.h`'s names have no counterpart in `udsota.h`. The SIDs, NRCs and levels come from `iso14229.h` (`UDS_SID_*`, `UDS_NRC_*`, `UDS_LEV_*`), and any other the app uses (timing, security-access delays, request-format lengths and the like) becomes its own, for example `UDSOTA_DL_REASON_COUNT` (reasons 0–15 are unchanged, so a local 16 keeps an assert), `UDSOTA_STATUS_LEN` (16), `UDSOTA_RESULT_LEN` (5), `UDSOTA_SHA256_LEN` (32), `UDSOTA_DL_MAX_DATA` (4093), `UDSOTA_DL_ALFID` (0x44), `UDSOTA_IMAGE_MIN_LEN` (320), and `UDSOTA_IMG_DESC_MAGIC`, `_VERSION` and `UDSOTA_IMG_FLAG_RELEASE` (0x5544534F, 1, 0x01).

## Tasks and logs

udsota's flash worker runs at priority 2 with an 8 KB stack and no core affinity, all fixed, where 0.14's Kconfig set them; check the app's own priorities against it. The server task is the app's: its priority, core and stack are the app's choice. udsota's 0x27 key check runs on it, and CANDash gives it 8 KB of internal RAM. udsota logs only start-up warnings, under the tag `udsota`, so the step lines 0.14 logged are gone; read an update's outcome from F1F1 or `cfg.progress`.

## What testers see

[docs/wire.md](docs/wire.md) replaces the wire reference in 0.14's `components/udsota/README.md`, and its [Flashing without the client](docs/wire.md#flashing-without-the-client) that README's section of the same name: repoint a product README's links to them, and any Kconfig help that describes the 0.14 port. The client must be 0.14.1 or newer, since 0.14.0 added the `3E 00` that holds sessions open and 0.14.1 fixed it; pin 0.14.2, the client this repository carries, in the product's own tests.

Testers lose DFI 20 delta downloads (and DFI 30 unless the app turns delta on, from 0.16), F1F2, functional addressing, the answered repeat of a 36 or 37 (a lost answer fails the run, and the next run starts from the first byte), the 0x78 to 27, and the 0x21 to a request sent while a job answers 0x78: iso14229 reads no other request meanwhile, udsota's job or the app's, and answers only the last one sent, after the job ends. Padding and the 1 s N_Cr go too, unless the build sets them ([Build](#build)).

Updating a unit that runs CANDash v0.3.0 to v0.5.0 (udsota v0.3.0 to v0.11.0, -O2) uses that unit's own isotp-c, built without -fwrapv. A block can fail with a false N_Cr once every 71.6 min of uptime. The client resends it once (`client/udsota/update.py:64-69`); if the run still fails, run it again.

## Host tests

0.14's `sources.cmake` lists, its `components/isotp`, the `udsota_image_check` library, rxwatch, the bootloop sources and the server a vcan harness ran on are gone. A host build compiles `udsota.c`, `iso14229/iso14229.c` with `-fwrapv` and `test/miniz/miniz.c` with `UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_C UDS_CUSTOM_MILLIS _DEFAULT_SOURCE`, the miniz defines in `CMakeLists.txt` and the app's ISO-TP list. Off ESP-IDF the build supplies the platform: `UDSMillis` and every `udsota_plat_*` function `udsota.h` declares. [`test/e2e/lite_platform.c`](test/e2e/lite_platform.c) is a complete one with RAM slots, and `test/test_udsota.c` one of stubs. `UDSOTA_TEST` adds `udsota_test_reboot()`, a power cycle of udsota's state; `udsota_test_check_first()`, the image rules on a first block, which replaces 0.14's descriptor tests; and `udsota_test_psa_depth()`. On a host the PSA lock is a depth counter that fails at once while held, so 0x27 answers 0x22, FF01 fails with reason 8 and F001 answers 0x72. `CHIP_ID` sets the chip a host build accepts (ESP32-S3, 9, by default), and `tools/image_check.c` runs the image rules on a built image.

## From lite-v0.1.0

An app on lite-v0.1.0 (5f29e74) moves to 0.15.0 by moving its pin, with a submodule that tracked `poc/udsota-lite` tracking `main`. The API, the wire and the `udsota_plat_*` functions are unchanged, and `udsota.h` gains three things. `UDSOTA_VERSION` and `UDSOTA_VERSION_MAJOR`, `_MINOR` and `_PATCH` name the release. The "Wire contract" block names the numbers `udsota.c` kept private, under v0.14's names (`UDSOTA_DID_STATUS`, `UDSOTA_RID_ACTIVATE_IMAGE` and the rest), so an app that defines macros of those names drops its own. And `udsota_psa_lock`/`udsota_psa_unlock` serialise PSA between udsota and the app: take the lock around the app's own PSA calls, where an app may have refused them while `udsota_busy()`, and expect 0x27 to answer 0x22 while the app holds it past 40 ms. Set `s_srv.p2_ms = 5` too, if the app doesn't yet ([Start-up](#start-up)).

## 0.15.x to 0.16.0

Nothing is needed to stay as you are. Without `UDSOTA_DELTA` udsota compiles no delta code and declares no new platform function, a delta `34` gets 0x31 as in 0.15, and the client then sends the full image. `udsota_cfg_t` gains `bool allow_delta` after `allow_downgrade`, which a cfg built with designated initializers leaves off.

To serve delta downloads (DFI 30), define `UDSOTA_DELTA=1` build-wide and set `cfg.allow_delta`. Under ESP-IDF the define goes in the top-level `CMakeLists.txt` before `project()`, with `idf_build_set_property(COMPILE_DEFINITIONS UDSOTA_DELTA=1 APPEND)` beside the ISO-TP options ([Build](#build)); the component reads it there and then compiles `detools/detools.c` and supplies the two base calls, and `udsota.c` refuses to compile when the define reaches it any other way. A host build that sets the define compiles `detools/detools.c`, with `detools/` on the include path, and the defines in `UDSOTA_DELTA_DEFS` in udsota's `CMakeLists.txt`; `udsota_with_delta()` there adds all three to a target of that file, and a build that lists udsota's sources itself copies the list. Its platform supplies `udsota_plat_base_read` and `udsota_plat_base_hash`, as `test/e2e/lite_platform.c` does. A delta download holds what a DEFLATE one holds plus detools' 116-byte state on an ESP32-S3, from its `34` to its `37` or abort. To send deltas, keep every shipped `.bin` as a base and pass the running one's with `flash --diff-from`, which needs the client's `diff` extra.
