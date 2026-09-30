# udsota

udsota is a device's UDS (ISO 14229) server on ISO-TP over CAN, with firmware update as its main service: the updater writes a new image into the inactive A/B slot, and, with rollback on, the device keeps it only once the installing client confirms it. It exists so that any UDS tester can drive a product's updates while the product keeps every "is it safe to update now?" decision for itself.

This component is the portable core: C11, with no platform headers. It builds as an ESP-IDF component, or in plain CMake as the library `udsota` (add `components/isotp` first). [udsota_esp32](../udsota_esp32/README.md) is the ESP-IDF port, and [examples/esp32](../../examples/esp32/README.md) is a minimal integration over TWAI. [`tools/linux_server`](../../tools/linux_server/README.md) runs the core on Linux as a demo server for the client's end-to-end tests.

The sources sit in three directories, here and in the port: `server/`, the generic UDS server and its transport; `update/`, the firmware updater; and `bootloop/`, the boot-loop breaker, which the app drives and which the updater only reports in F1F0. `udsota.h` and `udsota_wire.h` stay in `include/`. The core's `server/`, in this component, never calls the updater or touches its state: the updater registers on the server as its one service through `udsota_service.h`, and the host build checks that `server/` compiles and links without it. The one exception is that the server context embeds the updater's state type from `update/include/udsota_update_state.h` (116 B on ESP32), so a server-only build still needs that include dir. The port's `server/` is knowingly mixed: it includes the umbrella `udsota.h` and starts the updater. A host build names no file: it `include()`s `sources.cmake` from this component and from `udsota_esp32` and takes their lists, `UDSOTA_SRCS`, `UDSOTA_INCLUDE_DIRS` and `UDSOTA_PRIV_INCLUDE_DIRS` (empty, kept so existing lists still expand) for the whole core, or one unit's, such as `UDSOTA_SERVICES_SRCS` (`udsota_init()` and every service, no transport), `UDSOTA_SERVER_CORE_SRCS` (the server with neither the updater nor the transport, for a build that brings its own isotp-c), `UDSOTA_IMAGE_SRCS` or `UDSOTA_ESP32_IMAGE_SRCS`, for a test that links part of it. Each file's header lists the rest.

## Layers

```
app            CAN driver · gate and phase hooks · its own DIDs, writes and routines · product policy
  │
udsota         ISO-TP adapter (udsota_isotp) → UDS server (udsota_server) → updater (udsota_update) → engine interface
               image rules (descriptor, version) · key derivation · boot-loop counter
  │
udsota_esp32   diag task and flash worker · engine on esp_ota_* · PSA ECDSA or HMAC, and RNG · RTC boot-loop storage
```

Dependencies point down only. The app owns the CAN bus. udsota transmits through the app's send callback, receives only the frames the app hands it, and never touches the controller. The ISO-TP adapter, on `components/isotp`, is the only CAN-specific code in the core. A port implements the engine (`udsota_engine_t`: check the first block, erase, write, verify, activate, confirm, abort and status, and optionally the [coded-download](#compressed-downloads) ops), and any other front end that delivers an image can drive the same engine.

## Known limits

The transport is classic CAN with 11-bit IDs only: `udsota_can_t.send` takes a `uint16_t` ID and has no extended flag. The image rules assume the ESP-IDF app-image layout (`udsota_image.c` reads `esp_app_desc_t` and the descriptor at fixed offsets), so a port for another platform must produce that layout or bring its own rules. The ISO-TP pad byte is fixed at 0xAA. The adapter defines isotp-c's platform hooks, so no other isotp-c user can link into the same image.

Downloads do not resume: F000 always answers FF, so a client restarts at offset 0. A coded (compressed or delta) download could resume only with its decoder's state saved alongside the slot.

Future work: 29-bit IDs, CAN FD, resumable downloads, and a per-link isotp send callback so that another isotp-c user can share the image.

## Integrating on ESP32

An integration is one C file and two build lines. This is all of it for a product with a parked signal and a self-test:

```c
#include "udsota.h"
#include "udsota_wire.h"
#include "udsota_esp32.h"

#include "udsota_pubkey.h"   /* the tester's 0x27 public key, from `udsota keygen`; it unlocks nothing */

/* Allows each update step only while parked; confirming needs the app's own self-test instead. */
static uint8_t app_gate(void *ctx, udsota_op_t op)
{
    switch (op) {
    case UDSOTA_OP_ENTER_EXTENDED:
        return 0;
    case UDSOTA_OP_CONFIRM:
        return app_self_test_passed() ? 0 : UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    default:
        return app_parked() ? 0 : UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
}

/* Holds the drive interlock while an image is written and activated. */
static void app_phase(void *ctx, udsota_phase_t p)
{
    app_set_drive_inhibit(p == UDSOTA_PHASE_TRANSFERRING || p == UDSOTA_PHASE_ACTIVATING);
}

/* Queues one frame on the app's CAN driver; ESP_ERR_NO_MEM makes udsota keep the frame and retry. */
static esp_err_t app_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    return app_can_write(id, data, len);
}

/* Frames still queued in the driver, so a restart waits until its answer has left. */
static uint32_t app_tx_pending(void *ctx)
{
    return app_can_queued();
}

/* Starts the updater; call it once the CAN driver runs. */
esp_err_t app_updater_start(void)
{
    static const udsota_config_t cfg = {
        .req_id = 0x710, .resp_id = 0x718,
        .key_pubkey = udsota_pubkey, .key_pubkey_len = sizeof udsota_pubkey,   /* the ECDSA mode (Security) */
        .product = "example", .hw_id = 1, .layout_id = 1,
        .stmin_monitor = true,
    };
    const udsota_hooks_t hooks = { .gate = app_gate, .phase = app_phase };
    const udsota_esp32_can_t can = { .can_send = app_send, .tx_pending = app_tx_pending };   /* tx_dropped optional */
    return udsota_esp32_start(&cfg, &hooks, &can);
}

/* The app's CAN receive path: request frames go to udsota before the app decodes anything. */
void app_on_can_rx(uint32_t id, bool extended, const uint8_t *data, uint8_t dlc, uint32_t rx_us)
{
    if (!extended && id == 0x710) {
        udsota_esp32_on_frame((uint16_t)id, data, dlc, rx_us);
        return;
    }
    /* ... the app's own frames ... */
}

/* Boot order: the boot-loop counter runs before anything reads stored settings. */
void app_main(void)
{
    udsota_esp32_bootloop_init();
    if (!udsota_esp32_bootloop_config_ignored()) {
        app_load_settings();
    }
    app_can_start();
    app_updater_start();   /* on an error the updater stays off and the app runs on */
}
```

The image also carries the 32-byte [descriptor](#image-descriptor) that the first-block check reads. Place it once, in any source file of the app, with the values `cfg` expects:

```c
UDSOTA_ESP32_IMAGE_DESC(1, 1, 0x710, 0x718);   /* hw_id, layout_id, request ID, response ID */
```

Then, in that component's `CMakeLists.txt` after `idf_component_register()`, add:

```cmake
udsota_esp32_image_desc(${COMPONENT_LIB})
```

The CMake helper marks the build a release when `PROJECT_VER` is a clean `vX.Y.Z` tag, and it keeps the unreferenced descriptor in the link.

`cfg.product` is the `project()` name of the app, which ESP-IDF stores in `esp_app_desc_t`. `hw_id` and `layout_id` are the product's to allocate; bump `layout_id` whenever the partition table moves. The port copies `cfg`, `hooks` and `can`, but the strings and arrays `cfg` points to must outlive it. Call `udsota_esp32_bootloop_mark_healthy()` once the app has proved itself after boot: the boot-loop counter makes the fourth boot after three crash resets skip stored settings, because rollback cannot help a valid image that crashes on its own config.

## Hooks

Every struct carries its own `ctx`, which is passed back to its callbacks. A NULL hook means "not used", never "refuse".

| Hook | Asked | NULL means |
|---|---|---|
| `gate(ctx, op)` | at each enforcement point in the next table: after the core's own checks, except CONFIRM, where it is asked first | allow |
| `phase(ctx, p)` | on every phase change | nobody is told |
| `did_read(ctx, did, buf, max)` | for a 22 on any DID the core does not serve, unless `did_read_ex` is set; returns the bytes written, 0 for "no such DID" (0x31), or for a DID longer than `max` its length, writing nothing (0x14) | every such DID answers 0x31 |
| `did_write(ctx, did, data, len, access)` | for a 2E outside the default session with at least one value byte (the core answers 0x7F in the default session and 0x13 under 4 bytes first); `data` is the value after the DID, valid only during the call. Returns 0 to answer `6E <did>`, else the NRC | 2E answers 0x11 |
| `routine(ctx, rid, in, in_len, out, out_max, out_len, access)` | for 31 01 on a RID the core doesn't own, outside the default session, unless `routine_ex` is set; `in` is the option record after the RID. `in` and `out` are valid only during the call, so a pending routine copies what it needs. Returns 0 to answer `71 01 <rid>` and `out_len` bytes of `out`, an NRC, or `UDSOTA_PENDING` | such RIDs answer 0x31 |
| `routine_poll(ctx, out, out_max, out_len)` | on every `udsota_poll` while a routine is pending or orphaned; returns as `routine` does, and `out` is again valid only during the call | a routine that returns `UDSOTA_PENDING` answers 0x10 at the first poll |
| `stmin_us(ctx)` | when a request's first frame arrives, for that message's flow control | `cfg.stmin_us` (2 ms) |
| `reset(ctx)` | once the answer to 11 01 or ActivateImage has left (the transport's `tx_pending` reads 0, or after 100 ms); it returns only on failure, and the server then re-opens | in the core, 11 01 answers 0x11 and ActivateImage answers positive without a restart, so the new image boots at the next power cycle. The ESP32 port uses `esp_restart()` |
| `comm_control(ctx, control, comm_type)` | for a 28 that passed the core's checks; returns 0 once the app has stopped or resumed its own frames as asked, else the NRC. Called again with 00 and 03 (enable everything) when the session returns to default after a change | 28 answers 0x11 |
| `dtc_setting(ctx, on)` | after an accepted 85 01 or 85 02, and with `true` when the session returns to default after 85 02 | 85 answers 0x11, as before |
| `progress(ctx, p)` | at the end of a request, poll or other server call that changed the download's stage or wrote a block, at most once per call ([Progress](#progress)); `p` is valid only during the call. Never in a build without the updater | nobody is told; `udsota_progress()` reads the same values |
| `dtc_get(ctx, i, out)` | for each 19 that passes the core's own checks first, from `i` 0 up and never at 0xFFFF or past it. The walk ends at false, at the DTC a 19 06 asks for, or at the first DTC that would overflow a 19 02 or 0A (0x14), so the hook must not rely on being asked until false. It reports the i-th supported DTC, its 3 bytes in the low 24 bits of `out->dtc` (the top byte is ignored), and its status now. `i` must name the same DTC for as long as the server runs; only the status may change. A DTC reported at two indexes is counted and listed twice, and 19 06 answers with the first one's status | 19 answers 0x11, as before |
| `dtc_ext_data(ctx, dtc, record, buf, max, len)` | for a 19 06 once `dtc_get` has reported the DTC (record 00 and a DTC it doesn't report answer 0x31 without a call). `dtc` is the request's 24 bits, whatever top byte `dtc_get` gave it, and `record` is 01–FE, or FF for every record. Writes `<record> <data>...` into `buf`, at most `max` bytes, sets `*len` and returns 0, with `*len` 0 for a record held with no data; else returns 0x31 (no such record) or 0x14 (the records don't fit `max`) | 19 06 answers 0x12 |
| `dtc_clear(ctx, group, access)` | for a 14 of exactly four bytes (the core answers 0x13 to any other length first), physical only, in any session; `group` is the 24-bit groupOfDTC, FFFFFF for every DTC. Returns 0 to answer `54`, else the NRC, checked in ISO order: its session rule (0x7F), its key rule (0x33), then 0x31 for a group it doesn't clear | 14 answers 0x11, as before |
| `did_read_ex(ctx, did, buf, max, len, access)` | in place of `did_read`, for the same DIDs, with the session's access, so a DID can have a session or key rule. Writes the DID into `buf`, at most `max` bytes, sets `*len` and returns 0; a `*len` of 0 or over `max` answers 0x10. Else returns the NRC: 0x31 no such DID, 0x7F not in this session, 0x33 locked, 0x14 too long for `max`, or any other. A functional 22 drops 0x31 and 0x7F as usual | `did_read` answers |
| `routine_ex(ctx, sub, rid, in, in_len, out, out_max, out_len, access)` | in place of `routine`, for every 31 on a RID the updater doesn't own, in every session, the default one included, so the app owns the session rule; `sub` is 01 startRoutine, 02 stopRoutine or 03 requestRoutineResults (SPRMIB cleared; any other answers 0x12 without a call). Returns as `routine` does, and the answer, from `routine_poll` too, is `71 <sub> <rid>` and `out_len` bytes of `out` | `routine` answers, 01 only |

The gate returns 0 to allow, or the NRC to send: 0x22 conditionsNotCorrect in general, a specific code where one fits (0x88 vehicleSpeedTooHigh, 0x90 shifterLeverNotInPark, 0x92/0x93 voltage too high or too low, all ISO 14229-1), or 0x21 busyRepeatRequest for a condition that clears by itself shortly.

| `udsota_op_t` | Request | The core checks first |
|---|---|---|
| `UDSOTA_OP_ENTER_EXTENDED` | 10 03 | nothing |
| `UDSOTA_OP_ENTER_PROGRAMMING` | 10 02 | the boot slot is the running slot, the running image is not pending verify, no flash job runs, and no transfer is open |
| `UDSOTA_OP_START_DOWNLOAD` | 34 | the same, after the key and the message length |
| `UDSOTA_OP_CONTINUE_TRANSFER` | every 36, and every ISO-TP flow-control point inside one (every `block_size` frames) | the STmin monitor, when on; the gate is asked even when the monitor fails, and the answer is then 0x22 whatever it returns |
| `UDSOTA_OP_ACTIVATE` | 31 01 F001 | FF01 has verified the slot (else 0x24), and no flash job runs |
| `UDSOTA_OP_RESET` | 11 01 | no flash job runs |
| `UDSOTA_OP_CONFIRM` | 31 01 F002 | nothing (asked first); then the boot slot must be the running slot, and a pending-verify image is confirmed by the engine, a valid or undefined one answers positive at once, any other state 0x22 |

Without the updater, 10 02 answers 0x12 right after its length checks, since there is nothing to program, so neither ENTER_PROGRAMMING nor the download, activate and confirm ops are ever asked.

A deny during a transfer ends it, except 0x21 on a 36, which the client may retry with the transfer still open. On any other 36 deny the client gets the NRC; at a flow-control point any deny withholds the FC and the client times out. Either way the server drops to the default session, and F1F1 reads reason 11. Reads, TesterPresent, SecurityAccess, 10 01, 37, FF01 and F000 are never gated, because none of them changes what the device runs. Nor are 2E and app routines: the app's `did_write` and `routine` carry that policy themselves.

The phase is IDLE in the default session, and EXTENDED or PROGRAMMING in those sessions. It is TRANSFERRING from an accepted 34 until 37, an abort or a session change, and ACTIVATING from a positive ActivateImage until the restart.

`did_write`, `routine`, `dtc_clear`, `did_read_ex` and `routine_ex` get a `udsota_access_t` by value. `session` is the session in force, and `unlocked_level` is the requestSeed level unlocked in it, or 0 for none. It also reads 0 with security off, so it cannot tell "locked" from "no security"; the app knows which from the security it configured. The updater's own check, `udsota_access_check()` in `udsota_service.h`, does tell them apart: with security off it counts every level as unlocked. `epoch` goes up by one on every session entry, whatever causes it: each accepted 10 0x (a repeat of the current session included), the S3 timeout, `udsota_end_session`, the 90 s cap, the restart, a 36 the gate or the STmin monitor refuses with anything but 0x21, and a withheld flow control. The core applies only the ISO session rule, so the app decides which session and level each write or routine needs. An app that keeps state across requests, such as writes staged for a later commit routine, records the epoch it started under and drops the state when the epoch changes, so a second tester never inherits the first one's session. `udsota_init` restarts the epoch at 0, so such state must not outlive a re-init either.

A routine that returns `UDSOTA_PENDING` is a job like FF01: the core answers 0x78 on the flash-job cadence and every other request but 3E with 0x21, and at 90 s answers 0x10 generalReject and ends the session, where the updater's own jobs answer 0x72, which reports a programming failure. The routine is then orphaned. Until `routine_poll` stops returning `UDSOTA_PENDING`, every "no flash job runs" condition in the op table fails, so the programming session, and with it 34 and ActivateImage, is out of reach until the orphan ends: with the updater 10 02 answers 0x22 (without it, 0x12 as always), and so does 11 01. A 31 on an app RID answers 0x22 too, without calling the hook: with `routine_ex` any of 01, 02 and 03 in any session, with `routine` a 31 01 outside the default session, where 0x7F comes first. A routine that can outlast 90 s should leave its outcome where a client can read it, such as a DID, or with `routine_ex`, its requestRoutineResults.

The hooks run in the server's context, which in the ESP32 port is the diag task. The gate is asked at flow-control points while frames stream in, so it must read a snapshot the app keeps current, return at once and never block. The phase hook must not wait on anything either, and neither may `did_read_ex`, `did_write`, `routine`, `routine_ex`, `routine_poll`, `progress` or the three DTC hooks: work that takes time runs elsewhere, and the routine reports it through `UDSOTA_PENDING` and `routine_poll`. The progress hook must not call any udsota function, and the DTC hooks none but `udsota_phase()`; they read the app's fault table under the app's own lock.

## Adding DIDs, routines and services

An app adds its own diagnostics through the hooks, without touching udsota. A 22 on a DID the server doesn't serve goes to `did_read`, a 2E to `did_write`, and a 31 01 on a RID the server doesn't own to `routine`, which answers at once or returns `UDSOTA_PENDING` and finishes through `routine_poll` ([Hooks](#hooks)). `did_read_ex` and `routine_ex` take their place when set: a DID then gets the session's access, so it can need the extended session or a key, and a routine gets stopRoutine and requestRoutineResults too, in every session. The app's fault codes reach any UDS tester through `dtc_get`, `dtc_ext_data` and `dtc_clear`, which serve 19 and 14 while the core owns their framing. `did_write`, `routine` and the `_ex` hooks get the session, unlocked level and epoch in `udsota_access_t`, so the app decides what each one needs; `gate` is its say over the server's own steps. Without the updater the updater's DIDs and RIDs reach the same hooks ([Data identifiers](#data-identifiers)). Turning the updater on later takes them back silently: the app's `did_read` or `did_read_ex` then never sees F1F1, nor F189, F1F0 or F1F3 while the engine sets its source (`version`, `status`, `running_sha`), and its `routine` or `routine_ex` never sees FF01, F000, F001 or F002.

A new UDS service, a SID of its own, belongs in the server core on the pattern of 28 and 85: a handler in `server/udsota_server.c` that makes the core's checks (session, length, sub-function) and hands the app's part to a new hook in `udsota_hooks_t`, whose NULL answers 0x11, and a CHANGELOG entry, since the SID is on the wire. `udsota_service.h` is how the updater registers, one service per server; it is not an app API.

## Progress

An app that draws an update, with a bar or a percentage, reads the download's stage and bytes from `udsota_progress()` in the server's context, or takes them from the optional `progress` hook as they change; in the ESP32 port any task reads them with `udsota_esp32_progress()`. The phase alone cannot drive a bar: it reads TRANSFERRING from the 34 to the 37, erase included, and PROGRAMMING through the verify. Both give a `udsota_progress_t`: the `stage`, `done` and `total` in image bytes, and `last_reason`, the last download's F1F1 reason, so a display that falls back to IDLE can say that the update failed, and why. `udsota_progress_permille()` turns `done` and `total` into 0 to 1000 with 64-bit arithmetic. `last_reason` describes a finished download, so read it only in IDLE: during FF01 it reads 10 (worker timeout), as F1F1 does, until the verdict replaces it. In the ESP32 port `udsota_esp32_incoming_version()` also names the image arriving, so a display can say "Installing v0.3.1". Progress is the updater's: without it the phase never reads TRANSFERRING or ACTIVATING, `progress` is never called, and `udsota_progress()` and `udsota_progress_permille()`, in `update/udsota_update.c`, are not in the core.

| Stage | From | Until | `done` / `total` |
|---|---|---|---|
| IDLE | init, and every end below | an accepted 34 | 0 / 0 |
| ERASING | an accepted 34 | the first 36 is accepted; the first-block check and the erase run in that 36's job | 0 / memorySize |
| WRITING | the first accepted 36 | FF01 starts; after the 37, `done` equals `total` | image bytes written / memorySize |
| VERIFYING | FF01's job starts | its verdict, then IDLE | 0 / 0: engines report no hash progress, so it is indeterminate |
| ACTIVATING | a positive ActivateImage | the restart | 0 / 0 |

A download also returns to IDLE when it ends early: an abort, a session change, S3, the 90 s cap, a refused first block, a corrupt stream or patch, a delta for another base, or a failed write. `last_reason` then says which, as F1F1 does (reason 11, 10, 1 to 7, 12, 13 or 15). Within a download `done` only grows and never passes `total`: a resent block, a 36 refused for its counter or with 0x21, and a 0x78 leave it where it was. A new 34 starts it at the download's offset, which is 0 while GetResumePoint answers "not available".

A [compressed download](#compressed-downloads) counts `done` the same way, in image bytes, not in the compressed bytes its 36s carry. After each 76 the server takes the stream's count of bytes written from the engine's optional `zwritten` (`udsota_coded_written()`, the image sink's `written`), and once the 37 closes the stream it sets `done` to `total`. The stream holds its first bytes back until the first-block check has 320 of them, so WRITING can start with `done` at 0 and stay there for a block or two; the last 76 already reads `total`, because the stream writes what it held when it ends. An engine without `zwritten` shows `done` at 0 through the 36s and at `total` after the 37. A compressed 34 refused for memory stays IDLE and changes only `last_reason`, to 14, and the hook reports that too. Between a passed FF01 and a positive ActivateImage the stage reads IDLE with reason 0, so a display that saw VERIFYING can hold at "verified" there rather than treat it as idle.

The hook runs at the end of the call that changed the stage or `last_reason`, or wrote a block, and never more than once per call, so during a transfer of 4 KB blocks it runs about once a second. A 0x78 never calls it. Like every hook, it runs in the server's context and must not block; with it NULL, every answer is the same bytes.

How the stages share one bar is the app's policy: erase 0–2 %, write 2–95 %, verify 95–99 % and activate 99–100 %, say. Progress stays off the wire, since a client counts its own; a DID can carry it later if telemetry needs one. After the restart the stage reads IDLE, and whether the client confirmed the new image is F1F0's to say.

## Integrating safely

udsota enforces its own sequence and nothing else: with no gate, every step is allowed whenever the sequence allows it. What makes an update safe is the product's to decide, which is also where AUTOSAR's Dcm and UNECE R156 put it. These are the decisions an integrator makes.

**Keep the machine still.** Gate ENTER_PROGRAMMING, START_DOWNLOAD and CONTINUE_TRANSFER on the product's safe state. Use `phase` to hold a drive interlock while the phase is TRANSFERRING or ACTIVATING, since R156 asks that a vehicle "cannot be driven during the execution of the update". CONTINUE_TRANSFER is asked every `block_size` frames, so a transfer stops within one block of the state changing. Deny a condition that clears by itself, such as a brief voltage dip, with 0x21, the one answer that can keep a transfer open for the client's retry, but only when the gate is asked for the 36 itself. At a flow-control point inside a 36, its first frame included, any deny ends the transfer, 0x21 too, and the gate cannot tell the two asks apart ([Hooks](#hooks)). A multi-frame 36 reaches its first frame's flow-control point before its handler, so a dip that starts between blocks still ends the transfer, and since downloads do not resume, the client then sends the whole image again. ACTIVATE and RESET both restart the device, so gate them on the same state.

**Let the client confirm.** With rollback on, the client's ConfirmImage is the proof that CAN works on the new image. Gate CONFIRM on the app's own health, and on a soak if it needs one (30 s of uptime, say). Don't call `esp_ota_mark_app_valid_cancel_rollback()` from the app: an image confirmed without the client may have a broken CAN path that only a workshop visit can fix.

**One tester, one device.** udsota answers one request at a time on one ID pair. If two devices can share the pair, both would install the image. Detect a twin in the app, refuse ENTER_EXTENDED and ENTER_PROGRAMMING in the gate, and call `udsota_esp32_end_session()` for as long as the twin is heard: a repeat is harmless, because the request is latched and runs once.

**Frames in.** Hand udsota only standard (11-bit) frames on `cfg.req_id`. `udsota_esp32_on_frame()` takes a 16-bit ID, so an extended ID would be truncated and could alias the request ID. Take `rx_us` in the receive path, as close to the driver as possible, because the STmin monitor measures the gaps between those stamps.

**Frames out.** udsota transmits only on `cfg.resp_id`. `ESP_ERR_NO_MEM` from `can_send` means retry: an answer is parked and resent for up to 1 s (`UDSOTA_ISOTP_PARK_MAX_MS`), so a bus that acknowledges nothing cannot hold a session open, and a flow-control frame is retried at each service (1 ms apart) for `cfg.fc_retry_ms` (10 ms by default), then dropped. Set it to two token intervals of the driver's rate cap, or an FC refused just after an answer never reaches the next token. Any other error drops the frame. The port logs these losses; F1F2's `resp_frames_dropped` reports only what the app's `tx_dropped` counts. The app's CAN driver is the place for a rate cap or an allowlist that bounds what a fault could put on the bus.

**Pace.** STmin is the client's minimum gap between frames. Pick one the bus can carry beside its normal traffic, either `cfg.stmin_us` or a per-message value from `stmin_us`. The adapter rounds it up to a value a flow-control frame can carry (100–900 µs in 100 µs steps, else whole milliseconds up to 127 ms), and the monitor judges that value. Set `stmin_monitor` to stop a client whose median gap is under 0.8 × STmin.

**Keys and signing** are covered below. Without either, any node that can send on `cfg.req_id` can install any image the image rules accept.

## Security

With security on (the ESP32 port turns it on when `cfg.key_pubkey` or `cfg.key_label` is set), SecurityAccess (27) guards programming. `cfg.level_programming` (default 0x03) unlocks 34, 36, 37, FF01, ActivateImage and 11 01, and `cfg.level_extended` (default 0x01) unlocks 11 01. ConfirmImage (F002) needs no key by design, because it can only keep an image that passed FF01 and ActivateImage. The CONFIRM gate is its only guard: any node on the bus can confirm a pending-verify image the gate lets through, so gate it on the app's own health ([Let the client confirm](#integrating-safely)).

Each 16-byte seed is single-use and valid for 30 s. What the tester sends back in 27 02 or 27 04 depends on the mode. In both, `level` is the requestSeed sub-function and `device_id` is what F18C returns.

- **ECDSA** (recommended for production). The key is a 64-byte ECDSA P-256 signature, r ‖ s with 32 big-endian bytes each, over SHA-256("udsota-27-ecdsa-v1" ‖ seed ‖ level ‖ id_len ‖ device_id), where `id_len` is one byte; `udsota_keys_sig_msg()` builds the message. The tester signs with a private key that never leaves it, and the device holds only the public key. The server asks `security.verify` with `security.key_len` set to 64, so a sendKey is exactly 66 bytes. A high S is accepted as well as a low one: a seed is used once, so a second valid signature for it gains nothing. This follows SAE paper 2022-01-0132, as driftregion's iso14229 fwupdate example does with RSA.
- **HMAC** (the default, as in 0.1.0). The key is the first 16 bytes of HMAC-SHA256(K_dev, seed ‖ level ‖ device_id), where K_dev = HMAC-SHA256(K_master, label ‖ device_id). The server asks `security.key` for the expected key and compares the two in constant time.

Use ECDSA for a product. In the HMAC mode every device must be able to compute its own keys, so the port builds the fleet's master key into every image, and one leaked image or one flash dump unlocks every device. In the ECDSA mode a device stores nothing that makes a key: a dump yields a public key, and a signature for one seed only unlocks one level of one device, once. So keep the private key in an HSM or a signing service that answers seeds for authorised testers, never in a repository or an image. `udsota keygen` makes a key pair. The HMAC mode still suits a bench, or a fleet whose images and flash are protected (flash encryption) and whose master can be rotated.

The ESP32 port serves `cfg.device_id` as F18C and binds the keys to it when it is set (1 to 16 bytes), otherwise to the 6-byte base MAC. It picks the ECDSA mode when `cfg.key_pubkey` is set (65 bytes, 04 ‖ X ‖ Y), and the HMAC mode when only `cfg.key_label` is. A software P-256 verify takes tens of milliseconds on chips without an ECC accelerator, such as the ESP32 and ESP32-S3, so a sendKey answer may come after P2 (50 ms). The udsota client waits 150 ms. For a tester that holds the server to its announced P2, raise `cfg.p2_prog_ms` for `level_programming`, whose 27 03/04 run in the programming session, and `cfg.p2_ms` only for `level_extended`. A port for another platform sets `verify` to its own P-256 verify over the same message.

Three wrong keys answer 0x36, then 0x37 for 10 s, and the same 10 s delay follows every boot. An unlock ends at a session change, an S3 timeout or a reset. When no key can be checked, security stays on and no key matches: sendKey answers 0x22 and counts no attempt. That happens with a label but no master (a CI build, say), with a public key that PSA refuses, when the port's start-up self-test of its HMAC or ECDSA fails, or when `udsota_init()` was given a `security` with neither `key` nor `verify`, which it also reports by returning false. A `security` with no `rng16` is refused the same way: requestSeed answers 0x22, so no seed is ever issued.

With `security` NULL, or both `cfg.key_pubkey` and `cfg.key_label` NULL in the port, 27 answers 0x11, and the programming session, the download, activation and reset need no key.

## Rollback and confirm

With `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, ActivateImage makes the verified slot the boot slot and restarts, and the new image boots pending verify: F1F0 shows running state 2, and `udsota_esp32_image_unconfirmed()` is true. The client then sends 10 03 and 31 01 F002, and the engine marks the image valid (the op table above has the checks first). A reset before that boots the old image again, so an update the client never confirms is lost, never half-installed.

Without rollback, the restart after ActivateImage makes the new image permanent. It never reads pending verify, so once the gate allows CONFIRM the core answers positive without calling the engine. The only way back from a bad image is another update: over CAN if the image still answers, over serial if not.

## Signing

udsota_esp32 adds no signing guard: FF01 checks whatever the build checks. With `CONFIG_SECURE_SIGNED_ON_UPDATE`, which both app signing (`CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT`, no eFuse) and Secure Boot v2 set, `esp_ota_end()` checks the signature, and FF01 reports a bad or missing one as reason 8. Without it, `esp_ota_end()` checks only a SHA-256 that anyone can compute.

So turn signing on, sign every build, and keep the key out of the repository. Add a compile-time guard of your own if you want one, an `#error` unless `CONFIG_SECURE_SIGNED_ON_UPDATE` is set. F1F0 flag 0x01 tells a client whether the running build checks signatures. The image rules add a version rule on top, so a bad release is replaced by rolling forward, never back.

## Image rules

The first 36 block is checked before anything is erased, and FF01 checks the whole image again. A first-block refusal answers 0x31, and F1F1 records the [reason](#reason-codes):
- **Header (the port's check):** the chip ID and revision, and a flash mode that matches the running app's (ESP-IDF's `esp_ota_check_image_validity()`); then the ESP image magic, a valid segment count, and the app descriptor's magic (1).
- **Product:** the app's project name must be `cfg.product` (2).
- **Descriptor:** its magic, a version of at least 1, and `hw_id` must match `cfg.hw_id` (3). Its layout must match `cfg.layout_id` (4), and its IDs must match `cfg.req_id` and `cfg.resp_id` (5).
- **Version:** a release, meaning the descriptor's release flag and a clean `[v]X.Y.Z` version, must be newer than the running image by SemVer precedence, so `v1.2.3` installs over `v1.2.3-rc1`. A dev build needs at least the running core version (6). A version that doesn't parse, or a flag that disagrees with the version, is refused (1).
- **Size:** a 34 announcing more than the slot holds answers 0x31 and leaves F1F1 unchanged.

## Compressed downloads

A 34 with dataFormatIdentifier 0x10 opens a download whose 36 blocks carry the image as one raw DEFLATE stream (RFC 1951, no zlib or gzip header). An ESP-IDF app image usually deflates to 50–65 %, and at about 3.2 KB/s on the bus that takes an update of a 1.2 MB image from about 6 minutes to about 3½ to 4. The image itself, its signature, the slot and every rule are unchanged: the device inflates the stream and writes the bytes an uncompressed download would have written.

The 34's memorySize is the uncompressed size, so the slot-size check, the erase and the image rules see the image as before. The block counter, 36 lengths, maxNumberOfBlockLength and the 0x78 pacing are those of any download, and a repeated block is answered without being inflated twice. The server holds the inflated bytes until 320 of them are out, across as many 36s as that takes, then runs the first-block check, and only then erases, so nothing is erased for an image the rules refuse. A block the rules refuse answers 0x31 with their reason in F1F1, as an uncompressed first block does. So does a corrupt stream or one inflating past memorySize, with reason 13, and a stream that ends before 320 bytes are out, with reason 1. The compressed bytes may exceed memorySize by at most an eighth plus 1,024 (`UDSOTA_DL_Z_BOUND`), past which a 36 is an overrun (0x71). The 37 closes the transfer only once the stream has ended at exactly memorySize bytes with nothing after it; otherwise it answers 0x72, the download ends and F1F1 reads reason 13. F1F1's byte count is the compressed bytes accepted.

A server takes DFI 0x10 when its engine sets `zbegin`, `zwrite` and `zend` and names it in `zformats` (`UDSOTA_DL_FMT(0x10)`). With them NULL, a 34 with DFI 0x10 answers 0x31, and every answer is byte for byte what it was before compression existed. A product that never takes compressed downloads can also build `update/udsota_update.c` with `UDSOTA_COMPRESSION` defined as 0: the server then answers the same way whatever the engine sets, and none of the compressed handling is compiled in. The structs keep their layout either way. The ESP32 port defines it for the `udsota` component while `UDSOTA_ESP32_COMPRESSION` is off. The core includes no compression library. Instead `udsota_zstream.h` gives an engine the stream logic over any `udsota_inflate_t` (`init`, `feed`, `finish`), and `components/udsota_inflate` supplies one on miniz's tinfl: the ROM's copy under ESP-IDF, which every v6.1 target has, and miniz 3.0.2, vendored unpatched, elsewhere (the host). `zbegin` opens the stages with `udsota_coded_open()` (a `udsota_zstream_t` for 0x10) over the engine's synchronous check, erase and write, `zwrite` feeds them, and `zend` runs their 37 check; the engine decides where the inflating runs, which in the ESP32 port is the flash worker. tinfl needs a 32 KB dictionary and its state, which is 11,008 bytes for the ROM's copy and 8,408 for the vendored miniz on a 64-bit host, both allocated at the 34 and freed at the 37 or abort, never at boot. A 34 that finds no memory answers 0x22 with reason 14 in F1F1. It opens no download, but a finished image that never passed FF01 has already been released by then, so FF01 answers 0x24 and the client downloads the image again. The image sink's `written` count is the image bytes written so far, which the optional fourth op, `zwritten`, hands the server for [progress](#progress); F1F1 counts compressed bytes.

Two things differ from an uncompressed download. A 37 sent before the stream has ended answers 0x72 and ends the download, where an uncompressed one sent early answers 0x24 and leaves the transfer open. And `udsota_init()` never calls `engine.abort`, so a `zbegin` must cope with a stream a lost session left open, closing it before it opens the next.

## Delta downloads

A 34 with dataFormatIdentifier 0x20 or 0x30 opens a download whose 36 blocks carry a patch from the image the device runs, and the device rebuilds the new image from its running slot into the other one. A small code change then costs kilobytes on the bus instead of the whole image: for the ESP32 example, a one-line change to its 314,112-byte image is a 5,493-byte patch under 0x20 and a 1,027-byte one under 0x30, against a 192,794-byte DEFLATE stream, so at about 3.2 KB/s the time on the bus drops from about a minute compressed to under 2 s. The rebuilt image goes through everything a full one does, the first-block check before any erase, FF01's hash and signature check, ActivateImage and the confirm, so a patch that is wrong or hostile can at worst produce an image that fails them. The running slot is only ever read.

The patch is Espressif's `esp_delta_ota` format: a 64-byte header, the magic `0xfccdde10` (little-endian), the base image's 32-byte SHA-256 (the hash an ESP-IDF image appends, which `esp_partition_get_sha256()` returns) and 28 reserved bytes, then a detools sequential bsdiff patch. Under 0x20 the patch is heatshrink-compressed (window 8, lookahead 7), byte for byte what Espressif's `esp_delta_ota_patch_gen.py` writes. Under 0x30 it is uncompressed and the whole thing, header included, is one raw DEFLATE stream, which is usually several times smaller. The device takes either inner form under either DFI.

memorySize is the new image's size, as for 0x10, and `UDSOTA_DL_Z_BOUND` bounds the bytes the 36s carry. Once the header is whole, and before anything is erased, a wrong magic is reason 13 and a base hash other than the running image's is reason 15, `UDSOTA_DL_BAD_BASE`; both answer the 36 with 0x31, and after reason 15 a full download works. So does a patch that would rebuild another size than memorySize (reason 13), and a rebuilt first block the image rules refuse (their reason). A corrupt patch, a read of the base outside the running slot, output past memorySize, or any byte after the patch's end answers 0x31 with reason 13 at whichever 36 finds it. The 37 closes the transfer only once the patch has ended and the image is exactly memorySize bytes, all written; otherwise it answers 0x72 with the failure's reason: 13 for a patch that is short or a DEFLATE stream with bytes after its end, 12 for a flash write that fails, or the image rules' reason for a small image whose first block only comes out at the 37. A compressed patch's decoder can still hold the image's last bytes when the input ends, so the 37 may write flash: `zend` may return `UDSOTA_PENDING`, and the server answers 0x78 until the job ends, as for a 36. F1F1 counts the coded bytes accepted, and progress the image bytes rebuilt. Delta downloads cannot resume.

A server serves a coded DFI only when its engine names it in `engine.zformats` (`UDSOTA_DL_FMT(0x10) | ...`) and sets the z ops; `zbegin` gets the DFI. Any other DFI answers 0x31 before anything changes, exactly as an unknown one, with F1F1 untouched and an image that has not yet passed FF01 kept. The core includes no patch library. `udsota_patch.h` gives an engine the patch stage over any `udsota_patch_t` decoder (`init`, `feed`, `finish`) and a `udsota_pbase_t` for the running image (a bounded `read` and its `hash`), and `components/udsota_delta` supplies a decoder on detools 0.53.0's C side, vendored unpatched; its whole state is under 800 bytes. The rule "nothing is erased before the first block passes" lives in one place, the image sink (`udsota_isink.h`), which the compressed stream and the patch stage both write through, and `udsota_coded.h` chains the stages for a DFI (0x10 inflate → image, 0x20 patch → image, 0x30 inflate → patch → image), so an engine supplies only its sink, buffers and decoders. detools moves the base offset with no check of its own, so the decoder refuses a read that goes negative, and the engine's `read` must refuse one past the running slot (the ESP32 port bounds it by the partition: a signed image's signature block, which a patch may read, lies past the image's own length). The ESP32 port serves 0x20 and 0x30 with `UDSOTA_ESP32_DELTA`, and the client sends them with `flash --diff-from`.

## Client

[`client/`](../../client/README.md) is a generic PC client for Linux and SocketCAN. A product's TOML profile holds everything product-specific; the built-in `example` profile carries the values used here, and `udsota --profile example flash <image>` runs the whole sequence, from the precheck to ConfirmImage.

## Wire reference

### Services

| SID | Service | Accepts | Session | Key |
|---|---|---|---|---|
| 10 | DiagnosticSessionControl | 01 default, 02 programming (with the updater; 0x12 without), 03 extended; answers `50 xx` then P2 and P2*/10 as two big-endian words (`00 32 01 F4` by default) | any | – |
| 11 | ECUReset | 01 hardReset: answers, then restarts through `reset` | extended, programming | either level |
| 14 | ClearDiagnosticInformation (with `dtc_clear` only) | exactly a 3-byte groupOfDTC, FFFFFF for every DTC; answers `54` | the app's choice | the app's choice |
| 19 | ReadDTCInformation (with `dtc_get` only) | 01 reportNumberOfDTCByStatusMask, 02 reportDTCByStatusMask, 06 reportDTCExtDataRecordByDTCNumber (with `dtc_ext_data` only), 0A reportSupportedDTC; answers `59 xx` | any | – |
| 22 | ReadDataByIdentifier | one DID per request | any | – |
| 27 | SecurityAccess | `level_extended` and the next sub-function in extended, `level_programming` and the next in programming; a sendKey carries exactly 16 key bytes, or 64 in the ECDSA mode | extended, programming | – |
| 2E | WriteDataByIdentifier | one DID and at least one value byte, through `did_write`; answers `6E <did>` | extended, programming | the app's choice |
| 31 | RoutineControl | 01 startRoutine; with `routine_ex`, 02 stopRoutine and 03 requestRoutineResults on the app's RIDs | per routine | per routine |
| 34 | RequestDownload | DFI 00, or 10 (raw DEFLATE), 20 (a delta patch) or 30 (a delta patch as raw DEFLATE) when `engine.zformats` names it; any ALFID whose nibbles are each 1–4, the low one the address's bytes and the high one the size's (the client sends 44), address 0, 0 < size ≤ slot, size being the image; answers `74 20 0F FF` (`cfg.max_block_len`, 4,095 by default, which the ISO-TP adapter caps at `UDSOTA_ISOTP_RX_MAX`) | programming | programming |
| 36 | TransferData | block counter from 01, wrapping FF to 00, and up to `cfg.max_block_len` − 2 data bytes (4,093 by default), coded after a DFI 10, 20 or 30; a repeat of the last counter is answered and not rewritten | programming | programming |
| 37 | RequestTransferExit | once every announced byte has arrived, or after a coded DFI once the stream or patch has ended at exactly the announced size | programming | programming |
| 3E | TesterPresent | 00; 80 suppresses the answer | any | – |
| 28 | CommunicationControl (with `comm_control` only) | controlType 00–03 and a communicationType naming normal or network-management messages; answers `68 xx` | extended, programming | – |
| 85 | ControlDTCSetting (with `dtc_setting` only) | 01 on, 02 off, with any option record; answers `C5 xx` | extended, programming | – |

Every status byte 19 sends is the DTC's status ANDed with `cfg.dtc_availability_mask` (0 = 0xFF), which 59 01, 02 and 0A also carry, and a DTC matches a status mask when status & mask & availability is non-zero. `cfg.dtc_format` is 59 01's DTCFormatIdentifier, sent as given: 0x00 for SAE J2012 OBD codes with a failure-type byte, 0x01 for ISO 14229-1's. A 19 answer that would pass the response buffer answers 0x14 rather than a list cut short: through the ISO-TP adapter a list holds (`UDSOTA_ISOTP_RESP_MAX` − 3) / 4 DTCs, 63 at the default 256 bytes.

Any other SID answers 0x11, and so do 2E without `did_write`, 19 without `dtc_get`, 14 without `dtc_clear` and, without the updater, 34, 36 and 37. While a flash job or a pending app routine runs, every request but 3E answers 0x21. The key column applies only with security on. A return to the default session, by 10 01, S3 or an end of session, undoes 28 and 85 through their hooks.

### Functional addressing

With `cfg.func_id` set (OBD's broadcast ID is 0x7DF), the port hands single frames on that ID to `udsota_isotp_on_func_frame()`, and the answers go out on `cfg.resp_id` as usual. This lets a tester send 3E 80 to every device on the bus, or switch them all to the extended session and quiet them with 85 02 and 28 03 before it programs one of them. A functional request is served only when it is 10 01, 10 03, 3E, 19, 22, 28 or 85, as a single frame, and while no other request or answer is in progress (`functional_served()` in `udsota_server.c` is the one list, and `test_functional_answers_only_its_sids` checks, with every hook set and in every session, that no other SID ever answers); anything else gets no answer at all, including a 10 02, since the programming session is entered physically on the one device being programmed. NRCs 0x11, 0x12, 0x31, 0x7E and 0x7F are suppressed for a functional request, as ISO 14229-1 asks, so a device that serves none of a request stays silent: a functional 19 06 is answered only by the devices that have the DTC. 14 stays physical, since clearing needs a per-device unlock. While a flash job or a pending app routine runs only a functional 3E is answered.

### Routines

| RID | Routine | Session, key | Does |
|---|---|---|---|
| FF01 | CheckProgrammingDependencies | programming, programming | verifies the written image: hash, signature, and the image rules on the bytes in flash. Answers a status byte, 00 or a reason code. A pass marks the slot verified until the next 34 or reboot |
| F000 | GetResumePoint | programming, programming | reserved for resume; answers status FF, not available, after any download, compressed or not |
| F001 | ActivateImage | programming, programming | needs the slot verified (else 0x24); makes it the boot slot, answers, then restarts |
| F002 | ConfirmImage | extended, none | needs the boot slot; confirms a pending-verify image, answers positive for one already valid or undefined, else 0x22 |

A 31 in the default session answers 0x7F, and a sub-function other than 01 answers 0x12. A RID in this table that isn't served in the current session answers 0x31. Every other RID goes to `routine` with its option record, and answers 0x31 when `routine` is NULL. These four are the updater's: without it they go to `routine` like any other.

With `routine_ex` set, a 31 under 4 bytes answers 0x13 in every session, and these four answer as without it. Every other RID reaches `routine_ex` in every session, with sub-function 01, 02 or 03; any other answers 0x12.

### Data identifiers

| DID | Content | Source |
|---|---|---|
| F186 | active session, 1 byte | the server |
| F189 | running version string | `engine.version` |
| F18C | device ID | `cfg.device_id` (the ESP32 port's base MAC when it is NULL) |
| F1F0 | update status, 16 bytes | `engine.status` |
| F1F1 | last download result, 5 bytes | the updater |
| F1F2 | counters, 16 bytes | the server and the transport |
| F1F3 | running image `app_elf_sha256`, 32 bytes | `engine.running_sha` |

Every other DID goes to `did_read`, or `did_read_ex` when set, and so does any of these whose source is NULL. Without the updater (`udsota_core_init`, or `udsota_init` with a NULL engine) only F186, F18C and F1F2 are the server's: F189, F1F0, F1F1 and F1F3 go to the app's hook too.

### Negative responses

| NRC | Name | udsota sends it for |
|---|---|---|
| 0x10 | generalReject | a `routine`, `routine_ex` or `routine_poll` return that is not 0, an NRC or `UDSOTA_PENDING`, or an `out_len` over `out_max`; a `dtc_ext_data` `*len` over `max`; a `did_read_ex` `*len` of 0 or over `max`; a pending routine with no `routine_poll`, or still running at 90 s; a requestSeed whose answer has no room in the response buffer |
| 0x11 | serviceNotSupported | an unknown SID; 27 with security off; 11 01 with no `reset` hook; 28 with no `comm_control` hook; 85 with no `dtc_setting` hook; 2E with no `did_write` hook; 19 with no `dtc_get`, 14 with no `dtc_clear` |
| 0x12 | subFunctionNotSupported | an unknown sub-function, 19 06 with no `dtc_ext_data`, and 10 02 without the updater |
| 0x13 | incorrectMessageLengthOrInvalidFormat | a wrong length, or more than one DID in a 22 |
| 0x14 | responseTooLong | a 22 or 19 answer past the response buffer, or `dtc_ext_data`'s records past its `max` |
| 0x21 | busyRepeatRequest | any request but 3E while a flash job or a pending app routine runs; or the gate's choice |
| 0x22 | conditionsNotCorrect | a core-owned condition, the gate, or no memory, slot or worker for a coded download's decoder |
| 0x24 | requestSequenceError | a step out of order: 36 with no download open, 37 before the last byte, FF01 before 37, F001 before FF01, or a key with no live seed |
| 0x31 | requestOutOfRange | an unknown DID or RID, 34 parameters or size (an ALFID nibble outside 1–4, or a coded DFI the engine does not serve, among them), a first block the image rules refuse, a coded block that is corrupt or decodes past the announced size, or a delta patch with the wrong magic, size or base; a 19 06 for a DTC `dtc_get` doesn't report or for record 00 |
| 0x33 | securityAccessDenied | a keyed service while locked |
| 0x35 | invalidKey | a wrong key |
| 0x36 | exceedNumberOfAttempts | the third wrong key |
| 0x37 | requiredTimeDelayNotExpired | 27 within 10 s of boot or of a lockout |
| 0x71 | transferDataSuspended | a 36 that would overrun the announced size (for a compressed download, `UDSOTA_DL_Z_BOUND` of it); the download ends |
| 0x72 | generalProgrammingFailure | an erase, write, activate or confirm failure, a flash job past 90 s, or a coded 37 that fails (the stream or patch had not ended at exactly the announced size, a flash write, or the image rules) |
| 0x73 | wrongBlockSequenceCounter | a 36 counter that is neither the next nor a repeat |
| 0x78 | responsePending | a flash job or app routine still running after 40 ms, repeated every 1.5 s |
| 0x7E | subFunctionNotSupportedInActiveSession | a 27 level that belongs to the other session |
| 0x7F | serviceNotSupportedInActiveSession | 11, 27, 28 or 85 in the default session, 31 there without `routine_ex` (with it, the updater's RIDs only), and 2E there when `did_write` is set; 34, 36 or 37 outside programming |

`did_write`, `routine`, `routine_ex`, `routine_poll`, `did_read_ex`, `dtc_ext_data` and `dtc_clear` may answer any NRC the app picks but 0x78.

### Timing

P2 is 50 ms and P2\* 5,000 ms (`cfg.p2_ms`, `cfg.p2star_ms`); the programming session can have its own (`cfg.p2_prog_ms`, `cfg.p2star_prog_ms`), which its 10 02 answer carries and its 0x78 cadence follows. S3 is 5 s after the last answer (`cfg.s3_ms`); it pauses while a multi-frame request arrives, and its expiry returns the server to the default session, which aborts a download. A flash job or app routine not done within four fifths of P2 (40 ms) gets 0x78, repeated every three tenths of P2\* (1.5 s), and at 90 s the server answers 0x72, or 0x10 for an app routine, and ends the session.

ISO-TP flow control uses a block size of 64 (`cfg.block_size`) and an STmin of 2 ms, with frames padded with 0xAA. N_Cr is 1 s. The receive limit is 256 bytes, or `cfg.max_block_len` (4,095 by default) while a download is open.

Two build-time sizes set the adapter's buffers, 2 × `UDSOTA_ISOTP_RX_MAX` + 3 × `UDSOTA_ISOTP_RESP_MAX` bytes, 8,958 at the defaults. Define them alike for every file that includes `udsota_isotp.h`, since they size `udsota_isotp_bufs_t`; the ESP32 port sets them from Kconfig. `UDSOTA_ISOTP_RX_MAX`, the largest request (4,095 by default), runs from 66, an ECDSA sendKey, to 4,095. The adapter caps `cfg.max_block_len` at it, so the 74 answer and the download's receive limit follow it, and outside a download the limit is RX_MAX when that is under 256. With the updater it must be at least 322, for the first block's 320 image bytes; a server alone never takes a request over 256 bytes, so 256 is all it needs. `UDSOTA_ISOTP_RESP_MAX`, the largest answer (256 by default), runs from 35, which holds F1F3, to 4,095, and a 22 or 19 answer longer than it answers 0x14.

### Status (F1F0)

| Byte | Field | Values |
|---|---|---|
| 0 | `running_slot` | 00 ota_0, 01 ota_1, FF factory or unknown |
| 1 | `running_state` | 0 undefined, 1 new, 2 pending verify, 3 valid, 4 invalid, 5 aborted |
| 2 | `boot_slot` | as byte 0: the slot the next boot runs |
| 3 | `other_slot_state` | 0 empty, 1 holds an unverified image, 2 being written, 3 verified since boot (ActivateImage may use it), 4 rolled back |
| 4–6 | `other_version` | major, minor, patch; 0.0.0 when empty; the rolled-back image's when byte 3 is 4 |
| 7–14 | `other_elf_sha_prefix` | the first 8 bytes of the other slot's `app_elf_sha256` |
| 15 | `flags` | 0x01 updates are signature-checked; 0x02 this boot ignored stored settings (boot-loop counter); other bits are sent as 0 |

### Last download (F1F1)

| Byte | Field | Values |
|---|---|---|
| 0 | `reason_code` | a [reason code](#reason-codes) |
| 1–4 | `bytes_received` | data bytes accepted by 36, big-endian; compressed bytes for a compressed download |

### Counters (F1F2)

Eight big-endian 16-bit counters, each holding at 0xFFFF.

| Bytes | Field | Counts |
|---|---|---|
| 0–1 | `seq_errors` | wrong block counters (0x73) |
| 2–3 | `ncr_timeouts` | requests whose sender went silent mid-message |
| 4–5 | `repeated_blocks` | repeats of the last block, answered without a rewrite |
| 6–7 | `aborts` | downloads ended early |
| 8–9 | `withheld_fcs` | flow controls withheld by a gate deny, the STmin monitor or an app's end of session |
| 10–11 | `stmin_violations` | messages whose median frame gap was under 0.8 × STmin, counted only when the gate allowed |
| 12–13 | `resp_pending_caps` | 0x78 sequences that reached 90 s |
| 14–15 | `resp_frames_dropped` | response frames the app's CAN driver dropped after queueing them (the ESP32 port's `tx_dropped`) |

### Reason codes

The FF01 status byte and F1F1 byte 0.

| Code | Name | Meaning |
|---|---|---|
| 0 | `UDSOTA_DL_OK` | success |
| 1 | `UDSOTA_DL_BAD_HEADER` | ESP image header, app descriptor, chip ID or revision, or a flash mode other than the running app's; an unparseable version, or a release flag that disagrees with it |
| 2 | `UDSOTA_DL_BAD_PROJECT` | product name differs from `cfg.product` |
| 3 | `UDSOTA_DL_BAD_BOARD` | descriptor missing, wrong magic or version, or `hw_id` differs |
| 4 | `UDSOTA_DL_BAD_LAYOUT` | `layout_id` differs |
| 5 | `UDSOTA_DL_BAD_DIAG_IDS` | the image would not answer on this ID pair |
| 6 | `UDSOTA_DL_NOT_NEWER` | fails the version rule |
| 7 | `UDSOTA_DL_TOO_BIG` | the announced size exceeds the slot |
| 8 | `UDSOTA_DL_VERIFY_FAILED` | hash or signature check failed in FF01 |
| 9 | `UDSOTA_DL_SIG_FAILED` | reserved; ESP-IDF v6.1 reports a signature failure as 8 |
| 10 | `UDSOTA_DL_WORKER_TIMEOUT` | a flash job passed 90 s |
| 11 | `UDSOTA_DL_ABORTED` | ended early: a session change or S3, a gate deny mid-transfer, or an overrun (0x71) |
| 12 | `UDSOTA_DL_FLASH_ERROR` | an erase or write failed, or at the first block there was no slot or worker |
| 13 | `UDSOTA_DL_BAD_STREAM` | a coded download's stream or patch was corrupt, had the wrong magic or size, read the base outside the running slot, decoded past the announced size or carried bytes after a patch's end, or at 37 had not ended at exactly that size or carried bytes after a stream's end |
| 14 | `UDSOTA_DL_NO_MEMORY` | a coded 34 found no memory for its decoder |
| 15 | `UDSOTA_DL_BAD_BASE` | a delta patch made from another image than the running one, or a running image the engine could not identify; a full download still works |

### Image descriptor

32 bytes, little-endian, at image offset 288. That offset is the ESP image header (24 bytes), the first segment header (8) and `esp_app_desc_t` (256), so the first 36 block must carry at least 320 bytes.

| Offset | Field | Value |
|---|---|---|
| 0 | `magic` | 0x5544534F ("UDSO"); a hex dump of flash shows `4F 53 44 55` |
| 4 | `desc_version` | 1 (16-bit) |
| 6 | `hw_id` | the product's hardware ID |
| 7 | `partition_layout_id` | the partition layout ID |
| 8 | `diag_request_id` | request CAN ID (16-bit) |
| 10 | `diag_response_id` | response CAN ID (16-bit) |
| 12 | `flags` | bit 0: release build; other bits 0 |
| 13 | `reserved` | 19 zero bytes |

### Flashing without the client

A flasher that is not the client, such as an edge device that fetches updates from a server, sends the payloads `udsota pack` writes (client README) in this sequence, with every value it needs in their manifest. The client's `update.flash` is the reference implementation, with every recovery path; `flash_packed` in `client/tests/test_e2e_pipe.py` is a minimal one. The 0x27 key is not in the manifest. In the ECDSA mode the flasher sends each seed, the level and the F18C device ID to the product's signing service and sends back the 64-byte signature it returns ([Security](#security)), keeping the session open with 3E 00 while it waits; in the HMAC mode it needs the master key.

**Precheck**, in the default session. If F1F3 already reads the manifest's `image_elf_sha256`, there is nothing to send, or only ConfirmImage when F1F0 says the running image is pending verify. Any other pending-verify image must be confirmed or rolled back first. The board DID (`board_did`) must read `board`. If F1F0's other slot is verified (since the last boot) and its SHA prefix is the first 8 bytes of `image_elf_sha256`, skip the payloads and FF01: after 10 02 and the unlock, go straight to ActivateImage.

**Download.** 10 02 and the programming unlock, then the payloads in manifest order until one is taken, skipping a delta whose `base_elf_sha256` is not F1F3. Each goes as a 34 with the entry's `dfi`, ALFID 44, address 0 and `memory_size`; then 36 blocks of the 74's maxNumberOfBlockLength less 2 bytes, the counter from 01 wrapping FF to 00; then a 37. A 34 answered 0x31, or 0x22 with F1F1 reason 14 (`DL_NO_MEMORY`), means the device cannot take that mode now: try the next entry. A 36 answered 0x31 with F1F1 reason 15 (`DL_BAD_BASE`) has ended the download before any erase: skip the other deltas and go on to the full entries. Any other refusal stops the update, and F1F1 names why.

**Lost answers.** A 36, 37 or FF01 that gets no answer may be sent once more unchanged; a repeated block is answered without being written twice. 0x21 to a resend means the first copy is still being served: wait for its answer. A resent 37 answered 0x24 has succeeded when F1F1 reads reason 0 with `payload_size` bytes; a resent 36 refused with F1F1 reason 15 is the `DL_BAD_BASE` case, whether it answers 0x24 or, when longer than the 256 bytes the ended download's ISO-TP now takes, gets no flow control; a resent FF01 repeats status 00 after a pass, and answers 0x24 after a failure, which F1F1 names.

**Verify, activate, confirm.** FF01 must answer status 00. ActivateImage (F001) answers and restarts the device, so wait about 3 s, then poll F1F3 until the device answers (the client allows 60 s). Any value but `image_elf_sha256` means it rolled back or never switched: stop. Finally 10 03 and ConfirmImage (F002), sent again every 2 s while it answers 0x22 and the product's own checks run; the client allows 120 s.

## Third-party code

Vendored libraries, their versions and licences are in [THIRD_PARTY.md](../../THIRD_PARTY.md). The UDS server is udsota's own: driftregion's iso14229 (MIT) was the model for the fuzz harness and the 0x78 cadence, but none of its code is copied. udsota itself is MIT-licensed; see the repository's `LICENSE`.
