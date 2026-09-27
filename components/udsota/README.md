# udsota

udsota installs firmware over CAN. A UDS (ISO 14229) server on ISO-TP writes a new image into the inactive A/B slot, and, with rollback on, the device keeps it only once the installing client confirms it. It exists so that any UDS tester can drive a product's updates while the product keeps every "is it safe to update now?" decision for itself.

This component is the portable core: C11, with no platform headers. It builds as an ESP-IDF component, or in plain CMake as the library `udsota` (add `components/isotp` first). [udsota_esp32](../udsota_esp32/README.md) is the ESP-IDF port, and [examples/esp32](../../examples/esp32/README.md) is a minimal integration over TWAI.

## Layers

```
app            CAN driver · gate and phase hooks · its own DIDs · product policy
  │
udsota         ISO-TP adapter (udsota_isotp) → UDS server (udsota_server) → engine interface
               image rules (descriptor, version) · key derivation · boot-loop counter
  │
udsota_esp32   diag task and flash worker · engine on esp_ota_* · PSA HMAC and RNG · RTC boot-loop storage
```

Dependencies point down only. The app owns the CAN bus. udsota transmits through the app's send callback, receives only the frames the app hands it, and never touches the controller. The ISO-TP adapter, on `components/isotp`, is the only CAN-specific code in the core. A port implements the engine (`udsota_engine_t`: check the first block, erase, write, verify, activate, confirm, abort and status), and any other front end that delivers an image can drive the same engine.

## Known limits

The transport is classic CAN with 11-bit IDs only: `udsota_can_t.send` takes a `uint16_t` ID and has no extended flag. The image rules assume the ESP-IDF app-image layout (`udsota_image.c` reads `esp_app_desc_t` and the descriptor at fixed offsets), so a port for another platform must produce that layout or bring its own rules. The ISO-TP pad byte is fixed at 0xAA. The adapter defines isotp-c's platform hooks, so no other isotp-c user can link into the same image.

Future work: 29-bit IDs, CAN FD, a per-link isotp send callback so that another isotp-c user can share the image, and a Linux SocketCAN demo server for end-to-end client tests.

## Integrating on ESP32

An integration is one C file and two build lines. This is all of it for a product with a parked signal and a self-test:

```c
#include "udsota.h"
#include "udsota_wire.h"
#include "udsota_esp32.h"

extern const uint8_t app_key_master[32];   /* 0x27 master key, embedded from a git-ignored file */

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
        .key_label = "udsota-example", .key_master = app_key_master, .key_master_len = sizeof app_key_master,
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
| `did_read(ctx, did, buf, max)` | for a 22 on any DID the core does not serve; returns the bytes written, 0 for "no such DID" | every such DID answers 0x31 |
| `stmin_us(ctx)` | when a request's first frame arrives, for that message's flow control | `cfg.stmin_us` (2 ms) |
| `reset(ctx)` | once the answer to 11 01 or ActivateImage has left (the transport's `tx_pending` reads 0, or after 100 ms); it returns only on failure, and the server then re-opens | in the core, 11 01 answers 0x11 and ActivateImage answers positive without a restart, so the new image boots at the next power cycle. The ESP32 port uses `esp_restart()` |

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

A deny during a transfer ends it, except 0x21 on a 36, which the client may retry with the transfer still open. On any other 36 deny the client gets the NRC; at a flow-control point any deny withholds the FC and the client times out. Either way the server drops to the default session, and F1F1 reads reason 11. Reads, TesterPresent, SecurityAccess, 10 01, 37, FF01 and F000 are never gated, because none of them changes what the device runs.

The phase is IDLE in the default session, and EXTENDED or PROGRAMMING in those sessions. It is TRANSFERRING from an accepted 34 until 37, an abort or a session change, and ACTIVATING from a positive ActivateImage until the restart.

The hooks run in the server's context, which in the ESP32 port is the diag task. The gate is asked at flow-control points while frames stream in, so it must read a snapshot the app keeps current, return at once and never block. The phase hook must not wait on anything either.

## Integrating safely

udsota enforces its own sequence and nothing else: with no gate, every step is allowed whenever the sequence allows it. What makes an update safe is the product's to decide, which is also where AUTOSAR's Dcm and UNECE R156 put it. These are the decisions an integrator makes.

**Keep the machine still.** Gate ENTER_PROGRAMMING, START_DOWNLOAD and CONTINUE_TRANSFER on the product's safe state. Use `phase` to hold a drive interlock while the phase is TRANSFERRING or ACTIVATING, since R156 asks that a vehicle "cannot be driven during the execution of the update". CONTINUE_TRANSFER is asked every `block_size` frames, so a transfer stops within one block of the state changing. ACTIVATE and RESET both restart the device, so gate them on the same state.

**Let the client confirm.** With rollback on, the client's ConfirmImage is the proof that CAN works on the new image. Gate CONFIRM on the app's own health, and on a soak if it needs one (30 s of uptime, say). Don't call `esp_ota_mark_app_valid_cancel_rollback()` from the app: an image confirmed without the client may have a broken CAN path that only a workshop visit can fix.

**One tester, one device.** udsota answers one request at a time on one ID pair. If two devices can share the pair, both would install the image. Detect a twin in the app, refuse ENTER_EXTENDED and ENTER_PROGRAMMING in the gate, and call `udsota_esp32_end_session()` for as long as the twin is heard: a repeat is harmless, because the request is latched and runs once.

**Frames in.** Hand udsota only standard (11-bit) frames on `cfg.req_id`. `udsota_esp32_on_frame()` takes a 16-bit ID, so an extended ID would be truncated and could alias the request ID. Take `rx_us` in the receive path, as close to the driver as possible, because the STmin monitor measures the gaps between those stamps.

**Frames out.** udsota transmits only on `cfg.resp_id`. `ESP_ERR_NO_MEM` from `can_send` means retry: an answer is parked and resent, and a flow-control frame is retried at each service (1 ms apart) for `cfg.fc_retry_ms` (10 ms by default), then dropped. Set it to two token intervals of the driver's rate cap, or an FC refused just after an answer never reaches the next token. Any other error drops the frame. The port logs these losses; F1F2's `resp_frames_dropped` reports only what the app's `tx_dropped` counts. The app's CAN driver is the place for a rate cap or an allowlist that bounds what a fault could put on the bus.

**Pace.** STmin is the client's minimum gap between frames. Pick one the bus can carry beside its normal traffic, either `cfg.stmin_us` or a per-message value from `stmin_us`. Set `stmin_monitor` to stop a client whose median gap is under 0.8 × STmin.

**Keys and signing** are covered below. Without either, any node that can send on `cfg.req_id` can install any image the image rules accept.

## Security

With security on (the ESP32 port turns it on when `cfg.key_label` is set), SecurityAccess (27) guards programming. `cfg.level_programming` (default 0x03) unlocks 34, 36, 37, FF01, ActivateImage and 11 01, and `cfg.level_extended` (default 0x01) unlocks 11 01. ConfirmImage needs no key, because it can only keep an image that passed FF01 and ActivateImage.

Each 16-byte seed is single-use and valid for 30 s. The key is the first 16 bytes of HMAC-SHA256(K_dev, seed ‖ level ‖ device_id), where K_dev = HMAC-SHA256(K_master, label ‖ device_id); `level` is the requestSeed sub-function, `device_id` is what F18C returns, and the server compares keys in constant time. The ESP32 port serves and hashes `cfg.device_id` when it is set (1 to 16 bytes), otherwise the 6-byte base MAC. Three wrong keys answer 0x36, then 0x37 for 10 s, and the same 10 s delay follows every boot. An unlock ends at a session change, an S3 timeout or a reset. With a label but no master (a CI build, say), security stays on and no key can match: sendKey answers 0x22 and counts no attempt.

With `security` NULL, or `cfg.key_label` NULL in the port, 27 answers 0x11, and the programming session, the download, activation and reset need no key.

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

## Client

[`client/`](../../client/README.md) is a generic PC client for Linux and SocketCAN. A product's TOML profile holds everything product-specific; the built-in `example` profile carries the values used here, and `udsota --profile example flash <image>` runs the whole sequence, from the precheck to ConfirmImage.

## Wire reference

### Services

| SID | Service | Accepts | Session | Key |
|---|---|---|---|---|
| 10 | DiagnosticSessionControl | 01 default, 02 programming, 03 extended; answers `50 xx` then P2 and P2*/10 as two big-endian words (`00 32 01 F4` by default) | any | – |
| 11 | ECUReset | 01 hardReset: answers, then restarts through `reset` | extended, programming | either level |
| 22 | ReadDataByIdentifier | one DID per request | any | – |
| 27 | SecurityAccess | `level_extended` and the next sub-function in extended, `level_programming` and the next in programming | extended, programming | – |
| 31 | RoutineControl | 01 startRoutine | per routine | per routine |
| 34 | RequestDownload | DFI 00, ALFID 44, address 0, 0 < size ≤ slot; answers `74 20 0F FF` (`cfg.max_block_len`, 4,095 by default) | programming | programming |
| 36 | TransferData | block counter from 01, wrapping FF to 00, and up to 4,093 data bytes; a repeat of the last counter is answered and not rewritten | programming | programming |
| 37 | RequestTransferExit | once every announced byte has arrived | programming | programming |
| 3E | TesterPresent | 00; 80 suppresses the answer | any | – |

Any other SID answers 0x11. While a flash job runs, every request but 3E answers 0x21. The key column applies only with security on.

### Routines

| RID | Routine | Session, key | Does |
|---|---|---|---|
| FF01 | CheckProgrammingDependencies | programming, programming | verifies the written image: hash, signature, and the image rules on the bytes in flash. Answers a status byte, 00 or a reason code. A pass marks the slot verified until the next 34 or reboot |
| F000 | GetResumePoint | programming, programming | reserved for resume; answers status FF, not available |
| F001 | ActivateImage | programming, programming | needs the slot verified (else 0x24); makes it the boot slot, answers, then restarts |
| F002 | ConfirmImage | extended, none | needs the boot slot; confirms a pending-verify image, answers positive for one already valid or undefined, else 0x22 |

A 31 in the default session answers 0x7F. A RID that isn't served in the current session answers 0x31.

### Data identifiers

| DID | Content | Source |
|---|---|---|
| F186 | active session, 1 byte | the server |
| F189 | running version string | `engine.version` |
| F18C | device ID | `cfg.device_id` (the ESP32 port's base MAC when it is NULL) |
| F1F0 | update status, 16 bytes | `engine.status` |
| F1F1 | last download result, 5 bytes | the server |
| F1F2 | counters, 16 bytes | the server and the transport |
| F1F3 | running image `app_elf_sha256`, 32 bytes | `engine.running_sha` |

Every other DID goes to `did_read`, and so does any of these whose source is NULL.

### Negative responses

| NRC | Name | udsota sends it for |
|---|---|---|
| 0x11 | serviceNotSupported | an unknown SID; 27 with security off; 11 01 with no `reset` hook |
| 0x12 | subFunctionNotSupported | an unknown sub-function |
| 0x13 | incorrectMessageLengthOrInvalidFormat | a wrong length, or more than one DID in a 22 |
| 0x21 | busyRepeatRequest | any request but 3E while a flash job runs; or the gate's choice |
| 0x22 | conditionsNotCorrect | a core-owned condition, or the gate |
| 0x24 | requestSequenceError | a step out of order: 36 with no download open, 37 before the last byte, FF01 before 37, F001 before FF01, or a key with no live seed |
| 0x31 | requestOutOfRange | an unknown DID or RID, 34 parameters or size, or a first block the image rules refuse |
| 0x33 | securityAccessDenied | a keyed service while locked |
| 0x35 | invalidKey | a wrong key |
| 0x36 | exceedNumberOfAttempts | the third wrong key |
| 0x37 | requiredTimeDelayNotExpired | 27 within 10 s of boot or of a lockout |
| 0x71 | transferDataSuspended | a 36 that would overrun the announced size; the download ends |
| 0x72 | generalProgrammingFailure | an erase, write, activate or confirm failure, or a flash job past 90 s |
| 0x73 | wrongBlockSequenceCounter | a 36 counter that is neither the next nor a repeat |
| 0x78 | responsePending | a flash job still running after 40 ms, repeated every 1.5 s |
| 0x7E | subFunctionNotSupportedInActiveSession | a 27 level that belongs to the other session |
| 0x7F | serviceNotSupportedInActiveSession | 11, 27 or 31 in the default session; 34, 36 or 37 outside programming |

### Timing

P2 is 50 ms and P2\* 5,000 ms (`cfg.p2_ms`, `cfg.p2star_ms`). S3 is 5 s after the last answer (`cfg.s3_ms`); it pauses while a multi-frame request arrives, and its expiry returns the server to the default session, which aborts a download. A flash job not done within 40 ms gets 0x78, repeated every 1.5 s, and at 90 s the server answers 0x72 and ends the session.

ISO-TP flow control uses a block size of 64 (`cfg.block_size`) and an STmin of 2 ms, with frames padded with 0xAA. N_Cr is 1 s. The receive limit is 256 bytes, or 4,095 while a download is open.

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
| 1–4 | `bytes_received` | data bytes accepted by 36, big-endian |

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

## Third-party code

`components/isotp` vendors SimonCahill's isotp-c v1.9.3 (commit 1fc19e2, unpatched), which is MIT-licensed; its `LICENSE` sits beside it, and `isotp_port.c` gives each link its own block size and STmin. The UDS server is udsota's own. driftregion's iso14229 (MIT) was the model for the fuzz harness and the 0x78 cadence, but none of its code is copied. udsota itself is MIT-licensed; see the repository's `LICENSE` and `THIRD_PARTY.md`.
