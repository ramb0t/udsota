# udsota_esp32

udsota_esp32 is the ESP-IDF port of [udsota](../udsota/README.md). It runs the UDS server in its own task, writes images with `esp_ota_*` on a flash worker, and keeps the boot-loop counter in RTC memory. The app calls `udsota_esp32_start()` once and feeds it request frames; the integration walkthrough, hooks and wire reference are in the core README. [`examples/esp32`](../../examples/esp32/README.md) is a complete app that uses the port over TWAI.

## API (`udsota_esp32.h`, `udsota_esp32_image.h`)

| Function | Call from | Does |
|---|---|---|
| `esp_err_t udsota_esp32_start(const udsota_config_t *cfg, const udsota_hooks_t *hooks, const udsota_esp32_can_t *can)` | once, after the app's CAN driver runs | copies `cfg`, `hooks` and `can`, fixes the device ID (below), and starts the diag task and flash worker. Security is on when `cfg->key_label` is set, and a NULL `hooks->reset` means `esp_restart()`. Bad arguments (a `func_id` equal to `req_id` or `resp_id` among them), a second call or no memory return an error and leave the updater off; no inactive slot, or no worker, leaves it answering but refusing downloads |
| `udsota_esp32_on_frame(id, data, dlc, rx_us)` | the app's CAN receive task | queues one request frame on `cfg.req_id`, or on `cfg.func_id` when it is set (functional addressing); never blocks. Drops other IDs, frames before start, and frames past a full queue (counted) |
| `udsota_esp32_end_session()` | any task | ends an open session, after a running flash job has answered; the diag task runs `udsota_end_session()` |
| `udsota_esp32_phase()` | any task | the current `udsota_phase_t` |
| `udsota_esp32_image_unconfirmed()` | any task | true while the running image is pending verify and is the boot slot |
| `udsota_esp32_status(out)` | any task | the cached F1F0 snapshot |
| `udsota_esp32_engine()` | any task | the engine, for a front end other than UDS |
| `bool udsota_esp32_engine_busy(void)` | any task | true while an engine job or the boot-time OTA read is queued or running |
| `const udsota_security_t *udsota_esp32_security(const char *label, const uint8_t *master, size_t master_len, const uint8_t *id, size_t id_len)` | start code, before the diag task runs | builds the 0x27 security that start installs (start calls it itself, with `cfg.device_id`) over `id`, or the base MAC when `id` is NULL; NULL label gives NULL, and no master or a bad `id_len` gives security with no key that matches |
| `const uint8_t *udsota_esp32_device_id(size_t *len)` | any task | the device ID in use and its length: the ID start or `udsota_esp32_security()` fixed, else the 6-byte base MAC |
| `udsota_reason_t udsota_esp32_image_check(const uint8_t *buf, size_t len, uint32_t announced_size, uint16_t chip_id, const udsota_image_ctx_t *ctx, bool *is_release_out)` | any task (pure, host-testable) | the ESP image header half of the first-block check, then the core's image rules |
| `udsota_esp32_psa_lock(wait_ms)`, `udsota_esp32_psa_unlock()` | any task | the mutex the port's key HMAC and image verify hold around PSA crypto; take it around the app's own PSA operations, since ESP-IDF v6.1's PSA is not thread-safe for them |
| `udsota_esp32_bootloop_init()` | first thing in `app_main` | counts this boot |
| `udsota_esp32_bootloop_config_ignored()` | any task | true when this boot should skip stored settings |
| `udsota_esp32_bootloop_mark_healthy()` | once the app is healthy | clears the count |

The device ID is `cfg.device_id` (1 to 16 bytes) when set, else the 6-byte base MAC. Start copies it once, serves the copy as F18C and derives the 0x27 keys from the same bytes, so the key a client derives from F18C always matches. A set `device_id` of any other length makes start return `ESP_ERR_INVALID_ARG`. A custom ID must be unique per device, or devices share K_dev.

`udsota_esp32_can_t` is the app's transport: `can_send` (required; `ESP_ERR_NO_MEM` means retry), `tx_pending` (frames still in the driver, so a restart waits for its answer) and `tx_dropped` (response frames the driver dropped after queueing them, reported as F1F2 `resp_frames_dropped`), all called on the diag task; the last two may be NULL.

`UDSOTA_ESP32_IMAGE_DESC(hw, layout, req_id, resp_id)` places the image descriptor in `.rodata_custom_desc`, which ESP-IDF's linker script puts right after `esp_app_desc_t`, at image offset 288; the example's is `UDSOTA_ESP32_IMAGE_DESC(1, 1, 0x710, 0x718)`, matching its `cfg`. `udsota_esp32_image_desc(<target>)` in CMake sets its release flag from a clean `vX.Y.Z` `PROJECT_VER` and links with `-u udsota_image_desc`.

Rollback follows `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`; the core README's [Rollback and confirm](../udsota/README.md#rollback-and-confirm) says what changes without it.

The diag task sleeps on its frame queue until the adapter's next deadline, and the flash worker wakes it as each job finishes, so a block's 76 goes out as soon as its write is done. Set `CONFIG_FREERTOS_HZ=1000` (the example does): at 100 Hz the task wakes in 10 ms steps, which is slower per block and puts the first 0x78 near the end of P2, and the port logs a warning at start.

## Kconfig

| Symbol | Default | What |
|---|---|---|
| `UDSOTA_ESP32_TASK_CORE` | 0 | core of the diag task (ISO-TP and the UDS server); put it on the app's CAN task's core |
| `UDSOTA_ESP32_TASK_PRIO` | 5 | its priority: below the app's CAN task, above the app's other tasks and the flash worker |
| `UDSOTA_ESP32_TASK_STACK` | 6144 | its stack, in bytes |
| `UDSOTA_ESP32_TASK_STACK_PSRAM` | y | put the diag task's stack in PSRAM |
| `UDSOTA_ESP32_BUFS_PSRAM` | y | put the ISO-TP adapter's 9,214 bytes of buffers in PSRAM |
| `UDSOTA_ESP32_WORKER_CORE` | 0 | core of the flash worker (erase, write, verify, activate, confirm) |
| `UDSOTA_ESP32_WORKER_PRIO` | 3 | its priority; below the app's own tasks (a UI, say), so they keep running during an erase |
| `UDSOTA_ESP32_WORKER_STACK` | 8192 | its stack, in bytes, sized for the RSA-3072 verify inside `esp_ota_end()` |
| `UDSOTA_ESP32_RX_QUEUE_LEN` | 32 | request frames queued between `udsota_esp32_on_frame()` and the diag task |
| `UDSOTA_ESP32_DEBUG_MEASURE` | n | bench only: log update timings, stack headroom and internal heap |

## Memory and tasks

`udsota_esp32_start()` allocates everything once, and nothing after. By default the ISO-TP adapter's buffers (`UDSOTA_ESP32_BUFS_PSRAM`) and the diag task's stack (`UDSOTA_ESP32_TASK_STACK_PSRAM`) go in PSRAM. That needs `CONFIG_SPIRAM`, and the stack also needs `CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM`; it is safe because the diag task never touches flash. The app's hooks (`gate`, `did_read`, `phase`, `reset`) run on the diag task too, so with the stack in PSRAM a hook must not touch flash either (NVS, `esp_partition_*`): turn `UDSOTA_ESP32_TASK_STACK_PSRAM` off if one does. The flash worker's stack and its 4 KB block buffer stay in internal RAM, because flash operations disable the cache that PSRAM is reached through, and so do the request queue (which the app's CAN task writes), the worker's job queue and the PSA lock.

With security on, start enables the SAR-ADC entropy source (`bootloader_random_enable()`) and leaves it on, so seeds are truly random without Wi-Fi or Bluetooth. ESP-IDF's `random.rst` says the source must be disabled before the app uses the ADC, Wi-Fi or Bluetooth, so an app that uses any of them needs this changed first.

Logging is quiet. A restart over UDS logs at info and other routine events at debug; warnings mark a refused or aborted image, lost frames, a withheld flow control and the boot-loop counter tripping.
