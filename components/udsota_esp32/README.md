# udsota_esp32

udsota_esp32 is the ESP-IDF port of [udsota](../udsota/README.md). It runs the UDS server in its own task, writes images with `esp_ota_*` on a flash worker, and keeps the boot-loop counter in RTC memory. The app calls `udsota_esp32_start()` once and feeds it request frames; the integration walkthrough, hooks and wire reference are in the core README. [`examples/esp32`](../../examples/esp32/README.md) is a complete app that uses the port over TWAI.

## API (`udsota_esp32.h`, `udsota_esp32_image.h`)

| Function | Call from | Does |
|---|---|---|
| `esp_err_t udsota_esp32_start(const udsota_config_t *cfg, const udsota_hooks_t *hooks, const udsota_esp32_can_t *can)` | once, after the app's CAN driver runs | copies `cfg`, `hooks` and `can`, fixes the device ID (below), and starts the diag task and flash worker. Security is on when `cfg->key_pubkey` or `cfg->key_label` is set (below), and a NULL `hooks->reset` means `esp_restart()`. Bad arguments (a `func_id` equal to `req_id` or `resp_id` among them), a second call or no memory return an error and leave the updater off; no inactive slot, or no worker, leaves it answering but refusing downloads |
| `udsota_esp32_on_frame(id, data, dlc, rx_us)` | the app's CAN receive task | queues one request frame on `cfg.req_id`, or on `cfg.func_id` when it is set (functional addressing); never blocks. Drops other IDs, frames before start, and frames past a full queue (counted) |
| `udsota_esp32_end_session()` | any task | ends an open session, after a running flash job has answered; the diag task runs `udsota_end_session()` |
| `udsota_esp32_phase()` | any task | the current `udsota_phase_t` |
| `udsota_esp32_progress(out)` | any task | the download's `udsota_progress_t` ([Progress](../udsota/README.md#progress)) as the server last reported it, copied out of a snapshot under a spinlock, so a UI task draws it without touching the server; IDLE before start |
| `size_t udsota_esp32_incoming_version(char out[UDSOTA_ESP32_VERSION_MAX])` | any task | the version of the image being downloaded, from its `esp_app_desc_t`, so a display can say "Installing v0.3.1"; copied with its NUL into `out`, which must hold `UDSOTA_ESP32_VERSION_MAX` bytes, under the progress snapshot's spinlock, and returns its length. It is set when the first-block check accepts the image, compressed downloads included; it is kept after the download completes, aborts or fails verify, so it can name a failure next to `last_reason`; and it is cleared by the next accepted 34, or by a compressed 34 refused for memory (`last_reason` 14), whose image was never seen. The version and the progress are two reads, so to pair them read the progress, then the version, then the progress again, and read all three again if the stage or `last_reason` changed. At most 31 characters, with any byte outside printable ASCII shown as `?`. RAM only: "" before any download since start |
| `udsota_esp32_image_unconfirmed()` | any task | true while the running image is pending verify and is the boot slot |
| `udsota_esp32_status(out)` | any task | the cached F1F0 snapshot |
| `udsota_esp32_engine()` | any task | the engine, for a front end other than UDS |
| `bool udsota_esp32_engine_busy(void)` | any task | true while an engine job or the boot-time OTA read is queued or running |
| `const udsota_security_t *udsota_esp32_security(const char *label, const uint8_t *master, size_t master_len, const uint8_t *id, size_t id_len)` | start code, before the diag task runs | builds the HMAC-mode 0x27 security that start installs (start calls it itself, with `cfg.device_id`) over `id`, or the base MAC when `id` is NULL; NULL label gives NULL, and no master or a bad `id_len` gives security with no key that matches |
| `const udsota_security_t *udsota_esp32_security_ecdsa(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *id, size_t id_len)` | start code, before the diag task runs | the same for the ECDSA mode: self-tests PSA ECDSA and imports `pubkey` once; NULL `pubkey` gives NULL, and a key that is not a 65-byte P-256 point, a failed self-test or a bad `id_len` gives security with no key that matches. The first call of either function fixes the mode |
| `const uint8_t *udsota_esp32_device_id(size_t *len)` | any task | the device ID in use and its length: the ID start or `udsota_esp32_security()` fixed, else the 6-byte base MAC |
| `udsota_reason_t udsota_esp32_image_check(const uint8_t *buf, size_t len, uint32_t announced_size, uint16_t chip_id, const udsota_image_ctx_t *ctx, bool *is_release_out)` | any task (pure, host-testable) | the ESP image header half of the first-block check, then the core's image rules |
| `udsota_esp32_psa_lock(wait_ms)`, `udsota_esp32_psa_unlock()` | any task | the mutex the port's 0x27 HMAC or ECDSA check and image verify hold around PSA crypto; take it around the app's own PSA operations, since ESP-IDF v6.1's PSA is not thread-safe for them |
| `udsota_esp32_bootloop_init()` | first thing in `app_main` | counts this boot |
| `udsota_esp32_bootloop_config_ignored()` | any task | true when this boot should skip stored settings |
| `udsota_esp32_bootloop_mark_healthy()` | once the app is healthy | clears the count |

The device ID is `cfg.device_id` (1 to 16 bytes) when set, else the 6-byte base MAC. Start copies it once, serves the copy as F18C and derives or checks the 0x27 keys over the same bytes, so the key a client makes from F18C always matches. A set `device_id` of any other length makes start return `ESP_ERR_INVALID_ARG`. A custom ID must be unique per device, or devices share K_dev (HMAC) or accept each other's signatures (ECDSA).

Start passes every hook in `udsota_hooks_t` to the core with the app's own `ctx`, `did_write`, `routine`, `routine_poll` and `progress` included, and a hook the app leaves NULL stays NULL, so the core's default holds. The port adds only its phase copy, its progress snapshot and the `esp_restart()` default for `reset`. It wraps `phase` and `progress` to keep those copies, storing each before the app's own hook runs and holding no lock while it does, so that hook may read them back.

### Security config

Start reads these `udsota_config_t` fields for 0x27; the core README's [Security](../udsota/README.md#security) describes the two modes.

| Field | Mode | What |
|---|---|---|
| `key_pubkey`, `key_pubkey_len` | ECDSA | the tester's P-256 public key, uncompressed SEC1 (`04 ‖ X ‖ Y`, 65 bytes), as `udsota keygen` writes it in `udsota_pubkey.h`. It is public: the image holds no secret. Set, it turns security on in the ECDSA mode and wins over the fields below; a malformed one makes start return `ESP_ERR_INVALID_ARG` |
| `key_label` | HMAC | turns security on in the HMAC mode when `key_pubkey` is NULL; K_dev = HMAC-SHA256(master, label ‖ device ID) |
| `key_master`, `key_master_len` | HMAC | the fleet's master key, which every image then carries. NULL gives security with no key that matches. Given with `key_pubkey`, it is ignored and start logs a warning: leave it out of the image |
| `device_id`, `device_id_len` | both | the device ID above |

The ECDSA mode verifies with PSA (`psa_verify_hash`, `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`) on the diag task, under the PSA lock, against the public key start imports once as a volatile key. It needs `CONFIG_MBEDTLS_ECDSA_C` and `CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED`, which are on by default; start self-tests the verify against the core's known answer (two P-256 verifies), and logs an error and refuses every key when it fails. Each unlock costs one verify, tens of milliseconds in software, so the answer may come after P2 (see the core README), and it runs on the diag task's stack: check `UDSOTA_ESP32_TASK_STACK`'s headroom after an unlock with `UDSOTA_ESP32_DEBUG_MEASURE`.

`udsota_esp32_can_t` is the app's transport: `can_send` (required; `ESP_ERR_NO_MEM` means retry), `tx_pending` (frames still in the driver, so a restart waits for its answer) and `tx_dropped` (response frames the driver dropped after queueing them, reported as F1F2 `resp_frames_dropped`), all called on the diag task; the last two may be NULL.

`UDSOTA_ESP32_IMAGE_DESC(hw, layout, req_id, resp_id)` places the image descriptor in `.rodata_custom_desc`, which ESP-IDF's linker script puts right after `esp_app_desc_t`, at image offset 288; the example's is `UDSOTA_ESP32_IMAGE_DESC(1, 1, 0x710, 0x718)`, matching its `cfg`. `udsota_esp32_image_desc(<target>)` in CMake sets its release flag from a clean `vX.Y.Z` `PROJECT_VER` and links with `-u udsota_image_desc`.

Rollback follows `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`; the core README's [Rollback and confirm](../udsota/README.md#rollback-and-confirm) says what changes without it.

The diag task sleeps on its frame queue until the adapter's next deadline, and the flash worker wakes it as each job finishes, so a block's 76 goes out as soon as its write is done. Set `CONFIG_FREERTOS_HZ=1000` (the example does): at 100 Hz the task wakes in 10 ms steps, which is slower per block and puts the first 0x78 near the end of P2, and the port logs a warning at start.

## Kconfig

| Symbol | Default | What |
|---|---|---|
| `UDSOTA_ESP32_TASK_CORE` | 0 | core of the diag task (ISO-TP and the UDS server); put it on the app's CAN task's core |
| `UDSOTA_ESP32_TASK_PRIO` | 5 | its priority: below the app's CAN task, above the app's other tasks and the flash worker |
| `UDSOTA_ESP32_TASK_STACK` | 6144 | its stack, in bytes; the 0x27 check runs on it too (an ECDSA verify in that mode) |
| `UDSOTA_ESP32_TASK_STACK_PSRAM` | y | put the diag task's stack in PSRAM |
| `UDSOTA_ESP32_BUFS_PSRAM` | y | put the ISO-TP adapter's 9,214 bytes of buffers in PSRAM |
| `UDSOTA_ESP32_WORKER_CORE` | 0 | core of the flash worker (erase, write, verify, activate, confirm) |
| `UDSOTA_ESP32_WORKER_PRIO` | 3 | its priority; below the app's own tasks (a UI, say), so they keep running during an erase |
| `UDSOTA_ESP32_WORKER_STACK` | 8192 | its stack, in bytes, sized for the RSA-3072 verify inside `esp_ota_end()` |
| `UDSOTA_ESP32_RX_QUEUE_LEN` | 32 | request frames queued between `udsota_esp32_on_frame()` and the diag task |
| `UDSOTA_ESP32_COMPRESSION` | n | serve [compressed downloads](../udsota/README.md#compressed-downloads) (34 with DFI 0x10) |
| `UDSOTA_ESP32_DELTA` | n | with compression, also serve [delta downloads](../udsota/README.md#delta-downloads) (34 with DFI 0x20 or 0x30), rebuilt from the running slot |
| `UDSOTA_ESP32_INFLATE_PSRAM` | y (with `SPIRAM`; not offered on an ESP32 below revision 3) | put the inflater's state and dictionary in PSRAM |
| `UDSOTA_ESP32_DEBUG_MEASURE` | n | bench only: log update timings, stack headroom and internal heap |

## Memory and tasks

`udsota_esp32_start()` allocates everything once, and nothing after, compressed downloads aside (below). By default the ISO-TP adapter's buffers (`UDSOTA_ESP32_BUFS_PSRAM`) and the diag task's stack (`UDSOTA_ESP32_TASK_STACK_PSRAM`) go in PSRAM. That needs `CONFIG_SPIRAM`, and the stack also needs `CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM`; it is safe because the diag task never touches flash. The app's hooks run on the diag task too, so with the stack in PSRAM a hook must not touch flash either (NVS, `esp_partition_*`): turn `UDSOTA_ESP32_TASK_STACK_PSRAM` off if one does. The flash worker's stack and its 4 KB block buffer stay in internal RAM, because flash operations disable the cache that PSRAM is reached through, and so do the request queue (which the app's CAN task writes), the worker's job queue and the PSA lock.

A hook that blocks stalls the diag task, and every answer and 0x78 with it, wherever its stack is. A `routine` that writes flash or NVS hands the work to a task with an internal-RAM stack, returns `UDSOTA_PENDING`, and reports the result from `routine_poll`; `did_write` should only stage values in RAM.

With security on, start enables the SAR-ADC entropy source (`bootloader_random_enable()`) and leaves it on, so seeds are truly random without Wi-Fi or Bluetooth. ESP-IDF's `random.rst` says the source must be disabled before the app uses the ADC, Wi-Fi or Bluetooth, so an app that uses any of them needs this changed first.

Logging is quiet. A restart over UDS logs at info and other routine events at debug; warnings mark a refused or aborted image, lost frames, a withheld flow control and the boot-loop counter tripping.

## Compressed downloads

`UDSOTA_ESP32_COMPRESSION` turns on DFI 0x10. Left off, the default, a 34 with DFI 0x10 answers 0x31 as before, nothing is allocated for it, no inflate code is linked, and the port builds the core with `UDSOTA_COMPRESSION` 0, so the server compiles none of its compressed handling either, and the image carries only the engine's unused z-op fields. On, the diag task still never inflates: it copies each compressed 36 block into the worker's 4 KB buffer, as it does an uncompressed one, and the flash worker inflates it, runs the first-block check once 320 bytes are out, erases and writes. The worker calls the ROM's `tinfl_decompress`, which every ESP-IDF v6.1 target has, so the vendored miniz is not compiled and the inflater adds no decompressor to the image.

The memory is taken at each compressed 34 and given back at its 37 or abort, never at boot. Measured in QEMU on an ESP32-S3 with the ROM's tinfl, one download holds 47,884 bytes of internal heap: the decompressor's 11,008-byte state, its 32,768-byte dictionary and the worker's 4,096-byte buffer for inflated bytes, plus the allocator's headers. With `UDSOTA_ESP32_INFLATE_PSRAM` the state and dictionary go to PSRAM (internal RAM when PSRAM is full), and the download holds 4,100 bytes of internal heap. An ESP32 below revision 3 does not offer that option and keeps all of it internal, because the ROM's tinfl writes the dictionary and ROM code is not built with the workaround for that chip's PSRAM cache bug. A 34 that finds no memory answers 0x22, F1F1 reads reason 14, and the port logs the largest free internal block. In the QEMU runs, a 306,400-byte image sent as a 188,090-byte stream (61 %), at least 6,660 of the worker's 8,192 stack bytes stayed unused during inflating and 6,132 through FF01, so the default stack needs no change.

The example builds either way: add `examples/esp32/sdkconfig.compression` to `SDKCONFIG_DEFAULTS` to turn it on.

## Delta downloads

`UDSOTA_ESP32_DELTA`, which needs `UDSOTA_ESP32_COMPRESSION`, turns on DFI 0x20 and 0x30: the flash worker rebuilds the new image from the running partition and a patch, into the other slot, through the same first-block check before any erase, erase and writes as any download, and FF01 then verifies it as usual. The running partition is only ever read, through `esp_partition_read()`, which also decrypts it under flash encryption, and a read the patch asks for outside the partition is refused; the bound is the partition rather than the image, whose own length leaves out a signed image's signature block. A patch names its base by the SHA-256 the running image appends, which the worker reads once with `esp_image_get_metadata()` and compares with the patch's header before anything is erased; it is not recomputed, and FF01 is the backstop, since a base that differs from its stored hash only rebuilds an image FF01 refuses. A patch from any other image is refused with reason 15, and the client falls back to a full download. The decoder is detools 0.53.0's sequential patcher, vendored in `components/udsota_delta` and unpatched. It adds about 4 KB to the example's image, and with the option off detools is not linked, though the core's patch stage is (about 2 KB, in any build with compression on).

The memory is taken at each delta 34 and given back at its 37 or abort, never at boot. Measured in QEMU on an ESP32-S3 with no PSRAM, a 0x20 download holds 4,776 bytes of internal heap: the 4,096-byte image buffer the worker writes flash from and the decoder's 672-byte state, plus the allocator's headers. A 0x30 download also holds the inflater and a 1,024-byte buffer for inflated patch bytes, 49,844 bytes in all; with `UDSOTA_ESP32_INFLATE_PSRAM` the inflater's 43,776 bytes go to PSRAM as for 0x10. Rebuilding a 195,072-byte image from one 36 took 350 ms in QEMU, which does not time flash as a chip does, and at least 5,956 of the worker's 8,192 stack bytes stayed unused, so the default stack needs no change. Because one short patch block can rebuild most of an image, a 36 of a delta download may hold the worker for the whole rebuild, under 0x78s, within the 90 s job cap. The 37 runs on the worker too: a heatshrink patch's decoder can still hold the image's last bytes when the input ends, and writing them is flash work, which the diag task never does.

Add `examples/esp32/sdkconfig.delta` to `SDKCONFIG_DEFAULTS` to turn it on for the example.
