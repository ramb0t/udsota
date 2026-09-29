# Seam step 3: the ESP32 port without the updater

A Kconfig option, `CONFIG_UDSOTA_ESP32_UPDATER` (default y), builds the port as a UDS server alone. Part of the [seam plan](2026-09-29-server-update-seam.md); lines refer to 0.8.0 in `components/udsota_esp32/`, which step 1 moves to `server/` or `update/` and step 2 may shift by a few lines in `udsota_esp32.c`, so re-check before editing.

## Constraints found

- **REQUIRES and PRIV_REQUIRES can't depend on Kconfig**: ESP-IDF v6.1 expands requirements before loading the config (`docs/en/api-guides/build-system.rst:476`). Only SRCS can change. That costs no image size: archives link by reference with `--gc-sections`, and `app_update` forces no symbols. `bootloader_support` is needed by the server half anyway (`udsota_esp32_keys.c:13` includes `bootloader_random.h`, called at `:254`).
- **CANDash compiles `udsota_esp32_bootloop.c` on the host** (`test/host/test_ui_config.c:22` `#include`s it; its fakes have no `sdkconfig.h`). So that file and `udsota_esp32_priv.h`, which it includes, get no `sdkconfig.h` or new ESP include.
- **`project_include.cmake` must stay at the component root** and `udsota_esp32_image_desc()` stays defined in both configurations (CANDash's `CMakeLists.txt:75` checks for it).
- **Callers use more updater functions than the design named:** `udsota_esp32_image_unconfirmed()` (CANDash `main/app_main.c:226`, `candash_update_src_esp.c:29`; the example's `main.c:268`), `udsota_esp32_progress()` and `udsota_esp32_incoming_version()` (CANDash `candash_update_src_esp.c:23-25`). The last two live in `udsota_esp32.c` and keep working; `image_unconfirmed` is in `engine.c` and needs a stub.
- **The engine-less port calls `udsota_core_init()`, never `udsota_init(..., NULL, ...)`**: `udsota_init` lives in `update/` and references the updater's table, so it would link every updater handler.
- ESP-IDF v6.1 is at `~/.espressif/v6.1/esp-idf` (`. ~/.espressif/tools/activate_idf_v6.1.sh`); esp-idf-size 2.3.1 is in its venv; qemu-xtensa is not installed.

## 1. The option

`bool "Firmware updater (RequestDownload and the flash worker)"`, `default y`, first in the menu (before `Kconfig:3`). Existing sdkconfigs, the example and CANDash (which tracks only `sdkconfig.defaults*`) are unchanged. Help text: on, 0x34/0x36/0x37, FF01, F000-F002 and DIDs F189, F1F0, F1F1, F1F3, written by a flash worker to the inactive slot; off, 34/36/37 answer 0x11, those RIDs and DIDs go to the app's hooks (0x31 when unserved), everything else works as before, no flash worker (its stack and 4 KB buffer), no engine or esp_ota code, a factory-only partition table works; `udsota_esp32_engine()` is NULL, `_engine_busy()` and `_image_unconfirmed()` false, `_status()` no slots, `_progress()` IDLE, `_incoming_version()` ""; the ISO-TP buffers stay sized for a download block.

`depends on UDSOTA_ESP32_UPDATER` on `WORKER_CORE` (`:3`), `WORKER_PRIO` (`:9`), `WORKER_STACK` (`:17`) and `COMPRESSION` (`:25`); `DELTA` (`:38`) and `INFLATE_PSRAM` (`:57`) follow through COMPRESSION. With it off `CONFIG_UDSOTA_ESP32_WORKER_*` are undefined; only `engine.c` uses them (`:65-67`). `DEBUG_MEASURE`, `TASK_*`, `BUFS_PSRAM` and `RX_QUEUE_LEN` stay unconditional. `CMakeLists.txt:19-22` needs no change: with the option off COMPRESSION is undefined, so the core still gets `UDSOTA_COMPRESSION=0`.

SRCS (`CMakeLists.txt:8-10` today): always the `server/` and `bootloop/` files; with the option, `update/udsota_esp32_engine.c` and `_image.c`; without it, the new `update/udsota_esp32_noupdater.c`. PRIV_REQUIRES (`:14-15`) stay, with a comment saying why; `INCLUDE_DIRS` keep both `include/`. In `sources.cmake` the stub file gets its own list.

The boot-loop breaker (`bootloop/`) is built in both configurations: CANDash (`candash_config.c:20`, `candash_cfg_nvs_esp.c:101`, `app_main.c:442-488`) and the example (`main.c:240-267`) call it whatever the updater does; 8 B of RTC memory and a few hundred bytes of flash. Its only updater tie is the F1F0 flag: `engine.c`'s `status_flags()` (`:761-771`) reads `udsota_esp32_bootloop_reported()` (`bootloop.c:101`), and the stubbed `udsota_esp32_status()` reports the same flag, so the flag means the same in both builds. It lives in its own `bootloop/` directory (the main plan's first decision).

## 2. Every crossing between the halves

Server half into the engine, in `udsota_esp32.c`:

| Site | Now | Without the updater |
|---|---|---|
| `:296` | `udsota_esp32_engine_set_wake(worker_wake)` | behind one seam function (below) |
| `:297` | `udsota_esp32_engine_start(&s_cfg)`, which creates the worker (`engine.c:1084-1134`, task at `:1119`) | not called: no worker, `s_buf` or job queue |
| `:298` | `udsota_init(&s_srv, &s_cfg, udsota_esp32_engine(), sec, &s_hooks)` | `udsota_core_init(&s_srv, &s_cfg, sec, &s_hooks)` |
| `:313-318` | the `DEBUG_MEASURE` log reads `udsota_esp32_engine()->slot_size` | would dereference NULL: `e != NULL ? e->slot_size : 0` (`engine.c:1130` already logs the size) |
| `:179-191` | `worker_wake`, called by the worker through `s_wake` (`engine.c:695-701`, `:729-731`) | never called |
| `:56`, `:72`, `:195-199` | the wake item and `s_wake_posted` | dead but harmless |
| `:205-209` | reads `s_srv.counters.withheld_fcs` | reads 0 |

One seam function instead of `#if`s in `udsota_esp32.c`, declared in `priv/udsota_esp32_priv.h` with core types only so the header stays host-includable:

```c
/* Initialises the server: with CONFIG_UDSOTA_ESP32_UPDATER installs wake, starts the engine and calls udsota_init()
 * with udsota_esp32_engine(); without it calls udsota_core_init(), so no updater is registered or linked. */
bool udsota_esp32_server_init(udsota_server_t *srv, const udsota_config_t *cfg, const udsota_security_t *sec,
                              const udsota_hooks_t *hooks, void (*wake)(void));
```

With the option it is defined at the end of `update/udsota_esp32_engine.c`, and `udsota_esp32_engine_start` and `_set_wake` become static (their declarations at priv.h `:17-27` go). Without it, `udsota_esp32_noupdater.c` defines it as `(void)wake; return udsota_core_init(...)`. `udsota_esp32.c:296-298` become one call; `worker_wake` stays referenced in both builds, so no unused-static warning trips CI's `grep 'warning:'` gate (`ci.yml:90`). 
Engine into the server half: `udsota_esp32_first_block_checked` (`engine.c:269`, defined `udsota_esp32.c:356-359`) and `udsota_esp32_zbegin_refused` (`engine.c:865`, `:901`, defined `:362-365`) are unreferenced without the engine and dropped by gc; non-static, so no warning. The PSA lock (`engine.c:225-227`) is shared and unaffected. `udsota_image_desc` (`engine.c:1111`) is still placed by the app's `-u` (32 B of rodata).

The control block's progress snapshot and incoming version (`priv/udsota_esp32_ctl.h:21-22`, `udsota_esp32_ctl.c:35-47`, `:162-208`; `udsota_esp32.c:68-70`, `:106-116`, `:267`, `:367-385`) stay unchanged: without the updater the core never changes stage or `last_reason`, so the snapshot stays IDLE and the version "" (about 48 B of .bss). Splitting it would churn `test_udsota_esp32_ctl` for nothing; it goes on the response's "mixes" list.

Stubs in `update/udsota_esp32_noupdater.c` for the public functions `engine.c` defines:

- `udsota_esp32_engine()` returns NULL (`engine.c:1077`), matching `udsota_init(engine == NULL)`; documented in `udsota_esp32.h:19-26`.
- `udsota_esp32_engine_busy()` returns false (`engine.c:791`; already documented as "false when the engine never started").
- `udsota_esp32_image_unconfirmed()` returns false (`engine.c:784`).
- `udsota_esp32_status(out)` (`engine.c:774`): NULL `out` returns; else `*out = (udsota_status_t){.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE}` (the engine's own value before its boot read, `engine.c:96`, which CANDash already handles), then `flags` with `UDSOTA_STATUS_SIG_CHECKED` under `CONFIG_SECURE_SIGNED_ON_UPDATE` and `UDSOTA_STATUS_BOOT_IGNORED_CONFIG` when `udsota_esp32_bootloop_reported()`, copying `engine.c:761-771` with a comment naming it.
- `udsota_esp32_image_check`: no stub; `image.c` is compiled out and a caller gets a documented link error.

## 3. What it saves and still pays

Saves about 12.7 KB of internal heap at defaults, allocated at start (to confirm by measurement): the worker stack (`WORKER_STACK`, 8192 B), its TCB (about 350 B), the block buffer `s_buf` (4096 B), the job queue (about 120 B) and heap headers; `engine.c`'s static data (roughly 150-250 B); the transient 48-50 KB a compressed or delta download takes can never be taken. Flash: `engine.c`, `esp_ota_ops.c`, the image verification `esp_ota_end` pulls in, and the updater's core objects; estimated 10-20 KB, to measure.

Still pays: the ISO-TP buffers (`sizeof(udsota_isotp_bufs_t)` 8,958 B, internal unless `SPIRAM` and `BUFS_PSRAM`), the diag task stack (6144 B), the RX queue (32 × 16 B), the embedded `udsota_update_t` in `s_srv`, the control block's 48 B and the boot-loop state.

## 4. CI

- `examples/esp32/sdkconfig.noupdater`:
  ```
  # A UDS server without the updater (no downloads): list this file after sdkconfig.defaults in SDKCONFIG_DEFAULTS (see README.md).
  # CONFIG_UDSOTA_ESP32_UPDATER is not set
  ```
- `ci.yml:78`: `config: [default, compression, delta, noupdater]`; `:87` already maps it to `sdkconfig.<config>`. Six jobs become eight. The image-check step (`:91-98`) still applies.
- A step proving the option took effect and the engine is absent for `noupdater`, and present for `default` (the known positive). Actions runs `bash -eo pipefail`, so a `! a | grep -q` line that isn't last gates nothing and `nm | grep -q` can exit 141; write the symbols to a file first:
  ```sh
  b="examples/esp32/build/${{ matrix.target }}"
  xtensa-esp-elf-nm "$b/example.elf" > "$b/syms"
  if [ "${{ matrix.config }}" = noupdater ]; then
    grep -qx '# CONFIG_UDSOTA_ESP32_UPDATER is not set' "$b/sdkconfig"
    if grep -qw esp_ota_begin "$b/syms"; then echo "engine linked in noupdater"; exit 1; fi
  else
    grep -qw esp_ota_begin "$b/syms"
  fi
  ```
  Confirm the `nm` name in the IDF 6.1 container, and that kconfgen raises no `warning:` for the `is not set` line in a defaults file (CI fails on any).
- The example's `main.c` calls only `udsota_esp32_image_unconfirmed()` (`:268`) today, and unreferenced stubs are never linked. It gains calls to `udsota_esp32_engine_busy()` and `udsota_esp32_status()` (a log line will do), so the link proves the stubs CANDash needs exist.
- A build line in `examples/esp32/README.md`.

## 5. Measuring size

```sh
. ~/.espressif/tools/activate_idf_v6.1.sh
git -C /home/ben/Dev/Personal/udsota worktree add ../udsota-size-080 v0.8.0
# per tree T, TARGET in {esp32, esp32s3}, CONFIG in {default, compression, delta, noupdater}
b="$T/examples/esp32/build/$TARGET-$CONFIG"; d="$T/examples/esp32/sdkconfig.defaults"
[ "$CONFIG" = default ] || d="$d;$T/examples/esp32/sdkconfig.$CONFIG"
idf.py -C "$T/examples/esp32" -B "$b" -D SDKCONFIG="$b/sdkconfig" -D SDKCONFIG_DEFAULTS="$d" set-target $TARGET build
idf.py -C "$T/examples/esp32" -B "$b" size --format json2 --output-file "$b/size.json"
idf.py -C "$T/examples/esp32" -B "$b" size-components --format csv --output-file "$b/components.csv"
# diffs: size --diff, size-components --diff, size-files --diff "$old_b" | grep -i udsota
```

Record per target and config: total image size and `stat -c %s example.bin`; flash .text and rodata; internal `.data` and `.bss` (DRAM on esp32, DIRAM on esp32s3); IRAM text; the size-components rows for `libudsota.a`, `libudsota_esp32.a`, `libapp_update.a`, `libbootloader_support.a`, `libudsota_inflate.a`, `libudsota_delta.a`. Compare: step 3 vs 0.8.0 with the updater (the acceptance: flash within a few hundred bytes, the static internal-RAM change stated; heap is unchanged by construction; optionally confirm with `CONFIG_UDSOTA_ESP32_DEBUG_MEASURE=y` on a board); step 3 vs step 2 (about 0); noupdater vs default (the savings). `PROJECT_VER` is pinned (`examples/esp32/CMakeLists.txt:10`), so there's no version-string noise.

## 6. Commits

On a branch off the step-2 head; released with steps 1 and 2 in 0.9.0:

1. "ESP32 port: one call from the diag task into the updater": `udsota_esp32_server_init`, static `engine_start`/`set_wake`, the NULL-safe `:318` log. No behaviour change; size diff against step 2.
2. "ESP32 port: `CONFIG_UDSOTA_ESP32_UPDATER`": the option and `depends on`, the SRCS switch and comment, `update/udsota_esp32_noupdater.c`, `udsota_esp32.h` docs (`:17-36`, `:127-142`).
3. "examples/esp32: `sdkconfig.noupdater`, built in CI": the config, the matrix, the check, the two stub calls in `main.c`, the README line.
4. "Docs": the port README (Kconfig row, API rows `:9`, `:15-18`, `:22`, a "Without the updater" section) and a CHANGELOG entry with measured numbers. Additive, not Breaking.

Verify: `tools/run_tests.sh` (host is untouched; step 2's checks still pass); the CI command for four configs × two targets with no `warning:`; CANDash pointed at the branch builds with no source change, `idf.py size --diff` against its 0.8.0 build, and its host tests pass.

## Risks

- The warning gate: an unused static or parameter in the off build; the seam function and `(void)wake` handle it.
- A NULL `udsota_esp32_engine()` dereferenced at `:318` or by a third-party front end.
- A misspelt option in `sdkconfig.noupdater` would build the default silently; the `grep -qx` step catches it.
- Combining `noupdater` with `sdkconfig.compression` makes Kconfig drop COMPRESSION; don't combine them.
- The app loses F189 without the updater unless its `did_read` serves it (from `esp_app_get_description()`); documented, not served by the port.
