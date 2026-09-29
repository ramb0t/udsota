# Plan: the UDS server / updater seam

This plan implements the agreed design in CANDash's request `docs/design/requests/2026-09-29-udsota-server-update-seam.md` ("Response from udsota", accepted by CANDash): udsota's generic UDS server and its firmware updater get separate directories and a one-way seam, so they could be unpicked into two modules later. Nothing changes on the wire.

It ships as three PRs and one minor release (0.9.0). CANDash makes its one documented change once, when it pins that release. The per-step detail is in four appendices: [move](2026-09-29-seam-step1-move.md), [seam](2026-09-29-seam-step2-seam.md), [port](2026-09-29-seam-step3-port.md), [tests](2026-09-29-seam-tests.md). Line numbers there refer to 0.8.0 (`08cb5b0`).

## Decisions

These settle where the planners differed or asked.

- **The boot-loop breaker gets its own directory, `bootloop/`, in both components** (Ben, 2026-09-29; this amends the response's layout). It guards against stored config that crashes the app at boot, not against bad images (the bootloader's rollback handles those); the app drives it, and nothing in the download, verify or activate path uses it. Its only tie to the updater is that F1F0 reports its flag, so `update/` depends on `bootloop/`, one way, and `server/` doesn't need it. A server-only device keeps it, and reports the flag through its own DIDs. `udsota_bootloop.c` includes only `stdint`/`stdbool`; the ESP32 engine is its only other user.

- **Release.** All three PRs ship together as 0.9.0, so CANDash changes once and the request's engine-less CI criterion is met in the same release. No PR is released alone.
- **CHANGELOG.** **Breaking** for host builds (files moved; take `sources.cmake`), for the updater's fields moving to `srv.update.*`, for `udsota_priv.h` becoming `udsota_service.h`, and for `udsota_isotp.h` no longer pulling in `udsota.h`. ESP-IDF builds and the umbrella `#include`s are unchanged.
- **No wire change is proven by a response digest.** PR 1 first adds to `fuzz_udsota.c` a running hash of every request and response, printed on the PASS line, and records the four variants' digests at 0.8.0's behaviour. Every later commit must reproduce them. The PASS line's counts alone can't see an NRC swapped for another; the digest can. This is a harness addition, not a change to what the fuzz tests.
- **`udsota` has no private include dir after step 2.** `udsota_service.h` is the API a service builds on, so it goes in `server/include`; `udsota_priv.h` is deleted (its three tests include `udsota_service.h`), which empties `server/priv`, so step 2's first commit sets `UDSOTA_PRIV_INCLUDE_DIRS` empty and drops `PRIV_INCLUDE_DIRS` from the component (ESP-IDF fails on an include dir that doesn't exist). CANDash's `UDSOTA_PRIV` then expands to nothing.
- **Kconfig name:** `CONFIG_UDSOTA_ESP32_UPDATER`, default y. Without it `udsota_esp32_engine()` returns NULL rather than failing to link, and F189 is documented as the app's to serve.
- **Red-first tests.** The engine-NULL test crashes today (SIGSEGV at `udsota_server.c:227` and `:1099`), which CTest's `WILL_FAIL` does not invert. So the new tests land in the commit where they pass, and the PR records their failure against the step-1 tree (`gdb -batch` backtraces).
- **Core-only check:** an OBJECT library of `server/` sources (a static archive would hide unreferenced updater calls), plus include and link probes on the existing `udsota_core_probe_*` pattern. It lands with the physical split, where it first passes.
- **Grep check:** `tools/check_seam.sh` scans both `server/` directories (the port's `udsota_esp32.c` touches only `counters`, so it passes), with a fixture of known hits and near-misses and a live positive in `update/`, so an empty result is trusted.
- **The context isn't regrouped.** The table pointer adds 4 B to `udsota_server_t` (364 B on Xtensa today); the PR states the measured figure, as the response allows, rather than reordering core fields to win it back.
- **Headers.** `udsota_update_state.h` is self-contained and holds the wire types the embedded engine needs (`udsota_reason_t`, `udsota_status_t`, `udsota_result_t`) plus the progress types `hooks.progress` names. `UDSOTA_DL_MAX_BLOCK_LEN` stays in the server wire header and joins the response's "mixes" list. New header basenames stay unique, since every include resolves by basename.
- **A non-app job with no service registered** (only a test can make one) polls as `UDSOTA_NRC_GENERAL_REJECT`, as `app_poll` does without `routine_poll`.
- **`withheld_fcs`** stays bumped in the core's `udsota_fc_check`, which is reachable only with a service.
- **`sources.cmake` names:** `UDSOTA_SERVER_SRCS` and `UDSOTA_UPDATE_SRCS` are the directories; `UDSOTA_SERVICES_SRCS` is "`udsota_init()` and every service, no transport" (today's `SERVER_SRCS`), the unit CANDash links; it keeps that meaning when step 2 adds the updater's files.
- **Out of this plan:** extracting the image descriptor's CMake from `project_include.cmake`, and 0x19/0x14.
- **Known limit, first to fix if a server-only device becomes real:** an engine-less build still pays about 9 KB (8,958 B) for the ISO-TP buffers, sized for a download block: internal RAM, which on a small device matters more than the flash saving. The fix is sizing the transport's receive buffers from its config.

## PR 1: move (step 1)

Four commits, each building and passing:

0. The fuzz response digest (see Decisions), with the four 0.8.0 digests recorded in the commit message.
1. Add `components/udsota/sources.cmake` and `components/udsota_esp32/sources.cmake` with today's flat paths; switch both components' CMakeLists, the root CMakeLists and `tools/linux_server` to them. The test count stays the same.
2. `git mv` 35 files into `server/`, `update/` and `bootloop/`, and in the same commit fix `sources.cmake`, `ci.yml:95-96` (the esp32 job's `image_check` gcc line names paths) and five comment citations. Moved files stay byte-identical, so all 35 record as 100% renames. `Kconfig`, `project_include.cmake`, `components/udsota/test/`, both READMEs, `udsota.h`, `udsota_wire.h`, `udsota_esp32.h` and `udsota_esp32_priv.h` stay at the component root. No include list may name `udsota/priv` or `udsota_esp32/server/include`: after the move they are empty or absent, and ESP-IDF fails on a missing include dir.
3. Docs: the `server/`/`update/` layout and the `sources.cmake` variables in `components/udsota/README.md`; CHANGELOG `[Unreleased]`.

Verify: same ctest count and all pass; `git show -M --summary` shows 35 renames at 100%; the stale-path greps print nothing; the six ESP32 builds have no warnings and `idf.py size` totals equal 0.8.0's. Detail: [move](2026-09-29-seam-step1-move.md).

## PR 2: seam (step 2)

Seven commits, each passing `tools/run_tests.sh`, the fuzz digests and one ESP-IDF build (esp32s3 default; the host build ignores a missing include dir, ESP-IDF doesn't):

1. Header split: `udsota_server_wire.h`, `udsota_server.h`, `udsota_update_state.h`, `udsota_update_wire.h`, `udsota_update.h`; the top `udsota.h` and `udsota_wire.h` become umbrellas; `udsota_isotp.h/.c` and `server/udsota_codec.c` include the core headers; `udsota_priv.h` goes and `UDSOTA_PRIV_INCLUDE_DIRS` empties (see Decisions); `ci.yml`'s `image_check` gcc line gains `-Icomponents/udsota/server/include`, since the update wire header includes the server one. No logic change. `client/tests/test_udsota.py:1115-1158` parses `udsota_wire.h`'s text, so its `wire_header()` follows the umbrella's includes recursively (`udsota_reason_t` sits two levels down); that is the one harness change, not a wire change.
2. Codec split: `update/udsota_update_codec.c` takes F1F0 and F1F1.
3. State split, renames only: `udsota_update_t` and the `update` member; `s->X` becomes `s->update.X` in `udsota_server.c` and eight test files (164 occurrences, proven mechanical by a reverse-sed diff). The fuzz harness is untouched: it reads only core fields.
4. Seam logic, still one file: `udsota_service.h` (the nine-callback table, the "not mine" sentinel `UDSOTA_SVC_PASS`, the service API), `udsota_core_init`, `udsota_update_init`, the compatibility `udsota_init`, and every rewrite in the function map. Adds `test_udsota_server_no_engine`. This is the commit to review hardest.
5. Physical split: the updater half moves to `update/udsota_update.c`; adds the core-only OBJECT target, its probes and test, and `tools/check_seam.sh`.
6. `fuzz_udsota_no_update`, an engine-less fuzz variant behind a new define: an additive `#if` block, so the four existing variants' digests don't move.
7. Size and docs: `idf.py size` against 0.8.0; `sizeof(udsota_server_t)` on host and target; CHANGELOG with the Breaking entries. The request's README item: `README.md:5` and `components/udsota/README.md:3` open with "a device's UDS server, with firmware update as its main service", plus a section on adding DIDs, routines and services. Stale text to fix: `udsota.h:311` ("engine (required)"), `udsota.h:26-27` (who reads `UDSOTA_COMPRESSION`), `components/udsota/README.md:310` (DID routing without an updater), `client/udsota/wire.py:1`, and `fuzz_udsota.c:27-28`.

What must not move on the wire: the NRC check orders. `10 02` keeps today's order (slot status, job flags, the service's poll, transfer open); the updater decides "not mine" before any check or state change; the sentinel never escapes `udsota_on_request`. The one reorder is harmless: at the 90 s cap, F1F1's `WORKER_TIMEOUT` is written inside `enter_session`, before the relock rather than after.

Verify: the four fuzz digests equal 0.8.0's (the harness is deterministic), which with the exact-byte unit tests is the no-wire-change proof; codec and e2e sources are unchanged, and `fuzz_udsota.c` is unchanged through commit 5 (`git diff --exit-code`); the ESP32 flash grows by no more than a few hundred bytes, estimated 250-400 B; CANDash's host tests, vcan harness and firmware (`tools/build.sh ws43`, which applies stricter `-Werror` to udsota) build with its change. Detail: [seam](2026-09-29-seam-step2-seam.md) and [tests](2026-09-29-seam-tests.md).

## PR 3: port (step 3)

1. One seam call from the diag task into the updater: `udsota_esp32_server_init()` replaces `udsota_esp32.c:296-298`; `engine_start` and `set_wake` become static; the `DEBUG_MEASURE` log at `:318` becomes NULL-safe. No behaviour change.
2. `CONFIG_UDSOTA_ESP32_UPDATER`: `depends on` for the worker options and COMPRESSION; the SRCS switch (REQUIRES can't follow Kconfig in ESP-IDF, and needn't, since unreferenced archives cost nothing); `update/udsota_esp32_noupdater.c` with stubs for `udsota_esp32_engine`, `_engine_busy`, `_image_unconfirmed` and `_status`. The engine-less path calls `udsota_core_init()` directly: calling `udsota_init(NULL)` would link the whole updater.
3. `examples/esp32/sdkconfig.noupdater` in the CI matrix, with a check that the option took effect and that `esp_ota_begin` is absent (and present in the default build, the known positive). The example's `main.c` gains calls to `udsota_esp32_engine_busy()` and `udsota_esp32_status()` so the link proves the stubs CANDash needs exist; today it calls only `udsota_esp32_image_unconfirmed()`.
4. Docs: the port README's "Without the updater" section and a CHANGELOG entry with measured numbers. Additive, not Breaking.

An engine-less build saves about 12.7 KB of internal heap (worker stack, block buffer, queue) and an estimated 10-20 KB of flash, to be measured. It still pays for the ISO-TP buffers (8,958 B). Detail: [port](2026-09-29-seam-step3-port.md).

## CANDash's one change

Made once, in the commit that pins 0.9.0; its firmware build needs none.

- `test/host/CMakeLists.txt:54-61` includes both `sources.cmake` files in place of `UDSOTA_CORE_DIR` and `UDSOTA_ESP32_DIR`; the file lists at `:319`, `:341`, `:349-352`, `:404-417`, `:435` and `:537-539` use the exported variables. `test_ui_config.c:22` `#include`s `udsota_esp32_bootloop.c`, so its include dirs come from that file's list entry, plus the port's private include dirs.
- `vcan_harness.c:410` reads `srv.update.dl_announced`.
- Two comment citations follow the moved files.

The exact text is in the [move](2026-09-29-seam-step1-move.md) appendix.

## Baselines to record before PR 1

At `08cb5b0` from a fresh build directory: the ctest count (the local `build/` is stale), the four fuzz digests (from 0.8.0 plus PR 1's digest commit, which changes no server code), `idf.py size` and `size-components` for {esp32, esp32s3} × {default, compression, delta}, and `sizeof(udsota_server_t)`. ESP-IDF v6.1 is installed at `~/.espressif` (`. ~/.espressif/tools/activate_idf_v6.1.sh`); `idf.py` is not on PATH by default.
