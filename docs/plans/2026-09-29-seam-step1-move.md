# Seam step 1: move the files

Renames only: files that sit wholly on one side move into `server/` and `update/` inside the existing components, and `sources.cmake` exports the lists. Part of the [seam plan](2026-09-29-server-update-seam.md); lines refer to 0.8.0.

## What stays where it is

- `udsota/include/udsota.h` and `udsota_wire.h` stay at the component top; step 2 turns them into umbrellas.
- `udsota_esp32/include/udsota_esp32.h` (its API mixes engine, boot loop, image descriptor and task) and `udsota_esp32/priv/udsota_esp32_priv.h` (the start hooks both halves use) stay.
- Mixed `.c` files go to `server/` as the layout says: `udsota_server.c`, `udsota_codec.c`, `udsota_esp32_ctl.c` (its header to `server/priv/`).
- `components/udsota/test/` (`fake_engine.[ch]`, `fuzz_udsota.c`, `sha256_host.[ch]`) stays: test support, mixed, built by neither component.
- `udsota_esp32/Kconfig` and `project_include.cmake` stay: ESP-IDF reads both only from the component root (`build.cmake:518`), and CANDash's `CMakeLists.txt:75` checks that `project_include.cmake` exists.
- After the move `components/udsota/priv/` is empty and git drops it; `udsota_esp32/server/include` is never created. Neither may appear in an include list: ESP-IDF stops on a missing include dir.
- No moved file cites a path that goes stale, so all moves record as 100% renames.

## Move table (35 `git mv`s)

| From (components/udsota/) | To |
|---|---|
| `udsota_server.c`, `udsota_codec.c`, `udsota_isotp.c`, `udsota_rxwatch.c`, `udsota_keys.c` | `server/` |
| `include/udsota_isotp.h`, `udsota_rxwatch.h`, `udsota_keys.h` | `server/include/` |
| `priv/udsota_priv.h` | `server/priv/` |
| `udsota_image.c`, `udsota_isink.c`, `udsota_zstream.c`, `udsota_patch.c`, `udsota_coded.c` | `update/` |
| `include/udsota_image.h`, `udsota_image_desc.h`, `udsota_isink.h`, `udsota_zstream.h`, `udsota_patch.h`, `udsota_coded.h` | `update/include/` |
| `udsota_bootloop.c` | `bootloop/` |
| `include/udsota_bootloop.h` | `bootloop/include/` |

| From (components/udsota_esp32/) | To |
|---|---|
| `udsota_esp32.c`, `_keys.c`, `_sa.c`, `_psa.c`, `_devid.c`, `_ctl.c` | `server/` |
| `priv/udsota_esp32_ctl.h`, `udsota_esp32_devid.h`, `udsota_esp32_sa.h` | `server/priv/` |
| `udsota_esp32_engine.c`, `_image.c` | `update/` |
| `udsota_esp32_bootloop.c` | `bootloop/` |
| `include/udsota_esp32_image.h` | `update/include/` |

The boot-loop breaker's `bootloop/` directories are the main plan's first decision. `udsota_esp32_bootloop.c` still includes the root's `udsota_esp32.h` and `udsota_esp32_priv.h`, which stay mixed. No two headers share a basename, so every existing `#include "x.h"` resolves once all new directories are on the path.

## `sources.cmake`, one per component

Only `set()` and `unset()` on absolute paths from `${CMAKE_CURRENT_LIST_DIR}`; safe in ESP-IDF's script-mode requirements pass (`component_get_requirements.cmake:107`), and `idf_component_register` takes absolute SRCS and include dirs. No `include_guard` (the root includes it, then `add_subdirectory` includes it again; re-setting is idempotent). A local helper such as `_udsota_d` is unset at the end. It never uses CANDash's names: `UDSOTA_DIR`, `UDSOTA_INC`, `UDSOTA_PRIV`, `UDSOTA_CORE_DIR`, `UDSOTA_ESP32_DIR`.

`components/udsota/sources.cmake`:

- Directories: `UDSOTA_SERVER_SRCS` (every `server/*.c`), `UDSOTA_UPDATE_SRCS` (every `update/*.c`), `UDSOTA_BOOTLOOP_SRCS` (`bootloop/udsota_bootloop.c`), `UDSOTA_SRCS` (all three).
- Include dirs: `UDSOTA_SERVER_INCLUDE_DIRS` = `server/include`; `UDSOTA_UPDATE_INCLUDE_DIRS` = `update/include`; `UDSOTA_BOOTLOOP_INCLUDE_DIRS` = `bootloop/include`; `UDSOTA_INCLUDE_DIRS` = `include`, `server/include`, `update/include`, `bootloop/include`; `UDSOTA_PRIV_INCLUDE_DIRS` = `server/priv` (step 2 empties it when `udsota_priv.h` goes).
- Units a host test links: `UDSOTA_SERVICES_SRCS` = `server/udsota_server.c`, `server/udsota_codec.c` ("`udsota_init()` and every service, no transport"; step 2 adds `update/udsota_update.c` and `update/udsota_update_codec.c` and its consumers don't change); `UDSOTA_CODEC_SRCS` (step 2 adds the update codec), `UDSOTA_RXWATCH_SRCS`, `UDSOTA_KEYS_SRCS`, `UDSOTA_IMAGE_SRCS`, `UDSOTA_ZSTREAM_SRCS` (isink + zstream; the consumer adds a tinfl), `UDSOTA_CODED_SRCS` (patch + coded; needs the zstream list and a detools decoder).
- Step 2 adds `UDSOTA_UPDATE_STATE_H` (the path of `udsota_update_state.h`) for the core-only target.

`components/udsota_esp32/sources.cmake`: `UDSOTA_ESP32_SERVER_SRCS`, `UDSOTA_ESP32_UPDATE_SRCS`, `UDSOTA_ESP32_BOOTLOOP_SRCS` (always built), `UDSOTA_ESP32_SRCS`; `UDSOTA_ESP32_INCLUDE_DIRS` = `include`, `update/include`; `UDSOTA_ESP32_PRIV_INCLUDE_DIRS` = `priv`, `server/priv`; units `UDSOTA_ESP32_IMAGE_SRCS`, `_CTL_SRCS`, `_DEVID_SRCS`, `_SA_SRCS` (`_BOOTLOOP_SRCS` above is target-only; CANDash's `test_ui_config.c:22` includes it).

Consumers, one source of truth:

- `components/udsota/CMakeLists.txt` includes it. ESP-IDF: `SRCS ${UDSOTA_SRCS}`, `INCLUDE_DIRS ${UDSOTA_INCLUDE_DIRS}`, `PRIV_INCLUDE_DIRS ${UDSOTA_PRIV_INCLUDE_DIRS}`. Plain CMake: `udsota_core` from `${UDSOTA_SRCS}` with those include dirs; only udsota's directories and isotp are on its path, so the probes still fail on a platform include.
- `components/udsota_esp32/CMakeLists.txt`: the same with the `UDSOTA_ESP32_*` variables; the `UDSOTA_COMPRESSION` block (`:19-22`) is unchanged.
- The root `CMakeLists.txt` includes both; `tools/linux_server` inherits them.
- Optional guard: the root compares `file(GLOB server/*.c update/*.c)` with `UDSOTA_SRCS` and stops on a difference, so an unlisted `.c` can't go uncompiled.

## Every edit

Root `CMakeLists.txt`:

- `:25-28`: replace `CORE_DIR`, `CORE_INC`, `CORE_PRIV`, `ESP32_DIR` with `include()`s of both files, `set(CORE_INC ${UDSOTA_INCLUDE_DIRS})`, `set(CORE_PRIV ${UDSOTA_PRIV_INCLUDE_DIRS})`, `set(CORE_TEST ${ROOT}/components/udsota/test)`. Dropping `CORE_DIR` and `ESP32_DIR` makes any missed reference fail at configure time.
- `:55` `SERVER_SRCS` becomes `${UDSOTA_SERVICES_SRCS}`.
- Core unit tests: `:69` codec list, `:72` image list, `:77-78` keys list plus `${CORE_TEST}/sha256_host.c` and `INCLUDES ${CORE_TEST}`, `:81` rxwatch, `:84` bootloop.
- Server and download tests: `:95`, `:105`, `:114`, `:125` image list; `:100` `ZSTREAM_SRCS` from the zstream list plus inflate; `:113-114` coded list.
- ESP32 port tests: `:141` esp32 include dirs; `:151-152` esp32 image plus image lists; `:157-158` ctl list and esp32 priv dirs; `:163-164` devid, keys, include and priv lists; `:169-171` sa, devid, keys, `${CORE_TEST}/sha256_host.c`, `${CORE_TEST}`, include and priv lists.
- Fake engine and fuzz: `:177-179` `${CORE_TEST}/fake_engine.c`, `${CORE_TEST}/sha256_host.c`, image list, `INCLUDES ${CORE_TEST}`; `:227` `${CORE_TEST}/fuzz_udsota.c`; `:261` coded list.
- `image_check`: `:275` esp32 image and image lists; `:276` esp32 include dirs.

Elsewhere:

- `tools/linux_server/CMakeLists.txt:7-8`: `${CORE_TEST}/fake_engine.c`, `${CORE_TEST}/sha256_host.c`, esp32 image list, `${CORE_TEST}`, esp32 include dirs.
- `.github/workflows/ci.yml:95-96`, the esp32 job's `image_check` gcc line: `-Icomponents/udsota/include -Icomponents/udsota/update/include -Icomponents/udsota_esp32/update/include` and sources `components/udsota_esp32/update/udsota_esp32_image.c components/udsota/update/udsota_image.c`. The host build won't catch a miss here.
- Comment citations: `components/isotp/CMakeLists.txt:3` to `components/udsota/server/udsota_isotp.c`; `test/test_udsota_esp32_devid.c:1`, `_sa.c:1` (re-wrap), `_ctl.c:1` gain `server/`; `client/tests/test_udsota.py:164` to `components/udsota/server/udsota_server.c`.
- Checked, no change: `tools/run_tests.sh`, `examples/esp32` CMake, the rest of `ci.yml`, `release.yml`, `cut-release.yml`, the PR template, `THIRD_PARTY.md`, `RELEASING.md`, `.gitattributes`, `tools/release.py`, `client/udsota/wire.py:1`, `tools/linux_server/README.md:3`, `udsota_delta` and `udsota_inflate` (they reach udsota's headers through `REQUIRES udsota` or `udsota_core`'s public dirs), all READMEs (basenames only).

## Commits

0. "Fuzz: a digest of every request and response on the PASS line": the no-wire-change baseline, with the four 0.8.0 digests in the commit message (see the main plan's Decisions).
1. "Build: export udsota's source lists (sources.cmake)": both files with today's flat paths and `include`/`priv`; both components, the root and `linux_server` switch to them. Same test count.
2. "Move udsota's sources into server/ and update/": `mkdir`, the 35 `git mv`s, and in the same commit the paths in both `sources.cmake`, `ci.yml:95-96` and the five comments. Moved files have no content change, so they stay exact renames, and the commit builds (a rename-only commit would break bisect).
3. "Docs: layout and sources.cmake; CHANGELOG": a paragraph in `components/udsota/README.md` near line 5, optionally the `README.md:256-257` layout table, and the Breaking entry for host builds.

## Verification

- Baseline at 0.8.0, then after commits 1 and 2: `rm -rf build && tools/run_tests.sh && ctest --test-dir build -N | tail -1`. Same count, all pass, including `udsota_core_probe_esp`, `_freertos`, the fuzz targets and `udsota_demo_server_*`.
- `git show -M --summary HEAD | grep -c 'rename .*(100%)'` prints 35.
- Stale paths, each printing nothing: `git diff --name-status -M HEAD~1 HEAD | awk '/^R/{print $2}' | xargs -I{} git grep -nF {} -- ':!CHANGELOG.md'`; `git grep -nE 'components/udsota(_esp32)?/(udsota[a-z0-9_]*\.c|include/udsota_(isotp|rxwatch|keys|image|image_desc|isink|zstream|patch|coded|bootloop|esp32_image)\.h|priv/udsota_(priv|esp32_ctl|esp32_devid|esp32_sa)\.h)' -- ':!CHANGELOG.md'`; `git grep -nE '\$\{(CORE_DIR|ESP32_DIR)\}'`.
- ESP-IDF: `. ~/.espressif/tools/activate_idf_v6.1.sh` (or `podman run --rm -v $PWD:/p -w /p espressif/idf:v6.1 ...`), then `ci.yml:85-90` for {esp32s3, esp32} × {default, compression, delta}, failing on any `warning:`; `ci.yml:94-98`'s `image_check` on each image; `idf.py size` totals identical to 0.8.0's.
- Client: `python -m pytest -q client/tests`; `UDSOTA_DEMO_SERVER=build/tools/linux_server/udsota_demo_server python -m pytest -q -rsx client/tests/test_e2e_pipe.py` shows 0 skipped (a missing binary skips silently).
- CANDash, not committed: point `third_party/udsota` at the commit-2 SHA with the edits below; `tools/run_host_tests.sh` (vcan harness included) and `tools/build.sh ws43`, `crow35`, `ws43b`. `grep -nE 'UDSOTA_(CORE|ESP32)_DIR|(^|[^_a-z])udsota[a-z0-9_]*\.c' test/host/CMakeLists.txt` prints nothing. `srv.update.dl_announced` compiles only from step 2.

## CANDash's change, exactly

`test/host/CMakeLists.txt`:

- `:54-61`: keep `UDSOTA_DIR`; replace the rest with
  ```cmake
  if(NOT EXISTS "${UDSOTA_DIR}/udsota/sources.cmake")
      message(FATAL_ERROR "udsota submodule missing: run 'git submodule update --init' from the repo root")
  endif()
  include(${UDSOTA_DIR}/udsota/sources.cmake)
  include(${UDSOTA_DIR}/udsota_esp32/sources.cmake)
  set(UDSOTA_INC  ${UDSOTA_INCLUDE_DIRS})
  set(UDSOTA_PRIV ${UDSOTA_PRIV_INCLUDE_DIRS})
  ```
  and drop `UDSOTA_CORE_DIR` and `UDSOTA_ESP32_DIR`. `add_subdirectory(isotp)` at `:62` is unchanged.
- `:319`, `:352`, `:404`, `:435`: `${UDSOTA_ESP32_DIR}/include` becomes `${UDSOTA_ESP32_INCLUDE_DIRS}`.
- `:341` `${UDSOTA_RXWATCH_SRCS}`; `:349-351` `${UDSOTA_SERVICES_SRCS} ${UDSOTA_IMAGE_SRCS} ${UDSOTA_ESP32_IMAGE_SRCS}`; `:407` `${UDSOTA_IMAGE_SRCS}`; `:414-417` `${UDSOTA_SERVICES_SRCS}` ... `${UDSOTA_IMAGE_SRCS} ${UDSOTA_ESP32_IMAGE_SRCS} ${UDSOTA_KEYS_SRCS} ${UDSOTA_RXWATCH_SRCS}`; `:537` `${UDSOTA_BOOTLOOP_SRCS}`.
- `:538-539`: `test_ui_config.c:22` `#include`s `udsota_esp32_bootloop.c` (now in `bootloop/`), so its include dirs become `get_filename_component(UDSOTA_ESP32_BOOTLOOP_C_DIR "${UDSOTA_ESP32_BOOTLOOP_SRCS}" DIRECTORY)` in place of `${UDSOTA_ESP32_DIR}`, plus `${UDSOTA_ESP32_INCLUDE_DIRS}` and `${UDSOTA_ESP32_PRIV_INCLUDE_DIRS}` (`udsota_esp32_priv.h` includes `udsota_esp32_devid.h`, now in `server/priv`).
- Comments: `test/host/test_ui_config.c:10-11` and `test/host/fakes/idf_rtc/esp_attr.h:3` follow the file.
- From step 2: `vcan_harness.c:410` reads `h->srv.update.dl_announced`.

The firmware build needs nothing: `EXTRA_COMPONENT_DIRS` is `third_party/udsota/components`, which ESP-IDF scans one level deep, so `server/` and `update/` are never taken for components (never put a CMakeLists.txt in them); `main/CMakeLists.txt` keeps `PRIV_REQUIRES udsota udsota_esp32` and `udsota_esp32_image_desc()`; every header CANDash includes is on the public include dirs; the `-Werror` loop at `CMakeLists.txt:121-135` keys on the unchanged component directory.

## Risks

- An include dir that doesn't exist is fatal in ESP-IDF. A stale empty `priv/` in a local checkout hides this; CI's clean checkout doesn't.
- Headers resolve by basename across all directories: step 2's new headers must stay unique.
- `UDSOTA_SERVICES_SRCS` must keep its meaning through step 2, or CANDash's link breaks a second time.
- Any other out-of-tree host build that names udsota files breaks: a build break, not an API break.
- Verify from fresh build directories.
