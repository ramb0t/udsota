# Seam tests and enforcement

The tests and checks that prove no wire change and keep the seam one-way. Part of the [seam plan](2026-09-29-server-update-seam.md); lines refer to 0.8.0.

## Facts from the code

- Today `worker_busy()` (`udsota_server.c:227`) calls `s->engine.poll` unguarded; 10 02 (`:465` to `:280`), 11 01 (`:1189` to `:289`) and 34 in programming with level 03 (`:649` to `:280`) reach it. F002 reaches `s->engine.confirm` at `:1099`, because `confirm_action()` returns CONFIRM_RUN without `engine.status` (`:258`). `udsota_init` already accepts `engine == NULL` (`:1338`), so the crashes come at request time.
- Failures today that don't crash: F1F1 answers `62 F1 F1 00 00000000` from `s->last_dl` (`:521`) instead of reaching the app hook; F000 answers `71 01 F0 00 FF`; FF01 and F001 answer 0x24; 34, 36 and 37 answer 0x7F or 0x24 instead of 0x11. F189, F1F0 and F1F3 already fall through to `hooks.did_read` with a NULL engine source; those rows pass today and guard against regression.
- `fuzz_udsota.c` reads no field that moves: `S.session` (`:510`, `:953`, `:992`), `S.security` and `S.session_epoch` (`:511`), `S.app_orphan` (`:940`, `:944`, `:991`), `S.job_running` (`:940`, `:1016`), `S.job_app` (`:940`); its `_Static_assert`s (`:61-68`) pin `udsota_engine_t` and `udsota_hooks_t`, which don't change.

## 1. `test_udsota_server_no_engine`

`test/test_udsota_server_no_engine.c`, added to the `foreach` at `CMakeLists.txt:88-91` so it links `SERVER_SRCS` (core plus updater after step 2). Setup: `udsota_init(&s, &cfg, NULL, udsota_mock_security(), &hooks)` with the mock's gate, phase, did_read and reset, plus comm_control, dtc_setting, did_write, routine, routine_poll, and a progress hook that counts calls. Two app modes: **none** (did_read returns 0, `routine == NULL`) and **serves** (did_read answers `AA BB` for F189, F1F0, F1F1, F1F3; routine answers `71 01 <rid> 5A` for FF01 and F000-F002 and records the rid and access).

| # | Session / state | Request | Expect |
|---|---|---|---|
| A1 | default, extended, prog, prog+03 | `34 00 44 00000000 00000040` | `7F 34 11` (today 7F, or SIGSEGV at `:227` in prog+03) |
| A2 | each session | `34` (len 1), `36 01 AA`, `36`, `37`, `37 00` | `7F <sid> 11`: 0x11 before the length and session checks |
| A3 | after A1-A2 | | gate never asked START_DOWNLOAD or CONTINUE_TRANSFER; F1F2 `seq_errors`, `repeated_blocks`, `aborts`, `withheld_fcs`, `stmin_violations` 0; phase never TRANSFERRING; `udsota_download_active()` false |
| B1 | ext and prog+03, app none | `31 01 FF01`, `F000`, `F001`, `F002` | `7F 31 31` (today 0x24, positive FF, 0x24, SIGSEGV at `:1099`) |
| B2 | ext, prog locked, prog+03, app serves | same four | `71 01 <rid> 5A`; the hook got that rid and `access.session`; no 0x33 from the core in prog locked |
| B3 | ext, app serves | `31 01 FF01 07` | reaches the app with `in_len == 1` (today 0x31: FF01 isn't served in extended) |
| B4 | default | `31 01 F002` | `7F 31 7F`: the core's session check first |
| B5 | ext | `31 03 FF01` | `7F 31 12` |
| B6 | after B1-B5 | | gate never asked ACTIVATE or CONFIRM |
| C1 | each session, app none | `22 F189`, `F1F0`, `F1F1`, `F1F3` | `7F 22 31`, `did_read` called once with that DID (F1F1 fails today) |
| C2 | app serves | same | `62 <did> AA BB` |
| C3 | any | `22 F1F2` | `62 F1 F2` + 16 bytes; `did_read` not called; updater counters 0; `ncr_timeouts` 1 after `udsota_on_rx_timeout`; `resp_pending_caps` 1 after an app routine hits the 90 s cap |
| C4 | any | `22 F186`, `22 F18C` | `62 F1 86 <session>`, `62 F1 8C 02 00 00 00 00 01` |
| D1 | default, gate allows | `10 02` | `50 02 00 32 01 F4`; gate asked ENTER_PROGRAMMING once; phase PROGRAMMING (today SIGSEGV at `:227`) |
| D2 | gate answers NRC n | `10 02` | `7F 10 n` |
| D3 | app routine pending | `10 02` | `7F 10 21` |
| D4 | app orphan after the 90 s cap | `10 02` | `7F 10 22`, gate not asked; after `routine_poll` finishes, `50 02` |
| D5 | prog | `10 02` again | `50 02`, epoch +1 |
| E1 | ext locked | `11 01` | `7F 11 33` |
| E2 | ext+01, prog+03 | `11 01` | `51 01`; `udsota_restart_armed`; one poll after tx drains gives resets == 1, session default (today SIGSEGV at `:227`) |
| E3 | app orphan / gate NRC / reset hook returns false / reset hook NULL | `11 01` | `7F 11 22` / `7F 11 n` / re-opens default, phase never ACTIVATING / `7F 11 11` |
| F1 | ext / prog | 27 01-02 / 27 03-04 | unlock works; `7F 27 7F` in default |
| F2 | ext | `28 03 03`, `85 02`, `2E 1234 AA`, `3E 00` | `68 03`, `C5 02`, `6E 12 34`, `7E 00`; the 28 and 85 hooks undo back in default |
| F3 | ext | app routine `31 01 1234` pending | 0x78 at 40 ms, final answer on poll; at 90 s `7F 31 72` and an orphan; `ms_to_deadline == JOB_POLL_MS` |
| F4 | prog | idle 5 s; `udsota_end_session`, also latched during a job | default, phase IDLE |
| F5 | any | `udsota_fc_check(s, 100, 2000, now)`, `udsota_progress()` | true, `withheld_fcs` 0; IDLE 0/0/0 and the progress hook never called |
| G | 5 states (def, ext, ext+01, prog, prog+03) × SID 0x00-0xFF × len {1, 2, 3, 4, 11} × a poll at +100 ms | any | no crash; every answer empty, positive or `7F sid nrc`, never longer than `resp_max`; 34, 36, 37 and every unserved SID give exactly `7F sid 11` |
| H | | `udsota_init(s1, cfg, NULL, sec, h)` vs `udsota_core_init(s2, cfg, sec, h)` | `memcmp(&s1, &s2) == 0`; the same return for good, NULL and broken security |

Groups A to G use only the 0.8.0 API; group H needs `udsota_core_init`. For the PR's red evidence, run commit 4's version of the file without group H (before commit 5 extracts the rows into `udsota_core_rows.h`, which needs the core headers) against the step-1 tree with the groups ordered A, B without F002, C, then B-F002, D, E (Unity dies at the first SIGSEGV), let `main()` take a test name so each crash can be shown alone, and record `gdb -batch -ex run -ex bt`: frames at `udsota_server.c:227` and `:1099`. It lands in step 2's commit 4, where it passes.

## 2. The core-only test

Lands in step 2's commit 5. The include path is `server/include`, isotp, and the updater's state header copied alone into the build tree; not `components/udsota/include` (the umbrellas), `test/` or `udsota_mock.h`, which uses engine types.

```cmake
set(CORE_ONLY_INC ${CMAKE_CURRENT_BINARY_DIR}/core_only_include)
file(REMOVE_RECURSE ${CORE_ONLY_INC})
configure_file(${UDSOTA_UPDATE_STATE_H} ${CORE_ONLY_INC}/udsota_update_state.h COPYONLY)   # the one updater header allowed
add_library(udsota_server_only OBJECT ${UDSOTA_SERVER_SRCS})
target_include_directories(udsota_server_only PUBLIC ${UDSOTA_SERVER_INCLUDE_DIRS} ${CORE_ONLY_INC})
target_link_libraries(udsota_server_only PUBLIC isotp)
target_compile_options(udsota_server_only PRIVATE -Wall -Wextra -Werror)
add_executable(test_udsota_core_only test/core_only/test_udsota_core_only.c)
target_include_directories(test_udsota_core_only PRIVATE ${TEST_DIR}/core_only)
target_compile_options(test_udsota_core_only PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(test_udsota_core_only PRIVATE udsota_server_only unity m)
add_test(NAME test_udsota_core_only COMMAND test_udsota_core_only)
```

An OBJECT library, not STATIC: an archive pulls in only referenced members, so an updater call inside an unreferenced object (`udsota_isotp.o`) would never reach the linker. A core file that includes an updater header fails to compile (`fatal error: udsota_image.h: No such file`); one that calls an updater function fails to link (`undefined reference`).

Probes on the existing `udsota_core_probe_*` pattern (`CMakeLists.txt:195-199`), each a known positive:

- `udsota_core_only_probe_updater`: `-fsyntax-only -DPROBE_UPDATER` over `test/fixtures/udsota_portable_probe.c` (add `#include "udsota_image.h"` under that define) with the core-only `-I`s; pass regex `error: (udsota_image\.h: No such file|'udsota_image\.h' file not found)`.
- `udsota_core_only_probe_state`: `-DPROBE_STATE` includes only the state header and must compile, proving it stands alone.
- `udsota_core_only_link_updater`: `${CMAKE_C_COMPILER} fixture.c $<TARGET_OBJECTS:udsota_server_only> $<TARGET_FILE:isotp> -o ...` over a fixture that references `udsota_pack_result` (declared by hand); must match `undefined reference to .?udsota_pack_result`. Linking `test_udsota_core_only` itself already proves the good case, and the existing ESP and FreeRTOS probes cover the core-only path, which is a subset. Check `$<TARGET_OBJECTS>` in `add_test` on CMake 3.20.

What it asserts:

1. Groups A to G as a shared row table in `test/core_only/udsota_core_rows.h` (core headers only), driven through `udsota_core_init()`; the no-engine test includes the same rows, which proves the two paths answer alike. `udsota_core_init` returns what `udsota_init` does for each kind of security.
2. A seam contract test: a test-local const `udsota_service_t` registered through `udsota_register_service`. It claims SID 34, RID FF01 and DID F1F1 and gets them, and unclaimed ones reach 0x11 or the app hook; `on_session` runs on 10 xx, S3 and `udsota_end_session`; its `settled` refusal gives 0x22 on 10 02 before the gate is asked; its `poll` pending gives 0x22 on 10 02 and 11 01; a job it starts with `udsota_job_start(PENDING)` is polled, gets 0x78, and at the 90 s cap calls `on_session(s, true)` and leaves `worker_orphan` set until `poll` stops pending; `download_active` gives PHASE_TRANSFERRING; an `fc_point` refusal bumps `withheld_fcs` and returns to default; `udsota_restart_arm` returns false without a reset hook, and with one shows ACTIVATING and resets, and a failed reset clears ACTIVATING; `udsota_access_check` separates "security off" from "locked"; `udsota_sat_inc16` on `counters.aborts` shows in F1F2; `udsota_end_session_now`.
3. One single-frame `22 F186` through `udsota_isotp_on_frame`, proving the transport links and runs without the updater on the idle receive limit.

## 3. The grep check

`tools/check_seam.sh`, registered as `add_test(NAME udsota_seam_grep COMMAND sh ${ROOT}/tools/check_seam.sh)` with `PASS_REGULAR_EXPRESSION "check_seam: PASS"`. Lands in step 2's commit 5.

```sh
#!/bin/sh
# Fails when a server-core source mentions the updater's member of udsota_server_t (->update or .update).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
pat='(->|\.)[[:space:]]*update([^[:alnum:]_]|$)'
scan() { grep -rnE --include='*.c' --include='*.h' "$pat" "$@" || [ $? -eq 1 ]; }   # 2 (error) still fails
# Self-check 1: the fixture holds exactly 4 hits and 3 near-misses.
n=$(scan "$root/test/fixtures/seam_grep_probe.c" | wc -l)
[ "$n" -eq 4 ] || { echo "check_seam: self-check found $n of 4 hits: the pattern is broken"; exit 2; }
# Self-check 2: a live positive, since the updater itself uses the member.
scan "$root/components/udsota/update" | grep -q . || { echo "check_seam: no hit in update/"; exit 2; }
# The scanned tree must exist and hold sources: a moved or empty directory would pass silently.
[ "$(find "$root/components/udsota/server" -name '*.c' | wc -l)" -ge 5 ] || { echo "check_seam: server/ missing"; exit 2; }
hits=$(scan "$root/components/udsota/server" "$root/components/udsota_esp32/server")
[ -z "$hits" ] || { printf '%s\n' "$hits"; echo "check_seam: server/ touches the updater's member"; exit 1; }
echo "check_seam: PASS"
```

`test/fixtures/seam_grep_probe.c`, never compiled, whose header comment must not contain the pattern: hits `s->update.dl_received;`, `srv.update.last_dl;`, `(*s) . update;`, `&s->  update;`; near-misses `#include "udsota_update.h"`, `s->update_count;`, `udsota_update_t *u;`. It scans both `server/` directories; the port's `udsota_esp32.c` touches only `counters`, so it passes.

## 4. Existing tests

Mechanical `update.` edits in step 2's commit 3, 8 files and 164 occurrences:

| File | Count | Fields |
|---|---|---|
| `test_udsota_server_download.c` | 78 | download_active 26, last_dl 19, ota_open 8, slot_verified 8, dl_received 7, dl_announced 4, next_bsc 3, dl_complete 2, cf_median_us 1 |
| `test_udsota_server_routines.c` | 23 | dl_complete 6, last_dl 6, slot_verified 6, ota_open 4, download_active 1 |
| `test_udsota_server.c` | 21 | download_active 8, last_dl 5, ota_open 5, slot_verified 2, dl_received 1 |
| `test_udsota_server_compress.c` | 21 | last_dl 11, download_active 5, one each of dl_announced, dl_compressed, dl_received, ota_open, slot_verified |
| `test_udsota_server_hooks.c` | 10 | last_dl 8, slot_verified 2 |
| `test_udsota_server_delta.c` | 6 | last_dl 3, `srv.engine =` 2 (`:566`, `:573`), dl_announced 1 |
| `test_udsota_server_nocompress.c` | 3 | last_dl 2, download_active 1 |
| `test_udsota_server_functional.c` | 2 | download_active 2 |

Proof they are mechanical (bash, `$STEP1` the step-1 commit):

```sh
F='download_active|ota_open|next_bsc|dl_announced|dl_received|dl_compressed|slot_verified|dl_complete|cf_median_us|cf_stmin_us|last_dl|dl_written|engine'
for f in test/test_udsota_server{,_compress,_delta,_download,_functional,_hooks,_nocompress,_routines}.c; do
  git show HEAD:$f | sed -E "s/\b(s|srv)\.update\.($F)\b/\1.\2/g" | diff -q <(git show $STEP1:$f) - >/dev/null || echo "NOT mechanical: $f"
done
```

No field edits: `test_udsota_server_security.c`, `_matrix.c`, `_write.c`, `_progress.c` (core fields only; `_matrix.c`, `_write.c` and `test_udsota_server.c` change their `udsota_priv.h` include); `test_udsota_esp32_ctl.c`'s `srv.stage/done/total` are on a `udsota_progress_t`; `udsota_mock.h`, `udsota_dl_harness.h` and `tools/linux_server` read no server fields.

Unchanged sources, each proven with `git diff --exit-code $STEP1 <commit> -- <files>`: `components/udsota/test/fuzz_udsota.c` through commit 5 (only its CMake sources grow; commit 6 adds the no-update block and commit 7 fixes the stale libFuzzer comment at `:27-28`), `test/test_udsota_codec.c` (it includes only the umbrella; its target links both codecs), `client/tests/test_e2e_pipe.py`, `test_e2e_vcan.py`, `demo_server.py` and `tools/linux_server/*.c` (the demo calls `udsota_init` with the fake engine; its CTest pin `718#0462F18601AAAAAA` still holds). The one named exception is `client/tests/test_udsota.py`'s `wire_header()`, a harness change.

## 5. Fuzz coverage

Today `check_coverage()` (`fuzz_udsota.c:1618-1660`) exits 1 unless every SID in `sid_served()` (`:762`) has drawn a positive answer and an NRC from fuzzed requests, every platform op was called, all 9 states were reached, and NRCs 0x13 and 0x35 were seen; the app-hooks variant also needs an app orphan and the progress variant every stage. Four variants: `fuzz_udsota`, `_app_hooks`, `_progress`, `_z`.

With the updater this stays true without a harness change. The harness is deterministic (seed `g_rng = 0x26C0FFEE`, `:1325`), but its PASS line (`:1850`) prints only counts, which an NRC swapped for another leaves unchanged. So PR 1's first commit adds a running hash (e.g. FNV-1a) over every request and response, printed on the PASS line; the four digests are pinned on the fuzz tests with `PASS_REGULAR_EXPRESSION` (`udsota_fuzz(... DIGEST <hex>)`), so `ctest` fails on a changed answer without anyone reading PASS lines. The harness never calls `udsota_on_functional_request`, so for the functional path the no-change proof is `test_udsota_server_functional`'s exact bytes. With the exact-byte unit tests, that is the no-wire-change proof.

Without the updater, step 2's commit 6 adds `udsota_fuzz(fuzz_udsota_no_update 300 DEFS UDSOTA_FUZZ_NO_UPDATE=1 UDSOTA_FUZZ_APP_HOOKS=1)` (the app hooks give 0x31 a positive answer). An additive `#if` block: `start_run` passes a NULL engine; `sid_served` drops 34, 36, 37, so a positive answer to them fails the run (for an unserved SID `check_request_answer` rejects only a positive answer and takes any known NRC); `reach()` and the `reached` loop stop at `ST_PROG_UNLOCKED` (5 states); the op coverage keeps OP_RESET plus did_write, routine and routine_poll; a new invariant says 34, 36 and 37 never get a positive answer or any NRC but 0x11 or 0x21. Random sequences reach what group G's sweep doesn't: an orphan at `poll_step` and S3 during a job. They don't reach `fc_check`, which no variant of the harness calls, nor an abort in `enter_session`, which has none to run with no service registered; group F5's row is what pins `fc_check` without a service. When 0x19 and 0x14 land, `sid_served()` must grow; an unlisted positive answer fails the run, so it enforces that itself.

## 6. CI

| Check | Mechanism | Where |
|---|---|---|
| no-engine unit test | CTest `test_udsota_server_no_engine` | `host`, via `tools/run_tests.sh` |
| core-only test, 4 include probes, 2 link probes | CTest | `host` |
| seam grep | CTest `udsota_seam_grep` | `host` |
| no wire change | the four fuzz digests equal the recorded ones | `host` (in the PRs) |
| `sources.cmake` complete | configure-time `file(GLOB)` comparison, `FATAL_ERROR` on a difference | every configure |
| engine-less fuzz | CTest `fuzz_udsota_no_update` | `host` |
| ESP32 without the updater | `sdkconfig.noupdater` in the matrix, both targets | `esp32` |
| engine really absent | `nm` shows no `esp_ota_begin` for noupdater and shows it for default | `esp32` |

Rename the host step to "... (core, isotp, port logic, seam checks, fuzz corpus)".

## 7. Per step

After step 1: `git diff -M --name-status 08cb5b0 HEAD -- components | grep -v '^R100'` lists only CMake, `sources.cmake`, README and the digest commit's edits; the ctest count equals the baseline and the fuzz digests match; client tests pass and `test_e2e_pipe.py` shows 0 skipped; the six ESP32 builds have no warnings and `idf.py size` totals equal 0.8.0's.

After step 2: the red evidence against the step-1 tree is in the PR; the new CTests pass; the mechanical-diff loop prints nothing and the per-file counts match the table; `git diff --exit-code` is clean for the unchanged list; the fuzz digests match; client, e2e and the ESP32 matrix pass; flash grows by no more than a few hundred bytes and the RAM change is recorded; CANDash's host, vcan and firmware (`tools/build.sh ws43`) build with both parts of its change; `fuzz_udsota_no_update` passes.

After step 3: the matrix passes with `noupdater` on both targets, no warnings, and the `nm` checks hold; default-config sizes equal step 2's; host results unchanged; CANDash's default firmware build unchanged.

## Risks

- `udsota_isotp.h` includes `udsota.h` today; step 2 points it at the core header, so downstream code that relied on it for engine types breaks. CANDash doesn't: it includes the umbrella itself.
- DID precedence must stay core, then service, then app hook; `test_udsota_server_hooks.c`'s `did_reads == 0` check pins it.
