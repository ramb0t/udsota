# Seam step 2: split the server and the updater

The core never names the updater; the updater reaches the core only through `udsota_service.h`. No wire change. Part of the [seam plan](2026-09-29-server-update-seam.md); lines refer to `udsota_server.c` at 0.8.0, which step 1 moves unchanged to `server/`.

## 1. The service interface

### `server/include/udsota_service.h`

Replaces `priv/udsota_priv.h`, which is deleted; `test_udsota_server.c`, `_matrix.c` and `_write.c` include this instead. `server/priv/` then holds nothing, so `UDSOTA_PRIV_INCLUDE_DIRS` becomes empty and the `udsota` component drops `PRIV_INCLUDE_DIRS`: ESP-IDF fails on an include dir that doesn't exist, and the host build wouldn't notice.

```c
#pragma once
#include "udsota_server.h"                 /* udsota_server_t, udsota_op_t, udsota_job_done_fn */

/* A service's "not mine": never a response or DID length (both are bounded by resp_max). */
#define UDSOTA_SVC_PASS ((size_t)-1)

typedef struct udsota_service {            /* const, registered once right after udsota_core_init; every member required */
    size_t (*request)(udsota_server_t *s, const uint8_t *req, size_t len,
                      uint8_t *resp, size_t resp_max, uint32_t now_ms);          /* SIDs the core doesn't own */
    size_t (*routine)(udsota_server_t *s, uint16_t rid, const uint8_t *req, size_t len, bool spr,
                      uint8_t *resp, size_t resp_max, uint32_t now_ms);          /* 31 01, after the core's 7F/13/12 */
    size_t (*read_did)(const udsota_server_t *s, uint16_t did, uint8_t *out, size_t room);
    void   (*on_session)(udsota_server_t *s, bool job_capped);                  /* every session entry, first */
    bool   (*settled)(const udsota_server_t *s);                                /* 10 02 slot rule */
    bool   (*download_active)(const udsota_server_t *s);                        /* transfer open */
    int    (*poll)(const udsota_server_t *s);                                   /* UDSOTA_PENDING while queued, else last result */
    bool   (*fc_point)(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us);   /* true = allow the FC */
    void   (*sync)(udsota_server_t *s);                                         /* end-of-call report (progress) */
} udsota_service_t;

typedef enum { UDSOTA_RESTART_RESET = 0, UDSOTA_RESTART_ACTIVATE } udsota_restart_t;
typedef struct { uint8_t session; bool unlocked; } udsota_svc_access_t;

void    udsota_register_service(udsota_server_t *s, const udsota_service_t *svc);
size_t  udsota_nrc(uint8_t *resp, size_t resp_max, uint8_t sid, uint8_t nrc);
size_t  udsota_job_start(udsota_server_t *s, uint8_t sid, bool suppress_pos, int rc, udsota_job_done_fn done,
                         uint32_t arg, uint8_t *resp, size_t resp_max, uint32_t now_ms);
uint8_t udsota_gate(const udsota_server_t *s, udsota_op_t op);
bool    udsota_worker_busy(const udsota_server_t *s);         /* core job/orphan flags, then svc->poll */
uint8_t udsota_restart_nrc(const udsota_server_t *s, udsota_op_t op);   /* worker idle, then gate */
void    udsota_end_session_now(udsota_server_t *s);           /* immediate enter_session(DEFAULT); no syncs */
bool    udsota_restart_arm(udsota_server_t *s, udsota_restart_t why, uint32_t now_ms);   /* false without hooks.reset */

static inline udsota_svc_access_t udsota_access_check(const udsota_server_t *s, uint8_t level)
{ return (udsota_svc_access_t){ .session = s->session, .unlocked = !s->secured || s->security == level }; }
static inline bool udsota_activating(const udsota_server_t *s) { return s->activating; }
static inline bool udsota_job_waiting_on(const udsota_server_t *s, udsota_job_done_fn f)
{ return s->job_running && s->job_done == f; }
static inline uint32_t udsota_job_arg(const udsota_server_t *s) { return s->job_arg; }
static inline udsota_counters_t *udsota_counters(udsota_server_t *s) { return &s->counters; }
```

The accessors are `static inline`, so they cost no flash. The updater may read `s->cfg` (`max_block_len`, `stmin_monitor`, `level_programming`) and `s->hooks.progress`; it writes only the counters, through `udsota_counters`.

### "Not mine"

- SIDs: the core's `dispatch` drops its 34/36/37 cases; `default:` calls `svc->request`, and with no service or `UDSOTA_SVC_PASS` answers `udsota_nrc(..., req[0], 0x11)`. The updater's `request` switches on 34/36/37 and passes anything else.
- RIDs: the core keeps the 0x31 preamble (1038-1048), then calls `svc->routine`; on PASS or with no service, `handle_app_routine`. The updater passes before any check or state change for a RID other than FF01 or F000-F002.
- DIDs: the core serves F186, F1F2 and F18C (only with `device_id`, as now); else `svc->read_did`; on PASS or with no service, `hooks.did_read` (0 without it); then `n == 0 || n > room` is 0x31 as today. The updater passes F189, F1F0 and F1F3 when their engine source is NULL, which keeps `test_udsota_server_hooks.c:814-830`. An engine output of `SIZE_MAX` is returned as 0 (it was 0x31 before and must not reach the app's hook).
- The sentinel never escapes: every core call site converts it, so `udsota_on_request` can't return `SIZE_MAX`.

### What each callback replaces

| Spec item | Callback | Replaces |
|---|---|---|
| SID 34/36/37 | `request` | `dispatch` 1283-1288 |
| RID FF01, F000-F002 | `routine` | `handle_routine` 1049-1107 |
| DID F189, F1F0, F1F1, F1F3 | `read_did` | `handle_read_did` 521-522, 525-526, 532-537 |
| abort a transfer on session end | `on_session(s, false)` | `enter_session` 437 to `abort_download` 402 |
| what to record at the 90 s cap | `on_session(s, true)` | `poll_job` 1516, 1520-1522 |
| conditions for 10 02 | `settled`, `download_active` | `download_nrc` 280 |
| worker has anything queued | `poll` | `worker_busy` 227 |
| result of a running or orphaned job | `poll` | `poll_job` 1508, `poll_step` 1542 |
| phase TRANSFERRING | `download_active` | `phase_of` 319 |
| progress stage and report | `sync` | `progress_sync` at 891, 1374, 1435, 1565 |
| FF01 stage | `udsota_job_waiting_on(s, check_done)` in the updater | `progress_of` 1119 |
| receive-limit switch | `download_active` | `udsota_download_active` 1386 |
| FC point | `fc_point` | `udsota_fc_check` 881-885 and `transfer_nrc` 295 |

Service API to today's code: `udsota_job_start` 1390 and `udsota_nrc` 189 (declarations move from priv); `udsota_access_check` for `dl_access_nrc` 579-583 and `handle_routine` 1055, 1058; `udsota_gate` 210; `udsota_worker_busy` 225; `udsota_restart_nrc` 287 (F001 at 1086); `udsota_end_session_now` for the refused 36 at 770; `udsota_restart_arm` for `activate_done` 959-962, `reset_arm` 918 and `handle_ecu_reset` 1196; `udsota_counters` at 302, 415, 780, 786; `udsota_activating` 1117; `udsota_job_arg` 725, 727. `udsota_restart_arm` checks `hooks.reset` itself and sets `activating` only for ACTIVATE, as today.

## 2. The state split

`update/include/udsota_update_state.h` includes only stdint, stddef and stdbool, so the core-only check can stage it alone. It holds `udsota_reason_t`, `udsota_status_t`, `udsota_result_t`, `udsota_engine_t` (the embedded engine needs them complete; an enum can't be forward-declared), `udsota_stage_t`, `udsota_progress_t` (named by `hooks.progress`) and:

```c
typedef struct {
    udsota_engine_t engine;           /* udsota_init's engine, copied (was s->engine) */
    udsota_result_t last_dl;          /* F1F1 */
    uint32_t dl_announced, dl_received, dl_written;
    uint32_t cf_median_us, cf_stmin_us;
    bool     download_active, ota_open, dl_compressed, slot_verified, dl_complete, progress_block;
    uint8_t  next_bsc, progress_stage, progress_reason;
} udsota_update_t;
```

| Fields | Side |
|---|---|
| `cfg`, `sec`, `secured`, `hooks`, `tx_pending`, `tx_pending_ctx`; `session`, `security`, `phase`, `activating`, `s3_running`, `comm_changed`, `dtc_off`, `s3_start_ms`, `session_epoch` | core |
| `job_running`, `job_pending_sent`, `job_suppress_pos`, `job_sid`, `job_start_ms`, `last_pending_ms`, `job_arg`, `job_done`, `worker_orphan`, `job_app`, `app_orphan`, `job_out_len`, `end_pending` | core |
| `counters` (the updater bumps its five through `udsota_counters`); `sa_*`, `reset_phase`, `reset_armed_ms`; new `const struct udsota_service *svc` next to `tx_pending_ctx` | core |
| `engine`, `download_active`, `ota_open`, `next_bsc`, `dl_announced`, `dl_received`, `dl_compressed`, `slot_verified`, `dl_complete`, `cf_median_us`, `cf_stmin_us`, `last_dl`, `dl_written`, `progress_stage`, `progress_reason`, `progress_block` | updater, as `update.*` |

Core names keep their top-level names: the fuzz harness, CANDash's `vcan_harness.c:519` and the port's `udsota_esp32.c:136,205,207` compile unchanged, and the fuzz harness's `_Static_assert`s on `udsota_engine_t` still hold. RAM: the table pointer adds 4 B to `udsota_server_t` (364 B on Xtensa today). Core fields are not regrouped to win it back; measure `sizeof(udsota_server_t)` with `-m32` and `s_srv` in the map file and state it.

## 3. Where each function goes

Lines not listed stay in the core unchanged.

| Line | Function | Goes to | Rewrite |
|---|---|---|---|
| 13-186 | `sa_*` | core | |
| 206-207 | forward declarations | core | drop `progress_sync`; add static helpers `svc_poll` (`UDSOTA_NRC_GENERAL_REJECT` without a service, as `app_poll` without `routine_poll`), `svc_download_active` (false without), `svc_sync` (no-op without) |
| 210 | `gate` | core | exported `udsota_gate` |
| 225 | `worker_busy` | core | exported `udsota_worker_busy`; `engine.poll(...) == PENDING` becomes `svc_poll(s) == UDSOTA_PENDING`, flags first as now |
| 231, 239, 251-275 | `status_now`, `slots_settled`, `confirm_action` | update | `slots_settled` is also `.settled` |
| 278 | `download_nrc` | update (34 only) | `!slots_settled(s) \|\| udsota_worker_busy(s) \|\| u->download_active ? 0x22 : udsota_gate(s, op)`, same call order |
| new | `program_nrc` (10 02) | core | `(v && !v->settled(s)) \|\| udsota_worker_busy(s) \|\| (v && v->download_active(s)) ? 0x22 : udsota_gate(s, ENTER_PROGRAMMING)`: today's order, slot status, flags, poll, transfer open |
| 287 | `restart_nrc` | core | exported `udsota_restart_nrc` |
| 295 | `transfer_nrc` | update | `udsota_gate`, `udsota_counters(s)->stmin_violations`, `u->cf_*` |
| 310 | `phase_of` | core | 319 becomes `svc_download_active(s)` |
| 327-397 | `phase_sync`, `orphan_job`, `apply_end_pending`, `p2*`, `pending_*`, `tx_drained`, `answered` | core | `apply_end_pending` calls `enter_session(..., false)` |
| 402 | `abort_download` | update | reached from `on_session`; `aborts` via `udsota_counters` |
| 435 | `enter_session` | core | gains `bool job_capped`; 437 becomes `if (s->svc) s->svc->on_session(s, job_capped)`; every caller passes false except the cap |
| 450 | `handle_session` | core | 465 calls `program_nrc(s)` |
| 506 | `handle_read_did` | core | the DID split above; F1F1 moves to the updater |
| 577 | `dl_access_nrc` | update | `udsota_access_check(s, s->cfg.level_programming)`: session not PROG is 7F, then not unlocked is 33 |
| 589-633 | `dl_slot_size` ... `dl_reason`, `DL_Z` | update | `DL_Z(u)` |
| 638-870 | 34, 36, 37 handlers and their done functions | update | `udsota_job_arg`; 770 becomes `udsota_end_session_now(s)`; 780, 786 counters |
| 874 | `udsota_fc_check` | core | `if (!svc_download_active(s) \|\| s->job_running) return true; if (!s->end_pending && s->svc->fc_point(s, median, stmin)) return true;` then unchanged: `withheld_fcs++`, `enter_session(DEFAULT, false)`, `phase_sync`, `svc_sync`. The latched path still skips the gate |
| new | `upd_fc_point` | update | `u->cf_median_us = median; u->cf_stmin_us = stmin; return transfer_nrc(s) == 0;` (881-883) |
| 902, 942-975 | `routine_pos`, `check_done`, `activate_done`, `confirm_done` | update | 959-962 become `(void)udsota_restart_arm(s, UDSOTA_RESTART_ACTIVATE, now_ms);`, called before returning so SPRMIB can't skip it |
| 918, 926 | `reset_arm`, `reset_poll` | core | `udsota_restart_arm`; `reset_poll` still clears `activating` |
| 979-1029 | `app_poll`, `app_routine_done`, `handle_app_routine` | core | |
| 1034 | `handle_routine` | split | core keeps 1037-1048, then `svc->routine`, on PASS `handle_app_routine`; the updater's `upd_routine` takes 1050-1107 verbatim with `udsota_access_check`, `udsota_restart_nrc`, `u->` |
| 1113-1154 | `progress_of`, `progress_sync`, `udsota_progress`, `udsota_progress_permille` | update | 1117 `udsota_activating(s)`, 1119 `udsota_job_waiting_on(s, check_done)`; `progress_sync` is `.sync`; the two public ones go in `udsota_update.h` |
| 1170 | `handle_ecu_reset` | core | 1196 `(void)udsota_restart_arm(s, UDSOTA_RESTART_RESET, now_ms)` |
| 1270 | `dispatch` | core | remove 1283-1288; `default:` to `svc->request`, then 0x11 |
| 1310 | `cfg_resolve` | core | still caps at `UDSOTA_DL_MAX_BLOCK_LEN` |
| 1333 | `udsota_init` | split | core `udsota_core_init(s, cfg, security, hooks)` = 1336-1337 and 1341-1350; `update/udsota_update.c` gets `udsota_update_init(s, engine)` (`s->update.engine = *engine; udsota_register_service(s, &k_update_service);`) and `udsota_init()` = core init, then `if (engine) udsota_update_init(s, engine)` |
| 1362, 1412, 1561 | `udsota_end_session`, `udsota_on_request`, `udsota_poll` | core | `progress_sync` calls become `svc_sync` |
| 1384 | `udsota_download_active` | core | `svc_download_active(s)` |
| 1506 | `poll_job` | core | 1508 `svc_poll(s)`; in the cap branch `const bool mine = !s->job_app;` before `orphan_job`, 1519 `enter_session(s, DEFAULT, mine)`, 1520-1522 deleted. The updater's `on_session`: `was = u->download_active \|\| u->ota_open; abort_download(s); if (job_capped && was) u->last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;` |
| 1537 | `poll_step` | core | 1542 `svc_poll(s)`; `worker_orphan` then `app_orphan`, order kept |

New in the updater: `upd_request`, `upd_routine`, `upd_read_did`, `upd_on_session`, `upd_download_active`, `upd_poll` (`u->engine.poll(ctx)`), `upd_fc_point`, and `static const udsota_service_t k_update_service`. The core no longer needs `udsota_rxwatch.h`; `UDSOTA_CF_MEDIAN_NONE` moves with the 34 handler.

## 4. Headers and codec

| New header | Contents |
|---|---|
| `server/include/udsota_server_wire.h` | all SIDs (dispatch owns them, 34/36/37 included), framing and `UDSOTA_POS`, sub-function constants (`RESET_HARD`, `RC_START`, `TP_ZERO`, `WRITE_DID_MIN_LEN`, `CC_*`, `DTC_*`), NRCs, `udsota_session_t`, SA constants, P2/P2*/S3, DIDs F186/F18C/F1F2, `UDSOTA_SERIAL_LEN`, `udsota_counters_t`, `COUNTERS_LEN`, pack/unpack counters, `sat_inc16`, put/get u16/u32, `UDSOTA_DL_MAX_BLOCK_LEN` |
| `server/include/udsota_server.h` | includes the server wire header and `udsota_update_state.h`; `JOB_CAP`, `JOB_POLL`, `IDLE_POLL`, `READ_DID_MAX`, `RESET_TX_WAIT`, `UDSOTA_PENDING`, `STMIN_DEFAULT`, `BLOCK_SIZE_DEFAULT`, `udsota_op_t`, `udsota_phase_t`, `udsota_security_t`, `udsota_access_t`, `udsota_hooks_t`, `udsota_config_t`, `udsota_job_done_fn`, `udsota_server_t`, `udsota_core_init` and every core entry point |
| `server/include/udsota_service.h` | section 1 |
| `update/include/udsota_update_state.h` | section 2 |
| `update/include/udsota_update_wire.h` | includes the state header; `DL_DFI*`, `DL_FMT`, `ALFID`, `LFID`, `DL_MAX_DATA`, `DL_REQ_LEN`, `TD_MIN_LEN`, `DL_Z_BOUND`, DIDs F189/F1F0/F1F1/F1F3, `SHA256_LEN`, RIDs FF01/F000-F002, `RESUME_NOT_AVAILABLE`, `SLOT_*`, `udsota_img_state_t`, `udsota_other_state_t`, `STATUS_*` flags, `STATUS_LEN`, `RESULT_LEN`, pack/unpack status and result |
| `update/include/udsota_update.h` | `UDSOTA_COMPRESSION`, `UDSOTA_SLOT_SIZE_DEFAULT`, `udsota_update_init`, `udsota_init`, `udsota_progress`, `udsota_progress_permille` |
| top `udsota.h`, `udsota_wire.h` | umbrellas: server + update header; server wire + update wire |

Includes: `udsota_isotp.h:15` to `udsota_server.h`; `udsota_isotp.c:8` and `server/udsota_codec.c:3` to `udsota_server_wire.h` (the codec's umbrella include would fail the core-only build); `server/udsota_server.c` to `udsota_server.h` and `udsota_service.h` only; updater sources and `udsota_image.h`, `udsota_isink.h`, `udsota_zstream.h`, `udsota_patch.h` (for `udsota_reason_t`) to `udsota_update_wire.h`. Every consumer already includes the umbrellas. `udsota_update_wire.h` includes `udsota_server_wire.h` (for `UDSOTA_DL_MAX_BLOCK_LEN` beside `UDSOTA_DL_MAX_DATA`), so `ci.yml`'s hand-written `image_check` gcc line gains `-Icomponents/udsota/server/include`; the host build won't catch a miss there. Codec: `server/udsota_codec.c` keeps the byte helpers, `sat_inc16` and F1F2; `update/udsota_update_codec.c` takes F1F0 and F1F1 (41-93); `test_udsota_codec` links both. After the split only `update/udsota_update.c` reads `UDSOTA_COMPRESSION`; the port still sets it on the whole library, which is harmless.

`client/tests/test_udsota.py:1115-1158` parses `udsota_wire.h`'s text for `udsota_reason_t` and the `#define`s; once it is an umbrella that raises AttributeError and KeyError. Its `wire_header()` follows `#include "udsota_*"` lines recursively into `server/include` and `update/include` (`udsota_reason_t` sits two levels down: umbrella, update wire, state header); the assertions stay the same.

## 5. With no updater registered

- 10 02: `program_nrc` runs `udsota_worker_busy` (core flags only), then `gate(ENTER_PROGRAMMING)`; no NULL `engine.poll`.
- 11 01: `udsota_restart_nrc`, the same `worker_busy`, then `gate(RESET)`.
- 34/36/37: `dispatch`'s `default:` gives 0x11.
- 31 01 FF01, F000-F002: the core preamble, then `handle_app_routine` (0x31 without `hooks.routine`, else the app's answer); F002 no longer reaches a NULL `engine.confirm`.
- 22 F189, F1F0, F1F1, F1F3: `did_read`, or 0x31.
- F1F2: the updater's five counters read 0; `withheld_fcs` stays 0 because `fc_check` returns early.
- The phase is never TRANSFERRING or ACTIVATING; `hooks.progress` is never called; `udsota_progress` reads IDLE, 0 of 0.
- Transport: `udsota_download_active` false (idle receive limit); `udsota_fc_check` true.

## 6. Commits

Each builds and passes `tools/run_tests.sh`, the four fuzz digests, and one ESP-IDF build (esp32s3 default).

1. Header split: the new headers, umbrellas, `udsota_isotp.h/.c` and `udsota_codec.c` on the core headers, `udsota_priv.h` replaced by `udsota_service.h` (declarations only yet) with `UDSOTA_PRIV_INCLUDE_DIRS` emptied, `ci.yml`'s `image_check` include, `test_udsota.py`'s `wire_header()`. Struct still flat; no `.c` logic change.
2. Codec split: `update/udsota_update_codec.c`; `sources.cmake` and test link lists.
3. State split, renames only: `udsota_update_t`, the `update` member, `s->X` to `s->update.X` in `udsota_server.c` and eight tests. The compiler checks it.
4. Seam logic, still one file: the service API bodies, the table, `udsota_register_service`, `udsota_core_init`, `udsota_update_init` and every rewrite in section 3; adds `test_udsota_server_no_engine` (its red run against the step-1 tree recorded in the PR). Review hardest; run all four fuzz variants and the e2e tests.
5. Physical split: the updater half to `update/udsota_update.c`; `sources.cmake` (which the port's CMake and host `SERVER_SRCS` already follow); the core-only OBJECT target, its probes and test; `tools/check_seam.sh`. The grep check can only land here: until now `server/udsota_server.c` contains `s->update.`.
6. `fuzz_udsota_no_update` (see the tests appendix): an additive `#if` block, so `fuzz_udsota.c` is unchanged through commit 5 and the existing digests don't move.
7. Size and docs: `idf.py size` / `size-components` on `examples/esp32` against 0.8.0; `sizeof(udsota_server_t)`; CHANGELOG with the Breaking entries (including `udsota_isotp.h` no longer pulling in `udsota.h`); the README items and stale text listed in the main plan.

## 7. Risks

- **A leaking sentinel.** `udsota_on_request` returning `SIZE_MAX` would make `tx_response` send garbage. The no-engine test asserts it can't, and the fuzz harness bounds `n <= resp_max`. A suppressed 0 and PASS are distinct values.
- **SPRMIB and jobs.** `job_suppress_pos`, `finish_job`'s `drop_pos` and `is_positive` stay in the core untouched; the updater still passes `spr` into `udsota_job_start`; its immediate `spr ? 0 : routine_pos` paths move verbatim.
- **Orphans.** `worker_orphan` now means "the service's job was orphaned", cleared only by `svc->poll`. Register only right after `udsota_core_init`: registering while a job or orphan exists would change which poll answers it.
- **Phase and progress timing.** `svc_sync` sits exactly where `progress_sync` was, with phase-then-progress kept; `fuzz_udsota_progress` checks it. The one reorder: at the cap, F1F1's `WORKER_TIMEOUT` is written inside `enter_session`, before the relock, epoch and `restore_default_comm`, rather than after. Not visible on the wire or through `hooks.progress`; only a `comm_control` or `dtc_setting` hook reading the struct could see it.
- **NRC order.** Keep 10 02's order (merging `settled` and `download_active` into one callback would skip `engine.poll` when a transfer is open: same wire result, but avoidable); the updater decides PASS before any check; `fc_check` keeps `download_active` before `job_running`. DID branches are disjoint, so their order doesn't matter.
- **Flash.** Estimated 250-400 B: the table (36 B rodata), about 15 guarded indirect calls at about 12 B, the exported `gate`, `worker_busy` and `restart_nrc` losing inlining, and the init wrapper. Over budget, the fallback is a stub "no service" table in place of the NULL checks.
