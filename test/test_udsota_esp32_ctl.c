/* Host tests for the ESP32 port's control block (components/udsota_esp32/udsota_esp32_ctl.c) with the
 * real udsota server: an app phase hook that calls back into the port neither deadlocks nor recurses,
 * an end-session it requests runs after the current request, one requested during a job runs after
 * that job's answer, the app's did_write, routine and routine_poll reach the app through the
 * port's wrappers with its ctx, the request's bytes and the session's access state, the progress
 * snapshot copies what the server reported, under the port's lock, before the app's own hook runs, and the
 * incoming version is set by an accepted first block, kept after the download ends and cleared by the next
 * accepted 34 in the same locked copy as its report. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_wire.h"
#include "udsota_esp32_ctl.h"

#define NOW 1000u

static udsota_esp32_ctl_t s_ctl;
static udsota_hooks_t     s_hooks;
static udsota_server_t    s_srv;
static int                s_marker;          /* the app's ctx */
static const void        *s_ctx_seen;        /* the ctx an app hook last received */
static int                s_phase_calls;
static int                s_depth, s_max_depth;
static udsota_phase_t     s_seen_arg;        /* the app phase hook's last argument */
static udsota_phase_t     s_seen_read;       /* what udsota_esp32_ctl_phase() returned inside it */
static bool               s_end_from_hook;   /* the app phase hook asks for an end-session on EXTENDED */
static int                s_default_resets, s_app_resets;
static uint8_t            s_running_state;   /* the mock engine's running image state */
static int                s_poll;            /* the mock engine's poll() and confirm() result */
static int                s_writes, s_routines, s_routine_polls;   /* app write and routine hook calls */
static uint16_t           s_write_did, s_routine_rid;
static uint8_t            s_write_data[4];   /* the first bytes of the last value written */
static size_t             s_write_len, s_routine_in_len;
static uint8_t            s_routine_in0;     /* the first option byte of the last routine */
static udsota_access_t    s_write_access, s_routine_access;
static int                s_routine_poll_ret;   /* what app_routine_poll returns */
static int                s_progress_calls;  /* app progress hook calls */
static udsota_progress_t  s_progress_arg;    /* what the app's progress hook last got */
static udsota_progress_t  s_progress_read;   /* what udsota_esp32_ctl_progress() returned inside it */
static int                s_lock_depth;      /* the fake lock: held now, and its most, lock and unlock calls */
static int                s_lock_max, s_locks, s_unlocks;
static int                s_lock_depth_in_hook;   /* s_lock_depth while the app's progress hook ran */
static const void        *s_lock_ctx_seen;
static char               s_version_at_lock[UDSOTA_ESP32_CTL_VERSION_MAX];     /* s_ctl's, as the last lock began */
static char               s_version_at_unlock[UDSOTA_ESP32_CTL_VERSION_MAX];   /* and as it ended */
static udsota_stage_t     s_stage_at_lock, s_stage_at_unlock;
static const char        *s_first_version;   /* the mock first-block check: what an accepted block stores */
static bool               s_refuse_first;    /* the mock first-block check refuses the block */
static char               s_version_in_hook[UDSOTA_ESP32_CTL_VERSION_MAX];     /* what the app's progress hook read */

/* Mock engine, as the port's check_first_block(): the first block passes unless s_refuse_first, and a pass
 * stores s_first_version (when set) as the incoming version. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    if (s_refuse_first) {
        *why = UDSOTA_DL_BAD_HEADER;
        return 1;
    }
    if (s_first_version != NULL) {
        udsota_esp32_ctl_set_version(&s_ctl, s_first_version, UDSOTA_ESP32_CTL_VERSION_MAX);
    }
    *why = UDSOTA_DL_OK;
    return 0;
}

/* Mock engine: begin succeeds at once. */
static int eng_begin(void *ctx, uint32_t size)
{
    return 0;
}

/* Mock engine: write succeeds at once. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    return 0;
}

/* Mock engine: verify and activate succeed at once. */
static int eng_ok(void *ctx)
{
    return 0;
}

/* Mock engine: confirm queues a job (s_poll is UDSOTA_PENDING) or succeeds at once. */
static int eng_confirm(void *ctx)
{
    return s_poll;
}

/* Mock engine: UDSOTA_PENDING while the test holds the job open, then its result. */
static int eng_poll(void *ctx)
{
    return s_poll;
}

/* Mock engine: abort has nothing to stop. */
static void eng_abort(void *ctx)
{
}

/* Mock engine: slot 0 runs and is the boot slot, in s_running_state. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->running_slot = UDSOTA_SLOT_OTA0;
    out->boot_slot = UDSOTA_SLOT_OTA0;
    out->running_state = s_running_state;
}

static const udsota_engine_t k_engine = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_ok,
    .activate = eng_ok, .confirm = eng_confirm, .abort = eng_abort, .unverify = NULL, .poll = eng_poll,
    .status = eng_status, .running_sha = NULL, .version = NULL, .slot_size = 0u, .ctx = NULL,
};

/* The app's phase hook: calls back into the port as an app may, and records what it saw. */
static void app_phase(void *ctx, udsota_phase_t p)
{
    s_ctx_seen = ctx;
    s_depth++;
    if (s_depth > s_max_depth) {
        s_max_depth = s_depth;
    }
    s_phase_calls++;
    s_seen_arg = p;
    s_seen_read = udsota_esp32_ctl_phase(&s_ctl);
    if (s_end_from_hook && p == UDSOTA_PHASE_EXTENDED) {
        udsota_esp32_ctl_request_end(&s_ctl);
    }
    s_depth--;
}

/* The app's gate: refuses 11 01 only. */
static uint8_t app_gate(void *ctx, udsota_op_t op)
{
    s_ctx_seen = ctx;
    return (op == UDSOTA_OP_RESET) ? 0x22u : 0u;
}

/* The app's did_read: answers three bytes for any DID. */
static size_t app_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    s_ctx_seen = ctx;
    return 3u;
}

/* The port's default reset stand-in: counts, and "fails" so the caller would re-open. */
static bool default_reset(void *ctx)
{
    s_ctx_seen = ctx;
    s_default_resets++;
    return false;
}

/* The app's reset: counts, and "fails". */
static bool app_reset(void *ctx)
{
    s_ctx_seen = ctx;
    s_app_resets++;
    return false;
}

/* The app's did_write: records what arrived and accepts the write. */
static uint8_t app_did_write(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access)
{
    s_ctx_seen = ctx;
    s_writes++;
    s_write_did = did;
    s_write_len = len;
    memcpy(s_write_data, data, (len < sizeof s_write_data) ? len : sizeof s_write_data);
    s_write_access = access;
    return 0u;
}

/* The app's routine: records what arrived and leaves the routine pending. */
static int app_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    s_ctx_seen = ctx;
    s_routines++;
    s_routine_rid = rid;
    s_routine_in_len = in_len;
    s_routine_in0 = (in_len > 0u) ? in[0] : 0u;
    s_routine_access = access;
    *out_len = 0u;
    return UDSOTA_PENDING;
}

/* The app's routine_poll: returns s_routine_poll_ret, with one status byte 00 when that is 0. */
static int app_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    s_ctx_seen = ctx;
    s_routine_polls++;
    *out_len = 0u;
    if (s_routine_poll_ret == 0 && out_max >= 1u) {
        out[0] = 0x00u;
        *out_len = 1u;
    }
    return s_routine_poll_ret;
}

/* The app's progress hook: records its ctx and argument, whether the port's lock was held, and what the
 * snapshot reads from inside it (a call back into the port). */
static void app_progress(void *ctx, const udsota_progress_t *p)
{
    s_ctx_seen = ctx;
    s_progress_calls++;
    s_progress_arg = *p;
    s_lock_depth_in_hook = s_lock_depth;
    udsota_esp32_ctl_progress(&s_ctl, &s_progress_read);
    (void)udsota_esp32_ctl_version(&s_ctl, s_version_in_hook);
}

/* The fake snapshot lock: counts, and tracks how deep it is held. */
static void fake_lock(void *ctx)
{
    s_lock_ctx_seen = ctx;
    s_locks++;
    s_lock_depth++;
    memcpy(s_version_at_lock, s_ctl.version, sizeof s_version_at_lock);
    s_stage_at_lock = s_ctl.progress.stage;
    if (s_lock_depth > s_lock_max) {
        s_lock_max = s_lock_depth;
    }
}

/* The fake snapshot unlock. */
static void fake_unlock(void *ctx)
{
    s_lock_ctx_seen = ctx;
    s_unlocks++;
    s_lock_depth--;
    memcpy(s_version_at_unlock, s_ctl.version, sizeof s_version_at_unlock);
    s_stage_at_unlock = s_ctl.progress.stage;
}

/* Wraps app's hooks and starts a server on them with default config and no security. */
static void start(const udsota_hooks_t *app)
{
    const udsota_config_t cfg = {0};
    udsota_esp32_ctl_init(&s_ctl, app, default_reset, &s_hooks);
    udsota_init(&s_srv, &cfg, &k_engine, NULL, &s_hooks);
}

/* Sends 10 03 and checks the positive answer. */
static void enter_extended(uint32_t now)
{
    const uint8_t req[] = {0x10, 0x03};
    uint8_t resp[16];
    TEST_ASSERT_EQUAL_UINT(6u, udsota_on_request(&s_srv, req, sizeof req, resp, sizeof resp, now));
    TEST_ASSERT_EQUAL_HEX8(0x50, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x03, resp[1]);
}

/* Unity hook: clears the recorders; the engine is idle with a VALID image. */
void setUp(void)
{
    s_ctx_seen = NULL;
    s_phase_calls = 0;
    s_depth = 0;
    s_max_depth = 0;
    s_seen_arg = UDSOTA_PHASE_IDLE;
    s_seen_read = UDSOTA_PHASE_IDLE;
    s_end_from_hook = false;
    s_default_resets = 0;
    s_app_resets = 0;
    s_running_state = UDSOTA_IMG_VALID;
    s_poll = 0;
    s_writes = 0;
    s_routines = 0;
    s_routine_polls = 0;
    s_write_did = 0u;
    s_routine_rid = 0u;
    memset(s_write_data, 0, sizeof s_write_data);
    s_write_len = 0u;
    s_routine_in_len = 0u;
    s_routine_in0 = 0u;
    s_write_access = (udsota_access_t){0};
    s_routine_access = (udsota_access_t){0};
    s_routine_poll_ret = 0;
    s_progress_calls = 0;
    s_progress_arg = (udsota_progress_t){0};
    s_progress_read = (udsota_progress_t){0};
    s_lock_depth = 0;
    s_lock_max = 0;
    s_locks = 0;
    s_unlocks = 0;
    s_lock_depth_in_hook = -1;
    s_lock_ctx_seen = NULL;
    memset(s_version_at_lock, 0, sizeof s_version_at_lock);
    memset(s_version_at_unlock, 0, sizeof s_version_at_unlock);
    s_stage_at_lock = UDSOTA_STAGE_IDLE;
    s_stage_at_unlock = UDSOTA_STAGE_IDLE;
    s_first_version = NULL;
    s_refuse_first = false;
    memset(s_version_in_hook, 0x55, sizeof s_version_in_hook);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* A phase hook that reads the phase and asks for an end-session from inside the server reads the new
 * phase, is never re-entered, and the session ends only when the diag task takes the request. */
static void test_end_session_from_phase_hook_runs_after_the_request(void)
{
    const udsota_hooks_t app = { .phase = app_phase, .ctx = &s_marker };
    start(&app);
    s_end_from_hook = true;
    const int before = s_phase_calls;
    enter_extended(NOW);
    TEST_ASSERT_EQUAL_INT(before + 1, s_phase_calls);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, s_seen_arg);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, s_seen_read);       /* stored before the app's hook ran */
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_phase(&s_srv));   /* not ended inside the request */
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 1u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s_srv));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_esp32_ctl_phase(&s_ctl));
    TEST_ASSERT_EQUAL_INT(before + 2, s_phase_calls);
    TEST_ASSERT_EQUAL_INT(1, s_max_depth);
    TEST_ASSERT_FALSE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 2u));
    TEST_ASSERT_EQUAL_INT(before + 2, s_phase_calls);
}

/* An end requested while a ConfirmImage job runs is latched by the core: the session stays open until
 * the job's answer has been built, and ends at the next poll after it (task-2 conflict 3). */
static void test_end_requested_during_a_job_applies_after_its_answer(void)
{
    const udsota_hooks_t app = { .phase = app_phase, .ctx = &s_marker };
    start(&app);
    s_running_state = UDSOTA_IMG_PENDING_VERIFY;
    enter_extended(NOW);
    s_poll = UDSOTA_PENDING;
    const uint8_t conf[] = {0x31, 0x01, (uint8_t)(UDSOTA_RID_CONFIRM_IMAGE >> 8), (uint8_t)UDSOTA_RID_CONFIRM_IMAGE};
    uint8_t resp[16];
    TEST_ASSERT_EQUAL_UINT(0u, udsota_on_request(&s_srv, conf, sizeof conf, resp, sizeof resp, NOW + 1u));
    udsota_esp32_ctl_request_end(&s_ctl);
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 2u));   /* taken, and latched by the core */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_phase(&s_srv));
    TEST_ASSERT_EQUAL_UINT(0u, udsota_poll(&s_srv, resp, sizeof resp, NOW + 3u));   /* job still running */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_phase(&s_srv));
    s_poll = 0;
    const size_t n = udsota_poll(&s_srv, resp, sizeof resp, NOW + 4u);
    TEST_ASSERT_TRUE(n >= 4u);
    TEST_ASSERT_EQUAL_HEX8(0x71, resp[0]);                               /* the job's answer still goes out */
    (void)udsota_poll(&s_srv, resp, sizeof resp, NOW + 5u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s_srv));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_esp32_ctl_phase(&s_ctl));
    TEST_ASSERT_EQUAL_INT(1, s_max_depth);
}

/* Requests raised before the diag task runs count once; with no app hooks the phase copy still
 * follows the server. */
static void test_requests_coalesce_and_phase_tracks_without_app_hooks(void)
{
    start(NULL);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_esp32_ctl_phase(&s_ctl));
    enter_extended(NOW);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_esp32_ctl_phase(&s_ctl));
    udsota_esp32_ctl_request_end(&s_ctl);
    udsota_esp32_ctl_request_end(&s_ctl);
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 1u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_esp32_ctl_phase(&s_ctl));
    TEST_ASSERT_FALSE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 2u));
}

/* The app's comm_control: records its ctx and refuses disableRxAndTx with 0x22. */
static uint8_t app_comm_control(void *ctx, uint8_t control, uint8_t comm_type)
{
    (void)comm_type;
    s_ctx_seen = ctx;
    return control == 0x03u ? 0x22u : 0u;
}

/* The app's dtc_setting: records its ctx. */
static void app_dtc_setting(void *ctx, bool on)
{
    (void)on;
    s_ctx_seen = ctx;
}

/* The wrapped hooks pass the app's ctx, keep a NULL gate, did_read or stmin_us NULL so the core's
 * default holds, and reset falls back to the port's default only when the app has none. */
static void test_wrapped_hooks_forward_app_ctx_and_keep_nulls(void)
{
    const udsota_hooks_t app = { .gate = app_gate, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &app, default_reset, &s_hooks);
    TEST_ASSERT_EQUAL_PTR(&s_ctl, s_hooks.ctx);
    TEST_ASSERT_TRUE(s_hooks.gate != NULL && s_hooks.phase != NULL && s_hooks.reset != NULL);
    TEST_ASSERT_TRUE(s_hooks.did_read == NULL && s_hooks.stmin_us == NULL);
    TEST_ASSERT_EQUAL_HEX8(0x22, s_hooks.gate(s_hooks.ctx, UDSOTA_OP_RESET));
    TEST_ASSERT_EQUAL_HEX8(0x00, s_hooks.gate(s_hooks.ctx, UDSOTA_OP_ACTIVATE));
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    s_ctx_seen = NULL;
    TEST_ASSERT_FALSE(s_hooks.reset(s_hooks.ctx));
    TEST_ASSERT_EQUAL_INT(1, s_default_resets);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);

    const udsota_hooks_t app2 = { .did_read = app_did_read, .reset = app_reset, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &app2, default_reset, &s_hooks);
    uint8_t buf[4];
    TEST_ASSERT_EQUAL_UINT(3u, s_hooks.did_read(s_hooks.ctx, 0xF191u, buf, sizeof buf));
    TEST_ASSERT_FALSE(s_hooks.reset(s_hooks.ctx));
    TEST_ASSERT_EQUAL_INT(1, s_app_resets);
    TEST_ASSERT_EQUAL_INT(1, s_default_resets);

    udsota_esp32_ctl_init(&s_ctl, NULL, NULL, &s_hooks);
    TEST_ASSERT_TRUE(s_hooks.reset == NULL && s_hooks.gate == NULL && s_hooks.phase != NULL);
    TEST_ASSERT_TRUE(s_hooks.comm_control == NULL && s_hooks.dtc_setting == NULL);

    const udsota_hooks_t app3 = { .comm_control = app_comm_control, .dtc_setting = app_dtc_setting, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &app3, NULL, &s_hooks);
    s_ctx_seen = NULL;
    TEST_ASSERT_EQUAL_HEX8(0x22, s_hooks.comm_control(s_hooks.ctx, 0x03, 0x01));
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    s_ctx_seen = NULL;
    s_hooks.dtc_setting(s_hooks.ctx, false);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
}

/* 2E and 31 01 on an app RID reach the app's did_write, routine and routine_poll through the port and the
 * real server, with the app's ctx, the request's bytes and the session's access state. The pending routine
 * answers from its poll, and a repeat 10 03 hands the next write the next epoch. */
static void test_write_and_routine_hooks_reach_the_app(void)
{
    const udsota_hooks_t app = {
        .did_write = app_did_write, .routine = app_routine, .routine_poll = app_routine_poll, .ctx = &s_marker,
    };
    start(&app);
    enter_extended(NOW);
    uint8_t resp[16];

    const uint8_t wr[] = {0x2E, 0x02, 0x00, 0xAB};
    TEST_ASSERT_EQUAL_UINT(3u, udsota_on_request(&s_srv, wr, sizeof wr, resp, sizeof resp, NOW + 1u));
    TEST_ASSERT_EQUAL_HEX8(0x6E, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(0x00, resp[2]);
    TEST_ASSERT_EQUAL_INT(1, s_writes);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_HEX16(0x0200, s_write_did);
    TEST_ASSERT_EQUAL_UINT(1u, s_write_len);
    TEST_ASSERT_EQUAL_HEX8(0xAB, s_write_data[0]);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s_write_access.session);
    TEST_ASSERT_EQUAL_UINT8(0u, s_write_access.unlocked_level);   /* no security: nothing unlocked */

    s_ctx_seen = NULL;
    s_routine_poll_ret = UDSOTA_PENDING;
    const uint8_t rc[] = {0x31, 0x01, 0x12, 0x34, 0x07};
    TEST_ASSERT_EQUAL_UINT(0u, udsota_on_request(&s_srv, rc, sizeof rc, resp, sizeof resp, NOW + 2u));
    TEST_ASSERT_EQUAL_INT(1, s_routines);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_HEX16(0x1234, s_routine_rid);
    TEST_ASSERT_EQUAL_UINT(1u, s_routine_in_len);
    TEST_ASSERT_EQUAL_HEX8(0x07, s_routine_in0);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s_routine_access.session);
    TEST_ASSERT_EQUAL_UINT32(s_write_access.epoch, s_routine_access.epoch);   /* same session, same epoch */

    s_ctx_seen = NULL;
    TEST_ASSERT_EQUAL_UINT(0u, udsota_poll(&s_srv, resp, sizeof resp, NOW + 3u));   /* pending, before any 0x78 */
    TEST_ASSERT_TRUE(s_routine_polls >= 1);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    s_routine_poll_ret = 0;
    TEST_ASSERT_EQUAL_UINT(5u, udsota_poll(&s_srv, resp, sizeof resp, NOW + 4u));
    TEST_ASSERT_EQUAL_HEX8(0x71, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(0x12, resp[2]);
    TEST_ASSERT_EQUAL_HEX8(0x34, resp[3]);
    TEST_ASSERT_EQUAL_HEX8(0x00, resp[4]);

    enter_extended(NOW + 5u);                         /* a repeat 10 03 enters the session again */
    TEST_ASSERT_EQUAL_UINT(3u, udsota_on_request(&s_srv, wr, sizeof wr, resp, sizeof resp, NOW + 6u));
    TEST_ASSERT_EQUAL_HEX8(0x6E, resp[0]);
    TEST_ASSERT_EQUAL_INT(2, s_writes);
    TEST_ASSERT_EQUAL_UINT32(s_routine_access.epoch + 1u, s_write_access.epoch);
}

/* Each of did_write, routine and routine_poll is wrapped only when the app sets it, and a direct call
 * through the wrapper reaches the app's hook with the app's ctx and the caller's access state unchanged. */
static void test_write_and_routine_wrappers_follow_each_app_hook(void)
{
    const udsota_access_t acc = { .session = UDSOTA_SESSION_PROGRAMMING, .unlocked_level = 0x03u, .epoch = 7u };
    uint8_t out[4];
    size_t n = 99u;

    const udsota_hooks_t only_poll = { .routine_poll = app_routine_poll, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &only_poll, default_reset, &s_hooks);
    TEST_ASSERT_NULL(s_hooks.did_write);
    TEST_ASSERT_NULL(s_hooks.routine);
    TEST_ASSERT_NOT_NULL(s_hooks.routine_poll);
    TEST_ASSERT_EQUAL_INT(0, s_hooks.routine_poll(s_hooks.ctx, out, sizeof out, &n));
    TEST_ASSERT_EQUAL_UINT(1u, n);
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);

    const udsota_hooks_t only_write = { .did_write = app_did_write, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &only_write, default_reset, &s_hooks);
    TEST_ASSERT_NOT_NULL(s_hooks.did_write);
    TEST_ASSERT_NULL(s_hooks.routine);
    TEST_ASSERT_NULL(s_hooks.routine_poll);
    const uint8_t v[] = {0x01, 0x02};
    s_ctx_seen = NULL;
    TEST_ASSERT_EQUAL_HEX8(0x00, s_hooks.did_write(s_hooks.ctx, 0xF1B0u, v, sizeof v, acc));
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_HEX16(0xF1B0, s_write_did);
    TEST_ASSERT_EQUAL_UINT(2u, s_write_len);
    TEST_ASSERT_EQUAL_HEX8(0x02, s_write_data[1]);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_PROGRAMMING, s_write_access.session);
    TEST_ASSERT_EQUAL_UINT8(0x03u, s_write_access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(7u, s_write_access.epoch);

    const udsota_hooks_t only_routine = { .routine = app_routine, .ctx = &s_marker };
    udsota_esp32_ctl_init(&s_ctl, &only_routine, default_reset, &s_hooks);
    TEST_ASSERT_NULL(s_hooks.did_write);
    TEST_ASSERT_NOT_NULL(s_hooks.routine);
    TEST_ASSERT_NULL(s_hooks.routine_poll);
    const uint8_t in[] = {0x07};
    s_ctx_seen = NULL;
    TEST_ASSERT_EQUAL_INT(UDSOTA_PENDING, s_hooks.routine(s_hooks.ctx, 0x1234u, in, sizeof in, out, sizeof out, &n, acc));
    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_HEX16(0x1234, s_routine_rid);
    TEST_ASSERT_EQUAL_UINT(1u, s_routine_in_len);
    TEST_ASSERT_EQUAL_HEX8(0x07, s_routine_in0);
    TEST_ASSERT_EQUAL_UINT8(0x03u, s_routine_access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(7u, s_routine_access.epoch);
}

/* With no app write or routine hooks the port leaves all three NULL, so the core answers as it always has:
 * 2E is 0x11 and an app RID is 0x31. */
static void test_without_write_and_routine_hooks_the_core_answers_as_before(void)
{
    start(NULL);
    TEST_ASSERT_TRUE(s_hooks.did_write == NULL && s_hooks.routine == NULL && s_hooks.routine_poll == NULL);
    enter_extended(NOW);
    uint8_t resp[16];
    const uint8_t wr[] = {0x2E, 0x02, 0x00, 0xAB};
    TEST_ASSERT_EQUAL_UINT(3u, udsota_on_request(&s_srv, wr, sizeof wr, resp, sizeof resp, NOW + 1u));
    TEST_ASSERT_EQUAL_HEX8(0x7F, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x2E, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(0x11, resp[2]);
    const uint8_t rc[] = {0x31, 0x01, 0x12, 0x34, 0x07};
    TEST_ASSERT_EQUAL_UINT(3u, udsota_on_request(&s_srv, rc, sizeof rc, resp, sizeof resp, NOW + 2u));
    TEST_ASSERT_EQUAL_HEX8(0x7F, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x31, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(0x31, resp[2]);
}

/* Sends req and asserts the answer's first byte. */
static void exchange(const uint8_t *req, size_t len, uint8_t first, uint32_t now)
{
    uint8_t resp[16];
    TEST_ASSERT_TRUE(udsota_on_request(&s_srv, req, len, resp, sizeof resp, now) >= 1u);
    TEST_ASSERT_EQUAL_HEX8(first, resp[0]);
}

/* Asserts the snapshot equals what the server's udsota_progress() reads now. */
static void expect_snapshot_is_server(void)
{
    udsota_progress_t srv, snap;
    udsota_progress(&s_srv, &srv);
    udsota_esp32_ctl_progress(&s_ctl, &snap);
    TEST_ASSERT_EQUAL_INT(srv.stage, snap.stage);
    TEST_ASSERT_EQUAL_UINT32(srv.done, snap.done);
    TEST_ASSERT_EQUAL_UINT32(srv.total, snap.total);
    TEST_ASSERT_EQUAL_UINT8(srv.last_reason, snap.last_reason);
}

/* Through a download with the real server, the snapshot copies each report under the port's lock (with its
 * lock_ctx), and the app's progress hook then runs with the app's ctx, the same values and the lock released,
 * so it can read the snapshot back. */
static void test_progress_snapshot_copies_the_report_and_forwards_it(void)
{
    const udsota_hooks_t app = { .progress = app_progress, .ctx = &s_marker };
    start(&app);
    TEST_ASSERT_NOT_NULL(s_hooks.progress);
    udsota_esp32_ctl_set_lock(&s_ctl, fake_lock, fake_unlock, &s_lock_depth);
    udsota_progress_t snap;
    udsota_esp32_ctl_progress(&s_ctl, &snap);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, snap.stage);
    TEST_ASSERT_EQUAL_UINT32(0u, snap.total);

    const uint8_t prog[] = {0x10, 0x02};
    const uint8_t rd[] = {0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x00, 0x08};   /* 8 bytes */
    const uint8_t blk1[] = {0x36, 0x01, 1, 2, 3, 4, 5};
    const uint8_t blk2[] = {0x36, 0x02, 6, 7, 8};
    exchange(prog, sizeof prog, 0x50, NOW);
    exchange(rd, sizeof rd, 0x74, NOW + 1u);
    TEST_ASSERT_EQUAL_INT(1, s_progress_calls);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_ERASING, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_UINT32(8u, s_progress_arg.total);
    expect_snapshot_is_server();
    exchange(blk1, sizeof blk1, 0x76, NOW + 2u);
    TEST_ASSERT_EQUAL_INT(2, s_progress_calls);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_WRITING, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_UINT32(5u, s_progress_arg.done);
    expect_snapshot_is_server();
    exchange(blk2, sizeof blk2, 0x76, NOW + 3u);
    TEST_ASSERT_EQUAL_INT(3, s_progress_calls);
    TEST_ASSERT_EQUAL_UINT32(8u, s_progress_arg.done);
    expect_snapshot_is_server();

    TEST_ASSERT_EQUAL_PTR(&s_marker, s_ctx_seen);
    TEST_ASSERT_EQUAL_INT(0, s_lock_depth_in_hook);            /* the lock is never held while the app's hook runs */
    TEST_ASSERT_EQUAL_UINT32(s_progress_arg.done, s_progress_read.done);   /* stored before the app's hook ran */
    TEST_ASSERT_EQUAL_INT(s_progress_arg.stage, s_progress_read.stage);
    TEST_ASSERT_EQUAL_PTR(&s_lock_depth, s_lock_ctx_seen);
    TEST_ASSERT_EQUAL_INT(s_locks, s_unlocks);
    TEST_ASSERT_EQUAL_INT(1, s_lock_max);
    TEST_ASSERT_EQUAL_INT(0, s_lock_depth);

    udsota_esp32_ctl_request_end(&s_ctl);                      /* the session ends: IDLE, aborted */
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 4u));
    TEST_ASSERT_EQUAL_INT(4, s_progress_calls);
    udsota_esp32_ctl_progress(&s_ctl, &snap);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, snap.stage);
    TEST_ASSERT_EQUAL_UINT32(0u, snap.done);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, snap.last_reason);
}

/* Without an app progress hook the port still keeps the snapshot, and init resets it and the lock. */
static void test_progress_snapshot_without_an_app_hook(void)
{
    start(NULL);
    TEST_ASSERT_NOT_NULL(s_hooks.progress);
    const uint8_t prog[] = {0x10, 0x02};
    const uint8_t rd[] = {0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x00, 0x08};
    exchange(prog, sizeof prog, 0x50, NOW);
    exchange(rd, sizeof rd, 0x74, NOW + 1u);
    expect_snapshot_is_server();
    TEST_ASSERT_EQUAL_INT(0, s_progress_calls);

    udsota_esp32_ctl_set_lock(&s_ctl, fake_lock, fake_unlock, NULL);
    start(NULL);
    TEST_ASSERT_NULL(s_ctl.lock);
    udsota_progress_t snap;
    udsota_esp32_ctl_progress(&s_ctl, &snap);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, snap.stage);
    TEST_ASSERT_EQUAL_UINT32(0u, snap.total);
    TEST_ASSERT_EQUAL_INT(0, s_locks);
}

/* Asserts the incoming version reads want, with its length. */
static void expect_version(const char *want)
{
    char v[UDSOTA_ESP32_CTL_VERSION_MAX];
    memset(v, 0x55, sizeof v);
    TEST_ASSERT_EQUAL_UINT(strlen(want), udsota_esp32_ctl_version(&s_ctl, v));
    TEST_ASSERT_EQUAL_STRING(want, v);
}

/* The version is empty in a zeroed control block before init (the port's static one, before start), after
 * init, and init empties one a previous start left. */
static void test_version_is_empty_after_init(void)
{
    static udsota_esp32_ctl_t zeroed;
    char v[UDSOTA_ESP32_CTL_VERSION_MAX];
    memset(v, 0x55, sizeof v);
    TEST_ASSERT_EQUAL_UINT(0u, udsota_esp32_ctl_version(&zeroed, v));
    TEST_ASSERT_EQUAL_STRING("", v);
    start(NULL);
    expect_version("");
    udsota_esp32_ctl_set_version(&s_ctl, "v0.3.1", UDSOTA_ESP32_CTL_VERSION_MAX);
    expect_version("v0.3.1");
    start(NULL);
    expect_version("");
}

/* Through downloads with the real server: the 34 reports ERASING with the version empty, an accepted first
 * block sets it, and it stays through WRITING and through IDLE after the session ends. The next accepted 34
 * clears it in the same locked copy that stores its ERASING report, before the app's hook runs, and a refused
 * first block leaves it empty. */
static void test_version_set_by_the_first_block_kept_after_the_end_and_cleared_by_the_next_34(void)
{
    const udsota_hooks_t app = { .progress = app_progress, .ctx = &s_marker };
    start(&app);
    udsota_esp32_ctl_set_lock(&s_ctl, fake_lock, fake_unlock, &s_lock_depth);
    s_first_version = "v0.3.1";
    const uint8_t prog[] = {0x10, 0x02};
    const uint8_t rd[] = {0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x00, 0x08};   /* 8 bytes */
    const uint8_t blk1[] = {0x36, 0x01, 1, 2, 3, 4, 5};
    const uint8_t blk2[] = {0x36, 0x02, 6, 7, 8};
    exchange(prog, sizeof prog, 0x50, NOW);
    exchange(rd, sizeof rd, 0x74, NOW + 1u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_ERASING, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_STRING("", s_version_in_hook);
    exchange(blk1, sizeof blk1, 0x76, NOW + 2u);                   /* the first block passes: stored */
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_WRITING, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_STRING("v0.3.1", s_version_in_hook);
    exchange(blk2, sizeof blk2, 0x76, NOW + 3u);
    expect_version("v0.3.1");
    udsota_esp32_ctl_request_end(&s_ctl);                          /* the session ends: IDLE, aborted */
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 4u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s_progress_arg.last_reason);
    TEST_ASSERT_EQUAL_STRING("v0.3.1", s_version_in_hook);          /* kept, so "v0.3.1 failed" can be drawn */
    expect_version("v0.3.1");

    s_first_version = "v0.3.2";
    exchange(prog, sizeof prog, 0x50, NOW + 5u);
    const int locks = s_locks;
    exchange(rd, sizeof rd, 0x74, NOW + 6u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_ERASING, s_progress_arg.stage);
    TEST_ASSERT_EQUAL_INT(locks + 3, s_locks);         /* the report's copy in, then the hook's two copies out */
    TEST_ASSERT_EQUAL_STRING("", s_version_in_hook);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_ERASING, s_progress_read.stage);
    exchange(blk1, sizeof blk1, 0x76, NOW + 7u);
    expect_version("v0.3.2");

    s_refuse_first = true;                                         /* a refused first block stores nothing */
    udsota_esp32_ctl_request_end(&s_ctl);
    TEST_ASSERT_TRUE(udsota_esp32_ctl_run_end(&s_ctl, &s_srv, NOW + 8u));
    exchange(prog, sizeof prog, 0x50, NOW + 9u);
    exchange(rd, sizeof rd, 0x74, NOW + 10u);
    expect_version("");
    exchange(blk1, sizeof blk1, 0x7F, NOW + 11u);
    expect_version("");
    TEST_ASSERT_EQUAL_INT(s_locks, s_unlocks);
    TEST_ASSERT_EQUAL_INT(1, s_lock_max);
    TEST_ASSERT_EQUAL_INT(0, s_lock_depth_in_hook);
}

/* Reports straight to the wrapper: the move into ERASING from IDLE clears the version inside the one lock span
 * that stores the report (before it: IDLE and the old version; at its end: ERASING and ""), while a report
 * that stays in ERASING, one that stays in WRITING and the moves on to VERIFYING and IDLE keep it. */
static void test_version_cleared_only_by_the_move_into_erasing(void)
{
    start(NULL);
    udsota_esp32_ctl_set_lock(&s_ctl, fake_lock, fake_unlock, &s_lock_depth);
    const udsota_progress_t erasing = { .stage = UDSOTA_STAGE_ERASING, .done = 0u, .total = 8u };
    const udsota_progress_t writing1 = { .stage = UDSOTA_STAGE_WRITING, .done = 4u, .total = 8u };
    const udsota_progress_t writing2 = { .stage = UDSOTA_STAGE_WRITING, .done = 8u, .total = 8u };
    const udsota_progress_t verifying = { .stage = UDSOTA_STAGE_VERIFYING };
    const udsota_progress_t idle = { .stage = UDSOTA_STAGE_IDLE, .last_reason = UDSOTA_DL_VERIFY_FAILED };

    udsota_esp32_ctl_set_version(&s_ctl, "v0.3.1", UDSOTA_ESP32_CTL_VERSION_MAX);
    const int locks = s_locks;
    s_hooks.progress(s_hooks.ctx, &erasing);
    TEST_ASSERT_EQUAL_INT(locks + 1, s_locks);
    TEST_ASSERT_EQUAL_STRING("v0.3.1", s_version_at_lock);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, s_stage_at_lock);
    TEST_ASSERT_EQUAL_STRING("", s_version_at_unlock);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_ERASING, s_stage_at_unlock);

    udsota_esp32_ctl_set_version(&s_ctl, "v0.3.2", UDSOTA_ESP32_CTL_VERSION_MAX);
    s_hooks.progress(s_hooks.ctx, &erasing);                  /* stays in ERASING */
    expect_version("v0.3.2");
    s_hooks.progress(s_hooks.ctx, &writing1);
    s_hooks.progress(s_hooks.ctx, &writing2);                 /* stays in WRITING */
    expect_version("v0.3.2");
    s_hooks.progress(s_hooks.ctx, &verifying);
    s_hooks.progress(s_hooks.ctx, &idle);                     /* failed verify: kept */
    expect_version("v0.3.2");

    s_hooks.progress(s_hooks.ctx, &writing1);                 /* WRITING after a 37 with the handle open */
    s_hooks.progress(s_hooks.ctx, &erasing);                  /* a 34 from WRITING clears too */
    expect_version("");
    TEST_ASSERT_EQUAL_INT(s_locks, s_unlocks);
    TEST_ASSERT_EQUAL_INT(1, s_lock_max);
}

/* A 32-byte version with no NUL keeps its first 31 bytes; a NUL ends it early; max bounds the read; each byte
 * outside 0x20-0x7E is stored as '?'. */
static void test_version_truncated_and_sanitised(void)
{
    start(NULL);
    char field[32];
    memset(field, 'a', sizeof field);                         /* esp_app_desc_t.version with no terminator */
    field[0] = 'v';
    udsota_esp32_ctl_set_version(&s_ctl, field, sizeof field);
    expect_version("vaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");            /* 31 bytes */

    udsota_esp32_ctl_set_version(&s_ctl, "v1.2\0garbage", 13u);
    expect_version("v1.2");
    udsota_esp32_ctl_set_version(&s_ctl, "v1.2.3", 3u);
    expect_version("v1.");

    const char raw[] = {0x01, 'v', '1', 0x7F, (char)0x80, (char)0xFF, 0x1F, ' ', '~', 0x09, 0x00};
    udsota_esp32_ctl_set_version(&s_ctl, raw, sizeof raw);
    expect_version("?v1???? ~?");
}

/* Every copy into and out of the version takes the lock once, with its lock_ctx, and never nests. */
static void test_version_copies_take_the_lock(void)
{
    start(NULL);
    udsota_esp32_ctl_set_lock(&s_ctl, fake_lock, fake_unlock, &s_lock_depth);
    char v[UDSOTA_ESP32_CTL_VERSION_MAX];
    udsota_esp32_ctl_set_version(&s_ctl, "v0.3.1", UDSOTA_ESP32_CTL_VERSION_MAX);
    TEST_ASSERT_EQUAL_INT(1, s_locks);
    TEST_ASSERT_EQUAL_INT(1, s_unlocks);
    TEST_ASSERT_EQUAL_STRING("", s_version_at_lock);          /* stored inside the span */
    TEST_ASSERT_EQUAL_STRING("v0.3.1", s_version_at_unlock);
    TEST_ASSERT_EQUAL_UINT(6u, udsota_esp32_ctl_version(&s_ctl, v));
    TEST_ASSERT_EQUAL_INT(2, s_locks);
    TEST_ASSERT_EQUAL_INT(2, s_unlocks);
    TEST_ASSERT_EQUAL_PTR(&s_lock_depth, s_lock_ctx_seen);
    TEST_ASSERT_EQUAL_INT(1, s_lock_max);
    TEST_ASSERT_EQUAL_INT(0, s_lock_depth);
}

/* Waits become ticks rounded down, never 0 for a real wait: 5 ms is 1 tick at 100 Hz (not 0, which spun the
 * diag task) and 5 at 1 kHz; 0 stays 0 and a huge wait saturates. */
static void test_wait_ticks_never_round_a_wait_to_zero(void)
{
    TEST_ASSERT_EQUAL_UINT32(1u, udsota_esp32_ctl_ticks(5u, 100u));
    TEST_ASSERT_EQUAL_UINT32(1u, udsota_esp32_ctl_ticks(1u, 100u));
    TEST_ASSERT_EQUAL_UINT32(4u, udsota_esp32_ctl_ticks(45u, 100u));
    TEST_ASSERT_EQUAL_UINT32(5u, udsota_esp32_ctl_ticks(5u, 1000u));
    TEST_ASSERT_EQUAL_UINT32(100u, udsota_esp32_ctl_ticks(100u, 1000u));
    TEST_ASSERT_EQUAL_UINT32(0u, udsota_esp32_ctl_ticks(0u, 100u));
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, udsota_esp32_ctl_ticks(UINT32_MAX, 10000000u));
}

/* Runs every udsota_esp32_ctl test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_end_session_from_phase_hook_runs_after_the_request);
    RUN_TEST(test_end_requested_during_a_job_applies_after_its_answer);
    RUN_TEST(test_requests_coalesce_and_phase_tracks_without_app_hooks);
    RUN_TEST(test_wrapped_hooks_forward_app_ctx_and_keep_nulls);
    RUN_TEST(test_write_and_routine_hooks_reach_the_app);
    RUN_TEST(test_write_and_routine_wrappers_follow_each_app_hook);
    RUN_TEST(test_without_write_and_routine_hooks_the_core_answers_as_before);
    RUN_TEST(test_wait_ticks_never_round_a_wait_to_zero);
    RUN_TEST(test_progress_snapshot_copies_the_report_and_forwards_it);
    RUN_TEST(test_progress_snapshot_without_an_app_hook);
    RUN_TEST(test_version_is_empty_after_init);
    RUN_TEST(test_version_set_by_the_first_block_kept_after_the_end_and_cleared_by_the_next_34);
    RUN_TEST(test_version_cleared_only_by_the_move_into_erasing);
    RUN_TEST(test_version_truncated_and_sanitised);
    RUN_TEST(test_version_copies_take_the_lock);
    return UNITY_END();
}
