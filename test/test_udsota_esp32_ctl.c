/* Host tests for the ESP32 port's control block (components/udsota_esp32/udsota_esp32_ctl.c) with the
 * real udsota server: an app phase hook that calls back into the port neither deadlocks nor recurses,
 * an end-session it requests runs after the current request, and one requested during a job runs
 * after that job's answer. */
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

/* Mock engine: the first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
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
    RUN_TEST(test_wait_ticks_never_round_a_wait_to_zero);
    return UNITY_END();
}
