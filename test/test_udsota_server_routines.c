/* Host tests for 0x31 RoutineControl: FF01, ActivateImage, ConfirmImage and the reserved GetResumePoint. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

#define T0       100000u   /* test clock start: 100 s after boot, past SecurityAccess's 10 s boot delay */
#define IMG_LEN  320u      /* the one-block image test_full_flow downloads */

/* Worker jobs the mock tells apart, so job_poll can report each one's own result. */
enum { JOB_NONE, JOB_FLASH, JOB_END, JOB_ACTIVATE, JOB_CONFIRM };

typedef struct {
    int      job;               /* JOB_* queued last */
    bool     hold;              /* job_poll answers UDSOTA_PENDING while set */
    bool     sync;              /* engine.verify returns end_result at once (a synchronous fake) instead of queuing */
    int      end_result;        /* FF01 result: UDSOTA_DL_OK or a udsota_reason_t */
    int      activate_result;   /* set_boot result: 0 ok */
    int      confirm_result;    /* mark-valid result: 0 ok */
    unsigned n_end, n_activate, n_confirm;
    unsigned n_unverify;        /* engine.unverify calls: one per accepted 0x34 */
    uint32_t tx_pending;        /* what the installed tx_pending source returns */
} mock_t;

static mock_t       m;
static udsota_server_t srv;
static uint32_t     now;
static uint8_t      resp[64];

/* Records job j as queued on the fake worker; returns UDSOTA_PENDING like the ESP ops. */
static int mock_queue(int j)
{
    m.job = j;
    return UDSOTA_PENDING;
}

/* Erase-and-begin, queued. */
static int mock_ota_begin(void *ctx, uint32_t size) { return mock_queue(JOB_FLASH); }
/* Block write, queued. */
static int mock_ota_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return mock_queue(JOB_FLASH); }

/* FF01 verify: queued, or answered at once when the test models a synchronous fake. */
static int mock_ota_end(void *ctx)
{
    m.n_end++;
    return m.sync ? m.end_result : mock_queue(JOB_END);
}

/* Fire-and-forget abort: never becomes the job engine.poll reports. */
static void mock_ota_abort(void *ctx) {}
/* set_boot for ActivateImage, queued. */
static int mock_ota_activate(void *ctx) { m.n_activate++; return mock_queue(JOB_ACTIVATE); }
/* mark-valid for ConfirmImage, queued. */
static int mock_ota_confirm(void *ctx) { m.n_confirm++; return mock_queue(JOB_CONFIRM); }

/* Synchronous unverify on an accepted 0x34; only counted. */
static void mock_ota_unverify(void *ctx) { m.n_unverify++; }

/* First-block check always passes; test_udsota_server_download.c covers its refusals. */
static int mock_image_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *reason)
{
    *reason = UDSOTA_DL_OK;
    return 0;
}

/* UDSOTA_PENDING while held, else the result of the last queued job (engine.poll's contract). */
static int mock_job_poll(void *ctx)
{
    if (m.hold) {
        return UDSOTA_PENDING;
    }
    return m.job == JOB_END ? m.end_result
         : m.job == JOB_ACTIVATE ? m.activate_result
         : m.job == JOB_CONFIRM ? m.confirm_result : 0;
}

/* Frames still waiting in the transport (udsota_set_tx_pending). */
static uint32_t mock_tx_pending(void *ctx) { return m.tx_pending; }

static udsota_mock_t g_mock;
static const udsota_engine_t ENGINE = {
    .check_first = mock_image_check, .begin = mock_ota_begin, .write = mock_ota_write, .verify = mock_ota_end,
    .activate = mock_ota_activate, .confirm = mock_ota_confirm, .abort = mock_ota_abort,
    .unverify = mock_ota_unverify, .poll = mock_job_poll, .status = udsota_mock_status, .ctx = &g_mock,
};

/* A newly booted server: the mock's config and hooks (restarts counted in g_mock.resets) and the TX source. */
static void boot(void)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, &ENGINE, udsota_mock_security(), &hooks);
    udsota_set_tx_pending(&srv, mock_tx_pending, NULL);
}

/* Unity hook: fresh mock, clock at T0, a newly booted server whose gate allows everything. */
void setUp(void)
{
    memset(&m, 0, sizeof m);
    udsota_mock_clear(&g_mock);
    now = T0;
    boot();
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends one request at `now`; returns the immediate response length (0 = none yet). */
static size_t send_raw(const uint8_t *req, size_t len)
{
    return udsota_on_request(&srv, req, len, resp, sizeof resp, now);
}

/* True when resp holds NRC 0x78 (response pending). */
static bool is_pending(size_t n)
{
    return n == 3 && resp[0] == 0x7F && resp[2] == UDSOTA_NRC_RESPONSE_PENDING;
}

/* Polls once at now + dt and returns the response length. */
static size_t poll_after(uint32_t dt)
{
    now += dt;
    return udsota_poll(&srv, resp, sizeof resp, now);
}

/* Sends a request, then polls every 10 ms while a job runs, until a final (non-0x78) answer; returns its length. */
static size_t send(const uint8_t *req, size_t len)
{
    size_t n = send_raw(req, len);
    for (int i = 0; i < 100 && (n == 0 || is_pending(n)); i++) {
        n = poll_after(10);
    }
    return n;
}

#define REQ(...)     send((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
#define REQ_RAW(...) send_raw((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

/* Asserts the answer is exactly 7F <sid> <nrc>; expect_nrc for 0x31's. */
static void expect_nrc_sid(size_t n, uint8_t sid, uint8_t nrc)
{
    TEST_ASSERT_EQUAL_UINT(3, n);
    TEST_ASSERT_EQUAL_HEX8(0x7F, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(sid, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(nrc, resp[2]);
}
#define expect_nrc(n, nrc) expect_nrc_sid((n), 0x31, (nrc))

/* Asserts 71 01 <rid>, plus one status byte when status >= 0 (no status record when it is -1). */
static void expect_pos(size_t n, uint16_t rid, int status)
{
    TEST_ASSERT_EQUAL_UINT(status >= 0 ? 5u : 4u, n);
    TEST_ASSERT_EQUAL_HEX8(0x71, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, resp[1]);
    TEST_ASSERT_EQUAL_HEX16(rid, udsota_get_u16be(&resp[2]));
    if (status >= 0) {
        TEST_ASSERT_EQUAL_HEX8((uint8_t)status, resp[4]);
    }
}

/* 27 <level> then 27 <level+1> with the mock's key; the server must already be in that level's session. */
static void unlock(uint8_t level)
{
    size_t n = REQ(0x27, level);
    TEST_ASSERT_EQUAL_UINT(2 + UDSOTA_SEED_LEN, n);
    TEST_ASSERT_EQUAL_HEX8(0x67, resp[0]);
    uint8_t key[2 + UDSOTA_KEY_LEN] = {0x27, (uint8_t)(level + 1u)};
    udsota_mock_key_for(&resp[2], level, &key[2]);
    n = send(key, sizeof key);
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_EQUAL_HEX8(0x67, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(level + 1u, resp[1]);
}

/* 10 02, then level 03 when unlocked is set. */
static void enter_programming(bool unlocked)
{
    size_t n = REQ(0x10, 0x02);
    TEST_ASSERT_EQUAL_UINT(6, n);
    TEST_ASSERT_EQUAL_HEX8(0x50, resp[0]);
    if (unlocked) {
        unlock(UDSOTA_SA_SEED_PROGRAMMING);
    }
}

/* 10 03 (no key). */
static void enter_extended(void)
{
    size_t n = REQ(0x10, 0x03);
    TEST_ASSERT_EQUAL_UINT(6, n);
    TEST_ASSERT_EQUAL_HEX8(0x50, resp[0]);
}

/* 10 01. */
static void enter_default(void)
{
    size_t n = REQ(0x10, 0x01);
    TEST_ASSERT_EQUAL_UINT(6, n);
    TEST_ASSERT_EQUAL_HEX8(0x50, resp[0]);
}

/* Stands in for 34/36/37, which test_udsota_server_download.c tests: the transfer is closed and the OTA handle open. */
static void mark_transfer_exited(void)
{
    srv.update.dl_complete = true;
    srv.update.ota_open = true;
}

/* A passing FF01 on a closed transfer; the server must be in programming with level 03. */
static void ff01_pass(void)
{
    mark_transfer_exited();
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);
}

/* Sends a real 34 for an IMG_LEN image and checks 74 20 0F FF. */
static void request_download(void)
{
    const uint8_t rd[] = {0x34, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x40};
    size_t n = send(rd, sizeof rd);
    TEST_ASSERT_EQUAL_UINT(4, n);
    TEST_ASSERT_EQUAL_HEX8(0x74, resp[0]);
}

/* ConfirmImage's core precondition at `now`: the running image is PENDING_VERIFY and the boot slot. */
static void confirm_ready(void)
{
    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;
}

/* ---- App routines: hooks.routine and hooks.routine_poll ---- */

#define APP_RID  0x1234u   /* a RID the core does not own */

/* What the app routine fakes answer and what they were handed. */
typedef struct {
    int      rc;               /* hooks.routine's return: 0, an NRC, UDSOTA_PENDING, or a value outside those */
    int      poll_rc;          /* hooks.routine_poll's return once hold is clear */
    bool     hold;             /* hooks.routine_poll answers UDSOTA_PENDING while set */
    uint8_t  out[4];           /* the out record both fakes write on success */
    size_t   out_len;          /* its reported length; past out_max or sizeof out, nothing is written */
    unsigned n_routine, n_poll;
    uint16_t rid;              /* what the last hooks.routine call got */
    uint8_t  in[8];
    size_t   in_len, out_max;
    udsota_access_t access;
    void    *ctx;
} app_mock_t;

static app_mock_t app;

/* Writes app.out into out when it fits and reports app.out_len (a longer report tests the core's check). */
static void app_write_out(uint8_t *out, size_t out_max, size_t *out_len)
{
    if (app.out_len <= out_max && app.out_len <= sizeof app.out) {
        memcpy(out, app.out, app.out_len);
    }
    *out_len = app.out_len;
}

/* hooks.routine fake: records the call and returns app.rc, writing the out record when that is 0. */
static int app_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    app.n_routine++;
    app.ctx = ctx;
    app.rid = rid;
    app.in_len = in_len;
    memcpy(app.in, in, in_len < sizeof app.in ? in_len : sizeof app.in);
    app.out_max = out_max;
    app.access = access;
    if (app.rc == 0) {
        app_write_out(out, out_max, out_len);
    }
    return app.rc;
}

/* hooks.routine_poll fake: UDSOTA_PENDING while app.hold, else app.poll_rc with the out record when that is 0. */
static int app_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    app.n_poll++;
    if (app.hold) {
        return UDSOTA_PENDING;
    }
    if (app.poll_rc == 0) {
        app_write_out(out, out_max, out_len);
    }
    return app.poll_rc;
}

/* A newly booted server with the mock's hooks plus hooks.routine, and hooks.routine_poll when with_poll is set;
 * the app fakes start cleared. */
static void boot_app(bool with_poll)
{
    memset(&app, 0, sizeof app);
    const udsota_config_t cfg = udsota_mock_cfg();
    udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    hooks.routine = app_routine;
    hooks.routine_poll = with_poll ? app_routine_poll : NULL;
    udsota_init(&srv, &cfg, &ENGINE, udsota_mock_security(), &hooks);
    udsota_set_tx_pending(&srv, mock_tx_pending, NULL);
}

/* Polls every 10 ms from a job started at t0, accepting only silence or 0x78, then once at the 90 s cap;
 * returns that poll's answer length. */
static size_t poll_to_cap(uint32_t t0)
{
    while (now + 10u < t0 + UDSOTA_JOB_CAP_MS) {
        const size_t n = poll_after(10);
        TEST_ASSERT_TRUE(n == 0 || is_pending(n));
    }
    return poll_after(t0 + UDSOTA_JOB_CAP_MS - now);
}

/* 0x31 is not served in the default session at all. */
static void test_default_session_is_7f(void)
{
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
}

/* Fewer than 4 bytes is a length error before anything else is looked at. */
static void test_short_request_is_13(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xFF), UDSOTA_NRC_INCORRECT_LENGTH);
    expect_nrc(REQ(0x31, 0x02), UDSOTA_NRC_INCORRECT_LENGTH);
    expect_nrc(REQ(0x31), UDSOTA_NRC_INCORRECT_LENGTH);
}

/* Only startRoutine is served: stop (02), requestResults (03) and 00 are 0x12 (udsoncan's RoutineControl NRC list). */
static void test_stop_and_results_are_12(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x02, 0xFF, 0x01), UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    expect_nrc(REQ(0x31, 0x03, 0xFF, 0x01), UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    expect_nrc(REQ(0x31, 0x00, 0xF0, 0x01), UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
}

/* RIDs udsota does not serve (0x1234, and 0xF003 next to its own) are 0x31 in both non-default sessions. */
static void test_unassigned_rids_are_31(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x03), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    enter_extended();
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x03), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
}

/* A RID served only in the other non-default session is 0x31 (requestOutOfRange: RID not supported in this session). */
static void test_rid_outside_its_session_is_31(void)
{
    enter_extended();
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x00), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
}

/* FF01, F000 and F001 need level 03; the security check comes before the sequence check. */
static void test_programming_rids_need_level_03(void)
{
    enter_programming(false);
    mark_transfer_exited();
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x00), UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* No served routine takes an option record, so a fifth byte is 0x13. */
static void test_trailing_bytes_are_13(void)
{
    enter_programming(true);
    mark_transfer_exited();
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01, 0x00), UDSOTA_NRC_INCORRECT_LENGTH);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x00, 0x00), UDSOTA_NRC_INCORRECT_LENGTH);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* FF01 needs both a transfer closed by 0x37 and an open handle; either missing is 0x24 and runs nothing. */
static void test_ff01_without_closed_transfer_is_24(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    srv.update.dl_complete = true;                                   /* closed, but the handle was aborted */
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    srv.update.dl_complete = false;
    srv.update.ota_open = true;                                      /* open, but 0x37 not accepted */
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* A passing FF01 answers status 00, records UDSOTA_DL_OK in F1F1, marks the slot verified and consumes the handle. */
static void test_ff01_pass(void)
{
    enter_programming(true);
    srv.update.last_dl.reason_code = UDSOTA_DL_ABORTED;
    ff01_pass();
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.update.last_dl.reason_code);
    TEST_ASSERT_TRUE(srv.update.slot_verified);
    TEST_ASSERT_FALSE(srv.update.ota_open);
    TEST_ASSERT_FALSE(srv.update.dl_complete);
}

/* A failed FF01 is still a positive answer: the status byte and F1F1 carry the reason, and F001 stays refused. */
static void test_ff01_fail_reports_reason(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.end_result = UDSOTA_DL_VERIFY_FAILED;
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_VERIFY_FAILED, srv.update.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.update.slot_verified);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_activate);
}

/* A result outside udsota_reason_t (an esp_err_t, say) is reported as UDSOTA_DL_VERIFY_FAILED. */
static void test_ff01_foreign_result_is_verify_failed(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.end_result = 0x1503;
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    mark_transfer_exited();
    m.end_result = -1;
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    mark_transfer_exited();
    m.end_result = UDSOTA_DL_REASON_COUNT;                           /* one past the last reason */
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    mark_transfer_exited();
    m.end_result = UDSOTA_DL_FLASH_ERROR;                            /* the last reason passes through */
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_FLASH_ERROR);
}

/* An ops table that verifies inline (not UDSOTA_PENDING) answers at once with the same status rule. */
static void test_ff01_synchronous_result(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.sync = true;
    m.end_result = UDSOTA_DL_BAD_BOARD;
    expect_pos(REQ_RAW(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_BAD_BOARD);
    TEST_ASSERT_FALSE(srv.job_running);
}

/* FF01 again after a pass, with no new download, repeats the verdict 00 without running the job again. */
static void test_ff01_again_after_pass_repeats_verdict(void)
{
    enter_programming(true);
    ff01_pass();
    expect_pos(REQ_RAW(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);   /* at once: no job */
    TEST_ASSERT_FALSE(srv.job_running);
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
    TEST_ASSERT_TRUE(srv.update.slot_verified);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.update.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0xFF, 0x01));                    /* SPRMIB: silent */
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
}

/* FF01 with neither a pass nor a closed transfer is 0x24, and so is FF01 again after a failed verdict:
 * esp_ota_end freed the handle and nothing is verified. Neither reaches the worker. */
static void test_ff01_unverified_without_transfer_is_24(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
    mark_transfer_exited();
    m.end_result = UDSOTA_DL_VERIFY_FAILED;
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
}

/* The verify outlasts P2: nothing at once, 0x78 by 50 ms, the verdict when the worker finishes. */
static void test_ff01_sends_78_while_verifying(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0xFF, 0x01));
    size_t n = poll_after(50);
    TEST_ASSERT_TRUE(is_pending(n));
    TEST_ASSERT_EQUAL_HEX8(0x31, resp[1]);
    m.hold = false;
    expect_pos(poll_after(10), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);
}

/* An FF01 still running at the 90 s cap ends with 0x72, leaves the slot unverified and records UDSOTA_DL_WORKER_TIMEOUT. */
static void test_ff01_cap_records_worker_timeout(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0xFF, 0x01));
    expect_nrc(poll_to_cap(now), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_WORKER_TIMEOUT, srv.update.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.update.slot_verified);
}

/* Leaving programming after 0x37 aborts the open handle (the server's enter_session), so FF01 next session is 0x24. */
static void test_session_change_after_exit_voids_ff01(void)
{
    enter_programming(true);
    mark_transfer_exited();
    enter_default();
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* An S3 fallback after a real 0x37 aborts the handle and clears dl_complete, so FF01 in the next session is 0x24. */
static void test_s3_fallback_after_exit_clears_dl_complete(void)
{
    enter_programming(true);
    request_download();
    static uint8_t blk[2 + IMG_LEN];
    blk[0] = 0x36;
    blk[1] = 0x01;
    memset(&blk[2], 0x5A, IMG_LEN);
    TEST_ASSERT_EQUAL_UINT(2, send(blk, sizeof blk));
    TEST_ASSERT_EQUAL_UINT(1, REQ(0x37));
    TEST_ASSERT_TRUE(srv.update.dl_complete);
    TEST_ASSERT_EQUAL_UINT(0, poll_after(UDSOTA_S3_MS));         /* S3 expires: back to default, handle aborted */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, srv.session);
    TEST_ASSERT_FALSE(srv.update.dl_complete);
    TEST_ASSERT_FALSE(srv.update.ota_open);
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* ActivateImage with no FF01 since boot is 0x24 and never calls set_boot. */
static void test_activate_before_ff01_is_24(void)
{
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    mark_transfer_exited();                                   /* downloaded but not checked */
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_activate);
}

/* An accepted 0x34 after a passing FF01 clears "verified", so F001 is 0x24 again. */
static void test_activate_after_new_download_is_24(void)
{
    enter_programming(true);
    ff01_pass();
    request_download();
    TEST_ASSERT_EQUAL_UINT(1, m.n_unverify);                  /* the accepted 0x34 unverified the slot */
    TEST_ASSERT_FALSE(srv.update.slot_verified);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_activate);
}

/* ActivateImage is refused with the gate's NRC (the app's own rules: parked, bus health and the like)
 * or with 0x22 while the worker is busy (the core's rule); once both allow it runs. */
static void test_activate_refused_by_gate_and_busy_worker(void)
{
    enter_programming(true);
    ff01_pass();
    g_mock.gate_nrc[UDSOTA_OP_ACTIVATE] = 0x22;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    g_mock.gate_nrc[UDSOTA_OP_ACTIVATE] = 0x88;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), 0x88);
    g_mock.gate_nrc[UDSOTA_OP_ACTIVATE] = 0;
    m.hold = true;
    expect_nrc(REQ_RAW(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    m.hold = false;
    TEST_ASSERT_EQUAL_UINT(0, m.n_activate);
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(1, m.n_activate);
}

/* Unverified and a refusing gate together answer 0x24: the sequence check comes first and the gate is not asked. */
static void test_activate_sequence_error_before_conditions(void)
{
    enter_programming(true);
    g_mock.gate_nrc[UDSOTA_OP_ACTIVATE] = 0x22;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_ACTIVATE]);
}

/* F001 answers first, then restarts on the first poll that finds the TX FIFO empty, exactly once. */
static void test_activate_resets_when_tx_drains(void)
{
    enter_programming(true);
    ff01_pass();
    m.tx_pending = 1;                                         /* the 71 01 F0 01 frame is queued */
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_JOB_POLL_MS, udsota_ms_to_deadline(&srv, now));
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    m.tx_pending = 0;
    TEST_ASSERT_EQUAL_UINT(0, poll_after(1));
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    poll_after(1);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
}

/* udsota_restart_armed() is true from the F001 answer until the restart fires, and false again after. */
static void test_restart_armed_from_answer_to_fire(void)
{
    enter_programming(true);
    ff01_pass();
    TEST_ASSERT_FALSE(udsota_restart_armed(&srv));
    m.tx_pending = 1;
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_TRUE(udsota_restart_armed(&srv));
    poll_after(10);
    TEST_ASSERT_TRUE(udsota_restart_armed(&srv));          /* the answer is still leaving */
    m.tx_pending = 0;
    poll_after(1);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_FALSE(udsota_restart_armed(&srv));         /* fired */
}

/* A TX FIFO that never drains delays the restart by at most 100 ms. */
static void test_activate_resets_after_100ms_if_tx_stuck(void)
{
    enter_programming(true);
    ff01_pass();
    m.tx_pending = 3;
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    poll_after(UDSOTA_RESET_TX_WAIT_MS - 1u);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    poll_after(1);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
}

/* A suppressed F001 (31 81 F0 01) sends nothing but still restarts: set_boot must never be left without its reset. */
static void test_activate_suppressed_still_resets(void)
{
    enter_programming(true);
    ff01_pass();
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0xF0, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));                /* set_boot done before any 0x78: answer dropped */
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    TEST_ASSERT_EQUAL_UINT(0, poll_after(1));
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_EQUAL_UINT(1, m.n_activate);
}

/* Between the F001 answer and the restart the server answers nothing, not even TesterPresent. */
static void test_requests_ignored_once_reset_armed(void)
{
    enter_programming(true);
    ff01_pass();
    m.tx_pending = 1;
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x3E, 0x00));
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x10, 0x01));
}

/* A set_boot failure is 0x72, no restart, and the slot must pass FF01 again before another F001. */
static void test_activate_failure_is_72(void)
{
    enter_programming(true);
    ff01_pass();
    m.activate_result = UDSOTA_DL_VERIFY_FAILED;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    poll_after(200);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(1, m.n_activate);
}

/* "Verified" survives 10 01 and a relock: the client may retry F001 in a new session. */
static void test_verified_survives_session_change(void)
{
    enter_programming(true);
    ff01_pass();
    enter_default();
    enter_programming(true);
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(1, m.n_activate);
}

/* A reboot (re-init) clears "verified", so F001 is 0x24 until FF01 passes again. */
static void test_reboot_clears_verified(void)
{
    enter_programming(true);
    ff01_pass();
    boot();
    enter_programming(true);
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_activate);
}

/* The real 34/36/37 path closes the transfer that FF01 needs, and F001 then runs. */
static void test_full_flow(void)
{
    enter_programming(true);
    request_download();
    static uint8_t blk[2 + IMG_LEN];
    blk[0] = 0x36;
    blk[1] = 0x01;
    memset(&blk[2], 0x5A, IMG_LEN);
    size_t n = send(blk, sizeof blk);
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_EQUAL_HEX8(0x76, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, resp[1]);
    n = REQ(0x37);
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_EQUAL_HEX8(0x77, resp[0]);
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
    TEST_ASSERT_EQUAL_UINT(1, m.n_activate);
}

/* ConfirmImage runs in extended with no key on a PENDING_VERIFY boot image (the gate allows it). */
static void test_confirm_ok_needs_no_key(void)
{
    enter_extended();
    confirm_ready();
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_RID_CONFIRM_IMAGE, -1);
    TEST_ASSERT_EQUAL_UINT(1, m.n_confirm);
}

/* ConfirmImage is refused with 0x22 for a boot slot that is not the running one, a state that is neither
 * PENDING_VERIFY, VALID nor UNDEFINED, and a refusing gate; none reaches the worker. */
static void test_confirm_refusals(void)
{
    enter_extended();
    confirm_ready();
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA1;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA0;
    g_mock.status.running_state = UDSOTA_IMG_INVALID;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    confirm_ready();
    g_mock.gate_nrc[UDSOTA_OP_CONFIRM] = 0x22;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(3, g_mock.gate_calls[UDSOTA_OP_CONFIRM]);   /* the gate is asked first every time */
    TEST_ASSERT_EQUAL_UINT(0, m.n_confirm);
}

/* A failed mark-valid is 0x72. */
static void test_confirm_failure_is_72(void)
{
    enter_extended();
    confirm_ready();
    m.confirm_result = -1;
    expect_nrc(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
}

/* The server never confirms on its own. After F001 restarts, a boot into the PENDING_VERIFY
 * image that idles for a minute in the extended session (where F002 needs no key), with every confirm
 * precondition true and S3 kept alive by 3E 80 every 2 s, calls ota_confirm zero times. So a reset before the
 * client's F002 rolls back, and after that rollback the old, VALID image answers F002 positive without calling the
 * engine. */
static void test_no_confirm_without_client_request(void)
{
    enter_programming(true);
    ff01_pass();
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x01), UDSOTA_RID_ACTIVATE_IMAGE, -1);
    poll_after(1);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    boot();                                                   /* the new image boots PENDING_VERIFY */
    confirm_ready();
    enter_extended();
    for (int i = 0; i < 30; i++) {                            /* 60 s */
        for (int j = 0; j < 20; j++) {
            TEST_ASSERT_EQUAL_UINT(0, poll_after(100));
        }
        TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x3E, 0x80));       /* keeps S3 alive, answered silently */
    }
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, srv.session);   /* no S3 fallback: the minute was in extended */
    TEST_ASSERT_EQUAL_UINT(0, m.n_confirm);
    boot();                                                   /* reset before F002: the old image is back */
    g_mock.status.running_state = UDSOTA_IMG_VALID;   /* rolled back: the old image is VALID */
    enter_extended();
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x02), UDSOTA_RID_CONFIRM_IMAGE, -1);   /* already VALID: confirmed without the engine */
    TEST_ASSERT_EQUAL_UINT(0, m.n_confirm);
}

/* GetResumePoint keeps its RID reserved and answers status 0xFF "not available". */
static void test_resume_point_reserved(void)
{
    enter_programming(true);
    expect_pos(REQ(0x31, 0x01, 0xF0, 0x00), UDSOTA_RID_GET_RESUME_POINT, UDSOTA_RESUME_NOT_AVAILABLE);
}

/* The suppress bit silences F000 and a job that ends before any 0x78; after a 0x78 the verdict is sent. */
static void test_sprmib(void)
{
    enter_programming(true);
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0xF0, 0x00));
    mark_transfer_exited();
    TEST_ASSERT_EQUAL_UINT(0, REQ(0x31, 0x81, 0xFF, 0x01));
    TEST_ASSERT_TRUE(srv.update.slot_verified);                      /* it ran; only the answer was dropped */
    mark_transfer_exited();
    m.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0xFF, 0x01));
    TEST_ASSERT_TRUE(is_pending(poll_after(50)));
    m.hold = false;
    expect_pos(poll_after(10), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);   /* echoes 01, without the bit */
}

/* A RID the core does not own goes to hooks.routine with the option record, the room after 71 01 <rid>, the
 * hooks' ctx and the access state; 0 answers 71 01 <rid> and the out record at once, with no job. */
static void test_app_routine_answers_at_once(void)
{
    boot_app(true);
    enter_extended();
    app.out[0] = 0x00;
    app.out[1] = 0x7B;
    app.out_len = 2;
    const size_t n = REQ_RAW(0x31, 0x01, 0x12, 0x34, 0xAA, 0xBB, 0xCC);
    const uint8_t want[] = {0x71, 0x01, 0x12, 0x34, 0x00, 0x7B};
    TEST_ASSERT_EQUAL_UINT(sizeof want, n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, resp, sizeof want);
    TEST_ASSERT_FALSE(srv.job_running);
    TEST_ASSERT_EQUAL_UINT(1, app.n_routine);
    TEST_ASSERT_EQUAL_UINT(0, app.n_poll);
    TEST_ASSERT_EQUAL_HEX16(APP_RID, app.rid);
    const uint8_t in[] = {0xAA, 0xBB, 0xCC};
    TEST_ASSERT_EQUAL_UINT(sizeof in, app.in_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(in, app.in, sizeof in);
    TEST_ASSERT_EQUAL_UINT(sizeof resp - 4u, app.out_max);
    TEST_ASSERT_EQUAL_PTR(&g_mock, app.ctx);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, app.access.session);
    TEST_ASSERT_EQUAL_UINT8(0, app.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(srv.session_epoch, app.access.epoch);
}

/* access carries the unlocked level and the epoch in force: a repeat 10 03 relocks and bumps the epoch, and in
 * programming with level 03 the app sees that session and level. The core leaves both to the app. */
static void test_app_routine_access_follows_session(void)
{
    boot_app(true);
    enter_extended();
    unlock(UDSOTA_SA_SEED_EXTENDED);
    expect_pos(REQ(0x31, 0x01, 0x12, 0x34), APP_RID, -1);
    TEST_ASSERT_EQUAL_UINT8(0x01, app.access.unlocked_level);
    const uint32_t e0 = app.access.epoch;
    enter_extended();
    expect_pos(REQ(0x31, 0x01, 0x12, 0x34), APP_RID, -1);
    TEST_ASSERT_EQUAL_UINT8(0, app.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(e0 + 1u, app.access.epoch);
    enter_programming(true);
    expect_pos(REQ(0x31, 0x01, 0x12, 0x34), APP_RID, -1);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_PROGRAMMING, app.access.session);
    TEST_ASSERT_EQUAL_UINT8(0x03, app.access.unlocked_level);
}

/* The core's own checks still come first and never reach the app: 0x7F in default, 0x13 under 4 bytes, 0x12 for
 * a sub-function other than 01. Its own RIDs keep their session, key and exact-length rules with the hook set. */
static void test_core_checks_come_before_the_app(void)
{
    boot_app(true);
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    enter_extended();
    expect_nrc(REQ(0x31, 0x01, 0x12), UDSOTA_NRC_INCORRECT_LENGTH);
    expect_nrc(REQ(0x31, 0x02, 0x12, 0x34), UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    expect_nrc(REQ(0x31, 0x03, 0x12, 0x34), UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_OUT_OF_RANGE);    /* FF01 outside programming */
    enter_programming(false);
    mark_transfer_exited();
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    unlock(UDSOTA_SA_SEED_PROGRAMMING);
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01, 0x00), UDSOTA_NRC_INCORRECT_LENGTH);
    TEST_ASSERT_EQUAL_UINT(0, app.n_routine);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* An NRC from the app is sent verbatim; a return that is neither 0, an NRC nor UDSOTA_PENDING, and an out record
 * longer than its room, are 0x10. */
static void test_app_nrc_passes_through(void)
{
    boot_app(true);
    enter_extended();
    app.rc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    app.rc = UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    app.rc = 0x100;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_GENERAL_REJECT);
    app.rc = -1;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_GENERAL_REJECT);
    app.rc = 0;
    app.out_len = sizeof resp - 3u;                          /* one byte more than the room after 71 01 <rid> */
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_EQUAL_UINT(5, app.n_routine);
    TEST_ASSERT_FALSE(srv.job_running);
}

/* UDSOTA_PENDING makes the app routine a job: nothing at once, 0x78 by 50 ms, 0x21 for anything but 3E, and the
 * final answer from routine_poll even while engine.poll still reports work of its own. */
static void test_app_pending_answers_through_routine_poll(void)
{
    boot_app(true);
    enter_extended();
    app.rc = UDSOTA_PENDING;
    app.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0x12, 0x34));
    TEST_ASSERT_TRUE(srv.job_running);
    TEST_ASSERT_TRUE(srv.job_app);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_JOB_POLL_MS, udsota_ms_to_deadline(&srv, now));
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));
    TEST_ASSERT_TRUE(is_pending(poll_after(40)));
    TEST_ASSERT_EQUAL_HEX8(0x31, resp[1]);
    expect_nrc_sid(REQ_RAW(0x22, 0xF1, 0x86), 0x22, UDSOTA_NRC_BUSY_REPEAT);
    TEST_ASSERT_EQUAL_UINT(2, REQ_RAW(0x3E, 0x00));
    TEST_ASSERT_EQUAL_HEX8(0x7E, resp[0]);
    m.hold = true;                                           /* engine.poll says pending: it must not matter */
    app.hold = false;
    app.out[0] = 0x00;
    app.out_len = 1;
    expect_pos(poll_after(10), APP_RID, 0x00);
    TEST_ASSERT_FALSE(srv.job_running);
    TEST_ASSERT_FALSE(srv.job_app);
    TEST_ASSERT_EQUAL_UINT(1, app.n_routine);
}

/* A pending app routine's final NRC is sent. With SPRMIB a positive final answer is dropped unless a 0x78 went
 * out first, as for the core's own jobs, and a synchronous positive answer is dropped. */
static void test_app_pending_final_nrc_and_sprmib(void)
{
    boot_app(true);
    enter_extended();
    app.rc = UDSOTA_PENDING;
    app.poll_rc = UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    app.poll_rc = 0;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0x12, 0x34));
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));               /* finished before any 0x78: silent */
    TEST_ASSERT_FALSE(srv.job_running);
    app.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0x12, 0x34));
    TEST_ASSERT_TRUE(is_pending(poll_after(50)));
    app.hold = false;
    expect_pos(poll_after(10), APP_RID, -1);                  /* after a 0x78 the answer is sent */
    app.rc = 0;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0x12, 0x34));
}

/* An app routine still pending at the 90 s cap ends in 0x72 and the default session. The core keeps it as an app
 * orphan: an idle engine.poll never clears it, 10 02 and 11 01 are 0x22, and a second app routine is 0x22 without
 * a call, until routine_poll stops returning pending. The orphan's own answer is never sent. */
static void test_app_cap_orphans_until_routine_poll(void)
{
    boot_app(true);
    enter_extended();
    app.rc = UDSOTA_PENDING;
    app.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0x12, 0x34));
    expect_nrc(poll_to_cap(now), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, srv.session);
    TEST_ASSERT_FALSE(srv.job_running);
    TEST_ASSERT_TRUE(srv.app_orphan);
    TEST_ASSERT_FALSE(srv.worker_orphan);
    TEST_ASSERT_EQUAL_HEX16(1, srv.counters.resp_pending_caps);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_JOB_POLL_MS, udsota_ms_to_deadline(&srv, now));   /* watched in default too */

    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));                /* engine.poll is idle: still the app's orphan */
    TEST_ASSERT_TRUE(srv.app_orphan);
    expect_nrc_sid(REQ(0x10, 0x02), 0x10, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    enter_extended();
    unlock(UDSOTA_SA_SEED_EXTENDED);
    expect_nrc_sid(REQ(0x11, 0x01), 0x11, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(1, app.n_routine);                 /* refused before the hook */

    app.hold = false;
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));                /* finished: cleared, nothing sent */
    TEST_ASSERT_FALSE(srv.app_orphan);
    const unsigned polls = app.n_poll;
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));
    TEST_ASSERT_EQUAL_UINT(polls, app.n_poll);                /* no orphan left: routine_poll is not asked again */
    enter_programming(false);                                 /* 10 02 is accepted again */
}

/* The converse: an FF01 orphaned at the cap belongs to engine.poll. routine_poll is never asked about it, app
 * routines still run beside it, and it clears when engine.poll goes idle. */
static void test_engine_orphan_is_not_the_apps(void)
{
    boot_app(true);
    enter_programming(true);
    mark_transfer_exited();
    m.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0xFF, 0x01));
    expect_nrc(poll_to_cap(now), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_TRUE(srv.worker_orphan);
    TEST_ASSERT_FALSE(srv.app_orphan);
    enter_extended();
    expect_pos(REQ(0x31, 0x01, 0x12, 0x34), APP_RID, -1);   /* answered beside the engine's orphan */
    m.hold = false;
    TEST_ASSERT_EQUAL_UINT(0, poll_after(10));
    TEST_ASSERT_FALSE(srv.worker_orphan);
    TEST_ASSERT_EQUAL_UINT(0, app.n_poll);
}

/* An app routine capped while a download is open ends that download as UDSOTA_DL_ABORTED (the session ended),
 * not UDSOTA_DL_WORKER_TIMEOUT, which reports the flash worker. */
static void test_app_cap_during_download_is_aborted(void)
{
    boot_app(true);
    enter_programming(true);
    request_download();
    app.rc = UDSOTA_PENDING;
    app.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x01, 0x12, 0x34));
    expect_nrc(poll_to_cap(now), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, srv.update.last_dl.reason_code);
    TEST_ASSERT_TRUE(srv.app_orphan);
}

/* A routine that returns UDSOTA_PENDING with no routine_poll registered cannot be polled: the first poll ends it
 * with 0x10 and leaves no orphan. */
static void test_app_pending_without_routine_poll_is_10(void)
{
    boot_app(false);
    enter_extended();
    app.rc = UDSOTA_PENDING;
    expect_nrc(REQ(0x31, 0x01, 0x12, 0x34), UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_FALSE(srv.job_running);
    TEST_ASSERT_FALSE(srv.app_orphan);
}

/* With under 4 bytes of response room the app is not called, as 0x34 starts nothing it cannot answer. */
static void test_app_routine_no_room_starts_nothing(void)
{
    boot_app(true);
    enter_extended();
    const uint8_t req[] = {0x31, 0x01, 0x12, 0x34};
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&srv, req, sizeof req, resp, 3, now));
    TEST_ASSERT_EQUAL_UINT(0, app.n_routine);
    TEST_ASSERT_FALSE(srv.job_running);
}

/* Runs every RoutineControl test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_default_session_is_7f);
    RUN_TEST(test_short_request_is_13);
    RUN_TEST(test_stop_and_results_are_12);
    RUN_TEST(test_unassigned_rids_are_31);
    RUN_TEST(test_rid_outside_its_session_is_31);
    RUN_TEST(test_programming_rids_need_level_03);
    RUN_TEST(test_trailing_bytes_are_13);
    RUN_TEST(test_ff01_without_closed_transfer_is_24);
    RUN_TEST(test_ff01_pass);
    RUN_TEST(test_ff01_fail_reports_reason);
    RUN_TEST(test_ff01_foreign_result_is_verify_failed);
    RUN_TEST(test_ff01_synchronous_result);
    RUN_TEST(test_ff01_again_after_pass_repeats_verdict);
    RUN_TEST(test_ff01_unverified_without_transfer_is_24);
    RUN_TEST(test_ff01_sends_78_while_verifying);
    RUN_TEST(test_ff01_cap_records_worker_timeout);
    RUN_TEST(test_session_change_after_exit_voids_ff01);
    RUN_TEST(test_s3_fallback_after_exit_clears_dl_complete);
    RUN_TEST(test_activate_before_ff01_is_24);
    RUN_TEST(test_activate_after_new_download_is_24);
    RUN_TEST(test_activate_refused_by_gate_and_busy_worker);
    RUN_TEST(test_activate_sequence_error_before_conditions);
    RUN_TEST(test_activate_resets_when_tx_drains);
    RUN_TEST(test_restart_armed_from_answer_to_fire);
    RUN_TEST(test_activate_resets_after_100ms_if_tx_stuck);
    RUN_TEST(test_activate_suppressed_still_resets);
    RUN_TEST(test_requests_ignored_once_reset_armed);
    RUN_TEST(test_activate_failure_is_72);
    RUN_TEST(test_verified_survives_session_change);
    RUN_TEST(test_reboot_clears_verified);
    RUN_TEST(test_full_flow);
    RUN_TEST(test_confirm_ok_needs_no_key);
    RUN_TEST(test_confirm_refusals);
    RUN_TEST(test_confirm_failure_is_72);
    RUN_TEST(test_no_confirm_without_client_request);
    RUN_TEST(test_resume_point_reserved);
    RUN_TEST(test_sprmib);
    RUN_TEST(test_app_routine_answers_at_once);
    RUN_TEST(test_app_routine_access_follows_session);
    RUN_TEST(test_core_checks_come_before_the_app);
    RUN_TEST(test_app_nrc_passes_through);
    RUN_TEST(test_app_pending_answers_through_routine_poll);
    RUN_TEST(test_app_pending_final_nrc_and_sprmib);
    RUN_TEST(test_app_cap_orphans_until_routine_poll);
    RUN_TEST(test_engine_orphan_is_not_the_apps);
    RUN_TEST(test_app_cap_during_download_is_aborted);
    RUN_TEST(test_app_pending_without_routine_poll_is_10);
    RUN_TEST(test_app_routine_no_room_starts_nothing);
    return UNITY_END();
}
