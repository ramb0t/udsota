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

/* Fixed, non-zero seed so the key below is predictable. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0xA0 + i);
    }
    return true;
}

/* Expected key = seed ^ level ^ 0x5A per byte; unlock_programming() computes the same. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0x5A);
    }
    return true;
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
static const udsota_security_t SECURITY = {.rng16 = mock_rng16, .key = mock_key};

/* A newly booted server: the mock's config and hooks (restarts counted in g_mock.resets) and the TX source. */
static void boot(void)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, &ENGINE, &SECURITY, &hooks);
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

/* Asserts the answer is exactly 7F 31 <nrc>. */
static void expect_nrc(size_t n, uint8_t nrc)
{
    TEST_ASSERT_EQUAL_UINT(3, n);
    TEST_ASSERT_EQUAL_HEX8(0x7F, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x31, resp[1]);
    TEST_ASSERT_EQUAL_HEX8(nrc, resp[2]);
}

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

/* 27 03 then 27 04 with the mock's key; the server must already be in the programming session. */
static void unlock_programming(void)
{
    size_t n = REQ(0x27, 0x03);
    TEST_ASSERT_EQUAL_UINT(2 + UDSOTA_SEED_LEN, n);
    TEST_ASSERT_EQUAL_HEX8(0x67, resp[0]);
    uint8_t key[2 + UDSOTA_KEY_LEN] = {0x27, 0x04};
    for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) {
        key[2 + i] = (uint8_t)(resp[2 + i] ^ 0x03 ^ 0x5A);
    }
    n = send(key, sizeof key);
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_EQUAL_HEX8(0x67, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x04, resp[1]);
}

/* 10 02, then level 03 when unlock is set. */
static void enter_programming(bool unlock)
{
    size_t n = REQ(0x10, 0x02);
    TEST_ASSERT_EQUAL_UINT(6, n);
    TEST_ASSERT_EQUAL_HEX8(0x50, resp[0]);
    if (unlock) {
        unlock_programming();
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
    srv.dl_complete = true;
    srv.ota_open = true;
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
    srv.dl_complete = true;                                   /* closed, but the handle was aborted */
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    srv.dl_complete = false;
    srv.ota_open = true;                                      /* open, but 0x37 not accepted */
    expect_nrc(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_UINT(0, m.n_end);
}

/* A passing FF01 answers status 00, records UDSOTA_DL_OK in F1F1, marks the slot verified and consumes the handle. */
static void test_ff01_pass(void)
{
    enter_programming(true);
    srv.last_dl.reason_code = UDSOTA_DL_ABORTED;
    ff01_pass();
    TEST_ASSERT_EQUAL_UINT(1, m.n_end);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.last_dl.reason_code);
    TEST_ASSERT_TRUE(srv.slot_verified);
    TEST_ASSERT_FALSE(srv.ota_open);
    TEST_ASSERT_FALSE(srv.dl_complete);
}

/* A failed FF01 is still a positive answer: the status byte and F1F1 carry the reason, and F001 stays refused. */
static void test_ff01_fail_reports_reason(void)
{
    enter_programming(true);
    mark_transfer_exited();
    m.end_result = UDSOTA_DL_VERIFY_FAILED;
    expect_pos(REQ(0x31, 0x01, 0xFF, 0x01), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_VERIFY_FAILED);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_VERIFY_FAILED, srv.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.slot_verified);
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
    TEST_ASSERT_TRUE(srv.slot_verified);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.last_dl.reason_code);
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
    const uint32_t t0 = now;
    while (now + 10u < t0 + UDSOTA_JOB_CAP_MS) {
        size_t n = poll_after(10);
        TEST_ASSERT_TRUE(n == 0 || is_pending(n));
    }
    expect_nrc(poll_after(t0 + UDSOTA_JOB_CAP_MS - now), UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_WORKER_TIMEOUT, srv.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.slot_verified);
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
    TEST_ASSERT_TRUE(srv.dl_complete);
    TEST_ASSERT_EQUAL_UINT(0, poll_after(UDSOTA_S3_MS));         /* S3 expires: back to default, handle aborted */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, srv.session);
    TEST_ASSERT_FALSE(srv.dl_complete);
    TEST_ASSERT_FALSE(srv.ota_open);
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
    TEST_ASSERT_FALSE(srv.slot_verified);
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
    TEST_ASSERT_TRUE(srv.slot_verified);                      /* it ran; only the answer was dropped */
    mark_transfer_exited();
    m.hold = true;
    TEST_ASSERT_EQUAL_UINT(0, REQ_RAW(0x31, 0x81, 0xFF, 0x01));
    TEST_ASSERT_TRUE(is_pending(poll_after(50)));
    m.hold = false;
    expect_pos(poll_after(10), UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_DL_OK);   /* echoes 01, without the bit */
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
    return UNITY_END();
}
