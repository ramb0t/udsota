/* Host tests for udsota_progress() and hooks.progress: the stage, bytes and last reason after each step of a
 * download, a resent block and a refused 36, every way a download ends early, a new download after GetResumePoint,
 * and when the hook runs: once per change of stage or written block, and at most once per server call. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

#define T0         60000u   /* 60 s after boot */
#define BLK        1000u    /* data bytes per 36 */
#define SIZE       (3u * BLK)
#define LOG_MAX    32u

/* The mock engine: each op either finishes at once or queues a job on a worker that finishes JOB_MS later. */
typedef struct {
    bool     async;                     /* begin, write and verify return UDSOTA_PENDING */
    int      activate_ret, verify_ret;  /* results: activate's at once, verify's at once or from poll */
    int      job_result;                /* poll's result once a queued job finishes */
    int      check_ret;                 /* check_first: 0 passes, else refuses with UDSOTA_DL_BAD_BOARD */
    bool     hold;                      /* queued jobs never finish (the 90 s cap) */
    uint32_t done_at;
    bool     queued;
} engine_mock_t;

/* What hooks.progress got, in order, and the ctx of its last call. */
typedef struct {
    udsota_progress_t log[LOG_MAX];
    size_t            n;
    void             *ctx;
} progress_log_t;

static engine_mock_t   e;
static progress_log_t  g_log;
static udsota_mock_t   g_mock;
static udsota_server_t srv;
static uint32_t        g_now;
static uint8_t         g_resp[64];
static size_t          g_resp_len;
static uint8_t         g_blk[2u + BLK];

#define JOB_MS  200u

/* Queues one worker job, or finishes it at once without async; returns what the op returns. */
static int job(int sync_result)
{
    if (!e.async) {
        return sync_result;
    }
    e.done_at = g_now + JOB_MS;
    e.queued = true;
    return UDSOTA_PENDING;
}

/* engine.check_first: passes, or refuses with UDSOTA_DL_BAD_BOARD. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = (e.check_ret == 0) ? UDSOTA_DL_OK : UDSOTA_DL_BAD_BOARD;
    return e.check_ret;
}

/* engine.begin: the erase, queued with async. */
static int eng_begin(void *ctx, uint32_t size)
{
    return job(0);
}

/* engine.write: queued with async (behind any queued erase). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    return job(0);
}

/* engine.verify: verify_ret, at once or from poll. */
static int eng_verify(void *ctx)
{
    if (e.async) {
        e.job_result = e.verify_ret;
    }
    return job(e.verify_ret);
}

/* engine.activate: activate_ret at once. */
static int eng_activate(void *ctx)
{
    return e.activate_ret;
}

/* engine.confirm: succeeds at once. */
static int eng_confirm(void *ctx)
{
    return 0;
}

/* engine.abort: nothing to stop. */
static void eng_abort(void *ctx)
{
}

/* engine.poll: UDSOTA_PENDING while a job runs (for ever with hold), then its result. */
static int eng_poll(void *ctx)
{
    if (e.queued && (e.hold || g_now < e.done_at)) {
        return UDSOTA_PENDING;
    }
    e.queued = false;
    return e.job_result;
}

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_verify,
    .activate = eng_activate, .confirm = eng_confirm, .abort = eng_abort, .poll = eng_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};

/* hooks.progress: appends what it got and the ctx it got it with. */
static void rec_progress(void *ctx, const udsota_progress_t *p)
{
    g_log.ctx = ctx;
    if (g_log.n < LOG_MAX) {
        g_log.log[g_log.n] = *p;
    }
    g_log.n++;
}

/* Boots the server on the mock's hooks plus progress (or without it), no security. */
static void boot(bool with_progress)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    hooks.progress = with_progress ? rec_progress : NULL;
    udsota_init(&srv, &cfg, &ENGINE, NULL, &hooks);
}

/* Unity hook: a fresh async engine, an empty log and a server with the progress hook, at T0. */
void setUp(void)
{
    memset(&e, 0, sizeof e);
    e.async = true;
    memset(&g_log, 0, sizeof g_log);
    udsota_mock_clear(&g_mock);
    g_now = T0;
    boot(true);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends one request at g_now; keeps and returns the immediate answer. */
static size_t send(const uint8_t *req, size_t len)
{
    g_resp_len = udsota_on_request(&srv, req, len, g_resp, sizeof g_resp, g_now);
    return g_resp_len;
}

/* Sends the request given as its bytes. */
#define SEND(...) do {                                                  \
        const uint8_t r_[] = {__VA_ARGS__};                             \
        (void)send(r_, sizeof r_);                                      \
    } while (0)

/* Asserts the last answer is exactly the bytes listed. */
#define EXPECT(...) do {                                                \
        const uint8_t e_[] = {__VA_ARGS__};                             \
        TEST_ASSERT_EQUAL_UINT(sizeof e_, g_resp_len);                  \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(e_, g_resp, sizeof e_);            \
    } while (0)

/* Polls every 10 ms until a final answer (0x78s skipped), for at most 100 s; returns its length. */
static size_t finish(void)
{
    for (uint32_t waited = 0; waited < 100000u; waited += 10u) {
        g_now += 10u;
        const size_t n = udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
        if (n == 3u && g_resp[0] == UDSOTA_NEG_RESPONSE && g_resp[2] == UDSOTA_NRC_RESPONSE_PENDING) {
            continue;
        }
        if (n > 0u) {
            g_resp_len = n;
            return n;
        }
    }
    TEST_FAIL_MESSAGE("the job never finished");
    return 0;
}

/* Asserts udsota_progress() reads stage, done of total and reason. */
static void expect_progress(udsota_stage_t stage, uint32_t done, uint32_t total, uint8_t reason)
{
    udsota_progress_t p;
    udsota_progress(&srv, &p);
    TEST_ASSERT_EQUAL_INT(stage, p.stage);
    TEST_ASSERT_EQUAL_UINT32(done, p.done);
    TEST_ASSERT_EQUAL_UINT32(total, p.total);
    TEST_ASSERT_EQUAL_UINT8(reason, p.last_reason);
}

/* Asserts hook call i got stage and done of total. */
static void expect_logged(size_t i, udsota_stage_t stage, uint32_t done, uint32_t total)
{
    TEST_ASSERT_TRUE(i < g_log.n);
    TEST_ASSERT_EQUAL_INT(stage, g_log.log[i].stage);
    TEST_ASSERT_EQUAL_UINT32(done, g_log.log[i].done);
    TEST_ASSERT_EQUAL_UINT32(total, g_log.log[i].total);
}

/* 10 02 then 34 for SIZE bytes; asserts 74 20 0F FF. */
static void open_download(void)
{
    SEND(0x10, 0x02);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    SEND(0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(SIZE >> 24), (uint8_t)(SIZE >> 16), (uint8_t)(SIZE >> 8),
         (uint8_t)SIZE);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
}

/* Sends block bsc (BLK bytes); returns the immediate answer's length (0 while its job runs). */
static size_t send_block(uint8_t bsc)
{
    g_blk[0] = 0x36;
    g_blk[1] = bsc;
    memset(&g_blk[2], bsc, BLK);
    return send(g_blk, sizeof g_blk);
}

/* Sends block bsc and waits for its 76. */
static void write_block(uint8_t bsc)
{
    if (send_block(bsc) == 0u) {
        (void)finish();
    }
    EXPECT(0x76, bsc);
}

/* 34, erase, three blocks, 37, FF01 and ActivateImage: after each step udsota_progress() reads the stage and bytes,
 * and the hook got exactly one call per change of stage or written block, never for a 0x78. */
static void test_normal_download_reports_each_stage_and_block(void)
{
    SEND(0x10, 0x02);
    expect_progress(UDSOTA_STAGE_IDLE, 0, 0, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(0u, g_log.n);                       /* no stage change: IDLE in any session */

    open_download();
    expect_progress(UDSOTA_STAGE_ERASING, 0, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(1u, g_log.n);
    TEST_ASSERT_EQUAL_PTR(&g_mock, g_log.ctx);

    TEST_ASSERT_EQUAL_UINT(0u, send_block(1));                 /* the first-block check, then the erase job */
    expect_progress(UDSOTA_STAGE_ERASING, 0, SIZE, UDSOTA_DL_OK);
    g_now += 100u;
    TEST_ASSERT_EQUAL_UINT(3u, udsota_poll(&srv, g_resp, sizeof g_resp, g_now));   /* 7F 36 78 */
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_NRC_RESPONSE_PENDING, g_resp[2]);
    TEST_ASSERT_EQUAL_UINT(1u, g_log.n);                       /* a 0x78 is not progress */
    (void)finish();
    EXPECT(0x76, 0x01);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(2u, g_log.n);

    write_block(2);
    expect_progress(UDSOTA_STAGE_WRITING, 2u * BLK, SIZE, UDSOTA_DL_OK);
    write_block(3);
    expect_progress(UDSOTA_STAGE_WRITING, SIZE, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(4u, g_log.n);

    SEND(0x37);
    EXPECT(0x77);
    expect_progress(UDSOTA_STAGE_WRITING, SIZE, SIZE, UDSOTA_DL_OK);   /* until FF01: done == total */
    TEST_ASSERT_EQUAL_UINT(4u, g_log.n);

    SEND(0x31, 0x01, 0xFF, 0x01);
    TEST_ASSERT_EQUAL_UINT(0u, g_resp_len);
    expect_progress(UDSOTA_STAGE_VERIFYING, 0, 0, UDSOTA_DL_WORKER_TIMEOUT);   /* F1F1 until the verdict */
    (void)finish();
    EXPECT(0x71, 0x01, 0xFF, 0x01, 0x00);
    expect_progress(UDSOTA_STAGE_IDLE, 0, 0, UDSOTA_DL_OK);

    g_mock.reset_ok = false;                                   /* the host "restart" returns: the server re-opens */
    SEND(0x31, 0x01, 0xF0, 0x01);
    EXPECT(0x71, 0x01, 0xF0, 0x01);
    expect_progress(UDSOTA_STAGE_ACTIVATING, 0, 0, UDSOTA_DL_OK);
    g_now += UDSOTA_RESET_TX_WAIT_MS;
    (void)udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
    TEST_ASSERT_EQUAL_UINT(1u, g_mock.resets);
    expect_progress(UDSOTA_STAGE_IDLE, 0, 0, UDSOTA_DL_OK);

    TEST_ASSERT_EQUAL_UINT(8u, g_log.n);
    expect_logged(0, UDSOTA_STAGE_ERASING, 0, SIZE);
    expect_logged(1, UDSOTA_STAGE_WRITING, BLK, SIZE);
    expect_logged(2, UDSOTA_STAGE_WRITING, 2u * BLK, SIZE);
    expect_logged(3, UDSOTA_STAGE_WRITING, SIZE, SIZE);
    expect_logged(4, UDSOTA_STAGE_VERIFYING, 0, 0);
    expect_logged(5, UDSOTA_STAGE_IDLE, 0, 0);
    expect_logged(6, UDSOTA_STAGE_ACTIVATING, 0, 0);
    expect_logged(7, UDSOTA_STAGE_IDLE, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, g_log.log[5].last_reason);
}

/* With an engine that finishes every op at once, the first block moves ERASING to WRITING in the same request that
 * wrote it: one call for the change and the block together, never two. */
static void test_one_call_for_a_stage_change_and_a_block_together(void)
{
    e.async = false;
    open_download();
    TEST_ASSERT_EQUAL_UINT(1u, g_log.n);
    write_block(1);
    TEST_ASSERT_EQUAL_UINT(2u, g_log.n);
    expect_logged(1, UDSOTA_STAGE_WRITING, BLK, SIZE);
    write_block(2);
    TEST_ASSERT_EQUAL_UINT(3u, g_log.n);
    SEND(0x31, 0x01, 0xFF, 0x01);                              /* no 37 yet: 0x24, nothing changes */
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_NRC_REQUEST_SEQUENCE_ERROR, g_resp[2]);
    TEST_ASSERT_EQUAL_UINT(3u, g_log.n);
}

/* A resent block (its 76 lost), a 36 with the wrong counter and a 36 while the next block's job runs change
 * nothing: done stays and the hook is not called. */
static void test_resent_block_and_refused_36_leave_done(void)
{
    open_download();
    write_block(1);
    const size_t calls = g_log.n;

    TEST_ASSERT_EQUAL_UINT(2u, send_block(1));                 /* the repeat: 76 01 at once, no rewrite */
    EXPECT(0x76, 0x01);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(calls, g_log.n);

    (void)send_block(3);                                       /* wrong counter */
    EXPECT(0x7F, 0x36, UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(calls, g_log.n);

    TEST_ASSERT_EQUAL_UINT(0u, send_block(2));
    (void)send_block(2);                                       /* the same block again while its job runs */
    EXPECT(0x7F, 0x36, UDSOTA_NRC_BUSY_REPEAT);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(calls, g_log.n);
    (void)finish();
    EXPECT(0x76, 0x02);
    expect_progress(UDSOTA_STAGE_WRITING, 2u * BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(calls + 1u, g_log.n);

    TEST_ASSERT_EQUAL_UINT(2u, send_block(2));                 /* and its resend once written */
    EXPECT(0x76, 0x02);
    expect_progress(UDSOTA_STAGE_WRITING, 2u * BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(calls + 1u, g_log.n);
}

/* Asserts the download just ended: IDLE, 0 of 0, reason, and one hook call (after `before`) that said so. */
static void expect_ended(size_t before, uint8_t reason)
{
    expect_progress(UDSOTA_STAGE_IDLE, 0, 0, reason);
    TEST_ASSERT_EQUAL_UINT(before + 1u, g_log.n);
    expect_logged(before, UDSOTA_STAGE_IDLE, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(reason, g_log.log[before].last_reason);
}

/* An overrun (0x71) aborts the transfer mid-way, in the same session: IDLE, UDSOTA_DL_ABORTED. */
static void test_abort_mid_transfer_is_idle_aborted(void)
{
    open_download();
    write_block(1);
    write_block(2);
    write_block(3);
    const size_t before = g_log.n;
    (void)send_block(4);                                       /* past the announced size */
    EXPECT(0x7F, 0x36, UDSOTA_NRC_TRANSFER_DATA_SUSPENDED);
    expect_ended(before, UDSOTA_DL_ABORTED);
}

/* A session change mid-transfer (10 03, and the app's udsota_end_session) ends it: IDLE, UDSOTA_DL_ABORTED. */
static void test_session_change_is_idle_aborted(void)
{
    open_download();
    write_block(1);
    size_t before = g_log.n;
    SEND(0x10, 0x03);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    expect_ended(before, UDSOTA_DL_ABORTED);

    open_download();
    write_block(1);
    before = g_log.n;
    udsota_end_session(&srv, g_now);
    expect_ended(before, UDSOTA_DL_ABORTED);
}

/* S3 runs out mid-transfer: the next poll ends the session and the download, IDLE, UDSOTA_DL_ABORTED. */
static void test_s3_is_idle_aborted(void)
{
    open_download();
    write_block(1);
    const size_t before = g_log.n;
    g_now += UDSOTA_S3_MS - 1u;
    (void)udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
    TEST_ASSERT_EQUAL_UINT(before, g_log.n);
    g_now += 1u;
    (void)udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
    expect_ended(before, UDSOTA_DL_ABORTED);
}

/* A block job that never finishes meets the 90 s cap: 0x72, IDLE, UDSOTA_DL_WORKER_TIMEOUT. */
static void test_90s_cap_is_idle_worker_timeout(void)
{
    open_download();
    write_block(1);
    e.hold = true;
    TEST_ASSERT_EQUAL_UINT(0u, send_block(2));
    const size_t before = g_log.n;
    (void)finish();
    EXPECT(0x7F, 0x36, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    expect_ended(before, UDSOTA_DL_WORKER_TIMEOUT);
}

/* A refused first block, a failed write and a failed FF01 end the download with the reason F1F1 reports. */
static void test_refusals_are_idle_with_their_reason(void)
{
    e.check_ret = 1;
    open_download();
    size_t before = g_log.n;
    (void)send_block(1);
    EXPECT(0x7F, 0x36, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    expect_ended(before, UDSOTA_DL_BAD_BOARD);

    e.check_ret = 0;
    SEND(0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(SIZE >> 24), (uint8_t)(SIZE >> 16), (uint8_t)(SIZE >> 8),
         (uint8_t)SIZE);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    e.job_result = 0x105;                                      /* the worker's write fails */
    TEST_ASSERT_EQUAL_UINT(0u, send_block(1));
    before = g_log.n;
    (void)finish();
    EXPECT(0x7F, 0x36, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    expect_ended(before, UDSOTA_DL_FLASH_ERROR);

    e.job_result = 0;
    SEND(0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(SIZE >> 24), (uint8_t)(SIZE >> 16), (uint8_t)(SIZE >> 8),
         (uint8_t)SIZE);
    write_block(1);
    write_block(2);
    write_block(3);
    SEND(0x37);
    e.verify_ret = UDSOTA_DL_VERIFY_FAILED;
    SEND(0x31, 0x01, 0xFF, 0x01);
    before = g_log.n;
    (void)finish();
    EXPECT(0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_VERIFY_FAILED);
    expect_ended(before, UDSOTA_DL_VERIFY_FAILED);
}

/* GetResumePoint answers "not available", so the 34 that follows starts at offset 0 and done starts there: a new
 * download after an aborted one reads 0 of its own total, and grows from 0 again. */
static void test_download_after_resume_point_starts_at_its_offset(void)
{
    open_download();
    write_block(1);
    write_block(2);
    SEND(0x10, 0x03);                                          /* ends it: 2000 bytes stay in the slot */
    expect_progress(UDSOTA_STAGE_IDLE, 0, 0, UDSOTA_DL_ABORTED);
    SEND(0x10, 0x02);
    SEND(0x31, 0x01, 0xF0, 0x00);
    EXPECT(0x71, 0x01, 0xF0, 0x00, UDSOTA_RESUME_NOT_AVAILABLE);
    const uint32_t size2 = 2u * BLK;
    SEND(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, (uint8_t)(size2 >> 8), (uint8_t)size2);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    expect_progress(UDSOTA_STAGE_ERASING, 0, size2, UDSOTA_DL_OK);
    write_block(1);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, size2, UDSOTA_DL_OK);
}

/* Without the hook, udsota_progress() reads the same values, and the answers are the same bytes. */
static void test_without_the_hook_progress_still_reads(void)
{
    boot(false);
    open_download();
    expect_progress(UDSOTA_STAGE_ERASING, 0, SIZE, UDSOTA_DL_OK);
    write_block(1);
    expect_progress(UDSOTA_STAGE_WRITING, BLK, SIZE, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(0u, g_log.n);
}

/* done / total in permille: 0 without a total, rounded down, exact at the ends, and no overflow near 2^32. */
static void test_permille(void)
{
    udsota_progress_t p = {.stage = UDSOTA_STAGE_VERIFYING, .done = 0u, .total = 0u};
    TEST_ASSERT_EQUAL_UINT16(0u, udsota_progress_permille(&p));
    p = (udsota_progress_t){.stage = UDSOTA_STAGE_WRITING, .done = 1u, .total = 3u};
    TEST_ASSERT_EQUAL_UINT16(333u, udsota_progress_permille(&p));
    p.done = 3u;
    TEST_ASSERT_EQUAL_UINT16(1000u, udsota_progress_permille(&p));
    p.done = 4u;                                               /* never past 1000 */
    TEST_ASSERT_EQUAL_UINT16(1000u, udsota_progress_permille(&p));
    p = (udsota_progress_t){.stage = UDSOTA_STAGE_WRITING, .done = 0x80000000u, .total = 0xFFFFFFFFu};
    TEST_ASSERT_EQUAL_UINT16(500u, udsota_progress_permille(&p));
    p.done = 0xFFFFFFFFu;
    TEST_ASSERT_EQUAL_UINT16(1000u, udsota_progress_permille(&p));
}

/* Runs every progress test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_normal_download_reports_each_stage_and_block);
    RUN_TEST(test_one_call_for_a_stage_change_and_a_block_together);
    RUN_TEST(test_resent_block_and_refused_36_leave_done);
    RUN_TEST(test_abort_mid_transfer_is_idle_aborted);
    RUN_TEST(test_session_change_is_idle_aborted);
    RUN_TEST(test_s3_is_idle_aborted);
    RUN_TEST(test_90s_cap_is_idle_worker_timeout);
    RUN_TEST(test_refusals_are_idle_with_their_reason);
    RUN_TEST(test_download_after_resume_point_starts_at_its_offset);
    RUN_TEST(test_without_the_hook_progress_still_reads);
    RUN_TEST(test_permille);
    return UNITY_END();
}
