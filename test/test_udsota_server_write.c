/* Host tests for 0x2E WriteDataByIdentifier through hooks.did_write and for the access state app hooks get:
 * 0x11 in every session and at every length while the hook is NULL, the core's session and length checks before
 * the hook, the hook's arguments and verdict, and the session epoch that every session entry advances. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_priv.h"
#include "udsota_mock.h"

#define T0         60000u   /* past the 10 s post-boot 0x27 delay */
#define NRC_SPEED  0x88u    /* vehicleSpeedTooHigh: an NRC only the app sends */
#define POS10(ss)  0x50, (ss), 0x00, 0x32, 0x01, 0xF4

/* What hooks.did_write saw, and the verdict it gives. */
typedef struct {
    unsigned        calls;
    void           *ctx;
    uint16_t        did;
    uint8_t         data[8];
    size_t          len;
    udsota_access_t access;
    uint8_t         nrc;          /* the verdict: 0 accepts */
} wr_t;

static wr_t            w;
static int             job_result;   /* engine.poll's answer: UDSOTA_PENDING while the fake worker is busy */
static udsota_mock_t   g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[64];
static size_t          rlen;
static uint32_t        now;

/* engine.check_first: passes. */
static int eng_check_first(void *ctx, const uint8_t *f, size_t n, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin: completes at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }
/* engine.write: completes at once. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return 0; }
/* engine.verify, activate and confirm: complete at once. */
static int eng_op(void *ctx) { return 0; }
/* engine.abort: nothing is open. */
static void eng_abort(void *ctx) {}
/* engine.poll: the fake worker's state the test chose. */
static int eng_poll(void *ctx) { return job_result; }

/* hooks.did_write: records its arguments (the first sizeof w.data data bytes) and answers w.nrc. */
static uint8_t app_did_write(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access)
{
    w.calls++;
    w.ctx = ctx;
    w.did = did;
    w.len = len;
    memcpy(w.data, data, len < sizeof w.data ? len : sizeof w.data);
    w.access = access;
    return w.nrc;
}

/* Final answer for the tests' stand-in worker job: none. */
static size_t job_done_none(udsota_server_t *srv, int result, uint8_t *out, size_t max, uint32_t t) { return 0; }

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_op,
    .activate = eng_op, .confirm = eng_op, .abort = eng_abort, .poll = eng_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};

/* Boots a server on g_cfg with sec and hooks (NULL = none); the clock restarts at T0. */
static void boot(const udsota_security_t *sec, const udsota_hooks_t *hooks)
{
    udsota_init(&s, &g_cfg, &ENGINE, sec, hooks);
    now = T0;
}

/* Unity hook: security on, the mock's hooks plus a did_write that accepts, the worker idle. */
void setUp(void)
{
    memset(&w, 0, sizeof w);
    job_result = 0;
    udsota_mock_clear(&g_mock);
    g_cfg = udsota_mock_cfg();
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.did_write = app_did_write;
    boot(udsota_mock_security(), &g_hooks);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends req 1 ms after the last request; the answer is left in resp and rlen, which it returns. */
static size_t txn(const uint8_t *req, size_t len)
{
    now += 1u;
    memset(resp, 0xEE, sizeof resp);
    rlen = udsota_on_request(&s, req, len, resp, sizeof resp, now);
    return rlen;
}
#define REQ(...) txn((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

/* Asserts the last answer is exactly the bytes listed. */
#define EXPECT(...) do {                                                   \
        const uint8_t want_[] = {__VA_ARGS__};                             \
        TEST_ASSERT_EQUAL_UINT(sizeof want_, rlen);                        \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want_, resp, sizeof want_);           \
    } while (0)

/* 27 <level>, then 27 <level+1> with the right key; asserts 67 <level+1>. */
static void unlock(uint8_t level)
{
    uint8_t req[2u + UDSOTA_KEY_LEN] = {0x27, level};
    TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_SEED_LEN, txn(req, 2));
    req[1] = (uint8_t)(level + 1u);
    udsota_mock_key_for(&resp[2], level, &req[2]);
    txn(req, sizeof req);
    EXPECT(0x67, (uint8_t)(level + 1u));
}

/* No setup: the default session. */
static void in_default(void) {}
/* 10 03, still locked. */
static void ext_locked(void) { REQ(0x10, 0x03); EXPECT(POS10(0x03)); }
/* 10 03 and level 01. */
static void ext_unlocked(void) { ext_locked(); unlock(UDSOTA_SA_SEED_EXTENDED); }
/* 10 02, still locked. */
static void prog_locked(void) { REQ(0x10, 0x02); EXPECT(POS10(0x02)); }
/* 10 02 and level 03. */
static void prog_unlocked(void) { prog_locked(); unlock(UDSOTA_SA_SEED_PROGRAMMING); }

/* A write request whose first 1..5 bytes the length tests send: 2E, DID 0x0200, data 05 06. */
static const uint8_t WR[] = {0x2E, 0x02, 0x00, 0x05, 0x06};

/* With did_write NULL, 0x2E answers 7F 2E 11 in every session and at every length, before the session and
 * length checks: the answer a server without the hook has always given. */
static void test_null_did_write_is_service_not_supported(void)
{
    static void (*const STATES[])(void) = {in_default, ext_locked, ext_unlocked, prog_locked, prog_unlocked};
    for (size_t i = 0; i < sizeof STATES / sizeof STATES[0]; i++) {
        for (size_t len = 1; len <= sizeof WR; len++) {
            const udsota_hooks_t h = udsota_mock_hooks(&g_mock);   /* did_write NULL */
            boot(udsota_mock_security(), &h);
            STATES[i]();
            txn(WR, len);
            EXPECT(0x7F, 0x2E, 0x11);
        }
    }
}

/* With the hook set, the default session answers 0x7F before the length is looked at, and the hook is not asked. */
static void test_write_default_session_is_7f(void)
{
    for (size_t len = 1; len <= sizeof WR; len++) {
        txn(WR, len);
        EXPECT(0x7F, 0x2E, 0x7F);
    }
    TEST_ASSERT_EQUAL_UINT(0, w.calls);
}

/* Outside the default session a request under 4 bytes (no DID, or a DID without data) is 0x13 from the core,
 * locked or not, and the hook is not asked. */
static void test_write_short_is_13(void)
{
    static void (*const STATES[])(void) = {ext_locked, ext_unlocked, prog_unlocked};
    for (size_t i = 0; i < sizeof STATES / sizeof STATES[0]; i++) {
        setUp();
        STATES[i]();
        for (size_t len = 1; len < UDSOTA_WRITE_DID_MIN_LEN; len++) {
            txn(WR, len);
            EXPECT(0x7F, 0x2E, 0x13);
        }
        TEST_ASSERT_EQUAL_UINT(0, w.calls);
    }
}

/* A request of 4 bytes or more reaches the hook with the hooks' ctx, the DID, the bytes after it and the access
 * state; 0 answers 6E <did> and nothing more, and the session is unchanged. */
static void test_write_hook_gets_did_data_and_access(void)
{
    static const uint8_t DATA[] = {0x05, 0x06};
    ext_unlocked();
    txn(WR, sizeof WR);
    EXPECT(0x6E, 0x02, 0x00);
    TEST_ASSERT_EQUAL_UINT(1, w.calls);
    TEST_ASSERT_EQUAL_PTR(&g_mock, w.ctx);
    TEST_ASSERT_EQUAL_HEX16(0x0200, w.did);
    TEST_ASSERT_EQUAL_UINT(sizeof DATA, w.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DATA, w.data, sizeof DATA);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, w.access.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, w.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(1u, w.access.epoch);                 /* one session entry since boot */
    REQ(0x2E, 0xF1, 0xB0, 0xAA);                                  /* one data byte is enough */
    EXPECT(0x6E, 0xF1, 0xB0);
    TEST_ASSERT_EQUAL_HEX16(0xF1B0, w.did);
    TEST_ASSERT_EQUAL_UINT(1, w.len);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, s.security);
}

/* The access state follows the session and the unlock: 0 while locked, the programming level in programming,
 * and always 0 on a server without security. */
static void test_write_access_per_state(void)
{
    ext_locked();
    REQ(0x2E, 0x02, 0x00, 0x05);
    EXPECT(0x6E, 0x02, 0x00);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, w.access.session);
    TEST_ASSERT_EQUAL_UINT8(0, w.access.unlocked_level);
    prog_unlocked();
    REQ(0x2E, 0x02, 0x00, 0x05);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_PROGRAMMING, w.access.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_PROGRAMMING, w.access.unlocked_level);
    boot(NULL, &g_hooks);
    ext_locked();
    REQ(0x2E, 0x02, 0x00, 0x05);
    EXPECT(0x6E, 0x02, 0x00);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, w.access.session);
    TEST_ASSERT_EQUAL_UINT8(0, w.access.unlocked_level);
}

/* Any non-zero verdict is sent verbatim as 7F 2E <nrc>, one the core never produces included. */
static void test_write_hook_nrc_verbatim(void)
{
    static const uint8_t NRCS[] = {UDSOTA_NRC_INCORRECT_LENGTH, UDSOTA_NRC_CONDITIONS_NOT_CORRECT,
                                   UDSOTA_NRC_REQUEST_OUT_OF_RANGE, UDSOTA_NRC_SECURITY_ACCESS_DENIED, NRC_SPEED};
    ext_unlocked();
    for (size_t i = 0; i < sizeof NRCS; i++) {
        w.nrc = NRCS[i];
        REQ(0x2E, 0x02, 0x00, 0x05);
        EXPECT(0x7F, 0x2E, NRCS[i]);
    }
    TEST_ASSERT_EQUAL_UINT(sizeof NRCS, w.calls);
}

/* While a worker job runs a write is 0x21 from the core; with no room for an answer (resp_max < 3) nothing is
 * sent and the hook is not asked, so nothing is staged without an answer. */
static void test_write_busy_and_no_room(void)
{
    ext_unlocked();
    job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, job_done_none, 0,
                                               resp, sizeof resp, now));
    txn(WR, sizeof WR);
    EXPECT(0x7F, 0x2E, 0x21);
    TEST_ASSERT_EQUAL_UINT(0, w.calls);
    setUp();
    ext_unlocked();
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, WR, sizeof WR, resp, 2u, now));
    TEST_ASSERT_EQUAL_UINT(0, w.calls);
}

/* The epoch is 0 after init and advances by one on every session entry: 10 01, 02 and 03 (a repeat of the
 * current session included), S3, udsota_end_session at once and latched behind a job, the 90 s cap and the
 * restart. A refused 10 02 and requests inside a session leave it, and the hook sees the current value. */
static void test_epoch_advances_on_every_session_entry(void)
{
    TEST_ASSERT_EQUAL_UINT32(0, s.session_epoch);
    ext_locked();
    TEST_ASSERT_EQUAL_UINT32(1, s.session_epoch);
    ext_locked();                                                 /* a repeat of 10 03 */
    TEST_ASSERT_EQUAL_UINT32(2, s.session_epoch);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    REQ(0x3E, 0x00);
    REQ(0x22, 0xF1, 0x86);
    REQ(0x2E, 0x02, 0x00, 0x05);
    EXPECT(0x6E, 0x02, 0x00);
    TEST_ASSERT_EQUAL_UINT32(2, w.access.epoch);
    TEST_ASSERT_EQUAL_UINT32(2, s.session_epoch);                 /* requests inside the session leave it */
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    REQ(0x10, 0x02);
    EXPECT(0x7F, 0x10, 0x22);
    TEST_ASSERT_EQUAL_UINT32(2, s.session_epoch);                 /* a refused 10 02 enters nothing */
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0;
    REQ(0x10, 0x02);
    TEST_ASSERT_EQUAL_UINT32(3, s.session_epoch);
    REQ(0x10, 0x01);
    TEST_ASSERT_EQUAL_UINT32(4, s.session_epoch);
    REQ(0x10, 0x01);                                              /* a repeat of 10 01 */
    TEST_ASSERT_EQUAL_UINT32(5, s.session_epoch);

    ext_locked();                                                 /* 6 */
    now += UDSOTA_S3_MS;
    udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT32(7, s.session_epoch);                 /* S3 */

    ext_locked();                                                 /* 8 */
    udsota_end_session(&s, now);
    TEST_ASSERT_EQUAL_UINT32(9, s.session_epoch);                 /* end_session with no job: at once */

    ext_locked();                                                 /* 10 */
    job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, job_done_none, 0,
                                               resp, sizeof resp, now));
    udsota_end_session(&s, now);
    TEST_ASSERT_EQUAL_UINT32(10, s.session_epoch);                /* latched behind the job */
    job_result = 0;
    now += 5u;
    udsota_poll(&s, resp, sizeof resp, now);                      /* the job answers */
    now += 5u;
    udsota_poll(&s, resp, sizeof resp, now);                      /* the latch applies */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT32(11, s.session_epoch);

    ext_locked();                                                 /* 12 */
    job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, job_done_none, 0,
                                               resp, sizeof resp, now));
    now += UDSOTA_JOB_CAP_MS;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x7F, 0x31, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_EQUAL_UINT32(13, s.session_epoch);                /* the 90 s cap */
    job_result = 0;
    now += 5u;
    udsota_poll(&s, resp, sizeof resp, now);                      /* the orphan finishes */

    ext_unlocked();                                               /* 14 */
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    udsota_poll(&s, resp, sizeof resp, now + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_EQUAL_UINT32(15, s.session_epoch);                /* the restart */
}

/* Runs every write and access test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_null_did_write_is_service_not_supported);
    RUN_TEST(test_write_default_session_is_7f);
    RUN_TEST(test_write_short_is_13);
    RUN_TEST(test_write_hook_gets_did_data_and_access);
    RUN_TEST(test_write_access_per_state);
    RUN_TEST(test_write_hook_nrc_verbatim);
    RUN_TEST(test_write_busy_and_no_room);
    RUN_TEST(test_epoch_advances_on_every_session_entry);
    return UNITY_END();
}
