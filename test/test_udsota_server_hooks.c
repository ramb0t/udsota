/* Host tests for the server's integration API: gate(op) at every enforcement point and never after an earlier NRC, an
 * NRC passed through verbatim, 0x21 as "retry", NULL hooks, the phase hook, udsota_end_session, running with no
 * security or no reset hook, config defaults and the server-owned DIDs. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_rxwatch.h"   /* UDSOTA_CF_MEDIAN_NONE */
#include "udsota_mock.h"

#define T0         60000u   /* past the 10 s post-boot 0x27 delay */
#define BLK        64u      /* data bytes per 0x36 block */
#define IMG        (2u * BLK)
#define NRC_SPEED  0x88u    /* vehicleSpeedTooHigh: an NRC only a gate sends */
#define HI(v)      (uint8_t)((v) >> 8)
#define LO(v)      (uint8_t)((v) & 0xFFu)
#define POS10(ss)  0x50, (ss), 0x00, 0x32, 0x01, 0xF4
#define REQ34      0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, IMG
#define FF01       0x31, 0x01, HI(UDSOTA_RID_CHECK_PROG_DEPS), LO(UDSOTA_RID_CHECK_PROG_DEPS)
#define ACT        0x31, 0x01, HI(UDSOTA_RID_ACTIVATE_IMAGE), LO(UDSOTA_RID_ACTIVATE_IMAGE)
#define CONF       0x31, 0x01, HI(UDSOTA_RID_CONFIRM_IMAGE), LO(UDSOTA_RID_CONFIRM_IMAGE)

/* The engine: every flash op is queued; poll reports `result` unless `hold` keeps the worker busy. */
typedef struct {
    bool            hold;
    int             result;
    udsota_reason_t check_reason;   /* check_first's verdict; UDSOTA_DL_OK passes */
    unsigned        begins, writes, verifies, activates, confirms, aborts;
    uint32_t        tx_pending;     /* what the installed tx_pending returns */
} eng_t;

static eng_t           e;
static udsota_mock_t   g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[64];
static size_t          rlen;
static uint32_t        now;

/* engine.check_first: check_reason decides. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = e.check_reason;
    return e.check_reason == UDSOTA_DL_OK ? 0 : 1;
}
/* engine.begin: queued. */
static int eng_begin(void *ctx, uint32_t size) { e.begins++; return UDSOTA_PENDING; }
/* engine.write: queued. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { e.writes++; return UDSOTA_PENDING; }
/* engine.verify: queued; the verdict is `result`. */
static int eng_verify(void *ctx) { e.verifies++; return UDSOTA_PENDING; }
/* engine.activate: queued. */
static int eng_activate(void *ctx) { e.activates++; return UDSOTA_PENDING; }
/* engine.confirm: queued. */
static int eng_confirm(void *ctx) { e.confirms++; return UDSOTA_PENDING; }
/* engine.abort: fire-and-forget. */
static void eng_abort(void *ctx) { e.aborts++; }
/* engine.poll: UDSOTA_PENDING while held, else the result. */
static int eng_poll(void *ctx) { return e.hold ? UDSOTA_PENDING : e.result; }

/* engine.version: F189 "v1.2.3". */
static size_t eng_version(void *ctx, char *out, size_t max)
{
    static const char v[] = "v1.2.3";
    if (max < sizeof v - 1u) {
        return 0;
    }
    memcpy(out, v, sizeof v - 1u);
    return sizeof v - 1u;
}

/* engine.running_sha: F1F3, bytes A0..BF. */
static size_t eng_sha(void *ctx, uint8_t *out, size_t max)
{
    if (max < UDSOTA_SHA256_LEN) {
        return 0;
    }
    for (size_t i = 0; i < UDSOTA_SHA256_LEN; i++) {
        out[i] = (uint8_t)(0xA0u + i);
    }
    return UDSOTA_SHA256_LEN;
}

/* The transport's tx_pending source. */
static uint32_t eng_tx_pending(void *ctx) { return e.tx_pending; }

/* The app's own DID behind hooks.did_read: F191 "devkit". */
static size_t app_dids(uint16_t did, uint8_t *buf, size_t max)
{
    if (did != 0xF191u || max < 6u) {
        return 0;
    }
    memcpy(buf, "devkit", 6);
    return 6;
}

/* security.rng16: 10..1F, never zero. */
static bool sec_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return true;
}

/* security.key: seed ^ level ^ 0xA5 per byte, as the other server suites. */
static bool sec_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5u);
    }
    return true;
}

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_verify,
    .activate = eng_activate, .confirm = eng_confirm, .abort = eng_abort, .unverify = NULL, .poll = eng_poll,
    .status = udsota_mock_status, .running_sha = eng_sha, .version = eng_version, .slot_size = 0u,
    .ctx = &g_mock,
};
static const udsota_security_t SECURITY = {.rng16 = sec_rng16, .key = sec_key, .ctx = NULL};

/* Boots a server on g_cfg with sec and hooks (NULL = none) and installs tx_pending; the clock restarts at T0. */
static void boot(const udsota_security_t *sec, const udsota_hooks_t *hooks)
{
    udsota_init(&s, &g_cfg, &ENGINE, sec, hooks);
    udsota_set_tx_pending(&s, eng_tx_pending, NULL);
    now = T0;
}

/* Unity hook: fresh engine and mock, the mock's config, security on, every mock hook registered. */
void setUp(void)
{
    memset(&e, 0, sizeof e);
    udsota_mock_clear(&g_mock);
    g_mock.app_did = app_dids;
    g_cfg = udsota_mock_cfg();
    g_hooks = udsota_mock_hooks(&g_mock);
    boot(&SECURITY, &g_hooks);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends req 1 ms after the last request, then polls every 5 ms while a job runs; the final answer (0x78s
 * skipped) is left in resp and rlen, which it returns. */
static size_t txn(const uint8_t *req, size_t len)
{
    now += 1u;
    rlen = udsota_on_request(&s, req, len, resp, sizeof resp, now);
    for (int i = 0; i < 100 && s.job_running; i++) {
        now += 5u;
        const size_t n = udsota_poll(&s, resp, sizeof resp, now);
        if (n != 0u && !(n == 3u && resp[0] == 0x7F && resp[2] == UDSOTA_NRC_RESPONSE_PENDING)) {
            rlen = n;
        }
    }
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
    for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) {
        req[2u + i] = (uint8_t)(resp[2u + i] ^ level ^ 0xA5u);
    }
    txn(req, sizeof req);
    EXPECT(0x67, (uint8_t)(level + 1u));
}

/* 36 <bsc> with BLK data bytes; returns the final answer's length. */
static size_t block(uint8_t bsc)
{
    uint8_t b[2u + BLK];
    b[0] = 0x36;
    b[1] = bsc;
    memset(&b[2], 0xE9, BLK);
    return txn(b, sizeof b);
}

/* No setup: the default session. */
static void in_default(void) {}
/* 10 02, still locked. */
static void prog_locked(void) { REQ(0x10, 0x02); EXPECT(POS10(0x02)); }
/* 10 02 and level 03. */
static void prog_unlocked(void) { prog_locked(); unlock(UDSOTA_SA_SEED_PROGRAMMING); }
/* prog_unlocked and an accepted 34 for IMG bytes. */
static void transfer_open(void) { prog_unlocked(); REQ(REQ34); EXPECT(0x74, 0x20, 0x0F, 0xFF); }
/* 10 03, still locked. */
static void ext_locked(void) { REQ(0x10, 0x03); EXPECT(POS10(0x03)); }
/* 10 03 and level 01. */
static void ext_unlocked(void) { ext_locked(); unlock(UDSOTA_SA_SEED_EXTENDED); }
/* 10 03 with the running image PENDING_VERIFY and the boot slot: ConfirmImage's core precondition holds. */
static void confirm_ready(void) { g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY; ext_locked(); }
/* Default session with the boot slot moved to the other slot. */
static void boot_moved(void) { g_mock.status.boot_slot = UDSOTA_SLOT_OTA1; }
/* Default session with the running image PENDING_VERIFY. */
static void unconfirmed(void) { g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY; }

/* transfer_open, both blocks, 37 and a passing FF01: the slot is verified, still programming + 03. */
static void verified(void)
{
    transfer_open();
    block(1);  EXPECT(0x76, 0x01);
    block(2);  EXPECT(0x76, 0x02);
    REQ(0x37); EXPECT(0x77);
    REQ(FF01); EXPECT(0x71, 0x01, HI(UDSOTA_RID_CHECK_PROG_DEPS), LO(UDSOTA_RID_CHECK_PROG_DEPS), UDSOTA_DL_OK);
}
/* verified, with a job still queued on the worker. */
static void verified_busy(void) { verified(); e.hold = true; }

/* One enforcement point: the state to reach, the op it must ask about and the request that reaches it. */
typedef struct {
    const char *name;
    void      (*setup)(void);
    udsota_op_t op;
    uint8_t     req[12];
    uint8_t     req_len;
} gate_row_t;

static const gate_row_t GATE_ROWS[] = {
    {"10 03",        in_default,    UDSOTA_OP_ENTER_EXTENDED,    {0x10, 0x03}, 2},
    {"10 02",        in_default,    UDSOTA_OP_ENTER_PROGRAMMING, {0x10, 0x02}, 2},
    {"34",           prog_unlocked, UDSOTA_OP_START_DOWNLOAD,    {REQ34}, 11},
    {"36",           transfer_open, UDSOTA_OP_CONTINUE_TRANSFER, {0x36, 0x01, 0xE9}, 3},
    {"ActivateImage", verified,     UDSOTA_OP_ACTIVATE,          {ACT}, 4},
    {"11 01",        ext_unlocked,  UDSOTA_OP_RESET,             {0x11, 0x01}, 2},
    {"ConfirmImage", confirm_ready, UDSOTA_OP_CONFIRM,           {CONF}, 4},
};

/* Each enforcement point asks the gate about its own op exactly once, with the hooks' ctx, and sends the
 * gate's NRC (0x88, which the core never produces) verbatim as 7F <sid> 88. */
static void test_gate_asked_at_every_point_nrc_verbatim(void)
{
    for (size_t i = 0; i < sizeof GATE_ROWS / sizeof GATE_ROWS[0]; i++) {
        const gate_row_t *r = &GATE_ROWS[i];
        setUp();
        r->setup();
        memset(g_mock.gate_calls, 0, sizeof g_mock.gate_calls);
        g_mock.gate_total = 0;
        g_mock.gate_nrc[r->op] = NRC_SPEED;
        txn(r->req, r->req_len);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(3, rlen, r->name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x7F, resp[0], r->name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(r->req[0], resp[1], r->name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(NRC_SPEED, resp[2], r->name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(1, g_mock.gate_calls[r->op], r->name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(1, g_mock.gate_total, r->name);
        TEST_ASSERT_EQUAL_PTR_MESSAGE(&g_mock, g_mock.last_ctx, r->name);
    }
}

/* A request refused by an earlier check never reaches the gate. */
typedef struct {
    const char *name;
    void      (*setup)(void);
    uint8_t     req[12];
    uint8_t     req_len;
    uint8_t     nrc;          /* the earlier check's NRC */
} order_row_t;

static const order_row_t ORDER_ROWS[] = {
    {"10 02 long",              in_default,    {0x10, 0x02, 0x00}, 3, 0x13},
    {"10 03 long",              in_default,    {0x10, 0x03, 0x00}, 3, 0x13},
    {"10 02 boot slot moved",   boot_moved,    {0x10, 0x02}, 2, 0x22},
    {"10 02 PENDING_VERIFY",    unconfirmed,   {0x10, 0x02}, 2, 0x22},
    {"34 locked",               prog_locked,   {REQ34}, 11, 0x33},
    {"34 short",                prog_unlocked, {0x34, 0x00, 0x44}, 3, 0x13},
    {"34 transfer open",        transfer_open, {REQ34}, 11, 0x22},
    {"36 no download",          prog_unlocked, {0x36, 0x01, 0xE9}, 3, 0x24},
    {"36 SID only",             transfer_open, {0x36}, 1, 0x13},
    {"Activate locked",         prog_locked,   {ACT}, 4, 0x33},
    {"Activate unverified",     prog_unlocked, {ACT}, 4, 0x24},
    {"Activate worker busy",    verified_busy, {ACT}, 4, 0x22},
    {"11 01 default",           in_default,    {0x11, 0x01}, 2, 0x7F},
    {"11 01 locked",            ext_locked,    {0x11, 0x01}, 2, 0x33},
    {"11 02",                   ext_unlocked,  {0x11, 0x02}, 2, 0x12},
    {"Confirm in programming",  prog_unlocked, {CONF}, 4, 0x31},
};

/* Length, sub-function, key, sequence and core-owned conditions all answer before the gate is asked, so every
 * NRC keeps its position (session 7F, length 13, sub-function 12, key 33, sequence 24, then conditions). */
static void test_gate_not_asked_after_earlier_nrc(void)
{
    for (size_t i = 0; i < sizeof ORDER_ROWS / sizeof ORDER_ROWS[0]; i++) {
        const order_row_t *r = &ORDER_ROWS[i];
        setUp();
        r->setup();
        memset(g_mock.gate_nrc, NRC_SPEED, sizeof g_mock.gate_nrc);
        g_mock.gate_total = 0;
        txn(r->req, r->req_len);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(3, rlen, r->name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x7F, resp[0], r->name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(r->nrc, resp[2], r->name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_total, r->name);
    }
}

/* 0x34 checks its conditions before its format: a bad DFI under a refusing gate gets the gate's NRC. */
static void test_download_conditions_before_format(void)
{
    prog_unlocked();
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = NRC_SPEED;
    REQ(0x34, 0x01, 0x44, 0, 0, 0, 0, 0, 0, 0, IMG);
    EXPECT(0x7F, 0x34, NRC_SPEED);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0;
    REQ(0x34, 0x01, 0x44, 0, 0, 0, 0, 0, 0, 0, IMG);
    EXPECT(0x7F, 0x34, 0x31);
}

/* 0x21 from the gate at a 0x36 means "retry": answered verbatim, nothing aborted or erased, and the same block
 * then goes through. */
static void test_gate_busy_at_transfer_keeps_it_open(void)
{
    transfer_open();
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = UDSOTA_NRC_BUSY_REPEAT;
    block(1);
    EXPECT(0x7F, 0x36, 0x21);
    TEST_ASSERT_TRUE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
    TEST_ASSERT_EQUAL_UINT(0, e.aborts);
    TEST_ASSERT_EQUAL_UINT(0, e.begins);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = 0;
    block(1);
    EXPECT(0x76, 0x01);
}

/* Any other gate NRC at a 0x36 is sent verbatim and ends the transfer and the session. */
static void test_gate_denial_at_transfer_ends_it(void)
{
    transfer_open();
    block(1);
    EXPECT(0x76, 0x01);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = NRC_SPEED;
    block(2);
    EXPECT(0x7F, 0x36, NRC_SPEED);
    TEST_ASSERT_FALSE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_EQUAL_UINT(1, e.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT16(0, s.counters.stmin_violations);
}

/* At an FC point the gate is asked too; any refusal (0x21 included) withholds the FC and ends the session, since
 * a withheld FC cannot carry an NRC. */
static void test_gate_denial_at_fc_point_withholds(void)
{
    transfer_open();
    TEST_ASSERT_TRUE(udsota_fc_check(&s, UDSOTA_CF_MEDIAN_NONE, 2000u, now));
    TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER]);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = UDSOTA_NRC_BUSY_REPEAT;
    TEST_ASSERT_FALSE(udsota_fc_check(&s, UDSOTA_CF_MEDIAN_NONE, 2000u, now));
    TEST_ASSERT_EQUAL_UINT(2, g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER]);
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(0, s.counters.stmin_violations);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
}

/* A fast client under a refusing gate is not counted as an STmin violation (the gate is the reason);
 * the same median under an allowing gate is. */
static void test_stmin_violation_counted_only_when_gate_allows(void)
{
    transfer_open();
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    TEST_ASSERT_FALSE(udsota_fc_check(&s, 1000u, 2000u, now));
    TEST_ASSERT_EQUAL_UINT16(0, s.counters.stmin_violations);
    setUp();
    transfer_open();
    TEST_ASSERT_FALSE(udsota_fc_check(&s, 1000u, 2000u, now));
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.stmin_violations);
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.withheld_fcs);
}

/* With cfg.stmin_monitor off, a fast client is never stopped at an FC point. */
static void test_stmin_monitor_off(void)
{
    g_cfg.stmin_monitor = false;
    boot(&SECURITY, &g_hooks);
    transfer_open();
    TEST_ASSERT_TRUE(udsota_fc_check(&s, 100u, 2000u, now));
    TEST_ASSERT_EQUAL_UINT16(0, s.counters.stmin_violations);
    TEST_ASSERT_TRUE(udsota_download_active(&s));
}

/* With no hooks at all every gate allows: a whole download runs, an app DID is 0x31, ActivateImage answers
 * positive without arming a restart, and 11 01 is 0x11. */
static void test_null_hooks_allow(void)
{
    boot(&SECURITY, NULL);
    verified();
    REQ(0x22, 0xF1, 0x91);
    EXPECT(0x7F, 0x22, 0x31);
    REQ(ACT);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_ACTIVATE_IMAGE), LO(UDSOTA_RID_ACTIVATE_IMAGE));
    TEST_ASSERT_FALSE(udsota_restart_armed(&s));
    TEST_ASSERT_EQUAL_UINT(1, e.activates);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_total);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.phase_n);
    ext_locked();
    REQ(0x11, 0x01);
    EXPECT(0x7F, 0x11, 0x11);
}

/* The phase hook sees each change once, in order, through a whole download and activation; init and requests
 * that change nothing are silent. */
static void test_phase_sequence_download_and_activate(void)
{
    TEST_ASSERT_EQUAL_UINT(0, g_mock.phase_n);
    REQ(0x3E, 0x00);
    REQ(0x22, 0xF1, 0x86);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.phase_n);
    verified();
    e.tx_pending = 1u;
    REQ(ACT);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_ACTIVATE_IMAGE), LO(UDSOTA_RID_ACTIVATE_IMAGE));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_ACTIVATING, udsota_phase(&s));
    e.tx_pending = 0u;
    now += 1u;
    udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    const int want[] = {UDSOTA_PHASE_PROGRAMMING, UDSOTA_PHASE_TRANSFERRING, UDSOTA_PHASE_PROGRAMMING,
                        UDSOTA_PHASE_ACTIVATING};
    TEST_ASSERT_EQUAL_UINT(4, g_mock.phase_n);
    TEST_ASSERT_EQUAL_INT_ARRAY(want, g_mock.phases, 4);
}

/* A failed restart re-opens the server and the phase falls back to IDLE; 10 03 and S3 then move it as usual. */
static void test_phase_after_failed_restart_and_s3(void)
{
    g_mock.reset_ok = false;
    verified();
    REQ(ACT);
    now += 1u;
    udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    REQ(0x10, 0x03);
    now += UDSOTA_S3_MS;
    udsota_poll(&s, resp, sizeof resp, now);
    const int want[] = {UDSOTA_PHASE_PROGRAMMING, UDSOTA_PHASE_TRANSFERRING, UDSOTA_PHASE_PROGRAMMING,
                        UDSOTA_PHASE_ACTIVATING, UDSOTA_PHASE_IDLE, UDSOTA_PHASE_EXTENDED, UDSOTA_PHASE_IDLE};
    TEST_ASSERT_EQUAL_UINT(7, g_mock.phase_n);
    TEST_ASSERT_EQUAL_INT_ARRAY(want, g_mock.phases, 7);
}

/* A refused first block closes the transfer but keeps the session: TRANSFERRING back to PROGRAMMING. */
static void test_phase_back_to_programming_on_refused_block(void)
{
    transfer_open();
    e.check_reason = UDSOTA_DL_BAD_BOARD;
    block(1);
    EXPECT(0x7F, 0x36, 0x31);
    const int want[] = {UDSOTA_PHASE_PROGRAMMING, UDSOTA_PHASE_TRANSFERRING, UDSOTA_PHASE_PROGRAMMING};
    TEST_ASSERT_EQUAL_UINT(3, g_mock.phase_n);
    TEST_ASSERT_EQUAL_INT_ARRAY(want, g_mock.phases, 3);
}

/* A keyed 11 01 is not an activation: the phase stays EXTENDED until the restart step ends the session. */
static void test_reset_is_not_activating(void)
{
    g_mock.reset_ok = false;
    ext_unlocked();
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_phase(&s));
    now += 1u;
    udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    const int want[] = {UDSOTA_PHASE_EXTENDED, UDSOTA_PHASE_IDLE};
    TEST_ASSERT_EQUAL_UINT(2, g_mock.phase_n);
    TEST_ASSERT_EQUAL_INT_ARRAY(want, g_mock.phases, 2);
}

/* udsota_end_session mid-transfer: the download aborts (DL_ABORTED with the bytes so far), security relocks, the
 * session is default, the hook sees IDLE, and the client's next 0x36 is 0x7F. */
static void test_end_session_mid_transfer(void)
{
    transfer_open();
    block(1);
    EXPECT(0x76, 0x01);
    udsota_end_session(&s, now);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_FALSE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_UINT(1, e.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(BLK, s.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, g_mock.phases[g_mock.phase_n - 1u]);
    block(2);
    EXPECT(0x7F, 0x36, 0x7F);
}

/* end_session while a 0x36 write is PENDING. The end is latched: the job's answer still goes out,
 * the session ends at the next poll after it, so no write is ever orphaned, and
 * the client's next 0x36 is 7F 36 7F. */
static void test_end_session_with_pending_write(void)
{
    transfer_open();
    uint8_t b[2u + BLK] = {0x36, 0x01};
    memset(&b[2], 0xE9, BLK);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, b, sizeof b, resp, sizeof resp, now));
    udsota_end_session(&s, now);
    TEST_ASSERT_TRUE(s.job_running);                          /* latched, not applied */
    TEST_ASSERT_TRUE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
    TEST_ASSERT_EQUAL_UINT(0, e.aborts);
    e.hold = false;
    now += 5u;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x76, 0x01);                                       /* the job's answer is still sent */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_PROGRAMMING, s.session);
    now += 5u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_poll(&s, resp, sizeof resp, now));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_FALSE(s.worker_orphan);
    TEST_ASSERT_FALSE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_UINT(1, e.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(BLK, s.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    block(2);
    EXPECT(0x7F, 0x36, 0x7F);
}

/* A latched end_session is applied before the next request too, when that request arrives before the next poll. */
static void test_end_session_latch_applied_before_next_request(void)
{
    transfer_open();
    uint8_t b[2u + BLK] = {0x36, 0x01};
    memset(&b[2], 0xE9, BLK);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, b, sizeof b, resp, sizeof resp, now));
    udsota_end_session(&s, now);
    e.hold = false;
    now += 5u;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x76, 0x01);
    block(2);                                                 /* no poll in between */
    EXPECT(0x7F, 0x36, 0x7F);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT(1, e.aborts);
}

/* A latched end_session is applied at a download FC point too, when the next 0x36's FF arrives before the next poll:
 * the FC is withheld and counted, the session ends without asking the gate, and the next request is served in the
 * default session. Before this, the FC went out and the client sent a whole block for 7F 36 7F. */
static void test_end_session_latch_applied_at_fc_point(void)
{
    transfer_open();
    uint8_t b[2u + BLK] = {0x36, 0x01};
    memset(&b[2], 0xE9, BLK);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, b, sizeof b, resp, sizeof resp, now));
    udsota_end_session(&s, now);                              /* latched behind the write job */
    e.hold = false;
    now += 5u;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x76, 0x01);                                       /* the job answers; the end is still latched */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
    const unsigned gate_calls = g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER];
    const uint16_t withheld = s.counters.withheld_fcs;
    now += 1u;
    TEST_ASSERT_FALSE(udsota_fc_check(&s, UDSOTA_CF_MEDIAN_NONE, 2000u, now));   /* block 2's FF, no poll between */
    TEST_ASSERT_EQUAL_UINT16(withheld + 1u, s.counters.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT(gate_calls, g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER]);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, g_mock.phases[g_mock.phase_n - 1u]);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_FALSE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_UINT(1, e.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(BLK, s.last_dl.bytes_received);
    REQ(0x22, 0xF1, 0x86);
    EXPECT(0x62, 0xF1, 0x86, UDSOTA_SESSION_DEFAULT);
}

/* What the ordering test's gate saw when asked about 10 02: udsota_phase() and the phase hook's last report. */
static int g_gate_saw_phase = -1;
static int g_gate_saw_hook = -1;

/* hooks.gate for the ordering test: records the phase state, then answers as the mock. */
static uint8_t gate_records_phase(void *ctx, udsota_op_t op)
{
    const udsota_mock_t *m = ctx;
    if (op == UDSOTA_OP_ENTER_PROGRAMMING) {
        g_gate_saw_phase = (int)udsota_phase(&s);
        g_gate_saw_hook = (m->phase_n > 0u) ? m->phases[m->phase_n - 1u] : -1;
    }
    return udsota_mock_gate(ctx, op);
}

/* A latched end_session that a request applies (no poll in between) reports IDLE through hooks.phase and
 * udsota_phase() before that request is dispatched, so its gate never sees the ended transfer's phase. */
static void test_latched_end_reports_idle_before_dispatch(void)
{
    g_hooks.gate = gate_records_phase;
    boot(&SECURITY, &g_hooks);
    transfer_open();
    uint8_t b[2u + BLK] = {0x36, 0x01};
    memset(&b[2], 0xE9, BLK);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, b, sizeof b, resp, sizeof resp, now));
    udsota_end_session(&s, now);                              /* latched behind the write job */
    e.hold = false;
    now += 5u;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x76, 0x01);                                       /* the job answers; the end is still latched */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
    g_gate_saw_phase = -1;
    g_gate_saw_hook = -1;
    REQ(0x10, 0x02);                                          /* applies the end, then asks the gate */
    EXPECT(POS10(0x02));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, g_gate_saw_phase);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, g_gate_saw_hook);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&s));
    TEST_ASSERT_TRUE(g_mock.phase_n >= 2u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, g_mock.phases[g_mock.phase_n - 2u]);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, g_mock.phases[g_mock.phase_n - 1u]);
}

/* end_session while FF01's verify is PENDING: the verdict is still sent and the slot stays verified (that survives
 * a session change), then the session ends. */
static void test_end_session_during_pending_verify(void)
{
    transfer_open();
    block(1);
    block(2);
    REQ(0x37);
    EXPECT(0x77);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, (const uint8_t[]){FF01}, 4, resp, sizeof resp, now));
    udsota_end_session(&s, now);
    e.hold = false;
    now += 5u;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_CHECK_PROG_DEPS), LO(UDSOTA_RID_CHECK_PROG_DEPS), UDSOTA_DL_OK);
    TEST_ASSERT_TRUE(s.slot_verified);
    now += 5u;
    udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_TRUE(s.slot_verified);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, s.last_dl.reason_code);
}

/* A worker orphan does not hold end_session back: after the 90 s cap, a new extended session ends at once. */
static void test_end_session_not_blocked_by_orphan(void)
{
    transfer_open();
    block(1);
    block(2);
    REQ(0x37);
    EXPECT(0x77);
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, (const uint8_t[]){FF01}, 4, resp, sizeof resp, now));
    now += UDSOTA_JOB_CAP_MS;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
    EXPECT(0x7F, 0x31, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);   /* the cap: the verify is now an orphan */
    TEST_ASSERT_TRUE(s.worker_orphan);
    ext_locked();                                             /* 10 03 needs no idle worker */
    udsota_end_session(&s, now);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_FALSE(s.end_pending);
    TEST_ASSERT_TRUE(s.worker_orphan);
}

/* end_session during an armed restart is a no-op, and nothing is latched: the restart ends the session itself,
 * exactly once. */
static void test_end_session_ignored_while_restart_armed(void)
{
    ext_unlocked();
    e.tx_pending = 1u;
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    udsota_end_session(&s, now);
    TEST_ASSERT_TRUE(udsota_restart_armed(&s));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, s.security);
    TEST_ASSERT_FALSE(s.end_pending);
    e.tx_pending = 0u;
    udsota_poll(&s, resp, sizeof resp, now + 1u);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
}

/* No security. 0x27 answers 0x11 in every session, before the session check; 34, FF01,
 * ActivateImage and a keyed 11 01 all run without a key. */
static void test_no_security(void)
{
    static const uint8_t KEY02[2u + UDSOTA_KEY_LEN] = {0x27, 0x02};
    boot(NULL, &g_hooks);
    REQ(0x27, 0x01);
    EXPECT(0x7F, 0x27, 0x11);                                 /* default session: 0x11, not 0x7F */
    ext_locked();
    REQ(0x27, 0x01);
    EXPECT(0x7F, 0x27, 0x11);
    txn(KEY02, sizeof KEY02);
    EXPECT(0x7F, 0x27, 0x11);
    prog_locked();
    REQ(0x27, 0x03);
    EXPECT(0x7F, 0x27, 0x11);
    REQ(REQ34);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    block(1);  EXPECT(0x76, 0x01);
    block(2);  EXPECT(0x76, 0x02);
    REQ(0x37); EXPECT(0x77);
    REQ(FF01); EXPECT(0x71, 0x01, HI(UDSOTA_RID_CHECK_PROG_DEPS), LO(UDSOTA_RID_CHECK_PROG_DEPS), UDSOTA_DL_OK);
    REQ(ACT);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_ACTIVATE_IMAGE), LO(UDSOTA_RID_ACTIVATE_IMAGE));
    TEST_ASSERT_TRUE(udsota_restart_armed(&s));
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    boot(NULL, &g_hooks);
    ext_locked();
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    TEST_ASSERT_TRUE(udsota_restart_armed(&s));
}

/* hooks.reset NULL. 11 01 answers 0x11 in every session, keyed or not; ActivateImage still sets the
 * boot slot and answers positive, but arms no restart, the phase stays PROGRAMMING and the server keeps serving. */
static void test_reset_hook_null(void)
{
    g_hooks.reset = NULL;
    boot(&SECURITY, &g_hooks);
    REQ(0x11, 0x01);
    EXPECT(0x7F, 0x11, 0x11);                                 /* default: 0x11 before 0x7F */
    ext_unlocked();
    REQ(0x11, 0x01);
    EXPECT(0x7F, 0x11, 0x11);
    verified();
    REQ(ACT);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_ACTIVATE_IMAGE), LO(UDSOTA_RID_ACTIVATE_IMAGE));
    TEST_ASSERT_EQUAL_UINT(1, e.activates);
    TEST_ASSERT_FALSE(udsota_restart_armed(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&s));
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_IDLE_POLL_MS, udsota_ms_to_deadline(&s, now));
    REQ(0x3E, 0x00);
    EXPECT(0x7E, 0x00);
}

/* Zero config fields take their defaults; set ones are used: P2/P2* in the 10 answer, the 34 block length and
 * the 36 length limit, the first 0x78 at 4/5 of P2, and the SecurityAccess levels. */
static void test_config_defaults_and_overrides(void)
{
    REQ(0x10, 0x03);
    EXPECT(POS10(0x03));
    g_cfg.p2_ms = 25u;
    g_cfg.p2star_ms = 2000u;
    g_cfg.max_block_len = 1026u;
    g_cfg.level_extended = 0x11u;
    g_cfg.level_programming = 0x05u;
    boot(&SECURITY, &g_hooks);
    REQ(0x10, 0x03);
    EXPECT(0x50, 0x03, 0x00, 0x19, 0x00, 0xC8);
    REQ(0x27, 0x01);
    EXPECT(0x7F, 0x27, 0x12);                                 /* the default level is no longer served */
    unlock(0x11u);
    REQ(0x10, 0x02);
    EXPECT(0x50, 0x02, 0x00, 0x19, 0x00, 0xC8);
    REQ(0x27, 0x11);
    EXPECT(0x7F, 0x27, 0x7E);                                 /* the extended level in programming */
    REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0x00, 0x00, 0x08, 0x00);
    EXPECT(0x7F, 0x34, 0x33);
    unlock(0x05u);
    REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0x00, 0x00, 0x08, 0x00);
    EXPECT(0x74, 0x20, 0x04, 0x02);
    static uint8_t big[1027];
    big[0] = 0x36;
    big[1] = 0x01;
    memset(&big[2], 0xE9, sizeof big - 2u);
    txn(big, sizeof big);
    EXPECT(0x7F, 0x36, 0x13);                                 /* 1027 > max_block_len */
    e.hold = true;
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, big, 1026u, resp, sizeof resp, now));
    TEST_ASSERT_EQUAL_UINT(0, udsota_poll(&s, resp, sizeof resp, now + 19u));
    TEST_ASSERT_EQUAL_UINT(3, udsota_poll(&s, resp, sizeof resp, now + 20u));
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_NRC_RESPONSE_PENDING, resp[2]);
}

/* A max_block_len over 4095 is clamped to it, so the 74 answer never announces a block the ISO-TP adapter (capped
 * at 4095 too) could not receive. */
static void test_max_block_len_clamped_to_4095(void)
{
    g_cfg.max_block_len = 8000u;
    boot(&SECURITY, &g_hooks);
    TEST_ASSERT_EQUAL_UINT16(UDSOTA_DL_MAX_BLOCK_LEN, s.cfg.max_block_len);
    transfer_open();                                          /* asserts 74 20 0F FF */
}

/* F189, F18C, F1F0 and F1F3 come from engine.version, cfg.device_id, engine.status and engine.running_sha, and
 * never reach hooks.did_read; with the source NULL the same DIDs go to hooks.did_read, as every app DID does. */
static void test_server_owned_dids_and_fallback(void)
{
    REQ(0x22, HI(UDSOTA_DID_SW_VERSION), LO(UDSOTA_DID_SW_VERSION));
    EXPECT(0x62, HI(UDSOTA_DID_SW_VERSION), LO(UDSOTA_DID_SW_VERSION), 'v', '1', '.', '2', '.', '3');
    REQ(0x22, HI(UDSOTA_DID_SERIAL), LO(UDSOTA_DID_SERIAL));
    EXPECT(0x62, HI(UDSOTA_DID_SERIAL), LO(UDSOTA_DID_SERIAL), 0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    g_mock.status.flags = UDSOTA_STATUS_SIG_CHECKED;
    REQ(0x22, HI(UDSOTA_DID_STATUS), LO(UDSOTA_DID_STATUS));
    EXPECT(0x62, HI(UDSOTA_DID_STATUS), LO(UDSOTA_DID_STATUS),
           0x00, 0x03, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01);
    REQ(0x22, HI(UDSOTA_DID_RUNNING_SHA), LO(UDSOTA_DID_RUNNING_SHA));
    TEST_ASSERT_EQUAL_UINT(3u + UDSOTA_SHA256_LEN, rlen);
    TEST_ASSERT_EQUAL_HEX8(0xA0, resp[3]);
    TEST_ASSERT_EQUAL_HEX8(0xBF, resp[34]);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.did_reads);
    REQ(0x22, 0xF1, 0x91);
    EXPECT(0x62, 0xF1, 0x91, 'd', 'e', 'v', 'k', 'i', 't');
    TEST_ASSERT_EQUAL_UINT(1, g_mock.did_reads);

    static udsota_engine_t bare;
    bare = ENGINE;
    bare.status = NULL;
    bare.running_sha = NULL;
    bare.version = NULL;
    g_cfg.device_id = NULL;
    g_cfg.device_id_len = 0u;
    udsota_init(&s, &g_cfg, &bare, &SECURITY, &g_hooks);
    static const uint16_t DIDS[] = {UDSOTA_DID_SW_VERSION, UDSOTA_DID_SERIAL, UDSOTA_DID_STATUS,
                                    UDSOTA_DID_RUNNING_SHA};
    for (size_t i = 0; i < sizeof DIDS / sizeof DIDS[0]; i++) {
        g_mock.did_reads = 0;
        const uint8_t rd[3] = {0x22, HI(DIDS[i]), LO(DIDS[i])};
        txn(rd, sizeof rd);
        EXPECT(0x7F, 0x22, 0x31);
        TEST_ASSERT_EQUAL_UINT(1, g_mock.did_reads);
        TEST_ASSERT_EQUAL_HEX16(DIDS[i], g_mock.last_did);
    }
}

/* Without engine.status the core's slot conditions are not checked: 10 02 opens though the mock's status says
 * the boot slot moved, and ConfirmImage goes straight to the gate and the engine. */
static void test_no_status_skips_slot_checks(void)
{
    static udsota_engine_t bare;
    bare = ENGINE;
    bare.status = NULL;
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA1;
    udsota_init(&s, &g_cfg, &bare, &SECURITY, &g_hooks);
    prog_locked();
    ext_locked();
    REQ(CONF);
    EXPECT(0x71, 0x01, HI(UDSOTA_RID_CONFIRM_IMAGE), LO(UDSOTA_RID_CONFIRM_IMAGE));
    TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_CONFIRM]);
    TEST_ASSERT_EQUAL_UINT(1, e.confirms);
}

/* ConfirmImage's core rule, applied after the gate: a PENDING_VERIFY boot image runs engine.confirm;
 * one already VALID or UNDEFINED (a build without rollback) answers positive without the engine; any other state,
 * or a boot slot that is not the running one, is 0x22. The gate is asked first every time, and its NRC wins. */
static void test_confirm_core_rule_per_state(void)
{
    static const struct {
        uint8_t  state, boot;
        bool     positive;
        unsigned confirms;
    } ROWS[] = {
        {UDSOTA_IMG_PENDING_VERIFY, UDSOTA_SLOT_OTA0, true,  1},
        {UDSOTA_IMG_VALID,          UDSOTA_SLOT_OTA0, true,  0},
        {UDSOTA_IMG_UNDEFINED,      UDSOTA_SLOT_OTA0, true,  0},
        {UDSOTA_IMG_NEW,            UDSOTA_SLOT_OTA0, false, 0},
        {UDSOTA_IMG_INVALID,        UDSOTA_SLOT_OTA0, false, 0},
        {UDSOTA_IMG_PENDING_VERIFY, UDSOTA_SLOT_OTA1, false, 0},
        {UDSOTA_IMG_VALID,          UDSOTA_SLOT_OTA1, false, 0},
    };
    for (size_t i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++) {
        setUp();
        g_mock.status.running_state = ROWS[i].state;
        g_mock.status.boot_slot = ROWS[i].boot;
        ext_locked();
        REQ(CONF);
        if (ROWS[i].positive) {
            EXPECT(0x71, 0x01, HI(UDSOTA_RID_CONFIRM_IMAGE), LO(UDSOTA_RID_CONFIRM_IMAGE));
        } else {
            EXPECT(0x7F, 0x31, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
        }
        TEST_ASSERT_EQUAL_UINT(ROWS[i].confirms, e.confirms);
        TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_CONFIRM]);
    }
    setUp();
    ext_locked();                                             /* VALID, but the gate refuses: its NRC wins */
    g_mock.gate_nrc[UDSOTA_OP_CONFIRM] = NRC_SPEED;
    REQ(CONF);
    EXPECT(0x7F, 0x31, NRC_SPEED);
    TEST_ASSERT_EQUAL_UINT(0, e.confirms);
}

/* With no tx_pending source installed a restart waits the full UDSOTA_RESET_TX_WAIT_MS. */
static void test_restart_waits_without_tx_pending(void)
{
    udsota_init(&s, &g_cfg, &ENGINE, &SECURITY, &g_hooks);
    now = T0;
    ext_unlocked();
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    const uint32_t t0 = now;
    udsota_poll(&s, resp, sizeof resp, t0 + UDSOTA_RESET_TX_WAIT_MS - 1u);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    udsota_poll(&s, resp, sizeof resp, t0 + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
}

/* Runs every hooks test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_gate_asked_at_every_point_nrc_verbatim);
    RUN_TEST(test_gate_not_asked_after_earlier_nrc);
    RUN_TEST(test_download_conditions_before_format);
    RUN_TEST(test_gate_busy_at_transfer_keeps_it_open);
    RUN_TEST(test_gate_denial_at_transfer_ends_it);
    RUN_TEST(test_gate_denial_at_fc_point_withholds);
    RUN_TEST(test_stmin_violation_counted_only_when_gate_allows);
    RUN_TEST(test_stmin_monitor_off);
    RUN_TEST(test_null_hooks_allow);
    RUN_TEST(test_phase_sequence_download_and_activate);
    RUN_TEST(test_phase_after_failed_restart_and_s3);
    RUN_TEST(test_phase_back_to_programming_on_refused_block);
    RUN_TEST(test_reset_is_not_activating);
    RUN_TEST(test_end_session_mid_transfer);
    RUN_TEST(test_end_session_with_pending_write);
    RUN_TEST(test_end_session_latch_applied_before_next_request);
    RUN_TEST(test_end_session_latch_applied_at_fc_point);
    RUN_TEST(test_latched_end_reports_idle_before_dispatch);
    RUN_TEST(test_end_session_during_pending_verify);
    RUN_TEST(test_end_session_not_blocked_by_orphan);
    RUN_TEST(test_end_session_ignored_while_restart_armed);
    RUN_TEST(test_no_security);
    RUN_TEST(test_reset_hook_null);
    RUN_TEST(test_config_defaults_and_overrides);
    RUN_TEST(test_max_block_len_clamped_to_4095);
    RUN_TEST(test_server_owned_dids_and_fallback);
    RUN_TEST(test_no_status_skips_slot_checks);
    RUN_TEST(test_confirm_core_rule_per_state);
    RUN_TEST(test_restart_waits_without_tx_pending);
    return UNITY_END();
}
