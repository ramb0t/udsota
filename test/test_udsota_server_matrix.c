/* Host tests for the pure UDS server as a whole: the full session x security x NRC matrix, the
 * keyed ECUReset and its respond-then-restart wait, session fallback mid-download, and the phase. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_priv.h"
#include "udsota_mock.h"

#define T0        60000u   /* every test starts 60 s after boot, past SecurityAccess's 10 s boot delay */
#define BLOCK_LEN 64u      /* data bytes in the one 0x36 block the mid-download tests send */

/* What the mock engine and reset hook saw and what they answer. */
typedef struct {
    unsigned n_begin, n_write, n_abort, n_reset;
    uint32_t tx_pending;   /* tx_pending answer: frames still in the TX FIFO */
    bool     reset_ok;     /* hooks.reset result (on the target a successful reset never returns) */
    int      job_result;   /* engine.poll answer; UDSOTA_PENDING while the fake worker is busy */
    uint8_t  security_at_reset, session_at_reset;   /* the server's state when hooks.reset was called */
    unsigned n_abort_at_reset;                      /* engine.abort calls queued before hooks.reset */
} mock_t;

static mock_t       m;
static udsota_server_t s;
static uint8_t      resp[64];
static uint32_t     now;

/* Mock seed source: always 10 11 .. 1F (non-zero, so SecurityAccess accepts it). */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return true;
}
/* Stand-in for HMAC-SHA256, as in test_udsota_server_security.c: key[i] = seed[i] ^ level ^ 0xA5. */
static void fake_key(const uint8_t *seed, uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5);
    }
}
/* Mock security.key: the expected key for seed and level. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    fake_key(seed, level, out);
    return true;
}
/* Counts an erase; completes at once (a synchronous fake). */
static int mock_ota_begin(void *ctx, uint32_t size) { m.n_begin++; return 0; }
/* Counts a write; completes at once. */
static int mock_ota_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { m.n_write++; return 0; }
/* Counts a queued abort (fire-and-forget). */
static void mock_ota_abort(void *ctx) { m.n_abort++; }
/* The other no-argument OTA ops (end, activate, confirm): complete at once with success. */
static int mock_ota_ok(void *ctx) { return 0; }
/* First-block check that always passes. */
static int mock_image_check(void *ctx, const uint8_t *f, size_t n, udsota_reason_t *r) { *r = UDSOTA_DL_OK; return 0; }
/* Counts a restart request and records the server's lock, session and aborts at that moment; returns the
 * result the test chose. */
static bool mock_reset(void *ctx)
{
    m.n_reset++;
    m.security_at_reset = s.security;
    m.session_at_reset = s.session;
    m.n_abort_at_reset = m.n_abort;
    return m.reset_ok;
}
/* Reports the TX FIFO depth the test chose. */
static uint32_t mock_tx_pending(void *ctx) { return m.tx_pending; }
/* Reports the fake worker's state the test chose. */
static int mock_job_poll(void *ctx) { return m.job_result; }

static udsota_mock_t g_mock;
static const udsota_engine_t ENGINE = {
    .check_first = mock_image_check, .begin = mock_ota_begin, .write = mock_ota_write, .verify = mock_ota_ok,
    .activate = mock_ota_ok, .confirm = mock_ota_ok, .abort = mock_ota_abort, .poll = mock_job_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};
static const udsota_security_t SECURITY = {.rng16 = mock_rng16, .key = mock_key};

/* A freshly booted server at T0: the mock's config (F18C) and hooks, but this file's reset hook, which records
 * the server's state at the restart; the gate allows everything. */
static void fresh(void)
{
    memset(&m, 0, sizeof m);
    m.reset_ok = true;
    udsota_mock_clear(&g_mock);
    now = T0;
    const udsota_config_t cfg = udsota_mock_cfg();
    udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    hooks.reset = mock_reset;
    udsota_init(&s, &cfg, &ENGINE, &SECURITY, &hooks);
    udsota_set_tx_pending(&s, mock_tx_pending, NULL);
}

/* Unity hook: every test starts from a fresh server. */
void setUp(void) { fresh(); }
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends one request 1 ms after the last; returns the response length (0 = nothing sent). */
static size_t send_req(const uint8_t *req, size_t len)
{
    now += 1u;
    memset(resp, 0xEE, sizeof resp);
    return udsota_on_request(&s, req, len, resp, sizeof resp, now);
}
#define SEND(...) send_req((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

/* Polls at absolute time t; returns the response length. */
static size_t poll_at(uint32_t t)
{
    now = t;
    memset(resp, 0xEE, sizeof resp);
    return udsota_poll(&s, resp, sizeof resp, now);
}

/* Asserts the last response was exactly want[0..wn). */
static void expect_bytes(const uint8_t *want, size_t wn, size_t got)
{
    TEST_ASSERT_EQUAL_UINT(wn, got);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, resp, wn);
}
#define EXPECT(got, ...) expect_bytes((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}), (got))

/* Requests a seed for `level` (0x01/0x03) and sends its correct key; asserts 67 <level+1>. */
static void unlock(uint8_t level)
{
    uint8_t req[2 + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, level};
    TEST_ASSERT_EQUAL_UINT(2 + UDSOTA_SEED_LEN, send_req(req, 2));
    uint8_t seed[UDSOTA_SEED_LEN];
    memcpy(seed, &resp[2], sizeof seed);
    req[1] = (uint8_t)(level + 1u);
    fake_key(seed, level, &req[2]);
    EXPECT(send_req(req, sizeof req), 0x67, level + 1u);
}

/* The five session x security states the matrix runs from. */
typedef enum { ST_D, ST_E, ST_E1, ST_P, ST_P3 } st_t;

/* Brings a fresh server into `st` through real requests: 10 03 / 10 02, then 27 01-02 / 27 03-04. */
static void reach(st_t st)
{
    fresh();
    if (st == ST_E || st == ST_E1) {
        EXPECT(SEND(0x10, 0x03), 0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    }
    if (st == ST_P || st == ST_P3) {
        EXPECT(SEND(0x10, 0x02), 0x50, 0x02, 0x00, 0x32, 0x01, 0xF4);
    }
    if (st == ST_E1) {
        unlock(UDSOTA_SA_SEED_EXTENDED);
    }
    if (st == ST_P3) {
        unlock(UDSOTA_SA_SEED_PROGRAMMING);
    }
}

/* One matrix row: from state `st`, request req[0..req_len) is answered exactly want[0..want_len). */
typedef struct {
    const char *name;
    uint8_t     st;
    uint8_t     req[20];
    uint8_t     req_len;
    uint8_t     want[20];
    uint8_t     want_len;
} row_t;

#define B(...)  {__VA_ARGS__}, (uint8_t)sizeof((const uint8_t[]){__VA_ARGS__})
#define NONE    {0}, 0
#define POS10(ss) B(0x50, ss, 0x00, 0x32, 0x01, 0xF4)
#define SEED16  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
#define ZERO16  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define REQ34   B(0x34, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00)

/* The session x security x NRC matrix (ISO 14229-1's per-service session and NRC rules, as udsota applies them).
 * D default, E extended, E1 extended + level 01, P programming, P3 programming + level 03. */
static const row_t MATRIX[] = {
    /* 0x10 DiagnosticSessionControl: any session, no key; 02 needs the download gate (passing here). */
    {"D 10 01",              ST_D,  B(0x10, 0x01), POS10(0x01)},
    {"D 10 02",              ST_D,  B(0x10, 0x02), POS10(0x02)},
    {"D 10 03",              ST_D,  B(0x10, 0x03), POS10(0x03)},
    {"E1 10 01",             ST_E1, B(0x10, 0x01), POS10(0x01)},
    {"E1 10 02",             ST_E1, B(0x10, 0x02), POS10(0x02)},
    {"P3 10 03",             ST_P3, B(0x10, 0x03), POS10(0x03)},
    {"P3 10 01",             ST_P3, B(0x10, 0x01), POS10(0x01)},
    {"D 10 04 subfunc",      ST_D,  B(0x10, 0x04), B(0x7F, 0x10, 0x12)},
    {"E 10 short",           ST_E,  B(0x10),       B(0x7F, 0x10, 0x13)},
    /* 0x11 ECUReset: extended or programming, level 01 or 03 (the keyed reset), 01 only. */
    {"D 11 01",              ST_D,  B(0x11, 0x01), B(0x7F, 0x11, 0x7F)},
    {"D 11 short",           ST_D,  B(0x11),       B(0x7F, 0x11, 0x7F)},
    {"E 11 01 locked",       ST_E,  B(0x11, 0x01), B(0x7F, 0x11, 0x33)},
    {"E 11 02 locked",       ST_E,  B(0x11, 0x02), B(0x7F, 0x11, 0x12)},
    {"E1 11 01",             ST_E1, B(0x11, 0x01), B(0x51, 0x01)},
    {"P 11 01 locked",       ST_P,  B(0x11, 0x01), B(0x7F, 0x11, 0x33)},
    {"P3 11 01",             ST_P3, B(0x11, 0x01), B(0x51, 0x01)},
    {"E1 11 02 softReset",   ST_E1, B(0x11, 0x02), B(0x7F, 0x11, 0x12)},
    {"E1 11 03 keyOffOn",    ST_E1, B(0x11, 0x03), B(0x7F, 0x11, 0x12)},
    {"E1 11 short",          ST_E1, B(0x11),       B(0x7F, 0x11, 0x13)},
    {"E1 11 01 long",        ST_E1, B(0x11, 0x01, 0x00), B(0x7F, 0x11, 0x13)},
    /* 0x27 SecurityAccess: 01/02 in extended, 03/04 in programming. */
    {"D 27 01",              ST_D,  B(0x27, 0x01), B(0x7F, 0x27, 0x7F)},
    {"E 27 01",              ST_E,  B(0x27, 0x01), B(0x67, 0x01, SEED16)},
    {"E 27 03",              ST_E,  B(0x27, 0x03), B(0x7F, 0x27, 0x7E)},
    {"P 27 03",              ST_P,  B(0x27, 0x03), B(0x67, 0x03, SEED16)},
    {"P 27 01",              ST_P,  B(0x27, 0x01), B(0x7F, 0x27, 0x7E)},
    {"E1 27 01 zero seed",   ST_E1, B(0x27, 0x01), B(0x67, 0x01, ZERO16)},
    {"P3 27 03 zero seed",   ST_P3, B(0x27, 0x03), B(0x67, 0x03, ZERO16)},
    {"E 27 02 no seed",      ST_E,  B(0x27, 0x02, ZERO16), B(0x7F, 0x27, 0x24)},
    {"E 27 05 subfunc",      ST_E,  B(0x27, 0x05), B(0x7F, 0x27, 0x12)},
    /* 0x3E TesterPresent: any session. */
    {"D 3E 00",              ST_D,  B(0x3E, 0x00), B(0x7E, 0x00)},
    {"E1 3E 00",             ST_E1, B(0x3E, 0x00), B(0x7E, 0x00)},
    {"P3 3E 00",             ST_P3, B(0x3E, 0x00), B(0x7E, 0x00)},
    {"P3 3E 80 silent",      ST_P3, B(0x3E, 0x80), NONE},
    {"E 3E 01 subfunc",      ST_E,  B(0x3E, 0x01), B(0x7F, 0x3E, 0x12)},
    /* 0x22 ReadDataByIdentifier: any session, no DID is secret. F186 reports the ISO session number. */
    {"D 22 F186",            ST_D,  B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01)},
    {"E 22 F186",            ST_E,  B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x03)},
    {"P3 22 F186",           ST_P3, B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x02)},
    {"E 22 F18C",            ST_E,  B(0x22, 0xF1, 0x8C), B(0x62, 0xF1, 0x8C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01)},
    {"D 22 unknown DID",     ST_D,  B(0x22, 0xF1, 0xFF), B(0x7F, 0x22, 0x31)},
    /* 0x2E WriteDataByIdentifier is not served in any session while did_write is NULL. */
    {"D 2E",                 ST_D,  B(0x2E, 0x01, 0x00, 0x00), B(0x7F, 0x2E, 0x11)},
    {"E1 2E",                ST_E1, B(0x2E, 0x01, 0x00, 0x00), B(0x7F, 0x2E, 0x11)},
    /* 0x31 RoutineControl: FF01/F000/F001 programming + 03; F002 extended, no key. */
    {"D 31 FF01",            ST_D,  B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x7F)},
    {"E 31 FF01",            ST_E,  B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x31)},
    {"E1 31 F001",           ST_E1, B(0x31, 0x01, 0xF0, 0x01), B(0x7F, 0x31, 0x31)},
    {"P 31 FF01 locked",     ST_P,  B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x33)},
    {"P 31 F001 locked",     ST_P,  B(0x31, 0x01, 0xF0, 0x01), B(0x7F, 0x31, 0x33)},
    {"P3 31 FF01 before 37", ST_P3, B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x24)},
    {"P3 31 F001 unverified",ST_P3, B(0x31, 0x01, 0xF0, 0x01), B(0x7F, 0x31, 0x24)},
    {"P3 31 F000 reserved",  ST_P3, B(0x31, 0x01, 0xF0, 0x00), B(0x71, 0x01, 0xF0, 0x00, 0xFF)},
    {"P3 31 F002",           ST_P3, B(0x31, 0x01, 0xF0, 0x02), B(0x7F, 0x31, 0x31)},
    /* confirm is idempotent: an already VALID image answers positive */
    {"E 31 F002 already valid", ST_E, B(0x31, 0x01, 0xF0, 0x02), B(0x71, 0x01, 0xF0, 0x02)},
    {"E 31 1234 unassigned", ST_E,  B(0x31, 0x01, 0x12, 0x34), B(0x7F, 0x31, 0x31)},
    {"E 31 02 stop",         ST_E,  B(0x31, 0x02, 0xF0, 0x02), B(0x7F, 0x31, 0x12)},
    {"E 31 short",           ST_E,  B(0x31, 0x01, 0x02),       B(0x7F, 0x31, 0x13)},
    /* 0x34/0x36/0x37 download: programming + 03. */
    {"D 34",                 ST_D,  REQ34, B(0x7F, 0x34, 0x7F)},
    {"E1 34",                ST_E1, REQ34, B(0x7F, 0x34, 0x7F)},
    {"P 34 locked",          ST_P,  REQ34, B(0x7F, 0x34, 0x33)},
    {"P3 34",                ST_P3, REQ34, B(0x74, 0x20, 0x0F, 0xFF)},
    {"P3 34 DFI 01",         ST_P3, B(0x34, 0x01, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00),
                                    B(0x7F, 0x34, 0x31)},
    {"D 36",                 ST_D,  B(0x36, 0x01, 0xAA), B(0x7F, 0x36, 0x7F)},
    {"P 36 locked",          ST_P,  B(0x36, 0x01, 0xAA), B(0x7F, 0x36, 0x33)},
    {"P3 36 no download",    ST_P3, B(0x36, 0x01, 0xAA), B(0x7F, 0x36, 0x24)},
    {"D 37",                 ST_D,  B(0x37),             B(0x7F, 0x37, 0x7F)},
    {"P 37 locked",          ST_P,  B(0x37),             B(0x7F, 0x37, 0x33)},
    {"P3 37 no download",    ST_P3, B(0x37),             B(0x7F, 0x37, 0x24)},
    /* Services udsota doesn't serve at all (0x28 and 0x85 need hooks.comm_control and hooks.dtc_setting, which
     * this suite leaves NULL: 0x11 before the session, length and sub-function checks). */
    {"E1 19 ReadDTC",        ST_E1, B(0x19, 0x02, 0xFF), B(0x7F, 0x19, 0x11)},
    {"P3 85 DTCSetting",     ST_P3, B(0x85, 0x01),       B(0x7F, 0x85, 0x11)},
    {"E 28 no hook",         ST_E,  B(0x28, 0x03, 0x01), B(0x7F, 0x28, 0x11)},
    {"D 85 no hook",         ST_D,  B(0x85, 0x02),       B(0x7F, 0x85, 0x11)},
    {"E 85 short no hook",   ST_E,  B(0x85),             B(0x7F, 0x85, 0x11)},
    {"E 85 03 no hook",      ST_E,  B(0x85, 0x03),       B(0x7F, 0x85, 0x11)},
    {"E 85 82 no hook",      ST_E,  B(0x85, 0x82),       B(0x7F, 0x85, 0x11)},
};

/* Every matrix row from a fresh server in its state: one assertion per row on length and bytes together. */
static void test_nrc_matrix(void)
{
    for (size_t i = 0; i < sizeof MATRIX / sizeof MATRIX[0]; i++) {
        const row_t *r = &MATRIX[i];
        reach((st_t)r->st);
        const size_t n = send_req(r->req, r->req_len);
        uint8_t want[1 + sizeof r->want], got[1 + sizeof resp];
        want[0] = r->want_len;
        memcpy(&want[1], r->want, r->want_len);
        got[0] = (uint8_t)n;
        memcpy(&got[1], resp, n <= sizeof resp ? n : sizeof resp);
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(want, got, 1u + r->want_len, r->name);
    }
}

/* Keyed-reset rule: without an unlocked level no request makes the server call hooks.reset, in any session
 * and during the soak (running image PENDING_VERIFY), so no node lacking K_dev can restart the device or
 * force a rollback. With the key, the reset (and so the rollback of an unconfirmed image) is allowed. */
static void test_reset_needs_the_key(void)
{
    static const st_t locked[] = {ST_D, ST_E, ST_P};
    static const uint8_t subs[] = {0x01, 0x81};
    char msg[48];
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < 2; j++) {
            for (int soak = 0; soak < 2; soak++) {
                reach(locked[i]);
                g_mock.status.running_state = (soak != 0) ? UDSOTA_IMG_PENDING_VERIFY : UDSOTA_IMG_VALID;
                const uint8_t req[2] = {UDSOTA_SID_RESET, subs[j]};
                send_req(req, sizeof req);
                const uint32_t t0 = now;             /* poll_at moves now, so the bound is fixed here */
                for (uint32_t t = t0 + 10u; t <= t0 + 200u; t += 10u) {
                    poll_at(t);
                }
                snprintf(msg, sizeof msg, "state %u sub %02X soak %d", (unsigned)locked[i], subs[j], soak);
                TEST_ASSERT_EQUAL_UINT_MESSAGE(0, m.n_reset, msg);
            }
        }
    }
    reach(ST_E1);
    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;
    EXPECT(SEND(0x11, 0x01), 0x51, 0x01);
    poll_at(now + 10u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
}

/* Final answer for the test's stand-in job: 71 00 <result>. */
static size_t test_done(udsota_server_t *srv, int result, uint8_t *out, size_t max, uint32_t t)
{
    if (max < 3) {
        return 0;
    }
    out[0] = UDSOTA_POS(UDSOTA_SID_ROUTINE);
    out[1] = 0x00;
    out[2] = (uint8_t)result;
    return 3;
}

/* 11 01 with the key is refused with the gate's NRC (the app's reset rule) or while the worker is busy, an
 * orphaned 90 s job included, and never restarts. */
static void test_reset_refused_by_the_reset_rule(void)
{
    reach(ST_E1);
    g_mock.gate_nrc[UDSOTA_OP_RESET] = 0x22;
    EXPECT(SEND(0x11, 0x01), 0x7F, 0x11, 0x22);
    g_mock.gate_nrc[UDSOTA_OP_RESET] = 0;
    m.job_result = UDSOTA_PENDING;                 /* the core's worker rule: engine.poll reports a queued job */
    EXPECT(SEND(0x11, 0x01), 0x7F, 0x11, 0x22);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_RESET]);
    m.job_result = UDSOTA_PENDING;                 /* a job that passes the 90 s cap still owns the worker */
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, test_done, 0,
                                            resp, sizeof resp, now));
    EXPECT(poll_at(now + UDSOTA_JOB_CAP_MS), 0x7F, 0x31, 0x72);   /* the cap ends the session and relocks */
    EXPECT(SEND(0x10, 0x03), 0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    EXPECT(SEND(0x11, 0x01), 0x7F, 0x11, 0x22);    /* the orphaned job still counts as a busy worker */
    poll_at(now + 200u);
    TEST_ASSERT_EQUAL_UINT(0, m.n_reset);
}

/* While the server waits on a job (one request at a time), 11 01 is 0x21 like any request but 3E. */
static void test_reset_during_job_is_busy(void)
{
    reach(ST_E1);
    m.job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, test_done, 0,
                                            resp, sizeof resp, now));
    EXPECT(SEND(0x11, 0x01), 0x7F, 0x11, 0x21);
    poll_at(now + 20u);
    TEST_ASSERT_EQUAL_UINT(0, m.n_reset);
}

/* The restart waits for the 51 01 frame to leave: never from on_request, not while tx_pending() > 0,
 * then at the first poll that sees 0. It relocks and ends the session first, then stays silent. */
static void test_reset_waits_for_tx_pending(void)
{
    reach(ST_E1);
    m.tx_pending = 1;                              /* the 51 01 frame is in the TX FIFO */
    EXPECT(SEND(0x11, 0x01), 0x51, 0x01);
    const uint32_t t0 = now;
    TEST_ASSERT_EQUAL_UINT(0, m.n_reset);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 10u));
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 50u));
    TEST_ASSERT_EQUAL_UINT(0, m.n_reset);
    m.tx_pending = 0;
    poll_at(t0 + 60u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
    TEST_ASSERT_EQUAL_UINT8(0, m.security_at_reset);                        /* relocked before, not after */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, m.session_at_reset);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    poll_at(t0 + 70u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);          /* once only */
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x3E, 0x00));   /* restarting: nothing more is answered */
}

/* A TX FIFO that never drains (a stall hold) delays the restart by at most 100 ms. */
static void test_reset_after_100ms_if_tx_stuck(void)
{
    reach(ST_P3);
    m.tx_pending = 3;
    EXPECT(SEND(0x11, 0x01), 0x51, 0x01);
    const uint32_t t0 = now;
    poll_at(t0 + UDSOTA_RESET_TX_WAIT_MS - 1u);
    TEST_ASSERT_EQUAL_UINT(0, m.n_reset);
    poll_at(t0 + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
}

/* 11 81 restarts without answering (SPRMIB). */
static void test_reset_suppressed_positive(void)
{
    reach(ST_E1);
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x11, 0x81));
    poll_at(now + 1u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
}

/* A reset op that returns false leaves the server default, locked and answering, not wedged. */
static void test_failed_reset_leaves_server_locked_and_serving(void)
{
    reach(ST_P3);
    m.reset_ok = false;
    EXPECT(SEND(0x11, 0x01), 0x51, 0x01);
    poll_at(now + 1u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
    TEST_ASSERT_EQUAL_UINT8(0, m.security_at_reset);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, m.session_at_reset);
    EXPECT(SEND(0x3E, 0x00), 0x7E, 0x00);
    EXPECT(SEND(0x22, 0xF1, 0x86), 0x62, 0xF1, 0x86, 0x01);
    EXPECT(SEND(0x11, 0x01), 0x7F, 0x11, 0x7F);
    EXPECT(SEND(0x10, 0x02), 0x50, 0x02, 0x00, 0x32, 0x01, 0xF4);
    EXPECT(SEND(0x34, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00), 0x7F, 0x34, 0x33);
}

/* Opens a 4 KiB download in P3 and sends block 1 (BLOCK_LEN bytes); asserts 74 20 0F FF and 76 01. */
static void start_download(void)
{
    reach(ST_P3);
    EXPECT(SEND(0x34, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00), 0x74, 0x20, 0x0F, 0xFF);
    uint8_t blk[2 + BLOCK_LEN];
    memset(blk, 0x5A, sizeof blk);
    blk[0] = UDSOTA_SID_TRANSFER_DATA;
    blk[1] = 0x01;
    size_t n = send_req(blk, sizeof blk);
    const uint32_t t0 = now;                       /* poll_at moves now, so the bound is fixed here */
    for (uint32_t t = t0 + 5u; n == 0 && t <= t0 + 100u; t += 5u) {
        n = poll_at(t);                            /* a job-backed answer arrives on a poll */
    }
    EXPECT(n, 0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.n_begin);
}

/* Asserts the download was aborted (one queued ota_abort, no second erase), security relocked, the session
 * default, and F1F1 = UDSOTA_DL_ABORTED with the BLOCK_LEN bytes received. */
static void expect_aborted_and_relocked(void)
{
    TEST_ASSERT_EQUAL_UINT(1, m.n_abort);
    TEST_ASSERT_EQUAL_UINT(1, m.n_begin);          /* the partial slot is kept, not re-erased */
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    EXPECT(SEND(0x22, 0xF1, 0xF1), 0x62, 0xF1, 0xF1, UDSOTA_DL_ABORTED, 0x00, 0x00, 0x00, BLOCK_LEN);
    EXPECT(SEND(0x36, 0x02, 0xAA), 0x7F, 0x36, 0x7F);
}

/* S3 (5 s after the 76) mid-download queues ota_abort, keeps the partial slot and relocks. */
static void test_s3_mid_download_aborts_and_relocks(void)
{
    start_download();
    const uint32_t t1 = now;
    poll_at(t1 + UDSOTA_S3_MS - 1u);
    TEST_ASSERT_EQUAL_UINT(0, m.n_abort);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
    poll_at(t1 + UDSOTA_S3_MS);
    expect_aborted_and_relocked();
}

/* 10 01 mid-download does the same through the same path. */
static void test_default_session_mid_download_aborts_and_relocks(void)
{
    start_download();
    EXPECT(SEND(0x10, 0x01), 0x50, 0x01, 0x00, 0x32, 0x01, 0xF4);
    expect_aborted_and_relocked();
}

/* A keyed 11 01 mid-download is allowed (the boot slot is still the running one); the restart step aborts
 * the open download and relocks before it calls hooks.reset. */
static void test_keyed_reset_mid_download_aborts_first(void)
{
    start_download();
    EXPECT(SEND(0x11, 0x01), 0x51, 0x01);
    TEST_ASSERT_EQUAL_UINT(0, m.n_abort);          /* nothing ends until the restart step runs */
    poll_at(now + 1u);
    TEST_ASSERT_EQUAL_UINT(1, m.n_reset);
    TEST_ASSERT_EQUAL_UINT(1, m.n_abort_at_reset);
    TEST_ASSERT_EQUAL_UINT8(0, m.security_at_reset);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, m.session_at_reset);
}

/* The phase is IDLE in default, EXTENDED in extended, PROGRAMMING in programming, and back to IDLE on 10 01, S3,
 * udsota_end_session and the 90 s cap; a refused 10 02 leaves it IDLE. */
static void test_phase_transitions(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    SEND(0x10, 0x03);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_EXTENDED, udsota_phase(&s));
    SEND(0x10, 0x02);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&s));
    SEND(0x10, 0x01);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));

    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0x22;
    EXPECT(SEND(0x10, 0x02), 0x7F, 0x10, 0x22);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0;

    SEND(0x10, 0x03);
    poll_at(now + UDSOTA_S3_MS);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));

    SEND(0x10, 0x02);
    udsota_end_session(&s, now + 10u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));

    SEND(0x10, 0x02);
    m.job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, UDSOTA_PENDING, test_done, 0,
                                            resp, sizeof resp, now));
    EXPECT(poll_at(now + UDSOTA_JOB_CAP_MS), 0x7F, 0x31, 0x72);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));
}

/* Runs every matrix test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_nrc_matrix);
    RUN_TEST(test_reset_needs_the_key);
    RUN_TEST(test_reset_refused_by_the_reset_rule);
    RUN_TEST(test_reset_during_job_is_busy);
    RUN_TEST(test_reset_waits_for_tx_pending);
    RUN_TEST(test_reset_after_100ms_if_tx_stuck);
    RUN_TEST(test_reset_suppressed_positive);
    RUN_TEST(test_failed_reset_leaves_server_locked_and_serving);
    RUN_TEST(test_s3_mid_download_aborts_and_relocks);
    RUN_TEST(test_default_session_mid_download_aborts_and_relocks);
    RUN_TEST(test_keyed_reset_mid_download_aborts_first);
    RUN_TEST(test_phase_transitions);
    return UNITY_END();
}
