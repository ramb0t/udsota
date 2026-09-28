#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_priv.h"
#include "udsota_mock.h"

#define RESP_MAX 64u

/* What the mock engine saw and what it answers. */
typedef struct {
    int      job_result;   /* engine.poll's answer: UDSOTA_PENDING while the fake worker is busy */
    unsigned aborts;       /* engine.abort calls */
} mock_t;

static mock_t          m;
static udsota_mock_t   g_mock;
static udsota_server_t s;
static uint8_t         resp[RESP_MAX];
static uint32_t        now;

static const char    VERSION[] = "v0.3.0-12-gabc1234";
static const char    BOARD[] = "devkit";
static const uint8_t PROTO[3] = {1, 2, 3};
static uint8_t       elf_sha[UDSOTA_SHA256_LEN];   /* 0x00..0x1F, filled in setUp */

/* Mock seed source; unused by the core. */
static bool mock_rng16(void *ctx, uint8_t out[16]) { memset(out, 0, 16); return true; }
/* Mock key source; unused by the core. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16]) { memset(out, 0, 16); return true; }
/* Mock first-block check that passes; unused by the core. */
static int mock_check_first(void *ctx, const uint8_t *f, size_t n, udsota_reason_t *r) { *r = UDSOTA_DL_OK; return 0; }
/* Mock erase that completes at once; unused by the core. */
static int mock_begin(void *ctx, uint32_t size) { return 0; }
/* Mock write that completes at once; unused by the core. */
static int mock_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return 0; }
/* Mock no-argument engine op that completes at once; unused by the core. */
static int mock_op(void *ctx) { return 0; }
/* Counts a queued abort. */
static void mock_abort(void *ctx) { m.aborts++; }
/* Reports the fake worker's state set by the test. */
static int mock_poll(void *ctx) { return m.job_result; }

/* engine.version: F189 from VERSION; 0 when out is short. */
static size_t mock_version(void *ctx, char *out, size_t max)
{
    const size_t n = strlen(VERSION);
    if (n > max) {
        return 0;
    }
    memcpy(out, VERSION, n);
    return n;
}

/* engine.running_sha: F1F3 from elf_sha; 0 when out is short. */
static size_t mock_running_sha(void *ctx, uint8_t *out, size_t max)
{
    if (max < sizeof elf_sha) {
        return 0;
    }
    memcpy(out, elf_sha, sizeof elf_sha);
    return sizeof elf_sha;
}

/* The app's DIDs behind hooks.did_read: board name F191 and API version F1B1; 0 otherwise or when short. */
static size_t app_dids(uint16_t did, uint8_t *out, size_t max)
{
    const uint8_t *src;
    size_t n;
    switch (did) {
    case 0xF191u: src = (const uint8_t *)BOARD; n = strlen(BOARD); break;
    case 0xF1B1u: src = PROTO; n = sizeof PROTO; break;
    default: return 0;
    }
    if (n > max) {
        return 0;
    }
    memcpy(out, src, n);
    return n;
}

static const udsota_engine_t k_engine = {
    .check_first = mock_check_first, .begin = mock_begin, .write = mock_write, .verify = mock_op,
    .activate = mock_op, .confirm = mock_op, .abort = mock_abort, .poll = mock_poll,
    .status = udsota_mock_status, .running_sha = mock_running_sha, .version = mock_version, .ctx = &g_mock,
};
static const udsota_security_t k_security = {.rng16 = mock_rng16, .key = mock_key};

/* Boots the server with the mock's cfg (F18C 02 00 00 00 00 01), security and hooks. */
static void boot(void)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&s, &cfg, &k_engine, &k_security, &hooks);
}

/* Fresh server at t = 60 s; the fake worker is idle with result 0 and the gate allows everything. */
void setUp(void)
{
    memset(&m, 0, sizeof m);
    udsota_mock_clear(&g_mock);
    g_mock.app_did = app_dids;
    memset(resp, 0xEE, sizeof resp);
    for (size_t i = 0; i < sizeof elf_sha; i++) {
        elf_sha[i] = (uint8_t)i;
    }
    now = 60000u;
    boot();
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends one request at the current fake time; returns the response length. */
static size_t send_req(const uint8_t *req, size_t len)
{
    memset(resp, 0xEE, sizeof resp);
    return udsota_on_request(&s, req, len, resp, sizeof resp, now);
}
#define SEND(...) send_req((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

/* Polls the server at time t; returns the response length. */
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
#define EXPECT_NRC(got, sid, nrc) EXPECT((got), 0x7F, (sid), (nrc))

/* Reads F186 and returns the session byte it reports. */
static uint8_t session_now(void)
{
    const size_t n = SEND(0x22, 0xF1, 0x86);
    TEST_ASSERT_EQUAL_UINT(4, n);
    return resp[3];
}

/* Enters `session` with a positive answer. */
static void enter(uint8_t session)
{
    EXPECT(SEND(0x10, session), 0x50, session, 0x00, 0x32, 0x01, 0xF4);
}

/* Test job completion: echoes job_arg and the job's result as 71 <arg> <result>. */
static size_t test_done(udsota_server_t *srv, int result, uint8_t *out, size_t max, uint32_t t)
{
    if (max < 3) {
        return 0;
    }
    out[0] = UDSOTA_POS(srv->job_sid);
    out[1] = (uint8_t)srv->job_arg;
    out[2] = (uint8_t)result;
    return 3;
}

/* Starts a pending 0x31 job at the current time, as a RoutineControl handler would. */
static void start_job(bool suppress_pos)
{
    m.job_result = UDSOTA_PENDING;
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, suppress_pos, UDSOTA_PENDING, test_done, 0x5A,
                                            resp, sizeof resp, now));
    TEST_ASSERT_TRUE(s.job_running);
}

/* 10 01/02/03 answer 50 ss 00 32 01 F4 and F186 follows the session. */
static void test_session_positive_responses(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x01, session_now());
    enter(0x03);
    TEST_ASSERT_EQUAL_HEX8(0x03, session_now());
    enter(0x02);
    TEST_ASSERT_EQUAL_HEX8(0x02, session_now());
    enter(0x01);
    TEST_ASSERT_EQUAL_HEX8(0x01, session_now());
}

/* 10 83 enters extended without a response (suppressPosRspMsgIndicationBit). */
static void test_session_suppressed_positive(void)
{
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x10, 0x83));
    TEST_ASSERT_EQUAL_HEX8(0x03, session_now());
}

/* Unknown session sub-functions are 0x12 and wrong lengths 0x13; neither changes the session. */
static void test_session_bad_subfunction_and_length(void)
{
    EXPECT_NRC(SEND(0x10, 0x00), 0x10, 0x12);
    EXPECT_NRC(SEND(0x10, 0x04), 0x10, 0x12);
    EXPECT_NRC(SEND(0x10, 0x7F), 0x10, 0x12);
    EXPECT_NRC(SEND(0x10), 0x10, 0x13);
    EXPECT_NRC(SEND(0x10, 0x03, 0x00), 0x10, 0x13);
    EXPECT_NRC(SEND(0x10, 0x84), 0x10, 0x12);   /* SPRMIB never hides an NRC */
    TEST_ASSERT_EQUAL_HEX8(0x01, session_now());
}

/* 10 02 is refused for each core condition (boot slot, PENDING_VERIFY, open transfer) and for a gate NRC, which
 * is passed through; then accepted. */
static void test_programming_gated_by_core_and_gate(void)
{
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0x22;
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x22);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0x88;
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x88);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0;
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA1;
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x22);
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA0;
    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x22);
    g_mock.status.running_state = UDSOTA_IMG_VALID;
    s.download_active = true;                                  /* the server's own state counts too */
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x22);
    TEST_ASSERT_EQUAL_HEX8(0x01, session_now());
    s.download_active = false;
    enter(0x02);
}

/* A gate refusing ENTER_EXTENDED refuses 10 03, but not 10 01. */
static void test_gate_refuses_extended(void)
{
    g_mock.gate_nrc[UDSOTA_OP_ENTER_EXTENDED] = 0x22;
    EXPECT_NRC(SEND(0x10, 0x03), 0x10, 0x22);
    enter(0x01);
}

/* udsota_end_session ends a non-default session at once when no job runs. */
static void test_end_session_ends_extended(void)
{
    enter(0x03);
    udsota_end_session(&s, now + 10u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
}

/* Any accepted 10 xx relocks security, the same session included. */
static void test_session_entry_relocks_security(void)
{
    enter(0x03);
    s.security = UDSOTA_SA_SEED_EXTENDED;
    enter(0x03);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    enter(0x02);
    s.security = UDSOTA_SA_SEED_PROGRAMMING;
    enter(0x01);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
}

/* 3E 00 answers 7E 00, 3E 80 is silent, other sub-functions are 0x12 and wrong lengths 0x13. */
static void test_tester_present(void)
{
    EXPECT(SEND(0x3E, 0x00), 0x7E, 0x00);
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x3E, 0x80));
    EXPECT_NRC(SEND(0x3E, 0x01), 0x3E, 0x12);
    EXPECT_NRC(SEND(0x3E), 0x3E, 0x13);
    EXPECT_NRC(SEND(0x3E, 0x00, 0x00), 0x3E, 0x13);
}

/* F189 and F1F3 come from the engine and F18C from cfg.device_id; the app's F191 and F1B1 reach hooks.did_read,
 * which gets the hooks' ctx. */
static void test_identity_dids_from_engine_cfg_and_hooks(void)
{
    size_t n = SEND(0x22, 0xF1, 0x89);
    TEST_ASSERT_EQUAL_UINT(3 + strlen(VERSION), n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){0x62, 0xF1, 0x89}), resp, 3);
    TEST_ASSERT_EQUAL_MEMORY(VERSION, &resp[3], strlen(VERSION));

    EXPECT(SEND(0x22, 0xF1, 0x8C), 0x62, 0xF1, 0x8C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    EXPECT(SEND(0x22, 0xF1, 0x91), 0x62, 0xF1, 0x91, 'd', 'e', 'v', 'k', 'i', 't');
    TEST_ASSERT_EQUAL_PTR(&g_mock, g_mock.last_ctx);
    EXPECT(SEND(0x22, 0xF1, 0xB1), 0x62, 0xF1, 0xB1, 1, 2, 3);

    n = SEND(0x22, 0xF1, 0xF3);
    TEST_ASSERT_EQUAL_UINT(3 + UDSOTA_SHA256_LEN, n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(elf_sha, &resp[3], UDSOTA_SHA256_LEN);
    TEST_ASSERT_EQUAL_UINT(2, g_mock.did_reads);
}

/* F186, F1F1 and F1F2 are answered from the server's own state and never reach hooks.did_read. */
static void test_server_owned_dids(void)
{
    EXPECT(SEND(0x22, 0xF1, 0x86), 0x62, 0xF1, 0x86, 0x01);
    s.last_dl.reason_code = UDSOTA_DL_NOT_NEWER;
    s.last_dl.bytes_received = 0x00001FFDu;
    EXPECT(SEND(0x22, 0xF1, 0xF1), 0x62, 0xF1, 0xF1, 0x06, 0x00, 0x00, 0x1F, 0xFD);
    s.counters.seq_errors = 0x0102;
    s.counters.resp_frames_dropped = 0xFFFF;
    EXPECT(SEND(0x22, 0xF1, 0xF2), 0x62, 0xF1, 0xF2, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.did_reads);
}

/* Unknown DIDs are 0x31; a request that isn't exactly one DID is 0x13. */
static void test_read_did_errors(void)
{
    EXPECT_NRC(SEND(0x22, 0xF1, 0x00), 0x22, 0x31);
    EXPECT_NRC(SEND(0x22, 0x02, 0x00), 0x22, 0x31);          /* outside the config range */
    EXPECT_NRC(SEND(0x22), 0x22, 0x13);
    EXPECT_NRC(SEND(0x22, 0xF1), 0x22, 0x13);
    EXPECT_NRC(SEND(0x22, 0xF1, 0x89, 0xF1), 0x22, 0x13);
    EXPECT_NRC(SEND(0x22, 0xF1, 0x89, 0xF1, 0x91), 0x22, 0x13);   /* two DIDs: more than UDSOTA_READ_DID_MAX */
}

/* Unsupported SIDs get 0x11, 0x2E included (not served with did_write NULL); an empty request gets nothing. */
static void test_unknown_sid(void)
{
    EXPECT_NRC(SEND(0x19, 0x02, 0xFF), 0x19, 0x11);
    EXPECT_NRC(SEND(0x14, 0xFF, 0xFF, 0xFF), 0x14, 0x11);
    EXPECT_NRC(SEND(0x2E, 0x01, 0x00, 0x00), 0x2E, 0x11);
    EXPECT_NRC(SEND(0x50, 0x01), 0x50, 0x11);                 /* a response SID sent as a request */
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, resp, 0, resp, sizeof resp, now));
    TEST_ASSERT_EQUAL_UINT(0, udsota_on_request(&s, NULL, 3, resp, sizeof resp, now));
}

/* No answer ever writes past resp_max, however small. */
static void test_never_writes_past_resp_max(void)
{
    static const uint8_t reqs[][3] = {
        {0x10, 0x03, 0}, {0x3E, 0x00, 0}, {0x22, 0xF1, 0xF3}, {0x22, 0xF1, 0xF2}, {0x19, 0x02, 0},
    };
    static const size_t lens[] = {2, 2, 3, 3, 2};
    for (size_t max = 0; max <= 8; max++) {
        for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            boot();
            memset(resp, 0xEE, sizeof resp);
            const size_t n = udsota_on_request(&s, reqs[i], lens[i], resp, max, now);
            TEST_ASSERT_TRUE(n <= max);
            TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, &resp[max], sizeof resp - max);
        }
    }
}

/* A non-default session falls back 5 s after its last answer, and the fallback relocks security. */
static void test_s3_timeout_falls_back(void)
{
    enter(0x03);
    s.security = UDSOTA_SA_SEED_EXTENDED;
    const uint32_t t0 = now;
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 4999u));
    TEST_ASSERT_EQUAL_HEX8(0x03, s.session);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 5000u));
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    TEST_ASSERT_EQUAL_UINT(0, m.aborts);                      /* nothing was open */
}

/* Every answered request restarts S3, a suppressed 3E 80 included. */
static void test_s3_restarts_on_each_answer(void)
{
    enter(0x03);
    now += 4000u;
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x3E, 0x80));
    const uint32_t t1 = now;
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t1 + 4999u));
    TEST_ASSERT_EQUAL_HEX8(0x03, s.session);
    poll_at(t1 + 5000u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
}

/* S3 stops at a First Frame and restarts only when that request is answered. */
static void test_s3_stops_at_first_frame(void)
{
    enter(0x02);
    udsota_on_rx_first_frame(&s, now + 1000u);
    poll_at(now + 60000u);
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);
    EXPECT(SEND(0x3E, 0x00), 0x7E, 0x00);
    const uint32_t t1 = now;
    poll_at(t1 + 4999u);
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);
    poll_at(t1 + 5000u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
}

/* An abandoned multi-frame request (N_Cr) counts in F1F2 and restarts S3 from then. */
static void test_rx_timeout_restarts_s3(void)
{
    enter(0x03);
    udsota_on_rx_first_frame(&s, now + 100u);
    const uint32_t t1 = now + 1100u;
    udsota_on_rx_timeout(&s, t1);
    TEST_ASSERT_EQUAL_HEX16(1, s.counters.ncr_timeouts);
    poll_at(t1 + 4999u);
    TEST_ASSERT_EQUAL_HEX8(0x03, s.session);
    poll_at(t1 + 5000u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
}

/* S3 during a download queues engine.abort, records UDSOTA_DL_ABORTED with the bytes so far, and keeps FF01's verdict. */
static void test_s3_fallback_aborts_open_download(void)
{
    enter(0x02);
    s.download_active = true;
    s.ota_open = true;
    s.dl_received = 8186u;
    s.slot_verified = true;
    poll_at(now + 5000u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_FALSE(s.download_active);
    TEST_ASSERT_FALSE(s.ota_open);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(8186u, s.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_HEX16(1, s.counters.aborts);
    TEST_ASSERT_TRUE(s.slot_verified);
}

/* 10 01 mid-download also queues the abort; an accepted 0x34 with no 0x36 yet ends without one. */
static void test_default_session_request_aborts_download(void)
{
    enter(0x02);
    s.download_active = true;
    s.ota_open = true;
    enter(0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_FALSE(s.ota_open);

    enter(0x02);
    s.download_active = true;                                  /* 0x34 accepted, no handle yet */
    enter(0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_FALSE(s.download_active);
    TEST_ASSERT_EQUAL_HEX16(2, s.counters.aborts);
}

/* A job gets its first 0x78 at 40 ms, repeats every 1.5 s, and its final answer when the worker reports. */
static void test_job_pending_cadence(void)
{
    enter(0x02);
    const uint32_t t0 = now;
    start_job(false);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 39u));
    EXPECT_NRC(poll_at(t0 + 40u), 0x31, 0x78);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 45u));
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 1539u));
    EXPECT_NRC(poll_at(t0 + 1540u), 0x31, 0x78);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 3039u));
    EXPECT_NRC(poll_at(t0 + 3040u), 0x31, 0x78);
    m.job_result = 0;
    EXPECT(poll_at(t0 + 3100u), 0x71, 0x5A, 0x00);
    TEST_ASSERT_FALSE(s.job_running);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 4600u));            /* nothing more once answered */
}

/* A job the worker finishes inside 40 ms is answered with no 0x78; a failure reaches done() as its code. */
static void test_fast_job_sends_no_pending(void)
{
    enter(0x02);
    const uint32_t t0 = now;
    start_job(false);
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 5u));
    m.job_result = 0x105;
    EXPECT(poll_at(t0 + 10u), 0x71, 0x5A, 0x05);
}

/* An op that finished synchronously is answered from the handler call itself, with no job. */
static void test_synchronous_op_answers_at_once(void)
{
    EXPECT(udsota_job_start(&s, UDSOTA_SID_ROUTINE, false, 0, test_done, 7, resp, sizeof resp, now), 0x71, 0x07, 0x00);
    TEST_ASSERT_FALSE(s.job_running);
    TEST_ASSERT_EQUAL_UINT(0, udsota_job_start(&s, UDSOTA_SID_ROUTINE, true, 0, test_done, 7, resp, sizeof resp, now));
}

/* SPRMIB drops a job's positive answer only if no 0x78 went out first. */
static void test_suppressed_job_answer(void)
{
    enter(0x02);
    uint32_t t0 = now;
    start_job(true);
    m.job_result = 0;
    TEST_ASSERT_EQUAL_UINT(0, poll_at(t0 + 10u));
    TEST_ASSERT_FALSE(s.job_running);

    t0 = now;
    start_job(true);
    EXPECT_NRC(poll_at(t0 + 40u), 0x31, 0x78);
    m.job_result = 0;
    EXPECT(poll_at(t0 + 50u), 0x71, 0x5A, 0x00);
}

/* During a job TesterPresent is answered and every other request is 0x21 without effect; S3 never fires. */
static void test_requests_during_job(void)
{
    enter(0x02);
    const uint32_t t0 = now;
    start_job(false);
    now = t0 + 20u;
    EXPECT_NRC(SEND(0x22, 0xF1, 0x89), 0x22, 0x21);
    EXPECT_NRC(SEND(0x10, 0x01), 0x10, 0x21);
    EXPECT_NRC(SEND(0x19, 0x02), 0x19, 0x21);
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.did_reads);
    EXPECT(SEND(0x3E, 0x00), 0x7E, 0x00);
    TEST_ASSERT_EQUAL_UINT(0, SEND(0x3E, 0x80));
    EXPECT_NRC(poll_at(t0 + 40u), 0x31, 0x78);
    poll_at(t0 + 30000u);                                      /* 6 x S3 with no answer: still in session */
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);
    m.job_result = 0;
    EXPECT(poll_at(t0 + 30010u), 0x71, 0x5A, 0x00);
    const uint32_t t1 = now;
    poll_at(t1 + 4999u);
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);                  /* S3 restarted at the final answer */
    poll_at(t1 + 5000u);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
}

/* At 90 s the 0x78s stop (60 were sent): 0x72, the session ends, the download aborts and 10 02 waits for the worker. */
static void test_job_cap_at_90s(void)
{
    enter(0x02);
    s.download_active = true;
    s.ota_open = true;
    const uint32_t t0 = now;
    start_job(false);
    unsigned pendings = 0;
    for (uint32_t t = 10u; t < UDSOTA_JOB_CAP_MS; t += 10u) {
        const size_t n = poll_at(t0 + t);
        if (n != 0) {
            EXPECT_NRC(n, 0x31, 0x78);
            pendings++;
        }
    }
    TEST_ASSERT_EQUAL_UINT(60, pendings);
    TEST_ASSERT_EQUAL_HEX8(0x02, s.session);
    EXPECT_NRC(poll_at(t0 + UDSOTA_JOB_CAP_MS), 0x31, 0x72);
    TEST_ASSERT_FALSE(s.job_running);
    TEST_ASSERT_EQUAL_HEX8(0x01, s.session);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_WORKER_TIMEOUT, s.last_dl.reason_code);
    TEST_ASSERT_EQUAL_HEX16(1, s.counters.resp_pending_caps);
    TEST_ASSERT_TRUE(s.worker_orphan);

    poll_at(now + 10u);
    EXPECT_NRC(SEND(0x10, 0x02), 0x10, 0x22);                  /* the stuck job still owns the worker */
    enter(0x03);                                               /* extended needs no worker */
    m.job_result = 0;
    poll_at(now + 10u);
    TEST_ASSERT_FALSE(s.worker_orphan);
    enter(0x02);
}

/* The poll deadline: none when idle in default, S3 remainder capped at 100 ms, 5 ms during a job. */
static void test_ms_to_deadline(void)
{
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, udsota_ms_to_deadline(&s, now));
    enter(0x03);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_IDLE_POLL_MS, udsota_ms_to_deadline(&s, now));
    TEST_ASSERT_EQUAL_UINT32(30u, udsota_ms_to_deadline(&s, now + 4970u));
    TEST_ASSERT_EQUAL_UINT32(0u, udsota_ms_to_deadline(&s, now + 6000u));
    start_job(false);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_JOB_POLL_MS, udsota_ms_to_deadline(&s, now));
}

/* Runs every udsota_server core test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_session_positive_responses);
    RUN_TEST(test_session_suppressed_positive);
    RUN_TEST(test_session_bad_subfunction_and_length);
    RUN_TEST(test_programming_gated_by_core_and_gate);
    RUN_TEST(test_gate_refuses_extended);
    RUN_TEST(test_end_session_ends_extended);
    RUN_TEST(test_session_entry_relocks_security);
    RUN_TEST(test_tester_present);
    RUN_TEST(test_identity_dids_from_engine_cfg_and_hooks);
    RUN_TEST(test_server_owned_dids);
    RUN_TEST(test_read_did_errors);
    RUN_TEST(test_unknown_sid);
    RUN_TEST(test_never_writes_past_resp_max);
    RUN_TEST(test_s3_timeout_falls_back);
    RUN_TEST(test_s3_restarts_on_each_answer);
    RUN_TEST(test_s3_stops_at_first_frame);
    RUN_TEST(test_rx_timeout_restarts_s3);
    RUN_TEST(test_s3_fallback_aborts_open_download);
    RUN_TEST(test_default_session_request_aborts_download);
    RUN_TEST(test_job_pending_cadence);
    RUN_TEST(test_fast_job_sends_no_pending);
    RUN_TEST(test_synchronous_op_answers_at_once);
    RUN_TEST(test_suppressed_job_answer);
    RUN_TEST(test_requests_during_job);
    RUN_TEST(test_job_cap_at_90s);
    RUN_TEST(test_ms_to_deadline);
    return UNITY_END();
}
