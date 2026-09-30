/* Host tests for hooks.request, the app's route for a SID the core doesn't serve: which requests reach it (never a
 * core SID, the updater's while it runs, a response SID, a functional request or one during a job), the framing of
 * its answers, its NRCs and faults, UDSOTA_NO_ANSWER, and its pending jobs, which share routine_poll, the 0x78
 * cadence, the 90 s cap and the one-app-job rule with the app's routines. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

/* request comes after routine_ex, the last hook before it, so the change is not breaking. fuzz_udsota.c pins the
 * whole order. */
_Static_assert(offsetof(udsota_hooks_t, request) == offsetof(udsota_hooks_t, routine_ex) + sizeof(void (*)(void)) &&
               offsetof(udsota_hooks_t, request) + sizeof(void (*)(void)) == sizeof(udsota_hooks_t),
               "udsota_hooks_t: request must follow routine_ex, and be the last member");
#if UINTPTR_MAX == UINT64_MAX
_Static_assert(offsetof(udsota_hooks_t, routine_ex) == 128u,
               "udsota_hooks_t: a hook before routine_ex moved the earlier layout (128 on a 64-bit host)");
#endif

#define T0        60000u    /* past the 10 s post-boot 0x27 delay */
#define SID       0xBAu     /* a SID the core doesn't serve: the app's */
#define POS10(ss) 0x50, (ss), 0x00, 0x32, 0x01, 0xF4

/* What request, routine_ex and routine_poll saw, and how they answer. */
typedef struct {
    unsigned        calls;                      /* request */
    uint8_t         req[64];                    /* its req, whole */
    size_t          len, out_max;
    const uint8_t  *out;                        /* where its out pointed */
    int             rc;                         /* what request returns */
    size_t          out_len;                    /* the *out_len it sets (it writes C0 C1 ... up to out_max) */
    udsota_access_t access;
    void           *ctx;
    unsigned        rt_calls;                   /* routine_ex */
    int             rt_rc;
    unsigned        poll_calls;                 /* routine_poll */
    bool            poll_hold;                  /* routine_poll keeps returning UDSOTA_PENDING */
    int             poll_rc;                    /* what routine_poll returns once released */
    size_t          poll_out_len;               /* the *out_len it sets (it writes D0 D1 ... up to out_max) */
    size_t          poll_out_max;
} rq_mock_t;

static rq_mock_t       x;
static bool            s_hold;                  /* engine.poll keeps a queued op pending */
static udsota_mock_t   g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[64];
static size_t          rlen;
static uint32_t        now;

/* engine.check_first: every first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin and write: done at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return 0; }
/* engine.verify, activate: done at once; engine.confirm: queued, so F002 runs as a job. */
static int eng_op(void *ctx) { return 0; }
static int eng_queued(void *ctx) { return UDSOTA_PENDING; }
/* engine.abort: fire-and-forget. */
static void eng_abort(void *ctx) {}
/* engine.poll: UDSOTA_PENDING while held, else 0. */
static int eng_poll(void *ctx) { return s_hold ? UDSOTA_PENDING : 0; }

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_op,
    .activate = eng_op, .confirm = eng_queued, .abort = eng_abort, .poll = eng_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};

/* hooks.request: records the call; writes C0 C1 ... into out (up to out_max), sets out_len and returns rc. */
static int hook_request(void *ctx, const uint8_t *req, size_t len, uint8_t *out, size_t out_max, size_t *out_len,
                        udsota_access_t access)
{
    x.calls++;
    x.len = len;
    memcpy(x.req, req, len < sizeof x.req ? len : sizeof x.req);
    x.out = out;
    x.out_max = out_max;
    x.access = access;
    x.ctx = ctx;
    for (size_t i = 0; i < out_max && i < x.out_len; i++) {
        out[i] = (uint8_t)(0xC0u + i);
    }
    *out_len = x.out_len;
    return x.rc;
}

/* hooks.routine_ex: counts; returns rt_rc with no out record. */
static int hook_routine_ex(void *ctx, uint8_t sub, uint16_t rid, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    x.rt_calls++;
    *out_len = 0u;
    return x.rt_rc;
}

/* hooks.routine_poll: pending while poll_hold, then D0 D1 ... (up to out_max), poll_out_len and poll_rc. */
static int hook_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    x.poll_calls++;
    x.poll_out_max = out_max;
    if (x.poll_hold) {
        return UDSOTA_PENDING;
    }
    for (size_t i = 0; i < out_max && i < x.poll_out_len; i++) {
        out[i] = (uint8_t)(0xD0u + i);
    }
    *out_len = x.poll_out_len;
    return x.poll_rc;
}

/* A server with the mock's hooks (gate, phase, did_read, reset) plus request, routine_ex and routine_poll, with the
 * updater when engine is set, and with security when secured. */
static void boot(bool engine, bool secured)
{
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.request = hook_request;
    g_hooks.routine_ex = hook_routine_ex;
    g_hooks.routine_poll = hook_routine_poll;
    udsota_init(&s, &g_cfg, engine ? &ENGINE : NULL, secured ? udsota_mock_security() : NULL, &g_hooks);
    now = T0;
}

/* Unity hook: default config, everything allowed, no job, request answering positive with 2 bytes. */
void setUp(void)
{
    memset(&x, 0, sizeof x);
    udsota_mock_clear(&g_mock);
    g_cfg = udsota_mock_cfg();
    s_hold = false;
    x.out_len = 2u;
    x.poll_out_len = 2u;
    boot(true, false);
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* One physical request into resp[0..max); the answer's length lands in rlen. */
static void req_max(const uint8_t *r, size_t n, size_t max) { rlen = udsota_on_request(&s, r, n, resp, max, now); }
/* One functional request. */
static void req_func(const uint8_t *r, size_t n)
{
    rlen = udsota_on_functional_request(&s, r, n, resp, sizeof resp, now);
}
/* One poll at now + dt. */
static void poll_after(uint32_t dt)
{
    now += dt;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
}

#define REQ(...)  req_max((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}), sizeof resp)
#define FUNC(...) req_func((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
#define EXPECT(...) do {                                                        \
        const uint8_t want_[] = {__VA_ARGS__};                                  \
        TEST_ASSERT_EQUAL_size_t(sizeof want_, rlen);                           \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want_, resp, sizeof want_);                \
    } while (0)
#define NRC(sid, n) EXPECT(0x7F, (sid), (n))

/* 27 <level> then the mock's key: the level unlocks. */
static void unlock(uint8_t level)
{
    REQ(0x27, level);
    TEST_ASSERT_EQUAL_size_t(2u + UDSOTA_SEED_LEN, rlen);
    uint8_t key[2u + UDSOTA_KEY_LEN] = {0x27, (uint8_t)(level + 1u)};
    udsota_mock_key_for(&resp[2], level, &key[2]);
    req_max(key, sizeof key, sizeof resp);
    EXPECT(0x67, (uint8_t)(level + 1u));
}

/* ---- Which requests reach it ---- */

/* A SID the core doesn't serve reaches request whole, SID and all, with the hooks' ctx; the core frames the response
 * SID at resp[0] and out is the room after it. */
static void test_request_gets_the_whole_request_and_frames_its_answer(void)
{
    REQ(SID, 0x01, 0xA1, 0xA2);
    EXPECT(SID + 0x40, 0xC0, 0xC1);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
    TEST_ASSERT_EQUAL_size_t(4, x.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){SID, 0x01, 0xA1, 0xA2}), x.req, 4);
    TEST_ASSERT_EQUAL_PTR(&resp[1], x.out);
    TEST_ASSERT_EQUAL_size_t(sizeof resp - 1u, x.out_max);
    TEST_ASSERT_EQUAL_PTR(&g_mock, x.ctx);
    REQ(0x2F);                                                    /* len 1: the length is the app's to judge */
    EXPECT(0x6F, 0xC0, 0xC1);
    TEST_ASSERT_EQUAL_size_t(1, x.len);
    TEST_ASSERT_FALSE(s.job_running);
}

/* Every SID the core serves stays the core's, its hook NULL or not (27 without security, 28, 85, 2E, 19 and 14
 * without theirs answer 0x11 as before), and with the updater so do 34, 36 and 37: request is never called. */
static void test_request_never_gets_a_core_or_updater_sid(void)
{
    static const uint8_t sids[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x28, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E, 0x85};
    for (size_t i = 0; i < sizeof sids; i++) {
        req_max((const uint8_t[]){sids[i], 0x01, 0x00, 0x00}, 4, sizeof resp);
        TEST_ASSERT_NOT_EQUAL(0, rlen);
    }
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
    REQ(0x28, 0x00, 0x01);
    NRC(0x28, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40);          /* the updater's: 0x7F in the default session */
    NRC(0x34, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
}

/* Without the updater its SIDs are the app's: 34, 36 and 37 reach request, as its DIDs and RIDs reach did_read and
 * routine; 10 02 still answers 0x12. */
static void test_request_gets_34_36_37_without_the_updater(void)
{
    boot(false, false);
    REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40);
    EXPECT(0x74, 0xC0, 0xC1);
    TEST_ASSERT_EQUAL_size_t(11, x.len);
    REQ(0x36, 0x01, 0xE9);
    EXPECT(0x76, 0xC0, 0xC1);
    REQ(0x37);
    EXPECT(0x77, 0xC0, 0xC1);
    TEST_ASSERT_EQUAL_UINT(3, x.calls);
    REQ(0x10, 0x02);
    NRC(0x10, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(3, x.calls);
}

/* Every one of the 256 first bytes: a response SID (40-7F, C0-FF) answers 0x11 without a call, 7F included; every
 * other SID the core and the updater leave alone reaches request once, and its answer is framed with SID + 0x40. */
static void test_response_sids_are_11_without_a_call(void)
{
    static const uint8_t core[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x28, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E, 0x85};
    char msg[32];
    for (unsigned sid = 0; sid < 256u; sid++) {
        if (memchr(core, (int)sid, sizeof core) != NULL) {
            continue;
        }
        snprintf(msg, sizeof msg, "SID %02X", sid);
        const unsigned before = x.calls;
        req_max((const uint8_t[]){(uint8_t)sid, 0x01}, 2, sizeof resp);
        if ((sid & 0x40u) != 0u) {
            TEST_ASSERT_EQUAL_size_t_MESSAGE(3, rlen, msg);
            TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(((const uint8_t[]){0x7F, (uint8_t)sid, 0x11}), resp, 3, msg);
            TEST_ASSERT_EQUAL_UINT_MESSAGE(before, x.calls, msg);
        } else {
            TEST_ASSERT_EQUAL_size_t_MESSAGE(3, rlen, msg);
            TEST_ASSERT_EQUAL_HEX8_MESSAGE(sid + 0x40u, resp[0], msg);
            TEST_ASSERT_EQUAL_UINT_MESSAGE(before + 1u, x.calls, msg);
        }
    }
}

/* With request NULL an unknown SID answers 0x11, as before, and no request answers into a buffer with no room for
 * the response SID; with room for it alone the hook is asked with out_max 0, and an NRC that doesn't fit is dropped. */
static void test_null_hook_and_tiny_buffers(void)
{
    g_hooks.request = NULL;
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);

    boot(true, false);
    req_max((const uint8_t[]){SID, 0x01}, 2, 0);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
    x.out_len = 0u;
    req_max((const uint8_t[]){SID, 0x01}, 2, 1);
    EXPECT(SID + 0x40);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
    TEST_ASSERT_EQUAL_size_t(0, x.out_max);
    x.rc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    req_max((const uint8_t[]){SID, 0x01}, 2, 2);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT(2, x.calls);
}

/* The session's access state reaches the hook: session, unlocked level and epoch. */
static void test_request_gets_the_access_state(void)
{
    boot(true, true);
    REQ(SID);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, x.access.session);
    TEST_ASSERT_EQUAL_UINT8(0, x.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(s.session_epoch, x.access.epoch);
    REQ(0x10, 0x03);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    REQ(SID);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, x.access.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, x.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(s.session_epoch, x.access.epoch);
    const uint32_t epoch = s.session_epoch;
    REQ(0x10, 0x03);                                              /* a repeat relocks and moves the epoch */
    REQ(SID);
    TEST_ASSERT_EQUAL_UINT8(0, x.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(epoch + 1u, x.access.epoch);
}

/* A functional request never reaches request, in any session, and gets no answer, a SID the hook serves included. */
static void test_functional_request_is_silent(void)
{
    FUNC(SID, 0x01);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    REQ(0x10, 0x03);
    FUNC(SID, 0x01);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    FUNC(0x2F, 0x02, 0x00, 0x03);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    FUNC(0x50, 0x01);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
    REQ(SID, 0x01);                                               /* the same request physically: answered */
    EXPECT(SID + 0x40, 0xC0, 0xC1);
}

/* ---- Its answers ---- */

/* 0 with *out_len 0 answers the response SID alone; *out_len equal to out_max fills resp, and one past it is a hook
 * fault, 0x10. */
static void test_out_len_bounds(void)
{
    x.out_len = 0u;
    REQ(SID);
    EXPECT(SID + 0x40);
    x.out_len = sizeof resp - 1u;
    REQ(SID);
    TEST_ASSERT_EQUAL_size_t(sizeof resp, rlen);
    TEST_ASSERT_EQUAL_HEX8(SID + 0x40, resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0xC0 + sizeof resp - 2u, resp[sizeof resp - 1u]);
    x.out_len = sizeof resp;
    REQ(SID);
    NRC(SID, UDSOTA_NRC_GENERAL_REJECT);
}

/* Every NRC the hook returns is sent as given, with SPRMIB set too; a return that is neither 0, an NRC,
 * UDSOTA_NO_ANSWER nor UDSOTA_PENDING is 0x10. */
static void test_nrcs_pass_through_and_bad_returns_are_10(void)
{
    static const uint8_t nrcs[] = {0x11, 0x12, 0x13, 0x22, 0x31, 0x33, 0x7F, 0x93};
    for (size_t i = 0; i < sizeof nrcs; i++) {
        x.rc = nrcs[i];
        REQ(SID, 0x01);
        NRC(SID, nrcs[i]);
        REQ(SID, 0x81);                                           /* SPRMIB never drops an NRC */
        NRC(SID, nrcs[i]);
    }
    static const int bad[] = {0x100, -1, UDSOTA_PENDING - 2};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        x.rc = bad[i];
        REQ(SID, 0x01);
        NRC(SID, UDSOTA_NRC_GENERAL_REJECT);
    }
    TEST_ASSERT_FALSE(s.job_running);
}

/* UDSOTA_NO_ANSWER sends nothing and changes nothing else: S3 restarts as for any answered request. */
static void test_no_answer_sends_nothing(void)
{
    REQ(0x10, 0x03);
    x.rc = UDSOTA_NO_ANSWER;
    now += 4000u;
    REQ(SID, 0x81);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
    TEST_ASSERT_FALSE(s.job_running);
    poll_after(4000u);                                            /* 8 s after 10 03, 4 s after the request */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s.session);
    poll_after(1000u);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
}

/* UDSOTA_NO_ANSWER is request's alone: from routine_ex, and from routine_poll finishing a routine or a request, it
 * is a hook fault, 0x10. */
static void test_no_answer_elsewhere_is_10(void)
{
    x.rt_rc = UDSOTA_NO_ANSWER;
    REQ(0x31, 0x81, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    x.rt_rc = UDSOTA_PENDING;
    x.poll_rc = UDSOTA_NO_ANSWER;
    REQ(0x31, 0x01, 0x12, 0x34);
    poll_after(5u);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    x.rc = UDSOTA_PENDING;
    REQ(SID, 0x81);
    poll_after(5u);
    NRC(SID, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_FALSE(s.job_running);
}

/* ---- Pending requests ---- */

/* UDSOTA_PENDING is an app job: nothing at once, 0x78 at 40 ms, 0x21 to anything but 3E without calling request or
 * routine_ex, then routine_poll's record after the response SID the core frames, with out the room after it. */
static void test_pending_request_is_an_app_job(void)
{
    x.rc = UDSOTA_PENDING;
    x.poll_hold = true;
    REQ(SID, 0x01, 0xA1);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_TRUE(s.job_running && s.job_app);
    poll_after(39u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    poll_after(1u);
    NRC(SID, UDSOTA_NRC_RESPONSE_PENDING);
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_BUSY_REPEAT);
    REQ(0x2F, 0x02, 0x00, 0x03);
    NRC(0x2F, UDSOTA_NRC_BUSY_REPEAT);
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_BUSY_REPEAT);
    REQ(0x3E, 0x00);
    EXPECT(0x7E, 0x00);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
    TEST_ASSERT_EQUAL_UINT(0, x.rt_calls);
    poll_after(1500u);
    NRC(SID, UDSOTA_NRC_RESPONSE_PENDING);
    x.poll_hold = false;
    x.poll_out_len = 3u;
    poll_after(5u);
    EXPECT(SID + 0x40, 0xD0, 0xD1, 0xD2);
    TEST_ASSERT_EQUAL_size_t(sizeof resp - 1u, x.poll_out_max);
    TEST_ASSERT_FALSE(s.job_running);
    REQ(SID);                                                     /* free again */
    TEST_ASSERT_EQUAL_UINT(2, x.calls);
}

/* A pending request's final answer is always sent, even before any 0x78 and with SPRMIB set, and may be the response
 * SID alone; routine_poll's NRC is sent, and its *out_len past the room is 0x10. Without routine_poll a pending request
 * ends in 0x10 at the first poll. */
static void test_pending_request_final_answers(void)
{
    x.rc = UDSOTA_PENDING;
    REQ(SID, 0x81);
    x.poll_out_len = 0u;
    poll_after(5u);
    EXPECT(SID + 0x40);
    REQ(SID, 0x01);
    x.poll_rc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    poll_after(5u);
    NRC(SID, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    REQ(SID, 0x01);
    x.poll_rc = 0;
    x.poll_out_len = sizeof resp;
    poll_after(5u);
    NRC(SID, UDSOTA_NRC_GENERAL_REJECT);

    g_hooks.routine_poll = NULL;
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
    REQ(SID, 0x01);
    TEST_ASSERT_TRUE(s.job_running);
    poll_after(5u);
    NRC(SID, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_FALSE(s.job_running);
}

/* A pending request still running at 90 s answers 0x10, as an app routine does, ends the session and is an app
 * orphan: until routine_poll finishes it, request and a 31 on an app RID answer 0x22 without a call, 10 02 and 11 01
 * 0x22 too, while a response SID is still 0x11. Then request is asked again. */
static void test_pending_request_cap_and_orphan(void)
{
    g_hooks.gate = NULL;
    udsota_init(&s, &g_cfg, &ENGINE, udsota_mock_security(), &g_hooks);
    REQ(0x10, 0x03);
    x.rc = UDSOTA_PENDING;
    x.poll_hold = true;
    REQ(SID, 0x01);
    poll_after(UDSOTA_JOB_CAP_MS - 1u);
    NRC(SID, UDSOTA_NRC_RESPONSE_PENDING);
    poll_after(1u);
    NRC(SID, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_TRUE(s.app_orphan);
    TEST_ASSERT_FALSE(s.job_running);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.resp_pending_caps);
    x.rc = 0;
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    REQ(0x10, 0x02);
    NRC(0x10, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    REQ(0x7F, 0x01);
    NRC(0x7F, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
    TEST_ASSERT_EQUAL_UINT(0, x.rt_calls);
    x.poll_hold = false;
    poll_after(5u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);                            /* the orphan's own answer is never sent */
    TEST_ASSERT_FALSE(s.app_orphan);
    REQ(SID, 0x01);
    EXPECT(SID + 0x40, 0xC0, 0xC1);
    REQ(0x10, 0x02);
    EXPECT(POS10(UDSOTA_SESSION_PROGRAMMING));
}

/* One app job at a time: a pending routine answers a request 0x21 without a call, and its orphan 0x22; a pending
 * request answers a 31 0x21 the same way, and routine_poll's record for each is framed as its own. */
static void test_one_app_job_for_routines_and_requests(void)
{
    x.rt_rc = UDSOTA_PENDING;
    x.poll_hold = true;
    REQ(0x31, 0x03, 0x12, 0x34);
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_BUSY_REPEAT);
    poll_after(UDSOTA_JOB_CAP_MS);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
    x.poll_hold = false;
    poll_after(5u);
    TEST_ASSERT_FALSE(s.app_orphan);

    x.rc = UDSOTA_PENDING;
    REQ(SID, 0x01);
    REQ(0x31, 0x03, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_BUSY_REPEAT);
    TEST_ASSERT_EQUAL_UINT(1, x.rt_calls);
    poll_after(5u);
    EXPECT(SID + 0x40, 0xD0, 0xD1);
    x.rc = 0;
    REQ(0x31, 0x03, 0x12, 0x34);                                  /* the routine's pending answer: 71 <sub> <rid> */
    poll_after(5u);
    EXPECT(0x71, 0x03, 0x12, 0x34, 0xD0, 0xD1);
    TEST_ASSERT_EQUAL_size_t(sizeof resp - 4u, x.poll_out_max);
}

/* While the updater's own job runs, a request answers 0x21 before dispatch, and request is not called. */
static void test_never_during_the_updaters_job(void)
{
    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;      /* F002 runs engine.confirm, which queues */
    s_hold = true;
    REQ(0x10, 0x03);
    REQ(0x31, 0x01, 0xF0, 0x02);
    TEST_ASSERT_TRUE(s.job_running && !s.job_app);
    REQ(SID, 0x01);
    NRC(SID, UDSOTA_NRC_BUSY_REPEAT);
    TEST_ASSERT_EQUAL_UINT(0, x.calls);
    s_hold = false;
    poll_after(5u);
    TEST_ASSERT_EQUAL_HEX8(0x71, resp[0]);                        /* F002's own answer */
    REQ(SID, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, x.calls);
}

/* Runs every request test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_request_gets_the_whole_request_and_frames_its_answer);
    RUN_TEST(test_request_never_gets_a_core_or_updater_sid);
    RUN_TEST(test_request_gets_34_36_37_without_the_updater);
    RUN_TEST(test_response_sids_are_11_without_a_call);
    RUN_TEST(test_null_hook_and_tiny_buffers);
    RUN_TEST(test_request_gets_the_access_state);
    RUN_TEST(test_functional_request_is_silent);
    RUN_TEST(test_out_len_bounds);
    RUN_TEST(test_nrcs_pass_through_and_bad_returns_are_10);
    RUN_TEST(test_no_answer_sends_nothing);
    RUN_TEST(test_no_answer_elsewhere_is_10);
    RUN_TEST(test_pending_request_is_an_app_job);
    RUN_TEST(test_pending_request_final_answers);
    RUN_TEST(test_pending_request_cap_and_orphan);
    RUN_TEST(test_one_app_job_for_routines_and_requests);
    RUN_TEST(test_never_during_the_updaters_job);
    return UNITY_END();
}
