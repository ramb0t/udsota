/* Host tests for hooks.did_read_ex and hooks.routine_ex: the answers and faults of each, their precedence over did_read
 * and routine, functional suppression, routine_ex's sub-functions, sessions, SPRMIB and pending jobs, the updater's
 * RIDs answering as without the hook, the 90 s cap's 0x10 for an app routine and 0x72 for the updater's job, and 10 02
 * refused (0x12) with no service registered. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

/* The two hooks come after 0.10.0's last, so the change is not breaking. fuzz_udsota.c pins the whole order. */
_Static_assert(offsetof(udsota_hooks_t, did_read_ex) == offsetof(udsota_hooks_t, dtc_clear) + sizeof(void (*)(void)) &&
               offsetof(udsota_hooks_t, routine_ex) == offsetof(udsota_hooks_t, did_read_ex) + sizeof(void (*)(void)),
               "udsota_hooks_t: did_read_ex and routine_ex must follow dtc_clear, 0.10.0's last hook");
#if UINTPTR_MAX == UINT64_MAX
_Static_assert(offsetof(udsota_hooks_t, dtc_clear) == 112u,
               "udsota_hooks_t: a hook before dtc_clear moved 0.10.0's layout (112 on a 64-bit host)");
#endif

#define T0        60000u    /* past the 10 s post-boot 0x27 delay */
#define APP_DID   0x0300u   /* an app DID */
#define APP_RID   0x1234u   /* an app RID */
#define POS10(ss) 0x50, (ss), 0x00, 0x32, 0x01, 0xF4

/* What the _ex hooks saw, and how they answer. */
typedef struct {
    unsigned        did_calls, did_old_calls;   /* did_read_ex, did_read */
    uint16_t        did;
    size_t          did_max;
    uint8_t         did_nrc;                    /* non-zero: did_read_ex answers it */
    size_t          did_len;                    /* the *len it sets with 0 (it writes AA BB CC ... up to max) */
    unsigned        rt_calls, rt_old_calls;     /* routine_ex, routine */
    uint8_t         rt_sub;
    uint16_t        rt_rid;
    size_t          rt_in_len, rt_out_max;
    int             rt_rc;                      /* what routine_ex returns */
    size_t          rt_out_len;                 /* the *out_len it sets (it writes 5A <sub> ...) */
    bool            poll_hold;                  /* routine_poll keeps returning UDSOTA_PENDING */
    unsigned        poll_calls;
    udsota_access_t access;                     /* the last access state an _ex hook got */
    void           *ctx;                        /* the last ctx an _ex hook got */
} ex_mock_t;

static ex_mock_t       x;
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

/* hooks.did_read_ex: records the call; answers did_nrc, or writes AA BB CC ... into buf (up to max) and sets did_len. */
static uint8_t hook_did_ex(void *ctx, uint16_t did, uint8_t *buf, size_t max, size_t *len, udsota_access_t access)
{
    x.did_calls++;
    x.did = did;
    x.did_max = max;
    x.access = access;
    x.ctx = ctx;
    if (x.did_nrc != 0u) {
        return x.did_nrc;
    }
    for (size_t i = 0; i < max && i < x.did_len; i++) {
        buf[i] = (uint8_t)(0xAAu + i);
    }
    *len = x.did_len;
    return 0u;
}

/* hooks.did_read: must never run while did_read_ex is set; counts. */
static size_t hook_did_old(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    x.did_old_calls++;
    return 0u;
}

/* hooks.routine_ex: records the call; returns rt_rc, having written 5A <sub> into out and set rt_out_len. */
static int hook_routine_ex(void *ctx, uint8_t sub, uint16_t rid, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    x.rt_calls++;
    x.rt_sub = sub;
    x.rt_rid = rid;
    x.rt_in_len = in_len;
    x.rt_out_max = out_max;
    x.access = access;
    x.ctx = ctx;
    if (out_max >= 2u) {
        out[0] = 0x5A;
        out[1] = sub;
    }
    *out_len = x.rt_out_len;
    return x.rt_rc;
}

/* hooks.routine: must never run while routine_ex is set; answers 71 01 <rid> 0E. */
static int hook_routine_old(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    x.rt_old_calls++;
    out[0] = 0x0E;
    *out_len = 1u;
    return 0;
}

/* hooks.routine_poll: pending while poll_hold, then 5A 77. */
static int hook_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    x.poll_calls++;
    if (x.poll_hold) {
        return UDSOTA_PENDING;
    }
    out[0] = 0x5A;
    out[1] = 0x77;
    *out_len = 2u;
    return 0;
}

/* A server with the mock's hooks (did_read among them) plus both _ex hooks, routine and routine_poll, with the
 * updater when engine is set, and with security when secured. */
static void boot(bool engine, bool secured)
{
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.did_read = hook_did_old;
    g_hooks.did_read_ex = hook_did_ex;
    g_hooks.routine = hook_routine_old;
    g_hooks.routine_ex = hook_routine_ex;
    g_hooks.routine_poll = hook_routine_poll;
    udsota_init(&s, &g_cfg, engine ? &ENGINE : NULL, secured ? udsota_mock_security() : NULL, &g_hooks);
    now = T0;
}

/* Unity hook: default config, everything allowed, no job, hooks answering positive with 3 bytes. */
void setUp(void)
{
    memset(&x, 0, sizeof x);
    udsota_mock_clear(&g_mock);
    g_cfg = udsota_mock_cfg();
    s_hold = false;
    x.did_len = 3u;
    x.rt_out_len = 2u;
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

/* ---- did_read_ex ---- */

/* A DID the core doesn't serve goes to did_read_ex with the room after 62 <did>, the hooks' ctx and the session's
 * access; 0 with *len answers 62 <did> and those bytes. did_read is never asked. */
static void test_did_read_ex_positive(void)
{
    boot(true, true);
    REQ(0x10, 0x03);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    REQ(0x22, 0x03, 0x00);
    EXPECT(0x62, 0x03, 0x00, 0xAA, 0xAB, 0xAC);
    TEST_ASSERT_EQUAL_UINT(1, x.did_calls);
    TEST_ASSERT_EQUAL_HEX16(APP_DID, x.did);
    TEST_ASSERT_EQUAL_size_t(sizeof resp - 3u, x.did_max);
    TEST_ASSERT_EQUAL_PTR(&g_mock, x.ctx);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, x.access.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, x.access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(s.session_epoch, x.access.epoch);
    x.did_len = sizeof resp - 3u;                                 /* exactly the room */
    REQ(0x22, 0x03, 0x00);
    TEST_ASSERT_EQUAL_size_t(sizeof resp, rlen);
    TEST_ASSERT_EQUAL_UINT(0, x.did_old_calls);
}

/* Every NRC the hook returns is sent as given: 0x31, 0x33, 0x7F, 0x22, 0x14 and one only an app sends. */
static void test_did_read_ex_nrcs_pass_through(void)
{
    static const uint8_t nrcs[] = {0x31, 0x33, 0x7F, 0x22, 0x14, 0x93};
    for (size_t i = 0; i < sizeof nrcs; i++) {
        x.did_nrc = nrcs[i];
        REQ(0x22, 0x03, 0x00);
        NRC(0x22, nrcs[i]);
    }
    TEST_ASSERT_EQUAL_UINT(sizeof nrcs, x.did_calls);
}

/* A *len over max, or 0 with *len 0, is a hook fault: 0x10. */
static void test_did_read_ex_faults_are_10(void)
{
    x.did_len = sizeof resp - 2u;                                 /* one byte past the room */
    REQ(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_GENERAL_REJECT);
    x.did_len = 0u;
    REQ(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_GENERAL_REJECT);
    x.did_len = 1u;
    REQ(0x22, 0x03, 0x00);
    EXPECT(0x62, 0x03, 0x00, 0xAA);
}

/* did_read_ex takes the DIDs did_read took: never the core's own (F186, F18C, F1F2) nor the updater's while it
 * serves them (F1F1, and F1F0 with engine.status), but F189 and F1F3 with their sources NULL, and every updater DID
 * without the updater. Length and room are the core's first, as before. did_read is never called. */
static void test_did_read_ex_takes_did_reads_place(void)
{
    REQ(0x22, 0xF1, 0x86);
    EXPECT(0x62, 0xF1, 0x86, UDSOTA_SESSION_DEFAULT);
    REQ(0x22, 0xF1, 0x8C);
    EXPECT(0x62, 0xF1, 0x8C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
    REQ(0x22, 0xF1, 0xF2);
    TEST_ASSERT_EQUAL_size_t(3u + UDSOTA_COUNTERS_LEN, rlen);
    REQ(0x22, 0xF1, 0xF1);
    TEST_ASSERT_EQUAL_size_t(3u + UDSOTA_RESULT_LEN, rlen);
    REQ(0x22, 0xF1, 0xF0);
    TEST_ASSERT_EQUAL_size_t(3u + UDSOTA_STATUS_LEN, rlen);
    TEST_ASSERT_EQUAL_UINT(0, x.did_calls);
    REQ(0x22, 0xF1, 0x89);                                        /* engine.version NULL: passed to the app */
    EXPECT(0x62, 0xF1, 0x89, 0xAA, 0xAB, 0xAC);
    TEST_ASSERT_EQUAL_UINT(1, x.did_calls);

    REQ(0x22, 0x03);                                              /* the core's length and room come first */
    NRC(0x22, UDSOTA_NRC_INCORRECT_LENGTH);
    req_max((const uint8_t[]){0x22, 0x03, 0x00}, 3, 3);
    NRC(0x22, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    TEST_ASSERT_EQUAL_UINT(1, x.did_calls);

    boot(false, false);                                           /* no updater: F1F1 is the app's too */
    REQ(0x22, 0xF1, 0xF1);
    EXPECT(0x62, 0xF1, 0xF1, 0xAA, 0xAB, 0xAC);
    TEST_ASSERT_EQUAL_UINT(2, x.did_calls);
    TEST_ASSERT_EQUAL_UINT(0, x.did_old_calls);

    g_hooks.did_read_ex = NULL;                                   /* without it, did_read as before */
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
    REQ(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    TEST_ASSERT_EQUAL_UINT(1, x.did_old_calls);
}

/* A functional 22 drops 0x31 and 0x7F, as for any functional request, and sends 0x33, 0x22 and a positive answer. */
static void test_did_read_ex_functional(void)
{
    x.did_nrc = UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    FUNC(0x22, 0x03, 0x00);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    x.did_nrc = UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    FUNC(0x22, 0x03, 0x00);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    x.did_nrc = UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    FUNC(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    x.did_nrc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    FUNC(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    x.did_nrc = 0u;
    FUNC(0x22, 0x03, 0x00);
    EXPECT(0x62, 0x03, 0x00, 0xAA, 0xAB, 0xAC);
    TEST_ASSERT_EQUAL_UINT(5, x.did_calls);
}

/* ---- routine_ex ---- */

/* routine_ex answers in every session, the default one included: 71 01 <rid> and its out record, with the option
 * record, the room after 71 01 <rid>, the ctx and each session's access. routine is never called. */
static void test_routine_ex_in_every_session(void)
{
    static const uint8_t sessions[] = {UDSOTA_SESSION_DEFAULT, UDSOTA_SESSION_EXTENDED, UDSOTA_SESSION_PROGRAMMING};
    for (size_t i = 0; i < sizeof sessions; i++) {
        if (sessions[i] != UDSOTA_SESSION_DEFAULT) {
            REQ(0x10, sessions[i]);
            EXPECT(POS10(sessions[i]));
        }
        REQ(0x31, 0x01, 0x12, 0x34, 0xC1, 0xC2);
        EXPECT(0x71, 0x01, 0x12, 0x34, 0x5A, 0x01);
        TEST_ASSERT_EQUAL_UINT8(sessions[i], x.access.session);
        TEST_ASSERT_EQUAL_UINT32(s.session_epoch, x.access.epoch);
    }
    TEST_ASSERT_EQUAL_UINT(3, x.rt_calls);
    TEST_ASSERT_EQUAL_HEX16(APP_RID, x.rt_rid);
    TEST_ASSERT_EQUAL_size_t(2, x.rt_in_len);
    TEST_ASSERT_EQUAL_size_t(sizeof resp - 4u, x.rt_out_max);
    TEST_ASSERT_EQUAL_PTR(&g_mock, x.ctx);
    TEST_ASSERT_EQUAL_UINT(0, x.rt_old_calls);
}

/* Sub-functions 01, 02 and 03 reach the hook and frame 71 <sub> <rid>; any other is 0x12 and a request under 4 bytes
 * 0x13, both without a call and in the default session too, where the core answered 0x7F before. */
static void test_routine_ex_subfunctions(void)
{
    REQ(0x31, 0x02, 0x12, 0x34);
    EXPECT(0x71, 0x02, 0x12, 0x34, 0x5A, 0x02);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_RC_STOP, x.rt_sub);
    REQ(0x31, 0x03, 0x12, 0x34);
    EXPECT(0x71, 0x03, 0x12, 0x34, 0x5A, 0x03);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_RC_RESULTS, x.rt_sub);
    static const uint8_t bad[] = {0x00, 0x04, 0x7F, 0x84};
    for (size_t i = 0; i < sizeof bad; i++) {
        REQ(0x31, bad[i], 0x12, 0x34);
        NRC(0x31, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    REQ(0x31, 0x01, 0x12);
    NRC(0x31, UDSOTA_NRC_INCORRECT_LENGTH);
    REQ(0x31);
    NRC(0x31, UDSOTA_NRC_INCORRECT_LENGTH);
    TEST_ASSERT_EQUAL_UINT(2, x.rt_calls);
}

/* SPRMIB drops a positive immediate answer, never an NRC; the hook is told the sub without the bit. A hook fault is
 * 0x10: an out record past its room, or a return that is neither 0, an NRC nor UDSOTA_PENDING. */
static void test_routine_ex_sprmib_and_faults(void)
{
    REQ(0x31, 0x83, 0x12, 0x34);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_RC_RESULTS, x.rt_sub);
    x.rt_rc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    REQ(0x31, 0x82, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    x.rt_rc = UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;      /* the app's own session rule */
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    x.rt_rc = 0x100;
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    x.rt_rc = 0;
    x.rt_out_len = sizeof resp - 3u;                              /* one byte past the room after 71 01 <rid> */
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_EQUAL_UINT(5, x.rt_calls);
    TEST_ASSERT_FALSE(s.job_running);
}

/* UDSOTA_PENDING from any sub, in the default session too, is a job: 0x78 at 40 ms, 0x21 to anything but 3E, and
 * routine_poll's answer framed 71 <sub> <rid>. With SPRMIB a positive final answer is dropped unless a 0x78 went
 * out first. */
static void test_routine_ex_pending(void)
{
    x.rt_rc = UDSOTA_PENDING;
    x.poll_hold = true;
    REQ(0x31, 0x03, 0x12, 0x34);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_TRUE(s.job_running && s.job_app);
    poll_after(39u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    poll_after(1u);
    NRC(0x31, UDSOTA_NRC_RESPONSE_PENDING);
    REQ(0x22, 0x03, 0x00);
    NRC(0x22, UDSOTA_NRC_BUSY_REPEAT);
    x.poll_hold = false;
    poll_after(5u);
    EXPECT(0x71, 0x03, 0x12, 0x34, 0x5A, 0x77);
    TEST_ASSERT_FALSE(s.job_running);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);

    REQ(0x31, 0x82, 0x43, 0x21);                                  /* finished before any 0x78: dropped */
    poll_after(5u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    x.poll_hold = true;
    REQ(0x31, 0x82, 0x43, 0x21);
    poll_after(40u);
    NRC(0x31, UDSOTA_NRC_RESPONSE_PENDING);
    x.poll_hold = false;
    poll_after(5u);                                               /* after a 0x78 it is sent */
    EXPECT(0x71, 0x02, 0x43, 0x21, 0x5A, 0x77);
    TEST_ASSERT_EQUAL_UINT(3, x.rt_calls);
}

/* An app routine past the 90 s cap answers 0x10, not 0x72, which is about programming; the session ends and the
 * routine is an app orphan: a 31 on an app RID is 0x22 without a call until routine_poll finishes it. The updater's
 * own job (F002 here) still answers 0x72 at the cap. */
static void test_cap_is_10_for_an_app_routine_72_for_the_updater(void)
{
    REQ(0x10, 0x03);
    x.rt_rc = UDSOTA_PENDING;
    x.poll_hold = true;
    REQ(0x31, 0x02, 0x12, 0x34);
    poll_after(UDSOTA_JOB_CAP_MS);
    NRC(0x31, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_TRUE(s.app_orphan);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.resp_pending_caps);
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(1, x.rt_calls);
    x.poll_hold = false;
    poll_after(5u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);                            /* the orphan's own answer is never sent */
    TEST_ASSERT_FALSE(s.app_orphan);

    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;      /* F002 runs engine.confirm, which queues */
    s_hold = true;
    REQ(0x10, 0x03);
    REQ(0x31, 0x01, 0xF0, 0x02);
    TEST_ASSERT_TRUE(s.job_running && !s.job_app);
    poll_after(UDSOTA_JOB_CAP_MS);
    NRC(0x31, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_TRUE(s.worker_orphan);
    TEST_ASSERT_EQUAL_UINT(1, x.rt_calls);
}

/* One request at st on a fresh server with routine_ex set (ex) or NULL; its answer in out[0..*n). */
static void updater_rid_answer(bool ex, int st, const uint8_t *r, uint8_t *out, size_t *n)
{
    setUp();
    g_hooks.routine_ex = ex ? hook_routine_ex : NULL;
    udsota_init(&s, &g_cfg, &ENGINE, udsota_mock_security(), &g_hooks);
    if (st != 0) {
        REQ(0x10, st == 1 ? UDSOTA_SESSION_EXTENDED : UDSOTA_SESSION_PROGRAMMING);
        if (st == 3) {
            unlock(UDSOTA_SA_SEED_PROGRAMMING);
        }
    }
    req_max(r, 4, sizeof resp);
    *n = rlen;
    memcpy(out, resp, rlen);
    TEST_ASSERT_EQUAL_UINT(0, x.rt_calls);
}

/* The updater's RIDs answer exactly as without routine_ex, byte for byte, in every session (default, extended,
 * programming locked and unlocked) and for every sub-function (01, 02, 03, 04, and 01 with SPRMIB), and never
 * reach the hook. */
static void test_updater_rids_unchanged(void)
{
    static const uint16_t rids[] = {UDSOTA_RID_CHECK_PROG_DEPS, UDSOTA_RID_GET_RESUME_POINT, UDSOTA_RID_ACTIVATE_IMAGE,
                                    UDSOTA_RID_CONFIRM_IMAGE};
    static const uint8_t subs[] = {0x01, 0x02, 0x03, 0x04, 0x81};
    char msg[64];
    for (int st = 0; st < 4; st++) {
        for (size_t i = 0; i < sizeof rids / sizeof rids[0]; i++) {
            for (size_t k = 0; k < sizeof subs; k++) {
                const uint8_t r[4] = {0x31, subs[k], (uint8_t)(rids[i] >> 8), (uint8_t)rids[i]};
                uint8_t with[64], without[64];
                size_t n_with, n_without;
                updater_rid_answer(true, st, r, with, &n_with);
                updater_rid_answer(false, st, r, without, &n_without);
                snprintf(msg, sizeof msg, "state %d, 31 %02X %04X", st, subs[k], rids[i]);
                TEST_ASSERT_EQUAL_size_t_MESSAGE(n_without, n_with, msg);
                if (n_with != 0u) {                               /* 0: SPRMIB dropped both positives */
                    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(without, with, n_with, msg);
                }
                if (st == 0 && n_with == 3u) {
                    TEST_ASSERT_EQUAL_HEX8_MESSAGE(UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION, with[2], msg);
                }
            }
        }
    }
}

/* Without the updater its RIDs are the app's: routine_ex gets FF01 in the default session and with sub 02. */
static void test_updater_rids_are_the_apps_without_it(void)
{
    boot(false, false);
    REQ(0x31, 0x02, 0xFF, 0x01);
    EXPECT(0x71, 0x02, 0xFF, 0x01, 0x5A, 0x02);
    TEST_ASSERT_EQUAL_HEX16(UDSOTA_RID_CHECK_PROG_DEPS, x.rt_rid);
}

/* With routine_ex NULL, routine is unchanged: 0x7F in the default session before the length, 0x12 for any sub but
 * 01, and 71 01 <rid> from routine. */
static void test_routine_unchanged_without_routine_ex(void)
{
    g_hooks.routine_ex = NULL;
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
    REQ(0x31, 0x01, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    REQ(0x31);
    NRC(0x31, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    REQ(0x10, 0x03);
    REQ(0x31, 0x02, 0x12, 0x34);
    NRC(0x31, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    REQ(0x31, 0x01, 0x12, 0x34);
    EXPECT(0x71, 0x01, 0x12, 0x34, 0x0E);
    TEST_ASSERT_EQUAL_UINT(1, x.rt_old_calls);
    TEST_ASSERT_EQUAL_UINT(0, x.rt_calls);
}

/* ---- 10 02 without a service ---- */

/* With no service registered 10 02 is 0x12 in every session, before the core's worker rule and the gate, and
 * functionally silent; with the updater it enters programming as before. */
static void test_programming_needs_a_service(void)
{
    boot(false, false);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0x88;
    REQ(0x10, 0x02);
    NRC(0x10, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    REQ(0x10, 0x03);
    EXPECT(POS10(UDSOTA_SESSION_EXTENDED));
    REQ(0x10, 0x02);
    NRC(0x10, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s.session);
    FUNC(0x10, 0x02);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING]);

    boot(true, false);
    REQ(0x10, 0x02);
    NRC(0x10, 0x88);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = 0u;
    REQ(0x10, 0x02);
    EXPECT(POS10(UDSOTA_SESSION_PROGRAMMING));
    FUNC(0x10, 0x02);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
}

/* Runs every did_read_ex, routine_ex and 10 02 test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_did_read_ex_positive);
    RUN_TEST(test_did_read_ex_nrcs_pass_through);
    RUN_TEST(test_did_read_ex_faults_are_10);
    RUN_TEST(test_did_read_ex_takes_did_reads_place);
    RUN_TEST(test_did_read_ex_functional);
    RUN_TEST(test_routine_ex_in_every_session);
    RUN_TEST(test_routine_ex_subfunctions);
    RUN_TEST(test_routine_ex_sprmib_and_faults);
    RUN_TEST(test_routine_ex_pending);
    RUN_TEST(test_cap_is_10_for_an_app_routine_72_for_the_updater);
    RUN_TEST(test_updater_rids_unchanged);
    RUN_TEST(test_updater_rids_are_the_apps_without_it);
    RUN_TEST(test_routine_unchanged_without_routine_ex);
    RUN_TEST(test_programming_needs_a_service);
    return UNITY_END();
}
