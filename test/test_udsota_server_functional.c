/* Host tests for functional addressing (udsota_on_functional_request) and the set of SIDs it answers, 0x28
 * CommunicationControl, 0x85 ControlDTCSetting, what a return to the default session undoes, and P2/P2* per session. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

#define T0  60000u   /* past the 10 s post-boot 0x27 delay */

/* The engine: every op queued; poll reports 0 unless `hold` keeps the worker busy. */
static bool            s_hold;
static udsota_mock_t   g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[64];
static uint32_t        now;

/* 0x28 and 0x85 hook state. */
static unsigned s_cc_calls, s_dtc_calls;
static uint8_t  s_cc_control, s_cc_type, s_cc_nrc;
static bool     s_dtc_on;

/* engine.check_first: every first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin, write, verify, activate, confirm: queued. */
static int eng_begin(void *ctx, uint32_t size) { return UDSOTA_PENDING; }
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return UDSOTA_PENDING; }
static int eng_queued(void *ctx) { return UDSOTA_PENDING; }
/* engine.abort: fire-and-forget. */
static void eng_abort(void *ctx) {}
/* engine.poll: UDSOTA_PENDING while held, else 0. */
static int eng_poll(void *ctx) { return s_hold ? UDSOTA_PENDING : 0; }

/* hooks.comm_control: records the call and answers s_cc_nrc. */
static uint8_t hook_cc(void *ctx, uint8_t control, uint8_t comm_type)
{
    s_cc_calls++;
    s_cc_control = control;
    s_cc_type = comm_type;
    return s_cc_nrc;
}
/* hooks.dtc_setting: records the call. */
static void hook_dtc(void *ctx, bool on)
{
    s_dtc_calls++;
    s_dtc_on = on;
}

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_queued,
    .activate = eng_queued, .confirm = eng_queued, .abort = eng_abort, .poll = eng_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};

/* A server with the mock's hooks plus comm_control and dtc_setting, no security, cfg as the test left it. */
static void init_server(void)
{
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.comm_control = hook_cc;
    g_hooks.dtc_setting = hook_dtc;
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
}

/* Unity hook: default config, everything allowed, no job, t = 60 s. */
void setUp(void)
{
    udsota_mock_clear(&g_mock);
    g_cfg = udsota_mock_cfg();
    s_hold = false;
    s_cc_calls = s_dtc_calls = 0u;
    s_cc_control = s_cc_type = s_cc_nrc = 0u;
    s_dtc_on = true;
    now = T0;
    init_server();
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* One physical request; its response length. */
static size_t phys(const uint8_t *req, size_t len) { return udsota_on_request(&s, req, len, resp, sizeof resp, now); }
/* One functional request; its response length. */
static size_t func(const uint8_t *req, size_t len)
{
    return udsota_on_functional_request(&s, req, len, resp, sizeof resp, now);
}
#define PHYS(...) phys((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
#define FUNC(...) func((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
#define EXPECT(...) do { \
        static const uint8_t want_[] = {__VA_ARGS__}; \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want_, resp, sizeof want_); \
    } while (0)

/* 3E functionally: 3E 00 is answered, 3E 80 is not; neither changes the session. */
static void test_functional_tester_present(void)
{
    TEST_ASSERT_EQUAL_UINT(2, FUNC(0x3E, 0x00));
    EXPECT(0x7E, 0x00);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x3E, 0x80));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
}

/* 10 03 and 10 01 are served functionally; 10 02 is not (the programming session is entered physically), and a
 * gate's 0x22 is still answered, as only 11/12/31/7E/7F are suppressed. */
static void test_functional_session_control(void)
{
    TEST_ASSERT_EQUAL_UINT(6, FUNC(0x10, 0x03));
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x10, 0x02));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s.session);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x10, 0x81));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_EXTENDED] = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    TEST_ASSERT_EQUAL_UINT(3, FUNC(0x10, 0x03));
    EXPECT(0x7F, 0x10, 0x22);
}

/* 22 functionally: a known DID is answered, an unknown one (0x31) is not. */
static void test_functional_read_did_suppresses_0x31(void)
{
    TEST_ASSERT_EQUAL_UINT(4, FUNC(0x22, 0xF1, 0x86));
    EXPECT(0x62, 0xF1, 0x86, 0x01);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x22, 0x12, 0x34));
    EXPECT(0x7F, 0x22, 0x31);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x22, 0x12, 0x34));
}

/* app_did for 0x0100: a DID one byte longer than the room it is offered. */
static size_t app_did_too_long(uint16_t did, uint8_t *buf, size_t max)
{
    return did == 0x0100u ? max + 1u : 0u;
}

/* 22 functionally: 0x14 for a DID too long for the answer is not among the suppressed NRCs, so it is answered. */
static void test_functional_read_did_answers_0x14(void)
{
    g_mock.app_did = app_did_too_long;
    TEST_ASSERT_EQUAL_UINT(3, FUNC(0x22, 0x01, 0x00));
    EXPECT(0x7F, 0x22, 0x14);
}

/* Services udsota never serves functionally get no answer and change nothing, whatever the session. */
static void test_functional_unserved_services_are_silent(void)
{
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x27, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x31, 0x01, 0xF0, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x11, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x14, 0xFF, 0xFF, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, func(NULL, 2));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40));
    TEST_ASSERT_FALSE(s.update.download_active);
}

/* 28 and 85 in the default session: physically 0x7F, functionally nothing. */
static void test_functional_suppresses_0x7f(void)
{
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x03, 0x01));
    EXPECT(0x7F, 0x28, 0x7F);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x28, 0x03, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x85, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, s_cc_calls + s_dtc_calls);
}

/* While a job runs a functional 3E is answered and anything else is silent (no 0x21 to a broadcast). */
static void test_functional_during_a_job(void)
{
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
    TEST_ASSERT_EQUAL_UINT(4, PHYS(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40));
    s_hold = true;
    TEST_ASSERT_EQUAL_UINT(0, PHYS(0x36, 0x01, 0xE9, 0x03));
    TEST_ASSERT_TRUE(s.job_running);
    TEST_ASSERT_EQUAL_UINT(2, FUNC(0x3E, 0x00));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x22, 0xF1, 0x86));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x10, 0x01));
    TEST_ASSERT_TRUE(s.job_running);
    TEST_ASSERT_TRUE(s.update.download_active);
}

/* 28: the hook gets controlType and communicationType, 68 <ct> answers, SPRMIB silences it, and the hook's NRC,
 * a bad communicationType (0x31), an unserved controlType (0x12) and a bad length (0x13) are answered. */
static void test_comm_control(void)
{
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x03, 0x01));
    EXPECT(0x68, 0x03);
    TEST_ASSERT_EQUAL_UINT(1, s_cc_calls);
    TEST_ASSERT_EQUAL_HEX8(0x03, s_cc_control);
    TEST_ASSERT_EQUAL_HEX8(0x01, s_cc_type);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x28, 0x81, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, s_cc_calls);
    TEST_ASSERT_EQUAL_HEX8(0x01, s_cc_control);
    s_cc_nrc = UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x02, 0x01));
    EXPECT(0x7F, 0x28, 0x22);
    s_cc_nrc = 0u;
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x03, 0x00));
    EXPECT(0x7F, 0x28, 0x31);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x04, 0x01));
    EXPECT(0x7F, 0x28, 0x12);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x03));
    EXPECT(0x7F, 0x28, 0x13);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x03, 0x01, 0x00));
    EXPECT(0x7F, 0x28, 0x13);
    TEST_ASSERT_EQUAL_UINT(3, s_cc_calls);                    /* only the three that reached the hook */
}

/* A return to the default session undoes 28 once, with 00 and all message types; after 28 00 03 nothing is owed,
 * but after a partial 28 00 01 (network management still off) the restore is still owed. */
static void test_default_session_reenables_communication(void)
{
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x03, 0x01));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_cc_calls);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_ENABLE_RX_TX, s_cc_control);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_TYPE_ALL, s_cc_type);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_cc_calls);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x03, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x00, 0x03));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(4, s_cc_calls);                    /* no restore owed after 28 00 03 */
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x03, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x00, 0x01));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(7, s_cc_calls);                    /* 28 00 01 left NM off: restored */
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_TYPE_ALL, s_cc_type);
}

/* S3 back to default also re-enables communication and DTC setting. */
static void test_s3_timeout_undoes_28_and_85(void)
{
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x01, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x85, 0x02));
    TEST_ASSERT_FALSE(s_dtc_on);
    now += UDSOTA_S3_MS;
    (void)udsota_poll(&s, resp, sizeof resp, now);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_ENABLE_RX_TX, s_cc_control);
    TEST_ASSERT_EQUAL_UINT(2, s_cc_calls);
    TEST_ASSERT_TRUE(s_dtc_on);
    TEST_ASSERT_EQUAL_UINT(2, s_dtc_calls);
}

/* 85 with the hook: C5 <sub> with an option record; SPRMIB silences it; a session change undoes 85 02 only.
 * Without the hook 85 answers 0x11 physically, functionally nothing, and the hook-less server owes no restore. */
static void test_dtc_setting(void)
{
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x85, 0x02, 0xFF, 0xFF, 0xFF));
    EXPECT(0xC5, 0x02);
    TEST_ASSERT_FALSE(s_dtc_on);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x85, 0x81));
    TEST_ASSERT_TRUE(s_dtc_on);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_dtc_calls);                   /* 85 01 left nothing to undo */
    g_hooks.dtc_setting = NULL;
    TEST_ASSERT_TRUE(udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85, 0x02));
    EXPECT(0x7F, 0x85, 0x11);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x85, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x85, 0x82));
    TEST_ASSERT_FALSE(s.dtc_off);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_dtc_calls);
}

/* 85 with the hook, its checks in order: session 0x7F, then length 0x13, then sub-function 0x12; 85 01 is served in
 * the programming session too. None of the refused ones reaches the hook. */
static void test_dtc_setting_checks(void)
{
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85, 0x02));
    EXPECT(0x7F, 0x85, 0x7F);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85));
    EXPECT(0x7F, 0x85, 0x7F);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85));
    EXPECT(0x7F, 0x85, 0x13);
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85, 0x03));
    EXPECT(0x7F, 0x85, 0x12);
    TEST_ASSERT_EQUAL_UINT(0, s_dtc_calls);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x85, 0x01));
    EXPECT(0xC5, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, s_dtc_calls);
    TEST_ASSERT_TRUE(s_dtc_on);
}

/* With only comm_control set, a return to default restores 28 and 85 answers 0x11; with only dtc_setting set, it
 * restores 85 and 28 answers 0x11. */
static void test_default_session_restores_with_one_hook(void)
{
    g_hooks.dtc_setting = NULL;
    TEST_ASSERT_TRUE(udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x28, 0x03, 0x01));
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x85, 0x02));
    EXPECT(0x7F, 0x85, 0x11);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_cc_calls);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_ENABLE_RX_TX, s_cc_control);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_TYPE_ALL, s_cc_type);
    TEST_ASSERT_EQUAL_UINT(0, s_dtc_calls);

    s_cc_calls = 0u;
    g_hooks.comm_control = NULL;
    g_hooks.dtc_setting = hook_dtc;
    TEST_ASSERT_TRUE(udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(3, PHYS(0x28, 0x03, 0x01));
    EXPECT(0x7F, 0x28, 0x11);
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x85, 0x02));
    TEST_ASSERT_FALSE(s_dtc_on);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_TRUE(s_dtc_on);
    TEST_ASSERT_EQUAL_UINT(2, s_dtc_calls);
    TEST_ASSERT_EQUAL_UINT(0, s_cc_calls);
}

/* cfg.p2_prog_ms and p2star_prog_ms: 10 02 advertises them and the programming session's 0x78 follows them;
 * 10 03 keeps the default-session values. */
static void test_p2_per_session(void)
{
    g_cfg.p2_prog_ms = 1000u;
    g_cfg.p2star_prog_ms = 10000u;
    init_server();
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
    EXPECT(0x50, 0x02, 0x03, 0xE8, 0x03, 0xE8);
    TEST_ASSERT_EQUAL_UINT(4, PHYS(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40));
    s_hold = true;
    TEST_ASSERT_EQUAL_UINT(0, PHYS(0x36, 0x01, 0xE9, 0x03));
    now += 799u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_poll(&s, resp, sizeof resp, now));
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(3, udsota_poll(&s, resp, sizeof resp, now));   /* 4/5 of 1000 ms */
    EXPECT(0x7F, 0x36, 0x78);
    now += 2999u;
    TEST_ASSERT_EQUAL_UINT(0, udsota_poll(&s, resp, sizeof resp, now));
    now += 1u;
    TEST_ASSERT_EQUAL_UINT(3, udsota_poll(&s, resp, sizeof resp, now));   /* 3/10 of 10 s */
}

/* ---- The functional set: every hook but request set, so every core service is live ---- */

/* hooks.did_write, routine, routine_poll and the _ex hooks: accept everything (the answer's record empty). */
static uint8_t all_did_write(void *ctx, uint16_t did, const uint8_t *d, size_t n, udsota_access_t a) { return 0u; }
static int all_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max,
                       size_t *out_len, udsota_access_t a)
{
    *out_len = 0u;
    return 0;
}
static int all_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    *out_len = 0u;
    return 0;
}
static uint8_t all_did_read_ex(void *ctx, uint16_t did, uint8_t *buf, size_t max, size_t *len, udsota_access_t a)
{
    buf[0] = 0x01;
    *len = 1u;
    return 0u;
}
static int all_routine_ex(void *ctx, uint8_t sub, uint16_t rid, const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t out_max, size_t *out_len, udsota_access_t a)
{
    *out_len = 0u;
    return 0;
}
/* hooks.dtc_get, dtc_ext_data and dtc_clear: one DTC, U0073 with status 09 and record 01 as 01 02; clears anything. */
static bool all_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    out->dtc = 0xC07300u;
    out->status = 0x09u;
    return i == 0u;
}
static uint8_t all_dtc_ext(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len)
{
    buf[0] = 0x01;
    buf[1] = 0x02;
    *len = 2u;
    return 0u;
}
static uint8_t all_dtc_clear(void *ctx, uint32_t group, udsota_access_t a) { return 0u; }

/* The states the functional sweep starts from: every service the core runs is live in at least one of them. */
enum { ST_DEFAULT, ST_EXTENDED, ST_PROGRAMMING, ST_DOWNLOAD, ST_COUNT };

/* A fresh server with every hook but request and security on, in `state`: the default session, the extended one
 * (10 03 sent physically), the programming one unlocked at level 03, or that with a download open (34 accepted). */
static void all_hooks_server(int state)
{
    setUp();
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.comm_control = hook_cc;
    g_hooks.dtc_setting = hook_dtc;
    g_hooks.did_write = all_did_write;
    g_hooks.routine = all_routine;
    g_hooks.routine_poll = all_routine_poll;
    g_hooks.dtc_get = all_dtc_get;
    g_hooks.dtc_ext_data = all_dtc_ext;
    g_hooks.dtc_clear = all_dtc_clear;
    g_hooks.did_read_ex = all_did_read_ex;
    g_hooks.routine_ex = all_routine_ex;
    udsota_init(&s, &g_cfg, &ENGINE, udsota_mock_security(), &g_hooks);
    if (state == ST_EXTENDED) {
        TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    }
    if (state >= ST_PROGRAMMING) {
        TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
        TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_SEED_LEN, PHYS(0x27, UDSOTA_SA_SEED_PROGRAMMING));
        uint8_t key[2u + UDSOTA_KEY_LEN] = {0x27, UDSOTA_SA_KEY_PROGRAMMING};
        udsota_mock_key_for(&resp[2], UDSOTA_SA_SEED_PROGRAMMING, &key[2]);
        TEST_ASSERT_EQUAL_UINT(2, phys(key, sizeof key));
        EXPECT(0x67, 0x04);
    }
    if (state == ST_DOWNLOAD) {
        TEST_ASSERT_EQUAL_UINT(4, PHYS(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40));
    }
}

/* A request live physically, with every hook set, in some ST_ state; the six functional ones among them. */
typedef struct { uint8_t len; uint8_t b[12]; } body_t;
static const body_t VALID[] = {
    {2, {0x10, 0x03}}, {2, {0x3E, 0x00}}, {3, {0x19, 0x02, 0xFF}}, {3, {0x22, 0xF1, 0x86}}, {3, {0x28, 0x00, 0x03}},
    {2, {0x85, 0x01}}, {2, {0x10, 0x01}}, {3, {0x22, 0x03, 0x00}}, {2, {0x19, 0x0A}}, {2, {0x11, 0x01}},
    {4, {0x14, 0xFF, 0xFF, 0xFF}}, {2, {0x27, 0x01}}, {4, {0x2E, 0x03, 0x00, 0xAA}}, {4, {0x31, 0x01, 0x12, 0x34}},
    {4, {0x31, 0x03, 0x12, 0x34}}, {11, {0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40}}, {3, {0x36, 0x01, 0xE9}},
    {1, {0x37}},
};

/* True when n bytes in resp are an NRC a functional request suppresses: 0x11, 0x12, 0x31, 0x7E or 0x7F. */
static bool suppressed_nrc(size_t n)
{
    return n == 3u && resp[0] == 0x7F &&
           (resp[2] == 0x11 || resp[2] == 0x12 || resp[2] == 0x31 || resp[2] == 0x7E || resp[2] == 0x7F);
}

/* Sends b functionally to a fresh all-hooks server in `state`; true when it answers or starts a job. */
static bool func_answers(int state, const uint8_t *b, size_t len)
{
    all_hooks_server(state);
    return func(b, len) != 0u || s.job_running;
}

/* True when b, sent physically to a fresh all-hooks server in some state, draws a positive answer, an NRC a
 * functional request would not suppress, or a job: the service is live there. */
static bool phys_live(const uint8_t *b, size_t len)
{
    bool live = false;
    for (int state = 0; state < ST_COUNT; state++) {
        all_hooks_server(state);
        const size_t n = phys(b, len);
        live = live || (n != 0u && !suppressed_nrc(n)) || s.job_running;
    }
    return live;
}

/* With every hook but request set and security on, SIDs 00-FF sent functionally in the default, extended and
 * programming sessions, the last unlocked at level 03 with and without a download open, each alone, as SID 01 F1 86 00
 * and SID 00, and every request in VALID: only 10, 3E, 19, 22, 28 and 85 ever draw an answer or start a job, and each
 * of those does to its valid request, while every request in VALID is live physically in some state (so 34, 36 and
 * 37 reach past their 0x7F). The set is functional_served()'s, and the core README names it; request's own sweep is
 * test_functional_request_is_silent in test_udsota_server_request.c. */
static void test_functional_answers_only_its_sids(void)
{
    static const uint8_t served[] = {0x10, 0x3E, 0x19, 0x22, 0x28, 0x85};
    bool answered[256] = {false};
    for (int state = 0; state < ST_COUNT; state++) {
        for (unsigned sid = 0; sid <= 0xFFu; sid++) {
            const uint8_t one[] = {(uint8_t)sid}, five[] = {(uint8_t)sid, 0x01, 0xF1, 0x86, 0x00};
            const uint8_t zero[] = {(uint8_t)sid, 0x00};
            answered[sid] = answered[sid] || func_answers(state, one, sizeof one) ||
                            func_answers(state, five, sizeof five) || func_answers(state, zero, sizeof zero);
        }
        for (size_t i = 0; i < sizeof VALID / sizeof VALID[0]; i++) {
            const bool a = func_answers(state, VALID[i].b, VALID[i].len);
            answered[VALID[i].b[0]] = answered[VALID[i].b[0]] || a;
        }
    }
    for (size_t i = 0; i < sizeof VALID / sizeof VALID[0]; i++) {
        char msg[48];
        snprintf(msg, sizeof msg, "VALID %02X is live physically", VALID[i].b[0]);
        TEST_ASSERT_TRUE_MESSAGE(phys_live(VALID[i].b, VALID[i].len), msg);
    }
    for (unsigned sid = 0; sid <= 0xFFu; sid++) {
        bool want = false;
        for (size_t k = 0; k < sizeof served; k++) {
            want = want || sid == served[k];
        }
        char msg[48];
        snprintf(msg, sizeof msg, "SID %02X answered functionally", sid);
        TEST_ASSERT_EQUAL_MESSAGE(want, answered[sid], msg);
    }
}

/* Runs every functional, 0x28, 0x85 and P2 test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_functional_tester_present);
    RUN_TEST(test_functional_session_control);
    RUN_TEST(test_functional_read_did_suppresses_0x31);
    RUN_TEST(test_functional_read_did_answers_0x14);
    RUN_TEST(test_functional_unserved_services_are_silent);
    RUN_TEST(test_functional_suppresses_0x7f);
    RUN_TEST(test_functional_during_a_job);
    RUN_TEST(test_comm_control);
    RUN_TEST(test_default_session_reenables_communication);
    RUN_TEST(test_s3_timeout_undoes_28_and_85);
    RUN_TEST(test_dtc_setting);
    RUN_TEST(test_dtc_setting_checks);
    RUN_TEST(test_default_session_restores_with_one_hook);
    RUN_TEST(test_p2_per_session);
    RUN_TEST(test_functional_answers_only_its_sids);
    return UNITY_END();
}
