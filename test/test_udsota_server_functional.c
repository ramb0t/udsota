/* Host tests for functional addressing (udsota_on_functional_request), 0x28 CommunicationControl, 0x85
 * ControlDTCSetting, what a return to the default session undoes, and P2/P2* per session. */
#include <stdbool.h>
#include <stdint.h>
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

/* Services udsota never serves functionally get no answer and change nothing, whatever the session. */
static void test_functional_unserved_services_are_silent(void)
{
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x27, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x31, 0x01, 0xF0, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x11, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x02, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, func(NULL, 2));
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x02));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40));
    TEST_ASSERT_FALSE(s.download_active);
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
    TEST_ASSERT_TRUE(s.download_active);
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

/* 85: C5 <sub> with or without a hook and with an option record; SPRMIB silences it; a session change undoes 85 02
 * only. */
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
    udsota_init(&s, &g_cfg, &ENGINE, NULL, &g_hooks);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, PHYS(0x85, 0x02));
    EXPECT(0xC5, 0x02);
    TEST_ASSERT_EQUAL_UINT(6, PHYS(0x10, 0x01));
    TEST_ASSERT_EQUAL_UINT(2, s_dtc_calls);
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

/* Runs every functional, 0x28, 0x85 and P2 test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_functional_tester_present);
    RUN_TEST(test_functional_session_control);
    RUN_TEST(test_functional_read_did_suppresses_0x31);
    RUN_TEST(test_functional_unserved_services_are_silent);
    RUN_TEST(test_functional_suppresses_0x7f);
    RUN_TEST(test_functional_during_a_job);
    RUN_TEST(test_comm_control);
    RUN_TEST(test_default_session_reenables_communication);
    RUN_TEST(test_s3_timeout_undoes_28_and_85);
    RUN_TEST(test_dtc_setting);
    RUN_TEST(test_p2_per_session);
    return UNITY_END();
}
