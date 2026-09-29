/* Host tests for the server with no updater: udsota_init with a NULL engine registers no service, so 34, 36 and 37
 * answer 0x11, the updater's RIDs and DIDs go to the app's hooks, 10 02 and 11 01 ask only the core's worker rule and
 * the gate, and nothing reaches a NULL engine op. Groups A to G and I are the rows test_udsota_core_only also runs,
 * through udsota_core_init (test/core_only/udsota_core_rows.h); here udsota_init runs them, and udsota_progress, the
 * updater's, is read too. Group H compares udsota_init with udsota_core_init. Pass a test's name to run it alone. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "udsota.h"

#define CORE_ROWS_INIT(srv, cfg, security, hooks) udsota_init((srv), (cfg), NULL, (security), (hooks))
#include "udsota_core_rows.h"

_Static_assert(ROWS_RID_CHECK_PROG_DEPS == UDSOTA_RID_CHECK_PROG_DEPS, "FF01");
_Static_assert(ROWS_RID_GET_RESUME_POINT == UDSOTA_RID_GET_RESUME_POINT, "F000");
_Static_assert(ROWS_RID_ACTIVATE_IMAGE == UDSOTA_RID_ACTIVATE_IMAGE, "F001");
_Static_assert(ROWS_RID_CONFIRM_IMAGE == UDSOTA_RID_CONFIRM_IMAGE, "F002");
_Static_assert(ROWS_DID_SW_VERSION == UDSOTA_DID_SW_VERSION, "F189");
_Static_assert(ROWS_DID_STATUS == UDSOTA_DID_STATUS, "F1F0");
_Static_assert(ROWS_DID_RESULT == UDSOTA_DID_RESULT, "F1F1");
_Static_assert(ROWS_DID_RUNNING_SHA == UDSOTA_DID_RUNNING_SHA, "F1F3");

/* F5, the updater's half: udsota_progress reads IDLE 0 of 0 with no last reason. */
static void test_F5_progress_reads_idle(void)
{
    const state_t states[] = {ST_DEF, ST_PROG03};
    for (size_t i = 0; i < 2u; i++) {
        enter(states[i], false);
        udsota_progress_t p;
        memset(&p, 0xFF, sizeof p);
        udsota_progress(&s, &p);
        TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, p.stage);
        TEST_ASSERT_EQUAL_UINT32(0, p.done);
        TEST_ASSERT_EQUAL_UINT32(0, p.total);
        TEST_ASSERT_EQUAL_UINT8(0, p.last_reason);
        TEST_ASSERT_EQUAL_UINT(0, app.progress_calls);
    }
}

/* ---- H: udsota_init without an engine is udsota_core_init ---- */

static udsota_server_t s1, s2;

/* Security with no rng16: init refuses it. */
static const udsota_security_t k_broken_security = {.rng16 = NULL, .key = rows_key};

/* H: the same context and the same return, byte for byte, for good, NULL and broken security. */
static void test_H_init_without_engine_is_core_init(void)
{
    const udsota_security_t *secs[] = {rows_security(), NULL, &k_broken_security};
    const bool rets[] = {true, true, false};
    g_hooks = rows_mock_hooks(&g_mock);
    for (size_t i = 0; i < 3u; i++) {
        memset(&s1, 0xA5, sizeof s1);
        memset(&s2, 0x5A, sizeof s2);
        const bool r1 = udsota_init(&s1, &g_cfg, NULL, secs[i], &g_hooks);
        const bool r2 = udsota_core_init(&s2, &g_cfg, secs[i], &g_hooks);
        TEST_ASSERT_EQUAL(rets[i], r1);
        TEST_ASSERT_EQUAL(r1, r2);
        TEST_ASSERT_EQUAL_MEMORY(&s1, &s2, sizeof s1);
    }
}

static const test_row_t k_tests[] = {
    CORE_ROWS,
    ROW(test_F5_progress_reads_idle),
    ROW(test_H_init_without_engine_is_core_init),
};

/* Runs every test, or only the one named in argv[1]. */
int main(int argc, char **argv)
{
    return core_rows_main(argc, argv, k_tests, sizeof k_tests / sizeof k_tests[0]);
}
