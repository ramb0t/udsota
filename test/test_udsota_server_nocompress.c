/* Host test for the server built with UDSOTA_COMPRESSION 0: an engine that offers every compressed-download op still
 * gets a 34 with DFI 0x10 answered 0x31, as a server without them answers it, and none of those ops is ever called;
 * an uncompressed download runs as before. The other download and progress tests also run in this build. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

_Static_assert(UDSOTA_COMPRESSION == 0, "this test is built with UDSOTA_COMPRESSION=0");

#define T0 60000u   /* 60 s after boot */

static udsota_server_t srv;
static udsota_mock_t g_mock;
static uint8_t g_resp[64];
static size_t g_resp_len;
static unsigned g_z_calls;       /* calls to any compressed-download op: there must be none */
static uint32_t g_written;       /* bytes engine.write took */

/* engine.check_first: every block passes. */
static int eng_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}

/* engine.begin: the erase, done at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }

/* engine.write: counts the bytes, done at once. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    g_written += (uint32_t)n;
    return 0;
}

/* engine.verify, activate and confirm: done at once. */
static int eng_ok(void *ctx) { return 0; }

/* engine.abort: nothing to release. */
static void eng_abort(void *ctx) {}

/* engine.zbegin: counted; the server must never call it. */
static int eng_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    g_z_calls++;
    return 0;
}

/* engine.zwrite: counted; the server must never call it. */
static int eng_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    g_z_calls++;
    return 0;
}

/* engine.zend: counted; the server must never call it. */
static int eng_zend(void *ctx)
{
    g_z_calls++;
    return 0;
}

/* engine.zwritten: counted; the server must never call it. */
static uint32_t eng_zwritten(void *ctx)
{
    g_z_calls++;
    return 0;
}

static const udsota_engine_t ENGINE = {
    .check_first = eng_check, .begin = eng_begin, .write = eng_write, .verify = eng_ok, .activate = eng_ok,
    .confirm = eng_ok, .abort = eng_abort, .poll = eng_ok, .status = udsota_mock_status, .ctx = &g_mock,
    .zbegin = eng_zbegin, .zwrite = eng_zwrite, .zend = eng_zend, .zwritten = eng_zwritten,
    .zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE) | UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA) |
                UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA_DEFLATE),
};

/* A server without security, on ENGINE, in the programming session at T0. */
void setUp(void)
{
    udsota_mock_clear(&g_mock);
    g_z_calls = 0;
    g_written = 0;
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, &ENGINE, NULL, &hooks);
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    g_resp_len = udsota_on_request(&srv, sess, sizeof sess, g_resp, sizeof g_resp, T0);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Asserts the last response is exactly the bytes listed. */
#define EXPECT(...) do {                                                       \
        const uint8_t e_[] = {__VA_ARGS__};                                    \
        TEST_ASSERT_EQUAL_UINT(sizeof e_, g_resp_len);                         \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(e_, g_resp, sizeof e_);                   \
    } while (0)

/* Sends one request at T0 and keeps its answer. */
static void send(const uint8_t *req, size_t len)
{
    g_resp_len = udsota_on_request(&srv, req, len, g_resp, sizeof g_resp, T0);
}

/* A 34 with DFI 0x10, 0x20 or 0x30 answers 0x31 though the engine sets the ops and names all three in zformats, and
 * leaves F1F1, the download and the engine untouched. */
static void test_dfi_10_answers_0x31_with_the_ops_set(void)
{
    srv.last_dl.reason_code = UDSOTA_DL_VERIFY_FAILED;
    const uint8_t dfis[] = {UDSOTA_DL_DFI_DEFLATE, UDSOTA_DL_DFI_DELTA, UDSOTA_DL_DFI_DELTA_DEFLATE};
    for (size_t i = 0; i < sizeof dfis; i++) {
        const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, dfis[i], UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0, 4, 0};
        send(r34, sizeof r34);
        EXPECT(0x7F, 0x34, 0x31);
    }
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_VERIFY_FAILED, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT(0u, g_z_calls);
}

/* An uncompressed download on the same engine runs 34, 36, 37 and FF01 as always, through engine.write, and progress
 * counts its bytes. */
static void test_uncompressed_download_runs_as_before(void)
{
    const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0, 0x01, 0x40};
    send(r34, sizeof r34);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    uint8_t blk[2u + 320u] = {UDSOTA_SID_TRANSFER_DATA, 0x01};
    send(blk, sizeof blk);
    EXPECT(0x76, 0x01);
    udsota_progress_t p;
    udsota_progress(&srv, &p);
    TEST_ASSERT_EQUAL_UINT32(320u, p.done);
    const uint8_t r37[] = {UDSOTA_SID_TRANSFER_EXIT};
    send(r37, sizeof r37);
    EXPECT(0x77);
    const uint8_t ff01[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01};
    send(ff01, sizeof ff01);
    EXPECT(0x71, 0x01, 0xFF, 0x01, 0x00);
    TEST_ASSERT_EQUAL_UINT32(320u, g_written);
    TEST_ASSERT_EQUAL_UINT(0u, g_z_calls);
}

/* Runs every test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dfi_10_answers_0x31_with_the_ops_set);
    RUN_TEST(test_uncompressed_download_runs_as_before);
    return UNITY_END();
}
