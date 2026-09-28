/* Host tests for the UDS download services (0x34/0x36/0x37), the block-counter rule, and the real first-block
 * rules behind engine.check_first. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"
#include "udsota_rxwatch.h"   /* UDSOTA_CF_MEDIAN_NONE */
#include "udsota_image.h"
#include "fixtures/example_first_block.h"   /* example_first_block() */

#define T0          60000u   /* 60 s after boot: past SecurityAccess's post-boot 10 s delay */
#define TWO_BLOCKS  (2u * UDSOTA_DL_MAX_DATA)
#define SYNC_ERR    0x103    /* an op that could not even be queued (ESP_ERR_INVALID_STATE) */

/* The mock platform: records OTA calls and simulates a FIFO worker whose queued ops finish at job_done_at. */
typedef struct {
    char        log[512];               /* one letter per call in order: C check, B begin, W write, A abort */
    size_t      log_n;
    int         check_ret;              /* check_first return and the reason it reports */
    bool        real_check;             /* check_first runs udsota_image_check for the example device instead */
    udsota_reason_t check_reason;
    int         begin_ret, write_ret;   /* SYNC_ERR: refused without queueing; else queued (UDSOTA_PENDING) */
    int         job_result;             /* engine.poll's answer once the queued ops finish (non-zero = worker failed) */
    uint32_t    erase_ms, write_ms;     /* simulated worker time per engine.begin / engine.write */
    uint32_t    job_done_at;
    bool        job_queued;
    uint32_t    begin_size;
    unsigned    writes, aborts;
    unsigned    unverifies;             /* engine.unverify calls (kept out of log so the call orders stay OTA-only) */
    size_t      unverify_at;            /* log_n when engine.unverify last ran: how many OTA calls preceded it */
    size_t      last_write_len;
    uint32_t    last_write_off;         /* the offset engine.write got last */
    uint8_t     first_data[4];          /* first bytes of the first engine.write */
} mock_t;

static mock_t       m;
static uint32_t     g_now;
static udsota_server_t srv;
static uint8_t      g_resp[64];
static size_t       g_resp_len;
static uint8_t      g_blk[UDSOTA_DL_MAX_BLOCK_LEN + 1u];   /* one byte spare for the too-long case */

/* Appends one call letter to the mock's call log, keeping it NUL-terminated. */
static void log_call(char c)
{
    if (m.log_n + 1u < sizeof m.log) {
        m.log[m.log_n++] = c;
        m.log[m.log_n] = '\0';
    }
}

/* Fixed non-zero seed pattern 01..10. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(i + 1);
    return true;
}

/* security.key stand-in: expected key = seed XOR 0x5A; the level is ignored. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(seed[i] ^ 0x5A);
    return true;
}

/* Queues the slot erase (UDSOTA_PENDING): the worker is busy for erase_ms, unless begin_ret refuses it. */
static int mock_begin(void *ctx, uint32_t size)
{
    log_call('B');
    if (m.begin_ret != 0) return m.begin_ret;
    m.begin_size = size;
    m.job_done_at = g_now + m.erase_ms;
    m.job_queued = true;
    return UDSOTA_PENDING;
}

/* Queues a block write behind any queued erase; the data is copied now, as the ESP worker must. */
static int mock_write(void *ctx, uint32_t off, const uint8_t *data, size_t len)
{
    log_call('W');
    if (m.write_ret != 0) return m.write_ret;
    if (m.writes == 0u) memcpy(m.first_data, data, sizeof m.first_data);
    m.writes++;
    m.last_write_len = len;
    m.last_write_off = off;
    m.job_done_at = (m.job_queued ? m.job_done_at : g_now) + m.write_ms;
    m.job_queued = true;
    return UDSOTA_PENDING;
}

/* Counts a fire-and-forget abort. */
static void mock_abort(void *ctx)
{
    log_call('A');
    m.aborts++;
}

/* Counts a synchronous unverify and notes how many OTA calls came before it. */
static void mock_unverify(void *ctx)
{
    m.unverifies++;
    m.unverify_at = m.log_n;
}

/* Unused by the download path; completes at once. */
static int mock_ok(void *ctx) { return 0; }

/* First-block check: logs the call and returns the configured verdict, or with real_check runs the core
 * image rules for a running example dev build at 0.0.0. */
static int mock_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *reason)
{
    log_call('C');
    if (m.real_check) {
        const udsota_image_ctx_t ic = {
            .product = EXAMPLE_PROJECT, .hw_id = EXAMPLE_HW_ID, .partition_layout_id = EXAMPLE_LAYOUT_ID,
            .diag_request_id = EXAMPLE_REQ_ID, .diag_response_id = EXAMPLE_RESP_ID,
            .running_version = {0, 0, 0}, .running_is_release = false, .slot_size = UDSOTA_SLOT_SIZE_DEFAULT,
        };
        *reason = udsota_image_check(first, len, srv.dl_announced, &ic, NULL);
        return *reason == UDSOTA_DL_OK ? 0 : 1;
    }
    *reason = m.check_reason;
    return m.check_ret;
}

/* UDSOTA_PENDING while the queued ops run (g_now < job_done_at), then job_result. */
static int mock_poll(void *ctx)
{
    if (m.job_queued && g_now < m.job_done_at) return UDSOTA_PENDING;
    m.job_queued = false;
    return m.job_result;
}

static udsota_mock_t g_mock;
static const udsota_engine_t ENGINE = {
    .check_first = mock_check_first, .begin = mock_begin, .write = mock_write, .verify = mock_ok,
    .activate = mock_ok, .confirm = mock_ok, .abort = mock_abort, .unverify = mock_unverify,
    .poll = mock_poll, .status = udsota_mock_status, .ctx = &g_mock,
};
static const udsota_security_t SECURITY = {.rng16 = mock_rng16, .key = mock_key};

/* Boots the server on engine (ENGINE or a copy) with the mock's config and hooks. */
static void boot(const udsota_engine_t *engine)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, engine, &SECURITY, &hooks);
}

/* Fresh server and mock at T0; the erase takes 3.3 s (1.34 MB) and a block write 15 ms; the gate allows. */
void setUp(void)
{
    memset(&m, 0, sizeof m);
    m.erase_ms = 3300u;
    m.write_ms = 15u;
    udsota_mock_clear(&g_mock);
    g_now = T0;
    boot(&ENGINE);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Asserts the last response is exactly the bytes listed. */
#define EXPECT(...) do {                                                       \
        const uint8_t e_[] = {__VA_ARGS__};                                    \
        TEST_ASSERT_EQUAL_UINT(sizeof e_, g_resp_len);                         \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(e_, g_resp, sizeof e_);                   \
    } while (0)

/* Sends one request at g_now; returns the immediate response length (0 = none yet) and keeps it in g_resp. */
static size_t send(const uint8_t *req, size_t len)
{
    g_resp_len = udsota_on_request(&srv, req, len, g_resp, sizeof g_resp, g_now);
    return g_resp_len;
}

/* Polls every 10 ms until a final response, asserting each interim one is 7F 36 78; fails after 100 s. */
static size_t finish_job(unsigned *pending_out)
{
    unsigned pending = 0;
    for (uint32_t waited = 0; waited < 100000u; waited += 10u) {
        g_now += 10u;
        const size_t n = udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
        if (n == 3u && g_resp[0] == UDSOTA_NEG_RESPONSE && g_resp[2] == UDSOTA_NRC_RESPONSE_PENDING) {
            TEST_ASSERT_EQUAL_HEX8(UDSOTA_SID_TRANSFER_DATA, g_resp[1]);
            pending++;
            continue;
        }
        if (n > 0u) {
            g_resp_len = n;
            if (pending_out != NULL) *pending_out = pending;
            return n;
        }
    }
    TEST_FAIL_MESSAGE("the 0x36 job never finished");
    return 0;
}

/* Sends 36 <bsc> with len pattern bytes (byte i = bsc*7 + i); returns the immediate response length. */
static size_t send_block(uint8_t bsc, size_t len)
{
    g_blk[0] = UDSOTA_SID_TRANSFER_DATA;
    g_blk[1] = bsc;
    for (size_t i = 0; i < len; i++) g_blk[2u + i] = (uint8_t)(bsc * 7u + i);
    return send(g_blk, len + 2u);
}

/* Sends one block and, if the server started a job, polls it to its final response. */
static size_t transfer(uint8_t bsc, size_t len, unsigned *pending_out)
{
    if (pending_out != NULL) *pending_out = 0;
    return send_block(bsc, len) != 0u ? g_resp_len : finish_job(pending_out);
}

/* 10 02, then 27 03 / 27 04 with the mock key: programming session, level 03 unlocked. */
static void enter_programming(void)
{
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, g_resp[1]);
    const uint8_t seed_req[] = {UDSOTA_SID_SECURITY, UDSOTA_SA_SEED_PROGRAMMING};
    send(seed_req, sizeof seed_req);
    TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_SEED_LEN, g_resp_len);
    TEST_ASSERT_EQUAL_HEX8(0x67, g_resp[0]);
    uint8_t key[2u + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, UDSOTA_SA_KEY_PROGRAMMING};
    for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) key[2u + i] = (uint8_t)(g_resp[2u + i] ^ 0x5A);
    send(key, sizeof key);
    EXPECT(0x67, 0x04);
}

/* Builds a 34 request with the given DFI, ALFID, address and size into r (UDSOTA_DL_REQ_LEN bytes). */
static void build_34(uint8_t *r, uint8_t dfi, uint8_t alfid, uint32_t addr, uint32_t size)
{
    r[0] = UDSOTA_SID_REQUEST_DOWNLOAD;
    r[1] = dfi;
    r[2] = alfid;
    r[3] = (uint8_t)(addr >> 24); r[4] = (uint8_t)(addr >> 16); r[5] = (uint8_t)(addr >> 8); r[6] = (uint8_t)addr;
    r[7] = (uint8_t)(size >> 24); r[8] = (uint8_t)(size >> 16); r[9] = (uint8_t)(size >> 8); r[10] = (uint8_t)size;
}

/* Sends 34 00 44 <addr 0> <size> and asserts 74 20 0F FF. */
static void request_download(uint32_t size)
{
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, size);
    send(r, sizeof r);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
}

/* Sends 37 and returns the immediate response length. */
static size_t send_exit(void)
{
    const uint8_t r[] = {UDSOTA_SID_TRANSFER_EXIT};
    return send(r, sizeof r);
}

/* 34 opens a download: 74 20 0F FF, counter 1, nothing received, verified cleared, F1F1 reset, flash untouched. */
static void test_request_download_accepts(void)
{
    enter_programming();
    srv.slot_verified = true;
    srv.last_dl.reason_code = UDSOTA_DL_SIG_FAILED;
    request_download(TWO_BLOCKS);
    TEST_ASSERT_TRUE(srv.download_active);
    TEST_ASSERT_FALSE(srv.ota_open);
    TEST_ASSERT_EQUAL_HEX8(0x01, srv.next_bsc);
    TEST_ASSERT_EQUAL_UINT32(TWO_BLOCKS, srv.dl_announced);
    TEST_ASSERT_EQUAL_UINT32(0, srv.dl_received);
    TEST_ASSERT_FALSE(srv.slot_verified);
    TEST_ASSERT_FALSE(srv.dl_complete);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_STRING("", m.log);
}

/* Bad DFI, ALFID, a non-zero address, size 0 or one byte over the slot each get 0x31; a short request 0x13. */
static void test_request_download_bad_format(void)
{
    enter_programming();
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, 0x11, UDSOTA_DL_ALFID, 0u, 4096u);                       send(r, sizeof r); EXPECT(0x7F, 0x34, 0x31);
    build_34(r, UDSOTA_DL_DFI, 0x24, 0u, 4096u);                         send(r, sizeof r); EXPECT(0x7F, 0x34, 0x31);
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0x1000u, 4096u);            send(r, sizeof r); EXPECT(0x7F, 0x34, 0x31);
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 0u);                    send(r, sizeof r); EXPECT(0x7F, 0x34, 0x31);
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, UDSOTA_SLOT_SIZE_DEFAULT + 1u);
    send(r, sizeof r); EXPECT(0x7F, 0x34, 0x31);
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, UDSOTA_DL_REQ_LEN - 1u); EXPECT(0x7F, 0x34, 0x13);
    TEST_ASSERT_FALSE(srv.download_active);
    request_download(UDSOTA_SLOT_SIZE_DEFAULT);                        /* exactly the slot fits */
}

/* 34/36/37 outside programming get 0x7F; 34 in programming without the level-03 key gets 0x33. */
static void test_download_needs_programming_and_key(void)
{
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x7F);
    send_block(1, 16);  EXPECT(0x7F, 0x36, 0x7F);
    send_exit();        EXPECT(0x7F, 0x37, 0x7F);
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x33);
    TEST_ASSERT_FALSE(srv.download_active);
}

/* 34 is refused by a gate NRC (passed through), a PENDING_VERIFY image (0x22), or a download already open (0x22). */
static void test_request_download_refused_by_core_and_gate(void)
{
    enter_programming();
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0x22;               send(r, sizeof r); EXPECT(0x7F, 0x34, 0x22);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0x88;               send(r, sizeof r); EXPECT(0x7F, 0x34, 0x88);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0;
    g_mock.status.running_state = UDSOTA_IMG_PENDING_VERIFY;       send(r, sizeof r); EXPECT(0x7F, 0x34, 0x22);
    g_mock.status.running_state = UDSOTA_IMG_VALID;
    request_download(4096u);
    /* The download is the server's own state: a second 34 is refused. */
    send(r, sizeof r); EXPECT(0x7F, 0x34, 0x22);
}

/* 10 02 and 34 are both refused while the boot slot is not the running slot. */
static void test_refused_while_boot_slot_not_running(void)
{
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA1;
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    EXPECT(0x7F, 0x10, 0x22);
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA0;
    enter_programming();
    g_mock.status.boot_slot = UDSOTA_SLOT_OTA1;
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);
    EXPECT(0x7F, 0x34, 0x22);
    TEST_ASSERT_FALSE(srv.download_active);
}

/* A full 4093-byte block at one CF per 10 ms (5.86 s, longer than S3) completes: S3 stops at the FF. */
static void test_full_block_at_10ms_per_cf_completes_without_fallback(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    g_now += 10u;
    udsota_on_rx_first_frame(&srv, g_now);            /* FF of block 1 */
    for (unsigned cf = 0; cf < 585u; cf++) {              /* 4095-byte message = FF (6 B) + 585 CFs (7 B) */
        g_now += 10u;
        TEST_ASSERT_EQUAL_UINT(0, udsota_poll(&srv, g_resp, sizeof g_resp, g_now));
    }
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_PROGRAMMING, srv.session);
    TEST_ASSERT_TRUE(srv.download_active);
    unsigned pending = 0;
    transfer(0x01, UDSOTA_DL_MAX_DATA, &pending);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_TRUE(pending >= 2u);                      /* 3.3 s erase: 0x78 at 40 ms, then every 1.5 s */
    TEST_ASSERT_EQUAL_UINT32(TWO_BLOCKS, m.begin_size);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_DL_MAX_DATA, m.last_write_len);
    const uint8_t first[4] = {0x07, 0x08, 0x09, 0x0A};   /* the pattern for bsc 1 */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first, m.first_data, 4);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.dl_received);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_PROGRAMMING, srv.session);
    transfer(0x02, UDSOTA_DL_MAX_DATA, &pending);            /* page programs only: no 0x78 */
    EXPECT(0x76, 0x02);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, m.last_write_off);   /* engine.write gets the block's offset */
    TEST_ASSERT_EQUAL_UINT(0, pending);
    TEST_ASSERT_EQUAL_STRING("CBWW", m.log);
}

/* The first block is checked before anything is erased; later blocks are not re-checked or re-erased. */
static void test_first_block_checked_before_erase(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_STRING("CBW", m.log);
    TEST_ASSERT_TRUE(srv.ota_open);
    transfer(0x02, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x02);
    TEST_ASSERT_EQUAL_STRING("CBWW", m.log);
}

/* A failed first-block check answers 0x31, records its reason in F1F1, erases nothing and closes the download. */
static void test_first_block_reject(void)
{
    m.check_ret = 1;
    m.check_reason = UDSOTA_DL_BAD_BOARD;
    enter_programming();
    request_download(TWO_BLOCKS);
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x01, UDSOTA_DL_MAX_DATA));   /* answered at once: no job */
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_STRING("C", m.log);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_FALSE(srv.ota_open);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_BOARD, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(0, srv.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.aborts);
    send_block(0x01, 16);
    EXPECT(0x7F, 0x36, 0x24);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_PROGRAMMING, srv.session);    /* the session survives; 34 may retry */
}

/* Sends 36 01 carrying the example first block with its descriptor magic set to magic, padded to a full block. */
static size_t send_example_first_block(uint32_t magic)
{
    g_blk[0] = UDSOTA_SID_TRANSFER_DATA;
    g_blk[1] = 0x01;
    for (size_t i = 0; i < UDSOTA_DL_MAX_DATA; i++) g_blk[2u + i] = (uint8_t)(i * 7u);
    example_first_block(&g_blk[2]);
    example_put_le32(&g_blk[2u + UDSOTA_IMG_DESC_OFFSET], magic);
    return send(g_blk, 2u + UDSOTA_DL_MAX_DATA);
}

/* With the real image rules, a first block whose descriptor magic is wrong (0xDEADBEEF) is refused at once with
 * 0x31: F1F1 reports reason 3 (UDSOTA_DL_BAD_BOARD) with 0 bytes, and nothing was erased or written. */
static void test_wrong_descriptor_magic_refused_before_erase(void)
{
    m.real_check = true;
    enter_programming();
    request_download(TWO_BLOCKS);
    TEST_ASSERT_NOT_EQUAL(0, send_example_first_block(0xDEADBEEFu));   /* answered at once: no job */
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_STRING("C", m.log);
    TEST_ASSERT_EQUAL_UINT32(0, m.begin_size);
    TEST_ASSERT_EQUAL_UINT(0, m.writes);
    const uint8_t rd[] = {UDSOTA_SID_READ_DID, 0xF1, 0xF1};
    send(rd, sizeof rd);
    EXPECT(0x62, 0xF1, 0xF1, UDSOTA_DL_BAD_BOARD, 0x00, 0x00, 0x00, 0x00);
}

/* Control for the test above: the same block with the right magic passes the real rules, then is erased and written. */
static void test_example_first_block_accepted(void)
{
    m.real_check = true;
    enter_programming();
    request_download(TWO_BLOCKS);
    TEST_ASSERT_EQUAL_UINT(0, send_example_first_block(UDSOTA_IMG_DESC_MAGIC));   /* a job: erase, then write */
    finish_job(NULL);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_STRING("CBW", m.log);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
}

/* A check that fails without naming a reason is recorded as UDSOTA_DL_BAD_HEADER, never UDSOTA_DL_OK. */
static void test_first_block_reject_without_reason(void)
{
    m.check_ret = 1;
    m.check_reason = UDSOTA_DL_OK;
    enter_programming();
    request_download(TWO_BLOCKS);
    send_block(0x01, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_HEADER, srv.last_dl.reason_code);
}

/* A resend of the last accepted block (its 76 was lost) is answered 76 at once and not rewritten. */
static void test_repeat_of_last_block_positive_without_rewrite(void)
{
    enter_programming();
    request_download(3u * UDSOTA_DL_MAX_DATA);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x01, UDSOTA_DL_MAX_DATA));
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.dl_received);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.repeated_blocks);
    TEST_ASSERT_EQUAL_HEX8(0x02, srv.next_bsc);
    transfer(0x02, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x02);
    TEST_ASSERT_EQUAL_UINT(2, m.writes);
}

/* The final block has filled the announced size; its resend is still a repeat (76), not an overrun (0x71). */
static void test_repeat_of_final_block_is_not_overrun(void)
{
    enter_programming();
    request_download(UDSOTA_DL_MAX_DATA + 100u);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);  EXPECT(0x76, 0x01);
    transfer(0x02, 100u, NULL);             EXPECT(0x76, 0x02);
    TEST_ASSERT_EQUAL_UINT32(srv.dl_announced, srv.dl_received);
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x02, 100u));
    EXPECT(0x76, 0x02);
    TEST_ASSERT_EQUAL_UINT(2, m.writes);
    TEST_ASSERT_TRUE(srv.download_active);
    send_exit();
    EXPECT(0x77);
}

/* Before any block is accepted there is nothing to repeat: counter 0x00 is a plain mismatch (0x73). */
static void test_bsc_zero_before_first_block_is_0x73(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    send_block(0x00, 16);
    EXPECT(0x7F, 0x36, 0x73);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.seq_errors);
    TEST_ASSERT_EQUAL_STRING("", m.log);
    TEST_ASSERT_TRUE(srv.download_active);
    transfer(0x01, 16, NULL);
    EXPECT(0x76, 0x01);
}

/* A counter that is neither next nor a repeat gets 0x73; the transfer stays open and resumes at the right counter. */
static void test_wrong_bsc_0x73_transfer_stays_open(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    send_block(0x03, 16);
    EXPECT(0x7F, 0x36, 0x73);
    TEST_ASSERT_TRUE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.seq_errors);
    transfer(0x02, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x02);
}

/* After 0xFF the counter wraps to 0x00, not 0x01; a resend of 0x00 is then a repeat. */
static void test_bsc_wraps_ff_to_00(void)
{
    m.erase_ms = 20u;
    enter_programming();
    request_download(300u * 16u);
    for (unsigned i = 1; i <= 255u; i++) {
        transfer((uint8_t)i, 16, NULL);
        TEST_ASSERT_EQUAL_HEX8(0x76, g_resp[0]);
        TEST_ASSERT_EQUAL_HEX8((uint8_t)i, g_resp[1]);
    }
    TEST_ASSERT_EQUAL_HEX8(0x00, srv.next_bsc);
    send_block(0x01, 16);
    EXPECT(0x7F, 0x36, 0x73);
    transfer(0x00, 16, NULL);
    EXPECT(0x76, 0x00);
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x00, 16));
    EXPECT(0x76, 0x00);
    TEST_ASSERT_EQUAL_UINT(256, m.writes);
    TEST_ASSERT_EQUAL_UINT32(256u * 16u, srv.dl_received);
}

/* A block past the announced size gets 0x71 and ends the transfer; the open slot is aborted (kept for resume). */
static void test_overrun_0x71_ends_transfer(void)
{
    enter_programming();
    request_download(UDSOTA_DL_MAX_DATA + 10u);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    send_block(0x02, 11u);
    EXPECT(0x7F, 0x36, 0x71);
    TEST_ASSERT_EQUAL_STRING("CBWA", m.log);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_FALSE(srv.ota_open);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.aborts);
    send_block(0x02, 10u);
    EXPECT(0x7F, 0x36, 0x24);
}

/* An oversized first block is refused as an overrun before the image check, so nothing is checked or erased. */
static void test_first_block_overrun_touches_nothing(void)
{
    enter_programming();
    request_download(100u);
    send_block(0x01, 101u);
    EXPECT(0x7F, 0x36, 0x71);
    TEST_ASSERT_EQUAL_STRING("", m.log);
    TEST_ASSERT_FALSE(srv.download_active);
}

/* 0x36 needs SID + BSC + 1..4093 data bytes (0x13 otherwise, transfer untouched); with no download open, 0x24. */
static void test_transfer_data_length_and_sequence(void)
{
    enter_programming();
    send_block(0x01, 16);
    EXPECT(0x7F, 0x36, 0x24);                             /* no 34 yet */
    request_download(TWO_BLOCKS);
    send_block(0x01, UDSOTA_DL_MAX_DATA + 1u);
    EXPECT(0x7F, 0x36, 0x13);
    send_block(0x01, 0);
    EXPECT(0x7F, 0x36, 0x13);
    const uint8_t sid_only[] = {UDSOTA_SID_TRANSFER_DATA};
    send(sid_only, sizeof sid_only);
    EXPECT(0x7F, 0x36, 0x13);
    TEST_ASSERT_TRUE(srv.download_active);
    TEST_ASSERT_EQUAL_STRING("", m.log);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x01);
}

/* 37 before the announced size is reached gets 0x24 and the transfer stays open; at the size it answers 77. */
static void test_transfer_exit_checks_byte_count(void)
{
    enter_programming();
    request_download(UDSOTA_DL_MAX_DATA + 50u);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    send_exit();
    EXPECT(0x7F, 0x37, 0x24);
    TEST_ASSERT_TRUE(srv.download_active);
    transfer(0x02, 50u, NULL);
    EXPECT(0x76, 0x02);
    send_exit();
    EXPECT(0x77);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_TRUE(srv.ota_open);                       /* FF01 closes the handle with engine.verify */
    TEST_ASSERT_TRUE(srv.dl_complete);                    /* FF01's precondition, with ota_open */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA + 50u, srv.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_UINT(0, m.aborts);
    send_exit();
    EXPECT(0x7F, 0x37, 0x24);                             /* nothing open any more */
}

/* 37 with a parameter byte is a length error and leaves the transfer open. */
static void test_transfer_exit_bad_length(void)
{
    enter_programming();
    request_download(16u);
    transfer(0x01, 16u, NULL);
    const uint8_t r[] = {UDSOTA_SID_TRANSFER_EXIT, 0x00};
    send(r, sizeof r);
    EXPECT(0x7F, 0x37, 0x13);
    TEST_ASSERT_TRUE(srv.download_active);
}

/* A new 34 after a finished but unverified download releases the old handle before the next erase. */
static void test_new_download_releases_unverified_image(void)
{
    enter_programming();
    request_download(16u);
    transfer(0x01, 16u, NULL);
    send_exit();
    EXPECT(0x77);
    TEST_ASSERT_TRUE(srv.ota_open);
    request_download(32u);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_FALSE(srv.ota_open);
    transfer(0x01, 32u, NULL);                            /* checked and erased afresh */
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_STRING("CBWACBW", m.log);
}

/* During a flash job every request but 3E gets 0x21 (a retry can't overwrite data mid-write); 3E is answered. */
static void test_requests_during_job(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    TEST_ASSERT_EQUAL_UINT(0, send_block(0x01, UDSOTA_DL_MAX_DATA));   /* queued: erase then write */
    g_now += 20u;
    const uint8_t rd[] = {UDSOTA_SID_READ_DID, 0xF1, 0xF0};
    send(rd, sizeof rd);
    EXPECT(0x7F, 0x22, 0x21);
    const uint8_t tp[] = {UDSOTA_SID_TESTER_PRESENT, 0x00};
    send(tp, sizeof tp);
    EXPECT(0x7E, 0x00);
    send_block(0x01, UDSOTA_DL_MAX_DATA);                    /* an impatient resend of the same block */
    EXPECT(0x7F, 0x36, 0x21);
    finish_job(NULL);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
}

/* The server can't tell testers apart on one request ID, so an app that detects a second tester (or a second
 * device on the IDs) refuses CONTINUE_TRANSFER in its gate. Mid-transfer that ends the download and the session. */
static void test_gate_denial_mid_transfer_ends_it(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = 0x22;
    send_block(0x02, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x22);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, srv.session);
    TEST_ASSERT_EQUAL_UINT8(0, srv.security);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.aborts);
    TEST_ASSERT_EQUAL_UINT16(0, srv.counters.stmin_violations);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.last_dl.bytes_received);
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);
    EXPECT(0x7F, 0x34, 0x7F);                             /* back in the default session */
}

/* A second tester's frames on the request ID mid-download: its 10 02 is refused (download open) and leaves the transfer
 * alone; its 10 03 is accepted and ends the transfer and the unlock, so the first tester's next 0x36 is 0x7F. */
static void test_second_tester_frame_ends_transfer(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    const uint8_t prog[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(prog, sizeof prog);
    EXPECT(0x7F, 0x10, 0x22);
    TEST_ASSERT_TRUE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT(0, m.aborts);
    const uint8_t ext[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_EXTENDED};
    send(ext, sizeof ext);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT8(0, srv.security);
    send_block(0x02, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x7F);
    TEST_ASSERT_EQUAL_UINT(1, m.writes);
}

/* A gate NRC between blocks (0x88 here; an app's lost interlock might send 0x22) is passed through on the
 * next 0x36 and ends the session. */
static void test_gate_nrc_mid_transfer_passed_through(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = 0x88;
    send_block(0x02, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x88);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, srv.session);
}

/* At an FC point a median under 0.8 x STmin withholds the FC, counts it and the STmin violation, and ends the session. */
static void test_fc_check_withholds_on_stmin_violation(void)
{
    TEST_ASSERT_TRUE(udsota_fc_check(&srv, 100u, 2000u, g_now));   /* no download: never withheld */
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    TEST_ASSERT_TRUE(udsota_fc_check(&srv, 1600u, 2000u, g_now));   /* exactly 0.8 x STmin passes */
    TEST_ASSERT_FALSE(udsota_fc_check(&srv, 1599u, 2000u, g_now));
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.stmin_violations);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.aborts);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, srv.session);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_TRUE(udsota_fc_check(&srv, 1599u, 2000u, g_now));   /* nothing open any more */
}

/* At an FC point a refusing gate (an app's lost interlock) withholds the FC without counting an STmin violation. */
static void test_fc_check_withholds_when_gate_refuses(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = 0x22;
    TEST_ASSERT_FALSE(udsota_fc_check(&srv, UDSOTA_CF_MEDIAN_NONE, 2000u, g_now));
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(0, srv.counters.stmin_violations);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, srv.session);
}

/* An FC check is never judged while a job runs: the client is waiting, not sending CFs. */
static void test_fc_check_ignored_during_job(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    TEST_ASSERT_EQUAL_UINT(0, send_block(0x01, UDSOTA_DL_MAX_DATA));
    g_mock.gate_nrc[UDSOTA_OP_CONTINUE_TRANSFER] = 0x22;
    TEST_ASSERT_TRUE(udsota_fc_check(&srv, 100u, 2000u, g_now));
    TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER]);   /* the 36's own; none at the FC */
    TEST_ASSERT_EQUAL_UINT16(0, srv.counters.withheld_fcs);
    TEST_ASSERT_TRUE(srv.download_active);
}

/* The CF timing an FC point recorded is re-judged on the 0x36 that follows. */
static void test_fc_timing_rechecked_on_transfer_data(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    TEST_ASSERT_TRUE(udsota_fc_check(&srv, 1700u, 2000u, g_now));
    srv.cf_median_us = 1000u;                             /* as if the last window had come in fast */
    send_block(0x02, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x22);
    TEST_ASSERT_EQUAL_UINT16(1, srv.counters.stmin_violations);
    TEST_ASSERT_EQUAL_UINT16(0, srv.counters.withheld_fcs);
}

/* A worker failure on a later block answers 0x72, aborts the slot and records UDSOTA_DL_FLASH_ERROR in F1F1. */
static void test_worker_write_failure_0x72(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    m.job_result = 1;
    transfer(0x02, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x7F, 0x36, 0x72);
    TEST_ASSERT_EQUAL_STRING("CBWWA", m.log);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_FLASH_ERROR, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.last_dl.bytes_received);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.dl_received);
    send_block(0x02, UDSOTA_DL_MAX_DATA);
    EXPECT(0x7F, 0x36, 0x24);
}

/* A failed erase on the first block fails its queued write too: 0x72, UDSOTA_DL_FLASH_ERROR, nothing counted as received. */
static void test_worker_erase_failure_0x72(void)
{
    m.job_result = 1;
    enter_programming();
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x7F, 0x36, 0x72);
    TEST_ASSERT_EQUAL_STRING("CBWA", m.log);
    TEST_ASSERT_EQUAL_UINT32(0, srv.dl_received);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_FLASH_ERROR, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(0, srv.last_dl.bytes_received);
}

/* An erase or a write the worker could not even queue answers 0x72 at once and records UDSOTA_DL_FLASH_ERROR. */
static void test_op_not_queued_0x72(void)
{
    enter_programming();
    request_download(TWO_BLOCKS);
    m.begin_ret = SYNC_ERR;
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x01, UDSOTA_DL_MAX_DATA));
    EXPECT(0x7F, 0x36, 0x72);
    TEST_ASSERT_EQUAL_STRING("CB", m.log);                /* nothing opened, so nothing to abort */
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_FALSE(srv.ota_open);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_FLASH_ERROR, srv.last_dl.reason_code);

    memset(&m, 0, sizeof m);
    m.write_ms = 15u;
    request_download(TWO_BLOCKS);
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    m.write_ret = SYNC_ERR;
    TEST_ASSERT_NOT_EQUAL(0, send_block(0x02, UDSOTA_DL_MAX_DATA));
    EXPECT(0x7F, 0x36, 0x72);
    TEST_ASSERT_FALSE(srv.download_active);
    TEST_ASSERT_EQUAL_UINT(1, m.aborts);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_FLASH_ERROR, srv.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_DL_MAX_DATA, srv.last_dl.bytes_received);
}

/* An accepted 34 un-verifies the other slot once, before anything is queued, even with FF01 passed. */
static void test_accepted_download_unverifies_slot(void)
{
    enter_programming();
    srv.slot_verified = true;                             /* as if FF01 had passed on an earlier download */
    request_download(TWO_BLOCKS);
    TEST_ASSERT_EQUAL_UINT(1, m.unverifies);
    TEST_ASSERT_EQUAL_UINT(0, m.unverify_at);             /* no OTA op ran before it */
    TEST_ASSERT_FALSE(srv.slot_verified);                 /* a following 31 01 F001 must get 0x24 */
    transfer(0x01, UDSOTA_DL_MAX_DATA, NULL);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1, m.unverifies);              /* 0x36 does not call it again */
}

/* Over a finished, unverified download the unverify still comes before the old handle's abort is queued. */
static void test_unverify_precedes_old_handle_abort(void)
{
    enter_programming();
    request_download(16u);
    transfer(0x01, 16u, NULL);
    send_exit();
    EXPECT(0x77);
    request_download(32u);
    TEST_ASSERT_EQUAL_UINT(2, m.unverifies);
    TEST_ASSERT_EQUAL_UINT(3, m.unverify_at);             /* after "CBW", before the 'A' */
    TEST_ASSERT_EQUAL_STRING("CBWA", m.log);
}

/* Every refused 34 (0x7F, 0x33, 0x13, 0x22, 0x31) leaves the verified state alone and never calls engine.unverify. */
static void test_refused_download_does_not_unverify(void)
{
    srv.slot_verified = true;
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x7F);         /* default session */
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x33);         /* programming, locked */
    enter_programming();
    send(r, UDSOTA_DL_REQ_LEN - 1u);  EXPECT(0x7F, 0x34, 0x13);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0x22;
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x22);
    g_mock.gate_nrc[UDSOTA_OP_START_DOWNLOAD] = 0;
    build_34(r, 0x11, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x31);
    TEST_ASSERT_EQUAL_UINT(0, m.unverifies);
    TEST_ASSERT_TRUE(srv.slot_verified);
    request_download(4096u);
    TEST_ASSERT_EQUAL_UINT(1, m.unverifies);
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 4096u);
    send(r, sizeof r);  EXPECT(0x7F, 0x34, 0x22);         /* a download is already open */
    TEST_ASSERT_EQUAL_UINT(1, m.unverifies);
}

/* engine.unverify is optional: a platform that leaves it NULL still opens and runs a download. */
static void test_null_unverify_op_is_safe(void)
{
    static udsota_engine_t no_unverify;
    no_unverify = ENGINE;
    no_unverify.unverify = NULL;
    boot(&no_unverify);
    enter_programming();
    srv.slot_verified = true;
    request_download(16u);
    TEST_ASSERT_FALSE(srv.slot_verified);
    transfer(0x01, 16u, NULL);
    EXPECT(0x76, 0x01);
    send_exit();
    EXPECT(0x77);
    TEST_ASSERT_EQUAL_UINT(0, m.unverifies);
}

/* engine.slot_size bounds a 34 when set: one byte over a 0x1000 slot is 0x31, exactly the slot is accepted. */
static void test_request_download_bounded_by_engine_slot_size(void)
{
    static udsota_engine_t small_slot;
    small_slot = ENGINE;
    small_slot.slot_size = 0x1000u;
    boot(&small_slot);
    enter_programming();
    uint8_t r[UDSOTA_DL_REQ_LEN];
    build_34(r, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0u, 0x1001u);
    send(r, sizeof r);
    EXPECT(0x7F, 0x34, 0x31);
    TEST_ASSERT_FALSE(srv.download_active);
    request_download(0x1000u);                                /* asserts 74 20 0F FF */
    TEST_ASSERT_EQUAL_UINT32(0x1000u, srv.dl_announced);
}

/* Runs every download test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_request_download_accepts);
    RUN_TEST(test_request_download_bad_format);
    RUN_TEST(test_request_download_bounded_by_engine_slot_size);
    RUN_TEST(test_download_needs_programming_and_key);
    RUN_TEST(test_request_download_refused_by_core_and_gate);
    RUN_TEST(test_refused_while_boot_slot_not_running);
    RUN_TEST(test_full_block_at_10ms_per_cf_completes_without_fallback);
    RUN_TEST(test_first_block_checked_before_erase);
    RUN_TEST(test_first_block_reject);
    RUN_TEST(test_first_block_reject_without_reason);
    RUN_TEST(test_wrong_descriptor_magic_refused_before_erase);
    RUN_TEST(test_example_first_block_accepted);
    RUN_TEST(test_repeat_of_last_block_positive_without_rewrite);
    RUN_TEST(test_repeat_of_final_block_is_not_overrun);
    RUN_TEST(test_bsc_zero_before_first_block_is_0x73);
    RUN_TEST(test_wrong_bsc_0x73_transfer_stays_open);
    RUN_TEST(test_bsc_wraps_ff_to_00);
    RUN_TEST(test_overrun_0x71_ends_transfer);
    RUN_TEST(test_first_block_overrun_touches_nothing);
    RUN_TEST(test_transfer_data_length_and_sequence);
    RUN_TEST(test_transfer_exit_checks_byte_count);
    RUN_TEST(test_transfer_exit_bad_length);
    RUN_TEST(test_new_download_releases_unverified_image);
    RUN_TEST(test_requests_during_job);
    RUN_TEST(test_gate_denial_mid_transfer_ends_it);
    RUN_TEST(test_second_tester_frame_ends_transfer);
    RUN_TEST(test_gate_nrc_mid_transfer_passed_through);
    RUN_TEST(test_fc_check_withholds_on_stmin_violation);
    RUN_TEST(test_fc_check_withholds_when_gate_refuses);
    RUN_TEST(test_fc_check_ignored_during_job);
    RUN_TEST(test_fc_timing_rechecked_on_transfer_data);
    RUN_TEST(test_worker_write_failure_0x72);
    RUN_TEST(test_worker_erase_failure_0x72);
    RUN_TEST(test_op_not_queued_0x72);
    RUN_TEST(test_accepted_download_unverifies_slot);
    RUN_TEST(test_unverify_precedes_old_handle_abort);
    RUN_TEST(test_refused_download_does_not_unverify);
    RUN_TEST(test_null_unverify_op_is_safe);
    return UNITY_END();
}
