/* Host tests for udsota_isotp at the buffer sizes a build sets: CMakeLists.txt builds this file at the defaults and
 * again with UDSOTA_ISOTP_RX_MAX and UDSOTA_ISOTP_RESP_MAX set, and each build checks the rules against its own sizes.
 * The receive limit and 34's maxNumberOfBlockLength follow RX_MAX, and the largest answer, a 22 DID or a 19 list of
 * (RESP_MAX - 3) / 4 DTCs, follows RESP_MAX. The real adapter, server, updater and isotp-c run on a fake bus with one
 * fake clock; the test is the client, as in test_udsota_isotp.c. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_wire.h"
#include "udsota_keys.h"
#include "udsota_isotp.h"

#define REQ_ID     0x710u
#define RESP_ID    0x718u
#define RX         UDSOTA_ISOTP_RX_MAX
#define RESP       UDSOTA_ISOTP_RESP_MAX
#define IDLE       (RX < UDSOTA_ISOTP_RX_LIMIT_IDLE ? RX : UDSOTA_ISOTP_RX_LIMIT_IDLE)   /* limit outside a download */
#define DTC_CAP    ((RESP - 3u) / 4u)        /* the most DTCs a 59 02 or 59 0A holds */
#define DID_FULL   0x0200u                   /* RESP - 3 bytes: fills the response buffer */
#define DID_OVER   0x0201u                   /* RESP - 2 bytes: one past it */
#define DID_500    0x0202u                   /* 500 bytes: fits only a RESP_MAX of 503 or more */
#define CF_GAP_US  2000u
#define T0_US      20000000u                 /* 20 s: past 0x27's post-boot delay */
#define ANSWER_MS  2000u                     /* room for a 4,095-byte answer's CFs, a few ms apart */

/* Fake clock, bus and client state. */
static uint32_t s_now_us;
static bool     s_fc_owed;                   /* the client owes an FC for the adapter's FF, fed at the next service */
static unsigned s_fc_n;                      /* FCs the adapter sent for the client's requests */
static uint8_t  s_fc_last;                   /* the last one's first byte: 30 CTS, 32 overflow */
static uint8_t  s_resp[4095];
static uint32_t s_resp_len, s_resp_got;
static bool     s_resp_done;
static uint8_t  s_req[4095 + 1];

/* Mock engine and hooks state. */
static uint32_t s_written;
static bool     s_data_ok;
static size_t   s_dtc_n;                     /* DTCs dtc_get reports */
static uint16_t s_max_block_len;             /* cfg.max_block_len for the next init_all (0 = the default) */
static bool     s_secured;                   /* init_all with a 64-byte key the verifier checks */
static unsigned s_verify_calls;

static udsota_server_t     s_srv;
static udsota_isotp_t      s_tp;
static udsota_isotp_bufs_t s_bufs;
static udsota_config_t     s_cfg;
static udsota_engine_t     s_eng;
static udsota_hooks_t      s_hooks;
static udsota_security_t   s_sec;
static udsota_can_t        s_can;

/* The fake clock in milliseconds. */
static uint32_t now_ms(void) { return s_now_us / 1000u; }
/* Deterministic byte i of a block, a DID or a key. */
static uint8_t pattern(uint32_t i) { return (uint8_t)(i * 13u + 5u); }

/* engine.check_first: every first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin: the erase succeeds at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }
/* engine.write: checks the bytes against pattern(). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        s_data_ok = s_data_ok && d[i] == pattern(off + (uint32_t)i);
    }
    s_written += (uint32_t)n;
    return 0;
}
/* engine.verify, activate and confirm: pass. */
static int eng_ok(void *ctx) { return 0; }
/* engine.abort: nothing to undo. */
static void eng_abort(void *ctx) {}
/* engine.poll: nothing pending. */
static int eng_poll(void *ctx) { return 0; }
/* engine.status: running slot 0 VALID, the other slot empty. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->running_slot = UDSOTA_SLOT_OTA0;
    out->boot_slot = UDSOTA_SLOT_OTA0;
    out->running_state = UDSOTA_IMG_VALID;
    out->other_slot_state = UDSOTA_OTHER_EMPTY;
}

/* hooks.did_read: DID_FULL, DID_OVER and DID_500 in pattern bytes; a DID longer than max returns its length unwritten. */
static size_t hook_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    const size_t n = did == DID_FULL ? RESP - 3u : did == DID_OVER ? RESP - 2u : did == DID_500 ? 500u : 0u;
    if (n != 0u && n <= max) {
        for (size_t i = 0; i < n; i++) {
            buf[i] = pattern((uint32_t)i);
        }
    }
    return n;
}
/* hooks.dtc_get: s_dtc_n DTCs, 10 00 00 + i, each with status 09. */
static bool hook_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    if (i >= s_dtc_n) {
        return false;
    }
    out->dtc = 0x100000u + (uint32_t)i;
    out->status = 0x09u;
    return true;
}
/* security.rng16: a fixed non-zero seed. */
static bool sec_rng16(void *ctx, uint8_t out[16])
{
    memset(out, 0x5A, 16);
    return true;
}
/* security.verify: 1 for pattern() bytes of the right length, else wrong. */
static int sec_verify(void *ctx, const uint8_t seed[16], uint8_t level, const uint8_t *key, size_t key_len)
{
    s_verify_calls++;
    if (key_len != UDSOTA_KEYS_SIG_LEN) {
        return 0;
    }
    for (size_t i = 0; i < key_len; i++) {
        if (key[i] != pattern((uint32_t)i)) {
            return 0;
        }
    }
    return 1;
}

/* Client side of every frame the adapter sends: reassembles answers, owes an FC for an FF, records FCs. */
static void client_rx(const uint8_t *d)
{
    uint32_t take;
    switch (d[0] >> 4) {
    case 0x0:
        s_resp_len = d[0] & 0x0Fu;
        memcpy(s_resp, &d[1], s_resp_len);
        s_resp_done = true;
        break;
    case 0x1:
        s_resp_len = ((uint32_t)(d[0] & 0x0Fu) << 8) | d[1];
        TEST_ASSERT_TRUE(s_resp_len <= RESP);        /* never past the response buffer */
        memcpy(s_resp, &d[2], 6);
        s_resp_got = 6;
        s_resp_done = false;
        s_fc_owed = true;
        break;
    case 0x2:
        take = s_resp_len - s_resp_got;
        take = take > 7u ? 7u : take;
        memcpy(&s_resp[s_resp_got], &d[1], take);
        s_resp_got += take;
        s_resp_done = s_resp_got >= s_resp_len;
        break;
    case 0x3:
        s_fc_n++;
        s_fc_last = d[0];
        break;
    default:
        break;
    }
}

/* can.send: hands every frame to the client. */
static int can_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    TEST_ASSERT_EQUAL_HEX16(RESP_ID, id);
    client_rx(data);
    return 0;
}
/* can.tx_pending: the fake driver is always empty. */
static uint32_t can_tx_pending(void *ctx) { return 0u; }
/* can.now_us: the one fake clock. */
static uint32_t can_now_us(void *ctx) { return s_now_us; }

/* Builds the server and adapter: the mock engine, the DID and DTC hooks, security when s_secured, the fake bus. */
static void init_all(void)
{
    s_cfg = (udsota_config_t){ .req_id = REQ_ID, .resp_id = RESP_ID, .max_block_len = s_max_block_len };
    s_eng = (udsota_engine_t){ .check_first = eng_check_first, .begin = eng_begin, .write = eng_write,
                               .verify = eng_ok, .activate = eng_ok, .confirm = eng_ok, .abort = eng_abort,
                               .poll = eng_poll, .status = eng_status };
    s_hooks = (udsota_hooks_t){ .did_read = hook_did_read, .dtc_get = hook_dtc_get };
    s_sec = (udsota_security_t){ .rng16 = sec_rng16, .verify = sec_verify, .key_len = UDSOTA_KEYS_SIG_LEN };
    s_can = (udsota_can_t){ .send = can_send, .tx_pending = can_tx_pending, .now_us = can_now_us };
    TEST_ASSERT_TRUE(udsota_init(&s_srv, &s_cfg, &s_eng, s_secured ? &s_sec : NULL, &s_hooks));
    udsota_isotp_init(&s_tp, &s_srv, &s_cfg, &s_hooks, &s_can, &s_bufs);
}

/* Unity hook: a fresh bus, client, mocks and adapter at T0_US. */
void setUp(void)
{
    s_now_us = T0_US;
    s_fc_owed = false;
    s_fc_n = 0u;
    s_fc_last = 0u;
    s_resp_len = s_resp_got = 0u;
    s_resp_done = false;
    s_written = 0u;
    s_data_ok = true;
    s_dtc_n = 0u;
    s_max_block_len = 0u;
    s_secured = false;
    s_verify_calls = 0u;
    init_all();
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Feeds one client frame, padded to 8 with 0xAA. */
static void feed(const uint8_t *d, uint8_t n)
{
    uint8_t f[8];
    memset(f, 0xAA, sizeof f);
    memcpy(f, d, n);
    udsota_isotp_on_frame(&s_tp, f, 8, s_now_us, now_ms());
}
/* The diag task's wake: the client's owed FC first, then the adapter's service. */
static void service(void)
{
    if (s_fc_owed) {
        static const uint8_t fc[3] = {0x30, 0x00, 0x00};   /* CTS, BS 0, STmin 0 */
        s_fc_owed = false;
        feed(fc, sizeof fc);
    }
    (void)udsota_isotp_service(&s_tp, now_ms());
}
/* Runs up to ms_max milliseconds until an answer completes; true if one did. */
static bool run_until_response(uint32_t ms_max)
{
    for (uint32_t i = 0; i < ms_max && !s_resp_done; i++) {
        s_now_us += 1000u;
        service();
    }
    return s_resp_done;
}
/* A First Frame for n bytes: FF_DL in 12 bits, or FF_DL 0 and 32 bits past 4,095. Returns its data bytes (6 or 2). */
static uint8_t first_frame(uint8_t f[8], uint32_t n, const uint8_t *req)
{
    if (n <= 4095u) {
        f[0] = (uint8_t)(0x10u | (n >> 8));
        f[1] = (uint8_t)n;
        memcpy(&f[2], req, 6);
        return 6u;
    }
    f[0] = 0x10u;
    f[1] = 0x00u;
    f[2] = (uint8_t)(n >> 24);
    f[3] = (uint8_t)(n >> 16);
    f[4] = (uint8_t)(n >> 8);
    f[5] = (uint8_t)n;
    memcpy(&f[6], req, 2);
    return 2u;
}
/* Sends n request bytes, an SF up to 7 and else an FF and CFs CF_GAP_US apart, servicing after each frame, then
 * runs up to ANSWER_MS for the answer; its length, or 0 for none. An FF the adapter refuses gets no CFs. */
static uint32_t request(const uint8_t *req, uint32_t n)
{
    uint8_t f[8];
    s_resp_done = false;
    s_resp_len = s_resp_got = 0u;
    if (n <= 7u) {
        f[0] = (uint8_t)n;
        memcpy(&f[1], req, n);
        feed(f, (uint8_t)(n + 1u));
        service();
        return run_until_response(ANSWER_MS) ? s_resp_len : 0u;
    }
    const unsigned fcs = s_fc_n;
    uint32_t off = first_frame(f, n, req);
    feed(f, 8);
    service();
    if (s_fc_n != fcs + 1u || s_fc_last != 0x30u) {
        return 0u;                                           /* overflow: nothing more to send */
    }
    for (uint8_t sn = 1u; off < n; sn = (uint8_t)((sn + 1u) & 0x0Fu)) {
        s_now_us += CF_GAP_US;
        const uint32_t take = (n - off < 7u) ? n - off : 7u;
        memset(f, 0xAA, sizeof f);
        f[0] = (uint8_t)(0x20u | sn);
        memcpy(&f[1], &req[off], take);
        feed(f, 8);
        service();
        off += take;
    }
    return run_until_response(ANSWER_MS) ? s_resp_len : 0u;
}
/* Sends the bytes given, then checks the answer is exactly want. */
#define EXPECT(want, ...)                                                                     \
    do {                                                                                      \
        static const uint8_t r_[] = {__VA_ARGS__};                                            \
        TEST_ASSERT_EQUAL_UINT32(sizeof(want), request(r_, sizeof r_));                       \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want, s_resp, sizeof(want));                             \
    } while (0)
/* Feeds a First Frame for n bytes and returns the first byte of the FC it drew (30 CTS, 32 overflow), or 0. */
static uint8_t ff_verdict(uint32_t n)
{
    uint8_t f[8];
    memset(s_req, 0x22, sizeof s_req);
    const unsigned fcs = s_fc_n;
    (void)first_frame(f, n, s_req);
    feed(f, 8);
    service();
    const uint8_t fc = (s_fc_n == fcs + 1u) ? s_fc_last : 0u;
    s_now_us += 1100000u;                                    /* past N_Cr: a CTS'd message is dropped */
    service();
    return fc;
}
/* Enters session s. */
static void enter_session(uint8_t s)
{
    TEST_ASSERT_EQUAL_UINT32(6, request((const uint8_t[]){0x10, s}, 2u));
    TEST_ASSERT_EQUAL_HEX8(0x50, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(s, s_resp[1]);
}
/* Enters the programming session and opens a download of size bytes; returns the 74's maxNumberOfBlockLength. */
static uint32_t open_download(uint32_t size)
{
    enter_session(0x02);
    const uint8_t r34[11] = {0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(size >> 24), (uint8_t)(size >> 16),
                             (uint8_t)(size >> 8), (uint8_t)size};
    TEST_ASSERT_EQUAL_UINT32(4, request(r34, sizeof r34));
    TEST_ASSERT_EQUAL_HEX8(0x74, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x20, s_resp[1]);
    service();                                               /* the next wake raises the receive limit */
    return ((uint32_t)s_resp[2] << 8) | s_resp[3];
}
/* A 36 of n bytes (36 <bsc> and pattern data from off) in s_req. */
static void build_block(uint8_t bsc, uint32_t off, uint32_t n)
{
    s_req[0] = 0x36;
    s_req[1] = bsc;
    for (uint32_t i = 0; i + 2u < n; i++) {
        s_req[2u + i] = pattern(off + i);
    }
}

/* The sizes this build was given, the struct they make, and the two floors' reasons. At the defaults nothing moves:
 * 8,958 bytes, 74 20 0F FF and 63 DTCs, as before the sizes could be set. */
static void test_sizes_and_the_struct_they_make(void)
{
    TEST_ASSERT_EQUAL_UINT(2u * RX + 3u * RESP, sizeof(udsota_isotp_bufs_t));
    TEST_ASSERT_EQUAL_UINT(RESP, sizeof s_bufs.resp);
    TEST_ASSERT_EQUAL_UINT(RX, sizeof s_bufs.req);
    TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_KEYS_SIG_LEN, UDSOTA_ISOTP_RX_MIN);    /* 27 xx and an ECDSA signature */
    TEST_ASSERT_EQUAL_UINT(3u + UDSOTA_SHA256_LEN, UDSOTA_ISOTP_RESP_MIN);   /* 62 F1F3 and the SHA-256 */
    TEST_ASSERT_EQUAL_UINT16(RX, s_srv.cfg.max_block_len);
#if UDSOTA_ISOTP_RX_MAX == 4095u && UDSOTA_ISOTP_RESP_MAX == 256u
    TEST_ASSERT_EQUAL_UINT(8958u, sizeof(udsota_isotp_bufs_t));
    TEST_ASSERT_EQUAL_UINT(63u, DTC_CAP);
    TEST_ASSERT_EQUAL_UINT32(4095u, open_download(4093u));
#endif
}

/* 34 announces RX_MAX, the adapter's cap on the default max_block_len; a smaller cfg.max_block_len is kept. */
static void test_74_announces_the_receive_buffer(void)
{
    TEST_ASSERT_EQUAL_UINT32(RX, open_download(RX - 2u));
    s_max_block_len = (uint16_t)(RX - 1u);
    init_all();
    TEST_ASSERT_EQUAL_UINT32(RX - 1u, open_download(RX - 2u));
    TEST_ASSERT_EQUAL_UINT16(RX - 1u, s_srv.cfg.max_block_len);
    s_max_block_len = 4095u;                                 /* over RX_MAX, or at it: capped there */
    init_all();
    TEST_ASSERT_EQUAL_UINT32(RX, open_download(RX - 2u));
}

/* With a download open, a 36 of exactly RX_MAX bytes is served and written whole, and an FF one byte longer draws the
 * overflow FC (FF_DL 0 and 32 bits for 4,096). */
static void test_a_36_of_rx_max_is_served_and_one_more_overflows(void)
{
    open_download(RX - 2u);
    TEST_ASSERT_EQUAL_HEX8(0x32, ff_verdict(RX + 1u));
    build_block(1u, 0u, RX);
    TEST_ASSERT_EQUAL_UINT32(2, request(s_req, RX));
    TEST_ASSERT_EQUAL_HEX8(0x76, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, s_resp[1]);
    TEST_ASSERT_EQUAL_UINT32(RX - 2u, s_written);
    TEST_ASSERT_TRUE(s_data_ok);
}

/* A cfg.max_block_len under RX_MAX is the download's receive limit: an FF at it is taken, one past it overflows. */
static void test_a_smaller_max_block_len_is_the_download_limit(void)
{
    s_max_block_len = (uint16_t)(RX - 1u);
    init_all();
    open_download(2u * RX);
    TEST_ASSERT_EQUAL_HEX8(0x32, ff_verdict(RX));
    TEST_ASSERT_EQUAL_HEX8(0x30, ff_verdict(RX - 1u));
}

/* Outside a download the limit is 256, or RX_MAX when smaller: an FF past it overflows, a request at it is served. */
static void test_the_idle_limit_follows_a_smaller_rx_max(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x32, ff_verdict(IDLE + 1u));
    memset(s_req, 0x01, IDLE);
    s_req[0] = 0x22;                                         /* the wrong length for a 22: 0x13 */
    static const uint8_t nrc13[] = {0x7F, 0x22, 0x13};
    TEST_ASSERT_EQUAL_UINT32(sizeof nrc13, request(s_req, IDLE));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(nrc13, s_resp, sizeof nrc13);
}

/* Checks a 59 <sub> FF list of n DTCs from hook_dtc_get. */
static void assert_dtc_list(uint8_t sub, size_t n)
{
    TEST_ASSERT_EQUAL_UINT32(3u + 4u * n, s_resp_len);
    TEST_ASSERT_EQUAL_HEX8(0x59, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(sub, s_resp[1]);
    TEST_ASSERT_EQUAL_HEX8(0xFF, s_resp[2]);
    for (size_t i = 0; i < n; i++) {
        const uint8_t *e = &s_resp[3u + 4u * i];
        TEST_ASSERT_EQUAL_HEX8(0x10, e[0]);
        TEST_ASSERT_EQUAL_HEX8((uint8_t)(i >> 8), e[1]);
        TEST_ASSERT_EQUAL_HEX8((uint8_t)i, e[2]);
        TEST_ASSERT_EQUAL_HEX8(0x09, e[3]);
    }
}

/* 19 02 and 0A list (RESP_MAX - 3) / 4 DTCs, and one more answers 0x14; physical and functional alike. */
static void test_19_lists_up_to_the_response_buffer(void)
{
    static const uint8_t nrc14[] = {0x7F, 0x19, 0x14};
    s_dtc_n = DTC_CAP;
    TEST_ASSERT_EQUAL_UINT32(3u + 4u * DTC_CAP, request((const uint8_t[]){0x19, 0x02, 0xFF}, 3u));
    assert_dtc_list(0x02, DTC_CAP);
    TEST_ASSERT_EQUAL_UINT32(3u + 4u * DTC_CAP, request((const uint8_t[]){0x19, 0x0A}, 2u));
    assert_dtc_list(0x0A, DTC_CAP);
    s_resp_done = false;
    udsota_isotp_on_func_frame(&s_tp, (const uint8_t[8]){0x02, 0x19, 0x0A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 8,
                               now_ms());
    TEST_ASSERT_TRUE(run_until_response(ANSWER_MS));
    assert_dtc_list(0x0A, DTC_CAP);
    s_dtc_n = DTC_CAP + 1u;
    EXPECT(nrc14, 0x19, 0x02, 0xFF);
    EXPECT(nrc14, 0x19, 0x0A);
}

/* A 22 answer of exactly RESP_MAX bytes goes out whole; one byte more answers 0x14. A 500-byte DID fits only a
 * RESP_MAX of 503 or more. */
static void test_22_answers_up_to_the_response_buffer(void)
{
    static const uint8_t nrc14[] = {0x7F, 0x22, 0x14};
    TEST_ASSERT_EQUAL_UINT32(RESP, request((const uint8_t[]){0x22, 0x02, 0x00}, 3u));
    TEST_ASSERT_EQUAL_HEX8(0x62, s_resp[0]);
    for (uint32_t i = 0; i < RESP - 3u; i++) {
        TEST_ASSERT_EQUAL_HEX8(pattern(i), s_resp[3u + i]);
    }
    EXPECT(nrc14, 0x22, 0x02, 0x01);
    if (RESP >= 503u) {
        TEST_ASSERT_EQUAL_UINT32(503, request((const uint8_t[]){0x22, 0x02, 0x02}, 3u));
        TEST_ASSERT_EQUAL_HEX8(0x62, s_resp[0]);
        TEST_ASSERT_EQUAL_HEX8(pattern(499u), s_resp[502]);
    } else {
        EXPECT(nrc14, 0x22, 0x02, 0x02);
    }
}

/* The ECDSA mode's sendKey, 27 02 and a 64-byte signature (66 bytes, RX_MIN), arrives whole and unlocks. */
static void test_an_ecdsa_send_key_arrives_whole(void)
{
    s_secured = true;
    init_all();
    enter_session(0x03);
    TEST_ASSERT_EQUAL_UINT32(2u + UDSOTA_SEED_LEN, request((const uint8_t[]){0x27, 0x01}, 2u));
    s_req[0] = 0x27;
    s_req[1] = 0x02;
    for (uint32_t i = 0; i < UDSOTA_KEYS_SIG_LEN; i++) {
        s_req[2u + i] = pattern(i);
    }
    TEST_ASSERT_EQUAL_UINT32(2, request(s_req, UDSOTA_ISOTP_RX_MIN));
    TEST_ASSERT_EQUAL_HEX8(0x67, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, s_resp[1]);
    TEST_ASSERT_EQUAL_UINT(1, s_verify_calls);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sizes_and_the_struct_they_make);
    RUN_TEST(test_74_announces_the_receive_buffer);
    RUN_TEST(test_a_36_of_rx_max_is_served_and_one_more_overflows);
    RUN_TEST(test_a_smaller_max_block_len_is_the_download_limit);
    RUN_TEST(test_the_idle_limit_follows_a_smaller_rx_max);
    RUN_TEST(test_19_lists_up_to_the_response_buffer);
    RUN_TEST(test_22_answers_up_to_the_response_buffer);
    RUN_TEST(test_an_ecdsa_send_key_arrives_whole);
    return UNITY_END();
}
