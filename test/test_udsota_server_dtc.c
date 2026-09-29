/* Host tests for 0x19 ReadDTCInformation (01, 02, 06, 0A) and 0x14 ClearDiagnosticInformation through hooks.dtc_get,
 * dtc_ext_data and dtc_clear: each hook gating its own part, the core's check order, the status mask and availability,
 * the room judged on resp_max, the index cap, SPRMIB, every session, a running job, and functional addressing. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

/* The config fields come after 0.9.0's last field, so the change is not breaking. The hooks' place is pinned in
 * fuzz_udsota.c. */
_Static_assert(offsetof(udsota_config_t, dtc_availability_mask) ==
                   offsetof(udsota_config_t, key_pubkey_len) + sizeof(size_t) &&
               offsetof(udsota_config_t, dtc_format) == offsetof(udsota_config_t, dtc_availability_mask) + 1u,
               "udsota_config_t: the dtc_ fields must follow key_pubkey_len, 0.9.0's last field");
#if SIZE_MAX == UINT64_MAX && UINTPTR_MAX == UINT64_MAX
_Static_assert(offsetof(udsota_config_t, key_pubkey_len) == 96u,
               "udsota_config_t: a field before key_pubkey_len moved 0.9.0's layout (96 on a 64-bit host)");
#endif

#define T0         60000u   /* past the 10 s post-boot 0x27 delay */
#define RESP_FULL  256u     /* UDSOTA_ISOTP_RESP_MAX: the transport's response buffer */
#define AVAIL      0x2Fu    /* the tests' availability mask: bits 0-3 and 5 */
#define NRC_APP    0x22u    /* conditionsNotCorrect, as an app's dtc_clear might answer */
#define POS10(ss)  0x50, (ss), 0x00, 0x32, 0x01, 0xF4

/* The mock's DTCs: statuses inside and outside AVAIL, and one with a non-zero top byte. */
static const udsota_dtc_t TABLE[] = {
    {0x00C07300u, 0x2Fu},   /* U0073: every supported bit */
    {0x00056200u, 0x68u},   /* P0562: 0x28 on the wire, 0x40 masked off */
    {0x00923400u, 0x00u},   /* B1234: no bit, so only 19 0A lists it */
    {0xAAD10F1Cu, 0x09u},   /* a junk top byte: the core sends and compares D1 0F 1C */
    {0x00412300u, 0x40u},   /* only a bit outside AVAIL: 0x00 on the wire */
};
#define TABLE_N (sizeof TABLE / sizeof TABLE[0])

/* What the DTC hooks saw, and how they answer. */
typedef struct {
    unsigned        get_calls;
    size_t          gen;            /* non-zero: dtc_get reports gen generated DTCs (0x100000 + i, status 2F) instead */
    bool            endless;        /* dtc_get never returns false */
    unsigned        ext_calls;
    uint32_t        ext_dtc;
    uint8_t         ext_record;
    size_t          ext_max;
    const uint8_t  *ext_buf;
    uint8_t         ext_nrc;        /* non-zero: dtc_ext_data answers it */
    bool            ext_overlong;   /* dtc_ext_data sets *len to max + 1 */
    unsigned        clear_calls;
    uint32_t        clear_group;
    udsota_access_t clear_access;
    uint8_t         clear_nrc;
    void           *ctx;            /* the ctx the last DTC hook got */
} dtc_mock_t;

static dtc_mock_t      g;
static bool            s_hold;       /* engine.poll keeps a queued op pending */
static udsota_mock_t   g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[RESP_FULL];
static size_t          rlen;
static uint32_t        now;

/* engine.check_first: every first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin: done at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }
/* engine.write: queued, so a 36 runs as a job. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return UDSOTA_PENDING; }
/* engine.verify, activate, confirm: done at once. */
static int eng_op(void *ctx) { return 0; }
/* engine.abort: fire-and-forget. */
static void eng_abort(void *ctx) {}
/* engine.poll: UDSOTA_PENDING while held, else 0. */
static int eng_poll(void *ctx) { return s_hold ? UDSOTA_PENDING : 0; }

static const udsota_engine_t ENGINE = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_op,
    .activate = eng_op, .confirm = eng_op, .abort = eng_abort, .poll = eng_poll,
    .status = udsota_mock_status, .ctx = &g_mock,
};

/* hooks.dtc_get: TABLE, or gen generated DTCs, or an endless list. */
static bool hook_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    g.get_calls++;
    g.ctx = ctx;
    if (g.endless) {
        out->dtc = (uint32_t)i;
        out->status = 0x01u;
        return true;
    }
    if (g.gen != 0u) {
        if (i >= g.gen) {
            return false;
        }
        out->dtc = 0x100000u + (uint32_t)i;
        out->status = 0x2Fu;
        return true;
    }
    if (i >= TABLE_N) {
        return false;
    }
    *out = TABLE[i];
    return true;
}

/* Copies n bytes of rec into buf when they fit max: 0 with *len set, else 0x14. */
static uint8_t ext_put(const uint8_t *rec, size_t n, uint8_t *buf, size_t max, size_t *len)
{
    if (n > max) {
        return UDSOTA_NRC_RESPONSE_TOO_LONG;
    }
    memcpy(buf, rec, n);
    *len = n;
    return 0u;
}

/* hooks.dtc_ext_data: records the call and writes all of max first (so an oversized max faults under a sanitizer);
 * then record 01 is 01 05, 10 is 10 AA BB, 02 is held with no data, FE is FE 01, FF is 01 05 10 AA BB, and any other
 * is 0x31; ext_nrc and ext_overlong override. */
static uint8_t hook_ext(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len)
{
    g.ext_calls++;
    g.ctx = ctx;
    g.ext_dtc = dtc;
    g.ext_record = record;
    g.ext_max = max;
    g.ext_buf = buf;
    memset(buf, 0xDD, max);
    if (g.ext_nrc != 0u) {
        return g.ext_nrc;
    }
    if (g.ext_overlong) {
        *len = max + 1u;
        return 0u;
    }
    static const uint8_t R01[] = {0x01, 0x05}, R10[] = {0x10, 0xAA, 0xBB}, RFE[] = {0xFE, 0x01};
    static const uint8_t RFF[] = {0x01, 0x05, 0x10, 0xAA, 0xBB};
    switch (record) {
    case 0x01: return ext_put(R01, sizeof R01, buf, max, len);
    case 0x10: return ext_put(R10, sizeof R10, buf, max, len);
    case 0x02: *len = 0u; return 0u;
    case 0xFE: return ext_put(RFE, sizeof RFE, buf, max, len);
    case 0xFF: return ext_put(RFF, sizeof RFF, buf, max, len);
    default:   return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
}

/* hooks.dtc_clear: records the group and access and answers clear_nrc. */
static uint8_t hook_clear(void *ctx, uint32_t group, udsota_access_t access)
{
    g.clear_calls++;
    g.ctx = ctx;
    g.clear_group = group;
    g.clear_access = access;
    return g.clear_nrc;
}

/* Boots a server on g_cfg and g_hooks with sec (NULL = none); the clock restarts at T0. */
static void boot(const udsota_security_t *sec)
{
    TEST_ASSERT_TRUE(udsota_init(&s, &g_cfg, &ENGINE, sec, &g_hooks));
    now = T0;
}

/* Unity hook: the mock's hooks and the three DTC hooks, availability 0x2F and format 0x01, no security. */
void setUp(void)
{
    memset(&g, 0, sizeof g);
    s_hold = false;
    udsota_mock_clear(&g_mock);
    g_cfg = udsota_mock_cfg();
    g_cfg.dtc_availability_mask = AVAIL;
    g_cfg.dtc_format = 0x01u;
    g_hooks = udsota_mock_hooks(&g_mock);
    g_hooks.dtc_get = hook_get;
    g_hooks.dtc_ext_data = hook_ext;
    g_hooks.dtc_clear = hook_clear;
    boot(NULL);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends req physically into resp_max bytes, 1 ms after the last; the answer is left in resp and rlen. */
static size_t txn_max(const uint8_t *req, size_t len, size_t resp_max)
{
    now += 1u;
    memset(resp, 0xEE, sizeof resp);
    rlen = udsota_on_request(&s, req, len, resp, resp_max, now);
    return rlen;
}
/* Sends req functionally, with the full buffer. */
static size_t func(const uint8_t *req, size_t len)
{
    now += 1u;
    memset(resp, 0xEE, sizeof resp);
    rlen = udsota_on_functional_request(&s, req, len, resp, sizeof resp, now);
    return rlen;
}
#define REQ(...)        txn_max((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}), RESP_FULL)
#define REQ_MAX(m, ...) txn_max((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}), (m))
#define FUNC(...)       func((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

/* Asserts the last answer is exactly the bytes listed. */
#define EXPECT(...) do {                                                   \
        const uint8_t want_[] = {__VA_ARGS__};                             \
        TEST_ASSERT_EQUAL_UINT(sizeof want_, rlen);                        \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want_, resp, sizeof want_);           \
    } while (0)
#define NRC(sid, n) EXPECT(0x7F, (sid), (n))

/* 27 <level>, then 27 <level+1> with the mock's key; asserts 67 <level+1>. */
static void unlock(uint8_t level)
{
    uint8_t req[2u + UDSOTA_KEY_LEN] = {0x27, level};
    TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_SEED_LEN, txn_max(req, 2, RESP_FULL));
    req[1] = (uint8_t)(level + 1u);
    udsota_mock_key_for(&resp[2], level, &req[2]);
    TEST_ASSERT_EQUAL_UINT(2, txn_max(req, sizeof req, RESP_FULL));
}

/* Rebuilds the server with g_hooks as the test changed them. */
static void reboot(void)
{
    memset(&g, 0, sizeof g);
    boot(NULL);
}

/* Without dtc_get every 19, malformed ones included, answers 0x11 in all three sessions, and 14 is still served;
 * without dtc_ext_data 19 06 answers 0x12 while 01, 02 and 0A are served; without dtc_clear 14 answers 0x11. */
static void test_null_hooks(void)
{
    g_hooks.dtc_get = NULL;
    reboot();
    const uint8_t sessions[] = {UDSOTA_SESSION_DEFAULT, UDSOTA_SESSION_EXTENDED, UDSOTA_SESSION_PROGRAMMING};
    for (size_t i = 0; i < sizeof sessions; i++) {
        REQ(0x10, sessions[i]);
        TEST_ASSERT_EQUAL_UINT(6, rlen);
        REQ(0x19, 0x02, 0xFF);
        NRC(0x19, 0x11);
        REQ(0x19);
        NRC(0x19, 0x11);
        REQ(0x19, 0x04);
        NRC(0x19, 0x11);
        REQ(0x19, 0x06, 0xC0, 0x73);
        NRC(0x19, 0x11);
        REQ(0x19, 0x82, 0xFF);
        NRC(0x19, 0x11);
    }
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    EXPECT(0x54);
    TEST_ASSERT_EQUAL_UINT(0, g.get_calls + g.ext_calls);

    g_hooks.dtc_get = hook_get;
    g_hooks.dtc_ext_data = NULL;
    reboot();
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01);
    NRC(0x19, 0x12);
    REQ(0x19, 0x06);
    NRC(0x19, 0x12);                                   /* the sub-function before the length */
    TEST_ASSERT_EQUAL_UINT(0, g.get_calls);
    REQ(0x19, 0x01, 0xFF);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x03);
    REQ(0x19, 0x02, 0x01);
    TEST_ASSERT_EQUAL_HEX8(0x59, resp[0]);
    REQ(0x19, 0x0A);
    TEST_ASSERT_EQUAL_UINT(3u + 4u * TABLE_N, rlen);

    g_hooks.dtc_ext_data = hook_ext;
    g_hooks.dtc_clear = NULL;
    reboot();
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    NRC(0x14, 0x11);
    REQ(0x14);
    NRC(0x14, 0x11);
    REQ(0x10, 0x03);
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    NRC(0x14, 0x11);
}

/* 19 01: availability, format and the count of status & mask & availability; mask 0 and a mask outside availability
 * count 0; availability 0 in cfg reads 0xFF. */
static void test_count_by_mask(void)
{
    REQ(0x19, 0x01, 0xFF);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x03);       /* U0073, P0562 and D10F1C */
    REQ(0x19, 0x01, 0x08);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x03);       /* confirmedDTC: 2F, 28 and 09 */
    REQ(0x19, 0x01, 0x01);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x02);       /* testFailed: 2F and 09 */
    REQ(0x19, 0x01, 0x00);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x00);
    REQ(0x19, 0x01, 0x40);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x00);       /* 412300's 0x40 is outside availability */
    TEST_ASSERT_EQUAL_UINT(5u * (TABLE_N + 1u), g.get_calls);   /* each walk asks one past the last */
    TEST_ASSERT_EQUAL_PTR(&g_mock, g.ctx);

    g_cfg.dtc_availability_mask = 0u;
    g_cfg.dtc_format = 0x00u;
    reboot();
    REQ(0x19, 0x01, 0x40);
    EXPECT(0x59, 0x01, 0xFF, 0x00, 0x00, 0x02);        /* 0x68 and 0x40 now match */
}

/* 19 02: table order, status & availability on the wire, the status & mask & availability filter, the top byte
 * masked off, and no match answers 59 02 2F alone. */
static void test_by_mask(void)
{
    REQ(0x19, 0x02, 0xFF);
    EXPECT(0x59, 0x02, AVAIL, 0xC0, 0x73, 0x00, 0x2F, 0x05, 0x62, 0x00, 0x28, 0xD1, 0x0F, 0x1C, 0x09);
    REQ(0x19, 0x02, 0x04);
    EXPECT(0x59, 0x02, AVAIL, 0xC0, 0x73, 0x00, 0x2F);
    REQ(0x19, 0x02, 0x40);
    EXPECT(0x59, 0x02, AVAIL);
    REQ(0x19, 0x02, 0x00);
    EXPECT(0x59, 0x02, AVAIL);
}

/* 19 0A: every DTC in table order, status 00 included, each status masked. */
static void test_supported(void)
{
    REQ(0x19, 0x0A);
    EXPECT(0x59, 0x0A, AVAIL, 0xC0, 0x73, 0x00, 0x2F, 0x05, 0x62, 0x00, 0x28, 0x92, 0x34, 0x00, 0x00,
           0xD1, 0x0F, 0x1C, 0x09, 0x41, 0x23, 0x00, 0x00);
}

/* 19 06: one record; FF; the DTC with a non-zero top byte reaches the hook as its 24 bits; *len 0 answers the DTC
 * and status alone; the hook's 0x31 and 0x14 verbatim; *len over max is 0x10; max is resp_max - 6; FE reaches the
 * hook; record 00 and an unknown DTC answer 0x31 with no hook call. */
static void test_ext_data(void)
{
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01);
    EXPECT(0x59, 0x06, 0xC0, 0x73, 0x00, 0x2F, 0x01, 0x05);
    TEST_ASSERT_EQUAL_HEX32(0xC07300u, g.ext_dtc);
    TEST_ASSERT_EQUAL_HEX8(0x01, g.ext_record);
    TEST_ASSERT_EQUAL_UINT(RESP_FULL - 6u, g.ext_max);
    TEST_ASSERT_EQUAL_PTR(&resp[6], g.ext_buf);
    TEST_ASSERT_EQUAL_PTR(&g_mock, g.ctx);
    REQ(0x19, 0x06, 0x05, 0x62, 0x00, 0xFF);
    EXPECT(0x59, 0x06, 0x05, 0x62, 0x00, 0x28, 0x01, 0x05, 0x10, 0xAA, 0xBB);
    REQ(0x19, 0x06, 0xD1, 0x0F, 0x1C, 0x10);
    EXPECT(0x59, 0x06, 0xD1, 0x0F, 0x1C, 0x09, 0x10, 0xAA, 0xBB);
    TEST_ASSERT_EQUAL_HEX32(0xD10F1Cu, g.ext_dtc);     /* the request's 24 bits, not dtc_get's AAD10F1C */
    REQ(0x19, 0x06, 0x41, 0x23, 0x00, 0x02);
    EXPECT(0x59, 0x06, 0x41, 0x23, 0x00, 0x00);        /* held with no data */
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x03);
    NRC(0x19, 0x31);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0xFE);
    EXPECT(0x59, 0x06, 0xC0, 0x73, 0x00, 0x2F, 0xFE, 0x01);
    g.ext_nrc = UDSOTA_NRC_RESPONSE_TOO_LONG;
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0xFF);
    NRC(0x19, 0x14);
    g.ext_nrc = 0u;
    g.ext_overlong = true;
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0xFF);
    NRC(0x19, 0x10);
    g.ext_overlong = false;
    REQ_MAX(10u, 0x19, 0x06, 0xC0, 0x73, 0x00, 0xFF);
    NRC(0x19, 0x14);                                   /* the hook's: 5 record bytes into 4 */
    TEST_ASSERT_EQUAL_UINT(4, g.ext_max);
    REQ_MAX(11u, 0x19, 0x06, 0xC0, 0x73, 0x00, 0xFF);
    EXPECT(0x59, 0x06, 0xC0, 0x73, 0x00, 0x2F, 0x01, 0x05, 0x10, 0xAA, 0xBB);

    const unsigned calls = g.ext_calls;
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x00);
    NRC(0x19, 0x31);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x01, 0x01);           /* U0073 with FTB 01: not a DTC dtc_get reports */
    NRC(0x19, 0x31);
    REQ(0x19, 0x06, 0xAA, 0xD1, 0x0F, 0x01);           /* the top byte is never part of a DTC */
    NRC(0x19, 0x31);
    TEST_ASSERT_EQUAL_UINT(calls, g.ext_calls);
    g.get_calls = 0u;
    REQ(0x19, 0x06, 0x05, 0x62, 0x00, 0x01);
    TEST_ASSERT_EQUAL_UINT(2, g.get_calls);            /* the walk stops at the first match */
}

/* Lengths and sub-functions: 0x13 for 19, 19 01, 19 01 FF 00, 19 0A 00 and a short or long 19 06; 0x12 for 19 03
 * and 19 04 whatever their length, the sub-function checked before the exact length. None asks a hook. */
static void test_lengths_and_subfunctions(void)
{
    REQ(0x19);
    NRC(0x19, 0x13);
    REQ(0x19, 0x01);
    NRC(0x19, 0x13);
    REQ(0x19, 0x01, 0xFF, 0x00);
    NRC(0x19, 0x13);
    REQ(0x19, 0x02);
    NRC(0x19, 0x13);
    REQ(0x19, 0x0A, 0x00);
    NRC(0x19, 0x13);
    REQ(0x19, 0x06);
    NRC(0x19, 0x13);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00);
    NRC(0x19, 0x13);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01, 0x00);
    NRC(0x19, 0x13);
    REQ(0x19, 0x03);
    NRC(0x19, 0x12);
    REQ(0x19, 0x04);
    NRC(0x19, 0x12);
    REQ(0x19, 0x04, 0x00, 0x00, 0x00, 0x00);
    NRC(0x19, 0x12);
    REQ(0x19, 0x00);
    NRC(0x19, 0x12);
    TEST_ASSERT_EQUAL_UINT(0, g.get_calls + g.ext_calls);
}

/* Room is judged on resp_max: 63 DTCs fit 256 B and 64 answer 0x14; resp_max 3 + 4k fits k and one less answers
 * 0x14; 19 01 needs 6; 19 06 needs 6 for 59 06 <DTC> <status>, and short of it asks no hook, though an unknown DTC
 * still answers 0x31, found first; below 3 the 0x14 doesn't fit and nothing is sent. The walk stops at the DTC that
 * overflows. */
static void test_response_too_long(void)
{
    g.gen = 63u;
    REQ(0x19, 0x0A);
    TEST_ASSERT_EQUAL_UINT(3u + 4u * 63u, rlen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){0x59, 0x0A, AVAIL, 0x10, 0x00, 0x00, 0x2F}), resp, 7);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){0x10, 0x00, 0x3E, 0x2F}), &resp[3u + 4u * 62u], 4);
    g.gen = 64u;
    g.get_calls = 0u;
    REQ(0x19, 0x02, 0xFF);
    NRC(0x19, 0x14);
    TEST_ASSERT_EQUAL_UINT(64, g.get_calls);           /* stopped at the 64th: the end was never asked */
    REQ(0x19, 0x0A);
    NRC(0x19, 0x14);

    g.gen = 0u;                                        /* TABLE: 3 matches for 19 02 FF, 5 for 0A */
    REQ_MAX(3u + 4u * 3u, 0x19, 0x02, 0xFF);
    TEST_ASSERT_EQUAL_UINT(15, rlen);
    REQ_MAX(3u + 4u * 3u - 1u, 0x19, 0x02, 0xFF);
    NRC(0x19, 0x14);
    REQ_MAX(3u + 4u * TABLE_N, 0x19, 0x0A);
    TEST_ASSERT_EQUAL_UINT(3u + 4u * TABLE_N, rlen);
    REQ_MAX(3u + 4u * TABLE_N - 1u, 0x19, 0x0A);
    NRC(0x19, 0x14);
    REQ_MAX(3u, 0x19, 0x02, 0x40);
    EXPECT(0x59, 0x02, AVAIL);                         /* no match fits 3 */
    REQ_MAX(3u, 0x19, 0x02, 0xFF);
    NRC(0x19, 0x14);
    REQ_MAX(6u, 0x19, 0x01, 0xFF);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x03);
    g.get_calls = 0u;
    REQ_MAX(5u, 0x19, 0x01, 0xFF);
    NRC(0x19, 0x14);
    TEST_ASSERT_EQUAL_UINT(0, g.get_calls);
    REQ_MAX(6u, 0x19, 0x06, 0x92, 0x34, 0x00, 0x02);
    EXPECT(0x59, 0x06, 0x92, 0x34, 0x00, 0x00);
    TEST_ASSERT_EQUAL_UINT(0, g.ext_max);
    const unsigned calls = g.ext_calls;
    REQ_MAX(5u, 0x19, 0x06, 0x92, 0x34, 0x00, 0x02);
    NRC(0x19, 0x14);
    REQ_MAX(5u, 0x19, 0x06, 0x12, 0x34, 0x56, 0x01);
    NRC(0x19, 0x31);                                   /* the DTC walk before the room check */
    TEST_ASSERT_EQUAL_UINT(calls, g.ext_calls);
    REQ_MAX(2u, 0x19, 0x02, 0xFF);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    REQ_MAX(2u, 0x19, 0x06, 0x92, 0x34, 0x00, 0x02);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    TEST_ASSERT_EQUAL_UINT(calls, g.ext_calls);
}

/* A dtc_get that never returns false is asked 65,535 times, the last at UDSOTA_DTC_INDEX_MAX - 1, and 19 01 counts
 * 0xFFFF; 19 06 for a DTC it never reports stops there too. */
static void test_index_cap(void)
{
    g.endless = true;
    REQ(0x19, 0x01, 0xFF);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0xFF, 0xFF);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_DTC_INDEX_MAX, g.get_calls);
    g.get_calls = 0u;
    REQ(0x19, 0x06, 0xFF, 0xFF, 0xFF, 0x01);
    NRC(0x19, 0x31);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_DTC_INDEX_MAX, g.get_calls);
    TEST_ASSERT_EQUAL_UINT(0, g.ext_calls);
}

/* SPRMIB drops only a positive answer: 19 82 FF and 19 8A are silent after the walk, while 19 86 for an unknown DTC
 * still answers 0x31, 19 86 the hook refuses still answers the hook's NRC, and a 19 82 FF too long for resp_max
 * still answers 0x14. */
static void test_sprmib(void)
{
    REQ(0x19, 0x82, 0xFF);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    TEST_ASSERT_EQUAL_UINT(TABLE_N + 1u, g.get_calls);
    REQ(0x19, 0x8A);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    REQ(0x19, 0x81, 0xFF);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    REQ(0x19, 0x86, 0xC0, 0x73, 0x00, 0x01);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    TEST_ASSERT_EQUAL_UINT(1, g.ext_calls);
    REQ(0x19, 0x86, 0x12, 0x34, 0x56, 0x01);
    NRC(0x19, 0x31);
    g.ext_nrc = NRC_APP;
    REQ(0x19, 0x86, 0xC0, 0x73, 0x00, 0x01);
    NRC(0x19, NRC_APP);
    TEST_ASSERT_EQUAL_UINT(2, g.ext_calls);
    g.ext_nrc = 0u;
    REQ_MAX(10u, 0x19, 0x82, 0xFF);
    NRC(0x19, 0x14);
    REQ(0x19, 0x84);
    NRC(0x19, 0x12);
}

/* 19 is served in the default, extended and programming sessions, locked, with security on. */
static void test_sessions(void)
{
    boot(udsota_mock_security());
    REQ(0x19, 0x02, 0x01);
    EXPECT(0x59, 0x02, AVAIL, 0xC0, 0x73, 0x00, 0x2F, 0xD1, 0x0F, 0x1C, 0x09);
    REQ(0x10, 0x03);
    EXPECT(POS10(0x03));
    REQ(0x19, 0x01, 0xFF);
    EXPECT(0x59, 0x01, AVAIL, 0x01, 0x00, 0x03);
    REQ(0x10, 0x02);
    EXPECT(POS10(0x02));
    TEST_ASSERT_EQUAL_UINT8(0, s.security);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01);
    EXPECT(0x59, 0x06, 0xC0, 0x73, 0x00, 0x2F, 0x01, 0x05);
    REQ(0x19, 0x0A);
    TEST_ASSERT_EQUAL_UINT(3u + 4u * TABLE_N, rlen);
}

/* 14: any length but 4 answers 0x13 with no call; the group and the access state (session, level, epoch) reach the
 * hook, whose NRC is sent as given and whose 0 answers 54; resp_max 0 calls nothing; the default session reaches
 * the hook too, whose session rule is its own. */
static void test_clear(void)
{
    boot(udsota_mock_security());
    REQ(0x14, 0xFF, 0xFF);
    NRC(0x14, 0x13);
    REQ(0x14, 0xFF, 0xFF, 0xFF, 0x00);
    NRC(0x14, 0x13);
    REQ(0x14);
    NRC(0x14, 0x13);
    TEST_ASSERT_EQUAL_UINT(0, g.clear_calls);

    g.clear_nrc = UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    NRC(0x14, 0x7F);
    TEST_ASSERT_EQUAL_UINT(1, g.clear_calls);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, g.clear_access.session);
    TEST_ASSERT_EQUAL_PTR(&g_mock, g.ctx);

    REQ(0x10, 0x03);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    g.clear_nrc = NRC_APP;
    REQ(0x14, 0x12, 0x34, 0x56);
    NRC(0x14, NRC_APP);
    TEST_ASSERT_EQUAL_HEX32(0x123456u, g.clear_group);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, g.clear_access.session);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, g.clear_access.unlocked_level);
    TEST_ASSERT_EQUAL_UINT32(s.session_epoch, g.clear_access.epoch);
    g.clear_nrc = 0u;
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    EXPECT(0x54);
    TEST_ASSERT_EQUAL_HEX32(UDSOTA_DTC_GROUP_ALL, g.clear_group);
    TEST_ASSERT_EQUAL_UINT(3, g.clear_calls);
    REQ_MAX(1u, 0x14, 0xFF, 0xFF, 0xFF);
    EXPECT(0x54);
    REQ_MAX(0u, 0x14, 0xFF, 0xFF, 0xFF);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    TEST_ASSERT_EQUAL_UINT(4, g.clear_calls);
}

/* During a pending 36, a physical 19 or 14 answers 0x21 and asks no hook; a functional one is silent. */
static void test_busy(void)
{
    REQ(0x10, 0x02);
    REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    s_hold = true;
    REQ(0x36, 0x01, 0xE9, 0x03);
    TEST_ASSERT_EQUAL_UINT(0, rlen);
    TEST_ASSERT_TRUE(s.job_running);
    REQ(0x19, 0x02, 0xFF);
    NRC(0x19, 0x21);
    REQ(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01);
    NRC(0x19, 0x21);
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    NRC(0x14, 0x21);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x02, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x14, 0xFF, 0xFF, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, g.get_calls + g.ext_calls + g.clear_calls);
    TEST_ASSERT_TRUE(s.job_running);
}

/* Functionally: 19 02 and a 19 06 for a DTC the node has are answered; 19 06 for a DTC the node lacks or a record
 * the hook doesn't hold (0x31), 19 04 and a node without dtc_get are silent; a bare 19 still answers 0x13, and a
 * 19 0A too long for the buffer or a 19 06 whose records don't fit 0x14; 14 is dropped before the server, asking no
 * hook. */
static void test_functional(void)
{
    TEST_ASSERT_EQUAL_UINT(11, FUNC(0x19, 0x02, 0x01));
    EXPECT(0x59, 0x02, AVAIL, 0xC0, 0x73, 0x00, 0x2F, 0xD1, 0x0F, 0x1C, 0x09);
    TEST_ASSERT_EQUAL_UINT(6, FUNC(0x19, 0x01, 0xFF));
    TEST_ASSERT_EQUAL_UINT(8, FUNC(0x19, 0x06, 0xC0, 0x73, 0x00, 0x01));
    EXPECT(0x59, 0x06, 0xC0, 0x73, 0x00, 0x2F, 0x01, 0x05);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x06, 0x12, 0x34, 0x56, 0x01));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x06, 0xC0, 0x73, 0x00, 0x03));
    TEST_ASSERT_EQUAL_UINT(2, g.ext_calls);            /* the hook's 0x31, suppressed */
    g.ext_nrc = UDSOTA_NRC_RESPONSE_TOO_LONG;
    TEST_ASSERT_EQUAL_UINT(3, FUNC(0x19, 0x06, 0xC0, 0x73, 0x00, 0xFF));
    NRC(0x19, 0x14);
    g.ext_nrc = 0u;
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x04));
    TEST_ASSERT_EQUAL_UINT(3, FUNC(0x19));
    NRC(0x19, 0x13);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x8A));
    g.gen = 64u;
    TEST_ASSERT_EQUAL_UINT(3, FUNC(0x19, 0x0A));
    NRC(0x19, 0x14);
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x14, 0xFF, 0xFF, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x14));
    TEST_ASSERT_EQUAL_UINT(0, g.clear_calls);

    g_hooks.dtc_get = NULL;
    reboot();
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19, 0x02, 0xFF));
    TEST_ASSERT_EQUAL_UINT(0, FUNC(0x19));
    REQ(0x19, 0x02, 0xFF);
    NRC(0x19, 0x11);
}

/* Runs every DTC test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_null_hooks);
    RUN_TEST(test_count_by_mask);
    RUN_TEST(test_by_mask);
    RUN_TEST(test_supported);
    RUN_TEST(test_ext_data);
    RUN_TEST(test_lengths_and_subfunctions);
    RUN_TEST(test_response_too_long);
    RUN_TEST(test_index_cap);
    RUN_TEST(test_sprmib);
    RUN_TEST(test_sessions);
    RUN_TEST(test_clear);
    RUN_TEST(test_busy);
    RUN_TEST(test_functional);
    return UNITY_END();
}
