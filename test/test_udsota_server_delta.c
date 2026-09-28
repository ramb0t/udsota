/* Host tests for delta downloads (34 with DFI 0x20 or 0x30): the server's 34/36/37/FF01 on an engine whose zbegin,
 * zwrite and zend run udsota_coded over the real detools (components/udsota_delta) and tinfl, with the core's image
 * rules behind the first-block check; and the image sink (udsota_isink.h) on its own. The images and patches are
 * test/fixtures/delta_fixtures.h, which tools/make_delta_fixtures.py generates; DELTA_P20 is byte for byte what
 * Espressif's esp_delta_ota_patch_gen.py writes. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"
#include "udsota_image.h"
#include "udsota_coded.h"
#include "udsota_detools.h"
#include "udsota_tinfl.h"
#include "fixtures/delta_fixtures.h"
#include "miniz/miniz.h"   /* tdefl, to wrap a heatshrink patch in DEFLATE */

#define T0        60000u    /* past SecurityAccess's post-boot delay */
#define IMG_LEN   ((uint32_t)sizeof DELTA_NEW)
#define OUT_LEN   1024u     /* the image's buffer: small, so one image takes many writes */
#define ZBUF_LEN  256u      /* 0x30's inflated-patch buffer */
#define BLOCK     4093u     /* data bytes per 36 */
#define PATCH_CAP 16384u

/* The engine: udsota_coded over detools and tinfl into a RAM "slot", with call counts. */
typedef struct {
    udsota_coded_t   cd;
    udsota_detools_t detools;
    udsota_tinfl_t   tinfl;
    uint8_t          out[OUT_LEN];
    uint8_t          zbuf[ZBUF_LEN];
    uint8_t          flash[IMG_LEN + 4096u];
    uint32_t         begin_size;          /* size begin got; 0 = never erased */
    unsigned         checks, begins, writes, zbegins, zwrites, zends, aborts, verifies;
    unsigned         allocs, frees;       /* live decoder memory = allocs - frees */
    bool             fail_alloc;          /* the decoders' next allocations fail */
    uint8_t          last_dfi;            /* the DFI zbegin got */
    uint32_t         next_off;            /* where the next write must land */
    bool             offsets_ok;          /* every write landed at next_off */
    uint32_t         base_len;            /* the running image's length: reads past it are refused */
    unsigned         base_refusals;       /* reads refused */
    uint8_t          base_hash[UDSOTA_PATCH_HASH_LEN];
    bool             hash_fails;          /* base.hash cannot identify the running image */
    const char      *product;             /* the product the first-block check wants */
    bool             zend_job;            /* zend answers UDSOTA_PENDING, as the ESP32 port's worker job does */
    int              job_result;          /* the pending zend's result */
    uint32_t         job_done_at;         /* when it is done */
    bool             job_queued;
} eng_t;

static eng_t e;
static uint32_t g_now;
static udsota_server_t srv;
static uint8_t g_resp[64];
static size_t g_resp_len;
static uint8_t g_req[UDSOTA_DL_MAX_BLOCK_LEN];
static uint8_t g_p[PATCH_CAP];         /* the payload the 36s carry */
static size_t g_p_len;
static udsota_mock_t g_mock;

/* ---- the decoders' memory ---- */

/* Counts an allocation; NULL while fail_alloc is set. */
static void *t_alloc(void *ctx, size_t n)
{
    if (e.fail_alloc) return NULL;
    e.allocs++;
    return malloc(n);
}

/* Counts a free. */
static void t_free(void *ctx, void *p)
{
    e.frees++;
    free(p);
}

/* ---- the running image ---- */

/* base.read: DELTA_BASE up to base_len; any read past it is refused. */
static int b_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    if ((uint64_t)off + n > e.base_len) {
        e.base_refusals++;
        return -1;
    }
    memcpy(buf, &DELTA_BASE[off], n);
    return 0;
}

/* base.hash: base_hash, or a failure with hash_fails. */
static int b_hash(void *ctx, uint8_t out[UDSOTA_PATCH_HASH_LEN])
{
    if (e.hash_fails) return -1;
    memcpy(out, e.base_hash, UDSOTA_PATCH_HASH_LEN);
    return 0;
}

static const udsota_pbase_t BASE = {.read = b_read, .hash = b_hash};

/* ---- the sink: the core image rules, then a RAM slot ---- */

/* The core image rules for a running example dev build at 0.0.0, for e.product. */
static int s_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    e.checks++;
    const udsota_image_ctx_t ic = {
        .product = e.product, .hw_id = 1u, .partition_layout_id = 1u,
        .diag_request_id = 0x710u, .diag_response_id = 0x718u,
        .running_version = {0, 0, 0}, .running_is_release = false, .slot_size = UDSOTA_SLOT_SIZE_DEFAULT,
    };
    *why = udsota_image_check(first, len, srv.dl_announced, &ic, NULL);
    return *why == UDSOTA_DL_OK ? 0 : 1;
}

/* Erases the RAM slot. */
static int s_begin(void *ctx, uint32_t size)
{
    e.begins++;
    e.begin_size = size;
    memset(e.flash, 0xFF, sizeof e.flash);
    return 0;
}

/* Writes at off, which must follow the last write. */
static int s_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    e.writes++;
    e.offsets_ok = e.offsets_ok && off == e.next_off && e.begins == 1u;
    if (off + n > sizeof e.flash) return -1;
    memcpy(&e.flash[off], d, n);
    e.next_off = off + (uint32_t)n;
    return 0;
}

/* ---- the engine ---- */

/* engine.zbegin: opens the stages for dfi over detools, tinfl and the sink. */
static int eng_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    e.zbegins++;
    e.last_dfi = dfi;
    udsota_coded_close(&e.cd);
    const udsota_inflate_t inf = udsota_tinfl_inflate(&e.tinfl);
    const udsota_patch_t patch = udsota_detools_patch(&e.detools);
    const udsota_coded_cfg_t cfg = {
        .sink = {.check_first = s_check, .begin = s_begin, .write = s_write},
        .out = e.out, .out_max = sizeof e.out, .inflate = &inf, .patch = &patch, .base = &BASE,
        .zbuf = e.zbuf, .zbuf_max = sizeof e.zbuf,
    };
    return (int)udsota_coded_open(&e.cd, dfi, size, &cfg);
}

/* engine.zwrite: feeds the download at once. */
static int eng_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    e.zwrites++;
    return (int)udsota_coded_feed(&e.cd, d, n);
}

/* engine.zend: the 37 check; with zend_job, a job that finishes 100 ms later. */
static int eng_zend(void *ctx)
{
    e.zends++;
    const int r = (int)udsota_coded_end(&e.cd);
    if (!e.zend_job) return r;
    e.job_result = r;
    e.job_done_at = g_now + 100u;
    e.job_queued = true;
    return UDSOTA_PENDING;
}

/* engine.zwritten: the image bytes written, for progress. */
static uint32_t eng_zwritten(void *ctx)
{
    return udsota_coded_written(&e.cd);
}

/* engine.abort: closes any open download. */
static void eng_abort(void *ctx)
{
    e.aborts++;
    udsota_coded_close(&e.cd);
}

/* engine.verify (FF01): the slot holds DELTA_NEW. */
static int eng_verify(void *ctx)
{
    e.verifies++;
    return memcmp(e.flash, DELTA_NEW, IMG_LEN) == 0 ? 0 : (int)UDSOTA_DL_VERIFY_FAILED;
}

/* engine.check_first of the raw path: the core image rules, as the sink's. */
static int eng_raw_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    return s_check(ctx, first, len, why);
}

/* engine.begin of the raw path: the sink's erase. */
static int eng_raw_begin(void *ctx, uint32_t size) { return s_begin(ctx, size); }

/* engine.write of the raw path: the sink's write. */
static int eng_raw_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return s_write(ctx, off, d, n); }

/* engine.activate and engine.confirm: done at once. */
static int eng_ok(void *ctx) { return 0; }

/* UDSOTA_PENDING while a zend job runs, then its result; every other op answers at once. */
static int eng_poll(void *ctx)
{
    if (e.job_queued && g_now < e.job_done_at) return UDSOTA_PENDING;
    e.job_queued = false;
    return e.job_result;
}

#define ALL_FORMATS (UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE) | UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA) | \
                     UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA_DEFLATE))

static const udsota_engine_t ENGINE = {
    .check_first = eng_raw_check, .begin = eng_raw_begin, .write = eng_raw_write, .verify = eng_verify,
    .activate = eng_ok, .confirm = eng_ok, .abort = eng_abort, .poll = eng_poll, .status = udsota_mock_status,
    .ctx = &g_mock, .zbegin = eng_zbegin, .zwrite = eng_zwrite, .zend = eng_zend, .zwritten = eng_zwritten,
    .zformats = ALL_FORMATS,
};

/* ---- the server ---- */

/* Fixed non-zero seed pattern 01..10. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(i + 1);
    return true;
}

/* security.key stand-in: expected key = seed XOR 0x5A. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(seed[i] ^ 0x5A);
    return true;
}

static const udsota_security_t SECURITY = {.rng16 = mock_rng16, .key = mock_key};

/* Boots the server on engine with the mock's config and hooks. */
static void boot(const udsota_engine_t *engine)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, engine, &SECURITY, &hooks);
}

/* Copies n bytes of p into g_p. */
static void set_payload(const uint8_t *p, size_t n)
{
    TEST_ASSERT_TRUE(n <= sizeof g_p);
    memcpy(g_p, p, n);
    g_p_len = n;
}

/* Fresh engine and server at T0, with DELTA_BASE running and DELTA_P20 as the payload. */
void setUp(void)
{
    udsota_coded_close(&e.cd);
    memset(&e, 0, sizeof e);
    e.detools.alloc = t_alloc;
    e.detools.free = t_free;
    e.tinfl.alloc = t_alloc;
    e.tinfl.free = t_free;
    e.offsets_ok = true;
    e.base_len = (uint32_t)sizeof DELTA_BASE;
    memcpy(e.base_hash, DELTA_BASE_HASH, sizeof e.base_hash);
    e.product = "example";
    udsota_mock_clear(&g_mock);
    set_payload(DELTA_P20, sizeof DELTA_P20);
    g_now = T0;
    boot(&ENGINE);
}

/* Frees whatever a failed test left open. */
void tearDown(void)
{
    udsota_coded_close(&e.cd);
}

/* Asserts the last response is exactly the bytes listed. */
#define EXPECT(...) do {                                                       \
        const uint8_t e_[] = {__VA_ARGS__};                                    \
        TEST_ASSERT_EQUAL_UINT(sizeof e_, g_resp_len);                         \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(e_, g_resp, sizeof e_);                   \
    } while (0)

/* Sends one request at g_now; keeps the immediate response in g_resp. */
static size_t send(const uint8_t *req, size_t len)
{
    g_resp_len = udsota_on_request(&srv, req, len, g_resp, sizeof g_resp, g_now);
    return g_resp_len;
}

/* 10 02 and the level-03 unlock. */
static void enter_programming(void)
{
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    const uint8_t seed_req[] = {UDSOTA_SID_SECURITY, UDSOTA_SA_SEED_PROGRAMMING};
    send(seed_req, sizeof seed_req);
    uint8_t key[2u + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, UDSOTA_SA_KEY_PROGRAMMING};
    for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) key[2u + i] = (uint8_t)(g_resp[2u + i] ^ 0x5A);
    send(key, sizeof key);
    EXPECT(0x67, 0x04);
}

/* Sends 34 <dfi> 44 <address 0> <size>. */
static size_t send_34(uint8_t dfi, uint32_t size)
{
    const uint8_t r[UDSOTA_DL_REQ_LEN] = {
        UDSOTA_SID_REQUEST_DOWNLOAD, dfi, UDSOTA_DL_ALFID, 0, 0, 0, 0,
        (uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size,
    };
    return send(r, sizeof r);
}

/* Sends 36 <bsc> with n bytes of data. */
static size_t send_36_data(uint8_t bsc, const uint8_t *data, size_t n)
{
    g_req[0] = UDSOTA_SID_TRANSFER_DATA;
    g_req[1] = bsc;
    memcpy(&g_req[2], data, n);
    return send(g_req, n + 2u);
}

/* Sends g_p in blocks of chunk bytes, asserting 76 <bsc> for each; returns the next counter. */
static uint8_t send_payload(size_t chunk)
{
    uint8_t bsc = 1;
    for (size_t off = 0; off < g_p_len; off += chunk, bsc++) {
        const size_t n = (g_p_len - off < chunk) ? g_p_len - off : chunk;
        send_36_data(bsc, &g_p[off], n);
        EXPECT(0x76, bsc);
    }
    return bsc;
}

/* Polls every 10 ms until a final response, counting 0x78s; fails after 100 s. */
static size_t finish_job(unsigned *pending)
{
    for (uint32_t waited = 0; waited < 100000u; waited += 10u) {
        g_now += 10u;
        const size_t n = udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
        if (n == 3u && g_resp[0] == UDSOTA_NEG_RESPONSE && g_resp[2] == UDSOTA_NRC_RESPONSE_PENDING) {
            (*pending)++;
            continue;
        }
        if (n > 0u) {
            g_resp_len = n;
            return n;
        }
    }
    TEST_FAIL_MESSAGE("the job never finished");
    return 0;
}

/* Sends 37. */
static size_t send_37(void)
{
    const uint8_t r[] = {UDSOTA_SID_TRANSFER_EXIT};
    return send(r, sizeof r);
}

/* Sends 31 01 <rid>. */
static size_t send_routine(uint16_t rid)
{
    const uint8_t r[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, (uint8_t)(rid >> 8), (uint8_t)rid};
    return send(r, sizeof r);
}

/* Asserts F1F1's reason. */
static void expect_reason(uint8_t reason)
{
    TEST_ASSERT_EQUAL_UINT8(reason, srv.last_dl.reason_code);
}

/* The whole download of g_p under dfi in chunk-byte 36s, then 37 77 and FF01 passing on DELTA_NEW. */
static void download_ok(uint8_t dfi, size_t chunk)
{
    enter_programming();
    send_34(dfi, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    TEST_ASSERT_EQUAL_UINT8(dfi, e.last_dfi);
    send_payload(chunk);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.next_off);              /* the image is whole before the 37 */
    send_37();
    EXPECT(0x77);
    expect_reason(UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_UINT(1u, e.checks);
    TEST_ASSERT_EQUAL_UINT(1u, e.begins);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.begin_size);
    TEST_ASSERT_TRUE(e.offsets_ok);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.next_off);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);                 /* 37 freed every decoder */
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DELTA_NEW, e.flash, IMG_LEN);
}

/* Sends g_p's first n bytes in one 36 of a fresh download under dfi, expecting 7F 36 31 with reason why and no
 * erase. */
static void refused_before_erase(uint8_t dfi, uint32_t size, size_t n, uint8_t why)
{
    enter_programming();
    send_34(dfi, size);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    send_36_data(1, g_p, n);
    EXPECT(0x7F, 0x36, 0x31);
    expect_reason(why);
    TEST_ASSERT_EQUAL_UINT(0u, e.begins);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);                 /* the refusal released the decoder */
}

/* ---- tests: the whole download ---- */

/* DFI 20 with the heatshrink patch Espressif's tool writes: rebuilt from the running image, checked once, erased once
 * for memorySize, written at image offsets, and FF01 passes on the new image. */
static void test_delta_happy_path(void)
{
    download_ok(UDSOTA_DL_DFI_DELTA, BLOCK);
}

/* DFI 30: the uncompressed patch as raw DEFLATE, inflated into the patch stage and rebuilt the same way. */
static void test_compressed_delta_happy_path(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    download_ok(UDSOTA_DL_DFI_DELTA_DEFLATE, BLOCK);
}

/* Either inner form under either DFI: an uncompressed patch under 20, and a heatshrink one inside DEFLATE under 30. */
static void test_either_inner_patch_under_either_dfi(void)
{
    set_payload(DELTA_PNONE, sizeof DELTA_PNONE);
    download_ok(UDSOTA_DL_DFI_DELTA, BLOCK);

    setUp();
    static uint8_t z[PATCH_CAP];
    const int flags = (int)tdefl_create_comp_flags_from_zip_params(9, -15, MZ_DEFAULT_STRATEGY);
    const size_t zn = tdefl_compress_mem_to_mem(z, sizeof z, DELTA_P20, sizeof DELTA_P20, flags);
    TEST_ASSERT_TRUE(zn > 0u);
    set_payload(z, zn);
    download_ok(UDSOTA_DL_DFI_DELTA_DEFLATE, BLOCK);
}

/* The header split across 36s down to one byte per 36, and the patch after it in small pieces. */
static void test_header_split_one_byte_per_36(void)
{
    download_ok(UDSOTA_DL_DFI_DELTA, 1u);
}

/* The patch in 7-byte 36s under 30: the DEFLATE stream and the header split at odd points. */
static void test_compressed_delta_in_small_blocks(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    download_ok(UDSOTA_DL_DFI_DELTA_DEFLATE, 7u);
}

/* ---- tests: refused before any erase ---- */

/* A header whose magic is wrong: 7F 36 31, reason 13, nothing erased. */
static void test_wrong_magic(void)
{
    g_p[0] ^= 0x01;
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN, g_p_len, UDSOTA_DL_BAD_STREAM);
}

/* A patch made from another image: 7F 36 31, reason 15, nothing erased; a full download then works. */
static void test_wrong_base_then_full_download(void)
{
    e.base_hash[0] ^= 0x80;
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN, g_p_len, UDSOTA_DL_BAD_BASE);
    const uint8_t rdid[] = {UDSOTA_SID_READ_DID, 0xF1, 0xF1};
    send(rdid, sizeof rdid);
    TEST_ASSERT_EQUAL_HEX8(0x62, g_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_DL_BAD_BASE, g_resp[3]);

    send_34(UDSOTA_DL_DFI, IMG_LEN);                           /* the fallback: the image itself */
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    set_payload(DELTA_NEW, IMG_LEN);
    send_payload(BLOCK);
    send_37();
    EXPECT(0x77);
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_OK);
}

/* A running image the engine cannot identify is reason 15 too. */
static void test_unidentified_base(void)
{
    e.hash_fails = true;
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN, g_p_len, UDSOTA_DL_BAD_BASE);
}

/* The wrong base found inside a DEFLATE stream under 30 is refused the same way. */
static void test_wrong_base_under_30(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    e.base_hash[31] ^= 0x01;
    refused_before_erase(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN, g_p_len, UDSOTA_DL_BAD_BASE);
}

/* A 34 announcing another size than the patch rebuilds: 7F 36 31, reason 13, nothing erased. */
static void test_patch_for_another_size(void)
{
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN + 16u, g_p_len, UDSOTA_DL_BAD_STREAM);
    setUp();
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN - 1u, g_p_len, UDSOTA_DL_BAD_STREAM);
}

/* The rebuilt image's first block goes through the image rules: another product is reason 2, nothing erased. */
static void test_first_block_rules_run_on_the_rebuilt_image(void)
{
    e.product = "other";
    refused_before_erase(UDSOTA_DL_DFI_DELTA, IMG_LEN, g_p_len, UDSOTA_DL_BAD_PROJECT);
    TEST_ASSERT_EQUAL_UINT(1u, e.checks);
}

/* ---- tests: refused at a 36 or the 37 ---- */

/* A patch corrupted after its header: 7F 36 31, reason 13, and the download is over. */
static void test_corrupt_patch(void)
{
    for (size_t i = UDSOTA_PATCH_HEADER_LEN + 8u; i < g_p_len; i += 5u) g_p[i] ^= 0xA5;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_36_data(1, g_p, g_p_len);
    EXPECT(0x7F, 0x36, 0x31);
    expect_reason(UDSOTA_DL_BAD_STREAM);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
    send_36_data(2, g_p, 1);
    EXPECT(0x7F, 0x36, 0x24);                                  /* no transfer open */
}

/* A corrupt DEFLATE stream under 30: 7F 36 31, reason 13. */
static void test_corrupt_stream_under_30(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    g_p[0] = 0xFF;                                             /* BTYPE 11: reserved */
    refused_before_erase(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN, g_p_len, UDSOTA_DL_BAD_STREAM);
}

/* A patch that reads the base past the running image's end: the read is refused, 7F 36 31, reason 13. */
static void test_base_read_outside_the_running_image(void)
{
    e.base_len = 2000u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_36_data(1, g_p, g_p_len);
    EXPECT(0x7F, 0x36, 0x31);
    expect_reason(UDSOTA_DL_BAD_STREAM);
    TEST_ASSERT_TRUE(e.base_refusals > 0u);
}

/* A truncated patch passes its 36s and fails the 37: 7F 37 72, reason 13. */
static void test_truncated_patch_fails_at_37(void)
{
    g_p_len -= 40u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_payload(BLOCK);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    expect_reason(UDSOTA_DL_BAD_STREAM);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* Bytes after the patch's end fail the 37, in both inner forms: 7F 37 72, reason 13. */
static void test_trailing_bytes_fail_at_37(void)
{
    const struct { const uint8_t *p; size_t n; } forms[] = {{DELTA_P20, sizeof DELTA_P20},
                                                            {DELTA_PNONE, sizeof DELTA_PNONE}};
    for (size_t f = 0; f < 2u; f++) {
        setUp();
        set_payload(forms[f].p, forms[f].n);
        g_p[g_p_len++] = 0x00;
        enter_programming();
        send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
        send_payload(BLOCK);
        TEST_ASSERT_TRUE(e.cd.ps.trailing);                    /* seen at the 36, before the 37 */
        send_37();
        EXPECT(0x7F, 0x37, 0x72);
        expect_reason(UDSOTA_DL_BAD_STREAM);
    }
}

/* Bytes after the DEFLATE stream's end under 30 fail the 37 too. */
static void test_trailing_bytes_after_the_stream_under_30(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    g_p[g_p_len++] = 0x00;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    send_payload(BLOCK);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    expect_reason(UDSOTA_DL_BAD_STREAM);
}

/* ---- tests: formats, memory, progress ---- */

/* An engine serving only 0x10 answers 20 and 30 as an unknown DFI: 7F 34 31 before anything changes (F1F1, the
 * decoder and an image that has not passed FF01 all stay), and zbegin is never called. So is 40 on any engine. */
static void test_unserved_formats_answer_31_without_side_effects(void)
{
    udsota_engine_t only10 = ENGINE;
    only10.zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE);
    boot(&only10);
    enter_programming();
    send_34(UDSOTA_DL_DFI, IMG_LEN);                           /* an image, finished but not verified */
    set_payload(DELTA_NEW, IMG_LEN);
    send_payload(BLOCK);
    send_37();
    EXPECT(0x77);
    const unsigned aborts = e.aborts;
    srv.last_dl.reason_code = UDSOTA_DL_NOT_NEWER;             /* a marker F1F1 must keep */
    const uint8_t dfis[] = {UDSOTA_DL_DFI_DELTA, UDSOTA_DL_DFI_DELTA_DEFLATE, 0x40};
    for (size_t i = 0; i < sizeof dfis; i++) {
        send_34(dfis[i], IMG_LEN);
        EXPECT(0x7F, 0x34, 0x31);
    }
    TEST_ASSERT_EQUAL_UINT(0u, e.zbegins);
    TEST_ASSERT_EQUAL_UINT(aborts, e.aborts);
    expect_reason(UDSOTA_DL_NOT_NEWER);
    srv.last_dl.reason_code = UDSOTA_DL_OK;
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);                  /* the unverified image is still there */
    EXPECT(0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_OK);
}

/* zformats 0 serves no coded DFI, whatever zbegin is. */
static void test_zformats_zero_serves_nothing(void)
{
    udsota_engine_t none = ENGINE;
    none.zformats = 0u;
    boot(&none);
    enter_programming();
    const uint8_t dfis[] = {UDSOTA_DL_DFI_DEFLATE, UDSOTA_DL_DFI_DELTA, UDSOTA_DL_DFI_DELTA_DEFLATE};
    for (size_t i = 0; i < sizeof dfis; i++) {
        send_34(dfis[i], IMG_LEN);
        EXPECT(0x7F, 0x34, 0x31);
    }
    TEST_ASSERT_EQUAL_UINT(0u, e.zbegins);
}

/* No memory for the patch decoder: 7F 34 22 and reason 14, holding nothing. */
static void test_no_memory_for_the_decoder(void)
{
    e.fail_alloc = true;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x22);
    expect_reason(UDSOTA_DL_NO_MEMORY);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* An abort mid-patch (10 01) frees the decoders. */
static void test_abort_mid_patch_frees_the_decoders(void)
{
    set_payload(DELTA_P30, sizeof DELTA_P30);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    send_36_data(1, g_p, 100u);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_TRUE(e.allocs > e.frees);
    const uint8_t dflt[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_DEFAULT};
    send(dflt, sizeof dflt);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
    expect_reason(UDSOTA_DL_ABORTED);
}

/* Progress counts image bytes as the patch rebuilds them, never past memorySize, and reaches it at the 37. */
static void test_progress_counts_image_bytes(void)
{
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    uint32_t last = 0;
    uint8_t bsc = 1;
    for (size_t off = 0; off < g_p_len; off += 64u, bsc++) {
        const size_t n = (g_p_len - off < 64u) ? g_p_len - off : 64u;
        send_36_data(bsc, &g_p[off], n);
        EXPECT(0x76, bsc);
        udsota_progress_t pr;
        udsota_progress(&srv, &pr);
        TEST_ASSERT_TRUE(pr.done >= last && pr.done <= IMG_LEN);
        TEST_ASSERT_EQUAL_UINT32(IMG_LEN, pr.total);
        last = pr.done;
    }
    TEST_ASSERT_TRUE(last > 0u);
    send_37();
    EXPECT(0x77);
    udsota_progress_t pr;
    udsota_progress(&srv, &pr);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, pr.done);
}

/* A 37 whose check runs as a worker job (the ESP32 port runs a patch's end on its flash worker): nothing at once, 0x78
 * while it runs, then 77, and FF01 passes; a failing one answers 0x72 with its reason after the 0x78. */
static void test_37_as_a_worker_job(void)
{
    e.zend_job = true;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_payload(BLOCK);
    TEST_ASSERT_EQUAL_UINT(0u, send_37());
    unsigned pending = 0;
    finish_job(&pending);
    EXPECT(0x77);
    TEST_ASSERT_TRUE(pending >= 1u);
    expect_reason(UDSOTA_DL_OK);
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_OK);

    setUp();
    e.zend_job = true;
    g_p_len -= 40u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_payload(BLOCK);
    TEST_ASSERT_EQUAL_UINT(0u, send_37());
    pending = 0;
    finish_job(&pending);
    EXPECT(0x7F, 0x37, 0x72);
    expect_reason(UDSOTA_DL_BAD_STREAM);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* A heatshrink patch whose decoder still holds the image's last bytes when the input ends (DELTA_PTAIL, rebuilding
 * an image ending in 2,000 zeros): the 36s leave part of the image unwritten, and the 37 writes the rest, in order,
 * to exactly memorySize. That is flash work at the 37, which the ESP32 port therefore runs on its worker. */
static void test_37_writes_the_last_image_bytes(void)
{
    set_payload(DELTA_PTAIL, sizeof DELTA_PTAIL);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DELTA, IMG_LEN);
    send_payload(BLOCK);
    TEST_ASSERT_TRUE(e.next_off < IMG_LEN);
    const unsigned writes = e.writes;
    send_37();
    EXPECT(0x77);
    TEST_ASSERT_TRUE(e.writes > writes);
    TEST_ASSERT_TRUE(e.offsets_ok);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.next_off);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DELTA_TAIL, e.flash, IMG_LEN);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* The detools decoder's whole state is one small allocation. */
static void test_decoder_heap_cost(void)
{
    printf("detools state: %u bytes\n", (unsigned)udsota_detools_state_len());
    TEST_ASSERT_TRUE(udsota_detools_state_len() < 2048u);
}

/* ---- tests: the image sink on its own ---- */

static unsigned g_k_checks, g_k_begins, g_k_writes;
static uint32_t g_k_next;

/* A sink check that counts and passes. */
static int k_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    g_k_checks++;
    TEST_ASSERT_EQUAL_UINT(0u, g_k_begins);                    /* before any erase */
    return 0;
}

/* A sink erase that counts. */
static int k_begin(void *ctx, uint32_t size) { g_k_begins++; return 0; }

/* A sink write that counts and checks offsets follow on. */
static int k_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    g_k_writes++;
    TEST_ASSERT_EQUAL_UINT32(g_k_next, off);
    g_k_next = off + (uint32_t)n;
    return 0;
}

/* Held until the check has UDSOTA_IMAGE_MIN_LEN bytes; then written in full buffers, and the last at size; exactly
 * size bytes; past size is BAD_STREAM; a short image is BAD_HEADER at finish. */
static void test_isink_holds_checks_batches_and_bounds(void)
{
    static uint8_t buf[UDSOTA_IMAGE_MIN_LEN];
    const udsota_zsink_t sink = {.check_first = k_check, .begin = k_begin, .write = k_write};
    udsota_isink_t k;
    g_k_checks = g_k_begins = g_k_writes = 0;
    g_k_next = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_open(&k, &sink, buf, sizeof buf, 1000u));
    uint8_t d[1000];
    memset(d, 0x11, sizeof d);
    for (size_t i = 0; i < 319u; i++) {
        TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_push(&k, &d[i], 1u));
    }
    TEST_ASSERT_EQUAL_UINT(0u, g_k_checks);                    /* one byte short: held */
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_push(&k, &d[319], 1u));
    TEST_ASSERT_EQUAL_UINT(1u, g_k_checks);
    TEST_ASSERT_EQUAL_UINT(1u, g_k_begins);
    TEST_ASSERT_EQUAL_UINT(1u, g_k_writes);                    /* the buffer was full */
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_push(&k, &d[320], 680u));
    TEST_ASSERT_EQUAL_UINT(4u, g_k_writes);                    /* 320 + 320 + 40 at size */
    TEST_ASSERT_EQUAL_UINT32(1000u, k.written);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_isink_push(&k, d, 1u));   /* past size, and sticky */
    TEST_ASSERT_FALSE(udsota_isink_complete(&k));

    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_open(&k, &sink, buf, sizeof buf, 1000u));
    g_k_checks = g_k_begins = g_k_writes = 0;
    g_k_next = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_push(&k, d, 1000u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_finish(&k));
    TEST_ASSERT_TRUE(udsota_isink_complete(&k));

    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_open(&k, &sink, buf, sizeof buf, 1000u));
    g_k_checks = g_k_begins = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_isink_push(&k, d, 100u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_isink_finish(&k));        /* ended before the check */
    TEST_ASSERT_EQUAL_UINT(0u, g_k_begins);

    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_isink_open(&k, &sink, buf, sizeof buf - 1u, 1000u));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_delta_happy_path);
    RUN_TEST(test_compressed_delta_happy_path);
    RUN_TEST(test_either_inner_patch_under_either_dfi);
    RUN_TEST(test_header_split_one_byte_per_36);
    RUN_TEST(test_compressed_delta_in_small_blocks);
    RUN_TEST(test_wrong_magic);
    RUN_TEST(test_wrong_base_then_full_download);
    RUN_TEST(test_unidentified_base);
    RUN_TEST(test_wrong_base_under_30);
    RUN_TEST(test_patch_for_another_size);
    RUN_TEST(test_first_block_rules_run_on_the_rebuilt_image);
    RUN_TEST(test_corrupt_patch);
    RUN_TEST(test_corrupt_stream_under_30);
    RUN_TEST(test_base_read_outside_the_running_image);
    RUN_TEST(test_truncated_patch_fails_at_37);
    RUN_TEST(test_trailing_bytes_fail_at_37);
    RUN_TEST(test_trailing_bytes_after_the_stream_under_30);
    RUN_TEST(test_unserved_formats_answer_31_without_side_effects);
    RUN_TEST(test_zformats_zero_serves_nothing);
    RUN_TEST(test_no_memory_for_the_decoder);
    RUN_TEST(test_abort_mid_patch_frees_the_decoders);
    RUN_TEST(test_progress_counts_image_bytes);
    RUN_TEST(test_37_as_a_worker_job);
    RUN_TEST(test_37_writes_the_last_image_bytes);
    RUN_TEST(test_decoder_heap_cost);
    RUN_TEST(test_isink_holds_checks_batches_and_bounds);
    return UNITY_END();
}
