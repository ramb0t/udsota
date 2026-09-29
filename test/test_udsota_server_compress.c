/* Host tests for compressed downloads (34 with DFI 0x10): the server's 34/36/37/FF01/F000 on an engine whose zbegin,
 * zwrite and zend run udsota_zstream over the real tinfl (components/udsota_inflate), with the core's image rules
 * behind the first-block check. Streams come from miniz's tdefl, or are built by hand from stored blocks when a test
 * needs exact block boundaries. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_dl_harness.h"
#include "udsota_image.h"
#include "udsota_tinfl.h"
#include "udsota_zstream.h"
#include "fixtures/example_first_block.h"
#include "miniz/miniz.h"   /* tdefl, to make the streams */

#define T0        60000u    /* past SecurityAccess's post-boot delay */
#define IMG_LEN   20000u    /* the test image: the example first block, then text-like filler */
#define Z_CAP     (IMG_LEN * 2u)
#define OUT_LEN   1024u     /* the stream's buffer: small, so one image takes many writes */
#define BLOCK     4093u     /* data bytes per 36 */

/* The engine: udsota_zstream over tinfl into a RAM "slot", with call counts and an optional job delay. */
typedef struct {
    udsota_zstream_t zs;
    udsota_tinfl_t   tinfl;
    uint8_t          out[OUT_LEN];
    uint8_t          flash[IMG_LEN + 4096u];
    uint32_t         begin_size;          /* size begin got; 0 = never erased */
    unsigned         checks, begins, writes, zwrites, zends, aborts, verifies;
    unsigned         allocs, frees;       /* live inflater memory = allocs - frees */
    bool             fail_alloc;          /* the inflater's next allocations fail */
    size_t           check_len;           /* bytes the first-block check saw */
    uint32_t         next_off;            /* where the next write must land */
    bool             offsets_ok;          /* every write landed at next_off */
    uint32_t         job_ms;              /* 0: zwrite answers at once; else UDSOTA_PENDING for this long */
    uint32_t         job_done_at;
    int              job_result;
    bool             job_queued;
} eng_t;

static eng_t e;
static uint8_t g_req[UDSOTA_DL_MAX_BLOCK_LEN];
static uint8_t g_img[IMG_LEN];
static uint8_t g_z[Z_CAP];
static size_t g_z_len;
static unsigned g_fake_finishes;       /* the fake decompressor's finish calls */

/* ---- the inflater's memory ---- */

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

/* ---- the sink: the core image rules, then a RAM slot ---- */

/* The core image rules for a running example dev build at 0.0.0 (as test_udsota_server_download.c runs them). */
static int s_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    e.checks++;
    e.check_len = len;
    const udsota_image_ctx_t ic = {
        .product = EXAMPLE_PROJECT, .hw_id = EXAMPLE_HW_ID, .partition_layout_id = EXAMPLE_LAYOUT_ID,
        .diag_request_id = EXAMPLE_REQ_ID, .diag_response_id = EXAMPLE_RESP_ID,
        .running_version = {0, 0, 0}, .running_is_release = false, .slot_size = UDSOTA_SLOT_SIZE_DEFAULT,
    };
    *why = udsota_image_check(first, len, srv.update.dl_announced, &ic, NULL);
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

/* engine.zbegin: opens the stream over tinfl and the sink. */
static int eng_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    const udsota_inflate_t inf = udsota_tinfl_inflate(&e.tinfl);
    const udsota_zsink_t sink = {.check_first = s_check, .begin = s_begin, .write = s_write};
    return (int)udsota_zstream_open(&e.zs, &inf, &sink, e.out, sizeof e.out, size);
}

/* engine.zwrite: feeds the stream, answering at once or after job_ms as a worker would. */
static int eng_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    e.zwrites++;
    const int r = (int)udsota_zstream_feed(&e.zs, d, n);
    if (e.job_ms == 0u) return r;
    e.job_result = r;
    e.job_done_at = g_now + e.job_ms;
    e.job_queued = true;
    return UDSOTA_PENDING;
}

/* engine.zend: the 37 check. */
static int eng_zend(void *ctx)
{
    e.zends++;
    return (int)udsota_zstream_end(&e.zs);
}

/* engine.zwritten: the image bytes the stream has written, for progress. */
static uint32_t eng_zwritten(void *ctx)
{
    return e.zs.image.written;
}

/* engine.abort: closes any open stream. */
static void eng_abort(void *ctx)
{
    e.aborts++;
    udsota_zstream_close(&e.zs);
}

/* engine.verify (FF01): the slot holds the test image; a job of job_ms when that is set, as zwrite's. */
static int eng_verify(void *ctx)
{
    e.verifies++;
    const int r = memcmp(e.flash, g_img, IMG_LEN) == 0 ? 0 : (int)UDSOTA_DL_VERIFY_FAILED;
    if (e.job_ms == 0u) return r;
    e.job_result = r;
    e.job_done_at = g_now + e.job_ms;
    e.job_queued = true;
    return UDSOTA_PENDING;
}

/* engine.check_first of the raw path, which these tests never take: refuses. */
static int eng_raw_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why) { return 1; }

/* engine.begin of the raw path: fails. */
static int eng_raw_begin(void *ctx, uint32_t size) { return -1; }

/* engine.write of the raw path: fails. */
static int eng_raw_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return -1; }

/* engine.activate and engine.confirm: done at once. */
static int eng_ok(void *ctx) { return 0; }

/* UDSOTA_PENDING while a delayed zwrite runs, then its result. */
static int eng_poll(void *ctx)
{
    if (e.job_queued && g_now < e.job_done_at) return UDSOTA_PENDING;
    e.job_queued = false;
    return e.job_result;
}

static const udsota_engine_t ENGINE = {
    .check_first = eng_raw_check, .begin = eng_raw_begin, .write = eng_raw_write, .verify = eng_verify,
    .activate = eng_ok, .confirm = eng_ok, .abort = eng_abort, .poll = eng_poll, .status = udsota_mock_status,
    .ctx = &g_mock, .zbegin = eng_zbegin, .zwrite = eng_zwrite, .zend = eng_zend, .zwritten = eng_zwritten,
    .zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE),
};

/* ---- images and streams ---- */

/* The test image: the example first block, then words picked by an LCG, which DEFLATE shrinks to about half. */
static void make_image(void)
{
    static const char *const words[] = {"udsota ", "flash ", "worker ", "inflate ", "block ", "0x36 ", "slot ",
                                        "erase ", "image ", "stream ", "\n", "CAN ", "ISO-TP ", "0123 ", "abcd "};
    example_first_block(g_img);
    uint32_t x = 12345u;
    size_t i = UDSOTA_IMAGE_MIN_LEN;
    while (i < IMG_LEN) {
        x = x * 1103515245u + 12345u;
        const char *w = words[(x >> 16) % (sizeof words / sizeof words[0])];
        for (; *w != '\0' && i < IMG_LEN; w++, i++) {
            g_img[i] = (uint8_t)(*w ^ ((x >> 8) & 0x03u));
        }
    }
}

/* Raw DEFLATE of data at level 9 into g_z. */
static void deflate_into_z(const uint8_t *data, size_t n)
{
    const int flags = (int)tdefl_create_comp_flags_from_zip_params(9, -15, MZ_DEFAULT_STRATEGY);
    g_z_len = tdefl_compress_mem_to_mem(g_z, sizeof g_z, data, n, flags);
    TEST_ASSERT_TRUE(g_z_len > 0u && g_z_len < n);
}

/* Appends one stored block (BTYPE 00) of n bytes of data to g_z; final sets BFINAL. */
static void stored_block(const uint8_t *data, uint16_t n, bool final)
{
    g_z[g_z_len++] = final ? 0x01 : 0x00;
    g_z[g_z_len++] = (uint8_t)n;
    g_z[g_z_len++] = (uint8_t)(n >> 8);
    g_z[g_z_len++] = (uint8_t)~n;
    g_z[g_z_len++] = (uint8_t)(~n >> 8);
    memcpy(&g_z[g_z_len], data, n);
    g_z_len += n;
}

/* The image as stored blocks of 95 bytes, each sent as one 100-byte 36, so the first three hold their bytes back. */
static void stored_stream(void)
{
    for (size_t off = 0; off < IMG_LEN; off += 95u) {
        const uint16_t n = (uint16_t)((IMG_LEN - off < 95u) ? IMG_LEN - off : 95u);
        stored_block(&g_img[off], n, off + n == IMG_LEN);
    }
}

/* ---- the server ---- */

/* Fresh engine, image and server at T0. */
void setUp(void)
{
    udsota_zstream_close(&e.zs);
    memset(&e, 0, sizeof e);
    e.tinfl.alloc = t_alloc;
    e.tinfl.free = t_free;
    e.offsets_ok = true;
    udsota_mock_clear(&g_mock);
    g_fake_finishes = 0;
    make_image();
    g_z_len = 0;
    g_now = T0;
    boot(&ENGINE);
}

/* Frees whatever a failed test left open. */
void tearDown(void)
{
    udsota_zstream_close(&e.zs);
}

/* Sends 36 <bsc> with n bytes of g_z from off, and waits out any job; returns the final response length. */
static size_t send_36(uint8_t bsc, size_t off, size_t n)
{
    g_req[0] = UDSOTA_SID_TRANSFER_DATA;
    g_req[1] = bsc;
    memcpy(&g_req[2], &g_z[off], n);
    return send(g_req, n + 2u) != 0u ? g_resp_len : finish_job(NULL, 0);
}

/* Sends g_z from off on in blocks of chunk bytes, counters from bsc, asserting 76 <bsc> for each; returns the next
 * counter. */
static uint8_t send_stream_from(uint8_t bsc, size_t off, size_t chunk)
{
    for (; off < g_z_len; off += chunk, bsc++) {
        const size_t n = (g_z_len - off < chunk) ? g_z_len - off : chunk;
        send_36(bsc, off, n);
        EXPECT(0x76, bsc);
    }
    return bsc;
}

/* Sends all of g_z in blocks of chunk bytes, from counter 1. */
static uint8_t send_stream(size_t chunk) { return send_stream_from(1, 0, chunk); }

/* Sends 31 01 <rid>, and waits out any job. */
static size_t send_routine(uint16_t rid)
{
    const uint8_t r[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, (uint8_t)(rid >> 8), (uint8_t)rid};
    return send(r, sizeof r) != 0u ? g_resp_len : finish_job(NULL, 0);
}

/* Asserts F1F1: reason and bytes received. */
static void expect_result(uint8_t reason, uint32_t bytes)
{
    TEST_ASSERT_EQUAL_UINT8(reason, srv.update.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT32(bytes, srv.update.last_dl.bytes_received);
}

/* ---- tests ---- */

/* The whole compressed download: 34 with DFI 10 announcing the uncompressed size answers 74 20 0F FF as a raw one
 * does; each 36 carries compressed bytes; the slot receives the image at uncompressed offsets, erased once for
 * memorySize after one first-block check; 37 closes the stream and frees the inflater; FF01 passes on the image. */
static void test_compressed_happy_path(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    TEST_ASSERT_TRUE(srv.update.dl_compressed);
    TEST_ASSERT_EQUAL_UINT(2u, e.allocs);                       /* the state and the dictionary, at 34 */
    send_stream(BLOCK);
    TEST_ASSERT_EQUAL_UINT(1u, e.checks);
    TEST_ASSERT_EQUAL_UINT(1u, e.begins);
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.begin_size);           /* the erase covers the uncompressed image */
    TEST_ASSERT_TRUE(e.offsets_ok);
    TEST_ASSERT_TRUE(e.writes > 1u);
    send_37();
    EXPECT(0x77);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);                 /* freed at 37 */
    expect_result(UDSOTA_DL_OK, (uint32_t)g_z_len);            /* F1F1 counts the compressed bytes */
    TEST_ASSERT_EQUAL_UINT32(IMG_LEN, e.next_off);
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x71, 0x01, 0xFF, 0x01, 0x00);
    TEST_ASSERT_EQUAL_MEMORY(g_img, e.flash, IMG_LEN);
    TEST_ASSERT_TRUE(srv.update.slot_verified);
}

/* First-block buffering: stored blocks of 100 bytes inflate to 95 bytes each, so the first three 36s hold 285 bytes
 * and nothing is checked or erased; the fourth brings 380, and only then does the check run (on every byte held),
 * then the erase, then the writes from offset 0. */
static void test_first_block_buffered_across_blocks(void)
{
    stored_stream();
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    for (uint8_t bsc = 1; bsc <= 3; bsc++) {
        send_36(bsc, (size_t)(bsc - 1u) * 100u, 100u);
        EXPECT(0x76, bsc);
        TEST_ASSERT_EQUAL_UINT(0u, e.checks);
        TEST_ASSERT_EQUAL_UINT(0u, e.begins);
        TEST_ASSERT_EQUAL_UINT(0u, e.writes);
    }
    TEST_ASSERT_EQUAL_UINT32(285u, e.zs.image.held);
    send_36(4, 300u, 100u);
    EXPECT(0x76, 0x04);
    TEST_ASSERT_EQUAL_UINT(1u, e.checks);
    TEST_ASSERT_EQUAL_UINT(380u, e.check_len);
    TEST_ASSERT_EQUAL_UINT(1u, e.begins);
    send_stream_from(5, 400u, BLOCK);
    send_37();
    EXPECT(0x77);
    TEST_ASSERT_TRUE(e.offsets_ok);
    TEST_ASSERT_EQUAL_MEMORY(g_img, e.flash, IMG_LEN);
}

/* A stream that ends before 320 bytes are out is refused at the 36 that ends it: 0x31, F1F1 BAD_HEADER, nothing
 * erased, and the inflater freed. */
static void test_stream_ending_before_the_check_is_bad_header(void)
{
    stored_block(g_img, 200u, true);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, g_z_len);
    EXPECT(0x7F, 0x36, 0x31);
    expect_result(UDSOTA_DL_BAD_HEADER, 0u);
    TEST_ASSERT_EQUAL_UINT(0u, e.checks);
    TEST_ASSERT_EQUAL_UINT(0u, e.begins);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* A stream that ends early: memorySize announces 100 bytes more than it inflates to. Every 36 passes; 37 answers
 * 0x72 with F1F1 BAD_STREAM, the download ends, and FF01 has nothing to verify (0x24). */
static void test_stream_ending_early_fails_at_37(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN + 100u);
    send_stream(BLOCK);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    expect_result(UDSOTA_DL_BAD_STREAM, (uint32_t)g_z_len);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x7F, 0x31, 0x24);
}

/* A stream cut short (its last 36 never sent) has not ended at 37: 0x72, BAD_STREAM. */
static void test_truncated_stream_fails_at_37(void)
{
    deflate_into_z(g_img, IMG_LEN);
    g_z_len -= 10u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_stream(BLOCK);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_STREAM, srv.update.last_dl.reason_code);
}

/* Data after the end of the stream: the 36 carrying it passes, and 37 answers 0x72, BAD_STREAM. */
static void test_trailing_data_fails_at_37(void)
{
    deflate_into_z(g_img, IMG_LEN);
    memcpy(&g_z[g_z_len], "\x00\x01\x02", 3);
    g_z_len += 3u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_stream(BLOCK);
    TEST_ASSERT_TRUE(e.zs.trailing);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_STREAM, srv.update.last_dl.reason_code);
}

/* A stream that inflates to more than memorySize is refused at the 36 that overflows: 0x31, F1F1 BAD_STREAM, the
 * download over and the inflater freed; nothing past memorySize reaches the slot. */
static void test_stream_inflating_past_memory_size(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN - 1000u);
    uint8_t bsc = 1;
    size_t off = 0;
    for (; off < g_z_len; off += BLOCK, bsc++) {
        send_36(bsc, off, (g_z_len - off < BLOCK) ? g_z_len - off : BLOCK);
        if (g_resp[0] == UDSOTA_NEG_RESPONSE) break;
    }
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_STREAM, srv.update.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_TRUE(e.next_off <= IMG_LEN - 1000u);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* A corrupt stream (a block of the reserved type 11) is refused at its 36 with 0x31, F1F1 BAD_STREAM, before any
 * erase. So is one whose stored-block length check fails. */
static void test_corrupt_stream(void)
{
    g_z[0] = 0x07;                                             /* BFINAL 1, BTYPE 11 */
    memset(&g_z[1], 0x55, 99);
    g_z_len = 100;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, g_z_len);
    EXPECT(0x7F, 0x36, 0x31);
    expect_result(UDSOTA_DL_BAD_STREAM, 0u);
    TEST_ASSERT_EQUAL_UINT(0u, e.begins);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);

    g_z_len = 0;
    stored_block(g_img, 1000u, true);
    g_z[3] ^= 0x01;                                            /* NLEN no longer the complement of LEN */
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    send_36(1, 0u, g_z_len);
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_STREAM, srv.update.last_dl.reason_code);
}

/* The first-block rules run on the inflated bytes: an image for another product is refused with 0x31 and
 * BAD_PROJECT before anything is erased, as a raw one is. */
static void test_first_block_rules_run_on_inflated_bytes(void)
{
    memcpy(&g_img[80], "widget\0", 7);
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, (g_z_len < BLOCK) ? g_z_len : BLOCK);
    EXPECT(0x7F, 0x36, 0x31);
    expect_result(UDSOTA_DL_BAD_PROJECT, 0u);
    TEST_ASSERT_EQUAL_UINT(1u, e.checks);
    TEST_ASSERT_EQUAL_UINT(0u, e.begins);
}

/* No memory for the inflater at 34: 0x22, F1F1 NO_MEMORY, no download open (a 36 is 0x24), and a retry once memory
 * is back succeeds. */
static void test_allocation_failure_at_34(void)
{
    enter_programming();
    e.fail_alloc = true;
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x22);
    expect_result(UDSOTA_DL_NO_MEMORY, 0u);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_FALSE(srv.update.ota_open);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&srv));
    deflate_into_z(g_img, IMG_LEN);
    send_36(1, 0u, 100u);
    EXPECT(0x7F, 0x36, 0x24);
    e.fail_alloc = false;
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
}

/* An engine without a decompressor (zbegin NULL) answers a 34 with DFI 10 exactly as before: 7F 34 31, with F1F1,
 * the phase and the session untouched; DFI 00 still works on it. */
static void test_null_decompressor_refuses_dfi_10_as_before(void)
{
    udsota_engine_t raw = ENGINE;
    raw.zbegin = NULL;
    raw.zwrite = NULL;
    raw.zend = NULL;
    raw.zwritten = NULL;
    boot(&raw);
    enter_programming();
    srv.update.last_dl.reason_code = UDSOTA_DL_VERIFY_FAILED;
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x31);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_VERIFY_FAILED, srv.update.last_dl.reason_code);
    TEST_ASSERT_FALSE(srv.update.download_active);
    TEST_ASSERT_EQUAL_UINT(0u, e.allocs);
    send_34(UDSOTA_DL_DFI, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    /* Other compression or encryption nibbles stay refused with a decompressor, too. */
    boot(&ENGINE);
    enter_programming();
    send_34(0x11, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x31);
    send_34(0x20, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x31);
}

/* Compressed downloads are not resumable: F000 during one, after it and after one cut off answers status FF (not
 * available), so a client restarts from offset 0. */
static void test_resume_point_after_a_compressed_download(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, BLOCK);
    send_routine(UDSOTA_RID_GET_RESUME_POINT);
    EXPECT(0x71, 0x01, 0xF0, 0x00, UDSOTA_RESUME_NOT_AVAILABLE);
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_DEFAULT};
    send(sess, sizeof sess);                                   /* cuts the transfer off */
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
    enter_programming();
    send_routine(UDSOTA_RID_GET_RESUME_POINT);
    EXPECT(0x71, 0x01, 0xF0, 0x00, UDSOTA_RESUME_NOT_AVAILABLE);
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_stream(BLOCK);
    send_37();
    EXPECT(0x77);
    send_routine(UDSOTA_RID_GET_RESUME_POINT);
    EXPECT(0x71, 0x01, 0xF0, 0x00, UDSOTA_RESUME_NOT_AVAILABLE);
}

/* A 36 repeated because its 76 was lost is answered 76 again without feeding the inflater twice, and the image
 * still arrives intact. */
static void test_repeated_block_is_not_fed_twice(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, 2000u);
    EXPECT(0x76, 0x01);
    send_36(1, 0u, 2000u);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1u, e.zwrites);
    send_stream_from(2, 2000u, BLOCK);
    send_37();
    EXPECT(0x77);
    TEST_ASSERT_EQUAL_MEMORY(g_img, e.flash, IMG_LEN);
}

/* The compressed 36s may carry at most UDSOTA_DL_Z_BOUND(memorySize) bytes: a block past it is an overrun (0x71),
 * however little it inflates to (here empty stored blocks, which inflate to nothing). */
static void test_compressed_bytes_are_bounded(void)
{
    const uint32_t size = 400u;                                /* bound: 400 + 50 + 1024 = 1474 */
    TEST_ASSERT_EQUAL_UINT32(1474u, (uint32_t)UDSOTA_DL_Z_BOUND(size));
    while (g_z_len < 1475u) {
        stored_block(g_img, 0u, false);
    }
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, size);
    send_36(1, 0u, 5u);
    EXPECT(0x76, 0x01);
    send_36(2, 5u, 1470u);
    EXPECT(0x7F, 0x36, 0x71);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, srv.update.last_dl.reason_code);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* A session change mid-stream aborts the download and frees the inflater through engine.abort. */
static void test_abort_mid_stream_frees_the_inflater(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, BLOCK);
    TEST_ASSERT_EQUAL_UINT(2u, e.allocs - e.frees);
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_DEFAULT};
    send(sess, sizeof sess);
    TEST_ASSERT_EQUAL_UINT(1u, e.aborts);
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_ABORTED, srv.update.last_dl.reason_code);
}

/* A 34 that replaces a finished, unverified compressed image releases it before opening the new stream. */
static void test_new_34_after_an_unverified_image(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_stream(BLOCK);
    send_37();
    EXPECT(0x77);
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x74, 0x20, 0x0F, 0xFF);
    TEST_ASSERT_EQUAL_UINT(1u, e.aborts);
    TEST_ASSERT_EQUAL_UINT(2u, e.allocs - e.frees);            /* only the new stream's */
    send_stream(BLOCK);
    send_37();
    EXPECT(0x77);
    send_routine(UDSOTA_RID_CHECK_PROG_DEPS);
    EXPECT(0x71, 0x01, 0xFF, 0x01, 0x00);
}

/* With the inflate on a worker (zwrite answers UDSOTA_PENDING), each 36 gets 0x78 during a long job and then its
 * 76, and a refusal found on the worker still ends the transfer with 0x31. */
static void test_worker_jobs_answer_pending_then_final(void)
{
    deflate_into_z(g_img, IMG_LEN);
    e.job_ms = 200u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    g_req[0] = UDSOTA_SID_TRANSFER_DATA;
    g_req[1] = 1;
    memcpy(&g_req[2], g_z, BLOCK);
    TEST_ASSERT_EQUAL_UINT(0u, send(g_req, BLOCK + 2u));
    unsigned pending = 0;
    finish_job(&pending, 0);
    EXPECT(0x76, 0x01);
    TEST_ASSERT_EQUAL_UINT(1u, pending);

    memcpy(&g_img[80], "widget\0", 7);
    deflate_into_z(g_img, IMG_LEN);
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x22);                                  /* a download is open */
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_DEFAULT};
    send(sess, sizeof sess);                                   /* ends it */
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_36(1, 0u, BLOCK);
    EXPECT(0x7F, 0x36, 0x31);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_PROJECT, srv.update.last_dl.reason_code);
}

/* udsota_zstream on its own: a NULL or short buffer is refused at open, and bytes fed after a failure keep
 * returning that failure. */
static void test_zstream_open_and_sticky_failure(void)
{
    udsota_zstream_t z;
    const udsota_inflate_t inf = udsota_tinfl_inflate(&e.tinfl);
    const udsota_zsink_t sink = {.check_first = s_check, .begin = s_begin, .write = s_write};
    uint8_t small[UDSOTA_IMAGE_MIN_LEN - 1u];
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_zstream_open(&z, &inf, &sink, small, sizeof small, 1000u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_zstream_open(&z, NULL, &sink, e.out, sizeof e.out, 1000u));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_zstream_open(&z, &inf, &sink, e.out, sizeof e.out, 1000u));
    const uint8_t bad[] = {0x07, 0x00};
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, bad, sizeof bad));
    stored_block(g_img, 500u, true);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, g_z, g_z_len));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_end(&z));
    TEST_ASSERT_EQUAL_UINT(e.allocs, e.frees);
}

/* udsota_progress() now. */
static udsota_progress_t progress_now(void)
{
    udsota_progress_t p;
    udsota_progress(&srv, &p);
    return p;
}

/* Asserts the progress stage, done and total. */
static void expect_progress(udsota_stage_t stage, uint32_t done, uint32_t total)
{
    const udsota_progress_t p = progress_now();
    TEST_ASSERT_EQUAL_INT(stage, p.stage);
    TEST_ASSERT_EQUAL_UINT32(done, p.done);
    TEST_ASSERT_EQUAL_UINT32(total, p.total);
}

/* Progress on a compressed download counts image bytes. ERASING from the 34 through the first 36's job; WRITING
 * from its 76, with done 0 while the stream holds its first bytes back, then done equal to the bytes the stream
 * wrote (never the compressed bytes received), only growing; done == total by the last 76 and after the 37;
 * VERIFYING while FF01 runs; IDLE with reason 0 after it. */
static void test_compressed_progress_counts_image_bytes(void)
{
    stored_stream();
    e.job_ms = 200u;
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    expect_progress(UDSOTA_STAGE_ERASING, 0u, IMG_LEN);
    g_req[0] = UDSOTA_SID_TRANSFER_DATA;
    g_req[1] = 1;
    memcpy(&g_req[2], g_z, 100u);
    TEST_ASSERT_EQUAL_UINT(0u, send(g_req, 102u));            /* the first block's job runs */
    expect_progress(UDSOTA_STAGE_ERASING, 0u, IMG_LEN);
    finish_job(NULL, 0);
    EXPECT(0x76, 0x01);
    expect_progress(UDSOTA_STAGE_WRITING, 0u, IMG_LEN);        /* accepted, but nothing written yet */
    uint32_t last = 0u;
    bool grew = false;
    uint8_t bsc = 2;
    for (size_t off = 100u; off < g_z_len; off += 100u, bsc++) {
        send_36(bsc, off, (g_z_len - off < 100u) ? g_z_len - off : 100u);
        EXPECT(0x76, bsc);
        const udsota_progress_t p = progress_now();
        TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_WRITING, p.stage);
        TEST_ASSERT_EQUAL_UINT32(e.next_off, p.done);          /* the image bytes the sink got */
        TEST_ASSERT_TRUE(p.done >= last && p.done <= p.total);
        grew = grew || (p.done > last && p.done < IMG_LEN);
        last = p.done;
    }
    TEST_ASSERT_TRUE(grew);
    TEST_ASSERT_NOT_EQUAL_UINT32(srv.update.dl_received, IMG_LEN);   /* the 36s carried more than the image: headers */
    expect_progress(UDSOTA_STAGE_WRITING, IMG_LEN, IMG_LEN);   /* the last 76 flushed the stream */
    send_37();
    EXPECT(0x77);
    expect_progress(UDSOTA_STAGE_WRITING, IMG_LEN, IMG_LEN);
    const uint8_t ff01[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01};
    TEST_ASSERT_EQUAL_UINT(0u, send(ff01, sizeof ff01));
    expect_progress(UDSOTA_STAGE_VERIFYING, 0u, 0u);
    finish_job(NULL, 0);
    EXPECT(0x71, 0x01, 0xFF, 0x01, 0x00);
    expect_progress(UDSOTA_STAGE_IDLE, 0u, 0u);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_OK, progress_now().last_reason);
}

/* A compressed download that ends early reads IDLE after its failed 37, with reason 13 (BAD_STREAM). */
static void test_compressed_early_end_reads_idle_with_its_reason(void)
{
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN + 100u);
    send_stream(BLOCK);
    expect_progress(UDSOTA_STAGE_WRITING, IMG_LEN, IMG_LEN + 100u);
    send_37();
    EXPECT(0x7F, 0x37, 0x72);
    expect_progress(UDSOTA_STAGE_IDLE, 0u, 0u);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_BAD_STREAM, progress_now().last_reason);
}

/* An engine without zwritten: done stays 0 through the compressed 36s (never the compressed count), and the 37 sets
 * it to total. */
static void test_compressed_progress_without_zwritten(void)
{
    udsota_engine_t eng = ENGINE;
    eng.zwritten = NULL;
    boot(&eng);
    deflate_into_z(g_img, IMG_LEN);
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    send_stream(BLOCK);
    expect_progress(UDSOTA_STAGE_WRITING, 0u, IMG_LEN);
    send_37();
    EXPECT(0x77);
    expect_progress(UDSOTA_STAGE_WRITING, IMG_LEN, IMG_LEN);
}

static unsigned g_progress_calls;       /* hooks.progress calls since the test booted with progress_hook */
static udsota_progress_t g_progress;     /* what hooks.progress last got */

/* hooks.progress: counts the call and keeps what it got. */
static void progress_hook(void *ctx, const udsota_progress_t *p)
{
    g_progress_calls++;
    g_progress = *p;
}

/* A compressed 34 refused for memory changes F1F1's reason but not the stage (IDLE): hooks.progress still gets the
 * new reason, once, so it matches udsota_progress(). */
static void test_compressed_34_without_memory_reports_its_reason(void)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    hooks.progress = progress_hook;
    udsota_init(&srv, &cfg, &ENGINE, udsota_mock_security(), &hooks);
    enter_programming();
    g_progress_calls = 0;
    e.fail_alloc = true;
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    EXPECT(0x7F, 0x34, 0x22);
    TEST_ASSERT_EQUAL_UINT(1u, g_progress_calls);
    TEST_ASSERT_EQUAL_INT(UDSOTA_STAGE_IDLE, g_progress.stage);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_NO_MEMORY, g_progress.last_reason);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_NO_MEMORY, progress_now().last_reason);
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);                   /* the same refusal again: nothing new to report */
    TEST_ASSERT_EQUAL_UINT(1u, g_progress_calls);
}

/* A zwritten that reports 500, then 200, then 0: an engine whose count goes backwards. */
static uint32_t shrinking_zwritten(void *ctx)
{
    static const uint32_t counts[] = {500u, 200u};
    static unsigned calls;
    return calls < 2u ? counts[calls++] : 0u;
}

/* done never shrinks, whatever zwritten reports: 500 after the first 76 stays 500 after the next two. */
static void test_compressed_progress_never_shrinks(void)
{
    udsota_engine_t eng = ENGINE;
    eng.zwritten = shrinking_zwritten;
    boot(&eng);
    stored_stream();
    enter_programming();
    send_34(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    for (uint8_t bsc = 1; bsc <= 3; bsc++) {
        send_36(bsc, (size_t)(bsc - 1u) * 100u, 100u);
        EXPECT(0x76, bsc);
        expect_progress(UDSOTA_STAGE_WRITING, 500u, IMG_LEN);
    }
}

/* How the fake decompressor misbehaves: over-reports what it wrote, or what it took (and then claims the stream
 * ended), or takes nothing and writes nothing although input is left. */
typedef enum { FAKE_OVER_PRODUCED, FAKE_OVER_CONSUMED, FAKE_STUCK } fake_mode_t;

static fake_mode_t g_fake_mode;
static unsigned g_fake_feeds;          /* the fake decompressor's feed calls since fake_open */

/* Fake udsota_inflate_t.init: always has memory. */
static int fake_init(void *ctx) { return 0; }

/* Fake udsota_inflate_t.feed: reports what g_fake_mode says and writes nothing. FAKE_OVER_CONSUMED claims one byte
 * more than it was given, then that the stream ended. */
static int fake_feed(void *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, size_t *consumed,
                     size_t *produced)
{
    const bool first = (g_fake_feeds++ == 0u);
    *consumed = (g_fake_mode == FAKE_OVER_CONSUMED && first) ? in_len + 1u : 0u;
    *produced = (g_fake_mode == FAKE_OVER_PRODUCED) ? out_max + 1u : 0u;
    return (g_fake_mode == FAKE_OVER_CONSUMED && !first) ? UDSOTA_INFLATE_END : UDSOTA_INFLATE_MORE;
}

/* Fake udsota_inflate_t.finish: counted. */
static void fake_finish(void *ctx) { g_fake_finishes++; }

/* Opens a stream of 100,000 bytes over the fake decompressor in mode, so memorySize never stops a claim first. */
static void fake_open(udsota_zstream_t *z, fake_mode_t mode)
{
    g_fake_mode = mode;
    g_fake_feeds = 0;
    const udsota_inflate_t inf = {.init = fake_init, .feed = fake_feed, .finish = fake_finish};
    const udsota_zsink_t sink = {.check_first = s_check, .begin = s_begin, .write = s_write};
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_zstream_open(z, &inf, &sink, e.out, sizeof e.out, 100000u));
}

/* A decompressor that claims more output than the room it was given is a corrupt stream: nothing is counted, held
 * or written, so a later call can never write past the buffer. */
static void test_zstream_refuses_over_reported_output(void)
{
    udsota_zstream_t z;
    fake_open(&z, FAKE_OVER_PRODUCED);
    const uint8_t in[8] = {0};
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, in, sizeof in));
    TEST_ASSERT_EQUAL_UINT32(0u, z.produced);
    TEST_ASSERT_EQUAL_size_t(0u, z.image.held);
    TEST_ASSERT_EQUAL_UINT(0u, e.checks + e.begins + e.writes);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_end(&z));
    TEST_ASSERT_EQUAL_UINT(1u, g_fake_finishes);
}

/* A decompressor that claims to have taken more input than it was given is a corrupt stream at once, before the
 * wrapped count of what is left could reach it again. */
static void test_zstream_refuses_over_reported_input(void)
{
    udsota_zstream_t z;
    fake_open(&z, FAKE_OVER_CONSUMED);
    const uint8_t in[8] = {0};
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, in, sizeof in));
    TEST_ASSERT_EQUAL_UINT(1u, g_fake_feeds);
    TEST_ASSERT_FALSE(z.ended);
    TEST_ASSERT_EQUAL_UINT(0u, e.checks + e.begins + e.writes);
    udsota_zstream_close(&z);
}

/* A decompressor that takes nothing and writes nothing while input is left would drop that input: a corrupt stream.
 * With no input left the same answer just means it waits for more. */
static void test_zstream_refuses_a_stuck_decompressor(void)
{
    udsota_zstream_t z;
    fake_open(&z, FAKE_STUCK);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_zstream_feed(&z, NULL, 0u));
    const uint8_t in[8] = {0};
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, in, sizeof in));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_STREAM, udsota_zstream_feed(&z, NULL, 0u));   /* the failure sticks */
    udsota_zstream_close(&z);
}

/* Fills an allocation with 0xAA, as a reused heap block might hold. */
static void *t_alloc_dirty(void *ctx, size_t n)
{
    void *p = t_alloc(ctx, n);
    if (p != NULL) memset(p, 0xAA, n);
    return p;
}

/* A back-reference before the stream's first byte (fixed block: length 3 at distance 1, then end), which zlib refuses
 * as too far back, copies zeros from the cleared dictionary, never the heap's old bytes. */
static void test_reference_before_the_start_reads_zeros(void)
{
    static const uint8_t z[] = {0x03, 0x02, 0x00};
    e.tinfl.alloc = t_alloc_dirty;
    const udsota_inflate_t inf = udsota_tinfl_inflate(&e.tinfl);
    TEST_ASSERT_EQUAL_INT(0, inf.init(inf.ctx));
    uint8_t out[8];
    memset(out, 0x55, sizeof out);
    size_t used = 0, made = 0;
    const int rc = inf.feed(inf.ctx, z, sizeof z, out, sizeof out, &used, &made);
    inf.finish(inf.ctx);
    TEST_ASSERT_EQUAL_INT(UDSOTA_INFLATE_END, rc);
    TEST_ASSERT_EQUAL_size_t(3u, made);
    const uint8_t zeros[3] = {0};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zeros, out, 3);
}

/* The inflater's heap per stream: the state (8 to 11 KB by build; 11,008 B in the ESP32 ROM's layout) plus the 32 KB
 * dictionary. Printed for the port's docs. */
static void test_inflater_heap_cost(void)
{
    const size_t state = udsota_tinfl_state_len();
    TEST_ASSERT_TRUE(state > 7000u && state < 12000u);
    char msg[80];
    snprintf(msg, sizeof msg, "tinfl state %u B + dictionary %u B", (unsigned)state, (unsigned)UDSOTA_TINFL_DICT_LEN);
    TEST_MESSAGE(msg);
}

/* Runs every test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_compressed_happy_path);
    RUN_TEST(test_first_block_buffered_across_blocks);
    RUN_TEST(test_stream_ending_before_the_check_is_bad_header);
    RUN_TEST(test_stream_ending_early_fails_at_37);
    RUN_TEST(test_truncated_stream_fails_at_37);
    RUN_TEST(test_trailing_data_fails_at_37);
    RUN_TEST(test_stream_inflating_past_memory_size);
    RUN_TEST(test_corrupt_stream);
    RUN_TEST(test_first_block_rules_run_on_inflated_bytes);
    RUN_TEST(test_allocation_failure_at_34);
    RUN_TEST(test_null_decompressor_refuses_dfi_10_as_before);
    RUN_TEST(test_resume_point_after_a_compressed_download);
    RUN_TEST(test_repeated_block_is_not_fed_twice);
    RUN_TEST(test_compressed_bytes_are_bounded);
    RUN_TEST(test_abort_mid_stream_frees_the_inflater);
    RUN_TEST(test_new_34_after_an_unverified_image);
    RUN_TEST(test_worker_jobs_answer_pending_then_final);
    RUN_TEST(test_zstream_open_and_sticky_failure);
    RUN_TEST(test_compressed_progress_counts_image_bytes);
    RUN_TEST(test_compressed_early_end_reads_idle_with_its_reason);
    RUN_TEST(test_compressed_progress_without_zwritten);
    RUN_TEST(test_compressed_progress_never_shrinks);
    RUN_TEST(test_compressed_34_without_memory_reports_its_reason);
    RUN_TEST(test_zstream_refuses_over_reported_output);
    RUN_TEST(test_zstream_refuses_over_reported_input);
    RUN_TEST(test_zstream_refuses_a_stuck_decompressor);
    RUN_TEST(test_reference_before_the_start_reads_zeros);
    RUN_TEST(test_inflater_heap_cost);
    return UNITY_END();
}
