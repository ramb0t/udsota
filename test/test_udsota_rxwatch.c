/* Host tests for udsota_rxwatch: the byte-level mirror of isotp-c's receive state (FC points) and the
 * median CF interval over the last 64 CFs that the transport feeds to udsota_fc_check. */
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"           /* UDSOTA_STMIN_DEFAULT_US */
#include "udsota_rxwatch.h"

#define LIMIT_DL   4095u   /* receive limit during a download */
#define LIMIT_IDLE 256u    /* receive limit otherwise */
#define BS         64u

static udsota_rxwatch_t w;

/* Unity hook: every test starts with no message in progress and an empty window. */
void setUp(void) { udsota_rxwatch_reset(&w); }
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Feeds a short-form First Frame announcing len bytes (6 data bytes ride in it). */
static udsota_rxw_kind_t ff(uint32_t len, uint32_t limit)
{
    const uint8_t d[8] = { (uint8_t)(0x10u | ((len >> 8) & 0x0Fu)), (uint8_t)len, 1, 2, 3, 4, 5, 6 };
    return udsota_rxwatch_frame(&w, d, 8, 0, limit, BS);
}

/* Feeds a full 8-byte Consecutive Frame with sequence number sn at t_us, under block size bs. */
static udsota_rxw_kind_t cf_bs(uint32_t sn, uint32_t t_us, uint8_t bs)
{
    const uint8_t d[8] = { (uint8_t)(0x20u | (sn & 0x0Fu)), 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
    return udsota_rxwatch_frame(&w, d, 8, t_us, LIMIT_DL, bs);
}

/* Feeds a full Consecutive Frame under the diag link's BS 64. */
static udsota_rxw_kind_t cf(uint32_t sn, uint32_t t_us)
{
    return cf_bs(sn, t_us, BS);
}

/* A valid Single Frame is a complete request; SF_DL 0 (CAN FD escape) or more bytes than the DLC holds is ignored. */
static void test_single_frame_is_a_request(void)
{
    const uint8_t tp[8] = { 0x02, 0x3E, 0x80, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_SINGLE, udsota_rxwatch_frame(&w, tp, 8, 0, LIMIT_IDLE, BS));
    const uint8_t seven[8] = { 0x07, 1, 2, 3, 4, 5, 6, 7 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_SINGLE, udsota_rxwatch_frame(&w, seven, 8, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, seven, 7, 0, LIMIT_IDLE, BS));
    const uint8_t zero[8] = { 0x00, 1, 2, 3, 4, 5, 6, 7 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, zero, 8, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, zero, 0, 0, LIMIT_IDLE, BS));
}

/* A full 0x36 block (4,095 B = FF + 585 CFs) has FC points after CFs 64, 128 .. 576 and none after the last. */
static void test_full_block_fc_points(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    unsigned fc = 0;
    for (uint32_t i = 1; i <= 585u; i++) {
        const udsota_rxw_kind_t k = cf(i, i * 2000u);
        if (i == 585u) {
            TEST_ASSERT_EQUAL(UDSOTA_RXW_LAST, k);
        } else if (i % 64u == 0u) {
            TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC_FC, k);
            fc++;
        } else {
            TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, k);
        }
    }
    TEST_ASSERT_EQUAL_UINT(9, fc);
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, cf(586u, 0));   /* message complete: a stray CF changes nothing */
}

/* A message whose last byte lands in CF 64 completes there: isotp-c sends no FC after it. */
static void test_message_ending_on_the_64th_cf_sends_no_fc(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(6u + 64u * 7u, LIMIT_DL));
    for (uint32_t i = 1; i < 64u; i++) {
        TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(i, 0));
    }
    TEST_ASSERT_EQUAL(UDSOTA_RXW_LAST, cf(64u, 0));
}

/* An FF over the receive limit is refused (overflow FC, no message); one that fits a single frame is ignored. */
static void test_ff_over_limit_refused(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_REFUSED, ff(257u, LIMIT_IDLE));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, cf(1u, 0));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(256u, LIMIT_IDLE));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, ff(7u, LIMIT_IDLE));   /* isotp-c: LENGTH, the message goes on */
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));
}

/* A wrong sequence number abandons the message; later CFs of it are ignored. */
static void test_wrong_sn_breaks_the_message(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(100u, LIMIT_IDLE));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_BROKEN, cf(3u, 0));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, cf(2u, 0));
}

/* A short FF, a short CF, the client's own FC and a zero-length frame leave the message in progress alone. */
static void test_odd_frames_leave_the_message_alone(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(100u, LIMIT_IDLE));
    const uint8_t short_ff[7] = { 0x10, 0x64, 1, 2, 3, 4, 5 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, short_ff, 7, 0, LIMIT_IDLE, BS));
    const uint8_t short_cf[5] = { 0x21, 1, 2, 3, 4 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, short_cf, 5, 0, LIMIT_IDLE, BS));
    const uint8_t client_fc[8] = { 0x30, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, client_fc, 8, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, client_fc, 0, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));   /* still the same message, SN 1 */
}

/* The last CF may carry fewer bytes than 7, with a matching short DLC. */
static void test_short_last_cf_completes(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(15u, LIMIT_IDLE));   /* 6 + 7 + 2 */
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));
    const uint8_t tail[3] = { 0x22, 1, 2 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_LAST, udsota_rxwatch_frame(&w, tail, 3, 0, LIMIT_IDLE, BS));
}

/* A Single Frame arriving mid-message replaces it, as isotp-c does. */
static void test_single_frame_replaces_a_message(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(100u, LIMIT_IDLE));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));
    const uint8_t tp[8] = { 0x02, 0x3E, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_SINGLE, udsota_rxwatch_frame(&w, tp, 8, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, cf(2u, 0));
}

/* The escape-form FF carries a 32-bit big-endian length and 2 data bytes; over the limit it is refused. */
static void test_long_form_ff(void)
{
    const uint8_t lf[8] = { 0x10, 0x00, 0x00, 0x00, 0x01, 0x2C, 1, 2 };   /* 300 B */
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, udsota_rxwatch_frame(&w, lf, 8, 0, LIMIT_DL, BS));
    for (uint32_t i = 1; i < 43u; i++) {                                   /* 2 + 42 * 7 = 296 */
        TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(i, 0));
    }
    TEST_ASSERT_EQUAL(UDSOTA_RXW_LAST, cf(43u, 0));
    const uint8_t big[8] = { 0x10, 0x00, 0x00, 0x00, 0x13, 0x88, 1, 2 };  /* 5,000 B */
    TEST_ASSERT_EQUAL(UDSOTA_RXW_REFUSED, udsota_rxwatch_frame(&w, big, 8, 0, LIMIT_DL, BS));
    const uint8_t tiny[8] = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x07, 1, 2 }; /* fits a single frame */
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, tiny, 8, 0, LIMIT_DL, BS));
}

/* The median spans the last 64 CFs (63 intervals): NONE after 63 CFs, the spacing at CF 64, the first
 * FC point, so that point is judged. */
static void test_median_ready_at_cf_64(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    uint32_t t = 1000u;
    for (uint32_t i = 1; i <= 63u; i++) {
        cf(i, t);
        t += 2000u;
    }
    TEST_ASSERT_EQUAL_HEX32(UDSOTA_CF_MEDIAN_NONE, udsota_rxwatch_median_us(&w));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC_FC, cf(64u, t));
    TEST_ASSERT_EQUAL_UINT32(2000u, udsota_rxwatch_median_us(&w));
}

/* 63 intervals is an odd count, so the median is the middle value; the oldest intervals slide out. */
static void test_median_odd_window_and_slide(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    uint32_t t = 0u;
    uint32_t i = 1u;
    cf(i++, t);
    for (int n = 0; n < 32; n++) { t += 1000u; cf(i++, t); }
    for (int n = 0; n < 31; n++) { t += 3000u; cf(i++, t); }
    TEST_ASSERT_EQUAL_UINT32(1000u, udsota_rxwatch_median_us(&w));   /* 32 x 1000, 31 x 3000 */
    for (int n = 0; n < 2; n++) { t += 3000u; cf(i++, t); }
    TEST_ASSERT_EQUAL_UINT32(3000u, udsota_rxwatch_median_us(&w));   /* 30 x 1000, 33 x 3000 */
}

/* A client sending CFs 1 ms apart against the default STmin (2 ms) is caught at the first FC point, CF 64:
 * the median is 1 ms there, below the 0.8 x STmin that udsota_fc_check's monitor allows (that check itself
 * is tested in test_udsota_server_download.c). Before CF 64 there is no median to judge. */
static void test_too_fast_client_caught_at_first_fc_point(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    uint32_t t = 0u;
    for (uint32_t i = 1; i < 64u; i++) {
        TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(i, t));
        t += 1000u;
    }
    TEST_ASSERT_EQUAL_HEX32(UDSOTA_CF_MEDIAN_NONE, udsota_rxwatch_median_us(&w));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC_FC, cf(64u, t));
    const uint32_t median = udsota_rxwatch_median_us(&w);
    TEST_ASSERT_EQUAL_UINT32(1000u, median);
    TEST_ASSERT_TRUE(median * 10u < UDSOTA_STMIN_DEFAULT_US * 8u);
}

/* Each new FF starts a new window, so one block's pacing never judges the next block. */
static void test_first_frame_resets_the_window(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    for (uint32_t i = 1; i <= 65u; i++) {
        cf(i, i * 2000u);
    }
    TEST_ASSERT_EQUAL_UINT32(2000u, udsota_rxwatch_median_us(&w));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    TEST_ASSERT_EQUAL_HEX32(UDSOTA_CF_MEDIAN_NONE, udsota_rxwatch_median_us(&w));
}

/* Intervals are unsigned differences, so the 71-minute wrap of the microsecond clock is harmless. */
static void test_interval_survives_clock_wrap(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    uint32_t t = 0xFFFF0000u;
    for (uint32_t i = 1; i <= 64u; i++) {   /* 63 x 2000 us crosses 0xFFFFFFFF */
        cf(i, t);
        t += 2000u;
    }
    TEST_ASSERT_EQUAL_UINT32(2000u, udsota_rxwatch_median_us(&w));
}

/* BS 0 behaves as 64, because isotp_port_bs() maps 0 to 64. */
static void test_bs_zero_behaves_as_64(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(4095u, LIMIT_DL));
    for (uint32_t i = 1; i < 64u; i++) {
        TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf_bs(i, 0, 0));
    }
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC_FC, cf_bs(64u, 0, 0));
}

/* isotp-c drops any frame shorter than 2 bytes before reading its PCI (isotp.c:535): a 1-byte CF with a
 * wrong sequence number must not break the message, and a 1-byte SF is no request. */
static void test_one_byte_frames_are_ignored(void)
{
    TEST_ASSERT_EQUAL(UDSOTA_RXW_FIRST, ff(100u, LIMIT_IDLE));
    const uint8_t bad_sn[1] = { 0x25 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, bad_sn, 1, 0, LIMIT_IDLE, BS));
    const uint8_t sf[1] = { 0x01 };
    TEST_ASSERT_EQUAL(UDSOTA_RXW_IGNORE, udsota_rxwatch_frame(&w, sf, 1, 0, LIMIT_IDLE, BS));
    TEST_ASSERT_EQUAL(UDSOTA_RXW_CONSEC, cf(1u, 0));   /* the message is still in progress, SN 1 */
}

/* Runs every udsota_rxwatch test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_single_frame_is_a_request);
    RUN_TEST(test_full_block_fc_points);
    RUN_TEST(test_message_ending_on_the_64th_cf_sends_no_fc);
    RUN_TEST(test_ff_over_limit_refused);
    RUN_TEST(test_wrong_sn_breaks_the_message);
    RUN_TEST(test_odd_frames_leave_the_message_alone);
    RUN_TEST(test_short_last_cf_completes);
    RUN_TEST(test_single_frame_replaces_a_message);
    RUN_TEST(test_long_form_ff);
    RUN_TEST(test_median_ready_at_cf_64);
    RUN_TEST(test_median_odd_window_and_slide);
    RUN_TEST(test_too_fast_client_caught_at_first_fc_point);
    RUN_TEST(test_first_frame_resets_the_window);
    RUN_TEST(test_interval_survives_clock_wrap);
    RUN_TEST(test_bs_zero_behaves_as_64);
    RUN_TEST(test_one_byte_frames_are_ignored);
    return UNITY_END();
}
