/* Host tests for the core first-block rules udsota_image_check() (project, descriptor, version, size)
 * against a synthesised first block of the example device (fixtures/example_first_block.h). The ESP
 * header cases are test_udsota_esp32_image.c. */
#include <string.h>
#include "unity.h"
#include "udsota_image.h"
#include "udsota_image_desc.h"
#include "fixtures/example_first_block.h"   /* example_first_block() */

_Static_assert(UDSOTA_IMG_DESC_OFFSET == 288u, "descriptor right after esp_app_desc_t");

#define SLOT_SIZE 0x400000u   /* a 4 MB ota_0/ota_1 partition */
#define ANNOUNCED 0x100000u   /* a 1 MiB image */
#define VER_OFS   48u         /* esp_app_desc_t.version: 32 + 16 */
#define PROJ_OFS  80u         /* esp_app_desc_t.project_name: 32 + 48 */
#define DESC_OFS  UDSOTA_IMG_DESC_OFFSET
#define FLAGS_OFS (DESC_OFS + 12u)   /* udsota_image_desc_t.flags */

static uint8_t img[UDSOTA_IMAGE_MIN_LEN];
static udsota_image_ctx_t ctx;
static bool rel;

/* Unity hook: a fresh example first block (release 1.0.0, flag set) and a ctx for a running example dev
 * build at 0.0.0. */
void setUp(void)
{
    example_first_block(img);
    ctx = (udsota_image_ctx_t){ .product = EXAMPLE_PROJECT, .hw_id = EXAMPLE_HW_ID,
                               .partition_layout_id = EXAMPLE_LAYOUT_ID,
                               .diag_request_id = EXAMPLE_REQ_ID, .diag_response_id = EXAMPLE_RESP_ID,
                               .running_version = {0, 0, 0}, .running_is_release = false,
                               .slot_size = SLOT_SIZE };
    rel = true;   /* sentinel: every call must write it */
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Runs the check over img with a 1 MiB announced size. */
static udsota_reason_t check(void)
{
    return udsota_image_check(img, sizeof img, ANNOUNCED, &ctx, &rel);
}

/* Overwrites the 32-byte version field with s (at most 32 chars), NUL-padded; leaves the flag alone. */
static void set_version(const char *s)
{
    memset(&img[VER_OFS], 0, 32);
    memcpy(&img[VER_OFS], s, strlen(s));
}

/* Sets or clears the descriptor's release flag (bit0), leaving the other flag bits alone. */
static void set_release_flag(bool on)
{
    if (on) {
        img[FLAGS_OFS] |= UDSOTA_IMG_FLAG_RELEASE;
    } else {
        img[FLAGS_OFS] &= (uint8_t)~UDSOTA_IMG_FLAG_RELEASE;
    }
}

/* Makes img a release build of version s: the string and the flag set, as the build stamps it. */
static void release(const char *s)
{
    set_version(s);
    set_release_flag(true);
}

/* Makes img a dev build of version s: the string and the flag clear, as the build stamps it. */
static void dev(const char *s)
{
    set_version(s);
    set_release_flag(false);
}

/* Overwrites the 32-byte project_name field with s, NUL-padded. */
static void set_project(const char *s)
{
    memset(&img[PROJ_OFS], 0, 32);
    memcpy(&img[PROJ_OFS], s, strlen(s));
}

/* Sets the running version the downgrade rule compares against, as a non-release (rc, describe or
 * dirty) build of that core. */
static void running(uint8_t a, uint8_t b, uint8_t c)
{
    ctx.running_version[0] = a;
    ctx.running_version[1] = b;
    ctx.running_version[2] = c;
    ctx.running_is_release = false;
}

/* Sets the running version as a clean release of that core (its descriptor has the release flag). */
static void running_release(uint8_t a, uint8_t b, uint8_t c)
{
    running(a, b, c);
    ctx.running_is_release = true;
}

/* The fixture has the layout the checker's copied offsets assume (IDF v6.1 header, app desc, udsota
 * descriptor), in flash byte order. */
static void test_fixture_layout(void)
{
    static const uint8_t app_magic[4] = { 0x32, 0x54, 0xCD, 0xAB };   /* ESP_APP_DESC_MAGIC_WORD LE */
    static const uint8_t desc[13] = { 0x4F, 0x53, 0x44, 0x55, 0x01, 0x00, 0x01, 0x01,
                                      0x10, 0x07, 0x18, 0x07, 0x01 };   /* UDSO v1, hw 1, layout 1, 0x710/0x718, release */
    TEST_ASSERT_EQUAL_HEX8(0xE9, img[0]);                    /* esp_image_header_t.magic */
    TEST_ASSERT_EQUAL_HEX8(0x09, img[12]);                   /* chip_id LE: ESP32-S3 */
    TEST_ASSERT_EQUAL_HEX8(0x00, img[13]);
    TEST_ASSERT_EQUAL_HEX8(0x01, img[28 + 2]);               /* segment 0 data_len 0x00010000 LE */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(app_magic, &img[32], 4);
    TEST_ASSERT_EQUAL_STRING("1.0.0", (const char *)&img[VER_OFS]);
    TEST_ASSERT_EQUAL_STRING("example", (const char *)&img[PROJ_OFS]);
    TEST_ASSERT_EQUAL_STRING("v6.1", (const char *)&img[32 + 112]);   /* esp_app_desc_t.idf_ver */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(desc, &img[DESC_OFS], sizeof desc);
    for (unsigned i = FLAGS_OFS + 1u; i < UDSOTA_IMAGE_MIN_LEN; i++) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0, img[i], "descriptor reserved[] must be zero");
    }
}

/* The example first block passes on a matching unit, reported as a release. */
static void test_example_image_passes(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_TRUE(rel);
}

/* A NULL is_release_out is allowed. */
static void test_null_release_out(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_image_check(img, sizeof img, ANNOUNCED, &ctx, NULL));
}

/* Fewer than 320 bytes, a NULL buffer or a NULL ctx -> UDSOTA_DL_BAD_HEADER and *is_release_out false. */
static void test_short_or_null(void)
{
    release("v1.0.0");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER,
                          udsota_image_check(img, UDSOTA_IMAGE_MIN_LEN - 1u, ANNOUNCED, &ctx, &rel));
    TEST_ASSERT_FALSE(rel);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_image_check(NULL, sizeof img, ANNOUNCED, &ctx, &rel));
    TEST_ASSERT_FALSE(rel);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_image_check(img, sizeof img, ANNOUNCED, NULL, &rel));
    TEST_ASSERT_FALSE(rel);
}

/* A project other than exactly "example" -> UDSOTA_DL_BAD_PROJECT, including a longer name with it as prefix. */
static void test_wrong_project(void)
{
    set_project("examplf");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
    set_project("example2");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
    set_project("exampl");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
}

/* An image with no descriptor (e.g. a build without udsota) -> UDSOTA_DL_BAD_BOARD. */
static void test_missing_descriptor(void)
{
    memset(&img[DESC_OFS], 0, sizeof(udsota_image_desc_t));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
}

/* A wrong descriptor magic -> UDSOTA_DL_BAD_BOARD, and a flag byte behind it is not reported as a release. */
static void test_bad_desc_magic_hides_flag(void)
{
    set_release_flag(true);
    img[DESC_OFS] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
    TEST_ASSERT_FALSE(rel);
}

/* desc_version 0 -> UDSOTA_DL_BAD_BOARD; a later version with the v1 fields in place is accepted. */
static void test_desc_version(void)
{
    img[DESC_OFS + 4] = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
    img[DESC_OFS + 4] = 2;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
}

/* An image for board 3 on a board-1 unit, or a board-1 image on a board-2 unit -> UDSOTA_DL_BAD_BOARD; a
 * genuine descriptor's release flag is still reported. */
static void test_wrong_board(void)
{
    set_release_flag(true);
    img[DESC_OFS + 6] = 3;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
    TEST_ASSERT_TRUE(rel);
    img[DESC_OFS + 6] = 1;
    ctx.hw_id = 2;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
}

/* A different partition_layout_id -> UDSOTA_DL_BAD_LAYOUT. */
static void test_wrong_layout(void)
{
    img[DESC_OFS + 7] = 2;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_LAYOUT, check());
}

/* Either diag ID different (a second unit's 0x711/0x719) -> UDSOTA_DL_BAD_DIAG_IDS. */
static void test_wrong_diag_ids(void)
{
    img[DESC_OFS + 8] = 0x11;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_DIAG_IDS, check());
    img[DESC_OFS + 8] = 0x10;
    img[DESC_OFS + 10] = 0x19;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_DIAG_IDS, check());
}

/* announced_size equal to the slot passes, one byte more -> UDSOTA_DL_TOO_BIG, under 320 -> UDSOTA_DL_BAD_HEADER. */
static void test_size(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_image_check(img, sizeof img, SLOT_SIZE, &ctx, &rel));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_TOO_BIG, udsota_image_check(img, sizeof img, SLOT_SIZE + 1u, &ctx, &rel));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER,
                          udsota_image_check(img, sizeof img, UDSOTA_IMAGE_MIN_LEN - 1u, &ctx, &rel));
}

/* Bits 1-7 of flags are ignored (reserved for later descriptor versions); only bit0 means release. */
static void test_other_flag_bits_ignored(void)
{
    img[FLAGS_OFS] = 0xFF;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_TRUE(rel);
    set_version("1.0.0-dev");
    img[FLAGS_OFS] = 0xFE;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
}

/* A release equal to a running release -> UDSOTA_DL_NOT_NEWER, reported as a release. */
static void test_release_equal_not_newer(void)
{
    running_release(1, 2, 3);
    release("v1.2.3");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    TEST_ASSERT_TRUE(rel);
}

/* A release older than a running release -> UDSOTA_DL_NOT_NEWER, with or without the leading "v". */
static void test_release_older_not_newer(void)
{
    running_release(1, 2, 3);
    release("v1.2.2");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    release("1.1.9");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    release("v0.255.255");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
}

/* A release newer by patch, minor or major -> UDSOTA_DL_OK and *is_release_out true. */
static void test_release_newer_ok(void)
{
    running_release(1, 2, 3);
    release("v1.2.4");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_TRUE(rel);
    release("1.3.0");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    running_release(1, 255, 255);
    release("v2.0.0");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
}

/* A dev build (describe suffix, -dirty or +meta) equal to the running version -> UDSOTA_DL_OK, not a release. */
static void test_dev_equal_ok(void)
{
    running(0, 1, 0);
    dev("v0.1.0-3-gabc1234");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
    dev("v0.1.0-dirty");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
    dev("0.1.0+devkit");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
}

/* A dev build older than the running version -> UDSOTA_DL_NOT_NEWER, not a release. */
static void test_dev_older_not_newer(void)
{
    running(0, 2, 0);
    dev("v0.1.9-12-gabc1234-dirty");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    TEST_ASSERT_FALSE(rel);
}

/* SemVer: a release of the core a running rc (or describe/dirty) build carries is newer -> UDSOTA_DL_OK. */
static void test_release_over_running_rc_same_core_ok(void)
{
    running(1, 2, 3);   /* e.g. v1.2.3-rc1: flag clear on the running image */
    release("v1.2.3");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_TRUE(rel);
}

/* A release older than the core of a running rc -> UDSOTA_DL_NOT_NEWER. */
static void test_release_older_than_running_rc_not_newer(void)
{
    running(1, 2, 3);
    release("v1.2.2");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    TEST_ASSERT_TRUE(rel);
}

/* An rc is a dev build (flag clear): rc2 over a running rc1 of the same core, and an rc over an
 * older running release, are accepted by the dev rule. */
static void test_dev_rc_over_rc_ok(void)
{
    running(1, 2, 3);   /* v1.2.3-rc1 */
    dev("v1.2.3-rc2");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
    running_release(1, 2, 2);
    dev("v1.2.3-rc1");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
}

/* A dev build newer than the running version -> UDSOTA_DL_OK. */
static void test_dev_newer_ok(void)
{
    running(0, 1, 0);
    dev("v0.2.0-1-gabc1234");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
}

/* An unparseable running version arrives as {0,0,0} and fails open, so a release 0.0.1
 * and a dev 0.0.0-x are both accepted. */
static void test_unparseable_running_fails_open(void)
{
    running(0, 0, 0);   /* the caller's zeroed version, running_is_release false */
    release("v0.0.1");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_TRUE(rel);
    dev("0.0.0-x");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
}

/* Release flag set but the version has a describe suffix -> UDSOTA_DL_BAD_HEADER (flag and string disagree). */
static void test_flag_set_dev_string(void)
{
    set_release_flag(true);
    set_version("v1.2.3-4-gabc");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    TEST_ASSERT_TRUE(rel);
    set_version("v1.2.3+devkit");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* Release flag clear but the version is a clean tag -> UDSOTA_DL_BAD_HEADER (flag and string disagree). */
static void test_flag_clear_release_string(void)
{
    set_release_flag(false);
    set_version("v1.2.3");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    TEST_ASSERT_FALSE(rel);
    set_version("1.2.3");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* A clean tag the build flags as a release but with a component over 255 -> UDSOTA_DL_BAD_HEADER, still
 * reported as a release. */
static void test_release_component_over_255(void)
{
    release("v256.0.0");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    TEST_ASSERT_TRUE(rel);
    release("v1.2.256");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* A version that doesn't parse -> UDSOTA_DL_BAD_HEADER, so a tagless build (bare hash, IDF's "1") can't be
 * installed over CAN; the descriptor's clear flag is reported. */
static void test_unparseable_version(void)
{
    set_release_flag(false);
    static const char *const bad[] = { "abcdef0", "1a2b3c4-dirty", "1234567", "1", "1.2", "256.0.0",
                                       "1.2.300", "1.2.3x", "1..3", "", "v", "V1.2.3", " 1.2.3",
                                       "0000000000000000000000000001.2.3" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        set_version(bad[i]);   /* the last one fills all 32 bytes, leaving no terminator in the field */
        rel = true;
        TEST_ASSERT_EQUAL_INT_MESSAGE(UDSOTA_DL_BAD_HEADER, check(), bad[i]);
        TEST_ASSERT_FALSE_MESSAGE(rel, bad[i]);
    }
}

/* The first failing check wins: project before board, board before size, version before size. */
static void test_first_failure_wins(void)
{
    set_project("other");
    img[DESC_OFS + 6] = 3;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT,
                          udsota_image_check(img, sizeof img, SLOT_SIZE + 1u, &ctx, &rel));
    set_project("example");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD,
                          udsota_image_check(img, sizeof img, SLOT_SIZE + 1u, &ctx, &rel));
    img[DESC_OFS + 6] = 1;
    running_release(0, 1, 0);
    release("v0.1.0");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER,
                          udsota_image_check(img, sizeof img, SLOT_SIZE + 1u, &ctx, &rel));
    TEST_ASSERT_TRUE(rel);
}

/* Asserts udsota_parse_version(s, n) fails and leaves out {0,0,0} and clean false over sentinels. */
static void assert_parse_fails(const char *s, size_t n)
{
    uint8_t out[3] = {0xAA, 0xAA, 0xAA};
    bool clean = true;
    TEST_ASSERT_FALSE(udsota_parse_version(s, n, out, &clean));
    TEST_ASSERT_EQUAL_UINT8(0, out[0]);
    TEST_ASSERT_EQUAL_UINT8(0, out[1]);
    TEST_ASSERT_EQUAL_UINT8(0, out[2]);
    TEST_ASSERT_FALSE(clean);
}

/* Asserts udsota_parse_version(s, n) gives M.m.p and the expected clean flag. */
static void assert_parse_ok(const char *s, size_t n, uint8_t M, uint8_t m, uint8_t p, bool want_clean)
{
    uint8_t out[3] = {0xAA, 0xAA, 0xAA};
    bool clean = !want_clean;
    TEST_ASSERT_TRUE(udsota_parse_version(s, n, out, &clean));
    TEST_ASSERT_EQUAL_UINT8(M, out[0]);
    TEST_ASSERT_EQUAL_UINT8(m, out[1]);
    TEST_ASSERT_EQUAL_UINT8(p, out[2]);
    TEST_ASSERT_EQUAL(want_clean, clean);
}

/* The exported parser: clean only for NUL after the core, {0,0,0} on any failure (no partial parse). */
static void test_parse_version_exported(void)
{
    assert_parse_ok("v1.2.3", 7, 1, 2, 3, true);
    assert_parse_ok("0.0.0", 6, 0, 0, 0, true);
    assert_parse_ok("255.255.255", 12, 255, 255, 255, true);
    assert_parse_ok("1.2.3-rc1", 10, 1, 2, 3, false);
    assert_parse_ok("v1.2.3+g", 9, 1, 2, 3, false);

    assert_parse_fails("1.2.x", 6);          /* would leave {1,2,0} if out were written while parsing */
    assert_parse_fails("1.2", 4);
    assert_parse_fails("256.0.0", 8);
    assert_parse_fails("1.2.3x", 7);
    assert_parse_fails("1.2.3", 5);          /* the core fills n: no terminator */
    assert_parse_fails("", 1);
    assert_parse_fails("v1.2.3", 0);
    assert_parse_fails(NULL, 8);

    uint8_t out[3] = {0xAA, 0xAA, 0xAA};
    TEST_ASSERT_TRUE(udsota_parse_version("2.0.1", 6, out, NULL));   /* clean may be NULL */
    TEST_ASSERT_EQUAL_UINT8(2, out[0]);
    TEST_ASSERT_EQUAL_UINT8(1, out[2]);
    TEST_ASSERT_FALSE(udsota_parse_version("x", 2, out, NULL));
    TEST_ASSERT_EQUAL_UINT8(0, out[0]);
}

/* ctx.product is the integrator's: NULL skips the project rule, and another name refuses this image. */
static void test_product_from_ctx(void)
{
    ctx.product = NULL;
    set_project("anything");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    ctx.product = "widget";
    set_project("widget");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    set_project("example");
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
}

/* A project name that fills the whole 32-byte field, with no terminator, matches a ctx.product of exactly
 * that name and nothing longer. */
static void test_product_fills_field(void)
{
    static const char full[] = "abcdefghijklmnopqrstuvwxyz012345";   /* 32 characters */
    set_project(full);
    ctx.product = full;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    ctx.product = "abcdefghijklmnopqrstuvwxyz0123456";                /* 33 */
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
}

/* The image header is the port's (udsota_esp32_image_check): the core passes a block whose image magic,
 * chip and app-descriptor magic it never reads. */
static void test_header_is_the_ports(void)
{
    img[0] = 0xEA;
    img[12] = 0x02;
    img[32] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
}

/* Runs the Unity tests in this file. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_fixture_layout);
    RUN_TEST(test_example_image_passes);
    RUN_TEST(test_null_release_out);
    RUN_TEST(test_short_or_null);
    RUN_TEST(test_wrong_project);
    RUN_TEST(test_product_from_ctx);
    RUN_TEST(test_product_fills_field);
    RUN_TEST(test_header_is_the_ports);
    RUN_TEST(test_missing_descriptor);
    RUN_TEST(test_bad_desc_magic_hides_flag);
    RUN_TEST(test_desc_version);
    RUN_TEST(test_wrong_board);
    RUN_TEST(test_wrong_layout);
    RUN_TEST(test_wrong_diag_ids);
    RUN_TEST(test_size);
    RUN_TEST(test_other_flag_bits_ignored);
    RUN_TEST(test_release_equal_not_newer);
    RUN_TEST(test_release_older_not_newer);
    RUN_TEST(test_release_newer_ok);
    RUN_TEST(test_dev_equal_ok);
    RUN_TEST(test_dev_older_not_newer);
    RUN_TEST(test_release_over_running_rc_same_core_ok);
    RUN_TEST(test_release_older_than_running_rc_not_newer);
    RUN_TEST(test_dev_rc_over_rc_ok);
    RUN_TEST(test_dev_newer_ok);
    RUN_TEST(test_unparseable_running_fails_open);
    RUN_TEST(test_flag_set_dev_string);
    RUN_TEST(test_flag_clear_release_string);
    RUN_TEST(test_release_component_over_255);
    RUN_TEST(test_unparseable_version);
    RUN_TEST(test_first_failure_wins);
    RUN_TEST(test_parse_version_exported);
    return UNITY_END();
}
