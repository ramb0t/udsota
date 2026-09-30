/* Host tests for udsota_esp32_image_check(): the ESP-IDF image header, segment 0 and esp_app_desc_t magic
 * against a synthesised first block, then the core rules it hands the block on to. */
#include <string.h>
#include "unity.h"
#include "udsota_esp32_image.h"
#include "udsota_image_desc.h"

/* The first block's layout, written out from ESP-IDF v6.1's esp_app_format.h and esp_app_desc.h rather
 * than taken from the checker, so the test does not share its offsets with the code under test. */
#define HDR_MAGIC     0u      /* esp_image_header_t.magic */
#define HDR_SEGS      1u      /* .segment_count */
#define HDR_SPI_MODE  2u      /* .spi_mode */
#define HDR_CHIP_ID   12u     /* .chip_id, uint16 LE */
#define SEG0_ADDR     24u     /* esp_image_segment_header_t.load_addr, after the 24-byte header */
#define SEG0_LEN      28u     /* .data_len, uint32 LE */
#define APP_MAGIC     32u     /* esp_app_desc_t.magic_word, uint32 LE, after the 8-byte segment header */
#define APP_VERSION   48u     /* .version[32]: 32 + 16 */
#define PROJ_OFS      80u     /* .project_name[32]: 32 + 48 */
#define DESC_OFS      288u    /* udsota_image_desc_t: 32 + sizeof(esp_app_desc_t) 256 */
#define FLAGS_OFS     (DESC_OFS + 12u)   /* udsota_image_desc_t.flags */

#define ANNOUNCED 0x100000u   /* a 1 MiB image */

_Static_assert(DESC_OFS == UDSOTA_IMG_DESC_OFFSET, "the descriptor sits where the core reads it");

static uint8_t img[UDSOTA_IMAGE_MIN_LEN];
static udsota_image_ctx_t ctx;
static bool rel;

/* Writes v little-endian into n bytes at p. */
static void put_le(uint8_t *p, uint32_t v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(v >> (8u * i));
    }
}

/* Builds the first 320 bytes of a dev build of project "example" at 1.0.0-dev for an ESP32-S3: a four-segment
 * DIO image header, segment 0 (the DROM segment esp_app_desc_t opens) of 64 KiB, the app descriptor's magic,
 * version and project name, and the udsota descriptor for hw_id 1, layout 1, IDs 0x710/0x718, flags clear. */
static void make_first_block(uint8_t *b)
{
    memset(b, 0, UDSOTA_IMAGE_MIN_LEN);
    b[HDR_MAGIC] = 0xE9;                              /* ESP_IMAGE_HEADER_MAGIC */
    b[HDR_SEGS] = 4;
    b[HDR_SPI_MODE] = 2;                              /* ESP_IMAGE_SPI_MODE_DIO */
    put_le(&b[HDR_CHIP_ID], 0x0009u, 2);              /* ESP_CHIP_ID_ESP32S3 */
    put_le(&b[SEG0_ADDR], 0x3C020020u, 4);            /* a DROM load address */
    put_le(&b[SEG0_LEN], 0x10000u, 4);
    put_le(&b[APP_MAGIC], 0xABCD5432u, 4);            /* ESP_APP_DESC_MAGIC_WORD */
    memcpy(&b[APP_VERSION], "1.0.0-dev", 9);
    memcpy(&b[PROJ_OFS], "example", 7);
    uint8_t *d = &b[DESC_OFS];
    memcpy(d, "OSDU", 4);                             /* UDSOTA_IMG_DESC_MAGIC 0x5544534F, LE */
    put_le(&d[4], 1u, 2);                             /* desc_version */
    d[6] = 1;                                         /* hw_id */
    d[7] = 1;                                         /* partition_layout_id */
    put_le(&d[8], 0x710u, 2);                         /* diag_request_id */
    put_le(&d[10], 0x718u, 2);                        /* diag_response_id */
    d[12] = 0;                                        /* flags: a dev build */
}

/* Unity hook: a fresh dev block and a ctx for a running dev build at 0.0.0 that accepts it. */
void setUp(void)
{
    make_first_block(img);
    ctx = (udsota_image_ctx_t){ .hw_id = 1, .partition_layout_id = 1,
                                .diag_request_id = 0x710, .diag_response_id = 0x718,
                                .running_version = {0, 0, 0}, .running_is_release = false,
                                .slot_size = 0x400000u, .product = "example" };
    rel = true;   /* sentinel: every call must write it */
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Runs the ESP32-S3 check over img with a 1 MiB announced size. */
static udsota_reason_t check(void)
{
    return udsota_esp32_image_check(img, sizeof img, ANNOUNCED, UDSOTA_ESP32_CHIP_ID_S3, &ctx, &rel);
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

/* The synthesised first block passes on a matching unit, reported as not a release. */
static void test_first_block_passes(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    TEST_ASSERT_FALSE(rel);
}

/* A short block, an announced size under 320, a NULL buffer or a NULL ctx -> BAD_HEADER, flag false. */
static void test_short_or_null(void)
{
    set_release_flag(true);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_esp32_image_check(img, UDSOTA_IMAGE_MIN_LEN - 1u, ANNOUNCED,
                                                                         UDSOTA_ESP32_CHIP_ID_S3, &ctx, &rel));
    TEST_ASSERT_FALSE(rel);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_esp32_image_check(img, sizeof img, UDSOTA_IMAGE_MIN_LEN - 1u,
                                                                         UDSOTA_ESP32_CHIP_ID_S3, &ctx, &rel));
    TEST_ASSERT_FALSE(rel);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_esp32_image_check(NULL, sizeof img, ANNOUNCED,
                                                                         UDSOTA_ESP32_CHIP_ID_S3, &ctx, &rel));
    TEST_ASSERT_FALSE(rel);
    rel = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, udsota_esp32_image_check(img, sizeof img, ANNOUNCED,
                                                                         UDSOTA_ESP32_CHIP_ID_S3, NULL, &rel));
    TEST_ASSERT_FALSE(rel);
}

/* A wrong image magic -> BAD_HEADER, and the flag is not reported before the descriptor is read. */
static void test_bad_image_magic(void)
{
    set_release_flag(true);
    img[0] = 0xEA;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    TEST_ASSERT_FALSE(rel);
}

/* Another chip (ESP32-S2 0x0002) or ESP_CHIP_ID_INVALID -> BAD_HEADER. */
static void test_wrong_chip(void)
{
    img[12] = 0x02;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    img[12] = 0xFF;
    img[13] = 0xFF;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* spi_mode 5 (SLOW_READ) is the last valid value; 6 -> BAD_HEADER. */
static void test_spi_mode(void)
{
    img[2] = 5;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    img[2] = 6;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* Segment count must be 1..16. */
static void test_segment_count(void)
{
    img[1] = 16;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    img[1] = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    img[1] = 17;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* Segment 0 must hold both descriptors: data_len 288 passes, 287 -> BAD_HEADER. */
static void test_seg0_too_short(void)
{
    img[28] = 0x20; img[29] = 0x01; img[30] = 0; img[31] = 0;   /* 288 LE */
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    img[28] = 0x1F;                                             /* 287 */
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* A wrong esp_app_desc_t magic -> BAD_HEADER. */
static void test_bad_app_desc_magic(void)
{
    img[32] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* The chip is the caller's (CONFIG_IDF_FIRMWARE_CHIP_ID on target): an S2 image passes an S2 check and
 * fails an S3 one. */
static void test_chip_id_is_a_parameter(void)
{
    img[12] = 0x02;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_esp32_image_check(img, sizeof img, ANNOUNCED, 0x0002u, &ctx, &rel));
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

/* The header comes first, then the core rules in their order: a bad header beats a wrong project, and a
 * good header hands the core's verdict and release flag through. */
static void test_header_then_core_rules(void)
{
    set_release_flag(true);
    memcpy(&img[PROJ_OFS], "other\0\0", 7);
    img[0] = 0xEA;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
    TEST_ASSERT_FALSE(rel);
    img[0] = 0xE9;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_PROJECT, check());
    memcpy(&img[PROJ_OFS], "example", 8);
    img[DESC_OFS + 6] = 3;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_BOARD, check());
    TEST_ASSERT_TRUE(rel);
}

/* Runs the Unity tests in this file. */
/* The port's check hands ctx->allow_older to the core: an older dev build refused with it clear is accepted
 * with it set, and a bad header still wins. */
static void test_allow_older_passes_through(void)
{
    ctx.running_version[0] = 2;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_NOT_NEWER, check());
    ctx.allow_older = true;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, check());
    img[0] = 0xEA;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_BAD_HEADER, check());
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_first_block_passes);
    RUN_TEST(test_short_or_null);
    RUN_TEST(test_bad_image_magic);
    RUN_TEST(test_wrong_chip);
    RUN_TEST(test_spi_mode);
    RUN_TEST(test_segment_count);
    RUN_TEST(test_seg0_too_short);
    RUN_TEST(test_bad_app_desc_magic);
    RUN_TEST(test_chip_id_is_a_parameter);
    RUN_TEST(test_header_then_core_rules);
    RUN_TEST(test_allow_older_passes_through);
    return UNITY_END();
}
