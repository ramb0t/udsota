/* ESP-IDF first-block header check (see udsota_esp32_image.h). Pure: builds on the host. */
#include "udsota_esp32_image.h"

#include "udsota_image_desc.h"

/* IDF v6.1 layouts, copied so this file builds on the host; udsota_esp32_engine.c pins them to IDF's
 * headers at compile time. esp_image_header_t / esp_image_segment_header_t: bootloader_support/include/
 * esp_app_format.h. esp_app_desc_t: esp_app_format/include/esp_app_desc.h. */
#define IC_HDR_MAGIC        0u      /* uint8_t magic */
#define IC_HDR_SEG_COUNT    1u      /* uint8_t segment_count */
#define IC_HDR_SPI_MODE     2u      /* uint8_t spi_mode */
#define IC_HDR_CHIP_ID      12u     /* uint16_t chip_id, LE */
#define IC_HDR_LEN          24u     /* sizeof(esp_image_header_t) */
#define IC_SEG0_DATA_LEN    (IC_HDR_LEN + 4u)                 /* segment 0 data_len, LE */
#define IC_SEG_HDR_LEN      8u      /* sizeof(esp_image_segment_header_t) */
#define IC_APP_DESC         (IC_HDR_LEN + IC_SEG_HDR_LEN)     /* 32: esp_app_desc_t.magic_word */
#define IC_APP_DESC_LEN     256u    /* sizeof(esp_app_desc_t) */

#define IC_IMAGE_MAGIC      0xE9u        /* ESP_IMAGE_HEADER_MAGIC */
#define IC_MAX_SEGMENTS     16u          /* ESP_IMAGE_MAX_SEGMENTS */
#define IC_SPI_MODE_MAX     5u           /* ESP_IMAGE_SPI_MODE_SLOW_READ */
#define IC_APP_DESC_MAGIC   0xABCD5432u  /* ESP_APP_DESC_MAGIC_WORD */

_Static_assert(IC_APP_DESC + IC_APP_DESC_LEN == UDSOTA_IMG_DESC_OFFSET,
               "udsota_image_desc_t sits right after esp_app_desc_t");

/* Little-endian uint16 at p. */
static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

/* Little-endian uint32 at p. */
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Header, chip, segment 0 and app-desc magic, then the core rules; see udsota_esp32_image.h. */
udsota_reason_t udsota_esp32_image_check(const uint8_t *buf, size_t len, uint32_t announced_size, uint16_t chip_id,
                                         const udsota_image_ctx_t *ctx, bool *is_release_out)
{
    if (is_release_out != NULL) {
        *is_release_out = false;
    }
    if (buf == NULL || ctx == NULL || len < UDSOTA_IMAGE_MIN_LEN || announced_size < UDSOTA_IMAGE_MIN_LEN) {
        return UDSOTA_DL_BAD_HEADER;
    }
    if (buf[IC_HDR_MAGIC] != IC_IMAGE_MAGIC ||
        buf[IC_HDR_SEG_COUNT] == 0u || buf[IC_HDR_SEG_COUNT] > IC_MAX_SEGMENTS ||
        buf[IC_HDR_SPI_MODE] > IC_SPI_MODE_MAX ||
        le16(&buf[IC_HDR_CHIP_ID]) != chip_id ||
        le32(&buf[IC_SEG0_DATA_LEN]) < IC_APP_DESC_LEN + sizeof(udsota_image_desc_t) ||
        le32(&buf[IC_APP_DESC]) != IC_APP_DESC_MAGIC) {
        return UDSOTA_DL_BAD_HEADER;
    }
    return udsota_image_check(buf, len, announced_size, ctx, is_release_out);
}
