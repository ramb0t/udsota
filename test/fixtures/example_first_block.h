/* A synthesised first block (UDSOTA_IMAGE_MIN_LEN = 320 bytes) of an ESP-IDF v6.1 app image for the
 * neutral example device, built field by field so a reader can see what it holds:
 *   0    esp_image_header_t (24): magic E9, 4 segments, DIO, 80 MHz / 4 MB, ESP32-S3 (chip_id 9),
 *        max chip revision 0.99, SHA-256 appended
 *   24   esp_image_segment_header_t (8): segment 0 in DROM, 64 KiB
 *   32   esp_app_desc_t (256): project "example", version "1.0.0", IDF "v6.1"
 *   288  udsota_image_desc_t (32): UDSO, desc_version 1, hw_id 1, layout 1, IDs 0x710/0x718, release
 * "1.0.0" is a clean tag, so the release flag is set, as the ESP32 port's build would stamp it. The
 * header values are those of a typical v6.1 ESP32-S3 build; test_udsota_image.c pins the layout. */
#pragma once
#include <stdint.h>
#include <string.h>
#include "udsota_image.h"
#include "udsota_image_desc.h"

#define EXAMPLE_PROJECT   "example"
#define EXAMPLE_VERSION   "1.0.0"
#define EXAMPLE_HW_ID     1u
#define EXAMPLE_LAYOUT_ID 1u
#define EXAMPLE_REQ_ID    0x710u
#define EXAMPLE_RESP_ID   0x718u

/* Stores v little-endian at p. */
static inline void example_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* Stores v little-endian at p. */
static inline void example_put_le32(uint8_t *p, uint32_t v)
{
    example_put_le16(p, (uint16_t)v);
    example_put_le16(&p[2], (uint16_t)(v >> 16));
}

/* Fills out with the example device's first block, described above. */
static inline void example_first_block(uint8_t out[UDSOTA_IMAGE_MIN_LEN])
{
    memset(out, 0, UDSOTA_IMAGE_MIN_LEN);
    /* esp_image_header_t */
    out[0] = 0xE9;                              /* ESP_IMAGE_HEADER_MAGIC */
    out[1] = 4;                                 /* segment_count */
    out[2] = 0x02;                              /* spi_mode: DIO */
    out[3] = 0x2F;                              /* spi_speed 80 MHz (low nibble 0xF), spi_size 4 MB (high nibble 2) */
    example_put_le32(&out[4], 0x403799C0u);     /* entry_addr */
    out[8] = 0xEE;                              /* wp_pin: disabled */
    example_put_le16(&out[12], 0x0009);         /* chip_id: ESP32-S3 */
    out[14] = 0;                                /* min_chip_rev (legacy) */
    example_put_le16(&out[15], 0);              /* min_chip_rev_full: 0.0 */
    example_put_le16(&out[17], 99);             /* max_chip_rev_full: 0.99 */
    out[23] = 1;                                /* hash_appended */
    /* esp_image_segment_header_t */
    example_put_le32(&out[24], 0x3C090020u);    /* load_addr: DROM */
    example_put_le32(&out[28], 0x00010000u);    /* data_len */
    /* esp_app_desc_t */
    example_put_le32(&out[32], 0xABCD5432u);    /* ESP_APP_DESC_MAGIC_WORD */
    memcpy(&out[48], EXAMPLE_VERSION, strlen(EXAMPLE_VERSION));   /* version[32] */
    memcpy(&out[80], EXAMPLE_PROJECT, strlen(EXAMPLE_PROJECT));   /* project_name[32] */
    memcpy(&out[112], "00:00:00", 8);                             /* time[16] */
    memcpy(&out[128], "Jan  1 2026", 11);                         /* date[16] */
    memcpy(&out[144], "v6.1", 4);                                 /* idf_ver[32] */
    for (unsigned i = 0; i < 32u; i++) {
        out[176 + i] = (uint8_t)(0xA0u + i);                      /* app_elf_sha256[32]: any fixed bytes */
    }
    example_put_le16(&out[208], 0);             /* min_efuse_blk_rev_full */
    example_put_le16(&out[210], 199);           /* max_efuse_blk_rev_full */
    out[212] = 16;                              /* mmu_page_size: log2(64 KiB) */
    /* udsota_image_desc_t */
    const udsota_image_desc_t d = {
        .magic = UDSOTA_IMG_DESC_MAGIC, .desc_version = UDSOTA_IMG_DESC_VERSION,
        .hw_id = EXAMPLE_HW_ID, .partition_layout_id = EXAMPLE_LAYOUT_ID,
        .diag_request_id = EXAMPLE_REQ_ID, .diag_response_id = EXAMPLE_RESP_ID,
        .flags = UDSOTA_IMG_FLAG_RELEASE,
    };
    example_put_le32(&out[UDSOTA_IMG_DESC_OFFSET], d.magic);
    example_put_le16(&out[UDSOTA_IMG_DESC_OFFSET + 4u], d.desc_version);
    out[UDSOTA_IMG_DESC_OFFSET + 6u] = d.hw_id;
    out[UDSOTA_IMG_DESC_OFFSET + 7u] = d.partition_layout_id;
    example_put_le16(&out[UDSOTA_IMG_DESC_OFFSET + 8u], d.diag_request_id);
    example_put_le16(&out[UDSOTA_IMG_DESC_OFFSET + 10u], d.diag_response_id);
    out[UDSOTA_IMG_DESC_OFFSET + 12u] = d.flags;   /* reserved[19] stays zero */
}
