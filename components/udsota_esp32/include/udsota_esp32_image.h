/* ESP-IDF app-image first-block check (pure, host-tested): the IDF v6.1 esp_image_header_t, segment 0
 * and esp_app_desc_t magic, then the core rules (udsota_image.h) on the same block. The engine's
 * check_first calls it after esp_ota_check_image_validity() (chip revision and flash mode against the
 * running app). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_image.h"

/* ESP_CHIP_ID_ESP32S3, for host tests; the engine passes CONFIG_IDF_FIRMWARE_CHIP_ID. */
#define UDSOTA_ESP32_CHIP_ID_S3  0x0009u

/* Checks buf's image header (magic 0xE9, 1..16 segments, spi_mode <= 5, chip_id, segment 0 long enough
 * for both descriptors, esp_app_desc_t magic): UDSOTA_DL_BAD_HEADER on any failure, after the same
 * length and NULL guard as udsota_image_check(). Otherwise returns udsota_image_check(buf, len,
 * announced_size, ctx, is_release_out). *is_release_out (may be NULL) is written false on entry. */
udsota_reason_t udsota_esp32_image_check(const uint8_t *buf, size_t len, uint32_t announced_size, uint16_t chip_id,
                                         const udsota_image_ctx_t *ctx, bool *is_release_out);
