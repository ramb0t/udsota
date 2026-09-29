/* udsota image descriptor: the board, partition layout, diag IDs and release flag an app image was
 * built for, stamped at image offset 288 (right after esp_app_desc_t) so the first-block check
 * (image_check) can refuse a wrong image before anything is erased. Pure C: no IDF headers, host-testable.
 *
 * Flash bytes at offset 288 (little-endian), e.g. for layout 1 and IDs 0x710/0x718:
 *   4F 53 44 55  01 00  <hw_id>  01  10 07  18 07  <flags>  then 19 zero bytes
 * hw_id is the integrator's board number (one per board variant it ships); flags is 00 on a dev
 * build, 01 on a release build. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define UDSOTA_IMG_DESC_MAGIC      0x5544534Fu  /* "UDSO" as a big-endian word; flash bytes 4F 53 44 55 */
#define UDSOTA_IMG_DESC_VERSION    1
/* sizeof(esp_image_header_t) 24 + sizeof(esp_image_segment_header_t) 8 + sizeof(esp_app_desc_t) 256. */
#define UDSOTA_IMG_DESC_OFFSET     288u

/* flags bit0: a release build, i.e. PROJECT_VER is a clean tag [v]N.N.N (udsota_esp32_image_desc() in
 * the ESP32 port). Bits 1-7 are zero. */
#define UDSOTA_IMG_FLAG_RELEASE    0x01u

typedef struct {
    uint32_t magic;               /* UDSOTA_IMG_DESC_MAGIC */
    uint16_t desc_version;        /* UDSOTA_IMG_DESC_VERSION */
    uint8_t  hw_id;               /* the board the image was built for (cfg.hw_id) */
    uint8_t  partition_layout_id; /* the integrator's partition layout (cfg.layout_id) */
    uint16_t diag_request_id;     /* the request ID the image answers on (cfg.req_id; e.g. 0x710) */
    uint16_t diag_response_id;    /* the response ID it answers with (cfg.resp_id; e.g. 0x718) */
    uint8_t  flags;               /* UDSOTA_IMG_FLAG_* */
    uint8_t  reserved[19];        /* zeroed; keeps the struct 32 bytes */
} udsota_image_desc_t;           /* sizeof == 32, little-endian in flash */

_Static_assert(sizeof(udsota_image_desc_t) == 32, "udsota_image_desc_t must be 32 bytes");
_Static_assert(offsetof(udsota_image_desc_t, desc_version) == 4, "desc_version at 4");
_Static_assert(offsetof(udsota_image_desc_t, hw_id) == 6, "hw_id at 6");
_Static_assert(offsetof(udsota_image_desc_t, partition_layout_id) == 7, "partition_layout_id at 7");
_Static_assert(offsetof(udsota_image_desc_t, diag_request_id) == 8, "diag_request_id at 8");
_Static_assert(offsetof(udsota_image_desc_t, diag_response_id) == 10, "diag_response_id at 10");
_Static_assert(offsetof(udsota_image_desc_t, flags) == 12, "flags at 12");
_Static_assert(offsetof(udsota_image_desc_t, reserved) == 13, "reserved at 13");
