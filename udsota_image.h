/* udsota_image.h: the types of an image's identity, for an app that places its header and for the bootloader core and
 * the tests that read one. udsota.h takes udsota_image_desc_t from here, and udsota_app.h includes it whole. It
 * compiles as C11 and as C++.
 * Every field is little-endian; on a little-endian target each struct is its layout byte for byte, and the asserts
 * hold it to udsota_wire.h. The core reads a header as bytes, not through these types, since a 36's data may be
 * unaligned. */
#pragma once
#include <assert.h>         /* static_assert, a keyword in C++ and C23 */
#include <stddef.h>
#include <stdint.h>
#include "udsota_wire.h"

/* The descriptor: 32 bytes saying which board, slot layout and CAN IDs an image is for, so a device refuses a wrong
 * image before erasing anything. An ESP-IDF image carries it at UDSOTA_IMG_DESC_OFFSET, a bare image at the start of
 * its header's descriptor block. */
typedef struct {
    uint32_t magic;               /* UDSOTA_IMG_DESC_MAGIC */
    uint16_t desc_version;        /* 1; 0 is refused (rule BAD_BOARD) */
    uint8_t  hw_id;               /* the board (one number per board variant) */
    uint8_t  partition_layout_id; /* the partition table, or the slot layout */
    uint16_t diag_request_id;     /* the CAN IDs the image answers UDS on */
    uint16_t diag_response_id;
    uint8_t  flags;               /* 0x01: a release build (the version is a clean [v]X.Y.Z); other bits 0 */
    uint8_t  reserved[19];        /* 0 */
} udsota_image_desc_t;

static_assert(sizeof(udsota_image_desc_t) == 32u, "the descriptor is 32 bytes");
static_assert(offsetof(udsota_image_desc_t, desc_version) == 4u, "desc_version at 4");
static_assert(offsetof(udsota_image_desc_t, hw_id) == 6u, "hw_id at 6");
static_assert(offsetof(udsota_image_desc_t, partition_layout_id) == 7u, "partition_layout_id at 7");
static_assert(offsetof(udsota_image_desc_t, diag_request_id) == 8u, "diag_request_id at 8");
static_assert(offsetof(udsota_image_desc_t, diag_response_id) == 10u, "diag_response_id at 10");
static_assert(offsetof(udsota_image_desc_t, flags) == 12u, "flags at 12");
static_assert(offsetof(udsota_image_desc_t, reserved) == 13u, "reserved at 13");

/* The bare image's header: 224 bytes at the image's header offset (cfg.image_header_offset, the profile's
 * header_offset). The firmware build fills magic, header_version, flags, the descriptor, version and project, and
 * leaves the rest 0xFF; stamping pads the file with 0xFF to a multiple of 4 and writes image_length, image_id and
 * crc32, in that order, and stamping twice gives the same bytes.
 * The core accepts header_version 1 or later: fields defined in version 1 never move or change meaning, and an
 * incompatible layout gets a new magic. A version 1 core ignores the reserved bytes and the signature. The client
 * stays strict and refuses a version or a high-byte flag it does not know. */
typedef struct {
    uint32_t magic;               /* UDSOTA_BARE_HDR_MAGIC */
    uint16_t header_version;      /* UDSOTA_BARE_HDR_VERSION */
    uint16_t flags;               /* 0; version 1 defines no bit. A core ignores a set bit it does not know in the
                                     low byte, and refuses the image (reason 1) for one in the high byte */
    uint32_t image_length;        /* stamped: the image's length from its first byte, header included; a multiple
                                     of 4 */
    uint32_t crc32;               /* stamped: zlib's CRC-32 of the image's bytes before this field followed by those
                                     after it, up to image_length */
    uint8_t  reserved[16];        /* 0xFF */
    udsota_image_desc_t desc;     /* opens the 128-byte block (UDSOTA_BARE_DESC_LEN) */
    char     version[32];         /* NUL-terminated ASCII: what F189 returns */
    char     project[32];         /* NUL-terminated ASCII: the product name (rule BAD_PROJECT) */
    uint8_t  image_id[32];        /* stamped: SHA-256 of the image with image_id, crc32 and signature taken as 0xFF;
                                     what F1F3 returns */
    uint8_t  signature[UDSOTA_BARE_HDR_SIG_LEN]; /* 0xFF; reserved, no algorithm defined */
} udsota_image_header_t;

static_assert(sizeof(udsota_image_header_t) == UDSOTA_BARE_HDR_LEN, "the header is UDSOTA_BARE_HDR_LEN bytes");
static_assert(offsetof(udsota_image_header_t, magic) == 0u, "magic at 0");
static_assert(offsetof(udsota_image_header_t, header_version) == 4u, "header_version at 4");
static_assert(offsetof(udsota_image_header_t, flags) == 6u, "flags at 6");
static_assert(offsetof(udsota_image_header_t, image_length) == UDSOTA_BARE_HDR_LENGTH_OFFSET, "image_length");
static_assert(offsetof(udsota_image_header_t, crc32) == UDSOTA_BARE_HDR_CRC_OFFSET, "crc32");
static_assert(offsetof(udsota_image_header_t, reserved) == 16u, "reserved at 16");
static_assert(offsetof(udsota_image_header_t, desc) == UDSOTA_BARE_HDR_DESC_OFFSET, "the block");
static_assert(offsetof(udsota_image_header_t, version) == UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_VERSION_OFFSET,
               "version");
static_assert(offsetof(udsota_image_header_t, project) == UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET,
               "project");
static_assert(offsetof(udsota_image_header_t, image_id) == UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_IMAGE_ID_OFFSET,
               "image_id");
static_assert(offsetof(udsota_image_header_t, signature) == UDSOTA_BARE_HDR_SIG_OFFSET, "signature");
static_assert(UDSOTA_BARE_HDR_SIG_OFFSET - UDSOTA_BARE_HDR_DESC_OFFSET == UDSOTA_BARE_DESC_LEN, "the block's length");

/* 1 for a release build (a clean [v]X.Y.Z version), which sets the descriptor's flag 0x01. Under ESP-IDF udsota's
 * CMakeLists sets it from PROJECT_VER; elsewhere the product's build does. */
#ifndef UDSOTA_IMG_RELEASE
#define UDSOTA_IMG_RELEASE 0
#endif

/* The section UDSOTA_IMAGE_HEADER places the header in. The product's linker script puts that section at
 * image_header_offset into the image and keeps it. A product may define it before including this header. */
#ifndef UDSOTA_IMAGE_HEADER_SECTION
#if defined(__GNUC__)
#define UDSOTA_IMAGE_HEADER_SECTION __attribute__((section(".udsota_image_header"), used))
#else
#define UDSOTA_IMAGE_HEADER_SECTION
#endif
#endif

#define UDSOTA_IMAGE_FF8  0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
#define UDSOTA_IMAGE_FF16 UDSOTA_IMAGE_FF8, UDSOTA_IMAGE_FF8
#define UDSOTA_IMAGE_FF32 UDSOTA_IMAGE_FF16, UDSOTA_IMAGE_FF16
#define UDSOTA_IMAGE_FF64 UDSOTA_IMAGE_FF32, UDSOTA_IMAGE_FF32

/* Places the header, once, at file scope in the app: UDSOTA_IMAGE_HEADER(hw_id, layout_id, request_id, response_id,
 * "version", "project");. version and project are string literals of at most 31 characters. It fills magic,
 * header_version, flags, the descriptor, version and project, and leaves the stamped fields, the reserved bytes and
 * the signature 0xFF. The object is volatile because stamping writes image_length, image_id and crc32 after the
 * build: the app's reads of them, such as the F1F4 prefix, must come from flash, not from the initializer.
 * Example: UDSOTA_IMAGE_HEADER(1, 1, 0x710, 0x718, "1.0.0", "example"); */
#define UDSOTA_IMAGE_HEADER(hw, layout, req_id, resp_id, ver, proj)                                              \
    static_assert(sizeof(ver) <= 32u, "version: at most 31 characters");                                       \
    static_assert(sizeof(proj) <= 32u, "project: at most 31 characters");                                      \
    UDSOTA_IMAGE_HEADER_SECTION const volatile udsota_image_header_t udsota_image_header = {                    \
        .magic = UDSOTA_BARE_HDR_MAGIC, .header_version = UDSOTA_BARE_HDR_VERSION, .flags = 0u,                 \
        .image_length = 0xFFFFFFFFu, .crc32 = 0xFFFFFFFFu, .reserved = { UDSOTA_IMAGE_FF16 },                   \
        .desc = { .magic = UDSOTA_IMG_DESC_MAGIC, .desc_version = 1u, .hw_id = (uint8_t)(hw),                   \
                  .partition_layout_id = (uint8_t)(layout), .diag_request_id = (uint16_t)(req_id),              \
                  .diag_response_id = (uint16_t)(resp_id), .flags = UDSOTA_IMG_RELEASE ? 0x01u : 0x00u },        \
        .version = ver, .project = proj,                                                                        \
        .image_id = { UDSOTA_IMAGE_FF32 }, .signature = { UDSOTA_IMAGE_FF64 },                                  \
    }
extern const volatile udsota_image_header_t udsota_image_header;
