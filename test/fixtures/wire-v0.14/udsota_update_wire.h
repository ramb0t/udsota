/* The firmware updater's wire contract, over the server's (udsota_server_wire.h): the download framing, the
 * updater's DIDs and RIDs, and the F1F0 and F1F1 byte layouts with their codecs. Pure C. The reason codes and the
 * F1F0/F1F1 records are in udsota_update_state.h. Every value here is on the wire: changing one needs a matching
 * client change and a CHANGELOG entry. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_server_wire.h"    /* UDSOTA_DL_MAX_BLOCK_LEN */
#include "udsota_update_state.h"   /* udsota_reason_t, udsota_status_t, udsota_result_t */

/* ---- The updater's data identifiers (all readable in any session; none is secret) ---- */
#define UDSOTA_DID_SW_VERSION      0xF189   /* git describe string */
#define UDSOTA_DID_STATUS          0xF1F0   /* UDSOTA_STATUS_LEN B: udsota_status_t */
#define UDSOTA_DID_RUNNING_SHA     0xF1F3   /* 32 B: the running image's app_elf_sha256 */
#define UDSOTA_DID_RESULT          0xF1F1   /* UDSOTA_RESULT_LEN B: udsota_result_t */
#define UDSOTA_SHA256_LEN          32

/* ---- Routine identifiers (31 01 <rid>) ---- */
#define UDSOTA_RID_CHECK_PROG_DEPS   0xFF01 /* CheckProgrammingDependencies: engine.verify; status = udsota_reason_t */
#define UDSOTA_RID_GET_RESUME_POINT  0xF000 /* reserved for resume; answers status UDSOTA_RESUME_NOT_AVAILABLE */
#define UDSOTA_RID_ACTIVATE_IMAGE    0xF001
#define UDSOTA_RID_CONFIRM_IMAGE     0xF002
#define UDSOTA_RESUME_NOT_AVAILABLE  0xFF

/* ---- RequestDownload / TransferData ---- */
#define UDSOTA_DL_DFI            0x00       /* dataFormatIdentifier: no compression or encryption */
#define UDSOTA_DL_DFI_DEFLATE    0x10       /* dataFormatIdentifier: raw DEFLATE (RFC 1951, no zlib or gzip header), no
                                               encryption; served only when the engine's zformats has it */
#define UDSOTA_DL_DFI_DELTA      0x20       /* dataFormatIdentifier: a delta patch (udsota_patch.h) from the running
                                               image; served only when the engine's zformats has it */
#define UDSOTA_DL_DFI_DELTA_DEFLATE 0x30    /* dataFormatIdentifier: a delta patch, all of it raw DEFLATE; served only
                                               when the engine's zformats has it */
/* The engine.zformats bit for a coded dataFormatIdentifier: one bit per high nibble (0x10 bit 1, 0x20 bit 2, 0x30
 * bit 3). */
#define UDSOTA_DL_FMT(dfi)       ((uint16_t)(1u << (((unsigned)(dfi) >> 4) & 0xFu)))
#define UDSOTA_DL_ALFID          0x44       /* addressAndLengthFormatIdentifier the client sends: 4-byte address,
                                               4-byte size */
#define UDSOTA_DL_FIELD_MAX      4u         /* a 34 takes any ALFID whose nibbles are each 1..4: the low one the
                                               memoryAddress's bytes, the high one the memorySize's */
#define UDSOTA_DL_LFID           0x20       /* positive-response lengthFormatIdentifier: 2-byte block length */
#define UDSOTA_DL_MAX_DATA       (UDSOTA_DL_MAX_BLOCK_LEN - 2u)   /* 4093 data bytes per 0x36 */
#define UDSOTA_DL_REQ_MIN        3u         /* 34 DFI ALFID, then the two fields the ALFID sizes */
#define UDSOTA_DL_REQ_LEN        11u        /* 34 DFI ALFID address[4] size[4]: the client's 34, ALFID 44 */
#define UDSOTA_TD_MIN_LEN        3u         /* 36 BSC and at least one data byte */
/* The most bytes a coded download (DFI 0x10, 0x20 or 0x30) of a `size`-byte image may carry: size + size/8 + 1024.
 * zlib and miniz's tdefl never exceed it (their worst case is stored blocks, 5 bytes per 64 KB), and a delta patch
 * worth sending is far smaller than its image; a legal stream padded with empty blocks can, and a 36 that would carry
 * it past the bound is refused as an overrun (0x71). */
#define UDSOTA_DL_Z_BOUND(size)  ((uint64_t)(size) + ((uint64_t)(size) >> 3) + 1024u)

/* ---- F1F0 device state (engine.status; the ESP32 port answers from a cache, never esp_ota_* at read time) ---- */
#define UDSOTA_SLOT_OTA0  0x00
#define UDSOTA_SLOT_OTA1  0x01
#define UDSOTA_SLOT_NONE  0xFF          /* factory app or not known */

/* Enum values not listed below are unused: never sent; readers treat unknown values as unknown. */
typedef enum {                           /* running_state: the ESP32 port maps esp_ota_img_states_t explicitly (values differ; never cast) */
    UDSOTA_IMG_UNDEFINED      = 0,
    UDSOTA_IMG_NEW            = 1,
    UDSOTA_IMG_PENDING_VERIFY = 2,
    UDSOTA_IMG_VALID          = 3,
    UDSOTA_IMG_INVALID        = 4,
    UDSOTA_IMG_ABORTED        = 5,
} udsota_img_state_t;

typedef enum {                           /* other_slot_state (F1F0) */
    UDSOTA_OTHER_EMPTY      = 0,        /* no valid app descriptor */
    UDSOTA_OTHER_UNVERIFIED = 1,        /* holds an image not verified since boot */
    UDSOTA_OTHER_WRITING    = 2,        /* a download is writing it */
    UDSOTA_OTHER_VERIFIED   = 3,        /* passed FF01 since boot; ActivateImage may use it */
    UDSOTA_OTHER_INVALID    = 4,        /* rolled back (otadata INVALID or ABORTED) */
} udsota_other_state_t;

#define UDSOTA_STATUS_SIG_CHECKED          0x01   /* CONFIG_SECURE_SIGNED_ON_UPDATE is set */
#define UDSOTA_STATUS_BOOT_IGNORED_CONFIG  0x02   /* the boot-loop breaker ran this boot on defaults */
/* Flag bits 0x04-0x80 are reserved: sent as 0; readers treat unknown values as unknown. */

#define UDSOTA_STATUS_LEN  16                 /* udsota_status_t: single bytes in field order */
#define UDSOTA_RESULT_LEN  5                  /* udsota_result_t: reason, then bytes_received big-endian */

/* Packs F1F0 into out; returns UDSOTA_STATUS_LEN, or 0 without writing when max is short or a pointer is NULL. */
size_t udsota_pack_status(uint8_t *out, size_t max, const udsota_status_t *s);
/* Unpacks F1F0; false without touching *s when len < UDSOTA_STATUS_LEN or a pointer is NULL. */
bool   udsota_unpack_status(const uint8_t *in, size_t len, udsota_status_t *s);
/* Packs F1F1 (reason, u32 BE); returns UDSOTA_RESULT_LEN, or 0 without writing when short or NULL. */
size_t udsota_pack_result(uint8_t *out, size_t max, const udsota_result_t *s);
/* Unpacks F1F1; false without touching *s when len < UDSOTA_RESULT_LEN or a pointer is NULL. */
bool   udsota_unpack_result(const uint8_t *in, size_t len, udsota_result_t *s);
