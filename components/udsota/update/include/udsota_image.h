/* Core first-block rules for an image delivered over UDS (pure): project, descriptor, version and size.
 * The ESP-IDF image header half is the port's, udsota_esp32_image_check() (udsota_esp32_image.h). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_update_wire.h"   /* udsota_reason_t */

/* Bytes of the first block the checks read: esp_image_header_t 24 + segment header 8 +
 * esp_app_desc_t 256 + udsota_image_desc_t 32. */
#define UDSOTA_IMAGE_MIN_LEN 320u

typedef struct {
    uint8_t  hw_id;                 /* descriptor hw_id this unit accepts (cfg.hw_id) */
    uint8_t  partition_layout_id;   /* descriptor layout this unit accepts (cfg.layout_id) */
    uint16_t diag_request_id, diag_response_id;   /* descriptor diag IDs (cfg.req_id, cfg.resp_id) */
    uint8_t  running_version[3];    /* for the downgrade rule; {0,0,0} if the running version does not parse */
    /* True only when the running image is a clean release: its own descriptor has
     * UDSOTA_IMG_FLAG_RELEASE. False for an rc, describe-suffix or dirty build, which SemVer orders below
     * the release of the same core. */
    bool     running_is_release;
    bool     allow_older;           /* true skips the version rule (UDSOTA_DL_NOT_NEWER) only; false, the default, keeps it */
    uint32_t slot_size;             /* target partition size */
    const char *product;            /* expected esp_app_desc_t project_name, matched exactly; NULL = not checked */
} udsota_image_ctx_t;

/* Checks the first block of an image announced as announced_size bytes. The block is an ESP-IDF app
 * image's first UDSOTA_IMAGE_MIN_LEN bytes: esp_app_desc_t at 32 (version at 48, project_name at 80) and
 * the udsota descriptor at UDSOTA_IMG_DESC_OFFSET. The image header (magic, segments, flash mode, chip,
 * esp_app_desc_t magic) is the port's: udsota_esp32_image_check() runs it before this. The order here is
 * length (NULL buf or ctx, len or announced_size under UDSOTA_IMAGE_MIN_LEN: UDSOTA_DL_BAD_HEADER),
 * project against ctx->product (UDSOTA_DL_BAD_PROJECT; skipped when ctx->product is NULL), descriptor
 * magic/desc_version/hw_id (UDSOTA_DL_BAD_BOARD), layout (UDSOTA_DL_BAD_LAYOUT), diag IDs
 * (UDSOTA_DL_BAD_DIAG_IDS), version, then size (UDSOTA_DL_TOO_BIG). Version: an unparseable string, or a
 * descriptor release flag that disagrees with the string being a clean "[v]M.m.p", is UDSOTA_DL_BAD_HEADER.
 * By SemVer precedence a release is accepted when its core is newer than the running core, or equal to it
 * while the running image is not a release; a dev build needs a core at least equal. Otherwise
 * UDSOTA_DL_NOT_NEWER, unless ctx->allow_older, which skips this one rule and no other. *is_release_out
 * (may be NULL) is written false on entry, then set to the descriptor's release flag once its magic and
 * desc_version check out. */
udsota_reason_t udsota_image_check(const uint8_t *buf, size_t len, uint32_t announced_size,
                                            const udsota_image_ctx_t *ctx, bool *is_release_out);

/* Parses "[v]M.m.p" (each 0..255) followed by NUL, '-' or '+' from s, never reading past n bytes
 * (for a fixed, maybe unterminated field such as esp_app_desc_t.version). On success writes out
 * and, if clean is not NULL, sets *clean true only when NUL follows the core. On failure (NULL s,
 * n 0, bad syntax, a component over 255, or no terminator within n) writes out {0,0,0} and *clean false. */
bool udsota_parse_version(const char *s, size_t n, uint8_t out[3], bool *clean);
