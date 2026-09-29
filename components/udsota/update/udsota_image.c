/* Core first-block rules (see udsota_image.h): project, descriptor, version and size. Pure. */
#include "udsota_image.h"

#include <string.h>

#include "udsota_image_desc.h"

/* IDF v6.1 layouts, copied so this file builds on the host; test_udsota_image.c pins them against
 * a first block built field by field from these headers. esp_image_header_t / esp_image_segment_header_t: bootloader_support/include/
 * esp_app_format.h. esp_app_desc_t: esp_app_format/include/esp_app_desc.h. */
#define IC_HDR_LEN          24u     /* sizeof(esp_image_header_t) */
#define IC_SEG_HDR_LEN      8u      /* sizeof(esp_image_segment_header_t) */
#define IC_APP_DESC         (IC_HDR_LEN + IC_SEG_HDR_LEN)     /* 32: esp_app_desc_t.magic_word */
#define IC_APP_VERSION      (IC_APP_DESC + 16u)               /* char version[32] */
#define IC_APP_PROJECT      (IC_APP_DESC + 48u)               /* char project_name[32] */
#define IC_APP_FIELD_LEN    32u
#define IC_APP_DESC_LEN     256u    /* sizeof(esp_app_desc_t) */

_Static_assert(IC_APP_DESC + IC_APP_DESC_LEN == UDSOTA_IMG_DESC_OFFSET,
               "udsota_image_desc_t sits right after esp_app_desc_t");
_Static_assert(UDSOTA_IMG_DESC_OFFSET + sizeof(udsota_image_desc_t) == UDSOTA_IMAGE_MIN_LEN, "min len");

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

/* See udsota_image.h. For a string this accepts, *clean is exactly the ESP32 port's release regex
 * ^v?[0-9]+\.[0-9]+\.[0-9]+$ (udsota_esp32_image_desc() in project_include.cmake);
 * every string that regex matches but this rejects (a component over 255) is UDSOTA_DL_BAD_HEADER anyway.
 * Parses into a local so a partial parse never reaches out. */
bool udsota_parse_version(const char *s, size_t n, uint8_t out[3], bool *clean)
{
    uint8_t v3[3] = {0, 0, 0};
    out[0] = out[1] = out[2] = 0;
    if (clean != NULL) {
        *clean = false;
    }
    if (s == NULL || n == 0u) {
        return false;
    }
    size_t i = (s[0] == 'v') ? 1u : 0u;
    for (int part = 0; part < 3; part++) {
        uint32_t v = 0;
        size_t digits = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            v = v * 10u + (uint32_t)(s[i] - '0');
            if (v > 255u) {
                return false;
            }
            i++;
            digits++;
        }
        if (digits == 0) {
            return false;
        }
        v3[part] = (uint8_t)v;
        if (part < 2) {
            if (i >= n || s[i] != '.') {
                return false;
            }
            i++;
        }
    }
    if (i >= n || (s[i] != '\0' && s[i] != '-' && s[i] != '+')) {
        return false;                       /* no terminator within n, or trailing junk */
    }
    memcpy(out, v3, sizeof v3);
    if (clean != NULL) {
        *clean = (s[i] == '\0');
    }
    return true;
}

/* True when the n-byte field holds exactly name: the same bytes, then a NUL or the field's end. */
static bool product_matches(const char *field, size_t n, const char *name)
{
    const size_t len = strlen(name);
    return len <= n && memcmp(field, name, len) == 0 && (len == n || field[len] == '\0');
}

/* Project, descriptor, version and size checks in that order; see udsota_image.h. */
udsota_reason_t udsota_image_check(const uint8_t *buf, size_t len, uint32_t announced_size,
                                            const udsota_image_ctx_t *ctx, bool *is_release_out)
{
    if (is_release_out != NULL) {
        *is_release_out = false;
    }
    if (buf == NULL || ctx == NULL || len < UDSOTA_IMAGE_MIN_LEN || announced_size < UDSOTA_IMAGE_MIN_LEN) {
        return UDSOTA_DL_BAD_HEADER;
    }
    /* The image header (magic, segments, flash mode, chip, app-desc magic) is the port's, checked first. */
    if (ctx->product != NULL &&
        !product_matches((const char *)&buf[IC_APP_PROJECT], IC_APP_FIELD_LEN, ctx->product)) {
        return UDSOTA_DL_BAD_PROJECT;
    }

    const uint8_t *d = &buf[UDSOTA_IMG_DESC_OFFSET];
    /* desc_version >= 1: v1 fields never move, later versions only use reserved[]. */
    if (le32(d + offsetof(udsota_image_desc_t, magic)) != UDSOTA_IMG_DESC_MAGIC ||
        le16(d + offsetof(udsota_image_desc_t, desc_version)) < UDSOTA_IMG_DESC_VERSION) {
        return UDSOTA_DL_BAD_BOARD;
    }
    /* Only bit0 is read; bits 1-7 are left for later descriptor versions. */
    const bool release = (d[offsetof(udsota_image_desc_t, flags)] & UDSOTA_IMG_FLAG_RELEASE) != 0u;
    if (is_release_out != NULL) {
        *is_release_out = release;
    }
    if (d[offsetof(udsota_image_desc_t, hw_id)] != ctx->hw_id) {
        return UDSOTA_DL_BAD_BOARD;
    }
    if (d[offsetof(udsota_image_desc_t, partition_layout_id)] != ctx->partition_layout_id) {
        return UDSOTA_DL_BAD_LAYOUT;
    }
    if (le16(d + offsetof(udsota_image_desc_t, diag_request_id)) != ctx->diag_request_id ||
        le16(d + offsetof(udsota_image_desc_t, diag_response_id)) != ctx->diag_response_id) {
        return UDSOTA_DL_BAD_DIAG_IDS;
    }

    /* An unparseable version (a tagless build) can't be installed over CAN, and the release flag
     * must agree with the string, as the build derives one from the other. */
    uint8_t ver[3];
    bool clean = false;
    if (!udsota_parse_version((const char *)&buf[IC_APP_VERSION], IC_APP_FIELD_LEN, ver, &clean) ||
        clean != release) {
        return UDSOTA_DL_BAD_HEADER;
    }
    /* SemVer precedence: a release beats a newer core, or the same core when the running image is
     * an rc, describe-suffix or dirty build of it (!running_is_release). A dev build (rc included)
     * needs a core at least equal. A running version that did not parse arrives as {0,0,0} with
     * running_is_release false and so fails open. memcmp of the {major, minor, patch} bytes orders them. */
    const int c = memcmp(ver, ctx->running_version, sizeof ver);
    bool newer = release ? (c > 0 || (c == 0 && !ctx->running_is_release)) : (c >= 0);
    if (!newer) {
        return UDSOTA_DL_NOT_NEWER;
    }
    if (announced_size > ctx->slot_size) {
        return UDSOTA_DL_TOO_BIG;
    }
    return UDSOTA_DL_OK;
}
