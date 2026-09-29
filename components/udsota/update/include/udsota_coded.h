/* One coded download (DFI 0x10, 0x20 or 0x30) behind an engine's zbegin, zwrite and zend: picks the stages for the
 * DFI and chains them, so an engine only supplies its sink, buffers, decompressor and patch decoder. 0x10 is
 * inflate -> image, 0x20 is patch -> image, and 0x30 is inflate -> patch -> image, where the image is a
 * udsota_isink_t (udsota_isink.h), the inflating a udsota_zstream_t (udsota_zstream.h) and the patching a
 * udsota_pstream_t (udsota_patch.h). Pure C. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_isink.h"
#include "udsota_patch.h"
#include "udsota_zstream.h"

/* What udsota_coded_open needs; a DFI uses only its own stages' fields, and the others may be NULL. */
typedef struct {
    udsota_zsink_t          sink;       /* the engine's first-block check, erase and write */
    uint8_t                *out;        /* the image's buffer (at least UDSOTA_IMAGE_MIN_LEN bytes) */
    size_t                  out_max;
    const udsota_inflate_t *inflate;    /* 0x10 and 0x30 */
    const udsota_patch_t   *patch;      /* 0x20 and 0x30 */
    const udsota_pbase_t   *base;       /* 0x20 and 0x30: the running image */
    uint8_t                *zbuf;       /* 0x30: inflated patch bytes on their way to the patch stage */
    size_t                  zbuf_max;
} udsota_coded_cfg_t;

/* The stages of one coded download; read-only to the caller. */
typedef struct {
    uint8_t          dfi;       /* the 34's DFI; 0 while closed */
    udsota_isink_t   image;     /* 0x20 and 0x30 (0x10's image is zs.image) */
    udsota_zstream_t zs;        /* 0x10 and 0x30 */
    udsota_pstream_t ps;        /* 0x20 and 0x30 */
} udsota_coded_t;

/* Opens the stages for dfi and a size-byte image. UDSOTA_DL_OK, UDSOTA_DL_NO_MEMORY when a decoder's init fails, or
 * UDSOTA_DL_BAD_HEADER for another DFI or a missing field; a failed open holds nothing. */
udsota_reason_t udsota_coded_open(udsota_coded_t *c, uint8_t dfi, uint32_t size, const udsota_coded_cfg_t *cfg);
/* One 0x36 payload, in order: udsota_zstream_feed or udsota_pstream_push, with their results. */
udsota_reason_t udsota_coded_feed(udsota_coded_t *c, const uint8_t *d, size_t n);
/* The 37 check of every stage, outermost first; UDSOTA_DL_OK or the first failure. Closes the download. */
udsota_reason_t udsota_coded_end(udsota_coded_t *c);
/* Frees every decoder the download holds; idempotent. */
void udsota_coded_close(udsota_coded_t *c);
/* The image bytes written so far, for engine.zwritten. */
uint32_t udsota_coded_written(const udsota_coded_t *c);
