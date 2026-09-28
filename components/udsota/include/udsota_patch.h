/* Delta downloads (DFI 0x20, and the inner layer of 0x30): the patch decoder interface and the stage that turns a
 * patch into an image rebuilt from the running one, through udsota_isink.h, so the rebuilt image gets the same
 * first-block check before any erase as a full one. The patch is Espressif's esp_delta_ota format: a 64-byte header
 * (magic, the base image's 32-byte hash, 28 reserved bytes) and a patch the decoder understands. Pure C: the core
 * never includes a patch library; components/udsota_delta supplies a udsota_patch_t on detools. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_isink.h"  /* udsota_isink_t */
#include "udsota_wire.h"   /* udsota_reason_t */

#define UDSOTA_PATCH_MAGIC       0xfccdde10u   /* the header's first 4 bytes, little-endian (esp_delta_ota's magic) */
#define UDSOTA_PATCH_HEADER_LEN  64u           /* magic, base hash, reserved */
#define UDSOTA_PATCH_HASH_LEN    32u           /* the base image's SHA-256: an ESP-IDF image's appended hash */

/* udsota_patch_t.feed results. */
#define UDSOTA_PATCH_MORE   0    /* all input taken: call again with more */
#define UDSOTA_PATCH_END    1    /* the patch has ended and the whole image is out; *consumed < n marks bytes after it */
#define UDSOTA_PATCH_ERROR  (-1) /* corrupt patch, or a read or write callback failed */

/* What a decoder reads the base from and writes the rebuilt image to. Each returns 0 on success. */
typedef struct {
    int  (*read)(void *ctx, uint32_t off, uint8_t *buf, size_t n);   /* n base bytes at off */
    int  (*write)(void *ctx, const uint8_t *d, size_t n);            /* the rebuilt image's next n bytes */
    void  *ctx;
} udsota_patch_io_t;

/* A patch decoder, one patch at a time. */
typedef struct {
    int  (*init)(void *ctx, const udsota_patch_io_t *io, uint32_t to_size);
                               /* starts a patch that must rebuild exactly to_size bytes: allocates its state; 0 = ok,
                                  else no memory. A patch for any other size fails before its first write */
    int  (*feed)(void *ctx, const uint8_t *in, size_t n, size_t *consumed);
                               /* takes up to n patch bytes, reading the base and writing the image as it goes;
                                  returns UDSOTA_PATCH_*. After END it takes nothing more. n == 0 means the input has
                                  ended: the decoder finishes what it holds and answers END, or ERROR for a patch
                                  that is short */
    void (*finish)(void *ctx); /* frees what init allocated; idempotent */
    void  *ctx;
} udsota_patch_t;

/* The running image, as the stage needs it. Each returns 0 on success. */
typedef struct {
    int  (*read)(void *ctx, uint32_t off, uint8_t *buf, size_t n);   /* n bytes at off; refuse a read outside it */
    int  (*hash)(void *ctx, uint8_t out[UDSOTA_PATCH_HASH_LEN]);     /* its SHA-256, as the header names the base */
    void  *ctx;
} udsota_pbase_t;

/* One delta download. Fill it with udsota_pstream_open; the fields are read-only to the caller. */
typedef struct {
    udsota_patch_t   patch;
    udsota_pbase_t   base;
    udsota_isink_t  *image;        /* where the rebuilt image goes; the caller opened it for memorySize bytes */
    uint8_t          header[UDSOTA_PATCH_HEADER_LEN];
    size_t           header_len;   /* header bytes gathered so far */
    uint32_t         taken;        /* patch bytes taken so far, header included */
    bool             open;         /* patch.init succeeded and patch.finish has not run */
    bool             ended;        /* the decoder reported the end of the patch */
    bool             trailing;     /* bytes arrived after the end */
    udsota_reason_t  failed;       /* the first failure (UDSOTA_DL_OK while none); every later push returns it */
} udsota_pstream_t;

/* Starts a delta download into image (opened by the caller for memorySize bytes), reading the base through base:
 * copies patch and base and calls patch.init for image->size bytes. UDSOTA_DL_OK, UDSOTA_DL_NO_MEMORY when init
 * fails, or UDSOTA_DL_BAD_HEADER for a NULL argument. */
udsota_reason_t udsota_pstream_open(udsota_pstream_t *p, const udsota_patch_t *patch, const udsota_pbase_t *base,
                                    udsota_isink_t *image);
/* Takes patch bytes, in order, in any split. Once the header is whole: a wrong magic is UDSOTA_DL_BAD_STREAM, and a
 * base hash other than base.hash's (or no hash) is UDSOTA_DL_BAD_BASE, both before any erase. Then the decoder
 * rebuilds the image into image: its reasons (the first-block check's, UDSOTA_DL_FLASH_ERROR), UDSOTA_DL_BAD_STREAM
 * for a corrupt patch, one for another size or one reading outside the base. At the patch's end the image gets
 * udsota_isink_finish. Bytes after the end are noted for udsota_pstream_end. */
udsota_reason_t udsota_pstream_push(udsota_pstream_t *p, const uint8_t *d, size_t n);
/* A udsota_push_t push over udsota_pstream_push, for a udsota_zstream_t that inflates into the stage (DFI 0x30). */
udsota_reason_t udsota_pstream_push_cb(void *p, const uint8_t *d, size_t n);
/* The 37 check: tells the decoder the input has ended (a compressed patch's decoder may still hold the image's last
 * bytes), then UDSOTA_DL_OK when the patch ended with nothing after it and the image is complete (exactly memorySize
 * bytes, all written); else UDSOTA_DL_BAD_STREAM (or the earlier failure). Closes the stage either way. */
udsota_reason_t udsota_pstream_end(udsota_pstream_t *p);
/* Frees the decoder (patch.finish) if it is open; idempotent. */
void udsota_pstream_close(udsota_pstream_t *p);
