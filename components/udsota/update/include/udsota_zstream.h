/* Compressed downloads (DFI 0x10, and the outer layer of 0x30): the decompressor interface and the stream that turns
 * a download's compressed 0x36 payloads into an image (through udsota_isink.h: the first-block check, erase and writes
 * at image offsets) or into the next stage's input (the delta patch of DFI 0x30, udsota_patch.h). Pure C: the core
 * never includes a compression library. An engine reaches it through udsota_coded.h, which chains it for DFI 0x10
 * and 0x30; components/udsota_inflate supplies a udsota_inflate_t on miniz's tinfl. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_isink.h"  /* udsota_zsink_t, udsota_isink_t */
#include "udsota_wire.h"   /* udsota_reason_t */

/* udsota_inflate_t.feed results. */
#define UDSOTA_INFLATE_MORE   0    /* all input taken or the output full: call again with more input or room */
#define UDSOTA_INFLATE_END    1    /* the stream's last block has ended and all its output is out */
#define UDSOTA_INFLATE_ERROR  (-1) /* corrupt stream */

/* A raw DEFLATE decompressor (RFC 1951, no zlib or gzip header), one stream at a time. */
typedef struct {
    int  (*init)(void *ctx);   /* starts a stream: allocates the state and dictionary, or resets them; 0 = ok, else
                                  no memory */
    int  (*feed)(void *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, size_t *consumed,
                 size_t *produced);
                               /* takes up to in_len bytes and writes up to out_max, reporting both; returns
                                  UDSOTA_INFLATE_*. After END it takes nothing more, so *consumed < in_len marks
                                  bytes after the stream's end */
    void (*finish)(void *ctx); /* frees what init allocated; idempotent */
    void  *ctx;
} udsota_inflate_t;

/* The next stage of a stream that does not end in an image: takes inflated bytes in order, returning UDSOTA_DL_OK or
 * the reason the download fails. */
typedef struct {
    udsota_reason_t (*push)(void *ctx, const uint8_t *d, size_t n);
    void            *ctx;
} udsota_push_t;

/* One compressed download. Fill it with udsota_zstream_open or udsota_zstream_open_push; the fields are read-only to
 * the caller. */
typedef struct {
    udsota_inflate_t inflate;
    udsota_isink_t   image;        /* udsota_zstream_open: the image the stream inflates to */
    udsota_push_t    next;         /* udsota_zstream_open_push: the stage the stream inflates into (push NULL else) */
    uint8_t         *buf;          /* udsota_zstream_open_push: inflated bytes on their way to next */
    size_t           buf_max;
    uint32_t         produced;     /* bytes inflated so far */
    bool             open;         /* inflate.init succeeded and inflate.finish has not run */
    bool             ended;        /* the inflater reported the end of the stream */
    bool             trailing;     /* bytes arrived after the end */
    udsota_reason_t  failed;       /* the first failure (UDSOTA_DL_OK while none); every later feed returns it */
} udsota_zstream_t;

/* Starts a stream that inflates to an image of size bytes: copies inflate, opens z->image over sink with out
 * (out_max >= UDSOTA_IMAGE_MIN_LEN) as its buffer, and calls inflate.init. UDSOTA_DL_OK, UDSOTA_DL_NO_MEMORY when
 * init fails, or UDSOTA_DL_BAD_HEADER for a NULL argument or a short out. */
udsota_reason_t udsota_zstream_open(udsota_zstream_t *z, const udsota_inflate_t *inflate, const udsota_zsink_t *sink,
                                    uint8_t *out, size_t out_max, uint32_t size);
/* Starts a stream whose inflated bytes go to next, through buf (buf_max > 0), and calls inflate.init. The same
 * results; next bounds what it takes. */
udsota_reason_t udsota_zstream_open_push(udsota_zstream_t *z, const udsota_inflate_t *inflate,
                                         const udsota_push_t *next, uint8_t *buf, size_t buf_max);
/* Inflates one 0x36 payload. Opened to an image, the bytes go to z->image (udsota_isink_commit, then
 * udsota_isink_finish at the stream's end), so nothing is erased before the image passes its first-block check; opened
 * to a next stage, every inflated buffer goes to next.push. Returns UDSOTA_DL_OK, the image's or next's reason
 * (UDSOTA_DL_BAD_HEADER when the stream ends before the image check had its bytes), UDSOTA_DL_BAD_STREAM for a
 * corrupt stream or one inflating past size, or UDSOTA_DL_FLASH_ERROR when begin or write fails. Bytes after the end
 * are noted for udsota_zstream_end. */
udsota_reason_t udsota_zstream_feed(udsota_zstream_t *z, const uint8_t *in, size_t n);
/* The 37 check: UDSOTA_DL_OK when the stream ended with nothing after its end and, opened to an image, inflated to
 * exactly size bytes, all written; else UDSOTA_DL_BAD_STREAM (or the stream's earlier failure). A next stage makes its
 * own end check. Closes the stream either way. */
udsota_reason_t udsota_zstream_end(udsota_zstream_t *z);
/* Frees the inflater (inflate.finish) if it is open; idempotent. */
void udsota_zstream_close(udsota_zstream_t *z);
