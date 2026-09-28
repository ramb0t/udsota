/* Compressed downloads (DFI 0x10): the decompressor interface and the stream that turns a download's compressed
 * 0x36 payloads into the engine's first-block check, erase and writes at uncompressed offsets. Pure C: the core
 * never includes a compression library. An engine that serves DFI 0x10 runs a udsota_zstream_t behind its
 * zbegin, zwrite and zend (udsota.h) wherever it does its flash work; components/udsota_inflate supplies a
 * udsota_inflate_t on miniz's tinfl. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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

/* Where a stream's inflated bytes go: the engine's own synchronous first-block check, erase and write. Each
 * returns 0 on success. */
typedef struct {
    int  (*check_first)(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why);   /* as engine.check_first */
    int  (*begin)(void *ctx, uint32_t size);                               /* erase for size bytes */
    int  (*write)(void *ctx, uint32_t off, const uint8_t *d, size_t n);    /* write at uncompressed offset off */
    void  *ctx;
} udsota_zsink_t;

/* One compressed download. Fill it with udsota_zstream_open; the fields are read-only to the caller. */
typedef struct {
    udsota_inflate_t inflate;
    udsota_zsink_t   sink;
    uint8_t         *out;          /* the caller's output buffer: inflated bytes wait here until written */
    size_t           out_max;      /* at least UDSOTA_IMAGE_MIN_LEN */
    uint32_t         size;         /* memorySize: the uncompressed image the 34 announced */
    uint32_t         produced;     /* bytes inflated so far */
    uint32_t         written;      /* image bytes handed to sink.write so far: the download's progress */
    size_t           held;         /* bytes in out not yet written (produced - written) */
    bool             open;         /* inflate.init succeeded and inflate.finish has not run */
    bool             begun;        /* the first-block check passed and sink.begin succeeded */
    bool             ended;        /* the inflater reported the end of the stream */
    bool             trailing;     /* bytes arrived after the end */
    udsota_reason_t  failed;       /* the first failure (UDSOTA_DL_OK while none); every later feed returns it */
} udsota_zstream_t;

/* Starts a stream of size uncompressed bytes: copies inflate and sink, takes out (out_max >= UDSOTA_IMAGE_MIN_LEN)
 * as the output buffer and calls inflate.init. UDSOTA_DL_OK, UDSOTA_DL_NO_MEMORY when init fails, or
 * UDSOTA_DL_BAD_HEADER for a NULL argument or a short out. */
udsota_reason_t udsota_zstream_open(udsota_zstream_t *z, const udsota_inflate_t *inflate, const udsota_zsink_t *sink,
                                    uint8_t *out, size_t out_max, uint32_t size);
/* Inflates one 0x36 payload. The first min(UDSOTA_IMAGE_MIN_LEN, size) inflated bytes, and whatever else the
 * buffer holds by then, go to sink.check_first before sink.begin, so nothing is erased before the image passes;
 * payloads that inflate to less are held until then. A full buffer is written, and so is the last of the stream
 * at its end. Returns UDSOTA_DL_OK, check_first's reason (UDSOTA_DL_BAD_HEADER when the stream ends first),
 * UDSOTA_DL_BAD_STREAM for a corrupt stream or one inflating past size, or UDSOTA_DL_FLASH_ERROR when begin or
 * write fails. Bytes after the end are noted for udsota_zstream_end. */
udsota_reason_t udsota_zstream_feed(udsota_zstream_t *z, const uint8_t *in, size_t n);
/* The 37 check: UDSOTA_DL_OK when the stream ended, inflated to exactly size bytes, all written, with nothing after
 * its end; else UDSOTA_DL_BAD_STREAM (or the stream's earlier failure). Closes the stream either way. */
udsota_reason_t udsota_zstream_end(udsota_zstream_t *z);
/* Frees the inflater (inflate.finish) if it is open; idempotent. */
void udsota_zstream_close(udsota_zstream_t *z);
