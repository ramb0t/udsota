/* The compressed-download stream (udsota_zstream.h): inflate, hold the first bytes for the image check, then erase
 * and write at uncompressed offsets. Pure C over the caller's decompressor and sink. */
#include "udsota_zstream.h"
#include <string.h>
#include "udsota_image.h"   /* UDSOTA_IMAGE_MIN_LEN */

/* Records the stream's first failure and returns it. */
static udsota_reason_t fail(udsota_zstream_t *z, udsota_reason_t r)
{
    if (z->failed == UDSOTA_DL_OK) {
        z->failed = r;
    }
    return z->failed;
}

/* Bytes the first-block check needs before the erase: UDSOTA_IMAGE_MIN_LEN, or the whole image when it is shorter. */
static size_t first_len(const udsota_zstream_t *z)
{
    return z->size < UDSOTA_IMAGE_MIN_LEN ? (size_t)z->size : (size_t)UDSOTA_IMAGE_MIN_LEN;
}

/* Runs the first-block check on the held bytes, then the erase. */
static udsota_reason_t start(udsota_zstream_t *z)
{
    udsota_reason_t why = UDSOTA_DL_OK;
    if (z->sink.check_first(z->sink.ctx, z->out, z->held, &why) != 0) {
        return fail(z, why != UDSOTA_DL_OK ? why : UDSOTA_DL_BAD_HEADER);
    }
    if (z->sink.begin(z->sink.ctx, z->size) != 0) {
        return fail(z, UDSOTA_DL_FLASH_ERROR);
    }
    z->begun = true;
    return UDSOTA_DL_OK;
}

/* Writes the held bytes at their uncompressed offset and empties the buffer. */
static udsota_reason_t flush(udsota_zstream_t *z)
{
    if (z->held == 0u) {
        return UDSOTA_DL_OK;
    }
    if (z->sink.write(z->sink.ctx, z->written, z->out, z->held) != 0) {
        return fail(z, UDSOTA_DL_FLASH_ERROR);
    }
    z->written += (uint32_t)z->held;
    z->held = 0;
    return UDSOTA_DL_OK;
}

/* Starts a stream; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_open(udsota_zstream_t *z, const udsota_inflate_t *inflate, const udsota_zsink_t *sink,
                                    uint8_t *out, size_t out_max, uint32_t size)
{
    if (z == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(z, 0, sizeof *z);
    if (inflate == NULL || sink == NULL || out == NULL || out_max < UDSOTA_IMAGE_MIN_LEN) {
        return UDSOTA_DL_BAD_HEADER;
    }
    z->inflate = *inflate;
    z->sink = *sink;
    z->out = out;
    z->out_max = out_max;
    z->size = size;
    if (z->inflate.init(z->inflate.ctx) != 0) {
        return UDSOTA_DL_NO_MEMORY;
    }
    z->open = true;
    return UDSOTA_DL_OK;
}

/* Inflates one payload into the buffer, checking, erasing and writing as it fills; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_feed(udsota_zstream_t *z, const uint8_t *in, size_t n)
{
    if (z->failed != UDSOTA_DL_OK) {
        return z->failed;
    }
    if (!z->open) {
        return fail(z, UDSOTA_DL_BAD_STREAM);
    }
    for (;;) {
        if (z->ended) {
            z->trailing = z->trailing || n > 0u;
            return UDSOTA_DL_OK;
        }
        size_t used = 0, made = 0;
        const int rc = z->inflate.feed(z->inflate.ctx, in, n, z->out + z->held, z->out_max - z->held, &used, &made);
        if (rc == UDSOTA_INFLATE_ERROR || used > n || made > z->out_max - z->held) {
            return fail(z, UDSOTA_DL_BAD_STREAM);
        }
        if (made > z->size - z->produced) {
            return fail(z, UDSOTA_DL_BAD_STREAM);              /* inflates past memorySize */
        }
        in += used;
        n -= used;
        z->produced += (uint32_t)made;
        z->held += made;
        z->ended = (rc == UDSOTA_INFLATE_END);
        if (!z->begun) {
            if (z->held < first_len(z)) {
                if (z->ended) {
                    return fail(z, UDSOTA_DL_BAD_HEADER);      /* the stream ended before the check had its bytes */
                }
            } else if (start(z) != UDSOTA_DL_OK) {
                return z->failed;
            }
        }
        if (z->begun && (z->held == z->out_max || z->ended) && flush(z) != UDSOTA_DL_OK) {
            return z->failed;
        }
        if (!z->ended && used == 0u && made == 0u) {
            /* No progress with room to write: every byte was taken, or the decompressor refuses what is left. */
            return n == 0u ? UDSOTA_DL_OK : fail(z, UDSOTA_DL_BAD_STREAM);
        }
    }
}

/* The 37 check; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_end(udsota_zstream_t *z)
{
    udsota_reason_t r = z->failed;
    if (r == UDSOTA_DL_OK && (!z->ended || z->trailing || !z->begun || z->produced != z->size || z->held != 0u)) {
        r = fail(z, UDSOTA_DL_BAD_STREAM);
    }
    udsota_zstream_close(z);
    return r;
}

/* Frees the inflater once. */
void udsota_zstream_close(udsota_zstream_t *z)
{
    if (z->open) {
        z->open = false;
        z->inflate.finish(z->inflate.ctx);
    }
}
