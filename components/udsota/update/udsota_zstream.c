/* The compressed-download stream (udsota_zstream.h): inflate into the image sink, which holds the first bytes for the
 * image check and then erases and writes at image offsets, or into a next stage. Pure C over the caller's
 * decompressor, sink and stage. */
#include "udsota_zstream.h"
#include <string.h>

/* Records the stream's first failure and returns it. */
static udsota_reason_t fail(udsota_zstream_t *z, udsota_reason_t r)
{
    if (z->failed == UDSOTA_DL_OK) {
        z->failed = r;
    }
    return z->failed;
}

/* Copies inflate and calls its init: the shared tail of both opens. */
static udsota_reason_t start(udsota_zstream_t *z, const udsota_inflate_t *inflate)
{
    z->inflate = *inflate;
    if (z->inflate.init(z->inflate.ctx) != 0) {
        return UDSOTA_DL_NO_MEMORY;
    }
    z->open = true;
    return UDSOTA_DL_OK;
}

/* Starts a stream to an image; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_open(udsota_zstream_t *z, const udsota_inflate_t *inflate, const udsota_zsink_t *sink,
                                    uint8_t *out, size_t out_max, uint32_t size)
{
    if (z == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(z, 0, sizeof *z);
    if (inflate == NULL || udsota_isink_open(&z->image, sink, out, out_max, size) != UDSOTA_DL_OK) {
        return UDSOTA_DL_BAD_HEADER;
    }
    return start(z, inflate);
}

/* Starts a stream to a next stage; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_open_push(udsota_zstream_t *z, const udsota_inflate_t *inflate,
                                         const udsota_push_t *next, uint8_t *buf, size_t buf_max)
{
    if (z == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(z, 0, sizeof *z);
    if (inflate == NULL || next == NULL || next->push == NULL || buf == NULL || buf_max == 0u) {
        return UDSOTA_DL_BAD_HEADER;
    }
    z->next = *next;
    z->buf = buf;
    z->buf_max = buf_max;
    return start(z, inflate);
}

/* Inflates one payload into the image or the next stage; see udsota_zstream.h. */
udsota_reason_t udsota_zstream_feed(udsota_zstream_t *z, const uint8_t *in, size_t n)
{
    if (z->failed != UDSOTA_DL_OK) {
        return z->failed;
    }
    if (!z->open) {
        return fail(z, UDSOTA_DL_BAD_STREAM);
    }
    const bool to_image = (z->next.push == NULL);
    for (;;) {
        if (z->ended) {
            z->trailing = z->trailing || n > 0u;
            return UDSOTA_DL_OK;
        }
        uint8_t *at = z->buf;
        const size_t room = to_image ? udsota_isink_space(&z->image, &at) : z->buf_max;
        if (room == 0u) {
            return fail(z, z->image.failed != UDSOTA_DL_OK ? z->image.failed : UDSOTA_DL_BAD_STREAM);
        }
        size_t used = 0, made = 0;
        const int rc = z->inflate.feed(z->inflate.ctx, in, n, at, room, &used, &made);
        if (rc == UDSOTA_INFLATE_ERROR || used > n || made > room) {
            return fail(z, UDSOTA_DL_BAD_STREAM);
        }
        in += used;
        n -= used;
        z->produced += (uint32_t)made;
        z->ended = (rc == UDSOTA_INFLATE_END);
        udsota_reason_t r = UDSOTA_DL_OK;
        if (to_image) {
            r = udsota_isink_commit(&z->image, made);          /* past memorySize is UDSOTA_DL_BAD_STREAM */
            if (r == UDSOTA_DL_OK && z->ended) {
                r = udsota_isink_finish(&z->image);            /* the check, if it never had its bytes, and the rest */
            }
        } else if (made > 0u) {
            r = z->next.push(z->next.ctx, at, made);
        }
        if (r != UDSOTA_DL_OK) {
            return fail(z, r);
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
    const bool image_ok = (z->next.push != NULL) || udsota_isink_complete(&z->image);
    if (r == UDSOTA_DL_OK && (!z->ended || z->trailing || !image_ok)) {
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
