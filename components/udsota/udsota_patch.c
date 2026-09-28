/* The delta patch stage (udsota_patch.h): gather and check the 64-byte header, then run the decoder into the image
 * sink. Pure C over the caller's decoder, base and sink. */
#include "udsota_patch.h"
#include <string.h>

/* Records the stage's first failure and returns it. */
static udsota_reason_t fail(udsota_pstream_t *p, udsota_reason_t r)
{
    if (p->failed == UDSOTA_DL_OK) {
        p->failed = r;
    }
    return p->failed;
}

/* The decoder's base read: the caller's, with a refusal remembered as a read outside the running image. */
static int io_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    udsota_pstream_t *p = ctx;
    if (p->base.read(p->base.ctx, off, buf, n) != 0) {
        p->base_failed = true;
        return -1;
    }
    return 0;
}

/* The decoder's write: the rebuilt image's next bytes into the sink. */
static int io_write(void *ctx, const uint8_t *d, size_t n)
{
    udsota_pstream_t *p = ctx;
    return udsota_isink_push(p->image, d, n) == UDSOTA_DL_OK ? 0 : -1;
}

/* Starts a delta download; see udsota_patch.h. */
udsota_reason_t udsota_pstream_open(udsota_pstream_t *p, const udsota_patch_t *patch, const udsota_pbase_t *base,
                                    udsota_isink_t *image)
{
    if (p == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(p, 0, sizeof *p);
    if (patch == NULL || base == NULL || base->read == NULL || base->hash == NULL || image == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    p->patch = *patch;
    p->base = *base;
    p->image = image;
    const udsota_patch_io_t io = {.read = io_read, .write = io_write, .ctx = p};
    if (p->patch.init(p->patch.ctx, &io, image->size) != 0) {
        return UDSOTA_DL_NO_MEMORY;
    }
    p->open = true;
    return UDSOTA_DL_OK;
}

/* Checks the whole header: the magic, then the base hash against the running image's. */
static udsota_reason_t check_header(udsota_pstream_t *p)
{
    const uint32_t magic = (uint32_t)p->header[0] | ((uint32_t)p->header[1] << 8) | ((uint32_t)p->header[2] << 16) |
                           ((uint32_t)p->header[3] << 24);
    if (magic != UDSOTA_PATCH_MAGIC) {
        return fail(p, UDSOTA_DL_BAD_STREAM);
    }
    uint8_t running[UDSOTA_PATCH_HASH_LEN];
    if (p->base.hash(p->base.ctx, running) != 0 || memcmp(running, &p->header[4], sizeof running) != 0) {
        return fail(p, UDSOTA_DL_BAD_BASE);
    }
    return UDSOTA_DL_OK;
}

/* Takes patch bytes; see udsota_patch.h. */
udsota_reason_t udsota_pstream_push(udsota_pstream_t *p, const uint8_t *d, size_t n)
{
    if (p->failed != UDSOTA_DL_OK) {
        return p->failed;
    }
    if (!p->open) {
        return fail(p, UDSOTA_DL_BAD_STREAM);
    }
    if (p->ended) {
        p->trailing = p->trailing || n > 0u;
        return UDSOTA_DL_OK;
    }
    if (p->header_len < UDSOTA_PATCH_HEADER_LEN) {
        const size_t want = UDSOTA_PATCH_HEADER_LEN - p->header_len;
        const size_t take = n < want ? n : want;
        memcpy(&p->header[p->header_len], d, take);
        p->header_len += take;
        p->taken += (uint32_t)take;
        d += take;
        n -= take;
        if (p->header_len < UDSOTA_PATCH_HEADER_LEN) {
            return UDSOTA_DL_OK;
        }
        if (check_header(p) != UDSOTA_DL_OK) {
            return p->failed;
        }
    }
    while (n > 0u) {
        size_t used = 0;
        const int rc = p->patch.feed(p->patch.ctx, d, n, &used);
        if (rc == UDSOTA_PATCH_ERROR || used > n) {
            /* The image's reason when a write failed (the check, the flash, past memorySize), else the patch's. */
            return fail(p, p->image->failed != UDSOTA_DL_OK ? p->image->failed : UDSOTA_DL_BAD_STREAM);
        }
        p->taken += (uint32_t)used;
        d += used;
        n -= used;
        if (rc == UDSOTA_PATCH_END) {
            p->ended = true;
            p->trailing = n > 0u;
            const udsota_reason_t r = udsota_isink_finish(p->image);
            return r != UDSOTA_DL_OK ? fail(p, r) : UDSOTA_DL_OK;
        }
        if (used == 0u) {
            return fail(p, UDSOTA_DL_BAD_STREAM);              /* a decoder that takes nothing and has not ended */
        }
    }
    return UDSOTA_DL_OK;
}

/* A udsota_push_t push; see udsota_patch.h. */
udsota_reason_t udsota_pstream_push_cb(void *p, const uint8_t *d, size_t n)
{
    return udsota_pstream_push(p, d, n);
}

/* The 37 check; see udsota_patch.h. */
udsota_reason_t udsota_pstream_end(udsota_pstream_t *p)
{
    if (p->failed == UDSOTA_DL_OK && p->open && !p->ended && p->header_len == UDSOTA_PATCH_HEADER_LEN) {
        size_t used = 0;
        if (p->patch.feed(p->patch.ctx, NULL, 0, &used) == UDSOTA_PATCH_END) {   /* the input has ended */
            p->ended = true;
            (void)fail(p, udsota_isink_finish(p->image));
        } else {
            (void)fail(p, p->image->failed != UDSOTA_DL_OK ? p->image->failed : UDSOTA_DL_BAD_STREAM);
        }
    }
    udsota_reason_t r = p->failed;
    if (r == UDSOTA_DL_OK && (!p->ended || p->trailing || !udsota_isink_complete(p->image))) {
        r = fail(p, UDSOTA_DL_BAD_STREAM);
    }
    udsota_pstream_close(p);
    return r;
}

/* Frees the decoder once. */
void udsota_pstream_close(udsota_pstream_t *p)
{
    if (p->open) {
        p->open = false;
        p->patch.finish(p->patch.ctx);
    }
}
