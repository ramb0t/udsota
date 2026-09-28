/* udsota_patch_t on detools (udsota_detools.h). detools reads the base from a running offset that its seeks move
 * with no check, so every read is bounds-checked here before it reaches the caller's read. A patch is judged ended
 * by detools' own state (done once the target size is out) rather than by detools_apply_patch_finalize, which needs
 * the patch's length up front for an uncompressed patch. */
#include "udsota_detools.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include "detools.h"

/* The state init allocates. */
typedef struct {
    struct detools_apply_patch_t ap;
    udsota_patch_io_t            io;
    uint32_t                     to_size;   /* the size the patch must rebuild */
    int64_t                      from_off;  /* where detools' next base read starts */
} dt_state_t;

/* Allocates through t's allocator, malloc when it has none. */
static void *dt_alloc(udsota_detools_t *t, size_t n)
{
    return t->alloc != NULL ? t->alloc(t->alloc_ctx, n) : malloc(n);
}

/* Frees through t's allocator, free when it has none. */
static void dt_free(udsota_detools_t *t, void *p)
{
    if (t->free != NULL) {
        t->free(t->alloc_ctx, p);
    } else {
        free(p);
    }
}

/* detools' base read: n bytes at the running offset, refused when the offset is negative or the read would pass
 * INT_MAX, where detools' own int offset ends. */
static int dt_read(void *arg, uint8_t *buf, size_t n)
{
    dt_state_t *st = arg;
    if (st->from_off < 0 || (uint64_t)st->from_off + n > (uint64_t)INT_MAX) {
        return -DETOOLS_IO_FAILED;
    }
    if (st->io.read(st->io.ctx, (uint32_t)st->from_off, buf, n) != 0) {
        return -DETOOLS_IO_FAILED;
    }
    st->from_off += (int64_t)n;
    return 0;
}

/* detools' base seek: moves the running offset, which the next read checks. detools adds the same offset to its own
 * int offset, so a seek that would take it out of int's range is refused before it can overflow there. */
static int dt_seek(void *arg, int offset)
{
    dt_state_t *st = arg;
    const int64_t next = st->from_off + offset;
    if (next < INT_MIN || next > INT_MAX) {
        return -DETOOLS_IO_FAILED;
    }
    st->from_off = next;
    return 0;
}

/* detools' output: the rebuilt image's next bytes, refused for a patch whose target size is not the image's. */
static int dt_write(void *arg, const uint8_t *buf, size_t n)
{
    dt_state_t *st = arg;
    if (st->ap.to_size != st->to_size || st->io.write(st->io.ctx, buf, n) != 0) {
        return -DETOOLS_IO_FAILED;
    }
    return 0;
}

/* udsota_patch_t.init: allocates or resets the state and starts a patch for to_size bytes. */
static int dt_init(void *ctx, const udsota_patch_io_t *io, uint32_t to_size)
{
    udsota_detools_t *t = ctx;
    if (io == NULL || io->read == NULL || io->write == NULL) {
        return -1;
    }
    if (t->state == NULL) {
        t->state = dt_alloc(t, sizeof(dt_state_t));
        if (t->state == NULL) {
            return -1;
        }
    }
    dt_state_t *st = t->state;
    st->io = *io;
    st->to_size = to_size;
    st->from_off = 0;
    /* The patch's length is unknown; SIZE_MAX keeps the uncompressed reader's bound out of the way. */
    return detools_apply_patch_init(&st->ap, dt_read, dt_seek, SIZE_MAX, dt_write, st) == 0 ? 0 : -1;
}

/* udsota_patch_t.feed: applies up to n patch bytes; END once detools is done, with *consumed marking where. */
static int dt_feed(void *ctx, const uint8_t *in, size_t n, size_t *consumed)
{
    udsota_detools_t *t = ctx;
    dt_state_t *st = t->state;
    *consumed = 0;
    if (st == NULL) {
        return UDSOTA_PATCH_ERROR;
    }
    if (st->ap.state == detools_apply_patch_state_done_t) {
        return UDSOTA_PATCH_END;
    }
    if (n == 0u) {
        /* The input has ended: a heatshrink decoder may still hold output, which finalize drains. Its result is not
         * the verdict (for an uncompressed patch it wants a length given up front); detools' state is. */
        (void)detools_apply_patch_finalize(&st->ap);
        return (st->ap.state == detools_apply_patch_state_done_t && st->ap.to_offset == st->ap.to_size &&
                st->ap.to_size == st->to_size) ? UDSOTA_PATCH_END : UDSOTA_PATCH_ERROR;
    }
    const int res = detools_apply_patch_process(&st->ap, in, n);
    *consumed = st->ap.chunk.offset;
    if (res < 0 || st->ap.state == detools_apply_patch_state_failed_t) {
        return UDSOTA_PATCH_ERROR;
    }
    if (st->ap.state != detools_apply_patch_state_init_t && st->ap.to_size != st->to_size) {
        return UDSOTA_PATCH_ERROR;                             /* a patch for another size, even one that writes nothing */
    }
    return st->ap.state == detools_apply_patch_state_done_t ? UDSOTA_PATCH_END : UDSOTA_PATCH_MORE;
}

/* udsota_patch_t.finish: frees the state; idempotent. */
static void dt_finish(void *ctx)
{
    udsota_detools_t *t = ctx;
    if (t->state != NULL) {
        dt_free(t, t->state);
        t->state = NULL;
    }
}

/* See udsota_detools.h. */
udsota_patch_t udsota_detools_patch(udsota_detools_t *t)
{
    return (udsota_patch_t){.init = dt_init, .feed = dt_feed, .finish = dt_finish, .ctx = t};
}

/* See udsota_detools.h. */
size_t udsota_detools_state_len(void)
{
    return sizeof(dt_state_t);
}
