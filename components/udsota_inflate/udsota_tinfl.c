/* udsota_inflate_t on tinfl (udsota_tinfl.h): the ROM's copy with UDSOTA_TINFL_ROM, else the vendored miniz. */
#include "udsota_tinfl.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#if defined(UDSOTA_TINFL_ROM)
#include "miniz.h"          /* esp_rom's header: tinfl_decompress resolves to the ROM */
#else
#include "miniz/miniz.h"    /* the vendored miniz 3.0.2 */
#endif

_Static_assert(TINFL_LZ_DICT_SIZE == UDSOTA_TINFL_DICT_LEN, "the dictionary is tinfl's");
#if defined(UDSOTA_TINFL_ROM)
/* The ROM's tinfl was built with esp_rom's miniz.h: a miniz.h from another component must not change the layout. */
_Static_assert(sizeof(tinfl_decompressor) == 10992u, "tinfl_decompressor is not the ROM's layout");
#endif

/* The decompressor and what feed has inflated into the dictionary but not yet copied out. */
typedef struct {
    tinfl_decompressor r;
    size_t dict_ofs;        /* where tinfl writes next in the dictionary */
    size_t pend_ofs;        /* the oldest byte not yet copied out */
    size_t pend;            /* bytes not yet copied out */
    int    status;          /* the last tinfl_status */
} state_t;

/* t's alloc, or malloc. */
static void *t_alloc(udsota_tinfl_t *t, size_t n)
{
    return t->alloc != NULL ? t->alloc(t->alloc_ctx, n) : malloc(n);
}

/* t's free, or free; p may be NULL. */
static void t_free(udsota_tinfl_t *t, void *p)
{
    if (p == NULL) {
        return;
    }
    if (t->free != NULL) {
        t->free(t->alloc_ctx, p);
    } else {
        free(p);
    }
}

/* udsota_inflate_t.finish: frees the state and the dictionary. */
static void tf_finish(void *ctx)
{
    udsota_tinfl_t *t = ctx;
    t_free(t, t->dict);
    t_free(t, t->state);
    t->dict = NULL;
    t->state = NULL;
}

/* udsota_inflate_t.init: allocates what is not held yet and starts a stream; -1 when an allocation fails. */
static int tf_init(void *ctx)
{
    udsota_tinfl_t *t = ctx;
    if (t->state == NULL) {
        t->state = t_alloc(t, sizeof(state_t));
    }
    if (t->state != NULL && t->dict == NULL) {
        t->dict = t_alloc(t, TINFL_LZ_DICT_SIZE);
    }
    if (t->state == NULL || t->dict == NULL) {
        tf_finish(t);
        return -1;
    }
    state_t *st = t->state;
    memset(st, 0, sizeof *st);
    tinfl_init(&st->r);
    st->status = TINFL_STATUS_NEEDS_MORE_INPUT;
    return 0;
}

/* Copies pending dictionary bytes into out[*produced..out_max); true when none are left. */
static bool drain(udsota_tinfl_t *t, uint8_t *out, size_t out_max, size_t *produced)
{
    state_t *st = t->state;
    const size_t n = (st->pend < out_max - *produced) ? st->pend : out_max - *produced;
    memcpy(out + *produced, t->dict + st->pend_ofs, n);
    *produced += n;
    st->pend -= n;
    st->pend_ofs += n;
    return st->pend == 0u;
}

/* udsota_inflate_t.feed: runs tinfl over the input into the dictionary ring, copying each run out. At the end of
 * the stream, whole bytes tinfl read ahead are given back, so *consumed stops exactly at the stream's end. */
static int tf_feed(void *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max, size_t *consumed,
                   size_t *produced)
{
    udsota_tinfl_t *t = ctx;
    state_t *st = t->state;
    *consumed = 0;
    *produced = 0;
    if (st == NULL || t->dict == NULL) {
        return UDSOTA_INFLATE_ERROR;
    }
    for (;;) {
        if (!drain(t, out, out_max, produced)) {
            return UDSOTA_INFLATE_MORE;                        /* out is full */
        }
        if (st->status == TINFL_STATUS_DONE) {
            return UDSOTA_INFLATE_END;
        }
        if (st->status < 0) {
            return UDSOTA_INFLATE_ERROR;
        }
        if (st->status == TINFL_STATUS_NEEDS_MORE_INPUT && *consumed == in_len) {
            return UDSOTA_INFLATE_MORE;
        }
        size_t in_n = in_len - *consumed;
        size_t out_n = TINFL_LZ_DICT_SIZE - st->dict_ofs;
        st->status = tinfl_decompress(&st->r, in + *consumed, &in_n, t->dict, t->dict + st->dict_ofs, &out_n,
                                      TINFL_FLAG_HAS_MORE_INPUT);
        if (st->status == TINFL_STATUS_DONE) {
            /* miniz 3 gives back its look-ahead itself; older copies (the ROM's) leave it in the bit buffer. */
            const size_t ahead = st->r.m_num_bits >> 3;
            if (ahead > in_n) {
                st->status = TINFL_STATUS_FAILED;             /* it read past the end in an earlier call */
                return UDSOTA_INFLATE_ERROR;
            }
            in_n -= ahead;
            st->r.m_num_bits &= 7u;
        }
        *consumed += in_n;
        st->pend_ofs = st->dict_ofs;
        st->pend = out_n;
        st->dict_ofs = (st->dict_ofs + out_n) & (TINFL_LZ_DICT_SIZE - 1u);
        if (st->status < 0) {
            return UDSOTA_INFLATE_ERROR;
        }
        if (in_n == 0u && out_n == 0u && st->status != TINFL_STATUS_DONE) {
            return UDSOTA_INFLATE_MORE;                        /* no progress: needs input it has not had */
        }
    }
}

/* The inflater over t; see udsota_tinfl.h. */
udsota_inflate_t udsota_tinfl_inflate(udsota_tinfl_t *t)
{
    return (udsota_inflate_t){ .init = tf_init, .feed = tf_feed, .finish = tf_finish, .ctx = t };
}

/* sizeof the state allocation. */
size_t udsota_tinfl_state_len(void)
{
    return sizeof(state_t);
}
