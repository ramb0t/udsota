/* udsota_inflate_t (udsota_zstream.h) on miniz's tinfl: raw DEFLATE, a 32 KB dictionary. Under ESP-IDF it calls the
 * ROM's copy, which every v6.1 target has; a target without one, and the host, get the vendored miniz 3.0.2 (miniz/,
 * unpatched). Nothing is allocated until init, and finish frees it all. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "udsota_zstream.h"

#define UDSOTA_TINFL_DICT_LEN  32768u   /* TINFL_LZ_DICT_SIZE: DEFLATE's largest back-reference */

/* One decompressor. Set alloc, free and alloc_ctx (or leave the functions NULL for malloc and free) before
 * udsota_tinfl_inflate; state and dict belong to it. */
typedef struct {
    void   *(*alloc)(void *ctx, size_t n);   /* NULL = malloc; called at init for the state, then the dictionary */
    void    (*free)(void *ctx, void *p);     /* NULL = free */
    void     *alloc_ctx;
    void     *state;                         /* the decompressor and its output bookkeeping, while open */
    uint8_t  *dict;                          /* UDSOTA_TINFL_DICT_LEN bytes, while open */
} udsota_tinfl_t;

/* The udsota_inflate_t over t: init allocates the state and the dictionary (or resets them if still held), feed
 * inflates through the dictionary and copies out, finish frees both. */
udsota_inflate_t udsota_tinfl_inflate(udsota_tinfl_t *t);
/* Bytes the state allocation takes (the dictionary is UDSOTA_TINFL_DICT_LEN more). */
size_t udsota_tinfl_state_len(void);
