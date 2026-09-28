/* udsota_patch_t (udsota_patch.h) on detools' sequential patches: bsdiff, heatshrink-compressed (window 8, lookahead
 * 7, esp_delta_ota's format) or uncompressed. detools 0.53.0 is vendored unpatched (detools/). Nothing is allocated
 * until init, and finish frees it all. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "udsota_patch.h"

/* One decoder. Set alloc, free and alloc_ctx (or leave the functions NULL for malloc and free) before
 * udsota_detools_patch; state belongs to it. */
typedef struct {
    void   *(*alloc)(void *ctx, size_t n);   /* NULL = malloc; called at init for the state */
    void    (*free)(void *ctx, void *p);     /* NULL = free */
    void     *alloc_ctx;
    void     *state;                         /* detools' apply state and the base offset, while open */
} udsota_detools_t;

/* The udsota_patch_t over t: init allocates the state (or resets it if still held), feed applies patch bytes,
 * finish frees it. */
udsota_patch_t udsota_detools_patch(udsota_detools_t *t);
/* Bytes the state allocation takes. */
size_t udsota_detools_state_len(void);
