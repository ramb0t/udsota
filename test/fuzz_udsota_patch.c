/* Mutation fuzzing of the delta patch path a device runs on untrusted input: udsota_coded over the real detools and
 * tinfl, fed mutants of test/fixtures/delta_fixtures.h's patches (bit flips, byte overwrites, truncations,
 * insertions, deletions and header edits) in random splits, under DFI 0x20 and 0x30. Deterministic (a fixed LCG
 * seed), and built with the sanitizers. Every mutant must end without a crash, with every base read inside the
 * running image, every write at the next image offset and never past memorySize, and only a download that
 * rebuilt all memorySize bytes may pass its 37. DELTA_PTAIL's mutants also exercise image bytes the 37 writes. Prints one PASS line; exits 1 at the first broken invariant. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "udsota_coded.h"
#include "udsota_detools.h"
#include "udsota_image.h"
#include "udsota_tinfl.h"
#include "fixtures/delta_fixtures.h"
#include "miniz/miniz.h"   /* tdefl, to re-deflate a mutated uncompressed patch */

#define ITERATIONS 60000u
#define IMG_LEN    ((uint32_t)sizeof DELTA_NEW)
#define PATCH_CAP  32768u

static uint32_t g_seed = 0x2545F491u;
static uint8_t  g_out[1024];
static uint8_t  g_zbuf[256];
static uint32_t g_next;           /* where the next image write must land */
static bool     g_begun;
static unsigned g_failures;
static unsigned g_passes, g_drained, g_reasons[UDSOTA_DL_REASON_COUNT];

/* The next pseudo-random number. */
static uint32_t rnd(void)
{
    g_seed = g_seed * 1664525u + 1013904223u;
    return g_seed >> 8;
}

/* Records a broken invariant. */
static void broken(const char *what, unsigned it)
{
    if (g_failures++ < 10u) {
        printf("FAIL iteration %u: %s\n", it, what);
    }
}

static unsigned g_it;

/* base.read: DELTA_BASE; a read outside it is refused, which the stage must turn into a failure. */
static int b_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    (void)ctx;
    if ((uint64_t)off + n > sizeof DELTA_BASE) {
        return -1;
    }
    memcpy(buf, &DELTA_BASE[off], n);
    return 0;
}

/* base.hash: the base's appended SHA-256. */
static int b_hash(void *ctx, uint8_t out[UDSOTA_PATCH_HASH_LEN])
{
    (void)ctx;
    memcpy(out, DELTA_BASE_HASH, UDSOTA_PATCH_HASH_LEN);
    return 0;
}

/* The sink's check: passes, so every mutant reaches the writes. */
static int s_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    (void)ctx;
    (void)first;
    (void)len;
    *why = UDSOTA_DL_OK;
    return 0;
}

/* The sink's erase. */
static int s_begin(void *ctx, uint32_t size)
{
    (void)ctx;
    if (g_begun || size != IMG_LEN) {
        broken("a second erase, or one for another size", g_it);
    }
    g_begun = true;
    return 0;
}

/* The sink's write: at the next offset, never past memorySize. */
static int s_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    (void)d;
    if (!g_begun || off != g_next || (uint64_t)off + n > IMG_LEN) {
        broken("a write before the erase, out of order or past memorySize", g_it);
    }
    g_next = off + (uint32_t)n;
    return 0;
}

/* Mutates p (n bytes, cap bytes of room) in place a few times; returns its new length. */
static size_t mutate(uint8_t *p, size_t n, size_t cap)
{
    const unsigned edits = 1u + rnd() % 4u;
    for (unsigned e = 0; e < edits && n > 0u; e++) {
        const size_t at = rnd() % n;
        switch (rnd() % 7u) {
        case 0: p[at] ^= (uint8_t)(1u << (rnd() % 8u)); break;               /* a bit flip */
        case 1: p[at] = (uint8_t)rnd(); break;                                /* a byte */
        case 2: n = at; break;                                                /* truncation */
        case 3:                                                               /* insertion */
            if (n + 16u <= cap) {
                memmove(&p[at + 16u], &p[at], n - at);
                for (size_t i = 0; i < 16u; i++) p[at + i] = (uint8_t)rnd();
                n += 16u;
            }
            break;
        case 4: {                                                             /* deletion */
            const size_t k = 1u + rnd() % 32u;
            if (at + k <= n) {
                memmove(&p[at], &p[at + k], n - at - k);
                n -= k;
            }
            break;
        }
        case 5: if (n > UDSOTA_PATCH_HEADER_LEN) p[UDSOTA_PATCH_HEADER_LEN + rnd() % 8u] = (uint8_t)rnd(); break;
        default: if (n > 0u) p[rnd() % (n < UDSOTA_PATCH_HEADER_LEN ? n : UDSOTA_PATCH_HEADER_LEN)] ^= 0xFF; break;
        }
    }
    return n;
}

/* One download of payload under dfi, in random splits; checks the invariants at its end. */
static void run(uint8_t dfi, const uint8_t *payload, size_t n)
{
    udsota_detools_t dt = {0};
    udsota_tinfl_t tinfl = {0};
    const udsota_inflate_t inf = udsota_tinfl_inflate(&tinfl);
    const udsota_patch_t patch = udsota_detools_patch(&dt);
    const udsota_pbase_t base = {.read = b_read, .hash = b_hash};
    const udsota_coded_cfg_t cfg = {
        .sink = {.check_first = s_check, .begin = s_begin, .write = s_write},
        .out = g_out, .out_max = sizeof g_out, .inflate = &inf, .patch = &patch, .base = &base,
        .zbuf = g_zbuf, .zbuf_max = sizeof g_zbuf,
    };
    udsota_coded_t cd;
    g_next = 0;
    g_begun = false;
    if (udsota_coded_open(&cd, dfi, IMG_LEN, &cfg) != UDSOTA_DL_OK) {
        broken("open failed", g_it);
        return;
    }
    udsota_reason_t r = UDSOTA_DL_OK;
    for (size_t off = 0; off < n && r == UDSOTA_DL_OK;) {
        const size_t k = 1u + rnd() % 700u;
        const size_t m = (n - off < k) ? n - off : k;
        r = udsota_coded_feed(&cd, &payload[off], m);
        off += m;
    }
    if (r == UDSOTA_DL_OK) {
        const uint32_t before_end = g_next;
        r = udsota_coded_end(&cd);
        if (r == UDSOTA_DL_OK && g_next != IMG_LEN) {
            broken("a 37 passed without the whole image", g_it);
        }
        g_drained += (r == UDSOTA_DL_OK && before_end != IMG_LEN);   /* image bytes the 37's drain wrote */
    } else {
        udsota_coded_close(&cd);
    }
    if (dt.state != NULL || tinfl.state != NULL) {
        broken("a decoder left allocated", g_it);
    }
    if ((unsigned)r >= UDSOTA_DL_REASON_COUNT) {
        broken("a result that is no reason", g_it);
        return;
    }
    g_reasons[r]++;
    g_passes += (r == UDSOTA_DL_OK);
}

int main(void)
{
    static uint8_t p[PATCH_CAP], raw[PATCH_CAP];
    for (g_it = 0; g_it < ITERATIONS; g_it++) {
        const unsigned form = g_it % 4u;
        size_t n;
        if (form == 0u) {                               /* 0x20: the heatshrink patch, mutated */
            memcpy(p, DELTA_P20, sizeof DELTA_P20);
            n = mutate(p, sizeof DELTA_P20, sizeof p);
            run(UDSOTA_DL_DFI_DELTA, p, n);
        } else if (form == 1u) {                        /* 0x20: the uncompressed patch, mutated */
            memcpy(p, DELTA_PNONE, sizeof DELTA_PNONE);
            n = mutate(p, sizeof DELTA_PNONE, sizeof p);
            run(UDSOTA_DL_DFI_DELTA, p, n);
        } else if (form == 2u) {                        /* 0x20: the patch whose last image bytes wait for the 37 */
            memcpy(p, DELTA_PTAIL, sizeof DELTA_PTAIL);
            n = mutate(p, sizeof DELTA_PTAIL, sizeof p);
            run(UDSOTA_DL_DFI_DELTA, p, n);
        } else {                                        /* 0x30: the uncompressed patch mutated, then deflated */
            memcpy(raw, DELTA_PNONE, sizeof DELTA_PNONE);
            const size_t rn = mutate(raw, sizeof DELTA_PNONE, sizeof raw);
            const int flags = (int)tdefl_create_comp_flags_from_zip_params(6, -15, MZ_DEFAULT_STRATEGY);
            n = tdefl_compress_mem_to_mem(p, sizeof p, raw, rn, flags);
            run(UDSOTA_DL_DFI_DELTA_DEFLATE, p, n);
        }
    }
    printf("%s fuzz_udsota_patch: %u mutants, %u passed their 37 (rebuilding whole images, %u of them writing at the "
           "37); reasons:", g_failures == 0u ? "PASS" : "FAIL", ITERATIONS, g_passes, g_drained);
    for (unsigned i = 0; i < UDSOTA_DL_REASON_COUNT; i++) {
        if (g_reasons[i] != 0u) printf(" %u=%u", i, g_reasons[i]);
    }
    printf("\n");
    return g_failures == 0u ? 0 : 1;
}
