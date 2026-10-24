/* udsota: safe A/B firmware updates over UDS on iso14229's server (see udsota.h). One file:
 *   1. the limits and state; the wire contract is in udsota.h
 *   2. the image rules: what the first 320 bytes must say before anything is erased
 *   3. coded downloads: raw DEFLATE through the ROM's tinfl into the image, or for a delta into detools, which
 *      rebuilds the image from the running one
 *   4. 0x27 keys: HMAC per device, or ECDSA signatures, and the PSA lock around udsota's PSA calls
 *   5. the updater: 34, 36, 37, the routines, the DIDs and the session rules
 *   6. iso14229's events
 *   7. the ESP-IDF platform: the flash worker on esp_ota_*, the slot status, identity, crypto and a delta's base
 * iso14229 keeps ISO-TP, framing, timing, the 0x78 cadence and the 0x27 attempt delays; it is used as it is. */
#include "udsota.h"
#include <stdlib.h>
#include <string.h>
#if UDSOTA_DELTA
#include <limits.h>
#include "detools.h"
#endif

/* UDSOTA_DELTA=1 comes with detools' defines from udsota's CMakeLists, which also adds detools.c; without them it was
 * set where that CMakeLists never saw it, and the link would fail on detools_* instead. */
#if UDSOTA_DELTA && !defined(DETOOLS_CONFIG_COMPRESSION_HEATSHRINK)
#error "UDSOTA_DELTA=1 without detools: set it as udsota.h says, or on a host with udsota_with_delta()"
#endif

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#include "bootloader_random.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#if UDSOTA_DELTA
#include "esp_image_format.h"
#endif
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "miniz.h"                 /* esp_rom's: tinfl_decompress runs from ROM */
_Static_assert(sizeof(tinfl_decompressor) == 10992u && TINFL_LZ_DICT_SIZE == 32768, "the ROM's tinfl layout");
#include "psa/crypto.h"
#define CHIP_ID CONFIG_IDF_FIRMWARE_CHIP_ID
#define LOGW(...) ESP_LOGW("udsota", __VA_ARGS__)
#else
#include "miniz.h"                 /* host builds: miniz's tinfl */
#ifndef CHIP_ID
#define CHIP_ID 9u                 /* ESP32-S3, for host tests; tools/image_check sets the chip it checks for */
#endif
#define LOGW(...) ((void)0)
#endif

/* ==== 1. Limits and state (the wire contract is udsota.h's) ==== */

#define KEY_LOCK_MS     40u        /* 0x27's wait for the PSA lock: an app that holds it longer gets 0x22 */
#define LABEL_MAX       32u
#define BUF_LEN         4096u
#define IMAGE_MIN       320u       /* image header 24 + segment header 8 + esp_app_desc_t 256 + descriptor 32 */
#define JOB_CAP_MS      90000u     /* the longest udsota holds a session for its own flash job */
#define PATCH_MAGIC     0xFCCDDE10u   /* a delta patch's first 4 bytes, little-endian (esp_delta_ota's) */
#define PATCH_HDR_LEN   64u        /* the magic, the base's appended SHA-256 and 28 reserved bytes */

enum { DL_PLAIN, DL_DEFLATE, DL_DELTA };   /* a download's mode: the 34's DFI 00, 10 or 30 */

typedef int (*done_fn)(int result, uint8_t *status, size_t *status_len);

typedef struct {                   /* a coded download: tinfl (then detools) into buf, the image's next bytes */
    tinfl_decompressor *r;
    uint8_t *dict;                 /* TINFL_LZ_DICT_SIZE bytes: tinfl's window, whose new bytes are copied out */
    size_t   dict_ofs, pend_ofs, pend;
    int      status;
    uint32_t produced, written;    /* image bytes inflated, and written to flash */
    size_t   held;                 /* bytes waiting in buf */
    bool     begun, ended, trailing;
    uint8_t  failed;               /* the first udsota_reason_t */
#if UDSOTA_DELTA
    struct detools_apply_patch_t *dt;   /* a delta's patch state, between tinfl and buf; NULL for DFI 10 */
    uint8_t  hdr[PATCH_HDR_LEN];   /* the patch's header, checked before any byte reaches detools */
    size_t   hdr_len;
    int64_t  base_off;             /* where detools' next base read starts */
#endif
} zdl_t;

static struct {
    bool           started;
    udsota_cfg_t   cfg;
    /* Identity: this image's descriptor and version */
    uint8_t        running_version[3];
    bool           running_release;
    const char    *product;
    uint8_t        devid[UDSOTA_KEYS_ID_MAX];
    size_t         devid_len;
    /* 0x27 */
    bool           sec_on, sec_ecdsa, key_ok;
    uint8_t        kdev[32];
    bool           seed_valid;
    uint8_t        seed_level, seed[UDSOTA_SEED_LEN];
    uint32_t       seed_ms;
    /* The download */
    uint8_t        last_reason;
    uint32_t       last_bytes;
    uint32_t       announced, received, written;
    bool           dl_active;      /* between an accepted 34 and 37 or an abort */
    bool           ota_open;       /* an image is open on the flash side (from the first 36, or the 34 when coded) */
    uint8_t        mode;           /* DL_PLAIN, DL_DEFLATE or DL_DELTA */
    bool           dl_complete, slot_verified, activating, reset_mine, close_pending;
    uint8_t        progress_stage, progress_reason;
    bool           progress_block;
    /* A job on the worker */
    bool           job_running;
    uint8_t        job_sid;
    uint32_t       job_ms;
    done_fn        job_done;
    size_t         blk_len;
    uint8_t        blk[BUF_LEN];   /* the 36 being written: the worker reads it */
    uint8_t        zbuf[BUF_LEN];  /* a coded download's image bytes on their way to flash */
    zdl_t          z;
} U;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Zeroes n bytes where the compiler cannot drop it. */
static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n-- > 0u) {
        *v++ = 0u;
    }
}

/* ==== 2. The image rules ==== */

/* Parses "[v]M.m.p" (0..255 each) ending in NUL, '-' or '+' within n bytes. *clean: NUL follows, a release. */
static bool parse_version(const char *s, size_t n, uint8_t out[3], bool *clean)
{
    uint8_t v3[3] = {0, 0, 0};
    size_t i = (n > 0u && s[0] == 'v') ? 1u : 0u;
    *clean = false;
    memset(out, 0, 3);
    for (int part = 0; part < 3; part++) {
        uint32_t v = 0;
        size_t digits = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9' && v <= 255u) {
            v = v * 10u + (uint32_t)(s[i++] - '0');
            digits++;
        }
        if (digits == 0u || v > 255u || (part < 2 && (i >= n || s[i++] != '.'))) {
            return false;
        }
        v3[part] = (uint8_t)v;
    }
    if (i >= n || (s[i] != '\0' && s[i] != '-' && s[i] != '+')) {
        return false;
    }
    memcpy(out, v3, 3);
    *clean = (s[i] == '\0');
    return true;
}

/* The first IMAGE_MIN bytes of an image of `size` bytes, before anything is erased: an ESP-IDF image for this chip
 * that the platform can boot, this product, board, layout and CAN IDs, a newer version, and a size that fits. */
static udsota_reason_t check_first(const uint8_t *b, size_t len, uint32_t size)
{
    if (b == NULL || len < IMAGE_MIN || size < IMAGE_MIN || b[0] != 0xE9u || b[1] == 0u || b[1] > 16u ||
        b[2] > 5u || le16(&b[12]) != CHIP_ID || le32(&b[28]) < 256u + 32u || le32(&b[32]) != 0xABCD5432u ||
        !udsota_plat_compatible(b, len)) {
        return UDSOTA_DL_BAD_HEADER;
    }
    const char *project = (const char *)&b[32 + 48];
    const size_t plen = strnlen(U.product, 33);
    if (plen > 32u || memcmp(project, U.product, plen) != 0 || (plen < 32u && project[plen] != '\0')) {
        return UDSOTA_DL_BAD_PROJECT;
    }
    const uint8_t *d = &b[UDSOTA_IMG_DESC_OFFSET];
    if (le32(d) != udsota_image_desc.magic || le16(d + 4) < 1u || d[6] != udsota_image_desc.hw_id) {
        return UDSOTA_DL_BAD_BOARD;
    }
    if (d[7] != udsota_image_desc.partition_layout_id) {
        return UDSOTA_DL_BAD_LAYOUT;
    }
    if (le16(d + 8) != udsota_image_desc.diag_request_id || le16(d + 10) != udsota_image_desc.diag_response_id) {
        return UDSOTA_DL_BAD_DIAG_IDS;
    }
    /* SemVer: a release must be newer than the running image, or the same core when that is a dev build; a dev
     * build needs a core at least equal. The release flag must agree with the version string. allow_downgrade skips
     * the newer rule and nothing else. */
    uint8_t ver[3];
    bool clean;
    const bool release = (d[12] & 0x01u) != 0u;
    if (!parse_version((const char *)&b[32 + 16], 32u, ver, &clean) || clean != release) {
        return UDSOTA_DL_BAD_HEADER;
    }
    const int c = memcmp(ver, U.running_version, 3);
    if (!U.cfg.allow_downgrade && !(release ? (c > 0 || (c == 0 && !U.running_release)) : c >= 0)) {
        return UDSOTA_DL_NOT_NEWER;
    }
    return (size > udsota_plat_slot_size()) ? UDSOTA_DL_TOO_BIG : UDSOTA_DL_OK;
}

/* ==== 3. Coded downloads (DFI 0x10: raw DEFLATE; 0x30: a delta patch in it; memorySize the image's size) ==== */

static void zdl_close(void)
{
    free(U.z.r);
    free(U.z.dict);
#if UDSOTA_DELTA
    free(U.z.dt);
#endif
    memset(&U.z, 0, sizeof U.z);
}

static uint8_t zdl_fail(udsota_reason_t r)
{
    if (U.z.failed == UDSOTA_DL_OK) {
        U.z.failed = (uint8_t)r;
    }
    return U.z.failed;
}

/* Worker: the image's bytes into flash. Nothing is erased until the first IMAGE_MIN bytes pass check_first. */
static uint8_t zdl_take(size_t n, bool last)
{
    U.z.held += n;
    U.z.produced += (uint32_t)n;
    const size_t first = (U.announced < IMAGE_MIN) ? U.announced : IMAGE_MIN;
    if (!U.z.begun && (U.z.held >= first || last)) {
        const udsota_reason_t why = check_first(U.zbuf, U.z.held, U.announced);
        if (why != UDSOTA_DL_OK) {
            return zdl_fail(why);
        }
        if (udsota_plat_begin(U.announced) != UDSOTA_DL_OK) {
            return zdl_fail(UDSOTA_DL_FLASH_ERROR);
        }
        U.z.begun = true;
    }
    if (U.z.begun && U.z.held > 0u && (U.z.held == BUF_LEN || U.z.produced == U.announced || last)) {
        if (udsota_plat_write(U.zbuf, U.z.held) != UDSOTA_DL_OK) {
            return zdl_fail(UDSOTA_DL_FLASH_ERROR);
        }
        U.z.written += (uint32_t)U.z.held;
        U.z.held = 0;
    }
    return U.z.failed;
}

#if UDSOTA_DELTA
/* Worker, detools' base read: n bytes of the running image from the offset its seeks move unchecked, refused when that
 * is negative or the read would pass INT_MAX, where detools' own int offset ends; the platform refuses a read past the
 * slot. */
static int base_read(void *arg, uint8_t *buf, size_t n)
{
    (void)arg;
    if (U.z.base_off < 0 || (uint64_t)U.z.base_off + n > (uint64_t)INT_MAX ||
        !udsota_plat_base_read((uint32_t)U.z.base_off, buf, n)) {
        return -1;
    }
    U.z.base_off += (int64_t)n;
    return 0;
}

/* Worker, detools' base seek: moves the offset the next read checks, never out of int's range, as detools adds the
 * same offset to its own. */
static int base_seek(void *arg, int offset)
{
    (void)arg;
    const int64_t next = U.z.base_off + offset;
    if (next < INT_MIN || next > INT_MAX) {
        return -1;
    }
    U.z.base_off = next;
    return 0;
}

/* Worker, detools' output: the rebuilt image's next n bytes into zbuf. detools writes runs of up to 128 bytes at any
 * alignment, so each is split where zbuf fills, as job_zwrite splits tinfl's. A patch for an image of another size than
 * memorySize is BAD_STREAM before its first byte reaches the image rules. */
static int patch_write(void *arg, const uint8_t *buf, size_t n)
{
    (void)arg;
    if (U.z.dt->to_size != U.announced) {
        (void)zdl_fail(UDSOTA_DL_BAD_STREAM);
        return -1;
    }
    while (n > 0u) {
        size_t k = BUF_LEN - U.z.held;
        k = (k < n) ? k : n;
        if (k == 0u || U.z.produced + k > U.announced) {
            (void)zdl_fail(UDSOTA_DL_BAD_STREAM);              /* past memorySize */
            return -1;
        }
        memcpy(&U.zbuf[U.z.held], buf, k);
        buf += k;
        n -= k;
        if (zdl_take(k, false) != UDSOTA_DL_OK) {
            return -1;
        }
    }
    return 0;
}

/* Worker: n inflated patch bytes. The 64-byte header comes first, and no byte reaches detools before it passes: a wrong
 * magic is BAD_STREAM, and a base other than the running image, or a running image whose hash can't be read, BAD_BASE,
 * so a delta from another base is refused before the image rules and the erase. detools then rebuilds the image into
 * zbuf: a corrupt patch, one for another size, a refused base read and any byte after the patch's end are BAD_STREAM,
 * unless the image failed first (its rules, the flash). */
static uint8_t patch_take(const uint8_t *d, size_t n)
{
    if (U.z.hdr_len < PATCH_HDR_LEN) {
        const size_t want = PATCH_HDR_LEN - U.z.hdr_len, k = (n < want) ? n : want;
        memcpy(&U.z.hdr[U.z.hdr_len], d, k);
        U.z.hdr_len += k;
        d += k;
        n -= k;
        if (U.z.hdr_len < PATCH_HDR_LEN) {
            return UDSOTA_DL_OK;
        }
        if (le32(U.z.hdr) != PATCH_MAGIC) {
            return zdl_fail(UDSOTA_DL_BAD_STREAM);
        }
        uint8_t base[32];
        if (!udsota_plat_base_hash(base) || memcmp(base, &U.z.hdr[4], sizeof base) != 0) {
            return zdl_fail(UDSOTA_DL_BAD_BASE);
        }
    }
    if (n == 0u) {
        return UDSOTA_DL_OK;
    }
    struct detools_apply_patch_t *dt = U.z.dt;
    const bool ended = (dt->state == detools_apply_patch_state_done_t);
    const int res = ended ? 0 : detools_apply_patch_process(dt, d, n);
    const bool bad = ended || res < 0 || dt->state == detools_apply_patch_state_failed_t ||
                     (dt->state != detools_apply_patch_state_init_t && dt->to_size != U.announced) ||
                     dt->chunk.offset != n;            /* detools stops at its end: the rest came after it */
    return (bad && U.z.failed == UDSOTA_DL_OK) ? zdl_fail(UDSOTA_DL_BAD_STREAM) : U.z.failed;
}

/* detools' state for a patch of unknown length: SIZE_MAX keeps its uncompressed reader's bound out of the way. */
static bool patch_open(void)
{
    U.z.dt = malloc(sizeof *U.z.dt);
    return U.z.dt != NULL &&
           detools_apply_patch_init(U.z.dt, base_read, base_seek, SIZE_MAX, patch_write, NULL) == 0;
}
#endif

/* The inflater, and for a delta detools' state after it; NO_MEMORY, holding nothing, when either can't be had. */
static udsota_reason_t zdl_open(bool delta)
{
    zdl_close();
    U.z.r = malloc(sizeof *U.z.r);
    U.z.dict = calloc(1, TINFL_LZ_DICT_SIZE);   /* zeroed: a back-reference before the start reads zeros */
    bool ok = U.z.r != NULL && U.z.dict != NULL;
#if UDSOTA_DELTA
    ok = ok && (!delta || patch_open());
#else
    ok = ok && !delta;
#endif
    if (!ok) {
        zdl_close();
        return UDSOTA_DL_NO_MEMORY;
    }
    tinfl_init(U.z.r);
    U.z.status = TINFL_STATUS_NEEDS_MORE_INPUT;
    return UDSOTA_DL_OK;
}

/* Worker: inflates n bytes of one 36 through tinfl's window, copying each run into zbuf, or for a delta handing it to
 * the patch stage whole. Either way the size checks count image bytes. */
static int job_zwrite(void)
{
    const uint8_t *in = U.blk;
    size_t n = U.blk_len;
    while (U.z.failed == UDSOTA_DL_OK) {
        while (U.z.pend > 0u) {                                /* copy out what tinfl made */
#if UDSOTA_DELTA
            if (U.mode == DL_DELTA) {
                const size_t k = U.z.pend;
                U.z.pend = 0;
                if (patch_take(&U.z.dict[U.z.pend_ofs], k) != UDSOTA_DL_OK) {
                    return U.z.failed;
                }
                continue;
            }
#endif
            size_t k = BUF_LEN - U.z.held;
            k = (k < U.z.pend) ? k : U.z.pend;
            if (k == 0u || U.z.produced + k > U.announced) {
                return zdl_fail(UDSOTA_DL_BAD_STREAM);        /* past memorySize */
            }
            memcpy(&U.zbuf[U.z.held], &U.z.dict[U.z.pend_ofs], k);
            U.z.pend -= k;
            U.z.pend_ofs += k;
            if (zdl_take(k, false) != UDSOTA_DL_OK) {
                return U.z.failed;
            }
        }
        if (U.z.status == TINFL_STATUS_DONE) {
            if (!U.z.begun && U.z.held < ((U.announced < IMAGE_MIN) ? U.announced : IMAGE_MIN)) {
                return zdl_fail(UDSOTA_DL_BAD_HEADER);   /* ended before the image check had its bytes */
            }
            U.z.ended = true;
            U.z.trailing = U.z.trailing || n > 0u;
            return UDSOTA_DL_OK;
        }
        if (U.z.status < 0) {
            return zdl_fail(UDSOTA_DL_BAD_STREAM);
        }
        if (n == 0u && U.z.status == TINFL_STATUS_NEEDS_MORE_INPUT) {
            return UDSOTA_DL_OK;
        }
        size_t in_n = n, out_n = TINFL_LZ_DICT_SIZE - U.z.dict_ofs;
        U.z.status = tinfl_decompress(U.z.r, in, &in_n, U.z.dict, U.z.dict + U.z.dict_ofs, &out_n,
                                      TINFL_FLAG_HAS_MORE_INPUT);
        if (U.z.status == TINFL_STATUS_DONE) {                 /* give back whole bytes read past the end */
            const size_t ahead = U.z.r->m_num_bits >> 3;
            if (ahead > in_n) {
                return zdl_fail(UDSOTA_DL_BAD_STREAM);         /* it read past the end in an earlier call */
            }
            in_n -= ahead;
            U.z.r->m_num_bits &= 7u;
        }
        if (in_n > 0u) {
            in += in_n;
            n -= in_n;
        }
        U.z.pend_ofs = U.z.dict_ofs;
        U.z.pend = out_n;
        U.z.dict_ofs = (U.z.dict_ofs + out_n) & (TINFL_LZ_DICT_SIZE - 1u);
        if (in_n == 0u && out_n == 0u && U.z.status != TINFL_STATUS_DONE) {
            return (n == 0u) ? UDSOTA_DL_OK : zdl_fail(UDSOTA_DL_BAD_STREAM);
        }
    }
    return U.z.failed;
}

/* Worker, the 37: the stream ended at exactly memorySize bytes, all written, with nothing after it, and a delta's patch
 * ended too. detools' uncompressed reader holds nothing back, so the 36s wrote every byte the patch makes: finalize
 * only lets detools reach its end, and its result is no verdict, since with SIZE_MAX as the patch's length the reader's
 * end always reports a corrupt patch. */
static int job_zend(void)
{
#if UDSOTA_DELTA
    if (U.mode == DL_DELTA && U.z.failed == UDSOTA_DL_OK) {
        (void)detools_apply_patch_finalize(U.z.dt);
        if (U.z.dt->state != detools_apply_patch_state_done_t || U.z.dt->to_offset != U.z.dt->to_size ||
            U.z.dt->to_size != U.announced) {
            (void)zdl_fail(UDSOTA_DL_BAD_STREAM);
        }
    }
#endif
    if (U.z.failed == UDSOTA_DL_OK && U.z.ended && !U.z.trailing && U.z.produced == U.announced) {
        (void)zdl_take(0, true);
    }
    const bool ok = U.z.failed == UDSOTA_DL_OK && U.z.ended && !U.z.trailing && U.z.begun &&
                    U.z.written == U.announced;
    const uint8_t failed = U.z.failed;
    zdl_close();
    return ok ? UDSOTA_DL_OK : (failed != UDSOTA_DL_OK ? failed : UDSOTA_DL_BAD_STREAM);
}

/* ==== 4. 0x27 keys and the PSA lock ==== */

/* The PSA lock (udsota.h). On ESP-IDF a FreeRTOS mutex in static storage, created by udsota_init before its key
 * setup, so the worker inherits a waiting task's priority while it holds it. A host build is one task: the lock is a
 * depth that the host test reads, and a wait on it held fails at once. */
#if defined(ESP_PLATFORM)
static StaticSemaphore_t s_psa_storage;
static SemaphoreHandle_t s_psa;

static void psa_lock_init(void)
{
    if (s_psa == NULL) {
        s_psa = xSemaphoreCreateMutexStatic(&s_psa_storage);
    }
}

bool udsota_psa_lock(uint32_t wait_ms)
{
    if (s_psa == NULL) {
        return true;                                     /* before udsota_init: only start code runs */
    }
    const TickType_t ticks = (wait_ms == UDSOTA_PSA_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(wait_ms);
    return xSemaphoreTake(s_psa, ticks) == pdTRUE;
}

void udsota_psa_unlock(void)
{
    if (s_psa != NULL) {
        (void)xSemaphoreGive(s_psa);
    }
}
#else
static int s_psa_depth;

static void psa_lock_init(void) {}

bool udsota_psa_lock(uint32_t wait_ms)
{
    (void)wait_ms;
    if (s_psa_depth != 0) {
        return false;
    }
    s_psa_depth++;
    return true;
}

void udsota_psa_unlock(void)
{
    s_psa_depth--;
}

#if defined(UDSOTA_TEST)
int udsota_test_psa_depth(void)
{
    return s_psa_depth;
}
#endif
#endif

/* HMAC mode: the expected key for seed at requestSeed level: HMAC-SHA256(K_dev, seed || level || ID)[0..15]. */
static bool hmac_key(const uint8_t seed[UDSOTA_SEED_LEN], uint8_t level, uint8_t key[UDSOTA_KEY_LEN])
{
    uint8_t msg[UDSOTA_SEED_LEN + 1u + UDSOTA_KEYS_ID_MAX], full[32] = {0};
    memcpy(msg, seed, UDSOTA_SEED_LEN);
    msg[UDSOTA_SEED_LEN] = level;
    memcpy(&msg[UDSOTA_SEED_LEN + 1u], U.devid, U.devid_len);
    bool ok = U.key_ok && udsota_psa_lock(KEY_LOCK_MS);
    if (ok) {
        ok = udsota_plat_hmac(U.kdev, sizeof U.kdev, msg, UDSOTA_SEED_LEN + 1u + U.devid_len, full);
        udsota_psa_unlock();
    }
    memcpy(key, full, UDSOTA_KEY_LEN);
    wipe(full, sizeof full);
    wipe(msg, sizeof msg);
    return ok;
}

/* ECDSA mode: the tester signs UDSOTA_KEYS_SIG_TAG || seed || level || ID length || ID, so a signature opens one
 * level of one device for one seed. 1 valid, 0 not, -1 no verdict now. */
static int ecdsa_check(const uint8_t seed[UDSOTA_SEED_LEN], uint8_t level, const uint8_t *sig)
{
    uint8_t msg[sizeof UDSOTA_KEYS_SIG_TAG - 1u + UDSOTA_SEED_LEN + 2u + UDSOTA_KEYS_ID_MAX];
    size_t n = sizeof UDSOTA_KEYS_SIG_TAG - 1u;
    memcpy(msg, UDSOTA_KEYS_SIG_TAG, n);
    memcpy(&msg[n], seed, UDSOTA_SEED_LEN);
    n += UDSOTA_SEED_LEN;
    msg[n++] = level;
    msg[n++] = (uint8_t)U.devid_len;
    memcpy(&msg[n], U.devid, U.devid_len);
    if (!U.key_ok || !udsota_psa_lock(KEY_LOCK_MS)) {
        return -1;
    }
    const int v = udsota_plat_ecdsa(msg, n + U.devid_len, sig);
    udsota_psa_unlock();
    return v;
}

/* ==== 5. The updater ==== */

static void status_now(udsota_status_t *st)
{
    memset(st, 0, sizeof *st);
    udsota_plat_status(st);
}

/* The slot rule for 10 02 and 34: the boot slot is the running one and the running image is confirmed. */
static bool slots_settled(void)
{
    udsota_status_t st;
    status_now(&st);
    return st.running_slot != UDSOTA_SLOT_NONE && st.boot_slot == st.running_slot &&
           st.running_state != UDSOTA_IMG_PENDING_VERIFY;
}

static uint8_t gate(udsota_op_t op)
{
    return (U.cfg.gate != NULL) ? U.cfg.gate(U.cfg.ctx, op) : 0u;
}

/* An open image is closed once the worker is idle: now, or at the next event. */
static void settle(void)
{
    if (U.close_pending && udsota_plat_poll() != UDSOTA_PENDING) {
        zdl_close();
        udsota_plat_abort();
        U.close_pending = false;
    }
}

static bool worker_busy(void)
{
    return U.job_running || U.close_pending || udsota_plat_poll() == UDSOTA_PENDING;
}

/* Ends the download or an open, unverified image; F1F1 says ABORTED. */
static void abort_download(void)
{
    U.dl_complete = false;
    if (!U.dl_active && !U.ota_open) {
        return;
    }
    if (U.ota_open) {
        U.close_pending = true;
        settle();
    }
    U.dl_active = false;
    U.ota_open = false;
    U.last_reason = UDSOTA_DL_ABORTED;
    U.last_bytes = U.received;
}

static int verify_done(int result, uint8_t *status, size_t *status_len);

static udsota_progress_t progress_of(void)
{
    udsota_progress_t p = {.stage = UDSOTA_STAGE_IDLE, .last_reason = U.last_reason};
    if (U.activating) {
        p.stage = UDSOTA_STAGE_ACTIVATING;
    } else if (U.job_running && U.job_done == verify_done) {
        p.stage = UDSOTA_STAGE_VERIFYING;
    } else if (U.dl_active || (U.dl_complete && U.ota_open)) {
        p.stage = (U.dl_active && U.received == 0u) ? UDSOTA_STAGE_ERASING : UDSOTA_STAGE_WRITING;
        p.total = U.announced;
        p.done = (U.written < p.total) ? U.written : p.total;
    }
    return p;
}

/* Tells cfg.progress, once per call that changed the stage or the reason or wrote a block. */
static void progress_sync(void)
{
    const udsota_progress_t p = progress_of();
    const bool block = U.progress_block;
    U.progress_block = false;
    if ((uint8_t)p.stage == U.progress_stage && !block && p.last_reason == U.progress_reason) {
        return;
    }
    U.progress_stage = (uint8_t)p.stage;
    U.progress_reason = p.last_reason;
    if (U.cfg.progress != NULL) {
        U.cfg.progress(U.cfg.ctx, &p);
    }
}

/* Queues fn on the worker: UDSOTA_PENDING (the event answers 0x78 until done() has the result), or done() now. */
static int run_job(int (*fn)(void), done_fn done, uint8_t sid, uint8_t *status, size_t *status_len)
{
    if (udsota_plat_run(fn) != UDSOTA_PENDING) {
        return done(UDSOTA_DL_FLASH_ERROR, status, status_len);
    }
    U.job_running = true;
    U.job_done = done;
    U.job_sid = sid;
    U.job_ms = UDSMillis();
    return UDSOTA_PENDING;
}

/* ---- 34, 36, 37 ---- */

/* 34/36/37: 0x7F outside the programming session, 0x33 while locked. */
static int dl_access(const UDSServer_t *srv)
{
    if (srv->sessionType != UDS_LEV_DS_PRGS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    return (U.sec_on && srv->securityLevel != UDSOTA_SA_SEED_PROGRAMMING) ? UDS_NRC_SecurityAccessDenied : 0;
}

static void dl_flash_failed(void)
{
    abort_download();
    U.last_reason = UDSOTA_DL_FLASH_ERROR;
}

/* 34: access, then settled slots, an idle worker, no transfer and the gate, then DFI 00 or 10 (or 30, with delta
 * downloads built in and allowed), address 0 and a size that fits. */
static int request_download(const UDSServer_t *srv, uint8_t dfi, uint32_t addr, uint32_t size)
{
    int rc = dl_access(srv);
    if (rc != 0) {
        return rc;
    }
    if (!slots_settled() || worker_busy() || U.dl_active) {
        return UDS_NRC_ConditionsNotCorrect;
    }
    if ((rc = gate(UDSOTA_OP_START_DOWNLOAD)) != 0) {
        return rc;
    }
    if (udsota_plat_slot_size() == 0u) {
        U.last_reason = UDSOTA_DL_FLASH_ERROR;           /* no inactive slot */
        return UDS_NRC_ConditionsNotCorrect;
    }
    int mode = (dfi == UDSOTA_DL_DFI) ? DL_PLAIN : (dfi == UDSOTA_DL_DFI_DEFLATE) ? DL_DEFLATE : -1;
#if UDSOTA_DELTA
    if (dfi == UDSOTA_DL_DFI_DELTA_DEFLATE && U.cfg.allow_delta) {
        mode = DL_DELTA;
    }
#endif
    if (mode < 0 || addr != 0u || size == 0u || size > udsota_plat_slot_size()) {
        return UDS_NRC_RequestOutOfRange;
    }
    if (U.ota_open) {                                    /* a finished image that never passed FF01 */
        U.close_pending = true;
        settle();
        U.ota_open = false;
    }
    if (mode != DL_PLAIN && zdl_open(mode == DL_DELTA) != UDSOTA_DL_OK) {
        U.last_reason = UDSOTA_DL_NO_MEMORY;
        U.last_bytes = 0;
        return UDS_NRC_ConditionsNotCorrect;
    }
    udsota_plat_unverify();
    U.slot_verified = false;
    U.dl_active = true;
    U.ota_open = (mode != DL_PLAIN);                     /* the inflater is held from here */
    U.mode = (uint8_t)mode;
    U.dl_complete = false;
    U.announced = size;
    U.received = U.written = 0u;
    U.last_reason = UDSOTA_DL_OK;
    U.last_bytes = 0u;
    return 0;
}

static int job_write(void)
{
    return udsota_plat_write(U.blk, U.blk_len);
}

static int job_first(void)
{
    const int r = udsota_plat_begin(U.announced);
    return (r != UDSOTA_DL_OK) ? UDSOTA_DL_FLASH_ERROR : udsota_plat_write(U.blk, U.blk_len);
}

/* 36's answer once the worker has written the block: positive, 0x72 for a flash failure, 0x31 for a coded block the
 * image rules, the stream or a delta's patch refused. */
static int block_done(int result, uint8_t *status, size_t *status_len)
{
    (void)status;
    *status_len = 0;
    if (result != UDSOTA_DL_OK && U.mode != DL_PLAIN && result != UDSOTA_DL_FLASH_ERROR &&
        result != UDSOTA_DL_NO_MEMORY) {
        abort_download();
        U.last_reason = (uint8_t)result;
        return UDS_NRC_RequestOutOfRange;
    }
    if (result != UDSOTA_DL_OK) {
        dl_flash_failed();
        return UDS_NRC_GeneralProgrammingFailure;
    }
    U.received += (uint32_t)U.blk_len;
    U.written = (U.mode != DL_PLAIN) ? U.z.written : U.written + (uint32_t)U.blk_len;
    U.progress_block = true;
    U.last_bytes = U.received;
    return 0;
}

/* 36: access, length, sequence, the gate (any refusal ends the transfer, as iso14229 does on any NRC; one but 0x21
 * also ends the session), overrun, the image check on the first block, then the write on the worker. iso14229 has
 * already checked the block counter. */
static int transfer_data(UDSServer_t *srv, const uint8_t *data, size_t len, bool *end_session)
{
    int rc = dl_access(srv);
    if (rc != 0) {
        return rc;
    }
    if (len < 1u || len + 2u > UDSOTA_DL_MAX_BLOCK_LEN) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    if (!U.dl_active) {
        return UDS_NRC_RequestSequenceError;
    }
    if ((rc = gate(UDSOTA_OP_CONTINUE_TRANSFER)) != 0) {
        if (rc != UDS_NRC_BusyRepeatRequest) {
            abort_download();
            *end_session = true;
        }
        return rc;
    }
    const uint64_t limit = (U.mode != DL_PLAIN) ? UDSOTA_DL_Z_BOUND(U.announced) : U.announced;
    if ((uint64_t)U.received + len > limit) {
        abort_download();
        return UDS_NRC_TransferDataSuspended;
    }
    if (U.mode != DL_PLAIN) {
        srv->xferTotalBytes = (limit > SIZE_MAX) ? SIZE_MAX : (size_t)limit;   /* iso14229 counts memorySize */
    }
    memcpy(U.blk, data, len);
    U.blk_len = len;
    int (*job)(void) = (U.mode != DL_PLAIN) ? job_zwrite : job_write;
    if (U.mode == DL_PLAIN && !U.ota_open) {             /* the first block: check it before anything is erased */
        const udsota_reason_t why = check_first(data, len, U.announced);
        if (why != UDSOTA_DL_OK) {
            abort_download();
            U.last_reason = (uint8_t)why;
            return UDS_NRC_RequestOutOfRange;
        }
        U.ota_open = true;
        job = job_first;
    }
    size_t none = 0;
    return run_job(job, block_done, 0x36, NULL, &none);
}

static int exit_ok(void)
{
    U.dl_active = false;
    U.dl_complete = true;
    U.last_reason = UDSOTA_DL_OK;
    U.last_bytes = U.received;
    return 0;
}

static int zend_done(int result, uint8_t *status, size_t *status_len)
{
    (void)status;
    *status_len = 0;
    if (result != UDSOTA_DL_OK) {
        U.ota_open = false;                              /* the stream is closed: only the flash side remains */
        U.close_pending = true;
        abort_download();
        U.last_reason = (uint8_t)result;
        return UDS_NRC_GeneralProgrammingFailure;
    }
    U.written = U.announced;
    U.progress_block = true;
    return exit_ok();
}

/* 37: once every announced byte has arrived (else 0x24); a coded stream must also end exactly. */
static int transfer_exit(const UDSServer_t *srv, size_t extra)
{
    const int rc = dl_access(srv);
    if (rc != 0) {
        return rc;
    }
    if (extra != 0u) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    if (!U.dl_active || (U.mode == DL_PLAIN && U.received != U.announced)) {
        return UDS_NRC_RequestSequenceError;
    }
    size_t none = 0;
    return (U.mode != DL_PLAIN) ? run_job(job_zend, zend_done, 0x37, NULL, &none) : exit_ok();
}

/* ---- 31 01: FF01 verify, F000 resume point, F001 activate, F002 confirm ---- */

/* esp_ota_end and esp_ota_set_boot_partition hash through PSA. The wait has no limit: the app holds it briefly. */
static int job_verify(void)
{
    if (!udsota_psa_lock(UDSOTA_PSA_WAIT_FOREVER)) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    const int r = udsota_plat_end();
    udsota_psa_unlock();
    return r;
}

static int job_activate(void)
{
    if (!udsota_psa_lock(UDSOTA_PSA_WAIT_FOREVER)) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    const int r = udsota_plat_activate();
    udsota_psa_unlock();
    return r;
}

static int job_confirm(void) { return udsota_plat_confirm(); }

static int one_byte(uint8_t *status, size_t *status_len, uint8_t b)
{
    status[0] = b;
    *status_len = 1;
    return 0;
}

static int verify_done(int result, uint8_t *status, size_t *status_len)
{
    const uint8_t reason = (result >= 0 && result <= UDSOTA_DL_BAD_BASE) ? (uint8_t)result : UDSOTA_DL_VERIFY_FAILED;
    U.slot_verified = (reason == UDSOTA_DL_OK);
    U.last_reason = reason;
    return one_byte(status, status_len, reason);
}

static int activate_done(int result, uint8_t *status, size_t *status_len)
{
    (void)status;
    *status_len = 0;
    if (result != UDSOTA_DL_OK) {
        U.slot_verified = false;
        return UDS_NRC_GeneralProgrammingFailure;
    }
    U.activating = true;
    return 0;
}

static int confirm_done(int result, uint8_t *status, size_t *status_len)
{
    (void)status;
    *status_len = 0;
    return (result != UDSOTA_DL_OK) ? UDS_NRC_GeneralProgrammingFailure : 0;
}

/* The RIDs' checks in order: 7F in the default session, 12 for another control, the RID's session (31), the key
 * (33) and the length (13), then per RID its sequence (24) before its conditions (22). -1: not ours. */
static int routine(const UDSServer_t *srv, uint8_t ctrl, uint16_t rid, size_t opt_len, uint8_t *status,
                   size_t *status_len)
{
    const bool confirm = (rid == UDSOTA_RID_CONFIRM_IMAGE);
    if (!confirm && rid != UDSOTA_RID_CHECK_PROG_DEPS && rid != UDSOTA_RID_GET_RESUME_POINT &&
        rid != UDSOTA_RID_ACTIVATE_IMAGE) {
        return -1;
    }
    if (srv->sessionType == UDS_LEV_DS_DS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (ctrl != 0x01u) {
        return UDS_NRC_SubFunctionNotSupported;
    }
    if (srv->sessionType != (confirm ? UDS_LEV_DS_EXTDS : UDS_LEV_DS_PRGS)) {
        return UDS_NRC_RequestOutOfRange;
    }
    if (!confirm && U.sec_on && srv->securityLevel != UDSOTA_SA_SEED_PROGRAMMING) {
        return UDS_NRC_SecurityAccessDenied;
    }
    if (opt_len != 0u) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    int rc;
    switch (rid) {
    case UDSOTA_RID_CHECK_PROG_DEPS:
        if (U.slot_verified && !U.ota_open) {
            return one_byte(status, status_len, UDSOTA_DL_OK);   /* a repeat after a pass */
        }
        if (!U.dl_complete || !U.ota_open) {
            return UDS_NRC_RequestSequenceError;
        }
        U.dl_complete = U.ota_open = U.slot_verified = false;   /* the verify closes the image either way */
        U.last_reason = UDSOTA_DL_WORKER_TIMEOUT;                /* until the verdict */
        return run_job(job_verify, verify_done, 0x31, status, status_len);
    case UDSOTA_RID_GET_RESUME_POINT:
        return one_byte(status, status_len, UDSOTA_RESUME_NOT_AVAILABLE);
    case UDSOTA_RID_ACTIVATE_IMAGE:
        if (!U.slot_verified) {
            return UDS_NRC_RequestSequenceError;
        }
        if ((rc = worker_busy() ? UDS_NRC_ConditionsNotCorrect : gate(UDSOTA_OP_ACTIVATE)) != 0) {
            return rc;
        }
        return run_job(job_activate, activate_done, 0x31, status, status_len);
    default: {                                               /* UDSOTA_RID_CONFIRM_IMAGE */
        if ((rc = gate(UDSOTA_OP_CONFIRM)) != 0) {
            return rc;
        }
        udsota_status_t st;
        status_now(&st);
        if (st.running_slot == UDSOTA_SLOT_NONE || st.boot_slot != st.running_slot) {
            return UDS_NRC_ConditionsNotCorrect;
        }
        if (st.running_state == UDSOTA_IMG_VALID || st.running_state == UDSOTA_IMG_UNDEFINED) {
            return 0;                                        /* confirmed already */
        }
        if (st.running_state != UDSOTA_IMG_PENDING_VERIFY) {
            return UDS_NRC_ConditionsNotCorrect;
        }
        return run_job(job_confirm, confirm_done, 0x31, status, status_len);
    }
    }
}

/* ---- The DIDs ---- */

/* The DID's bytes into out; 0 for a DID that is not ours. */
static size_t read_did(const UDSServer_t *srv, uint16_t did, uint8_t *out)
{
    udsota_status_t st;
    switch (did) {
    case UDSOTA_DID_ACTIVE_SESSION:
        out[0] = srv->sessionType;
        return 1;
    case UDSOTA_DID_SERIAL:
        memcpy(out, U.devid, U.devid_len);
        return U.devid_len;
    case UDSOTA_DID_SW_VERSION: {
        const char *v = udsota_plat_version();
        const size_t n = strnlen(v, 32);
        memcpy(out, v, n);
        return n;
    }
    case UDSOTA_DID_STATUS:
        status_now(&st);
        out[0] = st.running_slot;
        out[1] = st.running_state;
        out[2] = st.boot_slot;
        out[3] = st.other_slot_state;
        memcpy(&out[4], st.other_version, 3);
        memcpy(&out[7], st.other_elf_sha_prefix, 8);
        out[15] = st.flags;
        return 16;
    case UDSOTA_DID_RESULT:
        out[0] = U.last_reason;
        out[1] = (uint8_t)(U.last_bytes >> 24);
        out[2] = (uint8_t)(U.last_bytes >> 16);
        out[3] = (uint8_t)(U.last_bytes >> 8);
        out[4] = (uint8_t)U.last_bytes;
        return 5;
    case UDSOTA_DID_RUNNING_SHA:
        memcpy(out, udsota_plat_sha(), 32);
        return 32;
    default:
        return 0;
    }
}

/* ==== 6. iso14229's events ==== */

/* Every session entry and S3 timeout: the download ends on both sides, the seed dies and the lock returns (iso14229
 * itself relocks only on S3, so an unlock would otherwise outlive 10 01 for good). */
static void session_changed(UDSServer_t *srv)
{
    const bool waited = U.job_running && (U.dl_active || U.ota_open || U.job_done == verify_done);   /* the cap, or S3 */
    U.job_running = false;                               /* a running job finishes on the worker by itself */
    abort_download();
    if (waited) {
        U.last_reason = UDSOTA_DL_WORKER_TIMEOUT;        /* its answer never came */
    }
    U.seed_valid = false;
    wipe(U.seed, sizeof U.seed);
    srv->xferIsActive = false;
    srv->securityLevel = 0;
    progress_sync();
}

/* udsota's own end of a session (a gate refusal mid-transfer, the job cap): back to default and locked. */
static void end_session(UDSServer_t *srv)
{
    session_changed(srv);
    srv->sessionType = UDS_LEV_DS_DS;
}

/* Once ActivateImage is positive, the device restarts as its own 11 01 would, once the answer has left. */
static void activation_check(UDSServer_t *srv)
{
    if (U.activating && srv->ecuResetScheduled == 0u) {
        srv->ecuResetScheduled = UDS_LEV_RT_HR;
        srv->ecuResetTimer = UDSMillis() + srv->p2_ms + UDS_SERVER_DEFAULT_POWER_DOWN_TIME_MS;
        U.reset_mine = true;
    }
}

/* A running job's next answer: 0x78 until the worker is done, 0x72 after 90 s, 0x21 for another service. The tester
 * is waiting on this request, so udsota holds the session meanwhile: iso14229 restarts S3 only on 10 and 3E, and a
 * compressed block can inflate into many seconds of erasing. */
static int resume(UDSServer_t *srv, uint8_t sid, uint8_t *status, size_t *status_len)
{
    *status_len = 0;
    if (sid != U.job_sid) {
        return UDS_NRC_BusyRepeatRequest;
    }
    if ((uint32_t)(UDSMillis() - U.job_ms) >= JOB_CAP_MS) {
        end_session(srv);                                /* F1F1: WORKER_TIMEOUT */
        return UDS_NRC_GeneralProgrammingFailure;
    }
    const int r = udsota_plat_poll();
    if (r == UDSOTA_PENDING) {
        srv->s3_session_timeout_timer = UDSMillis() + srv->s3_ms;
        return UDSOTA_PENDING;
    }
    U.job_running = false;
    return U.job_done(r, status, status_len);
}

static UDSErr_t as_err(int rc)
{
    return (rc == UDSOTA_PENDING) ? UDS_NRC_RequestCorrectlyReceived_ResponsePending : (UDSErr_t)rc;
}

static UDSErr_t on_session(UDSServer_t *srv, uint8_t type)
{
    uint8_t nrc = 0;
    if (type == UDS_LEV_DS_PRGS) {
        nrc = (!slots_settled() || worker_busy() || U.dl_active) ? UDS_NRC_ConditionsNotCorrect
                                                                 : gate(UDSOTA_OP_ENTER_PROGRAMMING);
    } else if (type == UDS_LEV_DS_EXTDS) {
        nrc = gate(UDSOTA_OP_ENTER_EXTENDED);
    }
    if (nrc != 0u) {
        return (UDSErr_t)nrc;
    }
    session_changed(srv);
    return UDS_PositiveResponse;
}

/* 27 at our two levels, in their sessions: a fresh single-use seed, then its key. iso14229 delays retries. */
static UDSErr_t on_security(UDSServer_t *srv, uint8_t level, const uint8_t *key, size_t len, bool seed,
                            UDSSecAccessRequestSeedArgs_t *sa)
{
    if (srv->sessionType == UDS_LEV_DS_DS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (srv->sessionType != (level == UDSOTA_SA_SEED_PROGRAMMING ? UDS_LEV_DS_PRGS : UDS_LEV_DS_EXTDS)) {
        return UDS_NRC_SubFunctionNotSupportedInActiveSession;
    }
    if (worker_busy()) {
        return UDS_NRC_ConditionsNotCorrect;             /* the worker may be using the crypto */
    }
    if (seed) {
        if (len != 0u) {
            return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
        }
        U.seed_valid = udsota_plat_rng16(U.seed);
        if (!U.seed_valid) {
            return UDS_NRC_ConditionsNotCorrect;
        }
        U.seed_level = level;
        U.seed_ms = UDSMillis();
        return (UDSErr_t)sa->copySeed(srv, U.seed, UDSOTA_SEED_LEN);
    }
    if (len != (U.sec_ecdsa ? UDSOTA_KEYS_SIG_LEN : UDSOTA_KEY_LEN)) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;   /* the seed stays */
    }
    const bool fresh = U.seed_valid && U.seed_level == level &&
                       (uint32_t)(UDSMillis() - U.seed_ms) < UDSOTA_SA_SEED_VALID_MS;
    U.seed_valid = false;
    UDSErr_t rc = UDS_NRC_RequestSequenceError;
    if (fresh && U.sec_ecdsa) {
        const int v = ecdsa_check(U.seed, level, key);
        rc = (v == 1) ? UDS_PositiveResponse : (v < 0) ? UDS_NRC_ConditionsNotCorrect : UDS_NRC_InvalidKey;
    } else if (fresh) {
        uint8_t expect[UDSOTA_KEY_LEN];
        volatile uint8_t diff = 0;
        if (!hmac_key(U.seed, level, expect)) {
            rc = UDS_NRC_ConditionsNotCorrect;
        } else {
            for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) {
                diff |= (uint8_t)(expect[i] ^ key[i]);   /* constant time */
            }
            rc = (diff == 0u) ? UDS_PositiveResponse : UDS_NRC_InvalidKey;
        }
        wipe(expect, sizeof expect);
    }
    wipe(U.seed, sizeof U.seed);
    return rc;
}

bool udsota_event(UDSServer_t *srv, UDSEvent_t ev, void *arg, UDSErr_t *rc)
{
    *rc = UDS_PositiveResponse;
    if (!U.started) {
        return false;
    }
    settle();
    if (!srv->xferIsActive && U.dl_active) {             /* iso14229 ended a transfer without an event (0x24, 0x70, 0x71) */
        abort_download();
        progress_sync();
    }
    uint8_t status[8], buf[64];
    size_t status_len = 0;
    bool end = false, mine = true;
    switch (ev) {
    case UDS_EVT_SessionTimeout:
        session_changed(srv);
        return false;                                    /* the app may want it too */
    case UDS_EVT_DoScheduledReset:
        if (!U.reset_mine) {
            return false;
        }
        if (U.cfg.reset != NULL) {
            U.cfg.reset(U.cfg.ctx);
        } else {
#if defined(ESP_PLATFORM)
            esp_restart();
#endif
        }
        return true;
    case UDS_EVT_DiagSessCtrl: {
        UDSDiagSessCtrlArgs_t *a = arg;
        if (a->type < UDS_LEV_DS_DS || a->type > UDS_LEV_DS_EXTDS) {
            return false;
        }
        if (a->p2_star_ms < srv->p2_star_ms) {           /* iso14229 sends its client default, 1500 ms, which the 0x78s
                                                            (every 0.3 x P2*) would race; P2 keeps its 150 ms */
            a->p2_star_ms = srv->p2_star_ms;
        }
        *rc = on_session(srv, a->type);
        break;
    }
    case UDS_EVT_EcuReset:
        if (((UDSECUResetArgs_t *)arg)->type != UDS_LEV_RT_HR) {
            return false;
        }
        *rc = (srv->sessionType == UDS_LEV_DS_DS)                       ? UDS_NRC_ServiceNotSupportedInActiveSession
            : (U.sec_on && srv->securityLevel == 0u)                    ? UDS_NRC_SecurityAccessDenied
            : worker_busy()                                             ? UDS_NRC_ConditionsNotCorrect
                                                                        : (UDSErr_t)gate(UDSOTA_OP_RESET);
        U.reset_mine = U.reset_mine || *rc == UDS_PositiveResponse;
        break;
    case UDS_EVT_SecAccessRequestSeed: {
        UDSSecAccessRequestSeedArgs_t *a = arg;
        if (!U.sec_on || (a->level != UDSOTA_SA_SEED_EXTENDED && a->level != UDSOTA_SA_SEED_PROGRAMMING)) {
            return false;
        }
        *rc = on_security(srv, a->level, NULL, a->len, true, a);
        break;
    }
    case UDS_EVT_SecAccessValidateKey: {
        const UDSSecAccessValidateKeyArgs_t *a = arg;
        if (!U.sec_on || (a->level != UDSOTA_SA_SEED_EXTENDED && a->level != UDSOTA_SA_SEED_PROGRAMMING)) {
            return false;
        }
        *rc = on_security(srv, a->level, a->key, a->len, false, NULL);
        break;
    }
    case UDS_EVT_ReadDataByIdent: {
        UDSRDBIArgs_t *a = arg;
        const size_t n = read_did(srv, a->dataId, buf);
        if (n == 0u) {
            return false;
        }
        *rc = (UDSErr_t)a->copy(srv, buf, (uint16_t)n);
        return true;
    }
    case UDS_EVT_RoutineCtrl: {
        UDSRoutineCtrlArgs_t *a = arg;
        int r;
        if (U.job_running) {
            r = resume(srv, 0x31, status, &status_len);
        } else {
            r = routine(srv, a->ctrlType, a->id, a->len, status, &status_len);
            if (r < 0) {
                return false;
            }
        }
        activation_check(srv);
        *rc = as_err(r);
        if (*rc == UDS_PositiveResponse && status_len != 0u) {
            *rc = (UDSErr_t)a->copyStatusRecord(srv, status, (uint16_t)status_len);
        }
        break;
    }
    case UDS_EVT_RequestDownload: {
        UDSRequestDownloadArgs_t *a = arg;
        if (a->addr != 0u) {
            return false;                                /* udsota's images go to address 0; the rest are the app's */
        }
        *rc = (a->size > UINT32_MAX)
                  ? UDS_NRC_RequestOutOfRange
                  : as_err(request_download(srv, a->dataFormatIdentifier, (uint32_t)a->addr, (uint32_t)a->size));
        if (*rc == UDS_PositiveResponse) {
            a->maxNumberOfBlockLength = UDSOTA_DL_MAX_BLOCK_LEN;
        }
        break;
    }
    case UDS_EVT_TransferData:
    case UDS_EVT_RequestTransferExit: {
        const uint8_t sid = (ev == UDS_EVT_TransferData) ? 0x36 : 0x37;
        if (!U.dl_active && !U.job_running) {
            return false;                                /* a transfer the app opened (34, 35 or 38) */
        }
        int r;
        if (U.job_running) {
            r = resume(srv, sid, status, &status_len);
        } else if (ev == UDS_EVT_TransferData) {
            const UDSTransferDataArgs_t *a = arg;
            r = transfer_data(srv, a->data, a->len, &end);
        } else {
            r = transfer_exit(srv, ((UDSRequestTransferExitArgs_t *)arg)->len);
        }
        *rc = as_err(r);
        if (*rc != UDS_PositiveResponse && *rc != UDS_NRC_RequestCorrectlyReceived_ResponsePending) {
            abort_download();                            /* iso14229 ends its transfer on any NRC */
        }
        if (end) {
            end_session(srv);
        }
        break;
    }
    default:
        mine = false;
        break;
    }
    progress_sync();
    return mine;
}

/* ==== The API ==== */

int udsota_init(const udsota_cfg_t *cfg)
{
    if (U.started || cfg == NULL || udsota_image_desc.magic != 0x5544534Fu) {
        return -1;
    }
    psa_lock_init();
    U.cfg = *cfg;
    U.product = (cfg->product != NULL) ? cfg->product : udsota_plat_project();
    const char *v = udsota_plat_version();
    const size_t vlen = strnlen(v, 32);
    if (vlen == 32u || !parse_version(v, vlen + 1u, U.running_version, &U.running_release)) {
        U.running_release = false;                        /* unparseable: {0,0,0}, a dev build */
    }
    if (cfg->device_id == NULL) {
        U.devid_len = udsota_plat_mac(U.devid);
    } else if (cfg->device_id_len >= 1u && cfg->device_id_len <= UDSOTA_KEYS_ID_MAX) {
        memcpy(U.devid, cfg->device_id, cfg->device_id_len);
        U.devid_len = cfg->device_id_len;
    }
    /* 0x27: ECDSA wins over HMAC. Any key field turns it on, and an incomplete set then unlocks nothing; with none,
     * 0x27 is the app's and downloads need no key. */
    U.sec_ecdsa = (cfg->key_pubkey != NULL || cfg->key_pubkey_len != 0u);
    U.sec_on = U.sec_ecdsa || cfg->key_label != NULL || cfg->key_master != NULL || cfg->key_master_len != 0u;
    if (U.devid_len == 0u) {
        LOGW("no device ID (a bad device_id_len, or no MAC)");
    } else if (U.sec_ecdsa) {
        if (cfg->key_pubkey != NULL && cfg->key_pubkey_len == UDSOTA_KEYS_PUBKEY_LEN &&
            udsota_psa_lock(UDSOTA_PSA_WAIT_FOREVER)) {
            U.key_ok = udsota_plat_ecdsa_key(cfg->key_pubkey) == 0;
            udsota_psa_unlock();
        }
    } else if (U.sec_on && cfg->key_label != NULL && cfg->key_master != NULL) {
        uint8_t msg[LABEL_MAX + UDSOTA_KEYS_ID_MAX];
        const size_t ln = strnlen(cfg->key_label, LABEL_MAX + 1u);
        if (ln <= LABEL_MAX && udsota_psa_lock(UDSOTA_PSA_WAIT_FOREVER)) {
            memcpy(msg, cfg->key_label, ln);
            memcpy(&msg[ln], U.devid, U.devid_len);
            U.key_ok = udsota_plat_hmac(cfg->key_master, cfg->key_master_len, msg, ln + U.devid_len, U.kdev);
            udsota_psa_unlock();
        }
        wipe(msg, sizeof msg);
    }
    if (!U.sec_on) {
        LOGW("security off: no key, so 0x27 is the app's and any node can download");
    } else if (!U.key_ok) {
        LOGW("0x27 keys unusable: nothing unlocks");
    }
    U.started = true;
    return udsota_plat_start();
}

/* iso14229 compares its deadlines with UDSTimeAfter, a 32-bit difference read as expired when it is 1 to 2^31 - 1, so
 * a deadline that expired 2^31 ms (24.86 days) ago reads as pending again until 2^32 ms. Its P2 timer, set at
 * UDSServerInit and when an answer goes out, then holds the next request's answer, and its two 0x27 delays, set at
 * UDSServerInit and on a failed key, answer 27 with 0x37 or 0x36. Run every pass, this moves each one that has expired
 * to now - 1, which still reads as expired (a difference of 0 would not), so none ever gets old enough to wrap; a
 * pending one is left alone. The other deadlines are set afresh before each use. */
void udsota_poll(UDSServer_t *srv)
{
    const uint32_t now = UDSMillis();
    uint32_t *const timers[] = {&srv->p2_timer, &srv->sec_access_boot_delay_timer, &srv->sec_access_auth_fail_timer};
    for (size_t i = 0; i < sizeof timers / sizeof timers[0]; i++) {
        if ((uint32_t)(now - *timers[i] - 1u) < 0x7FFFFFFFu) {
            *timers[i] = now - 1u;
        }
    }
}

bool udsota_busy(void)
{
    return U.started && (worker_busy() || U.dl_active);
}

/* See udsota.h. A poll either reads a request or sends its answer, never both, and iso14229 keeps requestInProgress
 * set until the answer is handed to ISO-TP, which has copied it. So once the flag is clear, between polls, no request
 * is half-served, and ending the session can't change an answer. */
bool udsota_end_session(UDSServer_t *srv)
{
    if (srv->requestInProgress) {
        return false;
    }
    if (srv->sessionType != UDS_LEV_DS_DS && srv->ecuResetScheduled == 0u) {
        if (U.started) {
            settle();
            end_session(srv);
        } else {
            srv->sessionType = UDS_LEV_DS_DS;
            srv->securityLevel = 0;
            srv->xferIsActive = false;
        }
    }
    return true;
}

void udsota_progress(udsota_progress_t *out)
{
    *out = progress_of();
}

bool udsota_unconfirmed(void)
{
    udsota_status_t st;
    status_now(&st);
    return st.running_slot != UDSOTA_SLOT_NONE && st.boot_slot == st.running_slot &&
           st.running_state == UDSOTA_IMG_PENDING_VERIFY;
}

#if defined(UDSOTA_TEST)
/* The host test's boot: udsota's state as it is at power-on. */
void udsota_test_reboot(void)
{
    zdl_close();
    memset(&U, 0, sizeof U);
}

/* The image rules on an image's first bytes, as a 34's first 36 meets them (tools/image_check). After udsota_init. */
udsota_reason_t udsota_test_check_first(const uint8_t *b, size_t len, uint32_t size)
{
    return check_first(b, len, size);
}

/* The image bytes a coded download holds in zbuf, and zbuf's size, which they never pass (the fuzzer checks). */
size_t udsota_test_held(size_t *cap)
{
    *cap = sizeof U.zbuf;
    return U.z.held;
}
#endif

/* ==== 7. The ESP-IDF platform ==== */
#if defined(ESP_PLATFORM)

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static udsota_status_t s_st = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE};
static const esp_partition_t *s_target;          /* the inactive slot; NULL refuses every download */
static esp_ota_handle_t s_handle;
static bool s_open, s_verified;
static TaskHandle_t s_worker;
static int (*s_job)(void);
static int s_result;
static bool s_busy = true;                       /* until the worker has read the slots */
static psa_key_id_t s_pub;
#if UDSOTA_DELTA
static const esp_partition_t *s_running;         /* a delta download's base */
static uint8_t s_base_hash[32];
static bool s_base_hash_ok;                      /* s_base_hash is read, and kept for the boot */
#endif

static uint8_t slot_of(const esp_partition_t *p)
{
    return (p == NULL || p->type != ESP_PARTITION_TYPE_APP)        ? UDSOTA_SLOT_NONE
         : (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0)          ? UDSOTA_SLOT_OTA0
         : (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1)          ? UDSOTA_SLOT_OTA1
                                                                    : UDSOTA_SLOT_NONE;
}

static uint8_t map_state(esp_ota_img_states_t s)
{
    switch (s) {
    case ESP_OTA_IMG_NEW:            return UDSOTA_IMG_NEW;
    case ESP_OTA_IMG_PENDING_VERIFY: return UDSOTA_IMG_PENDING_VERIFY;
    case ESP_OTA_IMG_VALID:          return UDSOTA_IMG_VALID;
    case ESP_OTA_IMG_INVALID:        return UDSOTA_IMG_INVALID;
    case ESP_OTA_IMG_ABORTED:        return UDSOTA_IMG_ABORTED;
    default:                         return UDSOTA_IMG_UNDEFINED;
    }
}

/* The other slot's state, with its version and SHA prefix read from its descriptor unless it is being written. */
static void set_other(uint8_t state)
{
    esp_app_desc_t d;
    uint8_t ver[3] = {0, 0, 0}, sha[8] = {0};
    bool clean;
    if (state != UDSOTA_OTHER_WRITING) {
        if (s_target == NULL || esp_ota_get_partition_description(s_target, &d) != ESP_OK) {
            state = UDSOTA_OTHER_EMPTY;
        } else {
            (void)parse_version(d.version, sizeof d.version, ver, &clean);
            memcpy(sha, d.app_elf_sha256, sizeof sha);
        }
    }
    taskENTER_CRITICAL(&s_mux);
    s_st.other_slot_state = (state == UDSOTA_OTHER_VERIFIED && !s_verified) ? UDSOTA_OTHER_UNVERIFIED : state;
    memcpy(s_st.other_version, ver, 3);
    memcpy(s_st.other_elf_sha_prefix, sha, 8);
    taskEXIT_CRITICAL(&s_mux);
}

/* The worker: reads the slots once, then runs one job at a time. Off the task watchdog: an erase busy-waits. */
static void worker(void *arg)
{
    (void)arg;
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    udsota_status_t s = {.running_slot = slot_of(run), .boot_slot = slot_of(esp_ota_get_boot_partition())};
    s.running_state = (esp_ota_get_state_partition(run, &st) == ESP_OK) ? map_state(st) : UDSOTA_IMG_UNDEFINED;
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    if (s.running_state == UDSOTA_IMG_PENDING_VERIFY) {
        s.running_state = UDSOTA_IMG_VALID;              /* without rollback nothing waits for a confirm */
    }
#endif
#if CONFIG_SECURE_SIGNED_ON_UPDATE
    s.flags = UDSOTA_STATUS_SIG_CHECKED;
#endif
    taskENTER_CRITICAL(&s_mux);
    s_st = s;
    taskEXIT_CRITICAL(&s_mux);
    const bool rolled_back = s_target != NULL && esp_ota_get_state_partition(s_target, &st) == ESP_OK &&
                             (st == ESP_OTA_IMG_INVALID || st == ESP_OTA_IMG_ABORTED);
    set_other(rolled_back ? UDSOTA_OTHER_INVALID : UDSOTA_OTHER_UNVERIFIED);
    for (;;) {
        taskENTER_CRITICAL(&s_mux);
        int (*job)(void) = s_job;
        s_job = NULL;
        s_busy = (job != NULL);
        taskEXIT_CRITICAL(&s_mux);
        if (job == NULL) {
            (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            continue;
        }
        const int r = job();
        taskENTER_CRITICAL(&s_mux);
        s_result = r;
        taskEXIT_CRITICAL(&s_mux);
    }
}

int udsota_plat_start(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
#if UDSOTA_DELTA
    s_running = run;
#endif
    s_target = esp_ota_get_next_update_partition(NULL);
    if (s_target == NULL || s_target == run) {
        s_target = NULL;
        LOGW("no inactive OTA slot: every download is refused");
    }
    if (xTaskCreatePinnedToCore(worker, "udsota", 8192, NULL, 2, &s_worker, tskNO_AFFINITY) != pdPASS) {
        LOGW("no memory for the flash worker: every download is refused");
        s_worker = NULL;
        s_busy = false;
        return -1;
    }
    return (s_target != NULL) ? 0 : -1;
}

int udsota_plat_run(int (*job)(void))
{
    taskENTER_CRITICAL(&s_mux);
    const bool ok = s_worker != NULL && !s_busy && s_job == NULL;
    if (ok) {
        s_job = job;
        s_busy = true;
    }
    taskEXIT_CRITICAL(&s_mux);
    if (ok) {
        xTaskNotifyGive(s_worker);
    }
    return ok ? UDSOTA_PENDING : -1;
}

int udsota_plat_poll(void)
{
    taskENTER_CRITICAL(&s_mux);
    const int r = s_busy ? UDSOTA_PENDING : s_result;
    taskEXIT_CRITICAL(&s_mux);
    return r;
}

void udsota_plat_abort(void)
{
    if (s_open) {
        (void)esp_ota_abort(s_handle);
        s_open = false;
        set_other(UDSOTA_OTHER_UNVERIFIED);
    }
}

bool udsota_plat_compatible(const uint8_t *first, size_t len)
{
    esp_image_header_t hdr;
    esp_app_desc_t app;
    if (len < sizeof hdr + sizeof(esp_image_segment_header_t) + sizeof app) {
        return false;
    }
    memcpy(&hdr, first, sizeof hdr);
    memcpy(&app, first + sizeof hdr + sizeof(esp_image_segment_header_t), sizeof app);
    return esp_ota_check_image_validity(ESP_PARTITION_TYPE_APP, &hdr, &app) == ESP_OK;   /* chip revision, flash mode */
}

/* Opens the slot with sequential writes, so each write erases only the sectors it writes and the erase is spread over
 * the download.
 * Refused while otadata already boots the slot (an activated image waiting for its reset). */
int udsota_plat_begin(uint32_t size)
{
    udsota_plat_abort();
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    const bool booting = s_st.boot_slot == slot_of(s_target);
    taskEXIT_CRITICAL(&s_mux);
    if (s_target == NULL || size > s_target->size || booting) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    set_other(UDSOTA_OTHER_WRITING);
    s_handle = 0;
    if (esp_ota_begin(s_target, OTA_WITH_SEQUENTIAL_WRITES, &s_handle) != ESP_OK) {
        (void)esp_ota_abort(s_handle);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return UDSOTA_DL_FLASH_ERROR;
    }
    s_open = true;
    return UDSOTA_DL_OK;
}

int udsota_plat_write(const uint8_t *d, size_t n)
{
    if (!s_open || esp_ota_write(s_handle, d, n) != ESP_OK) {
        udsota_plat_abort();
        return UDSOTA_DL_FLASH_ERROR;
    }
    return UDSOTA_DL_OK;
}

/* The first bytes of the slot, read back after the verify, pass the image rules again. */
static int recheck(void)
{
    uint8_t first[IMAGE_MIN];
    if (esp_partition_read(s_target, 0, first, sizeof first) != ESP_OK) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    return check_first(first, sizeof first, IMAGE_MIN);
}

/* FF01: esp_ota_end checks the SHA-256, and the signature with CONFIG_SECURE_SIGNED_ON_UPDATE. */
int udsota_plat_end(void)
{
    if (!s_open) {
        return s_verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    s_open = false;                                      /* esp_ota_end frees the handle either way */
    int r = (esp_ota_end(s_handle) == ESP_OK) ? recheck() : UDSOTA_DL_VERIFY_FAILED;
    taskENTER_CRITICAL(&s_mux);
    s_verified = (r == UDSOTA_DL_OK);
    taskEXIT_CRITICAL(&s_mux);
    set_other(r == UDSOTA_DL_OK ? UDSOTA_OTHER_VERIFIED : UDSOTA_OTHER_UNVERIFIED);
    return r;
}

/* F001: esp_ota_set_boot_partition checks the image again before it writes otadata. */
int udsota_plat_activate(void)
{
    int r = s_verified ? recheck() : UDSOTA_DL_VERIFY_FAILED;
    if (r == UDSOTA_DL_OK && esp_ota_set_boot_partition(s_target) != ESP_OK) {
        r = UDSOTA_DL_VERIFY_FAILED;
    }
    taskENTER_CRITICAL(&s_mux);
    if (r == UDSOTA_DL_OK) {
        s_st.boot_slot = slot_of(s_target);
    } else {
        s_verified = false;
    }
    taskEXIT_CRITICAL(&s_mux);
    if (r != UDSOTA_DL_OK) {
        set_other(UDSOTA_OTHER_UNVERIFIED);
    }
    return r;
}

/* F002: marks the running image valid; the updater checked it is the pending boot image. */
int udsota_plat_confirm(void)
{
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) {
        return UDSOTA_DL_ABORTED;
    }
#endif
    taskENTER_CRITICAL(&s_mux);
    s_st.running_state = UDSOTA_IMG_VALID;
    taskEXIT_CRITICAL(&s_mux);
    return UDSOTA_DL_OK;
}

void udsota_plat_unverify(void)
{
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    if (s_st.other_slot_state == UDSOTA_OTHER_VERIFIED) {
        s_st.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
    }
    taskEXIT_CRITICAL(&s_mux);
}

void udsota_plat_status(udsota_status_t *out)
{
    taskENTER_CRITICAL(&s_mux);
    *out = s_st;
    taskEXIT_CRITICAL(&s_mux);
}

#if UDSOTA_DELTA
/* The worker, a delta download's base: n bytes of the running slot at off, bounded by the slot and not the image, so a
 * signature block past the image reads too. esp_partition_read is esp_flash_read, or under flash encryption a map made
 * and dropped for each read. Never hold a map of the slot: with XIP from PSRAM a held map turns the cache off for every
 * erase and write. */
bool udsota_plat_base_read(uint32_t off, void *buf, size_t n)
{
    return s_running != NULL && (uint64_t)off + n <= s_running->size &&
           esp_partition_read(s_running, off, buf, n) == ESP_OK;
}

/* The worker, the base's identity: the SHA-256 the running image appends, as esp_image_get_metadata reads it, which
 * hashes nothing and takes no PSA lock. The first call reads it and later ones reuse it, as the running image never
 * changes. A base that no longer matches its stored hash only rebuilds an image FF01 refuses. */
bool udsota_plat_base_hash(uint8_t out[32])
{
    if (!s_base_hash_ok && s_running != NULL) {
        const esp_partition_pos_t pos = {.offset = s_running->address, .size = s_running->size};
        esp_image_metadata_t md;
        const esp_err_t err = esp_image_get_metadata(&pos, &md);
        s_base_hash_ok = (err == ESP_OK && md.image.hash_appended == 1u);
        if (s_base_hash_ok) {
            memcpy(s_base_hash, md.image_digest, sizeof s_base_hash);
        } else if (err != ESP_OK) {
            LOGW("can't read the running image to match a delta's base against: %s", esp_err_to_name(err));
        } else {
            LOGW("the running image has no appended SHA-256 to match a delta's base against");
        }
    }
    if (s_base_hash_ok) {
        memcpy(out, s_base_hash, sizeof s_base_hash);
    }
    return s_base_hash_ok;
}
#endif

uint32_t udsota_plat_slot_size(void) { return (s_target != NULL) ? s_target->size : 0u; }
const char *udsota_plat_version(void) { return esp_app_get_description()->version; }
const char *udsota_plat_project(void) { return esp_app_get_description()->project_name; }
const uint8_t *udsota_plat_sha(void) { return esp_app_get_description()->app_elf_sha256; }

size_t udsota_plat_mac(uint8_t out[16])
{
    return (esp_read_mac(out, ESP_MAC_BASE) == ESP_OK) ? 6u : 0u;
}

/* A true random seed: the SAR ADC entropy source is on only while it is drawn, so the app keeps the ADC and radio. */
bool udsota_plat_rng16(uint8_t out[16])
{
    bootloader_random_enable();
    esp_fill_random(out, 16);
    bootloader_random_disable();
    return true;
}

bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    size_t n = 0;
    bool ok = psa_import_key(&attr, key, key_len, &id) == PSA_SUCCESS &&
              psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len, out, 32, &n) == PSA_SUCCESS &&
              n == 32u;
    ok = (psa_destroy_key(id) == PSA_SUCCESS) && ok;
    if (!ok) {
        wipe(out, 32);
    }
    return ok;
}

int udsota_plat_ecdsa_key(const uint8_t *pubkey)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    return (psa_import_key(&attr, pubkey, UDSOTA_KEYS_PUBKEY_LEN, &s_pub) == PSA_SUCCESS) ? 0 : -1;
}

int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    uint8_t hash[32];
    size_t hn = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, msg, n, hash, sizeof hash, &hn) != PSA_SUCCESS) {
        return -1;
    }
    const psa_status_t st =
        psa_verify_hash(s_pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hn, sig, UDSOTA_KEYS_SIG_LEN);
    return (st == PSA_SUCCESS) ? 1 : (st == PSA_ERROR_INSUFFICIENT_MEMORY || st == PSA_ERROR_HARDWARE_FAILURE) ? -1 : 0;
}

#endif
