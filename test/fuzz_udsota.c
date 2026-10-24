/* fuzz_udsota: the bus input before every udsota path, fuzzed. CAN frames go through iso14229's isotp-c into
 * UDSServerPoll, with udsota_event first in the app's fn and udsota_poll after every poll, as an app's server task runs
 * them, over a platform of this file's own: two RAM slots that boot as ESP-IDF's bootloader does with rollback on,
 * jobs that finish some milliseconds after they are queued (so iso14229 answers 0x78 first), and stand-ins for the
 * keys. A tester of this file's own segments each request, answers the server's First Frames and reassembles its
 * answers, all on a clock the harness sets, so a run is the same every time.
 *
 * An input is a program of ops (op_t): a request (waited for, or not), the key for the last seed, a raw frame of any
 * PCI and DLC, a wait the server polls through, a clock jump it sleeps through, the tester's and the platform's
 * behaviour (the MODE_ bits), a gate refusal, a power cycle into a udsota_cfg_t (the BOOT_ bits), and the app ending
 * the session. Every program starts from a fresh boot. The built-in seeds update over DFI 00, 10 and 30 (a delta from
 * the running slot), are refused at a first block, at a delta's base and on bad streams, and walk the routines, the
 * DIDs, 0x27, the sessions, the worker's failures and ISO-TP's edges. Each run replays them, then deterministic
 * mutants of them (bytes flipped and set, ops inserted, deleted, repeated and spliced from other seeds; most bytes are
 * 36 payloads, so most edits mutate an image, a DEFLATE stream or a delta stored in one), random programs, and deltas
 * whose patch is mutated before it is deflated (bits flipped, bytes set, inserted and deleted, the patch cut short or
 * run on, its header edited), each sent in 36s of random lengths.
 *
 * Checked throughout, beside ASan and UBSan: every frame the server sends is on the response ID with a valid PCI, an
 * SF of 1-7 bytes, CFs in sequence and only as the tester's FCs allow, and never sooner than their STmin; every final
 * answer is 7F, an SID the tester sent and an NRC, or that SID's positive answer, whose shape is checked against the
 * request whenever it can only be that request's (udsota's DIDs at their lengths, 74 20 0F FF, the routines' status);
 * udsota holds the PSA lock for every PSA call and never between polls; nothing is written to flash before the
 * image's first bytes pass udsota's rules, nor past the announced size; nothing is activated that did not verify;
 * udsota_busy is true whenever the worker has a job; udsota_unconfirmed matches the slots; progress never reports
 * done past total; a coded download never holds more image bytes than its buffer; every base read udsota asks for
 * lies within int's range; a delta writes nothing unless the running image is its base and that base's hash reads;
 * and no 37 passes in a download whose base read was refused. The seeds alone must also reach a verified update over
 * DFI 00, 10 and 30, an activation and a confirm, a refused first block, a delta refused at its base, a bad stream and
 * the worker's failures.
 *
 *     fuzz_udsota [--mutations N] [--seed S] [-v] [--write-seeds DIR] [FILE|DIR ...]
 *
 * With FILEs it replays those programs (a libFuzzer corpus, say) instead. --mutations makes N mutants of each seed
 * (600) and 5N of the delta's patch, --seed starts the mutation PRNG elsewhere, -v traces every frame, and
 * --write-seeds writes the seed programs to DIR, as a corpus to start libFuzzer from.
 * A failing program is written to fuzz_udsota-fail.bin in the current directory; replay it with -v. Built with
 * UDSOTA_FUZZ_LIBFUZZER (CMakeLists.txt; clang only) the file is a libFuzzer target over the same programs, with
 * mutate() as half its mutator. Built without UDSOTA_DELTA=1 (fuzz_udsota_nodelta), every DFI 30 34 is refused and
 * the seeds need not reach DFI 30 or BAD_BASE. */
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sanitizer/common_interface_defs.h>
#include "iso14229.h"
#include "miniz.h"
#include "udsota.h"

#define REQ_ID     0x7E0u
#define RESP_ID    0x7E8u
#define HW_ID      1u
#define LAYOUT_ID  1u
#define SLOT       (32u * 1024u)
#define IMG_LEN    6000u             /* two 36s of plain image: 4093 and 1907 bytes */
#define APP_DESC   32u               /* esp_app_desc_t: version at +16, project at +48, app_elf_sha256 at +144 */
#define PROJECT    "udsota-fuzz"
#define T0_US      UINT64_C(10000000)
#define BOOT_MS    300u              /* silence after a power cycle */
#define POLL_CAP   400000u           /* polls per program: a program past it ends there */
#define PROG_MAX   65536u
#define MUTATIONS_DEFAULT 600u
#define RANDOM_PROGRAMS   2000u
#define DELTA_PER_MUTANT  5u      /* mutants of the delta's patch, for each mutant of a seed */
#define PATCH_CAP         8192u   /* a delta's uncompressed patch (g_dp: 6,100 bytes), mutated */

UDSOTA_IMAGE_DESC(HW_ID, LAYOUT_ID, REQ_ID, RESP_ID);
void udsota_test_reboot(void);
int  udsota_test_psa_depth(void);
udsota_reason_t udsota_test_check_first(const uint8_t *b, size_t len, uint32_t size);
size_t udsota_test_held(size_t *cap);

/* ---- The program ---- */

typedef enum {
    OP_REQ,      /* len (12 bits, big-endian), the request: sent and its final answer waited for (OP_NOWAIT: not) */
    OP_KEY,      /* level: 27 level+1 with the key for the last seed */
    OP_RAW,      /* dlc, 8 bytes: one frame on the request ID */
    OP_WAIT,     /* ms (little-endian u16): the server polls through it */
    OP_JUMP,     /* ms (little-endian u32): the clock moves without a poll, as when the device sleeps */
    OP_MODE,     /* the MODE_ bits */
    OP_GATE,     /* op, NRC: the gate's answer to that udsota_op_t from now on */
    OP_BOOT,     /* the BOOT_ bits: a power cycle into that udsota_cfg_t */
    OP_END,      /* the app calls udsota_end_session */
    OP_COUNT
} op_t;
#define OP_NOWAIT 0x80u

enum {           /* OP_MODE */
    MODE_JOB_MASK   = 0x03u,   /* a job's result after: 20 ms, at once, 300 ms, never */
    MODE_FC_MASK    = 0x0Cu,   /* the tester's FC to the server's FFs: CTS BS 0, CTS BS 1 STmin 2 ms, none, overflow */
    MODE_FLASH_FAIL = 0x10u,   /* flash writes fail */
    MODE_RNG_FAIL   = 0x20u,   /* the RNG fails */
    MODE_RUN_FAIL   = 0x40u,   /* the worker refuses jobs */
    MODE_SLOW_CF    = 0x80u,   /* the tester sends its CFs 1 ms apart */
};

enum {           /* OP_BOOT */
    BOOT_KEYS_MASK  = 0x03u,   /* HMAC keys, ECDSA, none (security off), HMAC with an unusable label */
    BOOT_DOWNGRADE  = 0x04u,   /* cfg.allow_downgrade */
    BOOT_PRODUCT    = 0x08u,   /* cfg.product names another project */
    BOOT_DEVICE_ID  = 0x10u,   /* cfg.device_id: 16 bytes, not the MAC */
    BOOT_NO_DELTA   = 0x20u,   /* cfg.allow_delta off */
    BOOT_NO_HASH    = 0x40u,   /* the running image's hash can't be read */
};

/* ---- Results ---- */

static struct {
    unsigned long programs, ops, polls, frames_in, frames_out, answers, pendings, unanswered, reboots;
    unsigned long pos[256], neg[256];          /* final answers by request SID */
    unsigned long verified[3], activated, confirmed;   /* verified: [0] DFI 00, [1] DFI 10, [2] DFI 30 */
    unsigned long reasons[16];                 /* each udsota_reason_t cfg.progress reported */
    unsigned long wrong_base;                  /* of reasons[BAD_BASE], those with the running image's hash readable */
} G;

static const uint8_t *g_prog;                  /* the program running, for a failure report */
static size_t         g_prog_len;
static const char    *g_what = "";
static bool           g_verbose;

#if !defined(UDSOTA_FUZZ_LIBFUZZER)
static void save_program(void)
{
    FILE *f = fopen("fuzz_udsota-fail.bin", "wb");
    if (f != NULL) {
        (void)fwrite(g_prog, 1, g_prog_len, f);
        fclose(f);
    }
}
#endif

/* A broken invariant: the program goes to fuzz_udsota-fail.bin (libFuzzer saves its own), and the run aborts. */
static void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fuzz_udsota: FAIL in %s program %lu: ", g_what, G.programs);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
#if !defined(UDSOTA_FUZZ_LIBFUZZER)
    save_program();
    fprintf(stderr, "fuzz_udsota: the program is in fuzz_udsota-fail.bin; fuzz_udsota -v fuzz_udsota-fail.bin "
                    "replays it\n");
#endif
    abort();
}

#define REQUIRE(cond, ...)                                                                               \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            fail(__VA_ARGS__);                                                                           \
        }                                                                                                \
    } while (0)

/* ---- The clock ---- */

static uint64_t g_us;

uint32_t UDSMillis(void)
{
    return (uint32_t)(g_us / 1000u);
}

uint32_t isotp_user_get_us(void)
{
    return (uint32_t)g_us;
}

void isotp_user_debug(const char *message, ...)
{
    if (g_verbose) {
        va_list ap;
        va_start(ap, message);
        fputs("  isotp-c: ", stderr);
        vfprintf(stderr, message, ap);
        fputc('\n', stderr);
        va_end(ap);
    }
}

/* ---- The images ---- */

static uint8_t  g_base[IMG_LEN];               /* slot 0's at power-on: 1.0.0, a release */
static uint8_t  g_img[IMG_LEN];                /* the update: 1.0.1, a release */
static uint8_t *g_z;                           /* g_img as raw DEFLATE */
static size_t   g_zlen;
static uint8_t  g_dp[PATCH_CAP];               /* the delta that rebuilds g_img from slot 0 at power-on, uncompressed */
static size_t   g_dplen;
static uint8_t *g_dz;                          /* g_dp as raw DEFLATE: a DFI 30 download */
static size_t   g_dzlen;
static uint8_t  g_ds[PATCH_CAP + 5u];          /* g_dp in one stored DEFLATE block, so edits to it edit the patch */
static size_t   g_dslen;

/* An ESP-IDF image header, app descriptor and udsota descriptor, as udsota's image rules read them, then filler that
 * DEFLATE halves (4 bits a byte). */
static void stamp(uint8_t *img, const char *version, uint8_t hw, uint8_t flags, uint32_t fill)
{
    const uint8_t desc[13] = {0x4F, 0x53, 0x44, 0x55, 1, 0, hw, LAYOUT_ID, (uint8_t)REQ_ID, (uint8_t)(REQ_ID >> 8),
                              (uint8_t)RESP_ID, (uint8_t)(RESP_ID >> 8), flags};
    memset(img, 0, IMG_LEN);
    img[0] = 0xE9;                                 /* magic */
    img[1] = 1;                                    /* segments */
    img[2] = 2;                                    /* SPI mode */
    img[12] = 9;                                   /* ESP32-S3, as a host build's CHIP_ID */
    img[28] = (uint8_t)(IMG_LEN - 32u);            /* segment 0's length */
    img[29] = (uint8_t)((IMG_LEN - 32u) >> 8);
    img[32] = 0x32, img[33] = 0x54, img[34] = 0xCD, img[35] = 0xAB;   /* esp_app_desc_t magic */
    memcpy(&img[APP_DESC + 16u], version, strlen(version));
    memcpy(&img[APP_DESC + 48u], PROJECT, sizeof PROJECT - 1u);
    for (unsigned i = 0; i < 32u; i++) {
        img[APP_DESC + 144u + i] = (uint8_t)((fill >> (i % 4u * 8u)) ^ i);   /* app_elf_sha256 */
    }
    memcpy(&img[UDSOTA_IMG_DESC_OFFSET], desc, sizeof desc);
    for (size_t i = 320; i < IMG_LEN; i++) {
        fill = fill * 1103515245u + 12345u;
        img[i] = (uint8_t)(0x40u | ((fill >> 24) & 0x0Fu));
    }
}

/* ---- The platform ---- */

static UDSServer_t s_srv;              /* the app's server, here so that the platform can read the 34 it is taking */

static struct {
    uint8_t  slot[2][SLOT];
    bool     aborted[2];               /* the bootloader rolled this slot's image back */
    uint8_t  running, boot, state;     /* the running and boot slots, and the running image's UDSOTA_IMG_* */
    bool     open, verified;           /* the other slot is being written; it passed FF01 */
    uint32_t size, pos;                /* the open image's announced size, and the bytes written to it */
    bool     first_written;
    uint8_t  dfi;                      /* the download's: 0 DFI 00, 1 DFI 10, 2 DFI 30 (G.verified's index) */
    bool     base_refused;             /* a base read was refused in this download */
    bool     no_hash;                  /* the running image's hash can't be read (BOOT_NO_HASH) */
    int    (*job)(void);
    uint64_t job_at_us;
    int      result;
    uint8_t  mode, seed_ctr;
    char     version[33], project[33];
} P;

static void psa_call(const char *what)
{
    REQUIRE(udsota_test_psa_depth() == 1, "%s ran without the PSA lock (depth %d)", what, udsota_test_psa_depth());
}

static unsigned other(void)
{
    return 1u - P.running;
}

/* A coded download's image bytes in udsota's buffer: never more than it holds. */
static void held_ok(const char *where)
{
    size_t cap;
    const size_t held = udsota_test_held(&cap);
    REQUIRE(held <= cap, "udsota holds %zu image bytes in a %zu-byte buffer, at %s", held, cap, where);
}

/* One of the running image's esp_app_desc_t strings (32 bytes at off), NUL-terminated. */
static void desc_str(size_t off, char out[33])
{
    memcpy(out, &P.slot[P.running][APP_DESC + off], 32);
    out[32] = '\0';
}

/* A power cycle: an activated slot boots pending verify, and one still pending verify rolls back. The worker's job
 * dies with it. */
static void plat_boot(void)
{
    P.open = P.verified = false;
    P.job = NULL;
    P.result = UDSOTA_DL_OK;
    if (P.boot != P.running) {
        P.running = P.boot;
        P.state = UDSOTA_IMG_PENDING_VERIFY;
    } else if (P.state == UDSOTA_IMG_PENDING_VERIFY) {
        P.aborted[P.running] = true;
        P.running = P.boot = (uint8_t)other();
        P.state = UDSOTA_IMG_VALID;
    }
    desc_str(16u, P.version);
    desc_str(48u, P.project);
}

int udsota_plat_start(void) { return 0; }

int udsota_plat_run(int (*job)(void))
{
    static const uint32_t delay_ms[] = {20u, 0u, 300u, 0u};
    if ((P.mode & MODE_RUN_FAIL) != 0u || P.job != NULL) {
        return -1;
    }
    P.job = job;
    P.job_at_us = g_us + delay_ms[P.mode & MODE_JOB_MASK] * 1000u;
    return UDSOTA_PENDING;
}

/* The job runs when its time comes (never, in MODE_JOB_MASK's last setting), as the worker finishing it. */
int udsota_plat_poll(void)
{
    if (P.job != NULL && (P.mode & MODE_JOB_MASK) != 3u && g_us >= P.job_at_us) {
        int (*job)(void) = P.job;
        P.job = NULL;
        P.result = job();
        held_ok("a job's end");
    }
    return (P.job != NULL) ? UDSOTA_PENDING : P.result;
}

void udsota_plat_abort(void)
{
    P.open = false;
}

bool udsota_plat_compatible(const uint8_t *first, size_t len)
{
    (void)first;
    (void)len;
    return true;
}

int udsota_plat_begin(uint32_t size)
{
    REQUIRE(P.dfi != 2u || (memcmp(P.slot[P.running], g_base, IMG_LEN) == 0 && !P.no_hash),
            "a delta began writing with a running image other than g_base, every patch's base, or its hash unreadable");
    udsota_plat_abort();
    P.verified = false;
    if (size > SLOT || P.boot != P.running) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    memset(P.slot[other()], 0xFF, SLOT);
    P.aborted[other()] = false;
    P.size = size;
    P.pos = 0u;
    P.first_written = false;
    P.open = true;
    return UDSOTA_DL_OK;
}

int udsota_plat_write(const uint8_t *d, size_t n)
{
    held_ok("a write");
    if ((P.mode & MODE_FLASH_FAIL) != 0u || !P.open) {
        udsota_plat_abort();
        return UDSOTA_DL_FLASH_ERROR;
    }
    REQUIRE(n <= P.size - P.pos, "wrote %zu bytes at %" PRIu32 " of a %" PRIu32 "-byte image", n, P.pos, P.size);
    if (!P.first_written) {
        REQUIRE(n >= 320u && udsota_test_check_first(d, n, P.size) == UDSOTA_DL_OK,
                "flashed %zu first bytes that fail the image rules", n);
        P.first_written = true;
    }
    memcpy(&P.slot[other()][P.pos], d, n);
    P.pos += (uint32_t)n;
    return UDSOTA_DL_OK;
}

/* FF01: the image verifies when it is g_img, every byte (a device checks its hash and signature). */
int udsota_plat_end(void)
{
    psa_call("udsota_plat_end");
    if (!P.open) {
        return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    P.open = false;
    P.verified = P.pos == IMG_LEN && memcmp(P.slot[other()], g_img, IMG_LEN) == 0;
    if (P.verified) {
        G.verified[P.dfi]++;
    }
    return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}

int udsota_plat_activate(void)
{
    psa_call("udsota_plat_activate");
    REQUIRE(P.verified, "activated an image that did not verify");
    P.boot = (uint8_t)other();
    G.activated++;
    return UDSOTA_DL_OK;
}

int udsota_plat_confirm(void)
{
    if (P.state == UDSOTA_IMG_PENDING_VERIFY) {
        G.confirmed++;
    }
    P.state = UDSOTA_IMG_VALID;
    return UDSOTA_DL_OK;
}

/* A 34 udsota took (its only call): a download of the 34's DFI starts, whether the tester sent it whole or as raw
 * frames. */
void udsota_plat_unverify(void)
{
    const uint8_t *r = s_srv.r.recv_buf;
    REQUIRE(s_srv.r.recv_len >= 2u && r[0] == 0x34u, "udsota_plat_unverify outside a 34");
    P.verified = false;
    P.dfi = r[1] == UDSOTA_DL_DFI_DEFLATE ? 1u : r[1] == UDSOTA_DL_DFI_DELTA_DEFLATE ? 2u : 0u;
    P.base_refused = false;
}

void udsota_plat_status(udsota_status_t *out)
{
    const unsigned o = other();
    memset(out, 0, sizeof *out);
    out->running_slot = P.running;
    out->running_state = P.state;
    out->boot_slot = P.boot;
    out->other_slot_state = P.open                                  ? UDSOTA_OTHER_WRITING
                          : P.slot[o][0] != 0xE9u                   ? UDSOTA_OTHER_EMPTY
                          : P.aborted[o]                            ? UDSOTA_OTHER_INVALID
                          : P.verified                              ? UDSOTA_OTHER_VERIFIED
                                                                    : UDSOTA_OTHER_UNVERIFIED;
    memcpy(out->other_elf_sha_prefix, &P.slot[o][APP_DESC + 144u], 8);
}

uint32_t udsota_plat_slot_size(void) { return SLOT; }
const char *udsota_plat_version(void) { return P.version; }
const char *udsota_plat_project(void) { return P.project; }
const uint8_t *udsota_plat_sha(void) { return &P.slot[P.running][APP_DESC + 144u]; }

static const uint8_t k_mac[6] = {0x02, 0, 0, 0, 0, 0x01};
static const uint8_t k_devid[16] = {'f', 'u', 'z', 'z', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

size_t udsota_plat_mac(uint8_t out[16])
{
    memcpy(out, k_mac, sizeof k_mac);
    return sizeof k_mac;
}

bool udsota_plat_rng16(uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0xA0u + P.seed_ctr + i);
    }
    P.seed_ctr++;
    return (P.mode & MODE_RNG_FAIL) == 0u;
}

/* A stand-in for HMAC-SHA256: udsota only needs the same function on both sides. */
static void stand_in_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < key_len; i++) {
        h = (h ^ key[i]) * 16777619u;
    }
    for (size_t i = 0; i < msg_len; i++) {
        h = (h ^ msg[i]) * 16777619u;
    }
    for (int i = 0; i < 32; i++) {
        h = (h ^ (uint8_t)i) * 16777619u;
        out[i] = (uint8_t)(h >> 24);
    }
}

bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    psa_call("udsota_plat_hmac");
    stand_in_hmac(key, key_len, msg, msg_len, out);
    return true;
}

/* A stand-in for ECDSA: any key imports, and a signature that starts 5A is valid. */
int udsota_plat_ecdsa_key(const uint8_t *pubkey)
{
    (void)pubkey;
    psa_call("udsota_plat_ecdsa_key");
    return 0;
}

int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    (void)msg;
    (void)n;
    psa_call("udsota_plat_ecdsa");
    return (sig[0] == 0x5Au) ? 1 : 0;
}

/* A stand-in for the SHA-256 an image appends: the same function over its IMG_LEN bytes on both sides. */
static void image_hash(const uint8_t *img, uint8_t out[32])
{
    stand_in_hmac(NULL, 0, img, IMG_LEN, out);
}

#if UDSOTA_DELTA
/* A delta's base: the running slot, refused past its end as esp_partition_read refuses. udsota refuses an offset
 * outside int's range itself, so none reaches the platform (a negative one would come cast, past 2^31). */
bool udsota_plat_base_read(uint32_t off, void *buf, size_t n)
{
    held_ok("a base read");
    REQUIRE((uint64_t)off + n <= (uint64_t)INT_MAX, "a base read of %zu bytes at %" PRIu32 ", outside int's range", n,
            off);
    if ((uint64_t)off + n > SLOT) {
        P.base_refused = true;
        return false;
    }
    memcpy(buf, &P.slot[P.running][off], n);
    return true;
}

bool udsota_plat_base_hash(uint8_t out[32])
{
    held_ok("the base's hash");
    image_hash(P.slot[P.running], out);
    return !P.no_hash;
}
#endif

/* ---- The app ---- */

static const char    k_label[] = "udsota-fuzz";
static const char    k_long_label[] = "a label longer than udsota's 32 bytes";
static const uint8_t k_master[32] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t k_pub[UDSOTA_KEYS_PUBKEY_LEN] = {0x04};

static UDSTpISOTpC_t s_tp;
static uint8_t       s_boot_flags, s_gate[8];
static bool          s_reset;

static UDSErr_t app_fn(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent: {
        UDSRDBIArgs_t *a = arg;
        return (a->dataId == 0xF191u) ? (UDSErr_t)a->copy(srv, "fuzz", 4u) : UDS_NRC_RequestOutOfRange;
    }
    case UDS_EVT_DiagSessCtrl:
        return UDS_NRC_SubFunctionNotSupported;
    case UDS_EVT_SecAccessRequestSeed:
    case UDS_EVT_SecAccessValidateKey:
        return UDS_NRC_RequestOutOfRange;
    case UDS_EVT_SessionTimeout:
    case UDS_EVT_DoScheduledReset:
    case UDS_EVT_Err:
        return UDS_OK;
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

static uint8_t gate(void *ctx, udsota_op_t op)
{
    (void)ctx;
    return s_gate[(unsigned)op & 7u];
}

static void progress(void *ctx, const udsota_progress_t *p)
{
    (void)ctx;
    REQUIRE(p->done <= p->total && p->stage <= UDSOTA_STAGE_ACTIVATING && p->last_reason <= UDSOTA_DL_BAD_BASE,
            "progress stage %d, %" PRIu32 " of %" PRIu32 ", reason %u", (int)p->stage, p->done, p->total,
            p->last_reason);
    G.reasons[p->last_reason & 15u]++;
    G.wrong_base += p->last_reason == UDSOTA_DL_BAD_BASE && !P.no_hash;
}

static void do_reset(void *ctx)
{
    (void)ctx;
    s_reset = true;
}

/* A boot: the slots, then udsota and iso14229 from scratch, as app_main starts them. */
static void boot(void)
{
    plat_boot();
    P.no_hash = (s_boot_flags & BOOT_NO_HASH) != 0u;
    udsota_test_reboot();
    udsota_cfg_t cfg = {.key_label = k_label, .key_master = k_master, .key_master_len = sizeof k_master,
                        .gate = gate, .progress = progress, .reset = do_reset,
                        .allow_downgrade = (s_boot_flags & BOOT_DOWNGRADE) != 0u,
                        .allow_delta = (s_boot_flags & BOOT_NO_DELTA) == 0u,
                        .product = (s_boot_flags & BOOT_PRODUCT) != 0u ? "another-project" : NULL};
    switch (s_boot_flags & BOOT_KEYS_MASK) {
    case 1:
        cfg.key_pubkey = k_pub;
        cfg.key_pubkey_len = sizeof k_pub;
        break;
    case 2:
        cfg.key_label = NULL;
        cfg.key_master = NULL;
        cfg.key_master_len = 0;
        break;
    case 3:
        cfg.key_label = k_long_label;
        break;
    default:
        break;
    }
    if ((s_boot_flags & BOOT_DEVICE_ID) != 0u) {
        cfg.device_id = k_devid;
        cfg.device_id_len = sizeof k_devid;
    }
    REQUIRE(udsota_init(&cfg) == 0, "udsota_init failed");
    REQUIRE(udsota_test_psa_depth() == 0, "udsota_init left the PSA lock held");
    REQUIRE(UDSServerInit(&s_srv) == UDS_OK, "UDSServerInit failed");
    REQUIRE(UDSServerTpISOTpCInit(&s_tp, REQ_ID, RESP_ID, UDS_TP_NOOP_ADDR) == UDS_OK, "the transport failed");
    s_srv.tp = &s_tp.hdl;
    s_srv.fn = app_fn;
    s_srv.p2_ms = 5;                                  /* as the examples set it */
    s_reset = false;
}

/* ---- The tester ---- */

typedef struct {
    uint32_t id;
    uint8_t  dlc, d[8];
} frame_t;

static struct {
    /* the server's frames since the last drain */
    frame_t  q[64];
    unsigned q_n;
    /* sending a request */
    uint8_t  msg[4095];
    size_t   len, off;
    uint8_t  sn, bs, bs_left;
    bool     sending, wait_fc;
    uint32_t stmin_us;
    uint64_t next_cf_us, fc_deadline_us;
    /* receiving an answer */
    uint8_t  rx[4095];
    size_t   rx_len, rx_off;
    uint8_t  rx_sn, cts_left;
    bool     rx_active, rx_bs;
    uint32_t rx_stmin_us;
    uint64_t last_cf_us;
    /* the answers */
    bool     answered, pending;          /* a final answer since the request; the last answer was a 0x78 */
    uint64_t last_rx_us;
    unsigned outstanding;                /* requests sent and not answered: above 1, an answer may be an old one's */
    uint8_t  sent[32];                   /* every SID sent, a bit each */
    uint8_t  req[8];                     /* the waited-for request's first bytes */
    size_t   req_len;
    uint8_t  seed[16];
} T;

static void trace(const char *dir, uint32_t id, const uint8_t *d, uint8_t dlc)
{
    if (!g_verbose) {
        return;
    }
    fprintf(stderr, "%10.3f %s %03X#", (double)g_us / 1000.0, dir, (unsigned)id);
    for (uint8_t i = 0; i < dlc; i++) {
        fprintf(stderr, "%02X", d[i]);
    }
    fputc('\n', stderr);
}

/* The server's frames, queued until the tester takes them: isotp-c sends from inside isotp_on_can_message too. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    (void)arg;
    trace("tx", arbitration_id, data, size);
    REQUIRE(arbitration_id == RESP_ID && size >= 1u && size <= 8u, "the server sent %03X with DLC %u",
            (unsigned)arbitration_id, size);
    REQUIRE(T.q_n < sizeof T.q / sizeof T.q[0], "the server sent more than %zu frames at once",
            sizeof T.q / sizeof T.q[0]);
    frame_t *f = &T.q[T.q_n++];
    f->id = arbitration_id;
    f->dlc = size;
    memcpy(f->d, data, size);
    G.frames_out++;
    return ISOTP_RET_OK;
}

/* One frame to the server, from a buffer of exactly its DLC, so ASan sees isotp-c read past it. */
static void feed(const uint8_t *d, uint8_t dlc)
{
    trace("rx", REQ_ID, d, dlc);
    uint8_t *b = malloc(dlc);
    REQUIRE(b != NULL, "out of memory");
    memcpy(b, d, dlc);
    isotp_on_can_message(&s_tp.phys_link, b, dlc);
    free(b);
    G.frames_in++;
}

static void note_sent(uint8_t sid)
{
    T.sent[sid >> 3] |= (uint8_t)(1u << (sid & 7u));
}

static bool was_sent(uint8_t sid)
{
    return (T.sent[sid >> 3] & (1u << (sid & 7u))) != 0u;
}

/* The tester's FC to the server's FF, as OP_MODE set it. */
static void send_fc(void)
{
    static const uint8_t fcs[4][3] = {{0x30, 0, 0}, {0x30, 1, 2}, {0}, {0x32, 0, 0}};
    const unsigned m = (P.mode & MODE_FC_MASK) >> 2;
    if (m == 2u) {
        return;
    }
    feed(fcs[m], 3);
    T.rx_active = (m != 3u);
    T.rx_bs = fcs[m][1] != 0u;
    T.cts_left = fcs[m][1];
    T.rx_stmin_us = fcs[m][2] * 1000u;
}

/* Checks a final answer: its SID was sent, and when it can only be the waited-for request's, its shape. */
static void check_answer(const uint8_t *a, size_t n)
{
    const bool neg = a[0] == 0x7Fu;
    const uint8_t sid = neg ? (n >= 2u ? a[1] : 0u) : (uint8_t)(a[0] - 0x40u);
    REQUIRE(!neg || (n == 3u && a[2] != 0u && a[2] != 0x78u), "a malformed negative answer of %zu bytes", n);
    REQUIRE(was_sent(sid) && (neg || a[0] >= 0x40u), "an answer %02X to SID %02X, which the tester never sent",
            a[0], sid);
    G.answers++;
    const bool waited = T.req_len != 0u && sid == T.req[0];
    const bool mine = waited && T.outstanding == 1u;
    T.outstanding = T.outstanding != 0u ? T.outstanding - 1u : 0u;
    T.answered = T.answered || waited;
    if (!neg && sid == 0x27u && n == 2u + UDSOTA_SEED_LEN && (a[1] & 1u) != 0u) {
        memcpy(T.seed, &a[2], sizeof T.seed);        /* the server's latest seed, whichever request it answered */
    }
    if (!mine) {
        return;
    }
    const uint8_t *r = T.req;
    const size_t rn = T.req_len;
    if (neg) {
        G.neg[sid]++;
        return;
    }
    G.pos[sid]++;
    const uint16_t id = (rn >= 3u) ? (uint16_t)(r[1] << 8 | r[2]) : 0u;
    const uint16_t rid = (rn >= 4u) ? (uint16_t)(r[2] << 8 | r[3]) : 0u;
    switch (sid) {
    case 0x10:
        REQUIRE(n == 6u && a[1] == (r[1] & 0x7Fu), "10 %02X answered with %zu bytes", r[1], n);
        break;
    case 0x11:                                       /* iso14229 keeps resetType's low six bits: 11 41 is 11 01 */
        REQUIRE(n == 2u && a[1] == (r[1] & 0x3Fu), "11 %02X answered with %zu bytes", r[1], n);
        break;
    case 0x22:
        if (rn == 3u) {
            const size_t want = id == UDSOTA_DID_ACTIVE_SESSION ? 1u : id == UDSOTA_DID_STATUS ? 16u
                              : id == UDSOTA_DID_RESULT ? 5u : id == UDSOTA_DID_RUNNING_SHA ? 32u
                              : id == UDSOTA_DID_SW_VERSION ? strnlen(P.version, 32)
                              : id == UDSOTA_DID_SERIAL ? ((s_boot_flags & BOOT_DEVICE_ID) ? 16u : 6u) : 4u;
            REQUIRE(n == 3u + want && a[1] == r[1] && a[2] == r[2], "22 %04X answered with %zu bytes", id, n);
        }
        break;
    case 0x27:
        if ((r[1] & 0x7Fu) == UDSOTA_SA_SEED_EXTENDED || (r[1] & 0x7Fu) == UDSOTA_SA_SEED_PROGRAMMING) {
            bool zeros = n >= 3u;                    /* iso14229's answer at a level already unlocked */
            for (size_t i = 2; i < n; i++) {
                zeros = zeros && a[i] == 0u;
            }
            REQUIRE((n == 2u + UDSOTA_SEED_LEN || zeros) && a[1] == (r[1] & 0x7Fu), "27 %02X answered with %zu bytes",
                    r[1], n);
        } else {
            REQUIRE(n == 2u && a[1] == (r[1] & 0x7Fu), "27 %02X answered with %zu bytes", r[1], n);
        }
        break;
    case 0x31:
        REQUIRE(rn >= 4u && n >= 4u && memcmp(&a[1], &r[1], 3) == 0, "31 answered with %zu bytes", n);
        if (rid == UDSOTA_RID_CHECK_PROG_DEPS) {
            REQUIRE(n == 5u && a[4] <= UDSOTA_DL_BAD_BASE, "FF01 answered with %zu bytes", n);
        } else if (rid == UDSOTA_RID_GET_RESUME_POINT) {
            REQUIRE(n == 5u && a[4] == UDSOTA_RESUME_NOT_AVAILABLE, "F000 answered with %zu bytes", n);
        } else if (rid == UDSOTA_RID_ACTIVATE_IMAGE || rid == UDSOTA_RID_CONFIRM_IMAGE) {
            REQUIRE(n == 4u, "%04X answered with %zu bytes", rid, n);
        }
        break;
    case 0x34:
        REQUIRE(n == 4u && a[1] == 0x20u && a[2] == 0x0Fu && a[3] == 0xFFu, "34 answered with %zu bytes", n);
        break;
    case 0x36:
        REQUIRE(n == 2u && a[1] == r[1], "36 %02X answered with %zu bytes", r[1], n);
        break;
    case 0x37:
        REQUIRE(n == 1u, "37 answered with %zu bytes", n);
        REQUIRE(!P.base_refused, "a 37 passed after a refused base read");
        break;
    case 0x3E:
        REQUIRE(n == 2u && a[1] == 0u, "3E answered with %zu bytes", n);
        break;
    default:
        break;
    }
}

/* A whole message from the server: a 0x78, or a final answer. */
static void on_message(const uint8_t *a, size_t n)
{
    if (n == 3u && a[0] == 0x7Fu && a[2] == 0x78u) {
        REQUIRE(was_sent(a[1]), "a 0x78 for SID %02X, which the tester never sent", a[1]);
        G.pendings++;
        T.pending = true;
        return;
    }
    T.pending = false;
    check_answer(a, n);
}

/* One frame from the server: an answer's SF, FF or CF, or an FC to the tester's request. */
static void take(const frame_t *f)
{
    const uint8_t *d = f->d;
    const uint8_t pci = d[0] >> 4;
    T.last_rx_us = g_us;
    switch (pci) {
    case 0x0: {
        const uint8_t n = d[0] & 0x0Fu;
        REQUIRE(n >= 1u && n <= 7u && n <= f->dlc - 1u, "an SF of %u bytes in DLC %u", n, f->dlc);
        T.rx_active = false;
        on_message(&d[1], n);
        break;
    }
    case 0x1: {
        const size_t n = (size_t)(d[0] & 0x0Fu) << 8 | d[1];
        REQUIRE(n >= 8u && f->dlc == 8u, "an FF of %zu bytes in DLC %u", n, f->dlc);
        T.rx_len = n;
        memcpy(T.rx, &d[2], 6);
        T.rx_off = 6;
        T.rx_sn = 1;
        T.rx_active = false;
        send_fc();
        break;
    }
    case 0x2: {
        REQUIRE(T.rx_active, "a CF with no FF in progress or after an overflow FC");
        REQUIRE((d[0] & 0x0Fu) == (T.rx_sn & 0x0Fu), "CF SN %u where %u was next", d[0] & 0x0Fu, T.rx_sn & 0x0Fu);
        REQUIRE(!T.rx_bs || T.cts_left > 0u, "a CF past the tester's block size");
        REQUIRE(T.rx_off == 6u || g_us - T.last_cf_us >= T.rx_stmin_us, "a CF %" PRIu64 " us after the last, under "
                "STmin %" PRIu32, g_us - T.last_cf_us, T.rx_stmin_us);
        const size_t k = (T.rx_len - T.rx_off < 7u) ? T.rx_len - T.rx_off : 7u;
        REQUIRE(f->dlc >= 1u + k, "a CF of DLC %u for %zu bytes", f->dlc, k);
        memcpy(&T.rx[T.rx_off], &d[1], k);
        T.rx_off += k;
        T.rx_sn++;
        T.last_cf_us = g_us;
        if (T.rx_off == T.rx_len) {
            T.rx_active = false;
            on_message(T.rx, T.rx_len);
        } else if (T.rx_bs && --T.cts_left == 0u) {
            send_fc();
        }
        break;
    }
    case 0x3: {
        const uint8_t fs = d[0] & 0x0Fu;
        REQUIRE(f->dlc >= 3u && (fs == 0u || fs == 2u), "an FC with FS %u in DLC %u", fs, f->dlc);
        if (T.sending && T.wait_fc) {
            T.wait_fc = false;
            T.sending = fs == 0u;
            T.bs = T.bs_left = d[1];
            T.stmin_us = d[2] <= 0x7Fu                    ? d[2] * 1000u
                       : (d[2] >= 0xF1u && d[2] <= 0xF9u) ? (d[2] - 0xF0u) * 100u
                                                          : 127000u;
        }
        break;
    }
    default:
        fail("a frame with PCI %X", pci);
    }
}

/* Hands the server's frames to the tester; its FCs may bring more. */
static void drain(void)
{
    for (unsigned i = 0; i < T.q_n; i++) {
        const frame_t f = T.q[i];
        take(&f);
    }
    T.q_n = 0;
}

/* Sends the tester's next CFs, as many as its FC and STmin allow now. */
static void pump(void)
{
    while (T.sending && !T.wait_fc && g_us >= T.next_cf_us) {
        uint8_t cf[8] = {(uint8_t)(0x20u | (T.sn & 0x0Fu))};
        const size_t k = (T.len - T.off < 7u) ? T.len - T.off : 7u;
        memcpy(&cf[1], &T.msg[T.off], k);
        T.off += k;
        T.sn++;
        feed(cf, (uint8_t)(1u + k));
        if (T.off == T.len) {
            T.sending = false;
        } else if (T.bs != 0u && --T.bs_left == 0u) {
            T.wait_fc = true;
            T.fc_deadline_us = g_us + 1000000u;
        }
        T.next_cf_us = g_us + ((P.mode & MODE_SLOW_CF) != 0u && T.stmin_us < 1000u ? 1000u : T.stmin_us);
        drain();
    }
}

/* ---- Running a program ---- */

static void reboot(void)
{
    G.reboots++;
    g_us += BOOT_MS * 1000u;
    memset(&T.q, 0, sizeof T.q);
    T.q_n = 0;
    T.sending = T.rx_active = false;
    boot();
}

/* One poll of the server task, as the app's loop runs it, with the checks that hold between polls. */
static void tick(void)
{
    G.polls++;
    UDSServerPoll(&s_srv);
    udsota_poll(&s_srv);
    REQUIRE(udsota_test_psa_depth() == 0, "the PSA lock is held between polls");
    udsota_progress_t p;
    udsota_progress(&p);
    REQUIRE(p.done <= p.total, "udsota_progress: %" PRIu32 " of %" PRIu32, p.done, p.total);
    REQUIRE(udsota_unconfirmed() == (P.boot == P.running && P.state == UDSOTA_IMG_PENDING_VERIFY),
            "udsota_unconfirmed disagrees with the slots");
    REQUIRE(udsota_busy() || P.job == NULL, "udsota_busy is false while the worker has a job");
    held_ok("a poll");
    drain();
    if (s_reset) {
        reboot();
    }
}

static unsigned long g_polls0;                       /* G.polls when the program began */

/* False once the program has had its POLL_CAP polls. */
static bool budget(void)
{
    return G.polls - g_polls0 < POLL_CAP;
}

static void step(void)
{
    g_us += 1000u;
    tick();
}

/* Starts sending msg, as an SF or an FF. */
static void send_request(const uint8_t *msg, size_t n)
{
    note_sent(msg[0]);
    if (!s_srv.requestInProgress && s_tp.phys_link.receive_status == ISOTP_RECEIVE_STATUS_IDLE &&
        s_tp.phys_link.send_status != ISOTP_SEND_STATUS_INPROGRESS && !T.rx_active) {
        T.outstanding = 0;                           /* the server holds no request: nothing older can be answered */
    }
    T.outstanding++;
    if (n <= 7u) {
        uint8_t sf[8] = {(uint8_t)n};
        memcpy(&sf[1], msg, n);
        feed(sf, (uint8_t)(1u + n));
        T.sending = false;
    } else {
        memcpy(T.msg, msg, n);
        T.len = n;
        uint8_t ff[8] = {(uint8_t)(0x10u | n >> 8), (uint8_t)n};
        memcpy(&ff[2], msg, 6);
        T.off = 6;
        T.sn = 1;
        T.sending = T.wait_fc = true;
        T.fc_deadline_us = g_us + 1000000u;
        T.next_cf_us = g_us;
        feed(ff, 8);
    }
    drain();
}

/* A request: sent, then polled until its final answer, a timeout (300 ms of silence, 5.2 s after a 0x78), or the
 * program's poll budget. With wait false, only until it is sent. */
static void request(const uint8_t *msg, size_t n, bool wait)
{
    T.req_len = wait ? (n < sizeof T.req ? n : sizeof T.req) : 0u;
    memcpy(T.req, msg, T.req_len);
    T.answered = T.pending = false;
    send_request(msg, n);
    uint64_t quiet_from = g_us;
    while (budget()) {
        pump();
        if (T.sending && T.wait_fc && g_us > T.fc_deadline_us) {
            T.sending = false;                       /* the server never sent an FC */
        }
        if (!wait && !T.sending) {
            break;
        }
        step();
        if (T.answered) {
            break;
        }
        if (T.sending) {
            quiet_from = g_us;
        } else if (T.last_rx_us > quiet_from) {
            quiet_from = T.last_rx_us;
        }
        if (g_us - quiet_from > (T.pending ? 5200000u : 300000u)) {
            G.unanswered++;
            if (!s_srv.requestInProgress) {
                T.outstanding = 0;                   /* nothing can still come */
            }
            break;
        }
    }
    T.req_len = 0;
}

/* KEY: 27 level+1 with the key the tester holds for its last seed (zeros for none), or a valid ECDSA stand-in. */
static void send_key(uint8_t level)
{
    uint8_t req[2 + UDSOTA_KEYS_SIG_LEN] = {0x27, (uint8_t)(level + 1u)};
    size_t n = 2u + UDSOTA_KEY_LEN;
    if ((s_boot_flags & BOOT_KEYS_MASK) == 1u) {
        memset(&req[2], 0x5A, UDSOTA_KEYS_SIG_LEN);
        n = sizeof req;
    } else {
        const bool own = (s_boot_flags & BOOT_DEVICE_ID) != 0u;
        const uint8_t *id = own ? k_devid : k_mac;
        const size_t id_len = own ? sizeof k_devid : sizeof k_mac;
        uint8_t kdev[32], msg[64], full[32];
        memcpy(msg, k_label, sizeof k_label - 1u);
        memcpy(&msg[sizeof k_label - 1u], id, id_len);
        stand_in_hmac(k_master, sizeof k_master, msg, sizeof k_label - 1u + id_len, kdev);
        memcpy(msg, T.seed, 16);
        msg[16] = level;
        memcpy(&msg[17], id, id_len);
        stand_in_hmac(kdev, sizeof kdev, msg, 17u + id_len, full);
        memcpy(&req[2], full, UDSOTA_KEY_LEN);
    }
    request(req, n, true);
}

static uint32_t rd_le(const uint8_t *in, size_t len, size_t pos, unsigned n)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        v |= (uint32_t)(pos + i < len ? in[pos + i] : 0u) << (8u * i);
    }
    return v;
}

/* Bytes the op at in[pos] takes, op byte included. */
static size_t op_size(const uint8_t *in, size_t len, size_t pos)
{
    const uint8_t b1 = pos + 1u < len ? in[pos + 1u] : 0u;
    const uint8_t b2 = pos + 2u < len ? in[pos + 2u] : 0u;
    switch ((op_t)((in[pos] & 0x0Fu) % OP_COUNT)) {
    case OP_REQ: return 3u + (((size_t)b1 << 8 | b2) & 0x0FFFu);
    case OP_KEY: case OP_MODE: case OP_BOOT: return 2u;
    case OP_RAW: return 10u;
    case OP_WAIT: case OP_GATE: return 3u;
    case OP_JUMP: return 5u;
    default: return 1u;
    }
}

/* Runs one program from a fresh boot. */
static void run_program(const uint8_t *in, size_t len)
{
    g_prog = in;
    g_prog_len = len;
    if (len > PROG_MAX) {
        len = PROG_MAX;
    }
    memset(&T, 0, sizeof T);
    memset(&P, 0, sizeof P);
    memcpy(P.slot[0], g_base, IMG_LEN);
    memset(&P.slot[0][IMG_LEN], 0xFF, SLOT - IMG_LEN);
    memset(P.slot[1], 0xFF, SLOT);
    P.state = UDSOTA_IMG_VALID;
    memset(s_gate, 0, sizeof s_gate);
    s_boot_flags = 0;
    g_us = T0_US;
    boot();
    g_us += 1100000u;                                 /* past iso14229's 1 s boot delay for 0x27 */
    g_polls0 = G.polls;
    for (size_t pos = 0; pos < len && budget(); pos += op_size(in, len, pos)) {
        const uint8_t op = in[pos];
        const uint32_t a = rd_le(in, len, pos + 1u, 4);
        G.ops++;
        switch ((op_t)((op & 0x0Fu) % OP_COUNT)) {
        case OP_REQ: {
            size_t n = (((size_t)(a & 0xFFu) << 8) | (a >> 8 & 0xFFu)) & 0x0FFFu;
            n = (pos + 3u + n <= len) ? n : (pos + 3u < len ? len - pos - 3u : 0u);
            if (n != 0u) {
                request(&in[pos + 3u], n, (op & OP_NOWAIT) == 0u);
            }
            break;
        }
        case OP_KEY:
            send_key((uint8_t)a);
            break;
        case OP_RAW: {
            uint8_t f[8];
            const uint8_t dlc = (uint8_t)((a & 0xFFu) % 9u);
            for (unsigned i = 0; i < 8u; i++) {
                f[i] = pos + 2u + i < len ? in[pos + 2u + i] : 0u;
            }
            if (dlc != 0u && ((f[0] >> 4) == 0u || (f[0] >> 4) == 1u)) {
                note_sent(dlc > ((f[0] >> 4) == 0u ? 1u : 2u) ? f[(f[0] >> 4) + 1u] : 0u);
                T.outstanding++;
            }
            feed(f, dlc);
            drain();
            step();
            break;
        }
        case OP_WAIT:
            for (uint32_t ms = a & 0xFFFFu; ms > 0u && budget(); ms--) {
                step();
            }
            break;
        case OP_JUMP:
            g_us += (uint64_t)a * 1000u;
            step();
            break;
        case OP_MODE:
            P.mode = (uint8_t)a;
            break;
        case OP_GATE:
            s_gate[a & 7u] = (uint8_t)(a >> 8);
            break;
        case OP_BOOT:
            s_boot_flags = (uint8_t)a;
            reboot();
            break;
        default:                                       /* OP_END */
            (void)udsota_end_session(&s_srv);
            step();
            break;
        }
    }
    G.programs++;
}

/* ---- The seeds ---- */

static uint8_t g_seeds[262144];
static size_t  g_seeds_len, g_seed_start;
static struct {
    size_t off, len;
} g_seed[32];
static size_t g_seed_n;

static void p_bytes(const uint8_t *b, size_t n)
{
    if (g_seeds_len + n > sizeof g_seeds) {
        fprintf(stderr, "fuzz_udsota: the seeds outgrew their buffer\n");
        exit(2);
    }
    memcpy(&g_seeds[g_seeds_len], b, n);
    g_seeds_len += n;
}

static void p_op(uint8_t op, uint32_t a, unsigned n)
{
    uint8_t b[5] = {op, (uint8_t)a, (uint8_t)(a >> 8), (uint8_t)(a >> 16), (uint8_t)(a >> 24)};
    p_bytes(b, 1u + n);
}

static void p_req_flags(uint8_t flags, const uint8_t *r, size_t n)
{
    const uint8_t h[3] = {(uint8_t)(OP_REQ | flags), (uint8_t)(n >> 8), (uint8_t)n};
    p_bytes(h, 3);
    p_bytes(r, n);
}

#define REQ(...)                                                                                         \
    do {                                                                                                 \
        static const uint8_t r_[] = {__VA_ARGS__};                                                       \
        p_req_flags(0u, r_, sizeof r_);                                                                  \
    } while (0)
#define REQ_NOWAIT(...)                                                                                  \
    do {                                                                                                 \
        static const uint8_t r_[] = {__VA_ARGS__};                                                       \
        p_req_flags(OP_NOWAIT, r_, sizeof r_);                                                           \
    } while (0)
#define KEY(level)     p_op(OP_KEY, (level), 1)
#define WAIT(ms)       p_op(OP_WAIT, (ms), 2)
#define JUMP(ms)       p_op(OP_JUMP, (ms), 4)
#define MODE(m)        p_op(OP_MODE, (m), 1)
#define GATE(op, nrc)  p_op(OP_GATE, (uint32_t)(op) | (uint32_t)(nrc) << 8, 2)
#define BOOT(flags)    p_op(OP_BOOT, (flags), 1)
#define END()          p_op(OP_END, 0, 0)
#define RAW(dlc, ...)                                                                                    \
    do {                                                                                                 \
        const uint8_t f_[8] = {__VA_ARGS__};                                                             \
        p_op(OP_RAW, (dlc), 1);                                                                          \
        p_bytes(f_, 8);                                                                                  \
    } while (0)

static void seed_begin(void)
{
    g_seed_start = g_seeds_len;
}

static void seed_end(void)
{
    g_seed[g_seed_n].off = g_seed_start;
    g_seed[g_seed_n].len = g_seeds_len - g_seed_start;
    g_seed_n++;
}

static void p_unlock_programming(void)
{
    REQ(0x10, 0x02);
    REQ(0x27, 0x03);
    KEY(0x03);
}

static void p_download(uint8_t dfi, uint32_t size)
{
    const uint8_t r[] = {0x34, dfi, 0x44, 0, 0, 0, 0, (uint8_t)(size >> 24), (uint8_t)(size >> 16),
                         (uint8_t)(size >> 8), (uint8_t)size};
    p_req_flags(0u, r, sizeof r);
}

/* 36 bsc with n bytes of d. */
static void p_block(uint8_t flags, uint8_t bsc, const uint8_t *d, size_t n)
{
    const uint8_t h[5] = {(uint8_t)(OP_REQ | flags), (uint8_t)((n + 2u) >> 8), (uint8_t)(n + 2u), 0x36, bsc};
    p_bytes(h, sizeof h);
    p_bytes(d, n);
}

/* Every block of d, at most per bytes each. */
static void p_blocks(const uint8_t *d, size_t n, size_t per)
{
    uint8_t bsc = 1;
    for (size_t off = 0; off < n; off += per, bsc++) {
        p_block(0u, bsc, &d[off], (n - off < per) ? n - off : per);
    }
}

/* The rest of an update once the image is in: verify, activate, the restart, then confirm. */
static void p_finish(void)
{
    REQ(0x37);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x22, 0xF1, 0xF0);
    REQ(0x31, 0x01, 0xF0, 0x01);
    WAIT(300);
    REQ(0x22, 0xF1, 0x89);
    REQ(0x10, 0x03);
    REQ(0x31, 0x01, 0xF0, 0x02);
    REQ(0x22, 0xF1, 0xF0);
}

/* A detools size: 6 bits and a sign bit in the first byte, then 7 bits a byte, each top bit saying another follows. */
static size_t put_size(uint8_t *p, int32_t v)
{
    uint32_t u = (v < 0) ? (uint32_t)-(int64_t)v : (uint32_t)v;
    size_t i = 0;
    p[0] = (uint8_t)((u & 0x3Fu) | ((v < 0) ? 0x40u : 0u));
    for (u >>= 6; u != 0u; u >>= 7) {
        p[i++] |= 0x80u;
        p[i] = (uint8_t)(u & 0x7Fu);
    }
    return i + 1u;
}

/* One chunk of a detools sequential patch: diff bytes added to the base's, extra bytes as they are, then the base's
 * offset moved by adjust. */
typedef struct {
    uint32_t diff, extra;
    int32_t  adjust;
} chunk_t;

/* g_dp's chunks. The seeks go far both ways, to the slot's last bytes and back, so an edited one lands past the slot
 * or before its start. */
static const chunk_t k_chunks[] = {{320, 0, 16000}, {700, 300, -16700}, {1500, 200, 30000}, {940, 100, -32000},
                                   {1200, 740, 0}};

/* The uncompressed delta, into out (PATCH_CAP bytes), that rebuilds to's IMG_LEN bytes from slot 0 at power-on
 * (g_base, then FF) in n chunks, behind the header naming g_base; its length. */
static size_t patch_of(uint8_t *out, const uint8_t *to, const chunk_t *c, size_t n)
{
    static const uint8_t magic[4] = {0x10, 0xDE, 0xCD, 0xFC};   /* 0xFCCDDE10, little-endian */
    size_t k = 64;
    int64_t from = 0;
    uint32_t t = 0;
    memset(out, 0, k);
    memcpy(out, magic, sizeof magic);
    image_hash(g_base, &out[4]);
    out[k++] = 0x00;                                   /* sequential, uncompressed */
    k += put_size(&out[k], (int32_t)IMG_LEN);
    k += put_size(&out[k], 0);                         /* no data-format patch */
    for (size_t i = 0; i < n; i++) {
        k += put_size(&out[k], (int32_t)c[i].diff);
        for (uint32_t j = 0; j < c[i].diff; j++, t++, from++) {
            out[k++] = (uint8_t)(to[t] - (from >= 0 && from < (int64_t)IMG_LEN ? g_base[from] : 0xFFu));
        }
        k += put_size(&out[k], (int32_t)c[i].extra);
        for (uint32_t j = 0; j < c[i].extra; j++, t++) {
            out[k++] = to[t];
        }
        k += put_size(&out[k], c[i].adjust);
        from += c[i].adjust;
    }
    if (t != IMG_LEN) {
        fprintf(stderr, "fuzz_udsota: the delta's chunks don't make the image\n");
        exit(2);
    }
    return k;
}

/* d's n bytes as raw DEFLATE in out, which holds max; its length, 0 when it doesn't fit. */
static size_t deflated(uint8_t *out, size_t max, const uint8_t *d, size_t n)
{
    return tdefl_compress_mem_to_mem(out, max, d, n, TDEFL_DEFAULT_MAX_PROBES);
}

static void build_seeds(void)
{
    static uint8_t bad[IMG_LEN];

    /* 0: a whole update over DFI 00. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_blocks(g_img, IMG_LEN, 4093u);
    p_finish();
    REQ(0x22, 0xF1, 0xF1);
    seed_end();

    /* 1: a whole update over DFI 10, the stream in three blocks. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    p_blocks(g_z, g_zlen, g_zlen / 3u + 1u);
    p_finish();
    seed_end();

    /* 2: first blocks the image rules refuse (another board, an older release), a size past the slot, and a
     * compressed image of another board, each before anything is erased; then an image that fails its verify. */
    seed_begin();
    p_unlock_programming();
    stamp(bad, "1.0.1", 2u, 0x01u, 7u);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, bad, 4093u);
    REQ(0x22, 0xF1, 0xF1);
    stamp(bad, "0.9.9", HW_ID, 0x01u, 7u);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, bad, 4093u);
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI, SLOT + 1u);
    {
        size_t zn = 0;
        stamp(bad, "1.0.1", 2u, 0x01u, 7u);
        uint8_t *z = tdefl_compress_mem_to_heap(bad, IMG_LEN, &zn, TDEFL_DEFAULT_MAX_PROBES);
        p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
        p_block(0u, 1, z, zn < 4093u ? zn : 4093u);
        mz_free(z);
    }
    REQ(0x22, 0xF1, 0xF1);
    memcpy(bad, g_img, IMG_LEN);
    bad[5000] ^= 0x01u;
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_blocks(bad, IMG_LEN, 4093u);
    REQ(0x37);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x31, 0x01, 0xF0, 0x01);
    REQ(0x22, 0xF1, 0xF0);
    seed_end();

    /* 3: bad streams: a reserved block type, a stream cut short at 37, three past memorySize, a stream with bytes
     * after its end, one that ends before the image rules have their 320 bytes, and one past udsota's bound. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    {
        uint8_t z[64];
        memcpy(z, g_z, sizeof z);
        z[0] |= 0x06u;                                 /* BTYPE 11 */
        p_block(0u, 1, z, sizeof z);
    }
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    p_block(0u, 1, g_z, g_zlen / 2u);
    REQ(0x37);
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, 2400u);         /* under udsota's 4 KiB write buffer; iso14229 holds the */
    p_blocks(g_z, g_zlen, 2000u);                     /* first block to memorySize, udsota the rest to the bound */
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, 4095u);         /* one byte under the 4 KiB write buffer: the bound, not */
    p_block(0u, 1, g_z, g_zlen);                      /* iso14229, must stop the first full buffer */
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN - 1000u);
    p_block(0u, 1, g_z, g_zlen);
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    p_block(0u, 1, g_z, g_zlen);
    {
        const uint8_t tail[4] = {0x03, 0x00, 0xAA, 0x55};
        p_block(0u, 2, tail, sizeof tail);
    }
    REQ(0x37);
    REQ(0x22, 0xF1, 0xF1);
    {
        size_t zn = 0;
        uint8_t *z = tdefl_compress_mem_to_heap(g_img, 200u, &zn, TDEFL_DEFAULT_MAX_PROBES);
        p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
        p_block(0u, 1, z, zn);
        mz_free(z);
    }
    REQ(0x22, 0xF1, 0xF1);
    p_download(UDSOTA_DL_DFI_DEFLATE, 400u);
    p_block(0u, 1, g_z, 400u);
    p_block(0u, 2, &g_z[400], 2000u);
    REQ(0x22, 0xF1, 0xF1);
    seed_end();

    /* 4: the DIDs, in each session, one at a time and together, the app's and unknown ones. */
    seed_begin();
    REQ(0x22, 0xF1, 0x86);
    REQ(0x22, 0xF1, 0x89);
    REQ(0x22, 0xF1, 0x8C);
    REQ(0x22, 0xF1, 0xF0);
    REQ(0x22, 0xF1, 0xF1);
    REQ(0x22, 0xF1, 0xF3);
    REQ(0x22, 0xF1, 0x91);
    REQ(0x22, 0x12, 0x34);
    REQ(0x22, 0xF1, 0x86, 0xF1, 0xF1, 0xF1, 0xF3);
    REQ(0x22, 0xF1);
    REQ(0x2E, 0xF1, 0x86, 0x00);
    REQ(0x10, 0x03);
    REQ(0x22, 0xF1, 0x86);
    REQ(0x3E, 0x00);
    REQ(0x3E, 0x80);
    REQ(0x3E, 0x01);
    REQ(0x10, 0x83);
    REQ(0x10, 0x04);
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    REQ(0x85, 0x01);
    REQ(0x28, 0x00, 0x01);
    REQ(0x19, 0x02, 0xFF);
    REQ(0x10, 0x01);
    REQ(0x22, 0xF1, 0x86);
    seed_end();

    /* 5: the routines in every session, with the wrong control, an option record, out of sequence, and locked. */
    seed_begin();
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x10, 0x03);
    REQ(0x31, 0x01, 0xF0, 0x00);
    REQ(0x31, 0x01, 0xF0, 0x02);
    REQ(0x31, 0x02, 0xF0, 0x02);
    REQ(0x31, 0x01, 0xF0, 0x02, 0x00);
    REQ(0x31, 0x01, 0x12, 0x34);
    REQ(0x10, 0x02);
    REQ(0x31, 0x01, 0xF0, 0x00);
    REQ(0x27, 0x03);
    KEY(0x03);
    REQ(0x31, 0x01, 0xF0, 0x00);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x31, 0x01, 0xF0, 0x01);
    REQ(0x31, 0x03, 0xFF, 0x01);
    REQ(0x31, 0x01, 0xF0, 0x02);
    REQ(0x31, 0x01);
    seed_end();

    /* 6: 0x27: each level in each session, a key without a seed, a wrong key and iso14229's delay after it, both
     * unlocks, and 11 01 locked and unlocked, then a 27 inside the boot delay. */
    seed_begin();
    REQ(0x27, 0x01);
    REQ(0x11, 0x01);
    REQ(0x10, 0x03);
    REQ(0x11, 0x01);
    REQ(0x27, 0x03);
    REQ(0x27, 0x05);
    REQ(0x27, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
    REQ(0x27, 0x01);
    REQ(0x27, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
    REQ(0x27, 0x01);
    WAIT(1100);
    REQ(0x27, 0x01, 0x00);
    REQ(0x27, 0x01);
    REQ(0x27, 0x02, 1, 2, 3);
    KEY(0x01);
    REQ(0x27, 0x01);
    KEY(0x01);
    REQ(0x11, 0x01);
    WAIT(200);
    REQ(0x10, 0x02);
    REQ(0x27, 0x03);
    JUMP(1100);
    REQ(0x27, 0x03);
    KEY(0x03);
    REQ(0x11, 0x01);
    WAIT(200);
    seed_end();

    /* 7: a transfer ended by S3, by 10 01, by the app, by the gate (0x22 ends the session, 0x21 only the block), and
     * the sequence errors around it; a 34 the gate refuses, a 36 with no data, and a 34 after a 37 with no FF01. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    WAIT(5200);
    REQ(0x22, 0xF1, 0xF1);
    p_unlock_programming();
    p_block(0u, 2, &g_img[4093], IMG_LEN - 4093u);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    REQ(0x37);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    p_block(0u, 3, g_img, 100u);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    REQ(0x10, 0x01);
    REQ(0x22, 0xF1, 0xF1);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    END();
    REQ(0x22, 0xF1, 0x86);
    p_unlock_programming();
    GATE(UDSOTA_OP_CONTINUE_TRANSFER, 0x21);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    GATE(UDSOTA_OP_CONTINUE_TRANSFER, 0x22);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    REQ(0x22, 0xF1, 0x86);
    GATE(UDSOTA_OP_CONTINUE_TRANSFER, 0);
    GATE(UDSOTA_OP_ENTER_PROGRAMMING, 0x22);
    REQ(0x10, 0x02);
    GATE(UDSOTA_OP_ENTER_PROGRAMMING, 0);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 2, &g_img[4093], IMG_LEN - 4093u);
    GATE(UDSOTA_OP_START_DOWNLOAD, 0x22);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    GATE(UDSOTA_OP_START_DOWNLOAD, 0);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    REQ(0x36, 0x01);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_blocks(g_img, IMG_LEN, 4093u);
    REQ(0x37);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    REQ(0x22, 0xF1, 0xF0);
    seed_end();

    /* 8: the worker: a slow job with requests sent meanwhile, a job that never ends (the 90 s cap), failed flash
     * writes, a refused job and a failed RNG. */
    seed_begin();
    MODE(0x02);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(OP_NOWAIT, 1, g_img, 4093u);
    WAIT(20);
    REQ(0x22, 0xF1, 0xF0);
    REQ(0x10, 0x02);
    REQ(0x10, 0x01);
    MODE(0x03);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    REQ(0x22, 0xF1, 0xF1);
    BOOT(0x00);
    MODE(0x10);
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    MODE(0x40);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    p_block(0u, 1, g_z, g_zlen);
    MODE(0x20);
    REQ(0x10, 0x02);
    REQ(0x27, 0x03);
    seed_end();

    /* 9: ISO-TP's edges: an FF left without its CFs (N_Cr), a CF out of sequence, an SF of length 0 and one longer
     * than its DLC, an escape FF, FCs to an idle server, then the tester's FC with BS 1 and STmin 2 ms, no FC (N_Bs),
     * an overflow FC, CFs 1 ms apart, and a request at the end that must still be answered. */
    seed_begin();
    RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0xF1, 0x89, 0xF1);
    WAIT(300);
    RAW(8, 0x10, 0x0A, 0x22, 0xF1, 0x86, 0xF1, 0x89, 0xF1);
    RAW(8, 0x22, 0xF0, 0xF1, 0xF3, 0, 0, 0, 0);
    WAIT(200);
    RAW(1, 0x00, 0, 0, 0, 0, 0, 0, 0);
    RAW(3, 0x07, 0x22, 0xF1, 0, 0, 0, 0, 0);
    RAW(8, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x22, 0xF1);
    RAW(3, 0x30, 0x00, 0x00, 0, 0, 0, 0, 0);
    RAW(3, 0x31, 0x00, 0x00, 0, 0, 0, 0, 0);
    WAIT(200);
    REQ(0x22, 0xF1, 0x86);
    MODE(0x04);
    REQ(0x22, 0xF1, 0xF3);
    REQ(0x22, 0xF1, 0x86, 0xF1, 0xF0, 0xF1, 0xF1);
    MODE(0x08);
    REQ(0x22, 0xF1, 0xF3);
    MODE(0x0C);
    REQ(0x22, 0xF1, 0xF3);
    MODE(0x80);
    REQ(0x2E, 0x01, 0x02, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20);
    MODE(0x00);
    REQ(0x22, 0xF1, 0x89);
    seed_end();

    /* 10: each udsota_cfg_t at a boot: security off (34 without 27; 27 is the app's), ECDSA, unusable keys,
     * allow_downgrade (an older release passes the first block), another product, and its own device ID. */
    seed_begin();
    BOOT(0x02);
    REQ(0x10, 0x02);
    REQ(0x27, 0x03);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    BOOT(0x01);
    JUMP(1100);
    p_unlock_programming();
    REQ(0x22, 0xF1, 0xF0);
    BOOT(0x03);
    JUMP(1100);
    p_unlock_programming();
    BOOT(0x04);
    JUMP(1100);
    p_unlock_programming();
    stamp(bad, "0.9.9", HW_ID, 0x01u, 7u);
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, bad, 4093u);
    BOOT(0x08);
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_block(0u, 1, g_img, 4093u);
    BOOT(0x10);
    JUMP(1100);
    REQ(0x22, 0xF1, 0x8C);
    p_unlock_programming();
    REQ(0x22, 0xF1, 0x86);
    seed_end();

    /* 11: the clock: a jump to just before isotp-c's us clock wraps, a 36 across the wrap, then a jump past the
     * 24.86 days at which iso14229's timers would wrap, and 0x27 after it. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    JUMP(4294967u - 11100u - 40u);
    REQ(0x3E, 0x00);
    p_block(0u, 1, g_img, 4093u);
    REQ(0x10, 0x01);
    JUMP(2147484000u);
    REQ(0x10, 0x03);
    REQ(0x27, 0x01);
    KEY(0x01);
    REQ(0x22, 0xF1, 0x86);
    seed_end();

    /* 12: a repeated FF01, an F001 the gate refuses, then a restart with the new image unconfirmed rolls it back; the
     * update then runs again. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DEFLATE, IMG_LEN);
    p_blocks(g_z, g_zlen, 4093u);
    REQ(0x37);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x31, 0x01, 0xFF, 0x01);
    GATE(UDSOTA_OP_ACTIVATE, 0x22);
    REQ(0x31, 0x01, 0xF0, 0x01);
    GATE(UDSOTA_OP_ACTIVATE, 0);
    REQ(0x31, 0x01, 0xF0, 0x01);
    WAIT(300);
    REQ(0x10, 0x02);
    REQ(0x22, 0xF1, 0xF0);
    BOOT(0x00);
    REQ(0x22, 0xF1, 0xF0);
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI, IMG_LEN);
    p_blocks(g_img, IMG_LEN, 4093u);
    REQ(0x37);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x22, 0xF1, 0xF0);
    seed_end();

    /* 13: a whole update over DFI 30, the delta in two blocks; then, with the update running, the same delta names a
     * base that is no longer there: BAD_BASE at its first block, before anything is erased. */
    seed_begin();
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    p_blocks(g_dz, g_dzlen, g_dzlen / 2u + 1u);
    p_finish();
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    p_blocks(g_dz, g_dzlen, 4093u);
    REQ(0x22, 0xF1, 0xF1);
    seed_end();

    /* 14: a whole update over DFI 30 on slow jobs, the delta in one stored DEFLATE block, so that the mutants' edits
     * to it are edits to the patch: the block's head and the patch's header in the first 36, the rest in two. */
    seed_begin();
    MODE(0x02);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    p_block(0u, 1u, g_ds, 5u + 64u);
    p_block(0u, 2u, &g_ds[69], 4093u);
    p_block(0u, 3u, &g_ds[69u + 4093u], g_dslen - 69u - 4093u);
    MODE(0x00);
    p_finish();
    seed_end();

    /* 15: deltas refused: with allow_delta off, 0x31 to the 34; with the running image's hash unreadable, and with a
     * wrong magic, at the first block, before anything is erased; one that rebuilds another board's image, at its
     * first bytes; one with bytes after the patch's end; one cut short, at its 37; two whose base reads leave int's
     * range, which udsota refuses before the platform sees them; and one whose seeks would pass INT_MAX. */
    seed_begin();
    BOOT(BOOT_NO_DELTA);
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    BOOT(BOOT_NO_HASH);
    JUMP(1100);
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    p_blocks(g_dz, g_dzlen, 4093u);
    REQ(0x22, 0xF1, 0xF1);
    BOOT(0x00);
    JUMP(1100);
    p_unlock_programming();
    {
        static uint8_t p[PATCH_CAP], z[PATCH_CAP + 1024u];
        size_t n;
        memcpy(p, g_dp, g_dplen);
        p[0] ^= 0xFFu;
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, g_dplen), 4093u);
        REQ(0x22, 0xF1, 0xF1);
        stamp(bad, "1.0.1", 2u, 0x01u, 2u);
        n = patch_of(p, bad, k_chunks, sizeof k_chunks / sizeof k_chunks[0]);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, n), 4093u);
        REQ(0x22, 0xF1, 0xF1);
        memcpy(p, g_dp, g_dplen);
        memset(&p[g_dplen], 0xAA, 16);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, g_dplen + 16u), 4093u);
        REQ(0x37);
        REQ(0x22, 0xF1, 0xF1);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, g_dp, 3000u), 4093u);
        REQ(0x37);
        REQ(0x22, 0xF1, 0xF1);
        chunk_t c[17] = {{320, 0, -1000}, {5680, 0, 0}};   /* a read before the slot's start */
        n = patch_of(p, g_img, c, 2);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, n), 4093u);
        REQ(0x22, 0xF1, 0xF1);
        int64_t left = INT_MAX - 64 - 320;               /* a read 64 bytes under INT_MAX: a detools size holds */
        for (size_t i = 0; i < 16u; i++) {               /* 27 bits, so the seek takes 16 chunks */
            const int32_t seek = (int32_t)(left < 0x7FFFFFF ? left : 0x7FFFFFF);
            c[i] = (chunk_t){i == 0u ? 320u : 0u, 0, seek};
            left -= seek;
        }
        c[16] = (chunk_t){5680, 0, 0};
        n = patch_of(p, g_img, c, 17);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, n), 4093u);
        REQ(0x22, 0xF1, 0xF1);
        for (size_t i = 0; i < 16u; i++) {               /* 16 seeks of 2^27 - 1 after 320 bytes: past INT_MAX */
            c[i].adjust = 0x7FFFFFF;
        }
        n = patch_of(p, g_img, c, 17);
        p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
        p_blocks(z, deflated(z, sizeof z, p, n), 4093u);
        REQ(0x22, 0xF1, 0xF1);
    }
    seed_end();
}

/* ---- Mutation ---- */

static uint32_t g_rng = 0x5EEDF00Du;

/* xorshift32 with a fixed seed, so every replay makes the same mutants. */
static uint32_t rnd(void)
{
    uint32_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng = x;
    return x;
}

/* One random, well-formed op at out; returns its length. Requests are built per SID from the numbers udsota and
 * iso14229 act on. */
static size_t random_op(uint8_t *out)
{
    static const uint8_t SIDS[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27, 0x28, 0x2E, 0x31, 0x34, 0x35, 0x36,
                                   0x37, 0x38, 0x3D, 0x3E, 0x85, 0x87, 0xBA};
    static const uint16_t DIDS[] = {0xF186, 0xF189, 0xF18C, 0xF1F0, 0xF1F1, 0xF1F3, 0xF191, 0x1234};
    static const uint16_t RIDS[] = {0xFF01, 0xF000, 0xF001, 0xF002, 0x1234};
    size_t n = 0;
    const unsigned kind = rnd() % 12u;
    if (kind >= OP_COUNT) {                                  /* requests, more often than the rest */
        uint8_t r[4095];
        size_t rn = 0;
        const uint8_t sid = SIDS[rnd() % sizeof SIDS];
        r[rn++] = sid;
        switch (sid) {
        case 0x10: case 0x11: case 0x3E: {
            const uint32_t sub = rnd() % 6u;
            const bool sprmib = rnd() % 4u == 0u;
            r[rn++] = (uint8_t)(sub | (sprmib ? 0x80u : 0u));
            break;
        }
        case 0x22: {
            const unsigned k = 1u + rnd() % 3u;
            for (unsigned i = 0; i < k; i++) {
                const uint16_t did = DIDS[rnd() % (sizeof DIDS / sizeof DIDS[0])];
                r[rn++] = (uint8_t)(did >> 8);
                r[rn++] = (uint8_t)did;
            }
            break;
        }
        case 0x27:
            r[rn++] = (uint8_t)(1u + rnd() % 6u);
            for (unsigned k = (r[1] & 1u) ? 0u : 16u; k > 0u; k--) {
                r[rn++] = (uint8_t)rnd();
            }
            break;
        case 0x31: {
            const uint16_t rid = RIDS[rnd() % (sizeof RIDS / sizeof RIDS[0])];
            r[rn++] = (uint8_t)(1u + rnd() % 3u);
            r[rn++] = (uint8_t)(rid >> 8);
            r[rn++] = (uint8_t)rid;
            break;
        }
        case 0x34: {
            static const uint8_t DFI[] = {0x00, 0x10, 0x01, 0x11, 0x20, 0x30};
            static const uint8_t ALFID[] = {0x44, 0x33, 0x11, 0x14, 0x41, 0x45, 0x00};
            static const uint32_t EDGE[] = {319, 320, 321, 4095, 4096, 4097, 8191, 8192};   /* IMAGE_MIN, BUF_LEN */
            const uint32_t pick = rnd() % 5u;
            const uint32_t size = pick == 0u ? rnd() : pick == 1u ? rnd() % IMG_LEN :
                                  pick == 2u ? EDGE[rnd() % (sizeof EDGE / sizeof EDGE[0])] :
                                  IMG_LEN - 64u + rnd() % 128u;
            r[rn++] = DFI[rnd() % sizeof DFI];
            r[rn++] = ALFID[rnd() % sizeof ALFID];
            for (unsigned i = 0; i < 4u; i++) {
                r[rn++] = (uint8_t)(rnd() % 8u == 0u ? rnd() : 0u);
            }
            for (unsigned i = 0; i < 4u; i++) {
                r[rn++] = (uint8_t)(size >> (24u - 8u * i));
            }
            break;
        }
        case 0x36: {
            const uint32_t which = rnd() % 3u;               /* the image, as it is or as DEFLATE, or the delta */
            const uint8_t *src = which == 0u ? g_img : which == 1u ? g_z : g_dz;
            const size_t src_len = which == 0u ? IMG_LEN : which == 1u ? g_zlen : g_dzlen;
            const size_t off = rnd() % 2u == 0u ? 0u : rnd() % src_len;
            size_t k = rnd() % 4u == 0u ? rnd() % 4094u : src_len - off;
            k = (k < 4093u) ? k : 4093u;
            k = (off + k <= src_len) ? k : src_len - off;
            r[rn++] = (uint8_t)(1u + rnd() % 3u);
            memcpy(&r[rn], &src[off], k);
            rn += k;
            break;
        }
        default:
            for (unsigned k = rnd() % 6u; k > 0u; k--) {
                r[rn++] = (uint8_t)rnd();
            }
            break;
        }
        out[n++] = (uint8_t)(OP_REQ | (rnd() % 8u == 0u ? OP_NOWAIT : 0u));
        out[n++] = (uint8_t)(rn >> 8);
        out[n++] = (uint8_t)rn;
        memcpy(&out[n], r, rn);
        return n + rn;
    }
    out[n++] = (uint8_t)kind;
    switch ((op_t)kind) {
    case OP_KEY:
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0x03u : 0x01u);
        break;
    case OP_RAW: {
        out[n++] = (uint8_t)(rnd() % 9u);
        const uint32_t pci = rnd() % 4u;
        const uint32_t low = rnd() % 16u;
        out[n++] = (uint8_t)(pci << 4 | low);
        for (unsigned i = 1; i < 8u; i++) {
            out[n++] = (uint8_t)rnd();
        }
        break;
    }
    case OP_WAIT: {
        const uint32_t ms = rnd() % 5u == 0u ? rnd() % 6000u : rnd() % 60u;
        out[n++] = (uint8_t)ms;
        out[n++] = (uint8_t)(ms >> 8);
        break;
    }
    case OP_JUMP: {
        const uint32_t ms = rnd() % 4u == 0u ? rnd() : rnd() % 2000u;
        for (unsigned i = 0; i < 4u; i++) {
            out[n++] = (uint8_t)(ms >> (8u * i));
        }
        break;
    }
    case OP_MODE: case OP_BOOT:
        out[n++] = (uint8_t)(rnd() % 3u == 0u ? rnd() : 0u);
        break;
    case OP_GATE:
        out[n++] = (uint8_t)(1u + rnd() % 7u);
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0u : rnd() % 2u == 0u ? 0x22u : 0x21u);
        break;
    default:
        break;
    }
    return n;
}

/* The op boundary at or before pos. */
static size_t boundary(const uint8_t *in, size_t len, size_t pos)
{
    size_t b = 0;
    for (size_t p = 0; p < len && p <= pos; p += op_size(in, len, p)) {
        b = p;
    }
    return b;
}

/* Writes a mutant of seed into out (PROG_MAX bytes) with 1-4 edits: bytes flipped or set, ops inserted, deleted,
 * repeated or taken from another seed, the tail cut; returns its length. */
static size_t mutate(const uint8_t *seed, size_t len, uint8_t *out)
{
    static const uint8_t INTERESTING[] = {0x00, 0x01, 0x02, 0x03, 0x07, 0x08, 0x0F, 0x10, 0x20, 0x30, 0x7F, 0x80,
                                          0xFE, 0xFF};
    static uint8_t op[4200];
    size_t n = len < PROG_MAX ? len : PROG_MAX;
    memcpy(out, seed, n);
    for (unsigned e = 1u + rnd() % 4u; e > 0u; e--) {
        const size_t at = n != 0u ? boundary(out, n, rnd() % n) : 0u;
        const size_t at_len = n != 0u ? (op_size(out, n, at) < n - at ? op_size(out, n, at) : n - at) : 0u;
        switch (rnd() % 10u) {
        case 0: case 1:
            if (n != 0u) {
                const size_t i = rnd() % n;
                out[i] ^= (uint8_t)(1u << (rnd() % 8u));
            }
            break;
        case 2: case 3:
            if (n != 0u) {
                const size_t i = rnd() % n;
                out[i] = INTERESTING[rnd() % sizeof INTERESTING];
            }
            break;
        case 4: {                                                     /* a byte inside the op at a boundary */
            if (at_len != 0u) {
                const size_t i = at + rnd() % (at_len < 16u ? at_len : 16u);
                out[i] = (uint8_t)rnd();
            }
            break;
        }
        case 5: case 6: {                                             /* a random op at a boundary */
            const size_t k = random_op(op);
            if (n + k <= PROG_MAX) {
                memmove(&out[at + k], &out[at], n - at);
                memcpy(&out[at], op, k);
                n += k;
            }
            break;
        }
        case 7:                                                       /* delete one op */
            memmove(&out[at], &out[at + at_len], n - at - at_len);
            n -= at_len;
            break;
        case 8:                                                       /* repeat one op */
            if (n + at_len <= PROG_MAX) {
                memmove(&out[at + at_len], &out[at], n - at);
                n += at_len;
            }
            break;
        default: {                                                    /* another seed's tail from a boundary */
            const size_t s = rnd() % g_seed_n;
            const uint8_t *src = &g_seeds[g_seed[s].off];
            const size_t from = g_seed[s].len != 0u ? boundary(src, g_seed[s].len, rnd() % g_seed[s].len) : 0u;
            const size_t k = (g_seed[s].len - from < PROG_MAX - at) ? g_seed[s].len - from : PROG_MAX - at;
            memcpy(&out[at], &src[from], k);
            n = at + k;
            break;
        }
        }
    }
    return n;
}

#if !defined(UDSOTA_FUZZ_LIBFUZZER)
/* Edits a delta's patch p (n bytes, PATCH_CAP of room) 1-4 times, as v0.14.2's fuzz_udsota_patch did: a bit flipped,
 * a byte set, the patch cut, 16 bytes inserted, up to 32 deleted, a byte of its type and sizes set, one of its header's
 * flipped, or up to 64 run on after its end; returns its new length. */
static size_t mutate_patch(uint8_t *p, size_t n)
{
    for (unsigned e = 1u + rnd() % 4u; e > 0u && n > 0u; e--) {
        const size_t at = rnd() % n;
        switch (rnd() % 8u) {
        case 0:
            p[at] ^= (uint8_t)(1u << (rnd() % 8u));
            break;
        case 1:
            p[at] = (uint8_t)rnd();
            break;
        case 2:
            n = at;
            break;
        case 3:
            if (n + 16u <= PATCH_CAP) {
                memmove(&p[at + 16u], &p[at], n - at);
                for (unsigned i = 0; i < 16u; i++) {
                    p[at + i] = (uint8_t)rnd();
                }
                n += 16u;
            }
            break;
        case 4: {
            const size_t k = 1u + rnd() % 32u;
            if (at + k <= n) {
                memmove(&p[at], &p[at + k], n - at - k);
                n -= k;
            }
            break;
        }
        case 5:                                                       /* after the 64-byte header */
            if (n >= 72u) {
                p[64u + rnd() % 8u] = (uint8_t)rnd();
            }
            break;
        case 6:
            p[rnd() % (n < 64u ? n : 64u)] ^= 0xFFu;
            break;
        default:
            for (unsigned k = 1u + rnd() % 64u; k > 0u && n < PATCH_CAP; k--) {
                p[n++] = (uint8_t)rnd();
            }
            break;
        }
    }
    return n;
}

/* A mutant of the delta's patch, deflated and sent after a 34 for the image in 36s of random lengths, then the 37,
 * FF01 and F1F1. The program is built after the seeds in their buffer, and dropped once run. */
static void run_delta_mutant(void)
{
    static uint8_t p[PATCH_CAP], z[PATCH_CAP + 1024u];
    memcpy(p, g_dp, g_dplen);
    const size_t zn = deflated(z, sizeof z, p, mutate_patch(p, g_dplen));
    const size_t mark = g_seeds_len;
    p_unlock_programming();
    p_download(UDSOTA_DL_DFI_DELTA_DEFLATE, IMG_LEN);
    uint8_t bsc = 1;
    for (size_t off = 0; off < zn; bsc++) {
        size_t k = rnd() % 4u == 0u ? 1u + rnd() % 64u : 1u + rnd() % 4093u;
        k = (k < zn - off) ? k : zn - off;
        p_block(0u, bsc, &z[off], k);
        off += k;
    }
    REQ(0x37);
    REQ(0x31, 0x01, 0xFF, 0x01);
    REQ(0x22, 0xF1, 0xF1);
    run_program(&g_seeds[mark], g_seeds_len - mark);
    g_seeds_len = mark;
}
#endif

/* ---- Entry points ---- */

static void harness_init(void)
{
    stamp(g_base, "1.0.0", HW_ID, 0x01u, 1u);
    stamp(g_img, "1.0.1", HW_ID, 0x01u, 2u);
    g_z = tdefl_compress_mem_to_heap(g_img, IMG_LEN, &g_zlen, TDEFL_DEFAULT_MAX_PROBES);
    g_dplen = patch_of(g_dp, g_img, k_chunks, sizeof k_chunks / sizeof k_chunks[0]);
    g_dz = tdefl_compress_mem_to_heap(g_dp, g_dplen, &g_dzlen, TDEFL_DEFAULT_MAX_PROBES);
    if (g_z == NULL || g_zlen < 600u || g_dz == NULL) {
        fprintf(stderr, "fuzz_udsota: no DEFLATE stream for the image or the delta\n");
        exit(2);
    }
    g_ds[0] = 0x01;                                    /* BFINAL, stored: LEN, NLEN, the bytes */
    g_ds[1] = (uint8_t)g_dplen;
    g_ds[2] = (uint8_t)(g_dplen >> 8);
    g_ds[3] = (uint8_t)~g_dplen;
    g_ds[4] = (uint8_t)(~g_dplen >> 8);
    memcpy(&g_ds[5], g_dp, g_dplen);
    g_dslen = 5u + g_dplen;
    build_seeds();
}

#if defined(UDSOTA_FUZZ_LIBFUZZER)
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    harness_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g_what = "libFuzzer";
    run_program(data, size);
    return 0;
}

/* Half of libFuzzer's mutations are its own, on bytes; the other half are mutate()'s, on ops. */
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed)
{
    static uint8_t out[PROG_MAX];
    if (seed % 2u == 0u || size == 0u) {
        return LLVMFuzzerMutate(data, size, max_size);
    }
    g_rng = seed | 1u;
    const size_t n = mutate(data, size < PROG_MAX ? size : PROG_MAX, out);
    memcpy(data, out, n < max_size ? n : max_size);
    return n < max_size ? n : max_size;
}
#else
/* ASan's and UBSan's reports end the run here too: keep the program they ended in. */
static void on_death(void)
{
    if (g_prog != NULL) {
        save_program();
        fprintf(stderr, "fuzz_udsota: %s program %lu is in fuzz_udsota-fail.bin\n", g_what, G.programs);
    }
}

/* Replays one file as a program. */
static void replay_file(const char *path)
{
    static uint8_t buf[PROG_MAX];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "fuzz_udsota: cannot read %s\n", path);
        exit(2);
    }
    const size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    g_what = path;
    run_program(buf, n);
}

/* Replays path: a file, or every file in a directory. */
static void replay_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        replay_file(path);
        return;
    }
    DIR *d = opendir(path);
    if (d == NULL) {
        fprintf(stderr, "fuzz_udsota: cannot open %s\n", path);
        exit(2);
    }
    for (struct dirent *e; (e = readdir(d)) != NULL;) {
        char p[4096];
        if (e->d_name[0] != '.' && (size_t)snprintf(p, sizeof p, "%s/%s", path, e->d_name) < sizeof p &&
            stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
            replay_file(p);
        }
    }
    closedir(d);
}

static void write_seeds(const char *dir)
{
    (void)mkdir(dir, 0777);
    for (size_t i = 0; i < g_seed_n; i++) {
        char p[4096];
        (void)snprintf(p, sizeof p, "%s/seed-%02zu", dir, i);
        FILE *f = fopen(p, "wb");
        if (f == NULL || fwrite(&g_seeds[g_seed[i].off], 1, g_seed[i].len, f) != g_seed[i].len) {
            fprintf(stderr, "fuzz_udsota: cannot write %s\n", p);
            exit(2);
        }
        fclose(f);
    }
    printf("fuzz_udsota: %zu seeds in %s\n", g_seed_n, dir);
}

/* What the replay reached. */
static void coverage(void)
{
    static const uint8_t SHOWN[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x28, 0x2E, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3E,
                                    0x85};
    printf("fuzz_udsota: reached %lu verified updates over DFI 00, %lu over DFI 10 and %lu over DFI 30, %lu activated, "
           "%lu confirmed, %lu restarts\n", G.verified[0], G.verified[1], G.verified[2], G.activated, G.confirmed,
           G.reboots);
    printf("fuzz_udsota: download reasons reported:");
    for (unsigned i = 0; i < 16u; i++) {
        printf(" %u:%lu", i, G.reasons[i]);
    }
    printf(", BAD_BASE %lu times with the running image's hash readable", G.wrong_base);
    printf("\nfuzz_udsota: answers by SID (positive/negative):");
    for (size_t i = 0; i < sizeof SHOWN; i++) {
        printf(" %02X:%lu/%lu", SHOWN[i], G.pos[SHOWN[i]], G.neg[SHOWN[i]]);
    }
    printf("\nfuzz_udsota: %lu answers, %lu 0x78s, %lu requests unanswered\n", G.answers, G.pendings, G.unanswered);
}

/* After the seeds alone: exits unless they reached every path they are there for, so that the mutants start from
 * them. */
static void seed_floor(void)
{
    static const uint8_t SIDS[] = {0x10, 0x11, 0x22, 0x27, 0x31, 0x34, 0x36, 0x37, 0x3E};
    static const uint8_t REASONS[] = {UDSOTA_DL_OK, UDSOTA_DL_BAD_BOARD, UDSOTA_DL_NOT_NEWER, UDSOTA_DL_BAD_PROJECT,
                                      UDSOTA_DL_VERIFY_FAILED, UDSOTA_DL_WORKER_TIMEOUT, UDSOTA_DL_ABORTED,
                                      UDSOTA_DL_FLASH_ERROR, UDSOTA_DL_BAD_STREAM};
    bool ok = G.verified[0] != 0u && G.verified[1] != 0u && G.activated != 0u && G.confirmed != 0u &&
              G.pendings != 0u;
#if UDSOTA_DELTA
    ok = ok && G.verified[2] != 0u && G.wrong_base != 0u &&     /* BAD_BASE for a wrong base, and an unreadable hash */
         G.reasons[UDSOTA_DL_BAD_BASE] > G.wrong_base;
#endif
    for (size_t i = 0; i < sizeof SIDS; i++) {
        ok = ok && G.pos[SIDS[i]] != 0u && G.neg[SIDS[i]] != 0u;
    }
    for (size_t i = 0; i < sizeof REASONS; i++) {
        ok = ok && G.reasons[REASONS[i]] != 0u;
    }
    if (!ok) {
        coverage();
        fprintf(stderr, "fuzz_udsota: FAIL: the seeds missed a path they are there for (above)\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    unsigned mutations = MUTATIONS_DEFAULT;
    const char *seed_dir = NULL;
    int first_file = argc;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mutations") == 0 && i + 1 < argc) {
            mutations = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            g_rng = (uint32_t)strtoul(argv[++i], NULL, 0) | 1u;
        } else if (strcmp(argv[i], "--write-seeds") == 0 && i + 1 < argc) {
            seed_dir = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "usage: fuzz_udsota [--mutations N] [--seed S] [-v] [--write-seeds DIR] [FILE|DIR ...]\n");
            return 2;
        } else {
            first_file = i;
            break;
        }
    }
    harness_init();
    if (seed_dir != NULL) {
        write_seeds(seed_dir);
        return 0;
    }
    __sanitizer_set_death_callback(on_death);
    if (first_file < argc) {
        for (int i = first_file; i < argc; i++) {
            replay_path(argv[i]);
        }
        coverage();
    } else {
        g_what = "seed";
        for (size_t i = 0; i < g_seed_n; i++) {
            run_program(&g_seeds[g_seed[i].off], g_seed[i].len);
        }
        seed_floor();
        static uint8_t buf[PROG_MAX];
        g_what = "mutant";
        for (size_t i = 0; i < g_seed_n; i++) {
            for (unsigned m = 0; m < mutations; m++) {
                run_program(buf, mutate(&g_seeds[g_seed[i].off], g_seed[i].len, buf));
            }
        }
        g_what = "random";
        for (unsigned i = 0; i < RANDOM_PROGRAMS; i++) {
            size_t n = 0;
            for (unsigned k = 4u + rnd() % 40u; k != 0u && n + 4200u < PROG_MAX; k--) {
                n += random_op(&buf[n]);
            }
            run_program(buf, n);
        }
        g_what = "delta mutant";
        for (unsigned i = 0; i < DELTA_PER_MUTANT * mutations; i++) {
            run_delta_mutant();
        }
        coverage();
    }
    g_prog = NULL;
    udsota_test_reboot();                             /* frees an inflater left open */
    mz_free(g_z);
    mz_free(g_dz);
    printf("fuzz_udsota: PASS %lu programs, %lu ops, %lu polls, %lu frames in, %lu out\n", G.programs, G.ops,
           G.polls, G.frames_in, G.frames_out);
    return 0;
}
#endif
