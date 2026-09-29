/* UDS request-parser fuzz harness. Feeds arbitrary bytes to
 * udsota_on_request from nine server states and fails unless the server never reads past
 * req_len, never writes past resp_max or into the request, and always answers with a well-formed
 * positive response, a known NRC, or nothing.
 *
 * This host has no libasan or clang, so guard pages (mmap + PROT_NONE) stand in for ASan: every
 * request sits flush against a guard page on one side, and every response buffer ends at one. UBSan
 * runs in trap mode (the top-level CMakeLists.txt), which needs no runtime library. A fork()ed self-test
 * proves each detector really kills the process before any replay counts as a pass.
 *
 * Inputs: built-in seeds, deterministic mutations of them, then every file named on the command line
 * (for example iso14229's libFuzzer corpus, used here only as arbitrary bytes). Sequence mode borrows
 * iso14229's fuzz_server.cc idea (MIT, Nick James Kirkby & Co-Operators): a stream of requests with
 * fuzzed waits between them. No iso14229 code is copied.
 *
 * Built four times, plus the no-update build below: fuzz_udsota with the app hooks NULL; fuzz_udsota_app_hooks (UDSOTA_FUZZ_APP_HOOKS=1) with
 * did_write, routine and routine_poll set, where it also checks that an app routine has exactly one owner;
 * fuzz_udsota_progress (UDSOTA_FUZZ_PROGRESS=1) with the progress hook set, where it also checks that done never
 * passes total nor shrinks within a download, and that the hook runs at most once per call and reports every
 * change of stage (its answers, and so its PASS line, are fuzz_udsota's); and fuzz_udsota_z (UDSOTA_FUZZ_Z=1 and
 * UDSOTA_FUZZ_PROGRESS=1), where the engine also serves compressed downloads (DFI 0x10) through udsota_zstream and
 * the real tinfl, the download states are reached with a compressed preamble, the generated inputs add raw DEFLATE
 * streams of random images, intact and mutated, sent as whole 34/36/37/FF01 sequences, and the progress checks
 * hold on the compressed path too.
 *
 * A fifth build, fuzz_udsota_no_update (UDSOTA_FUZZ_NO_UPDATE=1 with UDSOTA_FUZZ_APP_HOOKS=1), gives udsota_init a
 * NULL engine, so no update service is registered: it replays from the five states a download isn't needed for,
 * 34, 36 and 37 count as unserved and must only ever get NRC 0x11 (0x21 while an app routine runs), and its
 * coverage floor needs the reset and app hooks only.
 *
 * A sixth build, fuzz_udsota_dtc (UDSOTA_FUZZ_DTC=1), sets dtc_get, dtc_ext_data and dtc_clear over a table of
 * FUZZ_DTC_N DTCs with junk top bytes, so 19 and 14 are served: 19 02 FF and 19 0A outgrow the response buffer
 * (0x14, which the oracle takes from a 19 in this build alone) while 19 02 01 and 02 08 fit, the mocks fail on an
 * unknown DTC, a top byte or record 00 handed to dtc_ext_data, or an access state that is not the server's, and the
 * positive shapes check every status sent is a subset of the availability mask. Every walk ends at FUZZ_DTC_N, so
 * the index cap is test_index_cap's to pin, not this build's. The other five builds leave the DTC hooks NULL and
 * answer as they did without it.
 *
 * The PASS line ends with digest=, an FNV-1a hash of every request fed to the server and every answer it gave
 * (empty ones too), so an answer that changes shows there even where the counts don't. It draws no rnd().
 *
 * libFuzzer, on a machine with clang:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -DUDSOTA_LIBFUZZER <includes> fuzz_udsota.c
 *         <UDSOTA_SERVICES_SRCS> -o fuzz_udsota_lf && ./fuzz_udsota_lf -max_len=8192 <corpus>
 */
#define _DEFAULT_SOURCE   /* MAP_ANONYMOUS, sigaction, fork, prctl under -std=c11 */
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "udsota.h"
#ifdef UDSOTA_FUZZ_Z
#include "udsota_image.h"
#include "udsota_tinfl.h"
#include "udsota_zstream.h"
#include "miniz/miniz.h"   /* tdefl, to make the generated streams */
#endif

#ifndef UDSOTA_FUZZ_APP_HOOKS
#define UDSOTA_FUZZ_APP_HOOKS 0   /* 1: FUZZ_HOOKS also sets did_write, routine and routine_poll */
#endif
#ifndef UDSOTA_FUZZ_PROGRESS
#define UDSOTA_FUZZ_PROGRESS 0    /* 1: FUZZ_HOOKS also sets progress */
#endif
#ifndef UDSOTA_FUZZ_NO_UPDATE
#define UDSOTA_FUZZ_NO_UPDATE 0   /* 1: udsota_init gets a NULL engine, so no update service answers */
#endif
#ifndef UDSOTA_FUZZ_DTC
#define UDSOTA_FUZZ_DTC 0         /* 1: FUZZ_HOOKS also sets dtc_get, dtc_ext_data and dtc_clear */
#endif
#if UDSOTA_FUZZ_NO_UPDATE && (!UDSOTA_FUZZ_APP_HOOKS || UDSOTA_FUZZ_PROGRESS || defined(UDSOTA_FUZZ_Z))
#error "UDSOTA_FUZZ_NO_UPDATE needs UDSOTA_FUZZ_APP_HOOKS (0x31's positive answers) and no progress or z build"
#endif

/* Every engine and hook callback is mocked; these trip if the API structs gain a callback. */
_Static_assert(offsetof(udsota_engine_t, slot_size) == 12u * sizeof(void (*)(void)),
               "udsota_engine_t gained a callback: mock it in FUZZ_ENGINE and update this count");
_Static_assert(offsetof(udsota_engine_t, zformats) == offsetof(udsota_engine_t, zwritten) + sizeof(void (*)(void)) &&
               offsetof(udsota_engine_t, zformats) + _Alignof(udsota_engine_t) == sizeof(udsota_engine_t),
               "udsota_engine_t gained a member after zformats: mock it in FUZZ_ENGINE and move this check");
_Static_assert(offsetof(udsota_hooks_t, ctx) == 7u * sizeof(void (*)(void)),
               "udsota_hooks_t gained a callback: mock it in FUZZ_HOOKS and update this count");
_Static_assert(offsetof(udsota_hooks_t, dtc_clear) + sizeof(void (*)(void)) == sizeof(udsota_hooks_t),
               "udsota_hooks_t gained a member after dtc_clear: mock it in FUZZ_HOOKS and move this check");

#define REQ_MAX          UDSOTA_DL_MAX_BLOCK_LEN  /* the ISO-TP link never delivers a longer request */
#define RESP_FULL        256u                  /* UDSOTA_ISOTP_RESP_MAX: the transport's response buffer */
#define CANARY_LEN       64u                   /* bytes just before resp that must survive every call */
#define CANARY           0xA5u
#define SEQ_MAX_BYTES    65536u                /* a longer input is truncated for sequence mode */
#define SEQ_MAX_RECORDS  64u
#define SEQ_DT_UNIT_MS   25u                   /* a record's dt byte x 25 ms: up to 6.4 s, past S3 */
#define T0               60000u                /* 60 s after boot: past 0x27's post-boot delay */
#define JOB_MS           60u                   /* async mock: each queued op takes 60 ms, past the 40 ms 0x78 */
#define DL_SIZE          64u                   /* preamble download: two 32-byte blocks */
#define MUTATIONS_DEFAULT 400u                 /* mutants per built-in seed */
#define RANDOM_INPUTS    512u                  /* pure random inputs after the mutants */
#define VARIANT_COUNT    5u

typedef enum {                                 /* server states a replay starts from */
    ST_DEFAULT, ST_EXTENDED, ST_PROG, ST_EXT_UNLOCKED, ST_PROG_UNLOCKED,
    ST_DOWNLOAD, ST_TRANSFER, ST_EXITED, ST_VERIFIED, ST_COUNT
} state_t;
#if UDSOTA_FUZZ_NO_UPDATE
#define ST_FUZZED (ST_PROG_UNLOCKED + 1)       /* no download: the states from download-open on can't be reached */
#else
#define ST_FUZZED ST_COUNT                     /* the states a replay starts from */
#endif
static const char *const STATE_NAME[ST_COUNT] = {
    "default", "extended", "programming", "extended+01", "programming+03",
    "download-open", "mid-transfer", "transfer-exited", "image-verified",
};

typedef enum { LAYOUT_END, LAYOUT_START } layout_t;   /* request flush against the guard after / before it */

/* resp_max values a mutated or file input is answered into: each answer size (77 = 1, 7E/51/76 = 2, NRC = 3,
 * 74/71 = 4, 71+status = 5, 50 = 6, 67+seed = 18, 62+32 B = 35) both exactly and one byte short. */
static const size_t RESP_MAXES[] = {RESP_FULL, 64u, 35u, 34u, 19u, 18u, 17u, 6u, 5u, 4u, 3u, 2u, 1u, 0u};
#define RESP_MAX_COUNT (sizeof RESP_MAXES / sizeof RESP_MAXES[0])

typedef struct {
    uint8_t *page;                             /* first usable byte; PROT_NONE pages sit before and after */
    size_t   size;                             /* usable bytes, >= REQ_MAX + 1 */
} arena_t;

typedef struct {                               /* the mock platform behind the engine and hooks */
    bool     async;                            /* queued ops return UDSOTA_PENDING and finish JOB_MS later */
    uint32_t now;                              /* harness clock, for the async worker */
    bool     busy;
    uint32_t busy_until;
    unsigned rng_calls;
    unsigned resets;
    unsigned variant;                          /* this run's variant (VARIANT_COUNT of them) */
    bool     live;                             /* the preamble is done, so the variant applies */
    int      last_phase;                       /* the last phase the hook saw */
#if UDSOTA_FUZZ_APP_HOOKS
    bool     app_outstanding;                  /* routine returned UDSOTA_PENDING and routine_poll has not finished it */
    uint32_t app_until;                        /* when the outstanding app routine finishes */
#endif
#if UDSOTA_FUZZ_PROGRESS
    unsigned progress_calls;                   /* hooks.progress calls in the current server call */
    udsota_progress_t progress;                /* what hooks.progress last got (IDLE, 0 of 0 after init) */
#endif
#ifdef UDSOTA_FUZZ_Z
    int      job_result;                       /* async: the first failure of the queued zwrites, for engine.poll */
#endif
} mock_t;

typedef enum {                                 /* platform ops whose fuzz-phase calls the coverage floor counts */
    OP_BEGIN, OP_WRITE, OP_END, OP_ABORT, OP_ACTIVATE, OP_CONFIRM, OP_IMAGE_CHECK, OP_RESET, OP_UNVERIFY,
#if UDSOTA_FUZZ_APP_HOOKS
    OP_DID_WRITE, OP_ROUTINE, OP_ROUTINE_POLL,
#endif
#ifdef UDSOTA_FUZZ_Z
    OP_ZBEGIN, OP_ZWRITE, OP_ZEND,
#endif
#if UDSOTA_FUZZ_DTC
    OP_DTC_GET, OP_DTC_EXT_DATA, OP_DTC_CLEAR,
#endif
    OP_COUNT
} op_id_t;

typedef struct {                               /* counted outside the preamble only, so coverage is the fuzz's own */
    unsigned long inputs, runs, requests, positive, nrc, silent, poll_answers;
    unsigned long op_calls[OP_COUNT];
    bool pos_sid[256], nrc_sid[256], nrc_code[256], reached[ST_COUNT];
#if UDSOTA_FUZZ_APP_HOOKS
    bool app_orphaned;                         /* a fuzzed app routine reached the 90 s cap */
#endif
#if UDSOTA_FUZZ_NO_UPDATE
    bool dl_nrc11[3], dl_nrc21;                /* 34, 36, 37 got 0x11 (each), and one of them 0x21 during a job */
#endif
#if UDSOTA_FUZZ_PROGRESS
    bool stage_seen[UDSOTA_STAGE_ACTIVATING + 1];   /* stages hooks.progress reported from fuzzed calls */
    bool written_seen;                         /* a fuzzed block moved done past 0 */
#endif
} stats_t;

static arena_t      g_req, g_resp;
static mock_t       M;
static udsota_server_t S;
static stats_t      g_stats;
static uint8_t      g_staged[UDSOTA_DL_MAX_DATA]; /* ota_write copies its block here (engine.write contract) */
static uint8_t      g_pre_resp[RESP_FULL];     /* preamble answers (plain buffer) */
static char         g_label[256];              /* what is being replayed, for failure and crash reports */
static volatile unsigned g_rec;                /* sequence-mode record index, for crash reports */
static volatile uint8_t  g_sink;               /* every byte an op is handed is folded in here */
static bool         g_in_preamble;             /* reach() is running: answers are checked but not counted */
static uint64_t     g_digest = 0xCBF29CE484222325u; /* FNV-1a 64 over every exchange with the server */

/* Folds one exchange into g_digest: a tag ('Q' request, 'A' its answer, 'P' a poll's answer), the length as 8
 * bytes little-endian, then the bytes. Reads only, so it changes nothing the server or the mutator sees. */
static void digest_fold(uint8_t tag, const uint8_t *b, size_t n)
{
    uint8_t head[9] = {tag};
    for (unsigned i = 0; i < 8u; i++) {
        head[1u + i] = (uint8_t)((uint64_t)n >> (8u * i));
    }
    uint64_t h = g_digest;
    for (size_t i = 0; i < sizeof head + n; i++) {
        h = (h ^ (i < sizeof head ? head[i] : b[i - sizeof head])) * 0x100000001B3u;
    }
    g_digest = h;
}

/* Counts one fuzz-phase call of op for the coverage floor; preamble calls do not count. */
static void count_op(op_id_t op)
{
    if (!g_in_preamble) {
        g_stats.op_calls[op]++;
    }
}

/* Prints a harness error (not a server defect) and exits 2. */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("fuzz_udsota: HARNESS ERROR: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

/* Prints up to 48 bytes of b as hex after a tag. */
static void dump(const char *tag, const uint8_t *b, size_t n)
{
    fprintf(stderr, "  %s (%zu B):", tag, n);
    for (size_t i = 0; i < n && i < 48u; i++) {
        fprintf(stderr, " %02X", b[i]);
    }
    fputs(n > 48u ? " ...\n" : "\n", stderr);
}

/* Reports a server defect with the input that caused it, then exits 1. */
static void fail(const char *what, const uint8_t *req, size_t rl, const uint8_t *resp, size_t n)
{
    fprintf(stderr, "fuzz_udsota: FAIL: %s\n  while replaying %s, record %u\n", what, g_label, g_rec);
    if (req != NULL) {
        dump("request", req, rl);
    }
    if (resp != NULL) {
        dump("response", resp, n);
    }
    exit(1);
}

/* Maps a usable region of at least REQ_MAX + 1 bytes between two PROT_NONE guard pages. */
static void arena_init(arena_t *a)
{
    const long ps_l = sysconf(_SC_PAGESIZE);
    if (ps_l <= 0) {
        die("sysconf(_SC_PAGESIZE) failed");
    }
    const size_t ps = (size_t)ps_l;
    const size_t size = ((REQ_MAX + 1u + ps - 1u) / ps) * ps;
    uint8_t *base = mmap(NULL, size + 2u * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED || mprotect(base, ps, PROT_NONE) != 0 ||
        mprotect(base + ps + size, ps, PROT_NONE) != 0) {
        die("mmap/mprotect of a guard arena failed");
    }
    a->page = base + ps;
    a->size = size;
}

/* Makes an arena's usable bytes read-only (the server gets a const request) or writable again. */
static void arena_protect(const arena_t *a, bool read_only)
{
    if (mprotect(a->page, a->size, read_only ? PROT_READ : (PROT_READ | PROT_WRITE)) != 0) {
        die("mprotect failed");
    }
}

/* Reads every byte of p[0..n), so a pointer or length past the request faults on the guard page. */
static void touch(const uint8_t *p, size_t n)
{
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++) {
        x ^= p[i];
    }
    g_sink ^= x;
}

/* Models the flash worker: sync mode finishes at once with 0; async mode queues FIFO work of JOB_MS. */
static int queue_job(void)
{
    if (!M.async) {
        return 0;
    }
#ifdef UDSOTA_FUZZ_Z
    if (!M.busy || (int32_t)(M.now - M.busy_until) >= 0) {
        M.job_result = 0;                      /* a new batch */
    }
#endif
    const uint32_t start = M.busy ? M.busy_until : M.now;
    M.busy_until = start + JOB_MS;
    M.busy = true;
    return UDSOTA_PENDING;
}

/* The seed mock_rng16 hands out on its call-th call in a run: deterministic, never all zero. */
static void mock_seed(unsigned call, uint8_t out[16])
{
    for (unsigned i = 0; i < 16u; i++) {
        out[i] = (uint8_t)(0x11u * (i + 1u) + call);
    }
    out[0] |= 0x01u;
}

/* The 0x27 seed a real RNG would give: mock_seed of this run's call count. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    mock_seed(M.rng_calls++, out);
    return true;
}

/* The key the server expects: seed[i] ^ level ^ 0xA5, the stand-in the server tests use for HMAC. */
static void fake_key(const uint8_t *seed, uint8_t level, uint8_t out[16])
{
    for (unsigned i = 0; i < 16u; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5u);
    }
}

/* Mock security.key: reads all 16 seed bytes and returns fake_key. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    touch(seed, UDSOTA_SEED_LEN);
    fake_key(seed, level, out);
    return true;
}

/* Mock ota_begin: queued like the ESP op. */
static int mock_ota_begin(void *ctx, uint32_t size)
{
    count_op(OP_BEGIN);
    return queue_job();
}

/* Mock engine.write: copies the block before returning (engine.write contract), reading every byte it was handed. */
static int mock_ota_write(void *ctx, uint32_t off, const uint8_t *data, size_t len)
{
    count_op(OP_WRITE);
    if (len > sizeof g_staged) {
        fail("ota_write handed more than UDSOTA_DL_MAX_DATA bytes", NULL, 0, NULL, 0);
    }
    memcpy(g_staged, data, len);
    return queue_job();
}

/* Mock ota_end (FF01's verify): queued; the job result is UDSOTA_DL_OK (0). */
static int mock_ota_end(void *ctx)
{
    count_op(OP_END);
    return queue_job();
}

#ifdef UDSOTA_FUZZ_Z
static udsota_zstream_t g_zs;                  /* the compressed download the z ops run */
static void z_close(void);
#endif

/* Mock engine.abort: queued; the server never waits on it. The z build also frees any open stream. */
static void mock_ota_abort(void *ctx)
{
    count_op(OP_ABORT);
    (void)queue_job();
#ifdef UDSOTA_FUZZ_Z
    z_close();
#endif
}

/* Mock ota_activate (F001's set_boot): queued; the job result is 0. */
static int mock_ota_activate(void *ctx)
{
    count_op(OP_ACTIVATE);
    return queue_job();
}

/* Mock ota_confirm (F002): queued; the job result is 0. */
static int mock_ota_confirm(void *ctx)
{
    count_op(OP_CONFIRM);
    return queue_job();
}

/* Mock ota_unverify: synchronous, like the ESP op; only counted. */
static void mock_ota_unverify(void *ctx)
{
    count_op(OP_UNVERIFY);
}

/* Mock image_check: reads every byte; a first byte of 0x00 fails as UDSOTA_DL_BAD_HEADER, anything else passes. */
static int mock_image_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *reason)
{
    count_op(OP_IMAGE_CHECK);
    touch(first, len);
    if (len == 0 || first[0] == 0x00u) {
        *reason = UDSOTA_DL_BAD_HEADER;
        return 1;
    }
    *reason = UDSOTA_DL_OK;
    return 0;
}

/* The app's DIDs the mock serves through hooks.did_read, with fixed lengths; F189, F18C, F1F0 and F1F3 are
 * the server's own (engine and config). */
static const struct { uint16_t did; uint8_t len; uint8_t fill; } DIDS[] = {
    {0xF191u, 4u, 'w'}, {0xF1B0u, UDSOTA_SHA256_LEN, 0x8Cu}, {0xF1B1u, 3u, 0x01u},
    {0x0200u, 1u, 0x00u}, {0x0201u, 1u, 0x01u}, {0x0202u, 2u, 0x09u}, {0x0203u, 2u, 0x09u}, {0x0204u, 2u, 0x0Eu},
};

/* Mock hooks.did_read: first writes all max bytes it was offered (so an oversized max faults on the guard page), then
 * the DID, or only its length when max is short (0x14). */
static size_t mock_did_read(void *ctx, uint16_t did, uint8_t *out, size_t max)
{
    memset(out, 0xDD, max);
    for (size_t i = 0; i < sizeof DIDS / sizeof DIDS[0]; i++) {
        if (DIDS[i].did == did) {
            if (DIDS[i].len <= max) {
                memset(out, DIDS[i].fill, DIDS[i].len);
            }
            return DIDS[i].len;
        }
    }
    return 0;
}

/* Mock hooks.reset: counts it; the chip would restart here. */
static bool mock_reset(void *ctx)
{
    count_op(OP_RESET);
    M.resets++;
    return true;
}

/* Mock tx_pending: the bus is always drained. */
static uint32_t mock_tx_pending(void *ctx)
{
    return 0;
}

/* Mock engine.poll: UDSOTA_PENDING until the async worker's queue drains, then 0 (the z build: the batch's first
 * zwrite failure). */
static int mock_job_poll(void *ctx)
{
    if (M.busy && (int32_t)(M.now - M.busy_until) < 0) {
        return UDSOTA_PENDING;
    }
    M.busy = false;
#ifdef UDSOTA_FUZZ_Z
    return M.job_result;
#else
    return 0;
#endif
}

#define FUZZ_GATE_NRC 0x88u   /* vehicleSpeedTooHigh: variant 2's NRC, one the core never sends itself */

/* Mock engine.status: slot 0 running and booting, VALID; PENDING_VERIFY in variant 4 once the preamble is done
 * (ConfirmImage's core precondition, as the old running_pending_verify variant was). */
static void mock_status(void *ctx, udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->running_slot = UDSOTA_SLOT_OTA0;
    out->boot_slot = UDSOTA_SLOT_OTA0;
    out->running_state = (M.live && M.variant == 4u) ? UDSOTA_IMG_PENDING_VERIFY : UDSOTA_IMG_VALID;
}

/* Mock engine.version: first writes every byte it was offered (an oversized max faults on the guard page), then
 * 18 bytes of 'v'; when max is short, only the length (0x14). */
static size_t mock_version(void *ctx, char *out, size_t max)
{
    memset(out, 0xDD, max);
    if (max >= 18u) {
        memset(out, 'v', 18u);
    }
    return 18u;
}

/* Mock engine.running_sha: the same guard write, then 32 bytes of 0xA3, or only the length when max is short. */
static size_t mock_running_sha(void *ctx, uint8_t *out, size_t max)
{
    memset(out, 0xDD, max);
    if (max >= UDSOTA_SHA256_LEN) {
        memset(out, 0xA3, UDSOTA_SHA256_LEN);
    }
    return UDSOTA_SHA256_LEN;
}

/* Mock hooks.gate: allows during the preamble; afterwards variant 1 (a second device on the IDs; fuzz_poll also calls udsota_end_session) answers 0x22 to every op, 2 answers 0x88
 * (passed through verbatim), 3 answers 0x21 busy-repeat, and 0 and 4 allow. An op outside udsota_op_t is a defect. */
static uint8_t mock_gate(void *ctx, udsota_op_t op)
{
    static const uint8_t NRC[VARIANT_COUNT] = {0x00u, 0x22u, FUZZ_GATE_NRC, 0x21u, 0x00u};
    const unsigned o = (unsigned)op;
    if (o < (unsigned)UDSOTA_OP_ENTER_EXTENDED || o > (unsigned)UDSOTA_OP_CONFIRM) {
        fail("gate asked about an op outside udsota_op_t", NULL, 0, NULL, 0);
    }
    return M.live ? NRC[M.variant] : 0u;
}

/* Mock hooks.phase: the phase must be one of the five and must differ from the last one reported. */
static void mock_phase(void *ctx, udsota_phase_t p)
{
    if ((unsigned)p > (unsigned)UDSOTA_PHASE_ACTIVATING || (int)p == M.last_phase) {
        fail("phase hook called with an unknown phase or without a change", NULL, 0, NULL, 0);
    }
    M.last_phase = (int)p;
}

#if UDSOTA_FUZZ_PROGRESS
/* Mock hooks.progress: a known stage, done <= total, 0 of 0 outside ERASING and WRITING, and within one download
 * a done that never shrinks. Consecutive WRITING reports belong to one download, since a new 34 is reported as
 * ERASING first. */
static void mock_progress(void *ctx, const udsota_progress_t *p)
{
    const udsota_progress_t last = M.progress;
    M.progress_calls++;
    M.progress = *p;
    if ((unsigned)p->stage > (unsigned)UDSOTA_STAGE_ACTIVATING || p->done > p->total ||
        (p->total != 0u && p->stage != UDSOTA_STAGE_ERASING && p->stage != UDSOTA_STAGE_WRITING) ||
        (p->stage == UDSOTA_STAGE_ERASING && p->done != 0u)) {
        fail("progress hook got an unknown stage, done past total, or bytes outside a transfer", NULL, 0, NULL, 0);
    }
    if (p->stage == UDSOTA_STAGE_WRITING && last.stage == UDSOTA_STAGE_WRITING &&
        (p->done < last.done || p->total != last.total)) {
        fail("progress done shrank, or total changed, within one download", NULL, 0, NULL, 0);
    }
    if (!g_in_preamble) {
        g_stats.stage_seen[p->stage] = true;
        g_stats.written_seen = g_stats.written_seen || p->done != 0u;
    }
}
#endif

#if UDSOTA_FUZZ_APP_HOOKS
#define APP_RID_SYNC     0x1234u   /* answers 71 01 12 34 00 at once */
#define APP_RID_PENDING  0x1235u   /* pending for JOB_MS, then 71 01 12 35 00 */
#define APP_RID_HOLD     0x1236u   /* pending for APP_HOLD_MS: past the 90 s cap, so the core orphans it */
#define APP_RID_REFUSE   0x1237u   /* NRC 0x22 */
#define APP_HOLD_MS      100000u

/* Fails unless access is the server's own session, lock and epoch, and not the default session (the core
 * answers 0x7F there before any hook). */
static void check_access(udsota_access_t access)
{
    if (access.session == UDSOTA_SESSION_DEFAULT || access.session != S.session ||
        access.unlocked_level != S.security || access.epoch != S.session_epoch) {
        fail("app hook handed an access state that is not the server's", NULL, 0, NULL, 0);
    }
}

/* Mock hooks.did_write: reads every byte it was handed; 0x0200 takes 1 byte and 0x0202 takes 2, else 0x31. */
static uint8_t mock_did_write(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access)
{
    count_op(OP_DID_WRITE);
    check_access(access);
    touch(data, len);
    if ((did == 0x0200u && len == 1u) || (did == 0x0202u && len == 2u)) {
        return 0u;
    }
    return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
}

/* Writes the app's one status byte 00 into out when it has room; returns the record length. */
static size_t app_status(uint8_t *out, size_t out_max)
{
    if (out_max == 0u) {
        return 0u;
    }
    out[0] = 0x00u;
    return 1u;
}

/* Mock hooks.routine: reads the whole option record and writes all of out_max (an oversized one faults on a guard
 * page), then answers by RID. Never called for a core RID or while an app routine is outstanding. */
static int mock_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    count_op(OP_ROUTINE);
    check_access(access);
    if (M.app_outstanding) {
        fail("routine called while an app routine was outstanding", NULL, 0, NULL, 0);
    }
#if !UDSOTA_FUZZ_NO_UPDATE   /* with no update service its RIDs are the app's, answered 0x31 below */
    if (rid == UDSOTA_RID_CHECK_PROG_DEPS || rid == UDSOTA_RID_GET_RESUME_POINT ||
        rid == UDSOTA_RID_ACTIVATE_IMAGE || rid == UDSOTA_RID_CONFIRM_IMAGE) {
        fail("routine handed a RID the core owns", NULL, 0, NULL, 0);
    }
#endif
    touch(in, in_len);
    memset(out, 0xDD, out_max);
    switch (rid) {
    case APP_RID_SYNC:
        *out_len = app_status(out, out_max);
        return 0;
    case APP_RID_PENDING:
    case APP_RID_HOLD:
        M.app_outstanding = true;
        M.app_until = M.now + (rid == APP_RID_HOLD ? APP_HOLD_MS : JOB_MS);
        return UDSOTA_PENDING;
    case APP_RID_REFUSE:
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    default:
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
}

/* Mock hooks.routine_poll: writes all of out_max, then UDSOTA_PENDING until app_until, else finishes with status
 * 00. Only ever called while an app routine is outstanding. */
static int mock_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    count_op(OP_ROUTINE_POLL);
    if (!M.app_outstanding) {
        fail("routine_poll called with no app routine outstanding", NULL, 0, NULL, 0);
    }
    memset(out, 0xDD, out_max);
    if ((int32_t)(M.now - M.app_until) < 0) {
        return UDSOTA_PENDING;
    }
    M.app_outstanding = false;
    *out_len = app_status(out, out_max);
    return 0;
}
#endif

/* hooks.comm_control: refuses disableRxAndTx with 0x22, allows the rest. */
static uint8_t mock_comm_control(void *ctx, uint8_t control, uint8_t comm_type)
{
    (void)ctx;
    (void)comm_type;
    return control == UDSOTA_CC_DISABLE_RX_TX ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : 0u;
}

/* hooks.dtc_setting: nothing to record. */
static void mock_dtc_setting(void *ctx, bool on)
{
    (void)ctx;
    (void)on;
}

#if UDSOTA_FUZZ_DTC
#define FUZZ_DTC_N      90u    /* 19 0A and 19 02 FF outgrow 256 B; 19 02 01 and 02 08 fit */
#define FUZZ_DTC_AVAIL  0x2Fu  /* FUZZ_CFG's availability mask */

/* The i-th DTC's 24 bits: U0000 up by code, the failure-type byte i on every third, else 00; all distinct. */
static uint32_t fuzz_dtc24(size_t i)
{
    return 0xC00000u | ((uint32_t)i << 8) | ((i % 3u == 0u) ? 0u : (uint32_t)i);
}

/* hooks.dtc_get: FUZZ_DTC_N DTCs with a junk top byte, statuses cycling through 00, 01, 2F, 08, 40, 09, FF and 28.
 * An index at the cap is a defect, but the core's walks stop at FUZZ_DTC_N first, so only a walk that skipped ahead
 * would reach it; test_index_cap pins the cap itself. */
static bool mock_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    static const uint8_t STATUS[8] = {0x00, 0x01, 0x2F, 0x08, 0x40, 0x09, 0xFF, 0x28};
    count_op(OP_DTC_GET);
    if (i >= UDSOTA_DTC_INDEX_MAX) {
        fail("dtc_get asked for an index at UDSOTA_DTC_INDEX_MAX or past it", NULL, 0, NULL, 0);
    }
    if (i >= FUZZ_DTC_N) {
        return false;
    }
    out->dtc = ((uint32_t)(uint8_t)(0x5Bu + 7u * i) << 24) | fuzz_dtc24(i);
    out->status = STATUS[i % 8u];
    return true;
}

/* hooks.dtc_ext_data: first writes all of max (an oversized one faults on the guard page), then record 01 is 01 AB,
 * 02 is held with no data, FF is every record with data (01 AB) or 0x14, 7E sets *len to max + 1 (the core's 0x10)
 * and any other is 0x31. A DTC dtc_get doesn't report, a top byte or record 00 is a defect. */
static uint8_t mock_dtc_ext_data(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len)
{
    count_op(OP_DTC_EXT_DATA);
    bool known = false;
    for (size_t i = 0; i < FUZZ_DTC_N && !known; i++) {
        known = (fuzz_dtc24(i) & 0xFFFFFFu) == dtc;
    }
    if (!known || record == 0x00u) {
        fail("dtc_ext_data handed a DTC dtc_get doesn't report, a top byte, or record 00", NULL, 0, NULL, 0);
    }
    memset(buf, 0xDD, max);
    switch (record) {
    case 0x01:
    case UDSOTA_DTC_RECORD_ALL:
        if (max < 2u) {
            return UDSOTA_NRC_RESPONSE_TOO_LONG;
        }
        buf[0] = 0x01;
        buf[1] = 0xAB;
        *len = 2u;
        return 0u;
    case 0x02:
        *len = 0u;
        return 0u;
    case 0x7E:
        *len = max + 1u;
        return 0u;
    default:
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
}

/* hooks.dtc_clear: the access state must be the server's own; clears group FFFFFF (0x22 in variant 1, a second
 * device on the IDs), and any other group is 0x31. */
static uint8_t mock_dtc_clear(void *ctx, uint32_t group, udsota_access_t access)
{
    count_op(OP_DTC_CLEAR);
    if (access.session != S.session || access.unlocked_level != S.security || access.epoch != S.session_epoch ||
        group > 0xFFFFFFu) {
        fail("dtc_clear handed an access state that is not the server's, or a group past 24 bits", NULL, 0, NULL, 0);
    }
    if (group != UDSOTA_DTC_GROUP_ALL) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    return (M.live && M.variant == 1u) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : 0u;
}
#endif

#ifdef UDSOTA_FUZZ_Z
/* ---- Compressed downloads: udsota_zstream over the real tinfl, into the mock flash ops ---- */

#define Z_OUT_LEN   512u                        /* a small stream buffer, so an image takes many writes */
#define Z_MAPS      4u                          /* inflater allocations live at once: the state and the dictionary */
static udsota_tinfl_t g_tinfl;
static arena_t        g_zarena;                 /* holds g_zout flush against its end guard page */
static uint8_t       *g_zout;                   /* Z_OUT_LEN bytes; a write past them faults */
static long           g_z_live;                 /* inflater allocations not yet freed */
static unsigned long  g_z_allocs;
static struct { uint8_t *p, *base; size_t len; } g_zmaps[Z_MAPS];   /* each allocation's own guarded mapping */
static const uint8_t *g_z_expect;               /* an intact generated stream's image, for the output oracle */
static size_t         g_z_expect_len;

/* The inflater's allocations, each flush against a PROT_NONE page (16-byte aligned, so an overrun of up to 15 bytes
 * goes unseen); every 5th fails once the preamble is done, for 34's 0x22 path. */
static void *z_alloc(void *ctx, size_t n)
{
    if (!g_in_preamble && ++g_z_allocs % 5u == 0u) {
        return NULL;
    }
    const size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    const size_t used = (n + 15u) & ~(size_t)15u;
    const size_t len = ((used + ps - 1u) / ps + 1u) * ps;
    for (size_t i = 0; i < Z_MAPS; i++) {
        if (g_zmaps[i].p == NULL) {
            uint8_t *base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (base == MAP_FAILED || mprotect(base + len - ps, ps, PROT_NONE) != 0) {
                die("mmap/mprotect of an inflater allocation failed");
            }
            g_zmaps[i].base = base;
            g_zmaps[i].len = len;
            g_zmaps[i].p = base + len - ps - used;
            g_z_live++;
            return g_zmaps[i].p;
        }
    }
    fail("the inflater holds more than Z_MAPS allocations", NULL, 0, NULL, 0);
    return NULL;
}

/* Frees one inflater allocation: unmaps it, so a later use faults. */
static void z_free(void *ctx, void *p)
{
    for (size_t i = 0; i < Z_MAPS; i++) {
        if (g_zmaps[i].p == p) {
            munmap(g_zmaps[i].base, g_zmaps[i].len);
            g_zmaps[i].p = NULL;
            g_z_live--;
            return;
        }
    }
    fail("the inflater freed memory it was never given", NULL, 0, NULL, 0);
}

/* Closes the open stream, if any, and checks nothing is left allocated. */
static void z_close(void)
{
    udsota_zstream_close(&g_zs);
    if (g_z_live != 0) {
        fail("the inflater leaked or double-freed memory", NULL, 0, NULL, 0);
    }
}

/* Sink begin: the erase, synchronous on the worker. */
static int z_sink_begin(void *ctx, uint32_t size)
{
    count_op(OP_BEGIN);
    return 0;
}

/* Sink write: reads every byte it is handed, which must fit the stream's buffer and, for an intact generated stream,
 * be the image's own bytes at that offset. */
static int z_sink_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    count_op(OP_WRITE);
    if (n > Z_OUT_LEN) {
        fail("the stream wrote more than its buffer holds", NULL, 0, NULL, 0);
    }
    touch(d, n);
    if (g_z_expect != NULL && !g_in_preamble && g_zs.image.size == g_z_expect_len &&
        ((size_t)off + n > g_z_expect_len || memcmp(d, g_z_expect + off, n) != 0)) {
        fail("the stream wrote bytes the image does not hold at that offset", NULL, 0, d, n);
    }
    return 0;
}

/* engine.zbegin: opens a stream over tinfl and the mock sink. */
static int mock_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    (void)dfi;
    count_op(OP_ZBEGIN);
    z_close();                                  /* the server released the last one: nothing may be open */
    g_tinfl.alloc = z_alloc;
    g_tinfl.free = z_free;
    const udsota_inflate_t inf = udsota_tinfl_inflate(&g_tinfl);
    const udsota_zsink_t sink = {.check_first = mock_image_check, .begin = z_sink_begin, .write = z_sink_write};
    return (int)udsota_zstream_open(&g_zs, &inf, &sink, g_zout, Z_OUT_LEN, size);
}

/* engine.zwrite: inflates on the "worker": at once, or queued with its result kept for engine.poll. */
static int mock_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    count_op(OP_ZWRITE);
    touch(d, n);
    const int r = (int)udsota_zstream_feed(&g_zs, d, n);
    if (!M.async) {
        return r;
    }
    const int q = queue_job();
    if (r != 0 && M.job_result == 0) {
        M.job_result = r;
    }
    return q;
}

/* engine.zwritten: the image bytes the stream has written, for progress. */
static uint32_t mock_zwritten(void *ctx)
{
    return g_zs.image.written;
}

/* engine.zend: the 37 check; frees the stream. */
static int mock_zend(void *ctx)
{
    count_op(OP_ZEND);
    const int r = (int)udsota_zstream_end(&g_zs);
    z_close();
    return r;
}
#endif

static const uint8_t FUZZ_SERIAL[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const udsota_config_t FUZZ_CFG = {
    .stmin_monitor = true, .device_id = FUZZ_SERIAL, .device_id_len = sizeof FUZZ_SERIAL,
#if UDSOTA_FUZZ_DTC
    .dtc_availability_mask = FUZZ_DTC_AVAIL, .dtc_format = 0x00u,
#endif
};
static const udsota_engine_t FUZZ_ENGINE = {
    .check_first = mock_image_check, .begin = mock_ota_begin, .write = mock_ota_write, .verify = mock_ota_end,
    .activate = mock_ota_activate, .confirm = mock_ota_confirm, .abort = mock_ota_abort,
    .unverify = mock_ota_unverify, .poll = mock_job_poll, .status = mock_status,
    .running_sha = mock_running_sha, .version = mock_version, .slot_size = 0u, .ctx = NULL,
#ifdef UDSOTA_FUZZ_Z
    .zbegin = mock_zbegin, .zwrite = mock_zwrite, .zend = mock_zend, .zwritten = mock_zwritten,
    .zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE),
#endif
};
static const udsota_security_t FUZZ_SECURITY = {.rng16 = mock_rng16, .key = mock_key, .ctx = NULL};
static const udsota_hooks_t FUZZ_HOOKS = {
    .gate = mock_gate, .phase = mock_phase, .did_read = mock_did_read, .stmin_us = NULL, .reset = mock_reset,
    .comm_control = mock_comm_control, .dtc_setting = mock_dtc_setting, .ctx = NULL,
#if UDSOTA_FUZZ_APP_HOOKS
    .did_write = mock_did_write, .routine = mock_routine, .routine_poll = mock_routine_poll,
#endif
#if UDSOTA_FUZZ_PROGRESS
    .progress = mock_progress,
#endif
#if UDSOTA_FUZZ_DTC
    .dtc_get = mock_dtc_get, .dtc_ext_data = mock_dtc_ext_data, .dtc_clear = mock_dtc_clear,
#endif
};

#if UDSOTA_FUZZ_NO_UPDATE
/* 0 for 34, 1 for 36, 2 for 37 (the update service's SIDs), -1 for any other SID. */
static int dl_sid_index(uint8_t sid)
{
    return sid == UDSOTA_SID_REQUEST_DOWNLOAD ? 0 : sid == UDSOTA_SID_TRANSFER_DATA ? 1
         : sid == UDSOTA_SID_TRANSFER_EXIT ? 2 : -1;
}
#endif

/* True for the SIDs the server serves. check_request_answer fails a positive answer to any other SID, but takes any
 * known NRC for it; only the digest pins which (check_no_update pins 34, 36 and 37 without the update service). */
static bool sid_served(uint8_t sid)
{
#if UDSOTA_FUZZ_NO_UPDATE
    if (dl_sid_index(sid) >= 0) {
        return false;                          /* the update service's: none is registered */
    }
#endif
    switch (sid) {
    case UDSOTA_SID_SESSION: case UDSOTA_SID_RESET: case UDSOTA_SID_READ_DID: case UDSOTA_SID_SECURITY:
    case UDSOTA_SID_ROUTINE: case UDSOTA_SID_REQUEST_DOWNLOAD: case UDSOTA_SID_TRANSFER_DATA:
    case UDSOTA_SID_TRANSFER_EXIT: case UDSOTA_SID_TESTER_PRESENT: case UDSOTA_SID_COMM_CONTROL:
    case UDSOTA_SID_DTC_SETTING:
#if UDSOTA_FUZZ_APP_HOOKS
    case UDSOTA_SID_WRITE_DID:
#endif
#if UDSOTA_FUZZ_DTC
    case UDSOTA_SID_READ_DTC: case UDSOTA_SID_CLEAR_DTC:
#endif
        return true;
    default:
        return false;
    }
}

/* True for the NRCs udsota.h defines but 0x14, which too_long_ok takes from a 22 or a 19 alone; anything else on the
 * wire is a server defect. */
static bool nrc_known(uint8_t nrc)
{
    switch (nrc) {
    case UDSOTA_NRC_GENERAL_REJECT: case UDSOTA_NRC_SERVICE_NOT_SUPPORTED: case UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED:
    case UDSOTA_NRC_INCORRECT_LENGTH: case UDSOTA_NRC_BUSY_REPEAT:
    case UDSOTA_NRC_CONDITIONS_NOT_CORRECT:
    case UDSOTA_NRC_REQUEST_SEQUENCE_ERROR: case UDSOTA_NRC_REQUEST_OUT_OF_RANGE:
    case UDSOTA_NRC_SECURITY_ACCESS_DENIED: case UDSOTA_NRC_INVALID_KEY: case UDSOTA_NRC_EXCEEDED_ATTEMPTS:
    case UDSOTA_NRC_TIME_DELAY_NOT_EXPIRED: case UDSOTA_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED:
    case UDSOTA_NRC_TRANSFER_DATA_SUSPENDED: case UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE:
    case UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER: case UDSOTA_NRC_RESPONSE_PENDING:
    case UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION: case UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION:
        return true;
    default:
        return false;
    }
}

/* A known NRC, or the gate's own NRC in the variant that sends it. */
static bool nrc_ok(uint8_t nrc)
{
    return nrc_known(nrc) || (M.live && M.variant == 2u && nrc == FUZZ_GATE_NRC);
}

/* True for 0x14 responseTooLong to a 22 (a DID longer than the answer buffer) or, in the DTC build, a 19, the only
 * answers the core sends it in; the other five builds never serve 19, and it is a defect from a poll. */
static bool too_long_ok(uint8_t sid, uint8_t nrc)
{
    if (nrc != UDSOTA_NRC_RESPONSE_TOO_LONG) {
        return false;
    }
#if UDSOTA_FUZZ_DTC
    return sid == UDSOTA_SID_READ_DID || sid == UDSOTA_SID_READ_DTC;
#else
    return sid == UDSOTA_SID_READ_DID;
#endif
}

#if UDSOTA_FUZZ_DTC
/* 59 02 and 59 0A after the echo: whole <DTC> <status> entries, each status a subset of the availability mask and,
 * for 02, sharing a bit with the request's mask (status & mask & availability != 0, as status is already masked). */
static bool dtc_list_ok(uint8_t sub, uint8_t mask, const uint8_t *r, size_t n)
{
    if (n < 3u || (n - 3u) % 4u != 0u || r[2] != FUZZ_DTC_AVAIL) {
        return false;
    }
    for (size_t k = 3u; k < n; k += 4u) {
        const uint8_t st = r[k + 3u];
        if ((st & (uint8_t)~FUZZ_DTC_AVAIL) != 0u || (sub == UDSOTA_RDTC_BY_MASK && (st & mask) == 0u)) {
            return false;
        }
    }
    return true;
}

/* 59 xx for a 19 request: 01's count with the availability and format 00, 02 and 0A's lists, 06's DTC echo and a
 * masked status. */
static bool dtc_shape_ok(const uint8_t *req, size_t rl, uint8_t sub, const uint8_t *r, size_t n)
{
    if (n < 2u || r[1] != sub) {
        return false;
    }
    switch (sub) {
    case UDSOTA_RDTC_COUNT_BY_MASK:
        return n == 6u && rl == 3u && r[2] == FUZZ_DTC_AVAIL && r[3] == 0x00u;
    case UDSOTA_RDTC_BY_MASK:
        return rl == 3u && dtc_list_ok(sub, req[2], r, n);
    case UDSOTA_RDTC_SUPPORTED:
        return rl == 2u && dtc_list_ok(sub, 0u, r, n);
    case UDSOTA_RDTC_EXT_DATA:
        return n >= 6u && rl == 6u && r[2] == req[2] && r[3] == req[3] && r[4] == req[4] &&
               (r[5] & (uint8_t)~FUZZ_DTC_AVAIL) == 0u;
    default:
        return false;
    }
}
#endif

/* True when a positive answer r[0..n) to req has the shape the server tests pin for its SID. */
static bool positive_shape_ok(const uint8_t *req, size_t rl, const uint8_t *r, size_t n)
{
    const uint8_t sub = rl >= 2 ? (uint8_t)(req[1] & (uint8_t)~UDSOTA_SPRMIB) : 0u;
    switch (req[0]) {
    case UDSOTA_SID_SESSION:            /* 50 ss 00 32 01 F4 */
        return n == 6 && rl == 2 && r[1] == sub && r[2] == 0x00 && r[3] == 0x32 && r[4] == 0x01 && r[5] == 0xF4;
    case UDSOTA_SID_RESET:              /* 51 01 */
        return n == 2 && r[1] == UDSOTA_RESET_HARD;
    case UDSOTA_SID_READ_DID:           /* 62 did-hi did-lo data..., one DID per request */
        return n >= 4 && rl == 3 && r[1] == req[1] && r[2] == req[2];
    case UDSOTA_SID_SECURITY:           /* 67 ll + 16-byte seed, or 67 ll after a key */
        return (sub & 1u) != 0 ? (n == 2u + UDSOTA_SEED_LEN && r[1] == sub) : (n == 2 && r[1] == sub);
    case UDSOTA_SID_ROUTINE:            /* 71 01 rid-hi rid-lo [status] */
        return (n == 4 || n == 5) && rl >= 4 && r[1] == sub && r[2] == req[2] && r[3] == req[3];
    case UDSOTA_SID_REQUEST_DOWNLOAD:   /* 74 20 0F FF */
        return n == 4 && r[1] == UDSOTA_DL_LFID && r[2] == 0x0F && r[3] == 0xFF;
    case UDSOTA_SID_TRANSFER_DATA:      /* 76 bsc */
        return n == 2 && rl >= 2 && r[1] == req[1];
    case UDSOTA_SID_TRANSFER_EXIT:      /* 77 */
        return n == 1;
    case UDSOTA_SID_TESTER_PRESENT:     /* 7E 00 */
        return n == 2 && r[1] == UDSOTA_TP_ZERO_SUBFUNC;
    case UDSOTA_SID_COMM_CONTROL:       /* 68 ct, ct 00-03 */
        return n == 2 && rl == 3 && r[1] == sub && sub <= UDSOTA_CC_DISABLE_RX_TX;
    case UDSOTA_SID_DTC_SETTING:        /* C5 01 or C5 02 */
        return n == 2 && r[1] == sub && (sub == UDSOTA_DTC_ON || sub == UDSOTA_DTC_OFF);
#if UDSOTA_FUZZ_APP_HOOKS
    case UDSOTA_SID_WRITE_DID:          /* 6E did-hi did-lo */
        return n == 3 && rl >= 4 && r[1] == req[1] && r[2] == req[2];
#endif
#if UDSOTA_FUZZ_DTC
    case UDSOTA_SID_READ_DTC:           /* 59 sub ... */
        return dtc_shape_ok(req, rl, sub, r, n);
    case UDSOTA_SID_CLEAR_DTC:          /* 54, for exactly 14 and a 3-byte group */
        return n == 1 && rl == UDSOTA_CLEAR_DTC_LEN;
#endif
    default:
        return false;
    }
}

/* Checks the answer to one request against the universal invariants and records coverage. */
static void check_request_answer(const uint8_t *req, size_t rl, const uint8_t *r, size_t n, size_t resp_max)
{
    const bool count = !g_in_preamble;
    g_stats.requests += count;
    if (n > resp_max) {
        fail("response length exceeds resp_max", req, rl, NULL, 0);
    }
    if (n == 0) {
        g_stats.silent += count;
        return;
    }
    if (rl == 0) {
        fail("answered an empty request", req, rl, r, n);
    }
    if (r[0] == UDSOTA_NEG_RESPONSE) {
        if (n != 3 || r[1] != req[0] || !(nrc_ok(r[2]) || too_long_ok(req[0], r[2]))) {
            fail("malformed negative response (want 7F <request SID> <known NRC>)", req, rl, r, n);
        }
        if (count) {
            g_stats.nrc++;
            g_stats.nrc_sid[req[0]] = true;
            g_stats.nrc_code[r[2]] = true;
        }
        return;
    }
    if (!sid_served(req[0]) || r[0] != UDSOTA_POS(req[0]) || !positive_shape_ok(req, rl, r, n)) {
        fail("malformed positive response", req, rl, r, n);
    }
    if (count) {
        g_stats.positive++;
        g_stats.pos_sid[req[0]] = true;
    }
}

/* Checks an answer udsota_poll produced: a 0x78/0x72/job NRC, or the positive final answer of one of
 * the two services that start worker jobs (76 BSC for 0x36, 71 01 <rid> [status] for 0x31). */
static void check_poll_answer(const uint8_t *r, size_t n, size_t resp_max)
{
    if (n > resp_max) {
        fail("poll response length exceeds resp_max", NULL, 0, NULL, 0);
    }
    if (n == 0) {
        return;
    }
    g_stats.poll_answers += !g_in_preamble;
    if (r[0] == UDSOTA_NEG_RESPONSE) {
        if (n != 3 || !sid_served(r[1]) || !nrc_ok(r[2])) {
            fail("malformed negative poll response", NULL, 0, r, n);
        }
        return;
    }
    const uint8_t sid = (uint8_t)(r[0] & (uint8_t)~UDSOTA_POS_BIT);
    const bool ok = (r[0] & UDSOTA_POS_BIT) != 0 &&
                    ((sid == UDSOTA_SID_TRANSFER_DATA && n == 2) ||
                     (sid == UDSOTA_SID_ROUTINE && (n == 4 || n == 5) && r[1] == UDSOTA_RC_START));
#if UDSOTA_FUZZ_NO_UPDATE
    if (sid == UDSOTA_SID_TRANSFER_DATA) {
        fail("a 36 answered from a poll with no update service", NULL, 0, r, n);
    }
#endif
    if (!ok) {
        fail("malformed positive poll response", NULL, 0, r, n);
    }
    if (!g_in_preamble) {
        g_stats.pos_sid[sid] = true;   /* an async 0x36 or 0x31 gets its positive answer here */
    }
}

/* The server's phase is the last one its hook reported (the hook saw every change). */
static void check_phase(void)
{
    const udsota_phase_t p = udsota_phase(&S);
    if ((int)p != M.last_phase) {
        const uint8_t b = (uint8_t)p;
        fail("udsota_phase() differs from the last phase the hook saw", NULL, 0, &b, 1);
    }
}

#if UDSOTA_FUZZ_PROGRESS
/* After one server call: the hook ran at most once, and udsota_progress() reads what it last got, last_reason
 * included, so every change of stage, written block and reason was reported (the ESP32 port's snapshot follows
 * only the hook). Clears the call count for the next call. */
static void check_progress(void)
{
    udsota_progress_t now;
    udsota_progress(&S, &now);
    const unsigned calls = M.progress_calls;
    M.progress_calls = 0u;
    if (calls > 1u) {
        fail("progress hook ran more than once in one server call", NULL, 0, NULL, 0);
    }
    if (now.stage != M.progress.stage || now.done != M.progress.done || now.total != M.progress.total ||
        now.last_reason != M.progress.last_reason || now.done > now.total) {
        fail("udsota_progress() differs from what the progress hook last got", NULL, 0, NULL, 0);
    }
}
#else
/* Without the progress hook there is nothing to check. */
static void check_progress(void) {}
#endif

#if UDSOTA_FUZZ_APP_HOOKS
/* An app routine has exactly one owner: the job the server waits on, or the orphan that only routine_poll clears.
 * The server's view must match the hook's after every request and poll. */
static void check_app_owner(void)
{
    const bool owned = S.app_orphan || (S.job_running && S.job_app);
    if (owned != M.app_outstanding) {
        fail("app routine ownership differs from the hook's view", NULL, 0, NULL, 0);
    }
    if (S.app_orphan && !g_in_preamble) {
        g_stats.app_orphaned = true;
    }
}

/* An app orphan keeps the worker busy: a request answered while one ran must not have entered programming or armed
 * a restart (10 02, 11 01 and ActivateImage are 0x22 until routine_poll finishes it). */
static void check_orphan_held(bool orphan_before, uint8_t session_before, const uint8_t *req, size_t rl)
{
    if (orphan_before && ((S.session == UDSOTA_SESSION_PROGRAMMING && session_before != UDSOTA_SESSION_PROGRAMMING) ||
                          udsota_restart_armed(&S))) {
        fail("10 02, 11 01 or ActivateImage accepted while an app orphan ran", req, rl, NULL, 0);
    }
}
#endif

#if UDSOTA_FUZZ_NO_UPDATE
/* With no update service, 34, 36 and 37 are no one's: exactly 7F sid 11, or 7F sid 21 when a job was running (the
 * core's busy answer comes first), never a positive answer or another NRC; silent only when 3 bytes don't fit or a
 * restart was armed or had fired. Also records which of those answers the fuzz reached, for the coverage floor. */
static void check_no_update(bool job_before, bool restarting, const uint8_t *req, size_t rl, const uint8_t *r,
                            size_t n, size_t resp_max)
{
    const int k = (rl != 0u) ? dl_sid_index(req[0]) : -1;
    if (k < 0) {
        return;
    }
    if (n == 0u) {
        if (resp_max >= 3u && !restarting) {
            fail("34, 36 or 37 went unanswered with no update service", req, rl, r, n);
        }
        return;
    }
    const uint8_t want = job_before ? UDSOTA_NRC_BUSY_REPEAT : UDSOTA_NRC_SERVICE_NOT_SUPPORTED;
    if (n != 3u || r[0] != UDSOTA_NEG_RESPONSE || r[1] != req[0] || r[2] != want) {
        fail("34, 36 or 37 answered other than 0x11 (0x21 during a job) with no update service", req, rl, r, n);
    }
    if (!g_in_preamble) {
        if (job_before) {
            g_stats.dl_nrc21 = true;
        } else {
            g_stats.dl_nrc11[k] = true;
        }
    }
}
#endif

/* Returns the guarded response buffer for resp_max, with its canary armed. */
static uint8_t *resp_buf(size_t resp_max)
{
    uint8_t *resp = g_resp.page + g_resp.size - resp_max;
    memset(resp - CANARY_LEN, CANARY, CANARY_LEN);
    return resp;
}

/* Fails if the server wrote into the bytes just before its response buffer. */
static void check_canary(const uint8_t *resp, const uint8_t *req, size_t rl)
{
    for (size_t i = 1; i <= CANARY_LEN; i++) {
        if (resp[-(ptrdiff_t)i] != CANARY) {
            fail("server wrote before the start of resp", req, rl, NULL, 0);
        }
    }
}

/* Places the request flush against a guard page, makes it read-only, and sends it with a guarded resp. */
static size_t fuzz_request(const uint8_t *in, size_t len, layout_t lay, size_t resp_max, uint32_t now)
{
    arena_protect(&g_req, false);
    uint8_t *req = (lay == LAYOUT_END) ? g_req.page + g_req.size - len : g_req.page;
    memcpy(req, in, len);
    arena_protect(&g_req, true);
    uint8_t *resp = resp_buf(resp_max);
    M.now = now;
    if (len > 7u) {
        udsota_on_rx_first_frame(&S, now);   /* what the shim does for a multi-frame request */
    }
#if UDSOTA_FUZZ_APP_HOOKS
    const bool orphan_before = S.app_orphan;
    const uint8_t session_before = S.session;
#endif
#if UDSOTA_FUZZ_NO_UPDATE
    const bool job_before = S.job_running;
    const bool restarting = udsota_restart_armed(&S) || M.resets != 0u;
#endif
    const size_t n = udsota_on_request(&S, req, len, resp, resp_max, now);
    check_canary(resp, req, len);
    check_request_answer(req, len, resp, n, resp_max);
#if UDSOTA_FUZZ_NO_UPDATE
    check_no_update(job_before, restarting, req, len, resp, n, resp_max);
#endif
    digest_fold('Q', req, len);
    digest_fold('A', resp, n);
    check_phase();
    check_progress();
#if UDSOTA_FUZZ_APP_HOOKS
    check_app_owner();
    check_orphan_held(orphan_before, session_before, req, len);
#endif
    return n;
}

/* Polls the server at now into a guarded resp and checks any answer. */
static void fuzz_poll(size_t resp_max, uint32_t now)
{
    uint8_t *resp = resp_buf(resp_max);
    M.now = now;
    if (M.live && M.variant == 1u) {
        udsota_end_session(&S, now);   /* variant 1 is the second device: fuzz the end_pending latch */
        check_progress();
    }
#if UDSOTA_FUZZ_APP_HOOKS
    const bool job_before = S.job_running;
#endif
    const size_t n = udsota_poll(&S, resp, resp_max, now);
    check_canary(resp, NULL, 0);
    check_poll_answer(resp, n, resp_max);
    digest_fold('P', resp, n);
    check_phase();
    check_progress();
#if UDSOTA_FUZZ_APP_HOOKS
    check_app_owner();
    if (n != 0 && !job_before) {   /* only a job the server waits on is answered; an orphan's answer never is */
        fail("poll answered with no job running (a leaked orphan answer)", NULL, 0, resp, n);
    }
#endif
}

/* Sends one preamble request (plain buffers) and waits out any worker job; fails unless the final answer is positive. */
static size_t pre_exchange(uint32_t *now, state_t st, const uint8_t *req, size_t len)
{
    *now += 10u;
    M.now = *now;
    size_t n = udsota_on_request(&S, req, len, g_pre_resp, sizeof g_pre_resp, *now);
    check_request_answer(req, len, g_pre_resp, n, sizeof g_pre_resp);
    digest_fold('Q', req, len);
    digest_fold('A', g_pre_resp, n);
    check_progress();
    for (unsigned k = 0; k < 1000u && (n == 0 || (g_pre_resp[0] == UDSOTA_NEG_RESPONSE &&
                                                   g_pre_resp[2] == UDSOTA_NRC_RESPONSE_PENDING)); k++) {
        *now += 5u;
        M.now = *now;
        n = udsota_poll(&S, g_pre_resp, sizeof g_pre_resp, *now);
        check_poll_answer(g_pre_resp, n, sizeof g_pre_resp);
        digest_fold('P', g_pre_resp, n);
        check_progress();
    }
    if (n == 0 || g_pre_resp[0] != UDSOTA_POS(req[0])) {
        fprintf(stderr, "fuzz_udsota: PREAMBLE to state '%s' refused a step, so that state cannot be fuzzed\n",
                STATE_NAME[st]);
        dump("request", req, len);
        dump("response", g_pre_resp, n);
        exit(1);
    }
    return n;
}

/* Sends one preamble request given as its bytes, through pre_exchange. */
#define STEP(now, st, ...) do {                                        \
        const uint8_t step_[] = {__VA_ARGS__};                         \
        (void)pre_exchange((now), (st), step_, sizeof step_);          \
    } while (0)

/* Unlocks a security level in the preamble: 27 <level>, then 27 <level+1> with fake_key of the seed. */
static void unlock(uint32_t *now, state_t st, uint8_t level)
{
    const uint8_t seed_req[2] = {UDSOTA_SID_SECURITY, level};
    (void)pre_exchange(now, st, seed_req, sizeof seed_req);
    uint8_t key_req[2 + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, (uint8_t)(level + 1u)};
    fake_key(&g_pre_resp[2], level, &key_req[2]);
    (void)pre_exchange(now, st, key_req, sizeof key_req);
}

#ifdef UDSOTA_FUZZ_Z
#define PRE_HDR 5u   /* the z build's preamble blocks each carry one stored DEFLATE block: a 5-byte header, then data */
#else
#define PRE_HDR 0u
#endif

#define PRE_BLOCK_LEN (2u + PRE_HDR + DL_SIZE / 2u)

/* Fills blk with the preamble's 32-byte TransferData block bsc (1 or 2); block 1 starts with the ESP image magic
 * 0xE9. The z build wraps each in a stored block (the second final), so block 1 inflates short of the check and
 * is held until block 2. */
static void fill_block(uint8_t blk[PRE_BLOCK_LEN], uint8_t bsc)
{
    blk[0] = UDSOTA_SID_TRANSFER_DATA;
    blk[1] = bsc;
    for (size_t i = 2 + PRE_HDR; i < PRE_BLOCK_LEN; i++) {
        blk[i] = (uint8_t)(i * 7u + bsc);
    }
    if (bsc == 1u) {
        blk[2 + PRE_HDR] = 0xE9;
    }
#ifdef UDSOTA_FUZZ_Z
    const uint16_t len = DL_SIZE / 2u;
    blk[2] = (bsc == 2u) ? 0x01 : 0x00;
    blk[3] = (uint8_t)len;
    blk[4] = (uint8_t)(len >> 8);
    blk[5] = (uint8_t)~len;
    blk[6] = (uint8_t)(~len >> 8);
#endif
}

/* Sends the preamble's TransferData block bsc. */
static void send_block(uint32_t *now, state_t st, uint8_t bsc)
{
    uint8_t blk[PRE_BLOCK_LEN];
    fill_block(blk, bsc);
    (void)pre_exchange(now, st, blk, sizeof blk);
}

/* Drives a fresh server into st with valid requests, asserting each step is accepted. */
static void reach(state_t st, uint32_t *now)
{
    if (st == ST_DEFAULT) {
        return;
    }
    if (st == ST_EXTENDED || st == ST_EXT_UNLOCKED) {
        STEP(now, st, UDSOTA_SID_SESSION, UDSOTA_SESSION_EXTENDED);
        if (st == ST_EXT_UNLOCKED) {
            unlock(now, st, UDSOTA_SA_SEED_EXTENDED);
        }
        return;
    }
    STEP(now, st, UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING);
    if (st == ST_PROG) {
        return;
    }
    unlock(now, st, UDSOTA_SA_SEED_PROGRAMMING);
    if (st == ST_PROG_UNLOCKED) {
        return;
    }
#ifdef UDSOTA_FUZZ_Z
    STEP(now, st, UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI_DEFLATE, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0, 0, DL_SIZE);
#else
    STEP(now, st, UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0, 0, DL_SIZE);
#endif
    if (st == ST_DOWNLOAD) {
        return;
    }
    send_block(now, st, 1);
    if (st == ST_TRANSFER) {
        return;
    }
    send_block(now, st, 2);
    STEP(now, st, UDSOTA_SID_TRANSFER_EXIT);
    if (st == ST_EXITED) {
        return;
    }
    const uint8_t ff01[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01};
    if (pre_exchange(now, st, ff01, sizeof ff01) != 5u || g_pre_resp[4] != UDSOTA_DL_OK) {
        die("preamble FF01 did not answer 71 01 FF 01 00 (UDSOTA_DL_OK)");
    }
}

/* Starts one replay: a fresh server and mock driven to st with every gate open, then the variant switched on.
 * Odd runs leave the nullable engine.unverify NULL. */
static uint32_t start_run(state_t st, unsigned variant, bool async)
{
    memset(&M, 0, sizeof M);
    M.async = async;
    g_rec = 0;
#ifdef UDSOTA_FUZZ_Z
    z_close();                                  /* the last run may have ended mid-download */
#endif
    udsota_engine_t engine = FUZZ_ENGINE;
    if ((g_stats.runs & 1u) != 0u) {
        engine.unverify = NULL;
    }
#if UDSOTA_FUZZ_NO_UPDATE
    (void)engine;
    udsota_init(&S, &FUZZ_CFG, NULL, &FUZZ_SECURITY, &FUZZ_HOOKS);   /* the server alone: no update service */
#else
    udsota_init(&S, &FUZZ_CFG, &engine, &FUZZ_SECURITY, &FUZZ_HOOKS);
#endif
    udsota_set_tx_pending(&S, mock_tx_pending, NULL);
    uint32_t now = T0;
    g_in_preamble = true;
    reach(st, &now);
    g_in_preamble = false;
    M.variant = variant;
    M.live = true;
    g_stats.reached[st] = true;
    g_stats.runs++;
    return now + 10u;
}

/* Polls past the 0x78 point, the 1.5 s repeat and S3, checking every answer. */
static void finish_polls(size_t resp_max, uint32_t now)
{
    static const uint32_t STEPS[] = {1u, 45u, 100u, 1600u, 5001u};
    for (size_t i = 0; i < sizeof STEPS / sizeof STEPS[0]; i++) {
        fuzz_poll(resp_max, now + STEPS[i]);
    }
}

/* Records what is being replayed, for failure and crash reports. */
static void set_label(const char *src, unsigned long idx, size_t len, state_t st, const char *mode,
                      unsigned variant, size_t resp_max)
{
    snprintf(g_label, sizeof g_label, "%s #%lu (%zu B), state %s, %s, variant %u, resp_max %zu",
             src, idx, len, STATE_NAME[st], mode, variant, resp_max);
}

/* Replays in[0..len) as one request from state st. The start-guard run uses the async worker, so a
 * request that queues flash work gets its 0x78 and final answer from the polls that follow. */
static void run_single(const char *src, unsigned long idx, const uint8_t *in, size_t len, state_t st,
                       layout_t lay, unsigned variant, size_t resp_max)
{
    set_label(src, idx, len, st, lay == LAYOUT_END ? "single/end-guard" : "single/start-guard+async",
              variant, resp_max);
    const uint32_t now = start_run(st, variant, lay == LAYOUT_START);
    (void)fuzz_request(in, len, lay, resp_max, now);
    finish_polls(resp_max, now);
}

/* Replays in as records [dt][len | FF hi lo][bytes] from st with an async worker: dt x 25 ms pass (one
 * poll) before each request; a zero-length record is an abandoned multi-frame request (N_Cr). */
static void run_sequence(const char *src, unsigned long idx, const uint8_t *in, size_t len, state_t st,
                         unsigned variant, size_t resp_max)
{
    set_label(src, idx, len, st, "sequence", variant, resp_max);
    uint32_t now = start_run(st, variant, true);
    size_t pos = 0;
    for (unsigned rec = 0; pos + 2u <= len && rec < SEQ_MAX_RECORDS; rec++) {
        g_rec = rec;
        now += (uint32_t)in[pos++] * SEQ_DT_UNIT_MS;
        size_t l = in[pos++];
        if (l == 0xFFu && pos + 2u <= len) {
            l = (((size_t)in[pos] << 8) | in[pos + 1u]) & 0x0FFFu;
            pos += 2u;
        }
        if (l > len - pos) {
            l = len - pos;
        }
        fuzz_poll(resp_max, now);
        if (l == 0) {
            udsota_on_rx_timeout(&S, now);
        } else {
            (void)fuzz_request(&in[pos], l, (rec & 1u) ? LAYOUT_START : LAYOUT_END, resp_max, now);
        }
        pos += l;
    }
    finish_polls(resp_max, now);
}

/* Replays one input from every state: as one request in both layouts, then as a record stream.
 * A pristine seed always runs with every gate passing and the full buffer; others rotate both. */
static void replay_input(const char *src, const uint8_t *in, size_t len, bool pristine)
{
    const unsigned long idx = g_stats.inputs++;
    const size_t one = len > REQ_MAX ? REQ_MAX : len;
    const size_t seq = len > SEQ_MAX_BYTES ? SEQ_MAX_BYTES : len;
    const unsigned variant = pristine ? 0u : (unsigned)(idx % VARIANT_COUNT);
    for (int st = 0; st < ST_FUZZED; st++) {
        const size_t resp_max = pristine ? RESP_FULL : RESP_MAXES[(idx + (unsigned long)st) % RESP_MAX_COUNT];
        run_single(src, idx, in, one, (state_t)st, LAYOUT_END, variant, resp_max);
        run_single(src, idx, in, one, (state_t)st, LAYOUT_START, variant, resp_max);
        run_sequence(src, idx, in, seq, (state_t)st, variant, resp_max);
    }
}

/* Maps the two guard arenas once. */
static void harness_init(void)
{
    arena_init(&g_req);
    arena_init(&g_resp);
#ifdef UDSOTA_FUZZ_Z
    arena_init(&g_zarena);
    g_zout = g_zarena.page + g_zarena.size - Z_OUT_LEN;
#endif
}

#ifdef UDSOTA_LIBFUZZER
/* libFuzzer entry point: replays one input from every state, both layouts and both modes. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool ready;
    if (!ready) {
        harness_init();
        ready = true;
    }
    replay_input("libfuzzer", data, size, false);
    return 0;
}
#else  /* the ctest program: self-tests, seeds, mutants, corpus replay */

/* Writes s to stderr from a signal handler (async-signal-safe). */
static void say(const char *s)
{
    ssize_t r = write(STDERR_FILENO, s, strlen(s));
    (void)r;
}

/* Fatal-signal handler: names the input being replayed, then returns so the default action kills the process. */
static void on_fatal(int sig)
{
    char num[16];
    size_t i = sizeof num - 1;
    unsigned v = g_rec;
    num[i] = '\0';
    do {
        num[--i] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v != 0 && i > 0);
    say(sig == SIGILL ? "fuzz_udsota: CRASH (SIGILL: UBSan trap)" : "fuzz_udsota: CRASH (fatal signal: guard page or abort)");
    say(" while replaying ");
    say(g_label);
    say(", record ");
    say(&num[i]);
    say("\n");
}

/* Installs on_fatal for the signals a guard-page hit, a UBSan trap or an assert raise. */
static void install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fatal;
    sa.sa_flags = SA_RESETHAND;   /* the re-executed fault (or re-raised abort) then takes the default action */
    sigemptyset(&sa.sa_mask);
    const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0) {
            die("sigaction failed");
        }
    }
}

static uint32_t g_rng = 0x26C0FFEEu;   /* mutation PRNG state */

/* xorshift32 with a fixed seed, so every run replays the same mutants. */
static uint32_t rnd(void)
{
    uint32_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng = x;
    return x;
}

/* Short hand-written seeds: every served SID in valid, truncated, over-long and wrong-sub-function
 * forms, plus unserved SIDs. Each is replayed from every state. */
typedef struct { uint8_t len; uint8_t b[20]; } seed_t;
#define SEED(...) {(uint8_t)sizeof((uint8_t[]){__VA_ARGS__}), {__VA_ARGS__}}
static const seed_t SEEDS[] = {
    SEED(0x10, 0x01), SEED(0x10, 0x02), SEED(0x10, 0x03), SEED(0x10, 0x83), SEED(0x10, 0x04),
    SEED(0x10), SEED(0x10, 0x03, 0x00),
    SEED(0x3E, 0x00), SEED(0x3E, 0x80), SEED(0x3E, 0x01), SEED(0x3E), SEED(0x3E, 0x00, 0x00),
    SEED(0x22, 0xF1, 0x86), SEED(0x22, 0xF1, 0x89), SEED(0x22, 0xF1, 0x8C), SEED(0x22, 0xF1, 0x91),
    SEED(0x22, 0xF1, 0xB0), SEED(0x22, 0xF1, 0xF0), SEED(0x22, 0xF1, 0xB1), SEED(0x22, 0xF1, 0xF3),
    SEED(0x22, 0xF1, 0xF1), SEED(0x22, 0xF1, 0xF2), SEED(0x22, 0x02, 0x00), SEED(0x22, 0x02, 0x04),
    SEED(0x22, 0x01, 0xFF), SEED(0x22, 0xFF, 0xFF), SEED(0x22, 0xF1), SEED(0x22),
    SEED(0x22, 0xF1, 0x86, 0xF1, 0x89),
    SEED(0x27, 0x01), SEED(0x27, 0x03), SEED(0x27, 0x05), SEED(0x27), SEED(0x27, 0x03, 0x00),
    SEED(0x27, 0x81), SEED(0x27, 0x02), SEED(0x27, 0x04, 0x00),
    SEED(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
    SEED(0x27, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    SEED(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40), SEED(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0),
    SEED(0x34, 0x00, 0x44, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF), SEED(0x34, 0x00, 0x44, 0, 0, 0x10, 0, 0, 0, 0, 0x40),
    SEED(0x34, 0x01, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40), SEED(0x34, 0x00, 0x22, 0, 0, 0, 0x40),
    SEED(0x34, 0x00, 0x44), SEED(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x00),
    SEED(0x34, 0x00, 0x11, 0, 0x40), SEED(0x34, 0x00, 0x11, 0x01, 0x40), SEED(0x34, 0x00, 0x42, 0, 0, 0, 0, 0, 0x40),
    SEED(0x34, 0x00, 0x24, 0, 0, 0, 0, 0, 0x40, 0x00), SEED(0x34, 0x00, 0x45, 0, 0, 0, 0, 0, 0, 0, 0x40),
    SEED(0x34, 0x00, 0x00),
    SEED(0x36, 0x01, 0xE9, 0x03, 0x02, 0x4F), SEED(0x36, 0x01, 0x00, 0x03), SEED(0x36, 0x02, 0x55),
    SEED(0x36, 0x01), SEED(0x36, 0x00, 0x11), SEED(0x36, 0xFF, 0x11), SEED(0x36),
    SEED(0x37), SEED(0x37, 0x00),
    SEED(0x31, 0x01, 0xFF, 0x01), SEED(0x31, 0x01, 0xF0, 0x00), SEED(0x31, 0x81, 0xF0, 0x00),
    SEED(0x31, 0x01, 0xF0, 0x01), SEED(0x31, 0x01, 0xF0, 0x02), SEED(0x31, 0x01, 0x12, 0x34),
    SEED(0x31, 0x02, 0xFF, 0x01), SEED(0x31, 0x03, 0xFF, 0x01), SEED(0x31, 0x01, 0xFF),
    SEED(0x31, 0x01, 0xFF, 0x01, 0x00), SEED(0x31),
    SEED(0x11, 0x01), SEED(0x11, 0x81), SEED(0x11, 0x02), SEED(0x11, 0x03), SEED(0x11), SEED(0x11, 0x01, 0x00),
    SEED(0x2E, 0x01, 0x00, 0x00), SEED(0x19, 0x02, 0xFF), SEED(0x14, 0xFF, 0xFF, 0xFF), SEED(0x85, 0x01),
    SEED(0x28, 0x00, 0x01), SEED(0x28, 0x03, 0x01), SEED(0x28, 0x81, 0x03), SEED(0x28, 0x01, 0x00),
    SEED(0x28, 0x04, 0x01), SEED(0x28, 0x03), SEED(0x28, 0x03, 0x01, 0x00), SEED(0x85, 0x82), SEED(0x85, 0x02, 0xFF),
    SEED(0x85, 0x03), SEED(0x85), SEED(0x7F, 0x10, 0x11), SEED(0x50, 0x01), SEED(0x00), SEED(0xFF), SEED(0x3F, 0x00),
#if UDSOTA_FUZZ_APP_HOOKS
    SEED(0x2E, 0x02, 0x00, 0x05), SEED(0x2E, 0x02, 0x02, 0x0B, 0xB8), SEED(0x2E, 0x02, 0x00, 0x05, 0x00),
    SEED(0x2E, 0x02, 0x00), SEED(0x2E, 0x02, 0x02, 0x0B),
    SEED(0x31, 0x01, 0x12, 0x34, 0xAA, 0xBB), SEED(0x31, 0x81, 0x12, 0x34), SEED(0x31, 0x01, 0x12, 0x35),
    SEED(0x31, 0x81, 0x12, 0x35), SEED(0x31, 0x01, 0x12, 0x36), SEED(0x31, 0x01, 0x12, 0x37),
    SEED(0x31, 0x02, 0x12, 0x34),
#endif
#ifdef UDSOTA_FUZZ_Z
    SEED(0x34, 0x10, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40), SEED(0x34, 0x10, 0x44, 0, 0, 0, 0, 0, 0, 0x01, 0x40),
    SEED(0x34, 0x10, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x01), SEED(0x34, 0x90, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40),
    SEED(0x36, 0x01, 0x01, 0x05, 0x00, 0xFA, 0xFF, 0xE9, 0x01, 0x02, 0x03, 0x04),
    SEED(0x36, 0x01, 0x00, 0x20, 0x00, 0xDF, 0xFF, 0xE9, 0x01, 0x02),
    SEED(0x36, 0x02, 0x01, 0x20, 0x00, 0xDF, 0xFF, 0x11, 0x22),
    SEED(0x36, 0x01, 0x07, 0x00), SEED(0x36, 0x01, 0x03, 0x00), SEED(0x36, 0x02, 0x73, 0x75, 0x03, 0x00),
#endif
#if UDSOTA_FUZZ_DTC
    SEED(0x19, 0x01, 0xFF), SEED(0x19, 0x01, 0x08), SEED(0x19, 0x01, 0x40), SEED(0x19, 0x01),
    SEED(0x19, 0x01, 0xFF, 0x00), SEED(0x19, 0x81, 0xFF), SEED(0x19, 0x02, 0x01), SEED(0x19, 0x02, 0x08),
    SEED(0x19, 0x02, 0x40), SEED(0x19, 0x02), SEED(0x19, 0x02, 0x01, 0x00), SEED(0x19, 0x82, 0x01),
    SEED(0x19, 0x82, 0xFF), SEED(0x19, 0x0A), SEED(0x19, 0x0A, 0x00), SEED(0x19, 0x8A),
    SEED(0x19, 0x06, 0xC0, 0x01, 0x01, 0x01), SEED(0x19, 0x06, 0xC0, 0x02, 0x02, 0x02),
    SEED(0x19, 0x06, 0xC0, 0x03, 0x00, 0xFF), SEED(0x19, 0x06, 0xC0, 0x04, 0x04, 0x7E),
    SEED(0x19, 0x06, 0xC0, 0x05, 0x05, 0x00), SEED(0x19, 0x06, 0xC0, 0x05, 0x05, 0x03),
    SEED(0x19, 0x06, 0xC0, 0x05, 0x05, 0xFE), SEED(0x19, 0x06, 0x12, 0x34, 0x56, 0x01),
    SEED(0x19, 0x86, 0xC0, 0x01, 0x01, 0x01), SEED(0x19, 0x06, 0xC0, 0x01, 0x01),
    SEED(0x19, 0x06, 0xC0, 0x01, 0x01, 0x01, 0x00), SEED(0x19, 0x06), SEED(0x19, 0x04, 0xC0, 0x01, 0x01, 0x01),
    SEED(0x19, 0x03), SEED(0x19, 0x14), SEED(0x19),
    SEED(0x14, 0xFF, 0xFF, 0xFF), SEED(0x14, 0xC0, 0x01, 0x01), SEED(0x14, 0x00, 0x00, 0x00), SEED(0x14, 0xFF, 0xFF),
    SEED(0x14, 0xFF, 0xFF, 0xFF, 0x00), SEED(0x14),
#endif
};
#define SEED_COUNT (sizeof SEEDS / sizeof SEEDS[0])

#ifdef UDSOTA_FUZZ_Z
static void replay_z_streams(void);
#endif

/* Appends a sequence-mode record (dt byte, length, bytes) to buf; returns the new length. */
static size_t rec(uint8_t *buf, size_t n, uint8_t dt, const uint8_t *b, size_t len)
{
    buf[n++] = dt;
    if (len >= 0xFFu) {
        buf[n++] = 0xFF;
        buf[n++] = (uint8_t)(len >> 8);
        buf[n++] = (uint8_t)len;
    } else {
        buf[n++] = (uint8_t)len;
    }
    if (len != 0) {
        memcpy(&buf[n], b, len);
    }
    return n + len;
}

/* Replays the generated seeds: max-length blocks, over-long forms of short services, and record
 * streams that finish a download (36 02, 37, FF01, ActivateImage), let S3 expire or walk the 0x27 key paths. */
static void replay_generated(void)
{
    static uint8_t b[REQ_MAX];
    static uint8_t seq[2 * REQ_MAX];
    const uint8_t sids[] = {UDSOTA_SID_TRANSFER_DATA, UDSOTA_SID_READ_DID, UDSOTA_SID_TESTER_PRESENT,
                            UDSOTA_SID_SECURITY, UDSOTA_SID_ROUTINE, UDSOTA_SID_REQUEST_DOWNLOAD};
    for (size_t k = 0; k < sizeof sids; k++) {
        b[0] = sids[k];
        b[1] = (k == 0) ? 0x01 : 0x00;
        for (size_t i = 2; i < REQ_MAX; i++) {
            b[i] = (uint8_t)(i * 31u);
        }
        b[2] = 0xE9;
        replay_input("max-length", b, REQ_MAX, true);          /* 4095 B: the ISO-TP limit */
        replay_input("max-length-1", b, REQ_MAX - 1u, true);
        replay_input("short-block", b, 34u, true);
    }
    /* From mid-transfer: block 2, exit, FF01, ActivateImage. From elsewhere it is just a stream. */
    uint8_t blk2[PRE_BLOCK_LEN];
    fill_block(blk2, 2);
    const uint8_t exit_[] = {UDSOTA_SID_TRANSFER_EXIT};
    const uint8_t ff01[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01};
    const uint8_t act[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xF0, 0x01};
    const uint8_t tp[] = {UDSOTA_SID_TESTER_PRESENT, 0x80};
    const uint8_t sess[] = {UDSOTA_SID_READ_DID, 0xF1, 0x86};
    size_t n = 0;
    n = rec(seq, n, 0, blk2, sizeof blk2);
    n = rec(seq, n, 8, blk2, sizeof blk2);                     /* the repeat of a lost 76 */
    n = rec(seq, n, 8, exit_, sizeof exit_);
    n = rec(seq, n, 1, ff01, sizeof ff01);
    n = rec(seq, n, 0, act, sizeof act);
    n = rec(seq, n, 8, act, sizeof act);
    replay_input("seq-finish-download", seq, n, true);
    n = 0;
    n = rec(seq, n, 80, tp, sizeof tp);                        /* 2 s: S3 kept alive */
    n = rec(seq, n, 210, sess, sizeof sess);                   /* 5.25 s: S3 has expired */
    n = rec(seq, n, 0, NULL, 0);                               /* an abandoned multi-frame request */
    n = rec(seq, n, 0, b, 300);                                /* long record with a 0xFF length escape */
    replay_input("seq-s3-expiry", seq, n, true);
    /* SecurityAccess key paths, which need an outstanding seed no state leaves behind. Per level: the right
     * key for the run's first seed (unlocks from the matching session with no earlier 0x27 in the run),
     * then three wrong keys (0x35, 0x35, 0x36) and a seed request inside the delay (0x37). */
    for (uint8_t level = UDSOTA_SA_SEED_EXTENDED; level <= UDSOTA_SA_SEED_PROGRAMMING; level += 2u) {
        const uint8_t seed_req[] = {UDSOTA_SID_SECURITY, level};
        uint8_t key_req[2 + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, (uint8_t)(level + 1u)};
        uint8_t seed0[UDSOTA_SEED_LEN];
        mock_seed(0, seed0);
        fake_key(seed0, level, &key_req[2]);
        n = 0;
        n = rec(seq, n, 0, seed_req, sizeof seed_req);
        n = rec(seq, n, 1, key_req, sizeof key_req);
        replay_input("seq-sa-unlock", seq, n, true);
        memset(&key_req[2], 0x5A, UDSOTA_KEY_LEN);
        n = 0;
        for (unsigned k = 0; k < UDSOTA_SA_MAX_ATTEMPTS; k++) {
            n = rec(seq, n, 0, seed_req, sizeof seed_req);
            n = rec(seq, n, 1, key_req, sizeof key_req);
        }
        n = rec(seq, n, 4, seed_req, sizeof seed_req);
        replay_input("seq-sa-lockout", seq, n, true);
    }
#if UDSOTA_FUZZ_APP_HOOKS
    /* An app routine past the 90 s cap: 0x72, then its orphan refuses another app routine (0x22, no hook call) and
     * holds 10 02 at 0x22 until routine_poll finishes it at 100 s, and 10 02 is accepted after. From a
     * default-session state it is just a stream. */
    const uint8_t hold[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0x12, 0x36};
    const uint8_t ext[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_EXTENDED};
    const uint8_t sync[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0x12, 0x34};
    const uint8_t prog[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    n = 0;
    n = rec(seq, n, 0, hold, sizeof hold);
    for (unsigned k = 0; k < 15u; k++) {
        n = rec(seq, n, 255, tp, sizeof tp);                   /* 15 x 6.375 s = 95.6 s: past the cap */
    }
    n = rec(seq, n, 0, ext, sizeof ext);                       /* back out of default, as a tester would */
    n = rec(seq, n, 0, sync, sizeof sync);                     /* the orphan still runs: 0x22, routine not called */
    n = rec(seq, n, 0, prog, sizeof prog);                     /* the orphan still runs: 0x22 */
    n = rec(seq, n, 255, tp, sizeof tp);                       /* 102 s: routine_poll finishes it */
    n = rec(seq, n, 0, prog, sizeof prog);                     /* accepted */
    replay_input("seq-app-orphan", seq, n, true);
#endif
#if UDSOTA_FUZZ_NO_UPDATE
    /* 34, 36 and 37 while an app routine runs (0x21, the core's busy answer), then after it finishes (0x11). */
    const uint8_t pend[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0x12, 0x35};
    const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0, 0, DL_SIZE};
    const uint8_t r36[] = {UDSOTA_SID_TRANSFER_DATA, 0x01, 0xE9};
    n = 0;
    n = rec(seq, n, 0, pend, sizeof pend);
    n = rec(seq, n, 0, r34, sizeof r34);
    n = rec(seq, n, 0, r36, sizeof r36);
    n = rec(seq, n, 0, exit_, sizeof exit_);
    n = rec(seq, n, 4, r34, sizeof r34);                       /* 100 ms: the routine has finished */
    replay_input("seq-no-update-busy", seq, n, true);
#endif
#ifdef UDSOTA_FUZZ_Z
    replay_z_streams();
#endif
}

#ifdef UDSOTA_FUZZ_Z
#define Z_IMG_MAX   24000u                      /* largest generated image */
#define Z_STREAMS   96u                         /* generated streams */

/* Replays Z_STREAMS generated compressed downloads as record streams: 34 10 with the image's size, its raw
 * DEFLATE stream in 36s of a random size, 37, FF01 and F000. Images mix random and repetitive bytes (so both
 * stored and Huffman blocks appear), mostly starting with the magic the mock check wants; a quarter of the
 * streams go intact, the rest get a flipped bit, a cut, bytes after the end, or a wrong memorySize. */
static void replay_z_streams(void)
{
    static uint8_t img[Z_IMG_MAX], z[Z_IMG_MAX * 2u], seq[SEQ_MAX_BYTES], blk[REQ_MAX];
    for (unsigned k = 0; k < Z_STREAMS; k++) {
        const size_t len = 1u + rnd() % (k < 8u ? UDSOTA_IMAGE_MIN_LEN : Z_IMG_MAX);
        const unsigned alphabet = (k % 3u == 0u) ? 256u : 2u + rnd() % 24u;
        for (size_t i = 0; i < len; i++) {
            img[i] = (i > 64u && rnd() % 8u != 0u) ? img[i - 1u - rnd() % 64u] : (uint8_t)(rnd() % alphabet);
        }
        img[0] = (k % 7u == 3u) ? 0x00 : 0xE9;
        const int flags = (int)tdefl_create_comp_flags_from_zip_params((int)(k % 10u), -15, MZ_DEFAULT_STRATEGY);
        size_t zl = tdefl_compress_mem_to_mem(z, sizeof z - 16u, img, len, flags);
        if (zl == 0u) {
            die("tdefl could not compress generated stream %u", k);
        }
        uint32_t size = (uint32_t)len;
        switch (k % 8u) {
        case 0: case 1: break;                                          /* intact */
        case 2: z[rnd() % zl] ^= (uint8_t)(1u << (rnd() % 8u)); break;  /* a flipped bit */
        case 3: zl -= 1u + rnd() % (zl < 8u ? zl - 1u : 8u); break;     /* cut short */
        case 4: for (unsigned a = 1u + rnd() % 8u; a != 0; a--) { z[zl++] = (uint8_t)rnd(); } break;   /* trailing */
        case 5: size += 1u + rnd() % 64u; break;                        /* memorySize past the image */
        case 6: size = (size > 1u) ? size - 1u - rnd() % (size - 1u) : size; break;   /* memorySize short of it */
        default: z[rnd() % zl] = (uint8_t)rnd(); z[rnd() % zl] = (uint8_t)rnd(); break;
        }
        size_t n = 0;
        const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI_DEFLATE, UDSOTA_DL_ALFID, 0, 0, 0, 0,
                               (uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size};
        n = rec(seq, n, 0, r34, sizeof r34);
        const size_t chunk = 1u + rnd() % UDSOTA_DL_MAX_DATA;
        uint8_t bsc = 1;
        for (size_t off = 0; off < zl && n + REQ_MAX + 8u < sizeof seq; off += chunk, bsc++) {
            const size_t c = (zl - off < chunk) ? zl - off : chunk;
            blk[0] = UDSOTA_SID_TRANSFER_DATA;
            blk[1] = bsc;
            memcpy(&blk[2], &z[off], c);
            n = rec(seq, n, (rnd() % 16u == 0u) ? 0u : 4u, blk, c + 2u);   /* mostly past the 60 ms job */
        }
        const uint8_t exit_[] = {UDSOTA_SID_TRANSFER_EXIT};
        const uint8_t ff01[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01};
        const uint8_t f000[] = {UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xF0, 0x00};
        n = rec(seq, n, 1, exit_, sizeof exit_);
        n = rec(seq, n, 1, ff01, sizeof ff01);
        n = rec(seq, n, 0, f000, sizeof f000);
        const bool intact = (k % 8u) < 2u;              /* the oracle knows what these must write */
        g_z_expect = intact ? img : NULL;
        g_z_expect_len = intact ? len : 0u;
        replay_input("z-stream", seq, n, k % 2u == 0u);
        g_z_expect = NULL;
    }
}
#endif

/* Writes a mutant of seed into out (capacity REQ_MAX) with 1-4 random edits; returns its length. */
static size_t mutate(const uint8_t *seed, size_t len, uint8_t *out)
{
    static const uint8_t INTERESTING[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x7F, 0x80, 0x81, 0xFE, 0xFF};
#if UDSOTA_FUZZ_DTC
    static const uint8_t SIDS[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E};
#else
    static const uint8_t SIDS[] = {0x10, 0x11, 0x22, 0x27, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E};
#endif
    size_t n = len;
    memcpy(out, seed, len);
    const unsigned edits = 1u + rnd() % 4u;
    for (unsigned e = 0; e < edits; e++) {
        switch (rnd() % 7u) {
        case 0: if (n != 0) { out[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8u)); } break;
        case 1: if (n != 0) { out[rnd() % n] = INTERESTING[rnd() % sizeof INTERESTING]; } break;
        case 2: n = (n != 0) ? rnd() % n : 0; break;                                   /* truncate */
        case 3: for (unsigned a = 1u + rnd() % 64u; a != 0 && n < REQ_MAX; a--) { out[n++] = (uint8_t)rnd(); } break;
        case 4: if (n != 0) { out[0] = SIDS[rnd() % sizeof SIDS]; } break;              /* re-aim at a handler */
        case 5: if (n > 1) { out[1] ^= UDSOTA_SPRMIB; } break;                            /* toggle suppress */
        default: { const size_t t = REQ_MAX - rnd() % 3u; while (n < t) { out[n++] = (uint8_t)rnd(); } } break;
        }
    }
    return n;
}

/* Replays the seeds pristine, then `mutations` mutants of each, then RANDOM_INPUTS random inputs. */
static void replay_seeds(unsigned mutations)
{
    static uint8_t buf[REQ_MAX];
    replay_input("seed-empty", buf, 0, true);
    for (size_t i = 0; i < SEED_COUNT; i++) {
        replay_input("seed", SEEDS[i].b, SEEDS[i].len, true);
    }
    replay_generated();
    for (size_t i = 0; i < SEED_COUNT; i++) {
        for (unsigned m = 0; m < mutations; m++) {
            replay_input("mutant", buf, mutate(SEEDS[i].b, SEEDS[i].len, buf), false);
        }
    }
    for (unsigned i = 0; i < RANDOM_INPUTS; i++) {
        const size_t n = rnd() % (REQ_MAX + 1u);
        for (size_t k = 0; k < n; k++) {
            buf[k] = (uint8_t)rnd();
        }
        replay_input("random", buf, n, false);
    }
}

static const char *const OP_NAME[OP_COUNT] = {   /* op_id_t names for the coverage report */
    "ota_begin", "ota_write", "ota_end", "ota_abort", "ota_activate", "ota_confirm", "image_check",
    "reset", "ota_unverify",
#if UDSOTA_FUZZ_APP_HOOKS
    "did_write", "routine", "routine_poll",
#endif
#ifdef UDSOTA_FUZZ_Z
    "zbegin", "zwrite", "zend",
#endif
#if UDSOTA_FUZZ_DTC
    "dtc_get", "dtc_ext_data", "dtc_clear",
#endif
};

/* The replay's own positive control, from fuzzed requests only (preamble answers never count): every
 * served SID must have drawn a positive answer and an NRC, some request NRC 0x13 and 0x35, and every platform op
 * a call, so accepted 0x34s and written 0x36 blocks were reached, not just refusals. */
static void check_coverage(void)
{
    bool ok = g_stats.nrc_code[UDSOTA_NRC_INCORRECT_LENGTH] && g_stats.nrc_code[UDSOTA_NRC_INVALID_KEY];
#if UDSOTA_FUZZ_DTC
    if (!g_stats.nrc_code[UDSOTA_NRC_RESPONSE_TOO_LONG]) {
        fprintf(stderr, "fuzz_udsota: COVERAGE: no fuzzed 19 answered 0x14 (responseTooLong)\n");
        ok = false;
    }
#endif
    for (unsigned sid = 0; sid < 256u; sid++) {   /* sid_served() is the one list: a hand copy here drifted */
        if (sid_served((uint8_t)sid) && (!g_stats.pos_sid[sid] || !g_stats.nrc_sid[sid])) {
            fprintf(stderr, "fuzz_udsota: COVERAGE: SID 0x%02X positive=%d NRC=%d\n", sid, g_stats.pos_sid[sid],
                    g_stats.nrc_sid[sid]);
            ok = false;
        }
    }
    for (int op = 0; op < OP_COUNT; op++) {
#if UDSOTA_FUZZ_NO_UPDATE
        if (op != OP_RESET && op != OP_DID_WRITE && op != OP_ROUTINE && op != OP_ROUTINE_POLL) {
            continue;                                /* the engine's ops: there is no engine */
        }
#endif
        if (g_stats.op_calls[op] == 0) {
            fprintf(stderr, "fuzz_udsota: COVERAGE: no fuzzed request reached %s\n", OP_NAME[op]);
            ok = false;
        }
    }
#if UDSOTA_FUZZ_APP_HOOKS
    if (!g_stats.app_orphaned) {
        fprintf(stderr, "fuzz_udsota: COVERAGE: no fuzzed app routine reached the 90 s cap\n");
        ok = false;
    }
#endif
#if UDSOTA_FUZZ_NO_UPDATE
    for (int k = 0; k < 3; k++) {
        if (!g_stats.dl_nrc11[k]) {
            fprintf(stderr, "fuzz_udsota: COVERAGE: SID 0x%02X never drew 0x11 with no update service\n",
                    (unsigned)(k == 0 ? UDSOTA_SID_REQUEST_DOWNLOAD : k == 1 ? UDSOTA_SID_TRANSFER_DATA
                                                                              : UDSOTA_SID_TRANSFER_EXIT));
            ok = false;
        }
    }
    if (!g_stats.dl_nrc21) {
        fprintf(stderr, "fuzz_udsota: COVERAGE: no 34, 36 or 37 arrived during a job (its 0x21)\n");
        ok = false;
    }
#endif
#if UDSOTA_FUZZ_PROGRESS
    for (int st = 0; st <= (int)UDSOTA_STAGE_ACTIVATING; st++) {
        if (!g_stats.stage_seen[st]) {
            fprintf(stderr, "fuzz_udsota: COVERAGE: no fuzzed call reported progress stage %d\n", st);
            ok = false;
        }
    }
    if (!g_stats.written_seen) {
        fprintf(stderr, "fuzz_udsota: COVERAGE: no fuzzed block moved progress past 0\n");
        ok = false;
    }
#endif
    for (int st = 0; st < ST_FUZZED; st++) {
        ok = ok && g_stats.reached[st];
    }
    if (!ok) {
        fprintf(stderr, "fuzz_udsota: COVERAGE floor not met (NRC 0x13 seen=%d, 0x35 seen=%d): a clean run would "
                "prove nothing\n", g_stats.nrc_code[UDSOTA_NRC_INCORRECT_LENGTH], g_stats.nrc_code[UDSOTA_NRC_INVALID_KEY]);
        exit(1);
    }
}

/* Reads one corpus file (up to SEQ_MAX_BYTES) and replays it. */
static void replay_file(const char *path)
{
    static uint8_t buf[SEQ_MAX_BYTES];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        die("cannot open %s", path);
    }
    const size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    const char *base = strrchr(path, '/');
    replay_input(base != NULL ? base + 1 : path, buf, n, false);
}

/* qsort comparator for directory entry names, so a corpus replays in a fixed order. */
static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Replays a corpus file, or every regular file in a corpus directory in name order. */
static void replay_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        die("cannot stat %s", path);
    }
    if (!S_ISDIR(st.st_mode)) {
        replay_file(path);
        return;
    }
    DIR *d = opendir(path);
    if (d == NULL) {
        die("cannot open directory %s", path);
    }
    size_t cap = 1024, count = 0;
    char **names = malloc(cap * sizeof *names);
    for (struct dirent *e = readdir(d); names != NULL && e != NULL; e = readdir(d)) {
        if (e->d_name[0] == '.') {
            continue;
        }
        if (count == cap) {
            cap *= 2u;
            char **grown = realloc(names, cap * sizeof *names);
            if (grown == NULL) {
                die("out of memory listing %s", path);
            }
            names = grown;
        }
        const size_t len = strlen(path) + strlen(e->d_name) + 2u;
        names[count] = malloc(len);
        if (names[count] == NULL) {
            die("out of memory listing %s", path);
        }
        snprintf(names[count], len, "%s/%s", path, e->d_name);
        count++;
    }
    closedir(d);
    if (names == NULL) {
        die("out of memory listing %s", path);
    }
    qsort(names, count, sizeof *names, cmp_names);
    for (size_t i = 0; i < count; i++) {
        struct stat fs;
        if (stat(names[i], &fs) == 0 && S_ISREG(fs.st_mode)) {
            replay_file(names[i]);
        }
        free(names[i]);
    }
    free(names);
    printf("fuzz_udsota: replayed %zu entries from %s\n", count, path);
}

/* Child side of a self-test: one byte read just past the end-aligned request buffer. */
static void probe_read_past_end(void)
{
    const volatile uint8_t *p = g_req.page + g_req.size - 1u;
    g_sink = p[1];
}

/* Child side of a self-test: one byte read just before the start-aligned request buffer. */
static void probe_read_before_start(void)
{
    const volatile uint8_t *p = g_req.page;
    g_sink = p[-1];
}

/* Child side of a self-test: one byte written just past a response buffer of resp_max bytes. */
static void probe_write_past_end(void)
{
    volatile uint8_t *p = resp_buf(3u);
    p[3] = 0;
}

#ifdef UDSOTA_FUZZ_Z
/* Child side of a self-test: one byte written just past the stream buffer. */
static void probe_write_past_zout(void)
{
    volatile uint8_t *p = g_zout;
    p[Z_OUT_LEN] = 0;
}

/* Child side of a self-test: one byte written just past an inflater allocation of 40 bytes. */
static void probe_write_past_zalloc(void)
{
    g_in_preamble = true;                               /* no forced allocation failure */
    volatile uint8_t *p = z_alloc(NULL, 40u);
    p[48] = 0;                                          /* 40 rounds to 48: the first byte of the guard page */
}
#endif

/* Child side of a self-test: a write into the read-only request. */
static void probe_write_request(void)
{
    arena_protect(&g_req, true);
    volatile uint8_t *p = g_req.page;
    p[0] = 0;
}

/* Child side of a self-test: a signed overflow that UBSan (trap mode) must stop. */
static void probe_ubsan(void)
{
    volatile int a = INT_MAX;
    volatile int b = 1;
    volatile int sum = a + b;   /* kept in int: gcc narrows (uint8_t)(a + b) and drops the check */
    g_sink = (uint8_t)sum;
}

/* Runs probe in a child and dies unless the child was killed by sig: a detector that cannot fire proves nothing. */
static void expect_death(const char *what, void (*probe)(void), int sig)
{
    fflush(NULL);
    const pid_t pid = fork();
    if (pid < 0) {
        die("fork failed");
    }
    if (pid == 0) {
        (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);   /* no core file for a deliberate crash */
        probe();
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFSIGNALED(status) || WTERMSIG(status) != sig) {
        die("self-test '%s' was not stopped by signal %d (status 0x%x): the harness cannot see this bug class",
            what, sig, (unsigned)status);
    }
}

/* Proves each detector fires before any replay counts: guard reads both sides, guard write, const request, UBSan. */
static void self_test(void)
{
    expect_death("read past the request", probe_read_past_end, SIGSEGV);
    expect_death("read before the request", probe_read_before_start, SIGSEGV);
    expect_death("write past resp_max", probe_write_past_end, SIGSEGV);
    expect_death("write into the request", probe_write_request, SIGSEGV);
#ifdef UDSOTA_FUZZ_Z
    expect_death("write past the stream buffer", probe_write_past_zout, SIGSEGV);
    expect_death("write past an inflater allocation", probe_write_past_zalloc, SIGSEGV);
#endif
#ifdef UDSOTA_FUZZ_UBSAN_TRAP
    expect_death("UBSan signed overflow", probe_ubsan, SIGILL);
#else
    (void)probe_ubsan;
#endif
}

/* Self-tests the detectors, replays the seeds and their mutants, checks the coverage floor, then replays
 * each corpus path given. Usage: fuzz_udsota [--mutations N] [corpus-dir-or-file ...]. Exit 0 = pass. */
int main(int argc, char **argv)
{
    unsigned mutations = MUTATIONS_DEFAULT;
    int argi = 1;
    if (argc > 2 && strcmp(argv[1], "--mutations") == 0) {
        mutations = (unsigned)strtoul(argv[2], NULL, 10);
        argi = 3;
    }
    harness_init();
    self_test();
    install_handlers();
    replay_seeds(mutations);
    check_coverage();
    for (; argi < argc; argi++) {
        replay_path(argv[argi]);
    }
    int reached = 0;
    for (int st = 0; st < ST_FUZZED; st++) {
        reached += g_stats.reached[st] ? 1 : 0;
    }
    printf("fuzz_udsota: PASS %lu inputs, %lu runs, %lu requests (%lu positive, %lu NRC, %lu silent), "
           "%lu poll answers, %d/%d states reached, digest=%016" PRIx64 "\n",
           g_stats.inputs, g_stats.runs, g_stats.requests, g_stats.positive, g_stats.nrc, g_stats.silent,
           g_stats.poll_answers, reached, (int)ST_FUZZED, g_digest);
    return 0;
}
#endif
