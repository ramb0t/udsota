/* ISO-TP frame-path fuzz harness. Drives the ISO-TP adapter (udsota_isotp.c, over the vendored isotp-c and the
 * receive mirror udsota_rxwatch.c) with raw CAN frames, as the diag task does: udsota_isotp_on_frame with rx_us
 * timestamps, udsota_isotp_on_func_frame and udsota_isotp_service, with the real server and updater behind it and
 * fake_engine's file-backed slots behind those, so a download has somewhere to go. fuzz_udsota feeds the server whole
 * requests; this is the bus input before them.
 *
 * An input is a program of events (ev_kind_t): single and multi-frame requests, the latter with wrong, missing and
 * extra CFs, short and long gaps, escape-length FFs and a tester that honours or ignores the adapter's FCs; raw
 * physical and functional frames of any DLC 0-15 and any PCI; tester FCs at any time; waits the diag task runs
 * through and clock jumps it sleeps through; the bus refusing or failing sends; and how the tester answers the
 * server's First Frames (afc_mode_t). Built-in seed programs run in every variant, then deterministic mutants of them
 * and random programs each in one variant (variant_t: BS, STmin, FC retry window, security, engine timing, gate and
 * a clock that wraps).
 *
 * Checked on every call: every frame the adapter sends is 8 bytes on the response ID, padded with 0xAA, with a valid
 * PCI (an SF of 1-7 bytes, an FF of 8-256, a CF with the next SN only while the tester's last CTS allows it and no
 * sooner than its STmin, an FC that is CTS with the link's BS and the message's STmin, never under the STmin asked
 * for, or overflow); an FC goes out only at the FC point the receive mirror predicted for that frame (or the adapter
 * withheld it there, counted it and, with nothing sending, dropped isotp-c's copy), or as the retry of the FC the bus
 * refused, inside the retry window and while its message is still held; a refused answer is retried only inside
 * UDSOTA_ISOTP_PARK_MAX_MS; the wait service returns is 1 ms while anything waits for the bus and never over 100 ms; a
 * multi-frame answer stops early only after an overflow FC, a second WAIT, a failed send or N_Bs; every answer
 * reassembled from the frames is well formed (7F, a SID the tester sent and a known NRC, or that SID's positive
 * shape, the app's DIDs and DTC list byte for byte) and at most 256 bytes; a functional frame is answered only while
 * the link is idle and only as udsota_on_functional_request allows (the functional subset, no 0x11, 0x12, 0x31, 0x7E
 * or 0x7F, no positive answer under SPRMIB, only 3E while a job runs), and never with an FC; the mirror agrees with
 * isotp-c's receive state after every call (mid-message exactly when isotp-c is, bar an orphan, with the same length,
 * offset and next SN); and once a program ends and the diag task has run DRAIN_MS on a clean bus (and SETTLE_MS more
 * for an answer still going out), nothing is left sending, parked or unserved. A download seed must verify its image
 * through the frame path. The frame the adapter reads ends at a guard page, as does its buffer struct, and UBSan
 * traps, as in fuzz_udsota; -DUDSOTA_SANITIZE=ON adds ASan, with SIGSEGV left to the guard pages.
 *
 * The PASS line ends with digest=, an FNV-1a hash of every frame fed to the adapter and every frame it offered the
 * bus, with the bus's answer, so a changed frame shows there even where the counts don't. The coverage lines before
 * it say what the replay reached, and a floor on them fails a replay that proves nothing. A FAIL names the program;
 * --only replays it alone with a trace of every frame. */
#define _DEFAULT_SOURCE   /* MAP_ANONYMOUS, sigaction, fork, prctl under -std=c11 */
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
#include <sys/wait.h>
#include <unistd.h>
#include "udsota.h"
#include "udsota_isotp.h"
#include "udsota_rxwatch.h"
#include "fake_engine.h"

#ifndef FUZZ_FRAMES_OTA_DIR
#error "FUZZ_FRAMES_OTA_DIR names a directory for fake_engine's slot files (CMakeLists.txt sets it)"
#endif

#define REQ_ID            0x710u
#define RESP_ID           0x718u
#define FUNC_ID           0x7DFu
#define CAN_DL            8u
#define PAD               0xAAu                   /* the adapter's padding (ISO_TP_FRAME_PADDING_VALUE) */
#define PCI_SF            0x0u
#define PCI_FF            0x1u
#define PCI_CF            0x2u
#define PCI_FC            0x3u
#define FS_CTS            0x0u
#define FS_WAIT           0x1u
#define FS_OVFLW          0x2u
#define N_TIMEOUT_US      1000000u                /* isotp-c's N_Bs and N_Cr (components/isotp/CMakeLists.txt) */
#define T0_US             UINT64_C(60000000)      /* 60 s after boot: past 0x27's post-boot delay */
#define T0_WRAP_US        ((UINT64_C(1) << 32) - UINT64_C(1500000))   /* 1.5 s before the us clock wraps */
#define EVENT_US          100u                    /* the clock between two events */
#define DRAIN_MS          6000u                   /* after a program: past S3, N_Bs, N_Cr, the park limit and the FC
                                                     retry windows */
#define SETTLE_MS         30000u                  /* then at most this for answers still going out at the tester's
                                                     STmin: two of 37 CFs at 127 ms each, with room */
#define HONOUR_WAIT_MS    1000u                   /* an honouring tester waits this long for an FC (its N_Bs) */
#define STALL_MS          1100u                   /* MF_STALL: past N_Cr */
#define JOB_MS            60u                     /* async engine: a job answers 60 ms later, past the 40 ms 0x78 */
#define SLOT_SIZE         (16u * FAKE_OTA_SECTOR) /* 64 KiB slots: a 34 past them is refused */
#define IMG_PAYLOAD       4400u                   /* the seeds' image: two 36 blocks, 4,093 bytes and the rest */
#define IMG_MAX           (IMG_PAYLOAD + 128u)
#define DTC_N             40u                     /* 19 0A answers 163 bytes: 24 CFs, so the SN wraps */
#define PROG_MAX          32768u                  /* a longer program is cut */
#define MUTATIONS_DEFAULT 400u                    /* mutants per seed program */
#define RANDOM_PROGRAMS   2000u
#define VARIANT_COUNT     5u

/* ---- The program: one op byte per event, its kind (op & 0x3F) % EV_COUNT, then the kind's bytes ---- */
typedef enum {
    EV_SF,        /* [n] [n bytes]: a Single Frame request of (n % 7) + 1 bytes; EV_FLAG: DLC n + 1, not 8 */
    EV_MF,        /* [len hi] [len lo] [gap] [flags] [at] [len bytes]: a multi-frame request (MF_*), CFs gap x 50 us
                     apart; a 12-bit len under 8 is len + 8 */
    EV_RAW,       /* [dlc] [8 bytes] [jitter]: one physical frame as given, DLC 0-15, rx_us moved jitter x 37 us */
    EV_FUNC,      /* [dlc] [8 bytes]: one functional frame as given, DLC 0-15 */
    EV_FC,        /* [fs] [bs] [stmin] [dlc]: a tester FC, DLC 3-8; EV_FLAG: DLC 0-8 */
    EV_WAIT,      /* [lo] [hi]: the diag task runs for that many ms, up to 16,383 */
    EV_JUMP,      /* [a] [b]: the clock jumps a x 25 ms + b x 97 us with no service in between */
    EV_BUS,       /* [mode] [n]: the next n sends are refused (UDSOTA_TX_RETRY) or fail, or tx_pending reads n */
    EV_AUTOFC,    /* [mode] [bs] [stmin] [delay]: how the tester answers the server's FFs (afc_mode_t), delay in ms */
    EV_COUNT
} ev_kind_t;
#define EV_FLAG   0x40u   /* the kind's variant */
#define EV_NOSVC  0x80u   /* no service after the event: the next frame arrives in the same wake */

#define MF_BAD_SN 0x01u   /* CF `at` carries a wrong SN */
#define MF_SKIP   0x02u   /* CF `at` is never sent */
#define MF_EXTRA  0x04u   /* one more CF after the last */
#define MF_HONOUR 0x08u   /* wait for the adapter's CTS before each block, as a real tester does */
#define MF_ESCAPE 0x10u   /* an escape-length FF: FF_DL 0, then a 32-bit length */
#define MF_TIGHT  0x20u   /* every CF's DLC is its bytes + 1, not 8 */
#define MF_FUNC   0x40u   /* a functional 3E 00 before CF `at` */
#define MF_STALL  0x80u   /* the tester goes quiet for STALL_MS before CF `at` (past N_Cr), then carries on */

typedef enum {            /* how the tester answers the server's FF, and each block's end after a CTS */
    AFC_NONE, AFC_CTS, AFC_WAIT_CTS, AFC_WAIT, AFC_WAIT2, AFC_OVFLW, AFC_BADFS, AFC_SHORT, AFC_COUNT
} afc_mode_t;

typedef struct {
    uint8_t  bs;               /* cfg.block_size (0 = 64) */
    uint32_t stmin_us;         /* cfg.stmin_us (0 = 2 ms) */
    uint16_t fc_retry_ms;      /* cfg.fc_retry_ms (0 = 10) */
    bool     stmin_hook;       /* hooks.stmin_us cycles through STMIN_HOOK */
    bool     secured;          /* 0x27 served, and 34 needs the programming key */
    bool     async;            /* engine ops answer JOB_MS later, so 0x78 goes out */
    unsigned gate_deny_from;   /* the gate refuses CONTINUE_TRANSFER from its n-th call on; 0 = never */
    uint64_t t0_us;            /* the clock at the program's start */
} variant_t;

static const variant_t VARIANTS[VARIANT_COUNT] = {
    {0u, 0u, 0u, false, true, false, 0u, T0_US},          /* the defaults: BS 64, STmin 2 ms, a 10 ms FC retry */
    {8u, 500u, 40u, true, true, true, 0u, T0_US},         /* BS 8, a per-message STmin, 0x78 from the engine */
    {1u, 0u, 0u, false, true, false, 3u, T0_US},          /* BS 1, and the gate withholds from the third FC point */
    {255u, 100u, 0u, false, false, true, 0u, T0_WRAP_US}, /* BS 255, STmin 100 us, no security, the clock wraps */
    {0u, 0u, 2000u, false, true, true, 0u, T0_US},        /* a 2 s FC retry window, past N_Cr */
};

static const uint32_t STMIN_HOOK[] = {0u, 100u, 250u, 950u, 1500u, 5000u, 127000u, 200000u};

/* The app's DIDs: 0x0101 and up answer multi-frame, 0x0102 wraps the SN, 0x0103 fills the 256-byte buffer and 0x0104
 * does not fit it (0x14). */
static const struct { uint16_t did; uint16_t len; } DIDS[] = {
    {0x0100u, 4u}, {0x0101u, 40u}, {0x0102u, 200u}, {0x0103u, 253u}, {0x0104u, 254u},
};

typedef struct {
    uint8_t *page;                             /* first usable byte; PROT_NONE pages sit before and after */
    size_t   size;
} arena_t;

typedef enum { FCE_SF, FCE_BAD_SN, FCE_LAST, FCE_NCR, FCE_COUNT } fc_end_t;   /* how a parked FC's message ended */

typedef struct {                               /* coverage, printed before the PASS line; check_coverage's floor */
    unsigned long programs, runs, events, fed_phys, fed_func, offered, refused, failed;
    unsigned long fed_pci[16], fed_dlc[16], kind[UDSOTA_RXW_BROKEN + 1], sent_pci[4];
    unsigned long park_retried;
    unsigned long fc_cts, fc_ovflw, withheld, fc_parked, fc_retried, orphan, ff_escape, rx_sn_wrap, tx_sn_wrap;
    unsigned long tester_fc[16];               /* tester FCs fed while an answer was going out, by FS */
    unsigned long ncr, nbs, ovflw_abort, wft_abort, send_err, s3_end, pending78, abandoned, resp_lost, fc_lost;
    unsigned long fc_ended[FCE_COUNT];         /* a parked FC dropped, counted lost, as its message ended, by how */
    unsigned long func_invalid, func_busy, func_silent, func_answered;
    unsigned long answers_pos, answers_nrc, answers_mf, verify_ok, drained;
} stats_t;

static const char *const KIND_NAME[UDSOTA_RXW_BROKEN + 1] = {
    "ignore", "single", "first", "refused", "consec", "consec_fc", "last", "broken",
};

/* ---- Harness state ---- */
static stats_t          G;
static udsota_server_t  S;
static udsota_isotp_t   T;
static udsota_isotp_bufs_t *B;                 /* flush against a guard page */
static udsota_config_t  CFG;
static udsota_engine_t  ENG;
static udsota_hooks_t   HOOKS;
static udsota_security_t SEC;
static udsota_can_t     CAN;
static fake_ota_t       OTA;
static arena_t          g_fr, g_ba;            /* the frame the adapter reads; the adapter's buffers */
static uint64_t         g_us;                  /* the one clock: isotp-c's microseconds, the server's ms */
static uint32_t         g_wait_ms = 1u;        /* what the last service asked the caller to sleep */
static uint64_t         g_digest = 0xCBF29CE484222325u;   /* FNV-1a 64 over every frame in and out */
static char             g_label[160];          /* what is being replayed, for failure and crash reports */
static volatile unsigned g_ev;                 /* the event being replayed, for crash reports */
static uint8_t          g_img[IMG_MAX];        /* the seeds' image */
static size_t           g_img_len;
static uint8_t          g_sink;
static bool            g_orphan_seen;         /* the last mirror check saw an orphan (counted once) */
static long             g_only = -1;           /* --only N: replay program N alone, tracing every frame */

typedef enum { CTX_NONE, CTX_FRAME, CTX_FUNC, CTX_SERVICE } ctx_t;
static ctx_t g_ctx;                            /* which adapter call is running, for the bus */
static struct {                                /* what the bus saw during that call */
    unsigned fc, starts, cf;
    uint8_t  fc_f[CAN_DL], start_f[CAN_DL];
} g_call;

static struct {                                /* per run */
    const variant_t *v;
    unsigned variant;
    unsigned rng_calls, stmin_calls, gate_calls, resets;
    uint32_t stmin_asked;                      /* the STmin the current message asked for (hook or cfg) */
    bool     sent_sid[256];                    /* SIDs the tester sent in any frame that could start a request */
    bool     verify_ok;                        /* 71 01 FF 01 00 was reassembled */
    bool     job_open;                         /* async engine: a job answers at job_end_us */
    uint64_t job_end_us;
    int      job_rc, last_rc;
} R;

static struct { uint32_t refuse, fail, pending; } g_bus;   /* the bus's next answers and can.tx_pending */

static struct {                                /* the FC the bus last refused, as the adapter should retry it */
    bool     valid;
    uint8_t  f[CAN_DL];
    uint32_t park_ms, last_ms;
} g_pfc;

static struct {                                /* the answer the bus last refused, as the adapter should retry it */
    bool     on;
    uint32_t since_ms, last_ms;                /* parked, and its last attempt */
    uint32_t lost;                             /* udsota_isotp_resp_lost() then: a change means it was replaced */
} g_pa;

static struct {                                /* the tester's view of the answer coming in */
    bool     open;
    uint32_t len, got;
    uint8_t  buf[UDSOTA_ISOTP_RESP_MAX];
    uint8_t  sn;                               /* the next CF's SN */
    uint32_t bs_left;                          /* CFs the last CTS allows; UINT32_MAX = no limit */
    uint32_t stmin_us;                         /* the last CTS's STmin as isotp-c decodes it */
    bool     cf_seen;
    uint64_t last_cf_us;
    uint32_t last_cf_stmin;                    /* the STmin in force when the last CF left */
    unsigned waits;                            /* WAITs since the last CTS */
    bool     may_abort;                        /* an overflow FC, a second WAIT or a failed CF: the send may stop */
    uint64_t progress_us;                      /* the FF, a CF or a tester FC: what isotp-c's N_Bs restarts from */
} A;

static struct {                                /* the tester's FC policy for the server's FFs */
    uint8_t  mode, bs, stmin, delay;
    bool     owed;
    unsigned stage;
    uint64_t due_us;
} F;

static struct { unsigned n; uint8_t f[CAN_DL]; } Q;   /* FCs the adapter got onto the bus, and the last one */

/* ---- Reporting ---- */

/* Prints a harness error (not an adapter defect) and exits 2. */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("fuzz_udsota_frames: HARNESS ERROR: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

/* Reports a defect with what was being replayed and the frame at hand, then exits 1. */
static void fail(const char *what, const uint8_t *f, size_t n)
{
    fprintf(stderr, "fuzz_udsota_frames: FAIL: %s\n  while replaying %s, event %u, t=%" PRIu64 " us\n", what,
            g_label, g_ev, g_us);
    if (f != NULL) {
        fprintf(stderr, "  frame (%zu B):", n);
        for (size_t i = 0; i < n && i < 48u; i++) {
            fprintf(stderr, " %02X", f[i]);
        }
        fputc('\n', stderr);
    }
    exit(1);
}

/* Folds one frame into g_digest: a tag, the length as 8 bytes little-endian, then the bytes (as fuzz_udsota does). */
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

/* --only's trace: one frame with the clock and the event. */
static void trace(const char *tag, const uint8_t *f, uint8_t dlc)
{
    if (g_only < 0) {
        return;
    }
    printf("%12" PRIu64 " ev %3u %s [%2u]", g_us, g_ev, tag, dlc);
    for (unsigned i = 0; i < dlc && i < CAN_DL; i++) {
        printf(" %02X", f[i]);
    }
    putchar('\n');
}

/* Maps at least min usable bytes, a whole number of pages, between two PROT_NONE guard pages. */
static void arena_init(arena_t *a, size_t min)
{
    const long ps_l = sysconf(_SC_PAGESIZE);
    if (ps_l <= 0) {
        die("sysconf(_SC_PAGESIZE) failed");
    }
    const size_t ps = (size_t)ps_l;
    const size_t size = ((min + ps - 1u) / ps) * ps;
    uint8_t *base = mmap(NULL, size + 2u * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED || mprotect(base, ps, PROT_NONE) != 0 || mprotect(base + ps + size, ps, PROT_NONE) != 0) {
        die("mmap/mprotect of a guard arena failed");
    }
    a->page = base + ps;
    a->size = size;
}

/* The server's clock: milliseconds of the one clock. */
static uint32_t now_ms(void)
{
    return (uint32_t)(g_us / 1000u);
}

/* ---- The fake engine, synchronous or answering JOB_MS later, over fake_engine's slots ---- */

/* Reports rc as the port's worker would: at once, or with the running (or a new) job, whose first failure it keeps. */
static int job(int rc)
{
    if (!R.v->async) {
        R.last_rc = rc;
        return rc;
    }
    if (!R.job_open) {
        R.job_open = true;
        R.job_end_us = g_us + JOB_MS * 1000u;
        R.job_rc = rc;
    } else if (R.job_rc == 0) {
        R.job_rc = rc;
    }
    return UDSOTA_PENDING;
}

/* engine.check_first: the image magic, as fake_ota_write wants it. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    (void)ctx;
    *why = (len != 0u && first[0] == 0xE9u) ? UDSOTA_DL_OK : UDSOTA_DL_BAD_HEADER;
    return *why == UDSOTA_DL_OK ? 0 : 1;
}

/* engine.begin: erases the other slot's image extent. */
static int eng_begin(void *ctx, uint32_t size)
{
    (void)ctx;
    return job(fake_ota_begin(&OTA, size));
}

/* engine.write: appends at off, which must be where the last write ended; joins a running job (the erase). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    const int rc = (off == OTA.written) ? fake_ota_write(&OTA, d, n) : -1;
    if (R.job_open) {
        return job(rc);
    }
    R.last_rc = rc;
    return rc;
}

/* engine.verify (FF01): fake_ota_end's segment walk and SHA-256. */
static int eng_verify(void *ctx)
{
    (void)ctx;
    return job(fake_ota_end(&OTA));
}

/* engine.activate: the verified slot boots next. */
static int eng_activate(void *ctx)
{
    (void)ctx;
    return job(fake_ota_activate(&OTA));
}

/* engine.confirm: a PENDING_VERIFY running image becomes VALID. */
static int eng_confirm(void *ctx)
{
    (void)ctx;
    return job(fake_ota_confirm(&OTA));
}

/* engine.abort: drops the open write. */
static void eng_abort(void *ctx)
{
    (void)ctx;
    (void)fake_ota_abort(&OTA);
}

/* engine.unverify: an accepted 34 un-verifies the other slot. */
static void eng_unverify(void *ctx)
{
    (void)ctx;
    fake_ota_unverify(&OTA);
}

/* engine.poll: UDSOTA_PENDING until the job's time has come, then its result. */
static int eng_poll(void *ctx)
{
    (void)ctx;
    if (R.job_open) {
        if (g_us < R.job_end_us) {
            return UDSOTA_PENDING;
        }
        R.job_open = false;
        R.last_rc = R.job_rc;
    }
    return R.last_rc;
}

/* engine.status (F1F0): the slots as fake_engine models them. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    (void)ctx;
    fake_ota_fill_status(&OTA, out);
}

/* ---- Security, as fuzz_udsota mocks it ---- */

/* The seed rng16 hands out on its call-th call in a run: deterministic, never all zero. */
static void mock_seed(unsigned call, uint8_t out[16])
{
    for (unsigned i = 0; i < 16u; i++) {
        out[i] = (uint8_t)(0x11u * (i + 1u) + call);
    }
    out[0] |= 0x01u;
}

/* security.rng16: mock_seed of this run's call count. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    (void)ctx;
    mock_seed(R.rng_calls++, out);
    return true;
}

/* The key the server expects: seed[i] ^ level ^ 0xA5, the stand-in the server tests use for HMAC. */
static void fake_key(const uint8_t *seed, uint8_t level, uint8_t out[16])
{
    for (unsigned i = 0; i < 16u; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5u);
    }
}

/* security.key: fake_key. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    (void)ctx;
    fake_key(seed, level, out);
    return true;
}

/* ---- Hooks ---- */

/* hooks.gate: the variant's gate refuses CONTINUE_TRANSFER (every 36 and FC point) from its n-th call on. */
static uint8_t hook_gate(void *ctx, udsota_op_t op)
{
    (void)ctx;
    if (op != UDSOTA_OP_CONTINUE_TRANSFER || R.v->gate_deny_from == 0u) {
        return 0u;
    }
    return (++R.gate_calls >= R.v->gate_deny_from) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : 0u;
}

/* hooks.stmin_us: cycles through STMIN_HOOK: 250 us and 950 us, which the FC rounds up to 300 us and 1 ms (both of
 * stmin_sendable's rounding branches), and 200 ms, which it caps at 127 ms. */
static uint32_t hook_stmin(void *ctx)
{
    (void)ctx;
    R.stmin_asked = STMIN_HOOK[R.stmin_calls++ % (sizeof STMIN_HOOK / sizeof STMIN_HOOK[0])];
    return R.stmin_asked;
}

/* Byte i of an app DID. */
static uint8_t did_byte(uint16_t did, size_t i)
{
    return (uint8_t)(did * 7u + i * 13u + 1u);
}

/* The app DID's index in DIDS, or -1. */
static int did_find(uint16_t did)
{
    for (size_t k = 0; k < sizeof DIDS / sizeof DIDS[0]; k++) {
        if (DIDS[k].did == did) {
            return (int)k;
        }
    }
    return -1;
}

/* hooks.did_read: the app's DIDs, or their length, unwritten, when longer than max. */
static size_t hook_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    (void)ctx;
    const int k = did_find(did);
    if (k < 0) {
        return 0u;
    }
    const size_t len = DIDS[k].len;
    if (len > max) {
        return len;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = did_byte(did, i);
    }
    return len;
}

/* hooks.reset: counted; returns as a failed restart, so the server re-opens. */
static bool hook_reset(void *ctx)
{
    (void)ctx;
    R.resets++;
    return false;
}

/* hooks.comm_control: allows every control. */
static uint8_t hook_comm_control(void *ctx, uint8_t control, uint8_t comm_type)
{
    (void)ctx;
    (void)control;
    (void)comm_type;
    return 0u;
}

/* hooks.dtc_setting: nothing to record. */
static void hook_dtc_setting(void *ctx, bool on)
{
    (void)ctx;
    (void)on;
}

/* The i-th DTC's 24 bits and status. */
static uint32_t dtc24(size_t i)
{
    return 0x100000u + (uint32_t)i * 0x0101u;
}

/* The i-th DTC's status. */
static uint8_t dtc_status(size_t i)
{
    return (uint8_t)(i * 37u + 1u);
}

/* hooks.dtc_get: DTC_N DTCs, so 19 0A answers multi-frame. */
static bool hook_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    (void)ctx;
    if (i >= DTC_N) {
        return false;
    }
    out->dtc = dtc24(i);
    out->status = dtc_status(i);
    return true;
}

/* ---- The bus and the tester ---- */

/* can.now_us: the one clock. */
static uint32_t can_now_us(void *ctx)
{
    (void)ctx;
    return (uint32_t)g_us;
}

/* can.tx_pending: what EV_BUS set. */
static uint32_t can_tx_pending(void *ctx)
{
    (void)ctx;
    return g_bus.pending;
}

/* STmin byte to microseconds, exactly as isotp-c decodes it: a reserved value is 0, so the CF-pacing oracle's floor
 * for it is isotp-c's (the link's own STmin), not ISO 15765-2's, whose sender takes a reserved STmin as 127 ms. */
static uint32_t stmin_to_us(uint8_t b)
{
    if (b <= 0x7Fu) {
        return (uint32_t)b * 1000u;
    }
    return (b >= 0xF1u && b <= 0xF9u) ? (uint32_t)(b - 0xF0u) * 100u : 0u;
}

/* Microseconds to the STmin byte isotp-c sends (the adapter only asks for encodable values). */
static uint8_t stmin_byte(uint32_t us)
{
    if (us > 127000u) {
        return 0u;
    }
    return (us >= 100u && us <= 900u) ? (uint8_t)(0xF0u + us / 100u) : (uint8_t)(us / 1000u);
}

/* The BS the link's FCs carry. */
static uint8_t port_bs(void)
{
    return T.link_cfg.bs != 0u ? T.link_cfg.bs : (uint8_t)ISOTP_PORT_DEFAULT_BS;
}

/* True when the NRC is one the server sends for sid: every NRC udsota.h defines, 0x14 only for a 22 or 19. */
static bool nrc_known(uint8_t sid, uint8_t nrc)
{
    switch (nrc) {
    case UDSOTA_NRC_RESPONSE_TOO_LONG:
        return sid == UDSOTA_SID_READ_DID || sid == UDSOTA_SID_READ_DTC;
    case UDSOTA_NRC_GENERAL_REJECT: case UDSOTA_NRC_SERVICE_NOT_SUPPORTED: case UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED:
    case UDSOTA_NRC_INCORRECT_LENGTH: case UDSOTA_NRC_BUSY_REPEAT: case UDSOTA_NRC_CONDITIONS_NOT_CORRECT:
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

/* 59 0A: every DTC in order, with the availability mask 0xFF. */
static bool dtc_list_ok(const uint8_t *r, size_t n)
{
    if (n != 3u + 4u * DTC_N || r[2] != 0xFFu) {
        return false;
    }
    for (size_t i = 0; i < DTC_N; i++) {
        const uint8_t *e = &r[3u + 4u * i];
        if ((((uint32_t)e[0] << 16) | ((uint32_t)e[1] << 8) | e[2]) != dtc24(i) || e[3] != dtc_status(i)) {
            return false;
        }
    }
    return true;
}

/* True when a positive answer has its SID's shape; an app DID's data and 59 0A's list byte for byte. */
static bool positive_ok(uint8_t sid, const uint8_t *r, size_t n)
{
    switch (sid) {
    case UDSOTA_SID_SESSION:
        return n == 6u && r[1] >= 1u && r[1] <= 3u && r[2] == 0x00u && r[3] == 0x32u && r[4] == 0x01u && r[5] == 0xF4u;
    case UDSOTA_SID_RESET:
        return n == 2u && r[1] == UDSOTA_RESET_HARD;
    case UDSOTA_SID_READ_DID: {
        if (n < 4u) {
            return false;
        }
        const uint16_t did = (uint16_t)((r[1] << 8) | r[2]);
        const int k = did_find(did);
        if (k < 0) {
            return true;
        }
        if (n != 3u + DIDS[k].len) {
            return false;
        }
        for (size_t i = 0; i < DIDS[k].len; i++) {
            if (r[3u + i] != did_byte(did, i)) {
                return false;
            }
        }
        return true;
    }
    case UDSOTA_SID_SECURITY:
        return (r[1] & 1u) != 0u ? n == 2u + UDSOTA_SEED_LEN : n == 2u;
    case UDSOTA_SID_ROUTINE:
        return (n == 4u || n == 5u) && r[1] == UDSOTA_RC_START;
    case UDSOTA_SID_REQUEST_DOWNLOAD:
        return n == 4u && r[1] == UDSOTA_DL_LFID && r[2] == 0x0Fu && r[3] == 0xFFu;
    case UDSOTA_SID_TRANSFER_DATA:
        return n == 2u;
    case UDSOTA_SID_TRANSFER_EXIT:
        return n == 1u;
    case UDSOTA_SID_TESTER_PRESENT:
        return n == 2u && r[1] == UDSOTA_TP_ZERO_SUBFUNC;
    case UDSOTA_SID_COMM_CONTROL:
        return n == 2u && r[1] <= UDSOTA_CC_DISABLE_RX_TX;
    case UDSOTA_SID_DTC_SETTING:
        return n == 2u && (r[1] == UDSOTA_DTC_ON || r[1] == UDSOTA_DTC_OFF);
    case UDSOTA_SID_READ_DTC:
        if (n < 2u) {
            return false;
        }
        switch (r[1]) {
        case UDSOTA_RDTC_COUNT_BY_MASK:
            return n == 6u;
        case UDSOTA_RDTC_BY_MASK:
            return n >= 3u && (n - 3u) % 4u == 0u;
        case UDSOTA_RDTC_SUPPORTED:
            return dtc_list_ok(r, n);
        default:
            return false;
        }
    default:
        return false;
    }
}

/* Checks one answer reassembled from the adapter's frames. */
static void check_answer(const uint8_t *r, size_t n)
{
    if (n == 0u || n > UDSOTA_ISOTP_RESP_MAX) {
        fail("an answer of no bytes or over the 256-byte response buffer", r, n);
    }
    if (r[0] == UDSOTA_NEG_RESPONSE) {
        if (n != 3u || !R.sent_sid[r[1]] || !nrc_known(r[1], r[2])) {
            fail("malformed negative answer (want 7F <a SID the tester sent> <known NRC>)", r, n);
        }
        G.answers_nrc++;
        G.pending78 += r[2] == UDSOTA_NRC_RESPONSE_PENDING;
        return;
    }
    const uint8_t sid = (uint8_t)(r[0] & (uint8_t)~UDSOTA_POS_BIT);
    if ((r[0] & UDSOTA_POS_BIT) == 0u || !R.sent_sid[sid] || !positive_ok(sid, r, n)) {
        fail("malformed positive answer", r, n);
    }
    G.answers_pos++;
    static const uint8_t VERIFIED[] = {0x71, 0x01, 0xFF, 0x01, UDSOTA_DL_OK};
    if (n == sizeof VERIFIED && memcmp(r, VERIFIED, n) == 0) {
        R.verify_ok = true;
        G.verify_ok++;
    }
}

/* The tester owes an FC per its policy, delay ms from now. */
static void owe_fc(void)
{
    if (F.mode != AFC_NONE) {
        F.owed = true;
        F.stage = 0u;
        F.due_us = g_us + (uint64_t)F.delay * 1000u;
    }
}

/* A new answer's SF or FF: an answer still open must have been allowed to stop. */
static void answer_start(const uint8_t *d)
{
    if (A.open) {
        if (!A.may_abort && g_us - A.progress_us < N_TIMEOUT_US) {
            fail("a multi-frame answer stopped before an overflow FC, a second WAIT, a failed send or N_Bs", d, CAN_DL);
        }
        A.open = false;
        G.abandoned++;
    }
    F.owed = false;
}

/* The tester takes one frame the bus carried from the adapter. */
static void tester_rx(const uint8_t *d)
{
    switch (d[0] >> 4) {
    case PCI_SF:
        answer_start(d);
        check_answer(&d[1], d[0] & 0x0Fu);
        break;
    case PCI_FF:
        answer_start(d);
        memset(&A, 0, sizeof A);
        A.open = true;
        A.len = ((uint32_t)(d[0] & 0x0Fu) << 8) | d[1];
        A.got = CAN_DL - 2u;
        memcpy(A.buf, &d[2], A.got);
        A.sn = 1u;
        A.progress_us = g_us;
        G.answers_mf++;
        owe_fc();
        break;
    case PCI_CF: {
        if (!A.open) {
            fail("a CF with no multi-frame answer open", d, CAN_DL);
        }
        if ((d[0] & 0x0Fu) != A.sn) {
            fail("a CF with the wrong SN", d, CAN_DL);
        }
        if (A.bs_left == 0u) {
            fail("a CF the tester's FCs did not allow (no CTS, or its block is used up)", d, CAN_DL);
        }
        const uint32_t stmin = A.stmin_us < A.last_cf_stmin ? A.stmin_us : A.last_cf_stmin;   /* a later CTS may
                                                                                                  lower it at once */
        if (A.cf_seen && g_us - A.last_cf_us < stmin) {
            fail("two CFs closer than the tester's STmin", d, CAN_DL);
        }
        const uint32_t take = (A.len - A.got < 7u) ? A.len - A.got : 7u;
        for (uint32_t i = 1u + take; i < CAN_DL; i++) {
            if (d[i] != PAD) {
                fail("a CF not padded with 0xAA", d, CAN_DL);
            }
        }
        memcpy(&A.buf[A.got], &d[1], take);
        A.got += take;
        G.tx_sn_wrap += A.sn == 0u;
        A.sn = (uint8_t)((A.sn + 1u) & 0x0Fu);
        A.bs_left -= (A.bs_left != UINT32_MAX) ? 1u : 0u;
        A.cf_seen = true;
        A.last_cf_us = g_us;
        A.last_cf_stmin = A.stmin_us;
        A.progress_us = g_us;
        if (A.got == A.len) {
            A.open = false;
            F.owed = false;
            check_answer(A.buf, A.len);
        } else if (A.bs_left == 0u && (F.mode == AFC_CTS || F.mode == AFC_WAIT_CTS)) {
            owe_fc();
        }
        break;
    }
    case PCI_FC:
        Q.n++;
        memcpy(Q.f, d, CAN_DL);
        break;
    default:
        break;
    }
}

/* One FC the adapter offered the bus, with the bus's answer: in answer to a physical frame it is that frame's (the
 * FC-point check follows the call); from service it can only be the retry of the FC the bus refused, inside the
 * retry window and, for a CTS, while its message is still being received. */
static void fc_offered(const uint8_t *d, int rc)
{
    const uint8_t fs = d[0] & 0x0Fu;
    if (g_ctx == CTX_FRAME) {
        g_call.fc++;
        memcpy(g_call.fc_f, d, CAN_DL);
        g_pfc.valid = rc == UDSOTA_TX_RETRY;
        if (g_pfc.valid) {
            memcpy(g_pfc.f, d, CAN_DL);
            g_pfc.park_ms = g_pfc.last_ms = now_ms();
            G.fc_parked++;
        }
        return;
    }
    if (g_ctx != CTX_SERVICE) {
        fail("an FC in answer to a functional frame", d, CAN_DL);
    }
    if (!g_pfc.valid || memcmp(d, g_pfc.f, CAN_DL) != 0) {
        fail("an FC from service that is not the retry of the FC the bus refused", d, CAN_DL);
    }
    if ((uint32_t)(g_pfc.last_ms - g_pfc.park_ms) >= T.fc_retry_ms) {
        fail("a parked FC retried after its retry window closed", d, CAN_DL);
    }
    if (fs == FS_CTS && !T.rxw.in_msg) {
        fail("a parked CTS retried for a message the adapter no longer receives", d, CAN_DL);
    }
    g_call.fc++;
    G.fc_retried++;
    g_pfc.last_ms = now_ms();
    g_pfc.valid = rc == UDSOTA_TX_RETRY;
}

/* One SF or FF the adapter offered the bus: from service, while the answer the bus refused is still parked, it is that
 * answer's retry, which may follow only an attempt made inside UDSOTA_ISOTP_PARK_MAX_MS of parking it. */
static void answer_offered(int rc)
{
    const uint32_t lost = udsota_isotp_resp_lost(&T);
    if (g_pa.on && g_ctx == CTX_SERVICE && lost == g_pa.lost) {
        if ((uint32_t)(g_pa.last_ms - g_pa.since_ms) >= UDSOTA_ISOTP_PARK_MAX_MS) {
            fail("a parked answer retried after UDSOTA_ISOTP_PARK_MAX_MS", NULL, 0);
        }
        G.park_retried++;
    } else {
        g_pa.since_ms = now_ms();
    }
    g_pa.last_ms = now_ms();
    g_pa.lost = lost;
    g_pa.on = rc == UDSOTA_TX_RETRY;
}

/* can.send: checks the frame's shape, answers per EV_BUS, and hands an accepted frame to the tester. */
static int bus_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    (void)ctx;
    G.offered++;
    if (id != RESP_ID || len != CAN_DL) {
        fail("a frame off the response ID or not 8 bytes", data, len > CAN_DL ? CAN_DL : len);
    }
    const uint8_t pci = data[0] >> 4;
    switch (pci) {
    case PCI_SF: {
        const uint8_t n = data[0] & 0x0Fu;
        if (n == 0u || n > CAN_DL - 1u) {
            fail("an SF of 0 or over 7 bytes", data, CAN_DL);
        }
        for (unsigned i = 1u + n; i < CAN_DL; i++) {
            if (data[i] != PAD) {
                fail("an SF not padded with 0xAA", data, CAN_DL);
            }
        }
        break;
    }
    case PCI_FF: {
        const uint32_t n = ((uint32_t)(data[0] & 0x0Fu) << 8) | data[1];
        if (n < CAN_DL || n > UDSOTA_ISOTP_RESP_MAX) {
            fail("an FF under 8 or over 256 bytes (the response buffer)", data, CAN_DL);
        }
        break;
    }
    case PCI_CF:
        if (g_ctx != CTX_SERVICE) {
            fail("a CF outside service (isotp_poll)", data, CAN_DL);
        }
        g_call.cf++;
        break;
    case PCI_FC: {
        const uint8_t fs = data[0] & 0x0Fu;
        const uint32_t asked = R.v->stmin_hook ? R.stmin_asked : S.cfg.stmin_us;
        const bool cts = fs == FS_CTS && data[1] == port_bs() && data[2] == stmin_byte(T.msg_stmin_us) &&
                         stmin_to_us(data[2]) >= (asked < 127000u ? asked : 127000u);   /* rounded up, never down */
        const bool ovf = fs == FS_OVFLW && data[1] == 0u && data[2] == 0u;
        if (!cts && !ovf) {
            fail("an FC neither CTS with the link's BS and the message's STmin (never under what was asked) nor "
                 "overflow", data, CAN_DL);
        }
        for (unsigned i = 3u; i < CAN_DL; i++) {
            if (data[i] != PAD) {
                fail("an FC not padded with 0xAA", data, CAN_DL);
            }
        }
        G.fc_cts += cts;
        G.fc_ovflw += ovf;
        break;
    }
    default:
        fail("a frame with a reserved PCI", data, CAN_DL);
    }
    G.sent_pci[pci]++;
    int rc = 0;
    if (g_bus.fail != 0u) {
        g_bus.fail--;
        rc = -1;
        G.failed++;
    } else if (g_bus.refuse != 0u) {
        g_bus.refuse--;
        rc = UDSOTA_TX_RETRY;
        G.refused++;
    }
    uint8_t rec[CAN_DL + 1u];
    memcpy(rec, data, CAN_DL);
    rec[CAN_DL] = (uint8_t)(rc == 0 ? 0u : rc == UDSOTA_TX_RETRY ? 1u : 2u);
    digest_fold('T', rec, sizeof rec);
    trace(rc == 0 ? "tx  " : rc == UDSOTA_TX_RETRY ? "tx R" : "tx F", data, CAN_DL);
    if (pci == PCI_SF || pci == PCI_FF) {
        answer_offered(rc);
    }
    if (pci == PCI_FC) {
        fc_offered(data, rc);
    } else if (pci != PCI_CF && g_ctx != CTX_NONE && g_call.starts++ == 0u) {
        memcpy(g_call.start_f, data, CAN_DL);
    }
    if (rc == 0) {
        tester_rx(data);
    } else if (rc != UDSOTA_TX_RETRY && pci == PCI_CF) {
        A.may_abort = true;                    /* isotp-c ends the send */
    }
    return rc;
}

/* ---- The adapter's three entry points, each followed by its checks ---- */

/* True while the adapter holds an answer (parked or its CFs going out). */
static bool tx_busy(void)
{
    return T.park_len != 0u || T.link.send_status == ISOTP_SEND_STATUS_INPROGRESS;
}

/* The mirror's claim: isotp-c is mid-message exactly when the mirror is, with the same length, offset and next SN;
 * the one exception is an orphan, a message dropped at a withheld FC that isotp-c still holds while the answer goes
 * out. */
static void check_mirror(void)
{
    const bool inprog = T.link.receive_status == ISOTP_RECEIVE_STATUS_INPROGRESS;
    if (T.rx_orphan) {
        if (T.rxw.in_msg || !inprog) {
            fail("an orphan while the mirror is mid-message or isotp-c is not", NULL, 0);
        }
        G.orphan += !g_orphan_seen;
        g_orphan_seen = true;
        return;
    }
    g_orphan_seen = false;
    if (T.rxw.in_msg != inprog) {
        fail("the mirror's in_msg disagrees with isotp-c's receive_status", NULL, 0);
    }
    if (inprog && (T.rxw.msg_len != T.link.receive_size || T.rxw.msg_got != T.link.receive_offset ||
                   ((T.rxw.cf_count + 1u) & 0x0Fu) != T.link.receive_sn)) {
        fail("the mirror's message (length, offset or next SN) disagrees with isotp-c's", NULL, 0);
    }
}

/* Counts isotp-c's send ending in error since send_before, by cause. */
static void note_send_end(uint8_t send_before)
{
    if (send_before != ISOTP_SEND_STATUS_INPROGRESS || T.link.send_status != ISOTP_SEND_STATUS_ERROR) {
        return;
    }
    switch (T.link.send_protocol_result) {
    case ISOTP_PROTOCOL_RESULT_TIMEOUT_BS: G.nbs++; break;
    case ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW: G.ovflw_abort++; break;
    case ISOTP_PROTOCOL_RESULT_WFT_OVRN: G.wft_abort++; break;
    default: G.send_err++; break;
    }
}

/* Copies a frame of dlc bytes (8 at most, as a classic CAN driver holds) flush against the guard page. */
static const uint8_t *frame_at_guard(const uint8_t f[CAN_DL], uint8_t dlc)
{
    const size_t m = dlc < CAN_DL ? dlc : CAN_DL;
    uint8_t *p = g_fr.page + g_fr.size - m;
    memcpy(p, f, m);
    return p;
}

/* Marks the SID a frame could start a request with, so an answer to it is expected. */
static void note_sid(const uint8_t *f, uint8_t dlc)
{
    if (dlc < 2u) {
        return;
    }
    if ((f[0] >> 4) == PCI_SF && (f[0] & 0x0Fu) != 0u) {
        R.sent_sid[f[1]] = true;
    } else if ((f[0] >> 4) == PCI_FF && dlc >= CAN_DL) {
        R.sent_sid[(f[0] & 0x0Fu) != 0u || f[1] != 0u ? f[2] : f[6]] = true;
    }
}

/* The tester's FC reaches isotp-c while an answer goes out: what it lets the send do next. */
static void note_tester_fc(const uint8_t *f, uint8_t dlc)
{
    if (!A.open || dlc < 3u || dlc > CAN_DL || (f[0] >> 4) != PCI_FC) {
        return;                                /* isotp-c ignores it (no send, or LENGTH) */
    }
    const uint8_t fs = f[0] & 0x0Fu;
    G.tester_fc[fs]++;
    A.may_abort = A.may_abort || g_us - A.progress_us >= N_TIMEOUT_US;   /* too late: N_Bs may have ended the send */
    A.progress_us = g_us;                      /* any FC restarts N_Bs */
    if (fs == FS_CTS) {
        A.bs_left = f[1] != 0u ? f[1] : UINT32_MAX;
        A.stmin_us = stmin_to_us(f[2]);
        A.waits = 0u;
    } else if (fs == FS_WAIT) {
        A.may_abort = A.may_abort || ++A.waits > 1u;
    } else if (fs == FS_OVFLW) {
        A.may_abort = true;
    }
}

/* One physical frame through udsota_isotp_on_frame, then the FC-point and mirror checks: the mirror classifies the
 * frame again from its state before the call, and isotp-c must have sent exactly the FC that predicts. */
static void feed_phys(const uint8_t f[CAN_DL], uint8_t dlc, uint32_t rx_us)
{
    const uint8_t *data = frame_at_guard(f, dlc);
    uint8_t rec[CAN_DL + 1u] = {dlc};
    memcpy(&rec[1], data, dlc < CAN_DL ? dlc : CAN_DL);
    digest_fold('R', rec, 1u + (dlc < CAN_DL ? dlc : CAN_DL));
    trace("rx  ", data, dlc);
    G.fed_phys++;
    G.fed_dlc[dlc & 0x0Fu]++;
    if (dlc >= 1u) {
        G.fed_pci[f[0] >> 4]++;
    }
    note_sid(data, dlc);
    note_tester_fc(data, dlc);
    const udsota_rxwatch_t before = T.rxw;
    const uint16_t withheld = S.counters.withheld_fcs;
    const uint8_t send_before = T.link.send_status;
    const bool parked_before = T.fc_parked;
    const uint32_t fc_lost_before = udsota_isotp_fc_lost(&T);
    memset(&g_call, 0, sizeof g_call);
    g_ctx = CTX_FRAME;
    udsota_isotp_on_frame(&T, data, dlc, rx_us, now_ms());
    g_ctx = CTX_NONE;
    udsota_rxwatch_t pred = before;
    const udsota_rxw_kind_t k = udsota_rxwatch_frame(&pred, data, dlc, rx_us, T.rx_limit, T.link_cfg.bs);
    G.kind[k]++;
    G.ff_escape += k == UDSOTA_RXW_FIRST && data[0] == PCI_FF << 4 && data[1] == 0u;
    G.rx_sn_wrap += (k == UDSOTA_RXW_CONSEC || k == UDSOTA_RXW_CONSEC_FC || k == UDSOTA_RXW_LAST) &&
                    (data[0] & 0x0Fu) == 0u;
    const bool dropped = S.counters.withheld_fcs != withheld;
    const uint8_t fs = g_call.fc_f[0] & 0x0Fu;
    if (parked_before && !T.fc_parked && udsota_isotp_fc_lost(&T) != fc_lost_before && g_call.fc == 0u) {
        G.fc_ended[FCE_SF] += k == UDSOTA_RXW_SINGLE;
        G.fc_ended[FCE_BAD_SN] += k == UDSOTA_RXW_BROKEN;
        G.fc_ended[FCE_LAST] += k == UDSOTA_RXW_LAST;
    }
    switch (k) {
    case UDSOTA_RXW_FIRST:
    case UDSOTA_RXW_CONSEC_FC:
        if (dropped) {
            if (g_call.fc != 0u || T.rxw.in_msg) {
                fail("an FC point withheld, yet an FC went out or the mirror still holds the message", data, dlc);
            }
            if (T.link.send_status != ISOTP_SEND_STATUS_INPROGRESS &&
                T.link.receive_status == ISOTP_RECEIVE_STATUS_INPROGRESS) {
                fail("a message withheld while nothing was sending is still in isotp-c (not re-initialised)", data,
                     dlc);
            }
            g_pfc.valid = false;               /* the adapter drops a parked FC with its message */
            G.withheld++;
        } else if (g_call.fc != 1u || fs != FS_CTS) {
            fail("the mirror predicted an FC point, and isotp-c sent no CTS (or more than one FC)", data, dlc);
        }
        break;
    case UDSOTA_RXW_REFUSED:
        if (g_call.fc != 1u || fs != FS_OVFLW || dropped) {
            fail("the mirror predicted an overflow FC, and isotp-c sent none", data, dlc);
        }
        break;
    default:
        if (g_call.fc != 0u || dropped) {
            fail("isotp-c sent an FC, or the adapter withheld one, where the mirror predicted no FC point", data, dlc);
        }
        break;
    }
    note_send_end(send_before);
    check_mirror();
}

/* One functional frame through udsota_isotp_on_func_frame: answered only if it is an SF that reaches the server while
 * the link is idle, and then only as the functional rules allow; otherwise nothing is sent and nothing parked. */
static void feed_func(const uint8_t f[CAN_DL], uint8_t dlc)
{
    const uint8_t *data = frame_at_guard(f, dlc);
    uint8_t rec[CAN_DL + 1u] = {dlc};
    memcpy(&rec[1], data, dlc < CAN_DL ? dlc : CAN_DL);
    digest_fold('F', rec, 1u + (dlc < CAN_DL ? dlc : CAN_DL));
    trace("func", data, dlc);
    G.fed_func++;
    note_sid(data, dlc);
    const uint8_t n = (dlc >= 2u && dlc <= CAN_DL) ? (uint8_t)(data[0] & 0x0Fu) : 0u;
    const bool sf = dlc >= 2u && dlc <= CAN_DL && (data[0] >> 4) == PCI_SF && n != 0u && n <= dlc - 1u;
    const bool idle = !tx_busy() && T.link.receive_status == ISOTP_RECEIVE_STATUS_IDLE;
    const bool job_before = S.job_running;
    const size_t park_before = T.park_len;
    const uint32_t lost_before = udsota_isotp_resp_lost(&T);
    uint8_t req[CAN_DL];
    memcpy(req, &data[sf ? 1u : 0u], sf ? n : 0u);
    memset(&g_call, 0, sizeof g_call);
    g_ctx = CTX_FUNC;
    udsota_isotp_on_func_frame(&T, data, dlc, now_ms());
    g_ctx = CTX_NONE;
    check_mirror();
    if (!sf || !idle) {
        if (g_call.starts != 0u || T.park_len != park_before || udsota_isotp_resp_lost(&T) != lost_before) {
            fail("an answer to a functional frame that is no SF or arrived while the link was busy", data, dlc);
        }
        G.func_invalid += !sf;
        G.func_busy += sf && !idle;
        return;
    }
    size_t len = T.park_len;                   /* parked: the bus refused its first frame */
    if (g_call.starts != 0u) {
        const uint8_t *h = g_call.start_f;
        len = (h[0] >> 4) == PCI_SF ? (h[0] & 0x0Fu) : (((size_t)(h[0] & 0x0Fu) << 8) | h[1]);
    }
    if (len == 0u) {
        G.func_silent++;
        return;
    }
    const uint8_t *r = B->park;                /* the adapter's copy of the answer it sent or parked */
    const uint8_t sid = req[0];
    const uint8_t sub = n >= 2u ? (uint8_t)(req[1] & (uint8_t)~UDSOTA_SPRMIB) : 0u;
    const bool spr = n >= 2u && (req[1] & UDSOTA_SPRMIB) != 0u && sid != UDSOTA_SID_READ_DID;
    const bool served = sid == UDSOTA_SID_SESSION ? (sub == UDSOTA_SESSION_DEFAULT || sub == UDSOTA_SESSION_EXTENDED)
                      : (sid == UDSOTA_SID_TESTER_PRESENT || sid == UDSOTA_SID_READ_DTC || sid == UDSOTA_SID_READ_DID ||
                         sid == UDSOTA_SID_COMM_CONTROL || sid == UDSOTA_SID_DTC_SETTING);
    if (!served) {
        fail("answered a functional request outside the functional subset", data, dlc);
    }
    if (job_before && sid != UDSOTA_SID_TESTER_PRESENT) {
        fail("answered a functional request other than 3E while a job ran", data, dlc);
    }
    if (r[0] == UDSOTA_NEG_RESPONSE && len == 3u &&
        (r[2] == UDSOTA_NRC_SERVICE_NOT_SUPPORTED || r[2] == UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED ||
         r[2] == UDSOTA_NRC_REQUEST_OUT_OF_RANGE || r[2] == UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION ||
         r[2] == UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION)) {
        fail("an NRC ISO 14229-1 suppresses for a functional request", r, len);
    }
    if (r[0] != UDSOTA_NEG_RESPONSE && spr) {
        fail("a positive answer to a functional request with SPRMIB set", r, len);
    }
    G.func_answered++;
}

/* One udsota_isotp_service, then its checks: the mirror, the wait it returns, and what timed out. */
static void service(void)
{
    const uint8_t send_before = T.link.send_status;
    const bool rx_before = T.link.receive_status == ISOTP_RECEIVE_STATUS_INPROGRESS;
    const uint8_t session_before = S.session;
    const bool parked_before = T.fc_parked;
    const uint32_t fc_lost_before = udsota_isotp_fc_lost(&T);
    memset(&g_call, 0, sizeof g_call);
    g_ctx = CTX_SERVICE;
    const uint32_t w = udsota_isotp_service(&T, now_ms());
    g_ctx = CTX_NONE;
    if (w > UDSOTA_ISOTP_WAIT_IDLE_MS || ((tx_busy() || T.fc_parked) && w != UDSOTA_ISOTP_WAIT_SEND_MS)) {
        fail("service asked for a wait over 100 ms, or over 1 ms while a frame waits for the bus", NULL, 0);
    }
    g_wait_ms = w != 0u ? w : 1u;
    const bool ncr = rx_before && T.link.receive_status == ISOTP_RECEIVE_STATUS_IDLE &&
                     T.link.receive_protocol_result == ISOTP_PROTOCOL_RESULT_TIMEOUT_CR;
    G.ncr += ncr;
    G.fc_ended[FCE_NCR] += ncr && parked_before && !T.fc_parked && udsota_isotp_fc_lost(&T) != fc_lost_before &&
                           g_call.fc == 0u;
    G.s3_end += session_before != UDSOTA_SESSION_DEFAULT && S.session == UDSOTA_SESSION_DEFAULT;
    note_send_end(send_before);
    check_mirror();
}

/* The tester's turn: an FC it owes for the server's FF (or a block's end), once its delay has passed. */
static void tester_turn(void)
{
    if (!F.owed || g_us < F.due_us) {
        return;
    }
    uint8_t fc[CAN_DL] = {0x30, F.bs, F.stmin, PAD, PAD, PAD, PAD, PAD};
    uint8_t dlc = CAN_DL;
    F.owed = false;
    switch ((afc_mode_t)F.mode) {
    case AFC_WAIT_CTS:
    case AFC_WAIT2:
        if (F.stage == 0u) {
            fc[0] = 0x30u | FS_WAIT;
            F.owed = true;                     /* then a CTS, or a second WAIT */
            F.stage = 1u;
            F.due_us = g_us + (uint64_t)F.delay * 1000u + 1000u;
        } else if (F.mode == AFC_WAIT2) {
            fc[0] = 0x30u | FS_WAIT;
        }
        break;
    case AFC_WAIT:
        fc[0] = 0x30u | FS_WAIT;
        break;
    case AFC_OVFLW:
        fc[0] = 0x30u | FS_OVFLW;
        break;
    case AFC_BADFS:
        fc[0] = 0x37u;
        break;
    case AFC_SHORT:
        dlc = 2u;
        break;
    default:
        break;
    }
    feed_phys(fc, dlc, (uint32_t)g_us);
}

/* The diag task until end: the tester's owed FCs when due, and a service at each wake the adapter asked for. */
static void run_until(uint64_t end)
{
    while (g_us < end) {
        uint64_t next = g_us + (uint64_t)g_wait_ms * 1000u;
        if (F.owed && F.due_us > g_us && F.due_us < next) {
            next = F.due_us;
        }
        g_us = next < end ? next : end;
        tester_turn();
        service();
    }
}

/* ---- The program's events ---- */

/* Reads the program's next byte, 0 past its end. */
static uint8_t take(const uint8_t *in, size_t len, size_t *pos)
{
    return (*pos < len) ? in[(*pos)++] : 0u;
}

/* One tester frame, then the service that follows it unless the event says the next frame shares the wake. */
static void phys(const uint8_t f[CAN_DL], uint8_t dlc, bool svc)
{
    feed_phys(f, dlc, (uint32_t)g_us);
    if (svc) {
        service();
    }
}

/* Runs the diag task until the adapter sends a new FC or ms pass; true for a new FC. */
static bool wait_fc(unsigned seen, uint32_t ms)
{
    const uint64_t end = g_us + (uint64_t)ms * 1000u;
    while (Q.n == seen && g_us < end) {
        run_until(g_us + 1000u);
    }
    return Q.n != seen;
}

/* A multi-frame request of len bytes from msg: the FF, then CFs gap_us apart, per MF_* flags at CF `at`. An
 * honouring tester waits for a CTS before each block (WAIT keeps it waiting) and gives up on anything else. */
static void send_mf(const uint8_t *msg, uint32_t len, uint32_t gap_us, uint8_t flags, uint32_t at, bool svc)
{
    uint8_t f[CAN_DL];
    uint32_t off;
    if ((flags & MF_ESCAPE) != 0u) {
        const uint8_t esc[CAN_DL] = {0x10, 0x00, (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8),
                                     (uint8_t)len, msg[0], msg[1]};
        memcpy(f, esc, CAN_DL);
        off = 2u;
    } else {
        f[0] = (uint8_t)(0x10u | ((len >> 8) & 0x0Fu));
        f[1] = (uint8_t)len;
        memcpy(&f[2], msg, 6u);
        off = 6u;
    }
    const bool honour = (flags & MF_HONOUR) != 0u;
    unsigned seen = Q.n;
    phys(f, CAN_DL, svc);
    uint32_t block = 0u, stmin = 0u;          /* CFs the last CTS allows (UINT32_MAX: no limit) */
    uint8_t sn = 1u;
    for (uint32_t cf = 1u; off < len || ((flags & MF_EXTRA) != 0u && off == len); cf++) {
        while (honour && block == 0u) {
            if (!wait_fc(seen, HONOUR_WAIT_MS)) {
                return;                        /* no FC: the tester's N_Bs */
            }
            seen = Q.n;
            const uint8_t fs = Q.f[0] & 0x0Fu;
            if (fs == FS_CTS) {
                block = Q.f[1] != 0u ? Q.f[1] : UINT32_MAX;
                stmin = stmin_to_us(Q.f[2]);
            } else if (fs != FS_WAIT) {
                return;                        /* overflow: the tester stops */
            }
        }
        const uint32_t take_n = off < len ? ((len - off < 7u) ? len - off : 7u) : 7u;   /* 7 for MF_EXTRA's CF */
        if (cf == at && (flags & MF_FUNC) != 0u) {
            const uint8_t tp[CAN_DL] = {0x02, UDSOTA_SID_TESTER_PRESENT, 0x00, PAD, PAD, PAD, PAD, PAD};
            feed_func(tp, CAN_DL);
        }
        if (cf == at && (flags & MF_STALL) != 0u) {
            run_until(g_us + STALL_MS * 1000u);
        }
        g_us += gap_us > stmin ? gap_us : stmin;
        if (!(cf == at && (flags & MF_SKIP) != 0u)) {
            memset(f, PAD, sizeof f);
            f[0] = (uint8_t)(0x20u | ((cf == at && (flags & MF_BAD_SN) != 0u) ? (sn + 5u) & 0x0Fu : sn));
            if (off < len) {
                memcpy(&f[1], &msg[off], take_n);
            }
            tester_turn();
            phys(f, (flags & MF_TIGHT) != 0u ? (uint8_t)(take_n + 1u) : CAN_DL, svc);
        }
        if (off == len) {
            break;                             /* MF_EXTRA's one CF */
        }
        off += take_n;
        sn = (uint8_t)((sn + 1u) & 0x0Fu);
        block -= (block != UINT32_MAX && block != 0u) ? 1u : 0u;
    }
}

/* Replays one program event by event; each event advances the clock EVENT_US and ends with a service unless
 * EV_NOSVC. Missing bytes read as 0. */
static void run_program(const uint8_t *in, size_t len)
{
    static uint8_t msg[UDSOTA_DL_MAX_BLOCK_LEN];
    size_t pos = 0;
    for (g_ev = 0; pos < len; g_ev++) {
        tester_turn();
        const uint8_t op = in[pos++];
        const bool svc = (op & EV_NOSVC) == 0u;
        uint8_t f[CAN_DL];
        g_us += EVENT_US;
        G.events++;
        switch ((ev_kind_t)((op & 0x3Fu) % EV_COUNT)) {
        case EV_SF: {
            const uint8_t n = (uint8_t)(take(in, len, &pos) % 7u + 1u);
            memset(f, PAD, sizeof f);
            f[0] = n;
            for (uint8_t i = 0; i < n; i++) {
                f[1u + i] = take(in, len, &pos);
            }
            phys(f, (op & EV_FLAG) != 0u ? (uint8_t)(n + 1u) : CAN_DL, svc);
            break;
        }
        case EV_MF: {
            const uint32_t hi = take(in, len, &pos);   /* one call per statement: C leaves operand order open */
            uint32_t n = ((hi << 8) | take(in, len, &pos)) & 0x0FFFu;
            n = n < CAN_DL ? n + CAN_DL : n;
            const uint32_t gap = (uint32_t)take(in, len, &pos) * 50u;
            const uint8_t flags = take(in, len, &pos);
            const uint32_t at = take(in, len, &pos);
            for (uint32_t i = 0; i < n; i++) {
                msg[i] = take(in, len, &pos);
            }
            send_mf(msg, n, gap, flags, at, svc);
            break;
        }
        case EV_RAW: {
            const uint8_t dlc = take(in, len, &pos) & 0x0Fu;
            for (unsigned i = 0; i < CAN_DL; i++) {
                f[i] = take(in, len, &pos);
            }
            const int8_t jit = (int8_t)take(in, len, &pos);
            feed_phys(f, dlc, (uint32_t)g_us + (uint32_t)((int32_t)jit * 37));
            if (svc) {
                service();
            }
            break;
        }
        case EV_FUNC: {
            const uint8_t dlc = take(in, len, &pos) & 0x0Fu;
            for (unsigned i = 0; i < CAN_DL; i++) {
                f[i] = take(in, len, &pos);
            }
            feed_func(f, dlc);
            if (svc) {
                service();
            }
            break;
        }
        case EV_FC: {
            memset(f, PAD, sizeof f);
            f[0] = (uint8_t)(0x30u | (take(in, len, &pos) & 0x0Fu));
            f[1] = take(in, len, &pos);
            f[2] = take(in, len, &pos);
            const uint8_t d = take(in, len, &pos);
            phys(f, (op & EV_FLAG) != 0u ? (uint8_t)(d % 9u) : (uint8_t)(3u + d % 6u), svc);
            break;
        }
        case EV_WAIT: {
            const uint32_t lo = take(in, len, &pos);
            const uint32_t ms = (lo | ((uint32_t)take(in, len, &pos) << 8)) & 0x3FFFu;
            run_until(g_us + (uint64_t)ms * 1000u);
            break;
        }
        case EV_JUMP: {
            const uint8_t a = take(in, len, &pos);
            const uint8_t b = take(in, len, &pos);
            g_us += (uint64_t)a * 25000u + (uint64_t)b * 97u;
            if (svc) {
                service();
            }
            break;
        }
        case EV_BUS: {
            const uint8_t mode = take(in, len, &pos);
            const uint32_t n = take(in, len, &pos);
            const uint32_t count = n == 0xFFu ? 100000u : n;
            switch (mode % 4u) {
            case 0: g_bus.refuse = count; break;
            case 1: g_bus.fail = count; break;
            case 2: g_bus.pending = n; break;
            default: g_bus.refuse = g_bus.fail = g_bus.pending = 0u; break;
            }
            break;
        }
        case EV_AUTOFC:
            F.mode = (uint8_t)(take(in, len, &pos) % AFC_COUNT);
            F.bs = take(in, len, &pos);
            F.stmin = take(in, len, &pos);
            F.delay = take(in, len, &pos);
            break;
        default:
            break;
        }
    }
}

/* ---- Runs ---- */

/* Puts the fake engine back where each run starts: slot 0 running and VALID, slot 1 empty and erased. */
static void ota_reset(void)
{
    OTA.boot_slot = 0u;
    OTA.running_slot = 0u;
    OTA.state[0] = UDSOTA_IMG_VALID;
    OTA.state[1] = UDSOTA_IMG_UNDEFINED;
    if (fake_ota_begin(&OTA, FAKE_OTA_SECTOR) != 0) {
        die("fake_ota_begin failed in %s", FUZZ_FRAMES_OTA_DIR);
    }
    (void)fake_ota_abort(&OTA);
    OTA.written = 0u;
}

/* True while the adapter still holds something: an answer or its CFs, a parked FC, or a request mid-message or
 * waiting to be served. */
static bool held(void)
{
    return tx_busy() || T.fc_parked || T.link.receive_status != ISOTP_RECEIVE_STATUS_IDLE;
}

/* One replay of a program in one variant: a fresh server and adapter, the program, then DRAIN_MS on a clean bus, after
 * which nothing may be left sending, parked or unserved once a slow answer has had SETTLE_MS to finish. */
static void run_one(const char *src, unsigned long idx, const uint8_t *in, size_t len, unsigned variant, bool want_ok)
{
    if (g_only >= 0 && (long)idx != g_only) {
        return;
    }
    snprintf(g_label, sizeof g_label, "%s #%lu (%zu B), variant %u", src, idx, len, variant);
    memset(&R, 0, sizeof R);
    R.v = &VARIANTS[variant];
    R.variant = variant;
    memset(&g_bus, 0, sizeof g_bus);
    memset(&g_pfc, 0, sizeof g_pfc);
    memset(&g_pa, 0, sizeof g_pa);
    memset(&A, 0, sizeof A);
    memset(&F, 0, sizeof F);
    memset(&Q, 0, sizeof Q);
    F.mode = AFC_CTS;                          /* a tester that answers the server's FFs at once, BS 0, STmin 0 */
    g_us = R.v->t0_us;
    g_wait_ms = 1u;
    ota_reset();
    CFG = (udsota_config_t){ .req_id = REQ_ID, .resp_id = RESP_ID, .func_id = FUNC_ID, .stmin_us = R.v->stmin_us,
                             .block_size = R.v->bs, .fc_retry_ms = R.v->fc_retry_ms, .stmin_monitor = true };
    static const uint8_t SERIAL[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    CFG.device_id = SERIAL;
    CFG.device_id_len = sizeof SERIAL;
    HOOKS.stmin_us = R.v->stmin_hook ? hook_stmin : NULL;
    if (!udsota_init(&S, &CFG, &ENG, R.v->secured ? &SEC : NULL, &HOOKS)) {
        die("udsota_init refused the harness's config");
    }
    udsota_isotp_init(&T, &S, &CFG, &HOOKS, &CAN, B);
    run_program(in, len);
    g_bus.refuse = g_bus.fail = 0u;
    run_until(g_us + DRAIN_MS * 1000u);
    for (unsigned k = 0; k < SETTLE_MS / 100u && held(); k++) {
        run_until(g_us + 100000u);             /* an answer at the tester's 127 ms STmin, and one request behind it */
    }
    if (held()) {
        fail("after the drain on a clean bus an answer, an FC or a request is still held", NULL, 0);
    }
    if (want_ok && !R.verify_ok) {
        fail("the download seed's FF01 never answered 71 01 FF 01 00: the frame path lost the image", NULL, 0);
    }
    G.resp_lost += udsota_isotp_resp_lost(&T);
    G.fc_lost += udsota_isotp_fc_lost(&T);
    G.drained++;
    G.runs++;
}

/* ---- Seed programs ---- */

static uint8_t  g_p[PROG_MAX];                 /* the program being built */
static size_t   g_pn;

/* Appends one byte to the program being built. */
static void p8(uint8_t b)
{
    if (g_pn >= sizeof g_p) {
        die("a seed program outgrew PROG_MAX");
    }
    g_p[g_pn++] = b;
}

/* A Single Frame request of 1-7 bytes. */
static void p_sf(const uint8_t *b, uint8_t n, uint8_t opf)
{
    p8((uint8_t)(EV_SF | opf));
    p8((uint8_t)(n - 1u));
    for (uint8_t i = 0; i < n; i++) {
        p8(b[i]);
    }
}
#define SF(...) do { const uint8_t sf_[] = {__VA_ARGS__}; p_sf(sf_, sizeof sf_, 0u); } while (0)

/* A multi-frame request: len bytes of b (8..4095), CFs gap x 50 us apart, MF_* flags at CF `at`. */
static void p_mf(const uint8_t *b, uint32_t len, uint8_t gap, uint8_t flags, uint8_t at, uint8_t opf)
{
    p8((uint8_t)(EV_MF | opf));
    p8((uint8_t)(len >> 8));
    p8((uint8_t)len);
    p8(gap);
    p8(flags);
    p8(at);
    for (uint32_t i = 0; i < len; i++) {
        p8(b[i]);
    }
}

/* One raw physical frame. */
static void p_raw(uint8_t dlc, const uint8_t f[CAN_DL], int8_t jit, uint8_t opf)
{
    p8((uint8_t)(EV_RAW | opf));
    p8(dlc);
    for (unsigned i = 0; i < CAN_DL; i++) {
        p8(f[i]);
    }
    p8((uint8_t)jit);
}
#define RAW(dlc, ...) do { const uint8_t r_[CAN_DL] = {__VA_ARGS__}; p_raw((dlc), r_, 0, 0u); } while (0)

/* One raw functional frame. */
static void p_func(uint8_t dlc, const uint8_t f[CAN_DL])
{
    p8(EV_FUNC);
    p8(dlc);
    for (unsigned i = 0; i < CAN_DL; i++) {
        p8(f[i]);
    }
}
#define FUNC(dlc, ...) do { const uint8_t r_[CAN_DL] = {__VA_ARGS__}; p_func((dlc), r_); } while (0)

/* A tester FC. */
static void p_fc(uint8_t fs, uint8_t bs, uint8_t stmin, uint8_t d)
{
    p8(EV_FC);
    p8(fs);
    p8(bs);
    p8(stmin);
    p8(d);
}

/* The diag task runs ms. */
static void p_wait(uint16_t ms)
{
    p8(EV_WAIT);
    p8((uint8_t)ms);
    p8((uint8_t)(ms >> 8));
}

/* The clock jumps a x 25 ms + b x 97 us. */
static void p_jump(uint8_t a, uint8_t b)
{
    p8(EV_JUMP);
    p8(a);
    p8(b);
}

/* The bus's next answers: mode 0 refuse n, 1 fail n, 2 tx_pending n, 3 clean. */
static void p_bus(uint8_t mode, uint8_t n)
{
    p8(EV_BUS);
    p8(mode);
    p8(n);
}

/* The tester's FC policy for the server's FFs. */
static void p_autofc(afc_mode_t mode, uint8_t bs, uint8_t stmin, uint8_t delay)
{
    p8(EV_AUTOFC);
    p8((uint8_t)mode);
    p8(bs);
    p8(stmin);
    p8(delay);
}

/* 27 03, then 27 04 with the key for the run's first seed (a multi-frame request), and 10 02 before them. */
static void p_unlock_prog(void)
{
    SF(UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING);
    p_wait(5u);
    SF(UDSOTA_SID_SECURITY, UDSOTA_SA_SEED_PROGRAMMING);
    p_wait(5u);
    uint8_t seed[16], key[2u + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, UDSOTA_SA_KEY_PROGRAMMING};
    mock_seed(0u, seed);
    fake_key(seed, UDSOTA_SA_SEED_PROGRAMMING, &key[2]);
    p_mf(key, sizeof key, 20u, MF_HONOUR, 0u, 0u);
    p_wait(5u);
}

/* 34 for size bytes, then the image in 36 blocks of up to 4,093 bytes, gap x 50 us apart with flags at CF at, then
 * 37 and, when finish, FF01 and ActivateImage. */
static void p_download(uint32_t size, uint8_t gap, uint8_t flags, uint8_t at, bool finish)
{
    const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0,
                           (uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size};
    p_mf(r34, sizeof r34, 20u, MF_HONOUR, 0u, 0u);
    p_wait(10u);
    static uint8_t blk[UDSOTA_DL_MAX_BLOCK_LEN];
    uint8_t bsc = 1u;
    for (size_t off = 0; off < g_img_len; off += UDSOTA_DL_MAX_DATA, bsc++) {
        const size_t n = (g_img_len - off < UDSOTA_DL_MAX_DATA) ? g_img_len - off : UDSOTA_DL_MAX_DATA;
        blk[0] = UDSOTA_SID_TRANSFER_DATA;
        blk[1] = bsc;
        memcpy(&blk[2], &g_img[off], n);
        p_mf(blk, (uint32_t)n + 2u, gap, flags, at, 0u);
        p_wait(150u);
    }
    if (!finish) {
        return;
    }
    SF(UDSOTA_SID_TRANSFER_EXIT);
    p_wait(10u);
    SF(UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xFF, 0x01);
    p_wait(200u);
    SF(UDSOTA_SID_ROUTINE, UDSOTA_RC_START, 0xF0, 0x01);
    p_wait(300u);
}

typedef struct { size_t off, len; bool want_ok; } seed_t;
#define SEED_MAX 64u
static uint8_t g_seeds[1u << 20];              /* every seed program, back to back */
static size_t  g_seeds_len;
static seed_t  g_seed[SEED_MAX];
static size_t  g_seed_n;

/* Starts a seed program. */
static void seed_begin(void)
{
    g_pn = 0;
}

/* Keeps the program built since seed_begin as a seed; want_ok: variant 0 must verify its download. */
static void seed_end(bool want_ok)
{
    if (g_seed_n >= SEED_MAX || g_seeds_len + g_pn > sizeof g_seeds) {
        die("too many seed programs");
    }
    memcpy(&g_seeds[g_seeds_len], g_p, g_pn);
    g_seed[g_seed_n++] = (seed_t){g_seeds_len, g_pn, want_ok};
    g_seeds_len += g_pn;
}

/* The seed programs: every request kind, frame kind and timeout the frame path has, each written the way a tester
 * would send it, or breaks it on purpose. */
static void build_seeds(void)
{
    static uint8_t m[UDSOTA_DL_MAX_BLOCK_LEN];
    /* Single frames, answered in SFs and FFs: sessions, DIDs short and long (0x14 past the buffer), 3E with and
     * without SPRMIB, and 19 0A's 163 bytes, whose SN wraps. */
    seed_begin();
    SF(0x10, 0x03); SF(0x22, 0xF1, 0x86); SF(0x3E, 0x00); SF(0x3E, 0x80); SF(0x22, 0xF1, 0x8C);
    SF(0x22, 0xF1, 0xF2); SF(0x22, 0x01, 0x00); SF(0x22, 0x01, 0x01); p_wait(20u); SF(0x22, 0x01, 0x02);
    p_wait(50u); SF(0x22, 0x01, 0x03); p_wait(60u); SF(0x22, 0x01, 0x04); SF(0x19, 0x0A); p_wait(40u);
    SF(0x19, 0x01, 0xFF); SF(0x19, 0x02, 0x08); p_wait(40u); SF(0x28, 0x00, 0x01); SF(0x85, 0x02);
    SF(0x11, 0x01); SF(0x10, 0x01); p_wait(10u);
    p_sf((const uint8_t[]){0x22, 0xF1, 0x86}, 3u, EV_FLAG);   /* tight DLC */
    seed_end(false);
    /* The tester's answers to the server's FFs, one per mode, each on a 200-byte DID, then a request after N_Bs. */
    for (unsigned mode = 0; mode < AFC_COUNT; mode++) {
        seed_begin();
        p_autofc((afc_mode_t)mode, mode == AFC_WAIT_CTS ? 4u : 0u, mode == AFC_CTS ? 0xF5u : 0x00u, 3u);
        SF(0x22, 0x01, 0x02);
        p_wait(30u);
        SF(0x3E, 0x00);
        p_wait(1200u);
        SF(0x22, 0x01, 0x01);
        p_wait(50u);
        seed_end(false);
    }
    /* A CTS with BS 2 and STmin 3 ms, a CTS with a reserved STmin, then FCs at odd times: before any FF, a second CTS
     * mid-block, a WAIT and an overflow mid-answer. */
    seed_begin();
    p_fc(0, 0, 0, 5);
    p_autofc(AFC_CTS, 2u, 0x03u, 0u);
    SF(0x22, 0x01, 0x02);
    p_wait(40u);
    p_autofc(AFC_CTS, 0u, 0x80u, 1u);
    SF(0x19, 0x0A);
    p_wait(40u);
    p_autofc(AFC_NONE, 0u, 0u, 0u);
    SF(0x22, 0x01, 0x03);
    p_fc(0, 3, 0, 5); p_wait(2u); p_fc(0, 1, 0, 0); p_wait(3u); p_fc(1, 0, 0, 5); p_wait(3u); p_fc(0, 0, 0, 5);
    p_wait(2u); p_fc(2, 0, 0, 5); p_wait(10u); p_fc(0, 0, 0, 1);
    p8(EV_FC | EV_FLAG); p8(0); p8(0); p8(0); p8(2);   /* an FC of 2 bytes: LENGTH */
    p_wait(1100u);
    seed_end(false);
    /* Functional frames: served (3E, 10 03, 22, 19), suppressed (3E 80, 10 83, 11 01, 10 02, an unknown DID's 0x31),
     * no SF (FF, CF, FC, SF_DL 0, a DLC too short, DLC 9 and 15), during a physical request and during an answer. */
    seed_begin();
    FUNC(8, 0x02, 0x3E, 0x00, PAD, PAD, PAD, PAD, PAD); FUNC(3, 0x02, 0x10, 0x03, 0, 0, 0, 0, 0);
    FUNC(8, 0x03, 0x22, 0xF1, 0x86, PAD, PAD, PAD, PAD); FUNC(8, 0x02, 0x3E, 0x80, PAD, PAD, PAD, PAD, PAD);
    FUNC(8, 0x02, 0x10, 0x83, PAD, PAD, PAD, PAD, PAD); FUNC(8, 0x02, 0x11, 0x01, PAD, PAD, PAD, PAD, PAD);
    FUNC(8, 0x02, 0x10, 0x02, PAD, PAD, PAD, PAD, PAD); FUNC(8, 0x03, 0x22, 0x77, 0x77, PAD, PAD, PAD, PAD);
    FUNC(8, 0x03, 0x19, 0x02, 0xFF, PAD, PAD, PAD, PAD); p_wait(30u);
    FUNC(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); FUNC(8, 0x21, 0, 0, 0, 0, 0, 0, 0);
    FUNC(8, 0x30, 0, 0, 0, 0, 0, 0, 0); FUNC(8, 0x00, 0x3E, 0, 0, 0, 0, 0, 0); FUNC(2, 0x02, 0x3E, 0, 0, 0, 0, 0, 0);
    FUNC(9, 0x02, 0x3E, 0x00, PAD, PAD, PAD, PAD, PAD); FUNC(15, 0x02, 0x3E, 0x00, PAD, PAD, PAD, PAD, PAD);
    FUNC(0, 0, 0, 0, 0, 0, 0, 0, 0); FUNC(1, 0x01, 0, 0, 0, 0, 0, 0, 0);
    for (unsigned i = 0; i < 20u; i++) {
        m[i] = (uint8_t)(0x22u + i);
    }
    m[0] = 0x22;
    p_mf(m, 20u, 20u, MF_FUNC, 2u, 0u);
    p_wait(20u);
    p_autofc(AFC_NONE, 0u, 0u, 0u);
    SF(0x22, 0x01, 0x02);
    FUNC(8, 0x02, 0x3E, 0x00, PAD, PAD, PAD, PAD, PAD);
    p_fc(0, 0, 0, 5);
    FUNC(8, 0x02, 0x3E, 0x00, PAD, PAD, PAD, PAD, PAD);
    p_wait(40u);
    seed_end(false);
    /* The whole download over the frame path, FC honoured: 10 02, the key, 34, two 36 blocks (4,095 bytes, the SN
     * wrapping 36 times), 37, FF01 and ActivateImage. Variant 0 must verify the image. */
    seed_begin();
    p_unlock_prog();
    p_download((uint32_t)g_img_len, 40u, MF_HONOUR, 0u, true);
    seed_end(true);
    /* The same blasted without waiting for FCs (the STmin monitor judges CF 64), then with a wrong SN at CF 100, a
     * missing CF 64, an extra CF, a stall past N_Cr at CF 30, tight DLCs, escape-length FFs and a burst without
     * services. */
    static const struct { uint8_t gap, flags, at, opf; } DL_BREAKS[] = {
        {40u, 0u, 0u, 0u}, {2u, 0u, 0u, 0u}, {40u, MF_BAD_SN, 100u, 0u}, {40u, MF_SKIP, 64u, 0u},
        {40u, MF_EXTRA | MF_HONOUR, 0u, 0u}, {40u, MF_STALL | MF_HONOUR, 30u, 0u}, {40u, MF_TIGHT | MF_HONOUR, 0u, 0u},
        {40u, MF_ESCAPE | MF_HONOUR, 0u, 0u}, {40u, MF_FUNC, 70u, 0u}, {0u, 0u, 0u, EV_NOSVC},
    };
    for (size_t i = 0; i < sizeof DL_BREAKS / sizeof DL_BREAKS[0]; i++) {
        seed_begin();
        p_unlock_prog();
        const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0,
                               (uint8_t)(g_img_len >> 8), (uint8_t)g_img_len};
        p_mf(r34, sizeof r34, 20u, MF_HONOUR, 0u, 0u);
        p_wait(10u);
        m[0] = UDSOTA_SID_TRANSFER_DATA;
        m[1] = 1u;
        memcpy(&m[2], g_img, UDSOTA_DL_MAX_DATA);
        p_mf(m, UDSOTA_DL_MAX_BLOCK_LEN, DL_BREAKS[i].gap, DL_BREAKS[i].flags, DL_BREAKS[i].at, DL_BREAKS[i].opf);
        p_wait(1500u);
        SF(0x22, 0xF1, 0xF2);
        p_wait(20u);
        seed_end(false);
    }
    /* The orphan: an answer still going out (the tester holds its FC) while the gate or the STmin monitor withholds
     * an FC point of a 36, so isotp-c keeps the message; then N_Bs and N_Cr end both. */
    seed_begin();
    p_unlock_prog();
    const uint8_t r34[] = {UDSOTA_SID_REQUEST_DOWNLOAD, UDSOTA_DL_DFI, UDSOTA_DL_ALFID, 0, 0, 0, 0, 0, 0,
                           (uint8_t)(g_img_len >> 8), (uint8_t)g_img_len};
    p_mf(r34, sizeof r34, 20u, MF_HONOUR, 0u, 0u);
    p_wait(10u);
    p_autofc(AFC_NONE, 0u, 0u, 0u);
    SF(0x22, 0xF1, 0x8C);
    m[0] = UDSOTA_SID_TRANSFER_DATA;
    m[1] = 1u;
    memcpy(&m[2], g_img, UDSOTA_DL_MAX_DATA);
    p_mf(m, UDSOTA_DL_MAX_BLOCK_LEN, 2u, 0u, 0u, 0u);
    p_wait(1300u);
    p_autofc(AFC_CTS, 0u, 0u, 0u);
    SF(0x22, 0xF1, 0xF2);
    p_wait(30u);
    seed_end(false);
    /* Request lengths at the edges: FF_DL 8, 255, 256, 257 (overflow outside a download), an escape FF of 20, an FF of
     * DLC 7 and one of FF_DL 7 (both ignored), then a CF with no FF and CFs after a wrong SN. */
    seed_begin();
    memset(m, 0x01, 300u);
    m[0] = 0x22;
    p_mf(m, 8u, 10u, 0u, 0u, 0u); p_wait(20u);
    p_mf(m, 255u, 10u, MF_HONOUR, 0u, 0u); p_wait(20u);
    p_mf(m, 256u, 10u, MF_HONOUR, 0u, 0u); p_wait(20u);
    p_mf(m, 257u, 10u, MF_HONOUR, 0u, 0u); p_wait(20u);
    p_mf(m, 20u, 10u, MF_ESCAPE, 0u, 0u); p_wait(20u);
    RAW(7, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); RAW(8, 0x10, 0x07, 0x22, 0xF1, 0x86, 0, 0, 0);
    RAW(8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xF1); RAW(8, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x22, 0xF1);
    RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); RAW(8, 0x23, 1, 2, 3, 4, 5, 6, 7); RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); RAW(3, 0x21, 1, 2, 0, 0, 0, 0, 0); RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    RAW(8, 0x22, 1, 2, 3, 4, 5, 6, 7);
    p_wait(20u);
    seed_end(false);
    /* Garbage: every reserved PCI, DLC 0, 1, 9 and 15, an SF_DL past its DLC, an SF of 0, an FC with no answer out. */
    seed_begin();
    for (uint8_t pci = 4u; pci <= 0x0Fu; pci++) {
        RAW(8, (uint8_t)(pci << 4), 0x3E, 0x00, 0, 0, 0, 0, 0);
    }
    RAW(0, 0x02, 0x3E, 0x00, 0, 0, 0, 0, 0); RAW(1, 0x02, 0x3E, 0x00, 0, 0, 0, 0, 0);
    RAW(9, 0x02, 0x3E, 0x00, 0, 0, 0, 0, 0); RAW(15, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0);
    RAW(3, 0x05, 0x3E, 0x00, 0, 0, 0, 0, 0); RAW(8, 0x00, 0x3E, 0x00, 0, 0, 0, 0, 0);
    RAW(8, 0x30, 0x00, 0x00, 0, 0, 0, 0, 0); RAW(2, 0x02, 0x3E, 0, 0, 0, 0, 0, 0);
    p_wait(10u);
    seed_end(false);
    /* Time: S3 ends the extended session, N_Cr ends a message the tester left, a jump past the us clock's wrap, and
     * P2 while the async engine erases. */
    seed_begin();
    SF(0x10, 0x03);
    p_jump(240u, 0u);
    SF(0x22, 0xF1, 0x86);
    RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0);
    p_jump(44u, 7u);
    RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0);
    p_wait(1100u);
    RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    p_jump(255u, 255u);
    SF(0x3E, 0x00);
    seed_end(false);
    /* The bus: answers refused then taken, refused past the park limit, failed outright; an FC refused and retried,
     * refused past its window and failed; CFs refused and failed mid-answer; tx_pending under 11 01. */
    seed_begin();
    p_bus(0u, 3u); SF(0x3E, 0x00); p_wait(10u);
    p_bus(0u, 0xFFu); SF(0x3E, 0x00); p_wait(1100u); p_bus(3u, 0u);
    p_bus(1u, 1u); SF(0x3E, 0x00); p_wait(10u);
    p_bus(0u, 2u); RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); p_wait(5u); RAW(8, 0x21, 1, 2, 3, 4, 5, 6, 7);
    RAW(8, 0x22, 1, 2, 3, 4, 5, 6, 7); p_wait(10u);
    p_bus(0u, 40u); RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); p_wait(60u); p_bus(3u, 0u);
    p_bus(1u, 1u); RAW(8, 0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0); p_wait(1100u);
    SF(0x22, 0x01, 0x02); p_wait(3u); p_bus(0u, 5u); p_wait(30u);
    SF(0x22, 0x01, 0x02); p_wait(3u); p_bus(1u, 1u); p_wait(1200u);
    SF(0x10, 0x03); p_wait(5u); SF(0x27, 0x01); p_wait(5u);
    p_bus(2u, 3u); SF(0x11, 0x01); p_wait(150u);
    seed_end(false);
    /* A CTS the bus refused, then its message ends in the same wake, before the retry: a new SF, an FF over the limit,
     * a wrong SN, its last CF; and, where the retry window outlasts it (variant 4's 2 s), N_Cr. */
    seed_begin();
    static const uint8_t FF20[CAN_DL] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0, 0, 0};
    p_bus(0u, 1u); p_raw(8u, FF20, 0, EV_NOSVC); p_sf((const uint8_t[]){0x22, 0xF1, 0x86}, 3u, EV_NOSVC); p_wait(20u);
    p_bus(0u, 1u); p_raw(8u, FF20, 0, EV_NOSVC);
    p_raw(8u, (const uint8_t[CAN_DL]){0x11, 0x2C, 0x22, 0xF1, 0x86, 0, 0, 0}, 0, EV_NOSVC); p_wait(20u);
    p_bus(0u, 1u); p_raw(8u, FF20, 0, EV_NOSVC);
    p_raw(8u, (const uint8_t[CAN_DL]){0x25, 1, 2, 3, 4, 5, 6, 7}, 0, EV_NOSVC); p_wait(20u);
    p_bus(0u, 1u); p_raw(8u, (const uint8_t[CAN_DL]){0x10, 0x08, 0x22, 0xF1, 0x86, 0xF1, 0x8C, 0xF1}, 0, EV_NOSVC);
    p_raw(8u, (const uint8_t[CAN_DL]){0x21, 0x90, 0x00, PAD, PAD, PAD, PAD, PAD}, 0, EV_NOSVC); p_wait(20u);
    p_bus(0u, 0xFFu); p_raw(8u, FF20, 0, 0u); p_wait(1100u); p_bus(3u, 0u);
    p_wait(20u);
    seed_end(false);
}

/* ---- Mutation ---- */

static uint32_t g_rng = 0x5EEDF00Du;           /* mutation PRNG state */

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

/* Bytes the event at in[pos] takes, op byte included (what run_program reads for it). */
static size_t ev_size(const uint8_t *in, size_t len, size_t pos)
{
    const uint8_t op = in[pos];
    const uint8_t b1 = pos + 1u < len ? in[pos + 1u] : 0u;
    const uint8_t b2 = pos + 2u < len ? in[pos + 2u] : 0u;
    switch ((ev_kind_t)((op & 0x3Fu) % EV_COUNT)) {
    case EV_SF: return 2u + b1 % 7u + 1u;
    case EV_MF: {
        uint32_t n = (((uint32_t)b1 << 8) | b2) & 0x0FFFu;
        return 6u + (n < CAN_DL ? n + CAN_DL : n);
    }
    case EV_RAW: return 11u;
    case EV_FUNC: return 10u;
    case EV_FC: case EV_AUTOFC: return 5u;
    case EV_WAIT: case EV_JUMP: case EV_BUS: return 3u;
    default: return 1u;
    }
}

/* Writes one random, well-formed event (short requests and frames of every kind) at out; returns its length. */
static size_t random_event(uint8_t *out)
{
    static const uint8_t SIDS[] = {0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x28, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x3E, 0x85};
    size_t n = 0;
    const unsigned kind = rnd() % EV_COUNT;
    const uint8_t flag = (rnd() % 4u == 0u) ? EV_FLAG : 0u;   /* one rnd() per statement: C leaves operand order
                                                                  open, and the digest must not depend on it */
    out[n++] = (uint8_t)(kind | flag | ((rnd() % 6u == 0u) ? EV_NOSVC : 0u));
    switch ((ev_kind_t)kind) {
    case EV_SF: {
        const uint8_t k = (uint8_t)(rnd() % 7u);
        out[n++] = k;
        out[n++] = SIDS[rnd() % sizeof SIDS];
        for (uint8_t i = 0; i < k; i++) {
            out[n++] = (uint8_t)(rnd() % 3u == 0u ? rnd() : i);
        }
        break;
    }
    case EV_MF: {
        const uint32_t span = rnd() % 8u == 0u ? 4088u : 300u;
        const uint32_t len = 8u + rnd() % span;
        out[n++] = (uint8_t)(len >> 8);
        out[n++] = (uint8_t)len;
        out[n++] = (uint8_t)(rnd() % 64u);
        out[n++] = (uint8_t)rnd();
        out[n++] = (uint8_t)(rnd() % 80u);
        out[n++] = SIDS[rnd() % sizeof SIDS];
        for (uint32_t i = 1; i < len; i++) {
            out[n++] = (uint8_t)(i < 4u ? rnd() : i);
        }
        break;
    }
    case EV_RAW:
    case EV_FUNC:
        out[n++] = (uint8_t)(rnd() % 5u == 0u ? rnd() % 16u : 8u);
        const uint8_t pci = (uint8_t)(rnd() % 4u);
        out[n++] = (uint8_t)(pci << 4 | (rnd() % 16u));
        for (unsigned i = 1; i < CAN_DL; i++) {
            out[n++] = (uint8_t)(i == 1u ? SIDS[rnd() % sizeof SIDS] : rnd());
        }
        if (kind == EV_RAW) {
            out[n++] = (uint8_t)rnd();
        }
        break;
    case EV_FC:
        out[n++] = (uint8_t)(rnd() % 3u == 0u ? rnd() : rnd() % 3u);
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0u : rnd());
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0u : rnd());
        out[n++] = (uint8_t)rnd();
        break;
    case EV_WAIT: {
        const uint32_t ms = rnd() % 4u == 0u ? rnd() % 7000u : rnd() % 60u;
        out[n++] = (uint8_t)ms;
        out[n++] = (uint8_t)(ms >> 8);
        break;
    }
    case EV_AUTOFC:
        out[n++] = (uint8_t)rnd();
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0u : rnd());
        out[n++] = (uint8_t)(rnd() % 2u == 0u ? 0u : rnd());
        out[n++] = (uint8_t)(rnd() % 30u);
        break;
    default:
        out[n++] = (uint8_t)rnd();
        out[n++] = (uint8_t)(kind == EV_BUS ? rnd() % 8u : rnd());
        break;
    }
    return n;
}

/* The event boundary at or before pos. */
static size_t boundary(const uint8_t *in, size_t len, size_t pos)
{
    size_t b = 0;
    for (size_t p = 0; p < len && p <= pos; p += ev_size(in, len, p)) {
        b = p;
    }
    return b;
}

/* Writes a mutant of seed into out (capacity PROG_MAX) with 1-4 edits: bytes flipped or set, events inserted,
 * deleted, duplicated or taken from another seed, the tail cut; returns its length. */
static size_t mutate(const uint8_t *seed, size_t len, uint8_t *out)
{
    static const uint8_t INTERESTING[] = {0x00, 0x01, 0x07, 0x08, 0x0F, 0x10, 0x20, 0x30, 0x7F, 0x80, 0xFF};
    static uint8_t ev[UDSOTA_DL_MAX_BLOCK_LEN + 16u];
    size_t n = len < PROG_MAX ? len : PROG_MAX;
    memcpy(out, seed, n);
    const unsigned edits = 1u + rnd() % 4u;
    for (unsigned e = 0; e < edits; e++) {
        const size_t at = n != 0u ? boundary(out, n, rnd() % n) : 0u;
        switch (rnd() % 8u) {
        case 0: if (n != 0u) { const size_t i = rnd() % n; out[i] ^= (uint8_t)(1u << (rnd() % 8u)); } break;
        case 1: if (n != 0u) { const size_t i = rnd() % n; out[i] = INTERESTING[rnd() % sizeof INTERESTING]; } break;
        case 2: case 3: {                                                 /* a random event at a boundary */
            const size_t k = random_event(ev);
            if (n + k <= PROG_MAX) {
                memmove(&out[at + k], &out[at], n - at);
                memcpy(&out[at], ev, k);
                n += k;
            }
            break;
        }
        case 4: if (n != 0u) {                                            /* delete one event */
                const size_t k = ev_size(out, n, at) < n - at ? ev_size(out, n, at) : n - at;
                memmove(&out[at], &out[at + k], n - at - k);
                n -= k;
            }
            break;
        case 5: if (n != 0u) {                                            /* duplicate one event */
                const size_t k = ev_size(out, n, at) < n - at ? ev_size(out, n, at) : n - at;
                if (n + k <= PROG_MAX) {
                    memmove(&out[at + k], &out[at], n - at);
                    n += k;
                }
            }
            break;
        case 6: {                                                         /* another seed's tail from a boundary */
            const seed_t *o = &g_seed[rnd() % g_seed_n];
            const uint8_t *src = &g_seeds[o->off];
            const size_t from = o->len != 0u ? boundary(src, o->len, rnd() % o->len) : 0u;
            const size_t k = (o->len - from < PROG_MAX - at) ? o->len - from : PROG_MAX - at;
            memcpy(&out[at], &src[from], k);
            n = at + k;
            break;
        }
        default: n = at; break;                                           /* cut at a boundary */
        }
    }
    return n;
}

/* ---- Coverage ---- */

/* Prints what the replay reached. */
static void print_coverage(void)
{
    printf("fuzz_udsota_frames: fed by PCI:");
    for (unsigned p = 0; p < 16u; p++) {
        printf(" %X=%lu", p, G.fed_pci[p]);
    }
    printf("\nfuzz_udsota_frames: fed by DLC:");
    for (unsigned d = 0; d < 16u; d++) {
        printf(" %u=%lu", d, G.fed_dlc[d]);
    }
    printf("\nfuzz_udsota_frames: mirror:");
    for (unsigned k = 0; k <= UDSOTA_RXW_BROKEN; k++) {
        printf(" %s=%lu", KIND_NAME[k], G.kind[k]);
    }
    printf("\nfuzz_udsota_frames: sent SF=%lu FF=%lu CF=%lu FC=%lu (CTS %lu, overflow %lu), refused %lu, failed %lu; "
           "FC withheld %lu, parked %lu, retried %lu, lost %lu; answers retried %lu, lost %lu; orphans %lu\n",
           G.sent_pci[PCI_SF], G.sent_pci[PCI_FF], G.sent_pci[PCI_CF], G.sent_pci[PCI_FC], G.fc_cts, G.fc_ovflw,
           G.refused, G.failed, G.withheld, G.fc_parked, G.fc_retried, G.fc_lost, G.park_retried, G.resp_lost,
           G.orphan);
    printf("fuzz_udsota_frames: parked FCs dropped as their message ended: by an SF %lu, a wrong SN %lu, the last CF "
           "%lu, N_Cr %lu\n", G.fc_ended[FCE_SF], G.fc_ended[FCE_BAD_SN], G.fc_ended[FCE_LAST], G.fc_ended[FCE_NCR]);
    unsigned long reserved = 0;
    for (unsigned fs = FS_OVFLW + 1u; fs < 16u; fs++) {
        reserved += G.tester_fc[fs];
    }
    printf("fuzz_udsota_frames: tester FCs mid-answer: CTS=%lu WAIT=%lu OVFLW=%lu reserved=%lu; sends ended by N_Bs "
           "%lu, overflow %lu, WAIT overrun %lu, other %lu; answers stopped early %lu\n", G.tester_fc[FS_CTS],
           G.tester_fc[FS_WAIT], G.tester_fc[FS_OVFLW], reserved, G.nbs,
           G.ovflw_abort, G.wft_abort, G.send_err, G.abandoned);
    printf("fuzz_udsota_frames: timeouts N_Cr=%lu S3=%lu 0x78=%lu; SN wraps rx=%lu tx=%lu; escape FFs %lu; "
           "functional: answered %lu, silent %lu, no SF %lu, link busy %lu; answers %lu positive (%lu multi-frame), "
           "%lu NRC; images verified %lu\n", G.ncr, G.s3_end, G.pending78, G.rx_sn_wrap, G.tx_sn_wrap, G.ff_escape,
           G.func_answered, G.func_silent, G.func_invalid, G.func_busy, G.answers_pos, G.answers_mf, G.answers_nrc,
           G.verify_ok);
}

/* The replay's own positive control: every mirror class, frame kind, FC outcome, timeout and functional branch was
 * reached, and an image went through the frame path and verified, or a clean replay proves nothing. */
static void check_coverage(void)
{
    const struct { const char *what; unsigned long n; } floor[] = {
        {"a physical SF", G.fed_pci[PCI_SF]}, {"a physical FF", G.fed_pci[PCI_FF]}, {"a CF", G.fed_pci[PCI_CF]},
        {"a tester FC", G.fed_pci[PCI_FC]}, {"a reserved PCI", G.fed_pci[0xF]}, {"DLC 0", G.fed_dlc[0]},
        {"DLC over 8", G.fed_dlc[9] + G.fed_dlc[15]},
        {"mirror ignore", G.kind[UDSOTA_RXW_IGNORE]}, {"mirror single", G.kind[UDSOTA_RXW_SINGLE]},
        {"mirror first", G.kind[UDSOTA_RXW_FIRST]}, {"mirror refused", G.kind[UDSOTA_RXW_REFUSED]},
        {"mirror consec", G.kind[UDSOTA_RXW_CONSEC]}, {"mirror consec_fc", G.kind[UDSOTA_RXW_CONSEC_FC]},
        {"mirror last", G.kind[UDSOTA_RXW_LAST]}, {"mirror broken", G.kind[UDSOTA_RXW_BROKEN]},
        {"an SF sent", G.sent_pci[PCI_SF]}, {"an FF sent", G.sent_pci[PCI_FF]}, {"a CF sent", G.sent_pci[PCI_CF]},
        {"a CTS sent", G.fc_cts}, {"an overflow FC sent", G.fc_ovflw}, {"a withheld FC point", G.withheld},
        {"an FC parked", G.fc_parked}, {"an FC retried", G.fc_retried}, {"an answer retried", G.park_retried},
        {"a parked FC dropped by an SF", G.fc_ended[FCE_SF]},
        {"a parked FC dropped by a wrong SN", G.fc_ended[FCE_BAD_SN]},
        {"a parked FC dropped by its last CF", G.fc_ended[FCE_LAST]},
        {"a parked FC dropped at N_Cr", G.fc_ended[FCE_NCR]},
        {"an answer lost", G.resp_lost}, {"an orphan", G.orphan},
        {"a tester WAIT mid-answer", G.tester_fc[FS_WAIT]}, {"a tester overflow mid-answer", G.tester_fc[FS_OVFLW]},
        {"N_Bs", G.nbs}, {"an overflow-ended send", G.ovflw_abort}, {"a WAIT overrun", G.wft_abort},
        {"N_Cr", G.ncr}, {"S3", G.s3_end}, {"0x78", G.pending78}, {"an rx SN wrap", G.rx_sn_wrap},
        {"a tx SN wrap", G.tx_sn_wrap}, {"an escape FF", G.ff_escape}, {"a functional answer", G.func_answered},
        {"a functional request silenced", G.func_silent}, {"a functional non-SF", G.func_invalid},
        {"a functional frame on a busy link", G.func_busy}, {"an answer stopped early", G.abandoned},
        {"a multi-frame answer", G.answers_mf}, {"an NRC", G.answers_nrc}, {"a verified image", G.verify_ok},
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof floor / sizeof floor[0]; i++) {
        if (floor[i].n == 0u) {
            fprintf(stderr, "fuzz_udsota_frames: COVERAGE: never reached %s\n", floor[i].what);
            ok = false;
        }
    }
    if (!ok) {
        fprintf(stderr, "fuzz_udsota_frames: COVERAGE floor not met: a clean replay would prove nothing\n");
        exit(1);
    }
}

/* ---- Self-tests and crash reports ---- */

#if defined(__SANITIZE_ADDRESS__)
#define FUZZ_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FUZZ_ASAN 1
#endif
#endif
#ifdef FUZZ_ASAN
/* Under ASan a guard-page fault stays a plain SIGSEGV, as the self-test and on_fatal expect (as in fuzz_udsota). */
const char *__asan_default_options(void);
const char *__asan_default_options(void)
{
    return "handle_segv=0:handle_sigbus=0";
}
#endif

/* Writes s to stderr from a signal handler (async-signal-safe). */
static void say(const char *s)
{
    ssize_t r = write(STDERR_FILENO, s, strlen(s));
    (void)r;
}

/* Fatal-signal handler: names the program being replayed, then returns so the default action kills the process. */
static void on_fatal(int sig)
{
    char num[16];
    size_t i = sizeof num - 1;
    unsigned v = g_ev;
    num[i] = '\0';
    do {
        num[--i] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v != 0 && i > 0);
    say(sig == SIGILL ? "fuzz_udsota_frames: CRASH (SIGILL: UBSan trap)"
                      : "fuzz_udsota_frames: CRASH (fatal signal: guard page or abort)");
    say(" while replaying ");
    say(g_label);
    say(", event ");
    say(&num[i]);
    say("\n");
}

/* Installs on_fatal for the signals a guard-page hit, a UBSan trap or an assert raise. */
static void install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fatal;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0) {
            die("sigaction failed");
        }
    }
}

/* Child side of a self-test: one byte read just past an 8-byte frame. */
static void probe_read_past_frame(void)
{
    const uint8_t f[CAN_DL] = {0};
    const volatile uint8_t *p = frame_at_guard(f, CAN_DL);
    g_sink = p[CAN_DL];
}

/* Child side of a self-test: one byte written just past the adapter's buffers. */
static void probe_write_past_bufs(void)
{
    volatile uint8_t *p = B->park;
    p[sizeof B->park] = 0;
}

/* Child side of a self-test: a signed overflow that UBSan (trap mode) must stop. */
static void probe_ubsan(void)
{
    volatile int a = INT_MAX;
    volatile int b = 1;
    volatile int sum = a + b;
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
        (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        probe();
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFSIGNALED(status) || WTERMSIG(status) != sig) {
        die("self-test '%s' was not stopped by signal %d (status 0x%x): the harness cannot see this bug class",
            what, sig, (unsigned)status);
    }
}

/* Proves each detector fires before any replay counts. */
static void self_test(void)
{
    expect_death("read past the frame", probe_read_past_frame, SIGSEGV);
    expect_death("write past the adapter's buffers", probe_write_past_bufs, SIGSEGV);
#ifdef UDSOTA_FUZZ_UBSAN_TRAP
    expect_death("UBSan signed overflow", probe_ubsan, SIGILL);
#else
    (void)probe_ubsan;
#endif
}

/* Maps the guard arenas, opens the fake engine's slots, builds the seeds' image and the fixed structs. */
static void harness_init(void)
{
    arena_init(&g_fr, CAN_DL);
    arena_init(&g_ba, sizeof(udsota_isotp_bufs_t));
    B = (udsota_isotp_bufs_t *)(void *)(g_ba.page + g_ba.size - sizeof(udsota_isotp_bufs_t));
    if (!fake_ota_open(&OTA, FUZZ_FRAMES_OTA_DIR, SLOT_SIZE, true)) {
        die("fake_ota_open failed in %s", FUZZ_FRAMES_OTA_DIR);
    }
    g_img_len = fake_ota_build_image(g_img, sizeof g_img, "v1.2.3", NULL, IMG_PAYLOAD);
    if (g_img_len == 0u) {
        die("fake_ota_build_image failed");
    }
    ENG = (udsota_engine_t){ .check_first = eng_check_first, .begin = eng_begin, .write = eng_write,
                             .verify = eng_verify, .activate = eng_activate, .confirm = eng_confirm,
                             .abort = eng_abort, .unverify = eng_unverify, .poll = eng_poll, .status = eng_status,
                             .slot_size = SLOT_SIZE };
    HOOKS = (udsota_hooks_t){ .gate = hook_gate, .did_read = hook_did_read, .reset = hook_reset,
                              .comm_control = hook_comm_control, .dtc_setting = hook_dtc_setting,
                              .dtc_get = hook_dtc_get };
    SEC = (udsota_security_t){ .rng16 = mock_rng16, .key = mock_key };
    CAN = (udsota_can_t){ .send = bus_send, .tx_pending = can_tx_pending, .now_us = can_now_us };
}

/* Self-tests the detectors, replays the seeds in every variant, then their mutants and random programs, checks the
 * coverage floor. Usage: fuzz_udsota_frames [--mutations N] [--seed S] [--only P]: --seed starts the mutation PRNG
 * elsewhere (the pinned digest is the default's), and --only replays program P alone (the number a FAIL names, with
 * the same --mutations and --seed) and traces every frame. Exit 0 = pass. */
int main(int argc, char **argv)
{
    unsigned mutations = MUTATIONS_DEFAULT;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--mutations") == 0) {
            mutations = (unsigned)strtoul(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--seed") == 0) {
            g_rng = (uint32_t)strtoul(argv[i + 1], NULL, 0) | 1u;
        } else if (strcmp(argv[i], "--only") == 0) {
            g_only = strtol(argv[i + 1], NULL, 10);
        }
    }
    harness_init();
    self_test();
    install_handlers();
    build_seeds();
    for (size_t i = 0; i < g_seed_n; i++, G.programs++) {
        for (unsigned v = 0; v < VARIANT_COUNT; v++) {
            run_one("seed", G.programs, &g_seeds[g_seed[i].off], g_seed[i].len, v, g_seed[i].want_ok && v == 0u);
        }
    }
    static uint8_t buf[PROG_MAX];
    for (size_t i = 0; i < g_seed_n; i++) {
        for (unsigned m = 0; m < mutations; m++, G.programs++) {
            const size_t n = mutate(&g_seeds[g_seed[i].off], g_seed[i].len, buf);
            run_one("mutant", G.programs, buf, n, (unsigned)(G.programs % VARIANT_COUNT), false);
        }
    }
    for (unsigned i = 0; i < RANDOM_PROGRAMS; i++, G.programs++) {
        size_t n = 0;
        for (unsigned k = 4u + rnd() % 40u; k != 0u && n + UDSOTA_DL_MAX_BLOCK_LEN + 16u < PROG_MAX; k--) {
            n += random_event(&buf[n]);
        }
        run_one("random", G.programs, buf, n, (unsigned)(G.programs % VARIANT_COUNT), false);
    }
    fake_ota_close(&OTA);
    if (g_only >= 0) {
        printf("fuzz_udsota_frames: replayed program %ld alone\n", g_only);
        return 0;
    }
    print_coverage();
    check_coverage();
    printf("fuzz_udsota_frames: PASS %lu programs, %lu runs, %lu events, %lu frames fed (%lu physical, %lu "
           "functional), %lu offered to the bus, digest=%016" PRIx64 "\n", G.programs, G.runs, G.events,
           G.fed_phys + G.fed_func, G.fed_phys, G.fed_func, G.offered, g_digest);
    return 0;
}
