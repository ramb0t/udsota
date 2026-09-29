/* udsota_demo_server: the portable core on Linux, for end-to-end client tests. The real UDS server and
 * ISO-TP adapter run over SocketCAN or a stdin/stdout frame pipe (demo_can.h), with an update engine on
 * two file-backed A/B slots (demo_engine.h). ActivateImage and 11 01 "reboot" in-process: the engine runs
 * the boot slot, stays silent for --boot-ms, and a fresh server starts, so an activated image runs
 * PENDING_VERIFY until ConfirmImage and one reset before that rolls back. A three-DTC table serves 19 and 14.
 *
 *   udsota_demo_server [--socketcan IFACE] [options]      serve (the pipe by default)
 *   udsota_demo_server --make-image OUT --version V         write an image for the configured identity
 *   udsota_demo_server --self-test                          the key derivation's known answers on the host HMAC
 *
 * See tools/linux_server/README.md for every option. Host only (Linux). */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include "demo_can.h"
#include "demo_engine.h"
#include "hmac_sha256_host.h"
#include "udsota.h"
#include "udsota_esp32_image.h"
#include "udsota_isotp.h"
#include "udsota_keys.h"

#define DEMO_SLOT_SIZE      0x1E0000u   /* examples/esp32's OTA slot, as the example profile's slot_size */
#define DEMO_BOOT_MS        500u        /* silence after a restart */
#define DEMO_IMAGE_PAYLOAD  8192u       /* --make-image's default segment 0 size */
#define DEMO_MASTER_LEN     32u         /* the client's master_file: 32 raw bytes */
#define DID_BOARD           0xF191u     /* the example profile's board-name DID */
#define DEMO_DTC_AVAIL      0x2Fu       /* the status bits the demo supports: 0-3 and 5, as CANDash */
#define DTC_REC_COUNT       0x01u       /* extended data record 01: the occurrence count, 1 byte */
#define DTC_REC_SEEN        0x10u       /* extended data record 10: first and last seen, two u32 seconds */

/* Everything the command line sets. */
typedef struct {
    const char *iface;                /* NULL: the pipe */
    bool        allow_real_bus;       /* --allow-real-bus: iface may be a CAN interface other than vcan */
    const char *state_dir;            /* NULL: a fresh temporary directory, removed at exit */
    bool        fresh;
    uint32_t    slot_size;
    const char *running_version;      /* the image seeded into an empty slot 0 */
    const char *board;                /* F191 */
    const char *master_file;
    uint32_t    boot_ms, job_ms, soak_ms;
    bool        skip_boot_delay, no_rollback, no_compress, no_delta, verbose;
    uint16_t    chip_id;
    const char *make_image, *version; /* --make-image OUT --version V */
    uint32_t    payload;
    bool        self_test;
    uint32_t    withhold_fc_after;    /* --withhold-fc-after N: refuse the FC point after a message's Nth CF, once */
    uint32_t    drop_fc_after;        /* --drop-fc-after N: lose the FC sent after a message's Nth CF, once */
    bool        no_dtc;               /* --no-dtc: the DTC hooks stay NULL, so 19 and 14 answer 0x11 */
} opts_t;

/* One of the demo's DTCs and its extended data. */
typedef struct {
    uint32_t dtc;                     /* the SAE J2012 code and a failure-type byte 00 (DTCFormatIdentifier 0x00) */
    uint8_t  status;                  /* sent as status & DEMO_DTC_AVAIL */
    bool     has_records;             /* records 01 and 10 are held */
    bool     has_seen;                /* record 10 holds data (else it is held with none) */
    uint8_t  count;                   /* record 01 */
    uint32_t first_s, last_s;         /* record 10 */
} demo_dtc_t;

/* The one server instance: its options, engine, bus, and the state a restart replaces. */
typedef struct {
    opts_t              o;
    udsota_config_t     cfg;
    uint8_t             device_id[UDSOTA_KEYS_ID_MAX];
    char                label[UDSOTA_KEYS_LABEL_MAX + 1u];
    bool                secured;
    bool                have_kdev;
    uint8_t             kdev[UDSOTA_KEYS_KDEV_LEN];
    demo_engine_t       eng;
    demo_can_t          can;
    udsota_server_t     srv;
    udsota_isotp_t      tp;
    udsota_isotp_bufs_t bufs;
    uint64_t            boot_ms;      /* this boot's clock origin */
    bool                reset_fired;  /* hooks.reset ran: restart once the service call returns */
    bool                booting;      /* restarting: frames are dropped until boot_until */
    uint64_t            boot_until;
    unsigned            boots;
    char                dir[240];     /* the mkdtemp state directory, when --state-dir is not given */
    uint32_t            cfs;          /* CFs of the request message now arriving (fault injection counts them) */
    bool                ignore_ff;    /* the FF after a withheld FC is dropped unanswered */
} demo_t;

static demo_t d;
static volatile sig_atomic_t s_stop;

/* The DTC table (see the README). It lives in RAM for the process, so a restart keeps a clear, as NVS would. */
static demo_dtc_t s_dtcs[] = {
    {0xC07300u, 0x2Fu, true, true, 3u, 120u, 3600u},   /* U0073: lost communication with ECM/PCM "A" */
    {0x056200u, 0x68u, true, false, 1u, 0u, 0u},       /* P0562: system voltage low; 0x40 is off the wire */
    {0x923400u, 0x00u, false, false, 0u, 0u, 0u},      /* B1234: no bit set, so only 19 0A lists it */
};
#define DEMO_DTC_N (sizeof s_dtcs / sizeof s_dtcs[0])

/* Monotonic microseconds. */
static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* isotp-c's clock and the frame stamps: monotonic microseconds, wrapping. */
static uint32_t now_us(void)
{
    return (uint32_t)mono_us();
}

/* udsota_can_t.now_us. */
static uint32_t can_now_us(void *ctx)
{
    (void)ctx;
    return now_us();
}

/* The server's now_ms: milliseconds since this boot, so the 0x27 delay re-arms at every restart; plus
 * UDSOTA_SA_DELAY_MS with --skip-boot-delay, which starts each boot past that delay. */
static uint32_t server_ms(void)
{
    const uint64_t since = mono_us() / 1000u - d.boot_ms;
    return (uint32_t)(since + (d.o.skip_boot_delay ? UDSOTA_SA_DELAY_MS : 0u));
}

/* Name of a udsota_img_state_t, for the log. */
static const char *img_state(uint8_t s)
{
    static const char *const names[] = {"undefined", "new", "pending verify", "valid", "invalid", "aborted"};
    return s < sizeof names / sizeof names[0] ? names[s] : "?";
}

/* ---- Hooks and security ---- */

/* hooks.gate: allows everything, except CONFIRM during the first --soak-ms of a boot (0x22, as an app's soak), and
 * CONTINUE_TRANSFER at the FC point --withhold-fc-after names (0x22, which withholds the FC). */
static uint8_t on_gate(void *ctx, udsota_op_t op)
{
    (void)ctx;
    /* In the middle of a message only: the gate is also asked for the whole 36, after its last CF. */
    if (op == UDSOTA_OP_CONTINUE_TRANSFER && d.o.withhold_fc_after != 0u && d.cfs == d.o.withhold_fc_after &&
        d.tp.rxw.in_msg) {
        d.o.withhold_fc_after = 0u;
        d.ignore_ff = true;
        fprintf(stderr, "udsota_demo_server: --withhold-fc-after: refusing the FC point after CF %u\n",
                (unsigned)d.cfs);
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    if (op == UDSOTA_OP_CONFIRM && d.o.soak_ms != 0u && mono_us() / 1000u - d.boot_ms < d.o.soak_ms) {
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return 0;
}

/* hooks.phase: logs every change. */
static void on_phase(void *ctx, udsota_phase_t p)
{
    (void)ctx;
    static const char *const names[] = {"idle", "extended", "programming", "transferring", "activating"};
    fprintf(stderr, "udsota_demo_server: phase %s\n", (unsigned)p < 5u ? names[p] : "?");
}

/* hooks.did_read: F191, the board name the example profile's [board] table reads. */
static size_t on_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    (void)ctx;
    const size_t n = strlen(d.o.board);
    if (did != DID_BOARD || n == 0u || n > max) {
        return 0;
    }
    memcpy(buf, d.o.board, n);
    return n;
}

/* hooks.reset: the restart is taken once udsota_isotp_service returns; the server stays silent until then. */
static bool on_reset(void *ctx)
{
    (void)ctx;
    d.reset_fired = true;
    return true;
}

/* hooks.dtc_get: the i-th entry of s_dtcs. */
static bool on_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    (void)ctx;
    if (i >= DEMO_DTC_N) {
        return false;
    }
    out->dtc = s_dtcs[i].dtc;
    out->status = s_dtcs[i].status;
    return true;
}

/* Appends record rec of e at buf[*n]: 01 <count>, or 10 <first u32> <last u32> (nothing after the 10 while it holds
 * no data); false when it doesn't fit max. */
static bool dtc_record(const demo_dtc_t *e, uint8_t rec, uint8_t *buf, size_t max, size_t *n)
{
    const size_t need = (rec == DTC_REC_COUNT) ? 2u : e->has_seen ? 9u : 1u;
    if (max - *n < need) {
        return false;
    }
    buf[*n] = rec;
    if (rec == DTC_REC_COUNT) {
        buf[*n + 1u] = e->count;
    } else if (e->has_seen) {
        udsota_put_u32be(&buf[*n + 1u], e->first_s);
        udsota_put_u32be(&buf[*n + 5u], e->last_s);
    }
    *n += need;
    return true;
}

/* hooks.dtc_ext_data: 01 and 10 for U0073 and P0562 (P0562's 10 held with no data, so asked alone it answers the
 * DTC and status alone, and FF leaves it out), none for B1234 (FF answers no records, any other 0x31). */
static uint8_t on_dtc_ext_data(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len)
{
    (void)ctx;
    const demo_dtc_t *e = NULL;
    for (size_t i = 0; i < DEMO_DTC_N && e == NULL; i++) {
        e = (s_dtcs[i].dtc == dtc) ? &s_dtcs[i] : NULL;
    }
    *len = 0u;
    if (e == NULL || (!e->has_records && record != UDSOTA_DTC_RECORD_ALL)) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    if (!e->has_records) {
        return 0u;
    }
    if (record == DTC_REC_SEEN && !e->has_seen) {
        return 0u;                                  /* held, with no data */
    }
    bool ok = true;
    if (record == UDSOTA_DTC_RECORD_ALL) {
        ok = dtc_record(e, DTC_REC_COUNT, buf, max, len) &&
             (!e->has_seen || dtc_record(e, DTC_REC_SEEN, buf, max, len));
    } else if (record == DTC_REC_COUNT || record == DTC_REC_SEEN) {
        ok = dtc_record(e, record, buf, max, len);
    } else {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    return ok ? 0u : UDSOTA_NRC_RESPONSE_TOO_LONG;
}

/* hooks.dtc_clear, its rules in ISO order: the extended session (0x7F), then unlocked at the extended level when
 * security is on (0x33; the demo leaves cfg.level_extended at 0x01), then group FFFFFF only (0x31). Zeroes every
 * status, count and time. */
static uint8_t on_dtc_clear(void *ctx, uint32_t group, udsota_access_t access)
{
    (void)ctx;
    if (access.session != UDSOTA_SESSION_EXTENDED) {
        return UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    }
    if (d.secured && access.unlocked_level != UDSOTA_SA_SEED_EXTENDED) {
        return UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    }
    if (group != UDSOTA_DTC_GROUP_ALL) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    for (size_t i = 0; i < DEMO_DTC_N; i++) {
        s_dtcs[i].status = 0u;
        s_dtcs[i].count = 0u;
        s_dtcs[i].first_s = s_dtcs[i].last_s = 0u;
    }
    fprintf(stderr, "udsota_demo_server: cleared every DTC\n");
    return 0u;
}

/* security.rng16: 16 bytes from getrandom. */
static bool on_rng16(void *ctx, uint8_t out[16])
{
    (void)ctx;
    return getrandom(out, 16, 0) == 16;
}

/* security.key: the key udsota_keys.c derives from K_dev; false (0x22, not an attempt) without a master. */
static bool on_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    (void)ctx;
    return d.have_kdev &&
           udsota_keys_derive_key(hmac_sha256_host, d.kdev, seed, level, d.device_id, d.cfg.device_id_len, out);
}

/* ---- Boot and restart ---- */

/* One request frame from the bus: dropped while restarting, else handed to the adapter. Counts a message's CFs for
 * the fault options; after --withhold-fc-after's refusal the next FF is dropped, as a server on an erroring bus that
 * never answers it. */
static void on_frame(void *ctx, const demo_frame_t *f)
{
    (void)ctx;
    if (d.booting) {
        return;
    }
    const uint8_t pci = (f->dlc >= 1u) ? (uint8_t)(f->data[0] >> 4) : 0xFFu;
    if (pci == 1u) {
        d.cfs = 0u;
        if (d.ignore_ff) {
            d.ignore_ff = false;
            fprintf(stderr, "udsota_demo_server: --withhold-fc-after: ignoring the next FF\n");
            return;
        }
    } else if (pci == 2u) {
        d.cfs++;
    }
    udsota_isotp_on_frame(&d.tp, f->data, f->dlc, f->rx_us, server_ms());
}

/* udsota_can_t.send: demo_can_send, except that the FC after a message's --drop-fc-after'th CF is lost (reported
 * sent), once. */
static int on_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    if (len >= 1u && (data[0] >> 4) == 3u && d.o.drop_fc_after != 0u && d.cfs == d.o.drop_fc_after) {
        d.o.drop_fc_after = 0u;
        fprintf(stderr, "udsota_demo_server: --drop-fc-after: losing the FC after CF %u\n", (unsigned)d.cfs);
        return 0;
    }
    return demo_can_send(ctx, id, data, len);
}

/* Starts a fresh server and adapter on the image now running, as a boot of the device would. */
static void start_server(void)
{
    static udsota_hooks_t hooks;                /* the server and the adapter copy what they need */
    hooks = (udsota_hooks_t){
        .gate = on_gate, .phase = on_phase, .did_read = on_did_read, .reset = on_reset,
    };
    if (!d.o.no_dtc) {
        hooks.dtc_get = on_dtc_get;
        hooks.dtc_ext_data = on_dtc_ext_data;
        hooks.dtc_clear = on_dtc_clear;
    }
    static const udsota_security_t sec = { .rng16 = on_rng16, .key = on_key };
    const udsota_can_t can = {
        .send = on_send, .now_us = can_now_us, .ctx = &d.can,   /* a written frame has left: no tx_pending */
    };
    const udsota_engine_t eng = demo_engine_ops(&d.eng);
    d.boot_ms = mono_us() / 1000u;
    d.boots++;
    d.cfs = 0u;
    d.ignore_ff = false;
    udsota_init(&d.srv, &d.cfg, &eng, d.secured ? &sec : NULL, &hooks);
    udsota_isotp_init(&d.tp, &d.srv, &d.cfg, &hooks, &can, &d.bufs);
    char v[33];
    demo_engine_version(&d.eng, v);
    udsota_status_t st;
    fake_ota_fill_status(&d.eng.ota, &st);
    fprintf(stderr, "udsota_demo_server: boot %u: slot %u runs %s (%s), boot slot %u\n", d.boots, st.running_slot,
            v[0] != '\0' ? v : "no image", img_state(st.running_state), st.boot_slot);
}

/* The restart hooks.reset asked for: the engine boots the boot slot, and the bus is silent for --boot-ms. */
static void restart(void)
{
    d.reset_fired = false;
    demo_engine_boot(&d.eng);
    d.booting = true;
    d.boot_until = mono_us() / 1000u + d.o.boot_ms;
    fprintf(stderr, "udsota_demo_server: restarting\n");
}

/* Serves until stdin's EOF, a read error or SIGINT/SIGTERM. */
static int serve(void)
{
    start_server();
    while (!s_stop) {
        int timeout;
        if (d.booting) {
            const uint64_t now = mono_us() / 1000u;
            if (now >= d.boot_until) {
                d.booting = false;
                start_server();
                continue;
            }
            timeout = (int)(d.boot_until - now);
        } else {
            timeout = (int)udsota_isotp_service(&d.tp, server_ms());
            if (d.reset_fired) {
                restart();
                continue;
            }
        }
        struct pollfd p = { .fd = demo_can_fd(&d.can), .events = POLLIN };
        const int r = poll(&p, 1, timeout);
        if (r < 0 && errno != EINTR) {
            fprintf(stderr, "udsota_demo_server: poll: %s\n", strerror(errno));
            return 1;
        }
        if (r > 0 && demo_can_read(&d.can, on_frame, NULL) < 0) {
            break;                                   /* the pipe's EOF, or the interface went away */
        }
    }
    return 0;
}

/* ---- Command line ---- */

/* Parses a decimal or 0x-hex number in [lo, hi] into *out; false with a message otherwise. */
static bool num(const char *opt, const char *s, unsigned long lo, unsigned long hi, unsigned long *out)
{
    char *end = NULL;
    errno = 0;
    const unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi) {
        fprintf(stderr, "udsota_demo_server: --%s takes a number from %lu to %lu, not \"%s\"\n", opt, lo, hi, s);
        return false;
    }
    *out = v;
    return true;
}

/* Parses a device ID as hex bytes, optionally ':'-separated (1 to 16 bytes); false with a message otherwise. */
static bool parse_device_id(const char *s)
{
    size_t n = 0;
    while (*s != '\0') {
        if (*s == ':') {
            s++;
            continue;
        }
        unsigned b;
        if (n == UDSOTA_KEYS_ID_MAX || !isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]) ||
            sscanf(s, "%2x", &b) != 1) {
            fprintf(stderr, "udsota_demo_server: --device-id takes 1 to 16 hex bytes, e.g. 02:00:00:00:00:01\n");
            return false;
        }
        d.device_id[n++] = (uint8_t)b;
        s += 2;
    }
    d.cfg.device_id_len = n;
    return n > 0u;
}

/* Prints the usage text. */
static void usage(FILE *out)
{
    fputs("usage: udsota_demo_server [--socketcan IFACE] [options]\n"
          "       udsota_demo_server --make-image OUT --version V [identity options] [--payload N]\n"
          "       udsota_demo_server --self-test\n"
          "bus:      --socketcan IFACE (default: frames on stdin/stdout; vcan only unless --allow-real-bus),\n"
          "          --req-id 0x710, --resp-id 0x718\n"
          "identity: --product example, --hw-id 1, --layout-id 1, --board devkit (F191), --chip-id 0x0009\n"
          "slots:    --state-dir DIR, --fresh, --slot-size 0x1E0000, --running-version v0.1.0, --no-rollback,\n"
          "          --no-compress (refuse DFI 0x10, 0x20 and 0x30 downloads), --no-delta (refuse 0x20 and 0x30)\n"
          "security: --label LABEL [--master FILE (32 bytes)], --device-id 02:00:00:00:00:01, --skip-boot-delay\n"
          "dtc:      --no-dtc (no DTC hooks: 19 and 14 answer 0x11)\n"
          "timing:   --boot-ms 500, --job-ms 0, --soak-ms 0, --stmin-us 2000, --block-size 64, --stmin-monitor\n"
          "faults:   --withhold-fc-after N (refuse the FC point after a message's Nth CF, then ignore the next FF),\n"
          "          --drop-fc-after N (lose the FC sent after a message's Nth CF); each once, N a multiple of the BS\n"
          "          -v logs every frame on stderr\n", out);
}

/* Fills d.o and d.cfg from argv; false (after a message) on a bad option. */
static bool parse_args(int argc, char **argv)
{
    enum {
        O_SOCKETCAN = 256, O_REQ, O_RESP, O_PRODUCT, O_HW, O_LAYOUT, O_BOARD, O_CHIP, O_DIR, O_FRESH, O_SLOT, O_RUNNING,
        O_NO_ROLLBACK, O_LABEL, O_MASTER, O_DEVID, O_SKIP_DELAY, O_BOOT_MS, O_JOB_MS, O_SOAK_MS, O_STMIN, O_BS,
        O_MONITOR, O_MAKE, O_VERSION, O_PAYLOAD, O_SELF_TEST, O_HELP, O_REAL_BUS, O_NO_COMPRESS, O_WITHHOLD_FC,
        O_DROP_FC, O_NO_DELTA, O_NO_DTC,
    };
    static const struct option longopts[] = {
        {"socketcan", required_argument, NULL, O_SOCKETCAN}, {"req-id", required_argument, NULL, O_REQ},
        {"resp-id", required_argument, NULL, O_RESP}, {"product", required_argument, NULL, O_PRODUCT},
        {"hw-id", required_argument, NULL, O_HW}, {"layout-id", required_argument, NULL, O_LAYOUT},
        {"board", required_argument, NULL, O_BOARD}, {"chip-id", required_argument, NULL, O_CHIP},
        {"state-dir", required_argument, NULL, O_DIR}, {"fresh", no_argument, NULL, O_FRESH},
        {"slot-size", required_argument, NULL, O_SLOT}, {"running-version", required_argument, NULL, O_RUNNING},
        {"no-rollback", no_argument, NULL, O_NO_ROLLBACK}, {"label", required_argument, NULL, O_LABEL},
        {"master", required_argument, NULL, O_MASTER}, {"device-id", required_argument, NULL, O_DEVID},
        {"skip-boot-delay", no_argument, NULL, O_SKIP_DELAY}, {"boot-ms", required_argument, NULL, O_BOOT_MS},
        {"job-ms", required_argument, NULL, O_JOB_MS}, {"soak-ms", required_argument, NULL, O_SOAK_MS},
        {"stmin-us", required_argument, NULL, O_STMIN}, {"block-size", required_argument, NULL, O_BS},
        {"stmin-monitor", no_argument, NULL, O_MONITOR}, {"make-image", required_argument, NULL, O_MAKE},
        {"version", required_argument, NULL, O_VERSION}, {"payload", required_argument, NULL, O_PAYLOAD},
        {"self-test", no_argument, NULL, O_SELF_TEST}, {"help", no_argument, NULL, O_HELP},
        {"allow-real-bus", no_argument, NULL, O_REAL_BUS}, {"no-compress", no_argument, NULL, O_NO_COMPRESS},
        {"withhold-fc-after", required_argument, NULL, O_WITHHOLD_FC},
        {"drop-fc-after", required_argument, NULL, O_DROP_FC},
        {"no-delta", no_argument, NULL, O_NO_DELTA}, {"no-dtc", no_argument, NULL, O_NO_DTC},
        {NULL, 0, NULL, 0},
    };
    d.o = (opts_t){
        .slot_size = DEMO_SLOT_SIZE, .running_version = "v0.1.0", .board = "devkit", .boot_ms = DEMO_BOOT_MS,
        .chip_id = UDSOTA_ESP32_CHIP_ID_S3, .payload = DEMO_IMAGE_PAYLOAD,
    };
    d.cfg = (udsota_config_t){ .req_id = 0x710, .resp_id = 0x718, .product = "example", .hw_id = 1, .layout_id = 1,
                               .dtc_availability_mask = DEMO_DTC_AVAIL, .dtc_format = 0x00 };
    static const uint8_t default_id[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};   /* a locally administered MAC */
    memcpy(d.device_id, default_id, sizeof default_id);
    d.cfg.device_id_len = sizeof default_id;
    const char *label = NULL;
    unsigned long v = 0;
    int c;
    while ((c = getopt_long(argc, argv, "vh", longopts, NULL)) != -1) {
        bool ok = true;
        switch (c) {
        case O_SOCKETCAN:   d.o.iface = optarg; break;
        case O_REAL_BUS:    d.o.allow_real_bus = true; break;
        case O_REQ:         ok = num("req-id", optarg, 0, 0x7FF, &v); d.cfg.req_id = (uint16_t)v; break;
        case O_RESP:        ok = num("resp-id", optarg, 0, 0x7FF, &v); d.cfg.resp_id = (uint16_t)v; break;
        case O_PRODUCT:     d.cfg.product = optarg; break;
        case O_HW:          ok = num("hw-id", optarg, 0, 0xFF, &v); d.cfg.hw_id = (uint8_t)v; break;
        case O_LAYOUT:      ok = num("layout-id", optarg, 0, 0xFF, &v); d.cfg.layout_id = (uint8_t)v; break;
        case O_BOARD:       d.o.board = optarg; break;
        case O_CHIP:        ok = num("chip-id", optarg, 0, 0xFFFF, &v); d.o.chip_id = (uint16_t)v; break;
        case O_DIR:         d.o.state_dir = optarg; break;
        case O_FRESH:       d.o.fresh = true; break;
        case O_SLOT:        ok = num("slot-size", optarg, FAKE_OTA_SECTOR, 0x1000000, &v);
                            d.o.slot_size = (uint32_t)v; break;
        case O_RUNNING:     d.o.running_version = optarg; break;
        case O_NO_ROLLBACK: d.o.no_rollback = true; break;
        case O_NO_COMPRESS: d.o.no_compress = true; break;
        case O_WITHHOLD_FC: ok = num("withhold-fc-after", optarg, 1, 585, &v);
                            d.o.withhold_fc_after = (uint32_t)v; break;
        case O_DROP_FC:     ok = num("drop-fc-after", optarg, 1, 585, &v); d.o.drop_fc_after = (uint32_t)v; break;
        case O_NO_DELTA:    d.o.no_delta = true; break;
        case O_NO_DTC:      d.o.no_dtc = true; break;
        case O_LABEL:       label = optarg; break;
        case O_MASTER:      d.o.master_file = optarg; break;
        case O_DEVID:       ok = parse_device_id(optarg); break;
        case O_SKIP_DELAY:  d.o.skip_boot_delay = true; break;
        case O_BOOT_MS:     ok = num("boot-ms", optarg, 0, 60000, &v); d.o.boot_ms = (uint32_t)v; break;
        case O_JOB_MS:      ok = num("job-ms", optarg, 0, 120000, &v); d.o.job_ms = (uint32_t)v; break;
        case O_SOAK_MS:     ok = num("soak-ms", optarg, 0, 600000, &v); d.o.soak_ms = (uint32_t)v; break;
        case O_STMIN:       ok = num("stmin-us", optarg, 1, 127000, &v); d.cfg.stmin_us = (uint32_t)v; break;
        case O_BS:          ok = num("block-size", optarg, 1, 0xFF, &v); d.cfg.block_size = (uint8_t)v; break;
        case O_MONITOR:     d.cfg.stmin_monitor = true; break;
        case O_MAKE:        d.o.make_image = optarg; break;
        case O_VERSION:     d.o.version = optarg; break;
        case O_PAYLOAD:     ok = num("payload", optarg, FAKE_OTA_MIN_PAYLOAD, 0xFFFFFC, &v);
                            d.o.payload = (uint32_t)v; break;
        case O_SELF_TEST:   d.o.self_test = true; break;
        case 'v':           d.o.verbose = true; break;
        case 'h':
        case O_HELP:        usage(stdout); exit(0);
        default:            usage(stderr); return false;
        }
        if (!ok) {
            return false;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return false;
    }
    if (d.o.iface != NULL && !d.o.allow_real_bus && !demo_can_is_vcan(d.o.iface)) {
        fprintf(stderr, "udsota_demo_server: %s is not a vcan interface; a demo on a real bus would answer real "
                "testers (--allow-real-bus to serve on it anyway)\n", d.o.iface);
        return false;
    }
    if (d.o.slot_size % FAKE_OTA_SECTOR != 0u) {
        fprintf(stderr, "udsota_demo_server: --slot-size must be a multiple of %u\n", FAKE_OTA_SECTOR);
        return false;
    }
    if (d.o.payload % 4u != 0u) {
        fprintf(stderr, "udsota_demo_server: --payload must be a multiple of 4\n");
        return false;
    }
    if (d.o.master_file != NULL && label == NULL) {
        fprintf(stderr, "udsota_demo_server: --master needs --label\n");
        return false;
    }
    if (label != NULL) {
        if (strlen(label) > UDSOTA_KEYS_LABEL_MAX) {
            fprintf(stderr, "udsota_demo_server: --label is at most %d bytes\n", UDSOTA_KEYS_LABEL_MAX);
            return false;
        }
        strcpy(d.label, label);
        d.cfg.key_label = d.label;
        d.secured = true;                           /* a label without a master: on, and no key matches */
    }
    d.cfg.device_id = d.device_id;
    return true;
}

/* Reads the 32-byte master and derives K_dev over the label and device ID; false with a message otherwise. */
static bool load_master(void)
{
    uint8_t master[DEMO_MASTER_LEN + 1u];
    FILE *f = fopen(d.o.master_file, "rb");
    const size_t n = (f != NULL) ? fread(master, 1, sizeof master, f) : 0u;
    if (f != NULL) {
        fclose(f);
    }
    if (n != DEMO_MASTER_LEN) {
        fprintf(stderr, "udsota_demo_server: %s must hold exactly %u raw bytes\n", d.o.master_file, DEMO_MASTER_LEN);
        return false;
    }
    d.have_kdev = udsota_keys_derive_kdev(hmac_sha256_host, master, DEMO_MASTER_LEN, d.label, d.device_id,
                                          d.cfg.device_id_len, d.kdev);
    memset(master, 0, sizeof master);
    if (!d.have_kdev) {
        fprintf(stderr, "udsota_demo_server: K_dev derivation failed\n");
    }
    return d.have_kdev;
}

/* --make-image: writes an image for the configured identity at --version. */
static int make_image(void)
{
    if (d.o.version == NULL) {
        fprintf(stderr, "udsota_demo_server: --make-image needs --version\n");
        return 2;
    }
    const size_t cap = 32u + d.o.payload + 16u + 32u;   /* headers, segment 0, checksum padding, SHA-256 */
    uint8_t *img = malloc(cap);
    const size_t n = (img != NULL) ? demo_image_build(img, cap, d.o.version, &d.cfg, d.o.payload) : 0u;
    FILE *f = (n != 0u) ? fopen(d.o.make_image, "wb") : NULL;
    bool ok = f != NULL && fwrite(img, 1, n, f) == n;
    if (f != NULL && fclose(f) != 0) {
        ok = false;
    }
    free(img);
    if (!ok) {
        fprintf(stderr, "udsota_demo_server: cannot build or write %s (version \"%s\")\n", d.o.make_image, d.o.version);
        return 1;
    }
    fprintf(stderr, "udsota_demo_server: wrote %s: %s %s, hw_id %u, layout %u, IDs 0x%03X/0x%03X, %zu bytes\n",
            d.o.make_image, d.cfg.product, d.o.version, d.cfg.hw_id, d.cfg.layout_id, d.cfg.req_id, d.cfg.resp_id, n);
    return 0;
}

/* Removes the temporary state directory this run created; an atexit handler, so every exit after mkdtemp runs it. */
static void remove_temp_dir(void)
{
    static const char *const names[] = {"ota_0.bin", "ota_1.bin", "otadata.txt", "otadata.tmp"};
    char p[300];
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", d.dir, names[i]);
        (void)unlink(p);
    }
    (void)rmdir(d.dir);
}

/* SIGINT/SIGTERM: stop at the next wake. */
static void on_signal(int sig)
{
    (void)sig;
    s_stop = 1;
}

/* Parses the options, opens the slots and the bus, and serves. Exit 0 at EOF or on a signal, 1 on a runtime
 * error, 2 on a bad option. */
int main(int argc, char **argv)
{
    if (!parse_args(argc, argv)) {
        return 2;
    }
    if (d.o.self_test) {
        const bool ok = udsota_keys_self_test(hmac_sha256_host);
        printf("udsota_keys_self_test on the host HMAC-SHA256: %s\n", ok ? "pass" : "FAIL");
        return ok ? 0 : 1;
    }
    if (d.o.make_image != NULL) {
        return make_image();
    }
    if (d.secured && d.o.master_file != NULL && !load_master()) {
        return 2;
    }
    const char *dir = d.o.state_dir;   /* passed as given: fake_ota_open refuses one too long, never truncates it */
    if (dir == NULL) {
        const char *tmp = getenv("TMPDIR");
        snprintf(d.dir, sizeof d.dir, "%s/udsota_demo.XXXXXX", (tmp != NULL && *tmp != '\0') ? tmp : "/tmp");
        if (mkdtemp(d.dir) == NULL) {
            fprintf(stderr, "udsota_demo_server: cannot create a state directory: %s\n", strerror(errno));
            return 1;
        }
        atexit(remove_temp_dir);
        dir = d.dir;
    }
    const bool bus = d.o.iface != NULL ? demo_can_open_socketcan(&d.can, d.o.iface, d.cfg.req_id, now_us)
                                       : demo_can_open_pipe(&d.can, d.cfg.req_id, now_us);
    if (!bus) {
        return 1;
    }
    d.can.verbose = d.o.verbose;
    if (!demo_engine_open(&d.eng, dir, d.o.slot_size, d.o.fresh, &d.cfg, d.o.running_version, d.o.chip_id,
                          d.o.job_ms)) {
        fprintf(stderr, "udsota_demo_server: cannot open the slots in %s (or seed %s)\n", dir, d.o.running_version);
        demo_can_close(&d.can);
        return 1;
    }
    d.eng.ota.no_rollback = d.o.no_rollback;
    d.eng.compress = !d.o.no_compress;
    d.eng.delta = !d.o.no_compress && !d.o.no_delta;
    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    fprintf(stderr, "udsota_demo_server: %s%s, IDs 0x%03X/0x%03X, %s hw_id %u layout %u, slots of 0x%X in %s, "
            "security %s, compressed downloads %s, delta downloads %s\n", d.o.iface != NULL ? "SocketCAN " : "pipe on stdin/stdout",
            d.o.iface != NULL ? d.o.iface : "", d.cfg.req_id, d.cfg.resp_id, d.cfg.product, d.cfg.hw_id,
            d.cfg.layout_id, d.o.slot_size, dir,
            !d.secured ? "off" : d.have_kdev ? "on" : "on, no master (every key refused)",
            d.o.no_compress ? "off" : "on", d.eng.delta ? "on" : "off");
    const int rc = serve();
    demo_can_close(&d.can);
    demo_engine_close(&d.eng);
    return rc;
}
