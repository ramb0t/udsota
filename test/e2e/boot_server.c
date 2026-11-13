/* udsota_boot_server: the bootloader core (boot/udsota_boot.c), on iso14229 built as a product builds it, as a Linux
 * process, so the client can be run against the real core: client/tests/test_e2e_boot.py does, and so can anyone with
 * their own profile and stamped image. CAN frames arrive on stdin and leave on stdout, one per line as `710#0322F18C`
 * (the client tests' PipeTransport), on one bus. The port is the unit tests' fake (test/boot/fake_port.c), its clock
 * set from CLOCK_MONOTONIC before each call and its slot in RAM in 1 KB erase units. When the core starts the app, a
 * stand-in app on udsota_app.h runs instead: it answers 10 02 with 7F 10 78, writes the handover and resets into
 * the core, and once healthy clears the start count and answers 22 F1F4 with the installed image's ID prefix.
 *
 *     udsota_boot_server [--req-id N] [--resp-id N] [--product NAME] [--hw-id N] [--layout-id N] [--slot-size N]
 *                        [--header-offset N] [--write-unit N] [--boot-version TEXT] [--image FILE] [--hang ID]
 *                        [--no-handover] [--power-cycle-after N] [--fail-erase N]
 *
 * The identity and geometry default to udsota's example: 0x710 and 0x718, "example", hw_id 1, layout 1, a 0x20000
 * slot, the header at 0x100, a write unit of 2, bootloader "1.0.0". Numbers take 0x for hex. The policy is the
 * header's example: a 100 ms power-up window, a hold after 5 starts, a 1000 ms watchdog. --image installs a stamped
 * bare image (none: an empty slot), and the process starts as a power-on. A reset or power cycle is a boot after
 * 300 ms of silence; frames sent meanwhile wait, as frames nothing acknowledges do on a bus, and reach whichever runs
 * once it is up. The app reports healthy 200 ms after it starts.
 *
 * Faults: --hang ID (1 to 32 bytes of hex) makes an app whose image ID starts with ID hang, never healthy, so the
 * watchdog resets it until the start count holds the unit; --no-handover makes the app answer 7F 10 78 and reset
 * without writing the handover, so it comes back up as the app; --power-cycle-after N power-cycles the unit in place of
 * the app's answer to its Nth 10 02; --fail-erase N fails the Nth erase. Frames lost on the bus are the pipe's to drop.
 *
 * Logs go to stderr only. It exits 0 at stdin's end, SIGTERM or SIGINT, 1 if the core broke the port's contract
 * (fake_port.h) or reading stdin failed, 2 for bad arguments or a configuration the core refuses. */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "boot/fake_port.h"
#include "iso14229.h"
#include "udsota_app.h"
#include "udsota_boot.h"

#define BUS        1u     /* the pipe is one bus */
#define QUEUE      64u    /* frames waiting for the unit */
#define BOOT_MS    300u   /* from a reset or power cycle to the boot */
#define HEALTHY_MS 200u   /* from the app's start to its healthy mark */

typedef struct {
    uint32_t id;
    uint8_t  len;
    uint8_t  data[8];
} frame_t;

static udsota_boot_cfg_t s_cfg = {
    .request_id = 0x710u, .response_id = 0x718u, .product = "example", .hw_id = 1u, .layout_id = 1u,
    .boot_version = "1.0.0", .buses = 1u, .slot_size = 0x20000u, .slot_write_unit = 2u, .image_header_offset = 0x100u,
    .window_ms = 100u, .hold_after_starts = 5u, .watchdog_ms = 1000u,
};
static uint32_t s_power_cycle_after, s_fail_erase;
static uint8_t  s_hang[32];
static int      s_hang_len;
static bool     s_no_handover;
static volatile sig_atomic_t s_stop;

/* The unit: off (between a reset and its next boot), in its bootloader, or in its app; and the frames waiting for
 * it. */
static struct {
    enum { OFF, BOOT, APP } state;
    uint64_t at;                     /* OFF: when the next boot comes; APP: when the app started */
    udsota_boot_reset_t cause;       /* OFF: the next boot's reset cause */
    bool     healthy, hung;          /* APP */
    int      starts, resets, erases, programs;   /* the fake's counts already acted on */
    uint32_t handovers;              /* 10 02s the app has taken */
    frame_t  queue[QUEUE];
    size_t   head, queued;
} U;

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t now_ms(void) { return now_us() / 1000u; }

/* One frame out as a line on stdout, written at once. */
static void out(uint32_t id, const uint8_t *data, uint8_t len)
{
    char line[32];
    int n = snprintf(line, sizeof line, "%03X#", (unsigned)id);
    for (uint8_t i = 0; i < len; i++) {
        n += snprintf(&line[n], sizeof line - (size_t)n, "%02X", data[i]);
    }
    line[n++] = '\n';
    for (int off = 0; off < n;) {
        const ssize_t w = write(STDOUT_FILENO, &line[off], (size_t)(n - off));
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            s_stop = 1;                                  /* the client is gone */
            return;
        }
        off += (int)w;
    }
}

/* The unit goes silent for BOOT_MS, then boots with cause. */
static void power_off(udsota_boot_reset_t cause, const char *why)
{
    fprintf(stderr, "udsota_boot_server: %s; booting in %u ms\n", why, BOOT_MS);
    U.state = OFF;
    U.at = now_ms() + BOOT_MS;
    U.cause = cause;
}

static void boot(void)
{
    static const char *const k_names[] = {"HANDOVER", "NO_APP", "HELD", "WINDOW", "START_APP", "BAD_CFG"};
    static const char *const k_causes[] = {"power-on", "pin", "other"};
    fake.cause = U.cause;
    fake.wd_period = 0u;                                 /* a reset stops the watchdog and the buses */
    fake.started = 0u;
    if (U.cause == UDSOTA_BOOT_RESET_POWER_ON) {
        memset(fake.keep, 0, sizeof fake.keep);         /* a power-on loses the keep words */
    }
    fake.us = (uint32_t)now_us();
    const udsota_boot_decision_t d = udsota_boot_init(&s_cfg);
    fprintf(stderr, "udsota_boot_server: boot (%s reset): %s\n", k_causes[U.cause], k_names[d]);
    if (d == UDSOTA_BOOT_DECIDE_BAD_CFG) {
        fputs("udsota_boot_server: the core refuses this configuration (udsota_boot_init, boot/udsota_boot.h)\n",
              stderr);
        exit(2);
    }
    U.state = BOOT;
}

/* The installed image's ID, as the app reads it from its placed header. */
static const uint8_t *image_id(void)
{
    return fake.slot + s_cfg.image_header_offset + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_IMAGE_ID_OFFSET;
}

static void app_start(void)
{
    const uint8_t *id = image_id();
    U.state = APP;
    U.at = now_ms();
    U.healthy = false;
    U.hung = s_hang_len > 0 && memcmp(id, s_hang, (size_t)s_hang_len) == 0;
    fprintf(stderr, "udsota_boot_server: the app starts: image %02x%02x%02x%02x, start count %u%s\n", id[0], id[1],
            id[2], id[3], fake.keep[UDSOTA_KEEP_WORD_COUNT] & UDSOTA_START_COUNT_MASK, U.hung ? ", and hangs" : "");
}

/* After each call into the core: the frames it sent, its flash work logged, and the start of the app or the reset it
 * made. */
static void after_core(void)
{
    for (size_t i = 0; i < fake.n_frames; i++) {
        out(fake.frames[i].id, fake.frames[i].data, fake.frames[i].len);
    }
    fake.n_frames = 0;
    if (fake.erase_calls != U.erases) {
        U.erases = fake.erase_calls;
        fprintf(stderr, "udsota_boot_server: erase 0x%X bytes at 0x%X%s\n", (unsigned)fake.erase_len,
                (unsigned)fake.erase_off, fake.erase_fails ? ": fails (--fail-erase)" : "");
    }
    if (fake.program_calls != U.programs) {
        U.programs = fake.program_calls;
        fprintf(stderr, "udsota_boot_server: program 0x%X bytes at 0x%X\n", (unsigned)fake.program_len,
                (unsigned)fake.program_off);
    }
    if (fake.starts != U.starts) {
        U.starts = fake.starts;
        app_start();
    } else if (fake.resets != U.resets) {
        U.resets = fake.resets;
        power_off(UDSOTA_BOOT_RESET_OTHER, "the core resets the unit");
    }
}

/* The app's store for the keep words: the fake's, which the core reads. */
void udsota_app_port_keep_write(uint8_t word, uint16_t value)
{
    if (word < UDSOTA_KEEP_WORDS) {
        fake.keep[word] = value;
    }
}

/* One frame to the app, which takes only the two requests udsota_app.h names. A hung app takes nothing. */
static void app_frame(const frame_t *f)
{
    uint8_t a[8];
    if (U.hung) {
        return;
    }
    switch (udsota_app_classify(s_cfg.request_id, f->id, true, f->data, f->len)) {
    case UDSOTA_APP_RX_HANDOVER:
        if (++U.handovers == s_power_cycle_after) {
            power_off(UDSOTA_BOOT_RESET_POWER_ON, "--power-cycle-after: the unit is power-cycled");
            return;
        }
        udsota_app_answer_pending(a);
        out(s_cfg.response_id, a, 8u);
        if (!s_no_handover) {
            udsota_app_write_handover(BUS);
        }
        udsota_app_clear_start_count();                  /* before every deliberate reset */
        power_off(UDSOTA_BOOT_RESET_OTHER, s_no_handover ? "the app resets without a handover (--no-handover)"
                                                         : "the app hands over to the bootloader");
        break;
    case UDSOTA_APP_RX_READ_PREFIX:
        if (U.healthy) {
            udsota_app_answer_prefix(image_id(), a);
            out(s_cfg.response_id, a, 8u);
        }
        break;
    default:
        break;
    }
}

/* About every millisecond: the boot that ends a reset; the core's poll, or the app's own time (its healthy mark, or
 * the watchdog a hung app never reloads); then the waiting frames, to whichever runs, until one turns the unit off. */
static void step(void)
{
    if (U.state == OFF) {
        if (now_ms() < U.at) {
            return;
        }
        boot();
    }
    if (U.state == BOOT) {
        fake.erase_fails = s_fail_erase != 0u && (uint32_t)fake.erase_calls + 1u == s_fail_erase;
        fake.us = (uint32_t)now_us();
        udsota_boot_poll();
        after_core();
    } else if (U.hung && fake.wd_period != 0u && now_ms() - U.at >= fake.wd_period) {
        power_off(UDSOTA_BOOT_RESET_OTHER, "the watchdog resets the hung app");
    } else if (!U.hung && !U.healthy && now_ms() - U.at >= HEALTHY_MS) {
        U.healthy = true;
        udsota_app_clear_start_count();
        fputs("udsota_boot_server: the app reports healthy and clears the start count\n", stderr);
    }
    while (U.queued > 0u && U.state != OFF) {
        const frame_t *f = &U.queue[U.head];
        U.head = (U.head + 1u) % QUEUE;
        U.queued--;
        if (U.state == APP) {
            app_frame(f);
        } else {
            fake.us = (uint32_t)now_us();
            udsota_boot_rx(BUS, f->id, f->data, f->len);
            after_core();
        }
    }
}

static int hexval(char ch)
{
    return (ch >= '0' && ch <= '9') ? ch - '0'
         : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10
         : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
                                    : -1;
}

/* Hex digit pairs from s into out, up to max bytes: their count, or -1 when s is anything else. */
static int hex_bytes(const char *s, uint8_t *out, int max)
{
    int n = 0;
    for (; *s != '\0' && *s != '\r'; s += 2) {
        if (n == max || hexval(s[0]) < 0 || hexval(s[1]) < 0) {
            return -1;
        }
        out[n++] = (uint8_t)((hexval(s[0]) << 4) | hexval(s[1]));
    }
    return n;
}

/* One line, `<3 hex digits>#<0 to 8 hex bytes>`, into the queue; a malformed line, or one the full queue cannot
 * take, is logged and dropped. */
static void on_line(const char *s)
{
    frame_t f = {0};
    int digits = 0;
    for (; hexval(*s) >= 0; s++, digits++) {
        f.id = (f.id << 4) | (uint32_t)hexval(*s);
    }
    const int len = (digits == 3 && *s == '#') ? hex_bytes(s + 1, f.data, (int)sizeof f.data) : -1;
    if (len < 0 || U.queued == QUEUE) {
        fputs(len < 0 ? "udsota_boot_server: dropped a malformed line\n"
                      : "udsota_boot_server: dropped a frame: the queue is full\n", stderr);
        return;
    }
    f.len = (uint8_t)len;
    U.queue[(U.head + U.queued++) % QUEUE] = f;
}

/* Splits stdin's bytes into lines; a partial line waits for the next read, and an over-long one is dropped. */
static void take(const char *buf, size_t n)
{
    static char line[64];
    static size_t len;
    static bool too_long;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] != '\n') {
            too_long = too_long || len == sizeof line - 1u;
            if (!too_long) {
                line[len++] = buf[i];
            }
            continue;
        }
        line[len] = '\0';
        if (too_long) {
            fputs("udsota_boot_server: dropped an over-long line\n", stderr);
        } else if (len > 0u) {
            on_line(line);
        }
        len = 0;
        too_long = false;
    }
}

static void on_stop(int sig)
{
    (void)sig;
    s_stop = 1;
}

/* A number (0x for hex) up to max for option opt; exits 2 otherwise. */
static uint32_t number(const char *opt, const char *s, unsigned long max)
{
    char *end = NULL;
    errno = 0;
    const unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v > max) {
        fprintf(stderr, "udsota_boot_server: %s takes a number up to %lu, not \"%s\"\n", opt, max, s);
        exit(2);
    }
    return (uint32_t)v;
}

/* FILE into the erased slot; exits 2 when it cannot be read, is empty or is larger than the slot. */
static void install(const char *path)
{
    FILE *f = fopen(path, "rb");
    const size_t n = (f != NULL) ? fread(fake.slot, 1, s_cfg.slot_size, f) : 0u;
    const bool whole = f != NULL && !ferror(f) && fgetc(f) == EOF;
    if (f != NULL) {
        fclose(f);
    }
    if (!whole || n == 0u) {
        fprintf(stderr, "udsota_boot_server: %s cannot be read, is empty, or is larger than the 0x%X-byte slot\n",
                path, (unsigned)s_cfg.slot_size);
        exit(2);
    }
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"req-id", required_argument, NULL, 'q'},        {"resp-id", required_argument, NULL, 'r'},
        {"product", required_argument, NULL, 'p'},       {"hw-id", required_argument, NULL, 'w'},
        {"layout-id", required_argument, NULL, 'l'},     {"slot-size", required_argument, NULL, 's'},
        {"header-offset", required_argument, NULL, 'o'}, {"write-unit", required_argument, NULL, 'u'},
        {"boot-version", required_argument, NULL, 'V'},  {"image", required_argument, NULL, 'i'},
        {"hang", required_argument, NULL, 'H'},          {"no-handover", no_argument, NULL, 'n'},
        {"power-cycle-after", required_argument, NULL, 'P'}, {"fail-erase", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    static const char k_usage[] =
        "usage: udsota_boot_server [--req-id N] [--resp-id N] [--product NAME] [--hw-id N] [--layout-id N] "
        "[--slot-size N] [--header-offset N] [--write-unit N] [--boot-version TEXT] [--image FILE] [--hang ID] "
        "[--no-handover] [--power-cycle-after N] [--fail-erase N]\n";
    const char *image_path = NULL;
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
        case 'q': s_cfg.request_id = (uint16_t)number("--req-id", optarg, 0x7FFu); break;
        case 'r': s_cfg.response_id = (uint16_t)number("--resp-id", optarg, 0x7FFu); break;
        case 'p': s_cfg.product = optarg; break;
        case 'w': s_cfg.hw_id = (uint8_t)number("--hw-id", optarg, 0xFFu); break;
        case 'l': s_cfg.layout_id = (uint8_t)number("--layout-id", optarg, 0xFFu); break;
        case 's': s_cfg.slot_size = number("--slot-size", optarg, FAKE_SLOT_MAX); break;
        case 'o': s_cfg.image_header_offset = number("--header-offset", optarg, FAKE_SLOT_MAX); break;
        case 'u': s_cfg.slot_write_unit = (uint16_t)number("--write-unit", optarg, 0x8000u); break;
        case 'V': s_cfg.boot_version = optarg; break;
        case 'i': image_path = optarg; break;
        case 'H':
            s_hang_len = hex_bytes(optarg, s_hang, (int)sizeof s_hang);
            if (s_hang_len <= 0) {
                fprintf(stderr, "udsota_boot_server: --hang takes 1 to 32 bytes of hex, not \"%s\"\n", optarg);
                return 2;
            }
            break;
        case 'n': s_no_handover = true; break;
        case 'P': s_power_cycle_after = number("--power-cycle-after", optarg, 1000000u); break;
        case 'e': s_fail_erase = number("--fail-erase", optarg, 1000000u); break;
        default:  fputs(k_usage, stderr); return 2;
        }
    }
    if (optind != argc) {
        fputs(k_usage, stderr);
        return 2;
    }
    fake_reset();
    fake.erase_us = fake.program_us = fake.can_start_us = 0u;   /* the clock is real: no port call adds time */
    fake_geometry(s_cfg.slot_size, s_cfg.slot_write_unit, (const uint32_t[]){1024u}, 1u);
    if (image_path != NULL) {
        install(image_path);
    }
    signal(SIGPIPE, SIG_IGN);
    const struct sigaction stop = {.sa_handler = on_stop};   /* no SA_RESTART: poll returns, the loop sees s_stop */
    sigaction(SIGTERM, &stop, NULL);
    sigaction(SIGINT, &stop, NULL);
    fprintf(stderr, "udsota_boot_server: iso14229 %s, IDs 0x%03X/0x%03X, product %s, hw_id %u, layout %u, slot 0x%X, "
            "header at 0x%X, write unit %u, bootloader %s; %s%s\n", UDS_LIB_VERSION, s_cfg.request_id,
            s_cfg.response_id, s_cfg.product, s_cfg.hw_id, s_cfg.layout_id, (unsigned)s_cfg.slot_size,
            (unsigned)s_cfg.image_header_offset, s_cfg.slot_write_unit, s_cfg.boot_version,
            image_path != NULL ? "slot holds " : "empty slot", image_path != NULL ? image_path : "");
    U.cause = UDSOTA_BOOT_RESET_POWER_ON;
    boot();
    while (!s_stop) {
        struct pollfd p = {.fd = STDIN_FILENO, .events = POLLIN};
        const int r = poll(&p, 1, 1);
        if (r < 0 && errno != EINTR) {
            perror("udsota_boot_server: poll");
            return 1;
        }
        if (r > 0) {
            char buf[4096];
            const ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
            if (n == 0) {
                break;
            }
            if (n < 0 && errno != EINTR && errno != EAGAIN) {
                perror("udsota_boot_server: read");
                return 1;
            }
            take(buf, n > 0 ? (size_t)n : 0u);
        }
        step();
    }
    if (fake.bad != 0) {
        fprintf(stderr, "udsota_boot_server: the core broke the port's contract %d times\n", fake.bad);
        return 1;
    }
    return 0;
}
