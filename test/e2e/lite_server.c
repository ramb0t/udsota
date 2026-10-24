/* udsota_lite_server: udsota on unmodified iso14229 as an app runs it, on a Linux host, for the client's end-to-end
 * tests (client/tests/test_e2e_lite.py and test_e2e_lite_vcan.py). It plays examples/candash_ws43's main.c with the
 * example profile's identity: CAN frames arrive on stdin and leave on stdout, one per line as `710#0322F18C` (the
 * framing of the client tests' PipeTransport), or on a vcan interface with --can, through isotp-c; UDSServerPoll,
 * then udsota_poll, runs about every millisecond; and the event callback hands each event to udsota_event() first,
 * then serves the app's own: F191, and config writes (2E, a commit routine, a status DID and a hash DID) as the
 * profile's [dids] and [config] describe them. A restart (11 01, or F001's answer) is a boot in-process after
 * --boot-ms of silence: lite_platform.c's slots, then udsota and iso14229 from scratch.
 *
 *     udsota_lite_server --image FILE [--can IFNAME] [--soak-ms N] [--boot-ms N] [--drop-fc-after N] [--no-delta]
 *                        [-v]
 *
 * FILE is the app slot 0 runs, confirmed. --can serves on IFNAME through a CAN_RAW socket instead of the pipe; it is
 * built only where linux/can/raw.h is, and refuses any interface but a vcan. --soak-ms makes the app's gate refuse F002
 * (0x22) for that long after each boot. --drop-fc-after loses the FC sent after a request's Nth CF, once (N a multiple
 * of isotp-c's block size, 8). Built with -DUDSOTA_DELTA=ON, it serves delta downloads (DFI 0x30) from the running
 * slot, and --no-delta clears cfg.allow_delta so that a delta 34 answers 0x31; the start-up line says which. -v logs
 * every frame on stderr. stdin's EOF (in pipe mode), SIGTERM or SIGINT stops the server. */
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef LITE_SOCKETCAN
#include <net/if.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#include "iso14229.h"
#include "lite_platform.h"
#include "sha256_host.h"
#include "udsota.h"

/* The example profile's IDs, board and 0x27 label (client/udsota/profiles/example.toml); the master is bytes 0..31,
 * as the client tests' MASTER. */
#define REQ_ID         0x710u
#define RESP_ID        0x718u
#define HW_ID          1u
#define LAYOUT_ID      1u
#define KEY_LABEL      "udsota-example"
#define DID_BOARD      0xF191u
#define BOARD_NAME     "devkit"
/* The app's config, as the example profile's commented [dids] and [config] name it. */
#define DID_MODE       0x0200u     /* u8, 0..2 */
#define DID_TIMEOUT    0x0201u     /* u16, 1000..5000 */
#define DID_CFG_HASH   0xF1B0u
#define DID_CFG_STATUS 0xF1B2u
#define RID_COMMIT     0x1234u
#define CFG_SCHEMA     1u
#define LEVEL_EXT      0x01u       /* config writes need the extended level's key, the profile's level_extended */
#define BOOT_MS        300u        /* silence after a restart */

UDSOTA_IMAGE_DESC(HW_ID, LAYOUT_ID, REQ_ID, RESP_ID);
void udsota_test_reboot(void);

static const uint8_t k_master[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

typedef struct {
    uint8_t  mode;
    uint16_t timeout_ms;
} cfg_vals_t;

/* The config: what runs, what is stored (NVS on a device: it outlives a restart), and what is staged (until the
 * session ends). */
static struct {
    cfg_vals_t applied, stored, staged;
    uint8_t    staged_mask;        /* bit 0: mode, bit 1: timeout_ms */
} C = {.applied = {0u, 2000u}, .stored = {0u, 2000u}};

static UDSServer_t   s_srv;
static UDSTpISOTpC_t s_tp;
static uint64_t      s_boot_ms, s_boot_until;
static uint32_t      s_soak_ms, s_silence_ms = BOOT_MS;
static bool          s_booting, s_reset, s_verbose, s_no_delta;
static int           s_can_fd = -1;          /* the CAN_RAW socket with --can, else -1 (the pipe) */
static uint32_t      s_drop_fc_after, s_cfs;  /* --drop-fc-after's N, and the CFs of the request coming in */
static volatile sig_atomic_t s_stop;

static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t mono_ms(void)
{
    return mono_us() / 1000u;
}

/* Logs one frame on stderr with -v. */
static void log_frame(const char *dir, uint32_t id, const uint8_t *data, uint8_t len)
{
    if (!s_verbose) {
        return;
    }
    fprintf(stderr, "%s %03X#", dir, (unsigned)id);
    for (uint8_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X", data[i]);
    }
    fputc('\n', stderr);
}

/* ---- The bus ---- */

/* One frame out as a pipe line on stdout; false when the client is gone. */
static bool pipe_send(uint32_t id, const uint8_t *data, uint8_t size)
{
    char line[32];
    int n = snprintf(line, sizeof line, "%03X#", (unsigned)id);
    for (uint8_t i = 0; i < size && i < 8u; i++) {
        n += snprintf(&line[n], sizeof line - (size_t)n, "%02X", data[i]);
    }
    line[n++] = '\n';
    for (int off = 0; off < n;) {
        const ssize_t w = write(STDOUT_FILENO, &line[off], (size_t)(n - off));
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return false;
        }
        off += (int)w;
    }
    return true;
}

#ifdef LITE_SOCKETCAN
/* The attribute of this type among the rtattrs in [p, p + len), or NULL; a malformed list ends the search. */
static const struct rtattr *rta_find(const uint8_t *p, size_t len, unsigned short type)
{
    while (len >= sizeof(struct rtattr)) {
        const struct rtattr *a = (const struct rtattr *)(const void *)p;
        if (a->rta_len < sizeof *a || a->rta_len > len) {
            return NULL;
        }
        if ((a->rta_type & NLA_TYPE_MASK) == type) {
            return a;
        }
        const size_t step = RTA_ALIGN(a->rta_len);
        if (step >= len) {
            return NULL;
        }
        p += step;
        len -= step;
    }
    return NULL;
}

/* True when ifname is a vcan. The kernel's rtnetlink link kind (the "vcan" that `ip -details link show` prints) is
 * the only test that tells one apart: ARPHRD_CAN is the type of every CAN interface, real or virtual, and the absence
 * of /sys/class/net/<if>/device would pass slcan, a real bus behind a serial adapter. Fails closed: an unknown
 * interface, a netlink error or a reply without IFLA_INFO_KIND is not a vcan. */
static bool is_vcan(const char *ifname)
{
    const unsigned idx = if_nametoindex(ifname);
    const int fd = (idx != 0u) ? socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) : -1;
    if (fd < 0) {
        return false;
    }
    struct {
        struct nlmsghdr  nh;
        struct ifinfomsg ifi;
    } req = {
        .nh = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)), .nlmsg_type = RTM_GETLINK,
               .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 1u},
        .ifi = {.ifi_family = AF_UNSPEC, .ifi_index = (int)idx},
    };
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    static union {
        struct nlmsghdr nh;
        uint8_t         buf[32768];
    } rsp;
    ssize_t n = -1;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof kernel) ==
        (ssize_t)req.nh.nlmsg_len) {
        n = recv(fd, rsp.buf, sizeof rsp.buf, 0);
    }
    close(fd);
    const size_t head = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    if (n < (ssize_t)head || rsp.nh.nlmsg_type != RTM_NEWLINK || rsp.nh.nlmsg_len < head ||
        rsp.nh.nlmsg_len > (size_t)n) {
        return false;
    }
    const size_t at = NLMSG_ALIGN(head);                     /* the link's attributes follow the ifinfomsg */
    const size_t at_len = rsp.nh.nlmsg_len > at ? rsp.nh.nlmsg_len - at : 0u;
    const struct rtattr *info = rta_find(rsp.buf + at, at_len, IFLA_LINKINFO);
    const struct rtattr *kind = (info != NULL) ? rta_find((const uint8_t *)RTA_DATA(info), RTA_PAYLOAD(info),
                                                          IFLA_INFO_KIND)
                                               : NULL;
    static const char vcan[] = "vcan";
    return kind != NULL && RTA_PAYLOAD(kind) >= sizeof vcan && memcmp(RTA_DATA(kind), vcan, sizeof vcan) == 0;
}

/* A CAN_RAW socket on the vcan ifname that hears only standard frames on the request ID, or -1 (logged). */
static int can_open(const char *ifname)
{
    if (!is_vcan(ifname)) {
        fprintf(stderr, "udsota_lite_server: %s is not a vcan interface; --can serves only on vcan\n", ifname);
        return -1;
    }
    const int fd = socket(PF_CAN, SOCK_RAW | SOCK_CLOEXEC, CAN_RAW);
    const struct can_filter flt = {.can_id = REQ_ID, .can_mask = CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG};
    struct sockaddr_can addr = {.can_family = AF_CAN, .can_ifindex = (int)if_nametoindex(ifname)};
    if (fd < 0 || setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, &flt, sizeof flt) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(stderr, "udsota_lite_server: no CAN_RAW socket on %s: %s\n", ifname, strerror(errno));
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    return fd;
}

/* One frame out on the socket; false when the write fails. */
static bool can_send(uint32_t id, const uint8_t *data, uint8_t size)
{
    struct can_frame cf = {.can_id = id & CAN_SFF_MASK, .can_dlc = size < 8u ? size : 8u};
    memcpy(cf.data, data, cf.can_dlc);
    return write(s_can_fd, &cf, sizeof cf) == (ssize_t)sizeof cf;
}
#endif

/* ---- isotp-c's platform hooks: stdout or the socket is the bus out ---- */

/* The FC after a request's --drop-fc-after'th CF is lost (reported sent), once. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    (void)arg;
    if (size >= 1u && (data[0] >> 4) == 3u && s_drop_fc_after != 0u && s_cfs == s_drop_fc_after) {
        s_drop_fc_after = 0u;
        fprintf(stderr, "udsota_lite_server: --drop-fc-after: losing the FC after CF %u\n", (unsigned)s_cfs);
        return ISOTP_RET_OK;
    }
#ifdef LITE_SOCKETCAN
    const bool sent = (s_can_fd >= 0) ? can_send(arbitration_id, data, size) : pipe_send(arbitration_id, data, size);
#else
    const bool sent = pipe_send(arbitration_id, data, size);
#endif
    if (!sent) {
        return ISOTP_RET_ERROR;          /* the client or the socket is gone */
    }
    log_frame("tx", arbitration_id, data, size);
    return ISOTP_RET_OK;
}

/* iso14229's S3, P2, 0x27 delays and reset timer on the clock the soak gate and the boot silence use, as esp_timer
 * on the device (UDS_CUSTOM_MILLIS; iso14229's own UDSMillis on UNIX is the wall clock, which NTP can step). */
uint32_t UDSMillis(void)
{
    return (uint32_t)mono_ms();
}

uint32_t isotp_user_get_us(void)
{
    return (uint32_t)mono_us();
}

void isotp_user_debug(const char *message, ...)
{
    va_list ap;
    va_start(ap, message);
    fputs("udsota_lite_server: isotp-c: ", stderr);
    vfprintf(stderr, message, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---- The app: udsota first, then its own services ---- */

/* udsota_cfg_t.gate: CONFIRM is refused for --soak-ms after each boot, as an app's soak before it calls itself
 * healthy. */
static uint8_t gate(void *ctx, udsota_op_t op)
{
    (void)ctx;
    return (op == UDSOTA_OP_CONFIRM && mono_ms() - s_boot_ms < s_soak_ms) ? UDS_NRC_ConditionsNotCorrect : 0u;
}

/* udsota_cfg_t.reset: iso14229 has sent the answer; the main loop restarts once UDSServerPoll returns. */
static void do_reset(void *ctx)
{
    (void)ctx;
    s_reset = true;
}

/* F1B0: SHA-256 of the schema byte, then each config DID's ID (big-endian), length and value, ascending, as
 * `config set --reset` recomputes it from the DIDs it reads. */
static void cfg_hash(uint8_t out[32])
{
    const uint8_t enc[] = {CFG_SCHEMA,
                           (uint8_t)(DID_MODE >> 8), (uint8_t)DID_MODE, 1u, C.applied.mode,
                           (uint8_t)(DID_TIMEOUT >> 8), (uint8_t)DID_TIMEOUT, 2u,
                           (uint8_t)(C.applied.timeout_ms >> 8), (uint8_t)C.applied.timeout_ms};
    (void)sha256_host(enc, sizeof enc, out);
}

/* 22: F191, the config DIDs (the values running), F1B0 and F1B2 (bit 0: values staged, bit 1: stored values that
 * apply at the next boot). Any other DID is 0x31. */
static UDSErr_t read_did(UDSServer_t *srv, UDSRDBIArgs_t *a)
{
    uint8_t b[32];
    uint16_t n = 1u;
    switch (a->dataId) {
    case DID_BOARD:
        return (UDSErr_t)a->copy(srv, BOARD_NAME, sizeof BOARD_NAME - 1u);
    case DID_MODE:
        b[0] = C.applied.mode;
        break;
    case DID_TIMEOUT:
        b[0] = (uint8_t)(C.applied.timeout_ms >> 8);
        b[1] = (uint8_t)C.applied.timeout_ms;
        n = 2u;
        break;
    case DID_CFG_HASH:
        cfg_hash(b);
        n = 32u;
        break;
    case DID_CFG_STATUS:
        b[0] = (uint8_t)((C.staged_mask != 0u ? 0x01u : 0u) |
                         (memcmp(&C.stored, &C.applied, sizeof C.stored) != 0 ? 0x02u : 0u));
        break;
    default:
        return UDS_NRC_RequestOutOfRange;
    }
    return (UDSErr_t)a->copy(srv, b, n);
}

/* 2E for a config DID, staged until the commit: the extended session (0x7F), its level's key (0x33), the length
 * (0x13) and the value's range (0x31). Any other DID is 0x31. */
static UDSErr_t write_did(const UDSServer_t *srv, const UDSWDBIArgs_t *a)
{
    if (a->dataId != DID_MODE && a->dataId != DID_TIMEOUT) {
        return UDS_NRC_RequestOutOfRange;
    }
    if (srv->sessionType != UDS_LEV_DS_EXTDS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (srv->securityLevel != LEVEL_EXT) {
        return UDS_NRC_SecurityAccessDenied;
    }
    if (a->len != (a->dataId == DID_MODE ? 1u : 2u)) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    if (a->dataId == DID_MODE) {
        if (a->data[0] > 2u) {
            return UDS_NRC_RequestOutOfRange;
        }
        C.staged.mode = a->data[0];
        C.staged_mask |= 0x01u;
        return UDS_PositiveResponse;
    }
    const uint16_t v = (uint16_t)((a->data[0] << 8) | a->data[1]);
    if (v < 1000u || v > 5000u) {
        return UDS_NRC_RequestOutOfRange;
    }
    C.staged.timeout_ms = v;
    C.staged_mask |= 0x02u;
    return UDS_PositiveResponse;
}

/* 31 01 RID_COMMIT: stores the staged values, which apply at the next boot, and answers status 00. The extended
 * session (0x7F), start only (0x12), its level's key (0x33), no option record (0x13), and something staged (0x24,
 * as after a session change). Any other RID is 0x31. */
static UDSErr_t routine(UDSServer_t *srv, UDSRoutineCtrlArgs_t *a)
{
    if (a->id != RID_COMMIT) {
        return UDS_NRC_RequestOutOfRange;
    }
    if (srv->sessionType != UDS_LEV_DS_EXTDS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (a->ctrlType != 0x01u) {
        return UDS_NRC_SubFunctionNotSupported;
    }
    if (srv->securityLevel != LEVEL_EXT) {
        return UDS_NRC_SecurityAccessDenied;
    }
    if (a->len != 0u) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    if (C.staged_mask == 0u) {
        return UDS_NRC_RequestSequenceError;
    }
    if ((C.staged_mask & 0x01u) != 0u) {
        C.stored.mode = C.staged.mode;
    }
    if ((C.staged_mask & 0x02u) != 0u) {
        C.stored.timeout_ms = C.staged.timeout_ms;
    }
    C.staged_mask = 0u;
    fprintf(stderr, "udsota_lite_server: config stored: mode %u, timeout_ms %u\n", C.stored.mode,
            C.stored.timeout_ms);
    static const uint8_t ok = 0x00u;
    return (UDSErr_t)a->copyStatusRecord(srv, &ok, 1u);
}

/* iso14229's fn: the updater first, then the app's own services. Staged config ends with its session. */
static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        if (ev == UDS_EVT_DiagSessCtrl && rc == UDS_PositiveResponse) {
            C.staged_mask = 0u;
        }
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent:
        return read_did(srv, arg);
    case UDS_EVT_WriteDataByIdent:
        return write_did(srv, arg);
    case UDS_EVT_RoutineCtrl:
        return routine(srv, arg);
    case UDS_EVT_DiagSessCtrl:
        return UDS_NRC_SubFunctionNotSupported;          /* a session the updater doesn't know */
    case UDS_EVT_SessionTimeout:
        C.staged_mask = 0u;
        return UDS_OK;
    case UDS_EVT_Err:
        return UDS_OK;
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

/* ---- Boot, the bus and the server loop ---- */

/* A boot: the slots, the stored config, then udsota and iso14229 from scratch, as app_main starts them. */
static void boot(void)
{
    static unsigned boots;
    lite_plat_boot(++boots);
    C.applied = C.stored;
    C.staged_mask = 0u;
    const udsota_cfg_t cfg = {.key_label = KEY_LABEL, .key_master = k_master, .key_master_len = sizeof k_master,
                              .gate = gate, .reset = do_reset, .allow_delta = !s_no_delta};
    udsota_test_reboot();
    if (udsota_init(&cfg) != 0) {
        fprintf(stderr, "udsota_lite_server: udsota_init failed\n");
    }
    (void)UDSServerInit(&s_srv);
    (void)UDSServerTpISOTpCInit(&s_tp, REQ_ID, RESP_ID, UDS_TP_NOOP_ADDR);
    s_srv.tp = &s_tp.hdl;
    s_srv.fn = on_event;
    s_srv.p2_ms = 5;  /* match the example; iso14229's 50 ms default is a rate limit, not a deadline. See README. */
    s_boot_ms = mono_ms();
    s_booting = false;
}

static int hexval(char ch)
{
    return (ch >= '0' && ch <= '9') ? ch - '0'
         : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10
         : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
                                    : -1;
}

/* One frame from the bus: on the request ID it goes to isotp-c, unless the server is restarting, and its CFs are
 * counted for --drop-fc-after; any other frame is dropped. */
static void on_frame(uint32_t id, const uint8_t *data, uint8_t len)
{
    if (id != REQ_ID || s_booting) {
        return;
    }
    const uint8_t pci = (len >= 1u) ? (uint8_t)(data[0] >> 4) : 0xFFu;
    s_cfs = (pci == 1u) ? 0u : (pci == 2u) ? s_cfs + 1u : s_cfs;
    log_frame("rx", id, data, len);
    isotp_on_can_message(&s_tp.phys_link, data, len);
}

/* One pipe line, `<3 hex digits>#<0 to 8 hex bytes>`, to on_frame; a malformed line is logged and dropped. */
static void on_line(const char *s)
{
    uint32_t id = 0;
    size_t digits = 0;
    uint8_t data[8], len = 0;
    for (; hexval(*s) >= 0; s++, digits++) {
        id = (id << 4) | (uint32_t)hexval(*s);
    }
    bool ok = (*s++ == '#') && digits == 3u;
    for (; ok && *s != '\0' && *s != '\r'; s += 2) {
        ok = len < 8u && hexval(s[0]) >= 0 && hexval(s[1]) >= 0;
        if (ok) {
            data[len++] = (uint8_t)((hexval(s[0]) << 4) | hexval(s[1]));
        }
    }
    if (!ok) {
        fprintf(stderr, "udsota_lite_server: dropped a malformed line\n");
        return;
    }
    on_frame(id, data, len);
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
            fprintf(stderr, "udsota_lite_server: dropped an over-long line\n");
        } else if (len > 0u) {
            on_line(line);
        }
        len = 0;
        too_long = false;
    }
}

#ifdef LITE_SOCKETCAN
/* Every frame the socket holds to on_frame; false when a read fails. */
static bool can_take(void)
{
    for (;;) {
        struct can_frame cf;
        const ssize_t n = recv(s_can_fd, &cf, sizeof cf, MSG_DONTWAIT);
        if (n < 0) {
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
        }
        if ((size_t)n == sizeof cf && (cf.can_id & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG)) == 0u &&
            cf.can_dlc <= 8u) {
            on_frame(cf.can_id & CAN_SFF_MASK, cf.data, cf.can_dlc);
        }
    }
}
#else
static bool can_take(void)
{
    return false;                                        /* never called: s_can_fd stays -1 */
}
#endif

/* Serves until stdin's EOF (in pipe mode) or a stop signal: frames into isotp-c, then UDSServerPoll and udsota_poll,
 * at least every millisecond. */
static int serve(void)
{
    boot();
    while (!s_stop) {
        struct pollfd p = {.fd = s_can_fd >= 0 ? s_can_fd : STDIN_FILENO, .events = POLLIN};
        const int r = poll(&p, 1, 1);
        if (r < 0 && errno != EINTR) {
            perror("udsota_lite_server: poll");
            return 1;
        }
        if (r > 0 && s_can_fd >= 0) {
            if (!can_take()) {
                perror("udsota_lite_server: recv");
                return 1;
            }
        } else if (r > 0) {
            char buf[4096];
            const ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
            if (n == 0) {
                return 0;
            }
            if (n < 0 && errno != EINTR && errno != EAGAIN) {
                perror("udsota_lite_server: read");
                return 1;
            }
            take(buf, n > 0 ? (size_t)n : 0u);
        }
        if (s_booting) {
            if (mono_ms() >= s_boot_until) {
                boot();
            }
            continue;
        }
        UDSServerPoll(&s_srv);
        udsota_poll(&s_srv);
        if (s_reset) {
            s_reset = false;
            s_booting = true;
            s_boot_until = mono_ms() + s_silence_ms;
            fprintf(stderr, "udsota_lite_server: restarting\n");
        }
    }
    return 0;
}

static void on_stop(int sig)
{
    (void)sig;
    s_stop = 1;
}

/* A decimal number up to max for option opt; exits 2 otherwise. */
static uint32_t number(const char *opt, const char *s, unsigned long max)
{
    char *end = NULL;
    errno = 0;
    const unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > max) {
        fprintf(stderr, "udsota_lite_server: %s takes a number up to %lu, not \"%s\"\n", opt, max, s);
        exit(2);
    }
    return (uint32_t)v;
}

/* The whole of path into *out (malloc'd); its length, or 0 when it cannot be read or is larger than a slot. */
static size_t read_file(const char *path, uint8_t **out)
{
    FILE *f = fopen(path, "rb");
    *out = malloc(LITE_SLOT_SIZE + 1u);
    const size_t n = (f != NULL && *out != NULL) ? fread(*out, 1, LITE_SLOT_SIZE + 1u, f) : 0u;
    if (f != NULL) {
        fclose(f);
    }
    return (n <= LITE_SLOT_SIZE) ? n : 0u;
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"image", required_argument, NULL, 'i'}, {"soak-ms", required_argument, NULL, 's'},
        {"boot-ms", required_argument, NULL, 'b'}, {"can", required_argument, NULL, 'c'},
        {"drop-fc-after", required_argument, NULL, 'd'}, {"no-delta", no_argument, NULL, 'n'},
        {NULL, 0, NULL, 0},
    };
    static const char usage[] = "usage: udsota_lite_server --image FILE [--can IFNAME] [--soak-ms N] [--boot-ms N] "
                                "[--drop-fc-after N] [--no-delta] [-v]\n";
    const char *image_path = NULL, *ifname = NULL;
    int c;
    while ((c = getopt_long(argc, argv, "v", opts, NULL)) != -1) {
        switch (c) {
        case 'i': image_path = optarg; break;
        case 's': s_soak_ms = number("--soak-ms", optarg, 600000u); break;
        case 'b': s_silence_ms = number("--boot-ms", optarg, 60000u); break;
        case 'c': ifname = optarg; break;
        case 'd': s_drop_fc_after = number("--drop-fc-after", optarg, 4095u); break;
        case 'n': s_no_delta = true; break;
        case 'v': s_verbose = true; break;
        default:  fputs(usage, stderr); return 2;
        }
    }
    if (image_path == NULL || optind != argc) {
        fputs(usage, stderr);
        return 2;
    }
    uint8_t *image = NULL;
    const size_t len = read_file(image_path, &image);
    const bool loaded = len != 0u && lite_plat_load(image, len);
    free(image);
    if (!loaded) {
        fprintf(stderr, "udsota_lite_server: %s is not an ESP-IDF app image that fits a slot\n", image_path);
        lite_plat_close();
        return 2;
    }
    if (ifname != NULL) {
#ifdef LITE_SOCKETCAN
        s_can_fd = can_open(ifname);
#else
        fputs("udsota_lite_server: built without SocketCAN (no linux/can/raw.h), so no --can\n", stderr);
#endif
        if (s_can_fd < 0) {
            lite_plat_close();
            return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    const struct sigaction stop = {.sa_handler = on_stop};   /* no SA_RESTART: poll returns, the loop sees s_stop */
    sigaction(SIGTERM, &stop, NULL);
    sigaction(SIGINT, &stop, NULL);
    fprintf(stderr, "udsota_lite_server: iso14229 %s, %s%s, IDs 0x%03X/0x%03X, soak %u ms, delta downloads %s\n",
            UDS_LIB_VERSION, ifname != NULL ? "SocketCAN on " : "pipe on stdin/stdout", ifname != NULL ? ifname : "",
            REQ_ID, RESP_ID, (unsigned)s_soak_ms, !UDSOTA_DELTA ? "not built" : s_no_delta ? "off" : "on");
    const int rc = serve();
    udsota_test_reboot();                                /* frees an inflater left open */
    lite_plat_close();
    if (s_can_fd >= 0) {
        close(s_can_fd);
    }
    return rc;
}
