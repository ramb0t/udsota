/* udsota boot: the resident bootloader core of a single-slot unit, on iso14229's server (see udsota_boot.h). One file:
 *   1. the build checks, the limits and the state
 *   2. the encodings: little-endian fields, the start count, and the CRC-32
 *   3. the image rules: what an image's header must say before anything is erased, and again in FF01
 *   4. the boot rules: what a boot does, from the reset cause, the keep words and the app's validity
 *   5. the clock, the buses and the transport: iso14229's hooks, and a UDSTp_t over one IsoTpLink
 *   6. the slot: the boot check and FF01's, and a 36's erase, program and compare
 *   7. the services: the DIDs, 34, 36, 37, the routines and iso14229's events
 *   8. the API: a boot, the poll with the session rules, and a received frame
 * iso14229 keeps ISO-TP, framing and timing; it is compiled as it is, with the definitions udsota_boot.h lists. */
#include "udsota_boot_internal.h"
#include <string.h>

/* ==== 1. The build checks, the limits and the state ==== */

/* Both are #ifndef-guarded in iso14229.h, so they are checked before it is included. */
#ifndef UDS_SERVER_RECV_BUF_SIZE
#error "define UDS_SERVER_RECV_BUF_SIZE build-wide: the longest 36 (udsota_boot.h)"
#elif UDS_SERVER_RECV_BUF_SIZE > 4095u
#error "UDS_SERVER_RECV_BUF_SIZE is at most 4095, ISO-TP's longest message"
#elif UDS_SERVER_RECV_BUF_SIZE < 2u + UDSOTA_BARE_HDR_LEN
#error "UDS_SERVER_RECV_BUF_SIZE - 2 must hold the image header, UDSOTA_BARE_HDR_LEN bytes, or every cfg is BAD_CFG"
#endif
#ifndef UDS_SERVER_SEND_BUF_SIZE
#error "define UDS_SERVER_SEND_BUF_SIZE build-wide (udsota_boot.h)"
#elif UDS_SERVER_SEND_BUF_SIZE < 35u
#error "UDS_SERVER_SEND_BUF_SIZE must hold F1F3's answer, 35 bytes"
#endif
#ifndef ISO_TP_FRAME_PADDING
#error "define ISO_TP_FRAME_PADDING build-wide (udsota_boot.h)"
#endif
#include "udsota.h"        /* iso14229.h, and UDSOTA_VERSION for F180; nothing else of the ESP-IDF component */
#if UDS_SYS != UDS_SYS_CUSTOM
#error "build udsota_boot.c and iso14229.c with UDS_SYS=UDS_SYS_CUSTOM: the core defines UDSMillis"
#endif
#ifndef UDS_TP_ISOTP_C
#error "iso14229 without isotp-c: build it with UDS_SYS=UDS_SYS_CUSTOM and without UDS_AUTOSELECT_TP=0"
#endif
#if ISO_TP_MAX_CAN_FRAME_SIZE != 8
#error "the core speaks classic CAN: leave ISO_TP_MAX_CAN_FRAME_SIZE at 8"
#endif

#define BLOCK(off)     (UDSOTA_BARE_HDR_DESC_OFFSET + (off))   /* a descriptor-block offset in the header */
#define P2_MS          5u      /* iso14229's spacing of answers, set after each UDSServerInit */
#define P2_STAR_MS     5000u   /* the 10 answers' P2*, covering the handover's reboot */
#define IDLE_MS        5100u   /* the idle exit, and S3: from the last tester frame, or the last 10 or 3E served */
#define RESET_DELAY_MS 60u     /* from the poll that served 11 01 or F001 to the reset */
#define CRC_PIECE      4096u   /* the slot's CRC runs in pieces this long, with the watchdog reloaded between */
#define DATA_MAX       (UDS_SERVER_RECV_BUF_SIZE - 2u)   /* a 36's data */

/* What the core is doing. LISTENING and the three after it serve; S3's expiry can end any of them. */
enum {
    STOPPED = 0,   /* BAD_CFG, or port_reset or port_start_app returned: the poll only reloads the watchdog */
    STARTING,      /* START_APP: the next poll starts the app */
    LISTENING,     /* serving, with no deadline of the core's own */
    WINDOW,        /* serving in the power-up window, which ends at since + window_ms */
    TESTER,        /* serving with B.bus locked, the others stopped: the idle exit comes at since + IDLE_MS */
    S3_EXPIRED,    /* serving, and S3 expired in this poll, which ends in a session exit */
};
/* A download: OPEN from its 34 to its end, ENDED once its 37 passed, VERIFIED once FF01 passed, until the next 34. */
enum { DL_NONE = 0, DL_OPEN, DL_ENDED, DL_VERIFIED };

/* Every piece of the core's state. udsota_boot_init clears it all, so nothing relies on a zeroed .bss. */
static struct {
    const udsota_boot_cfg_t *cfg;
    uint8_t  state;                /* the enum above */
    uint32_t since;                /* ms: when the window opened, or the last tester frame */
    bool     reset;                /* 11 01 or F001 served at reset_at (ms): the reset follows the delay */
    uint32_t reset_at;
    uint32_t last_us, ms, rem_us;  /* UDSMillis: its last sample, the count, the microseconds not yet counted */

    bool     app_valid;            /* the valid app (udsota_boot_internal.h) */
    uint8_t  count;                /* the start count after the boot rules, at init or a session exit */

    uint8_t  bus;                  /* TESTER's, else the bus of the request in flight (busy()) or of the last frame */
    bool     replay;               /* the handover's 10 02, for iso14229's first receive */

    uint8_t  dl;                   /* DL_* */
    uint8_t  last_reason;          /* F1F1 byte 0 */
    uint32_t announced, received;  /* the 34's memorySize; the data bytes the 36s carried (F1F1 bytes 1-4) */

    UDSServer_t srv;
    struct {
        UDSTp_t    hdl;            /* iso14229's handle on this transport */
        IsoTpLink  link;
        uint8_t    rx[UDS_SERVER_RECV_BUF_SIZE];
        uint8_t    tx[UDS_SERVER_SEND_BUF_SIZE];
    } tp;
} B;

/* ==== 2. The encodings ==== */

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* The start count word 2 holds after the boot rules: 0 after a power-on or a pin reset, or without the marker. */
static uint8_t start_count_of(uint16_t word, udsota_boot_reset_t cause)
{
    if (cause != UDSOTA_BOOT_RESET_OTHER || (word >> UDSOTA_START_COUNT_MARKER_SHIFT) != UDSOTA_START_COUNT_MARKER) {
        return 0u;
    }
    return (uint8_t)(word & UDSOTA_START_COUNT_MASK);
}

/* zlib's CRC-32 a nibble at a time: one test a byte, and the table in RAM (.data), so no table read waits on flash
 * wait states; volatile keeps it there, where a table never written would be moved to flash. */
static volatile uint32_t crc_nibble[16] = {
    0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu, 0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
    0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu, 0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu,
};

uint32_t udsota_boot_crc32(uint32_t crc, const void *data, uint32_t len)
{
    const uint8_t *p = data;
    const uint8_t *const end = p + len;
    crc = ~crc;
    if (p != end) {
        do {
            crc ^= *p++;
            crc = (crc >> 4) ^ crc_nibble[crc & 0x0Fu];
            crc = (crc >> 4) ^ crc_nibble[crc & 0x0Fu];
        } while (p != end);
    }
    return ~crc;
}

/* s's length, at most max: strnlen, which a strict C11 libc need not declare. */
static uint16_t str_len(const char *s, uint16_t max)
{
    uint16_t n = 0;
    while (n < max && s[n] != '\0') {
        n++;
    }
    return n;
}

/* ==== 3. The image rules ==== */

/* A header's 32-byte project field against product: the same characters, then a NUL, or no NUL when product fills
 * the field, as udsota.c and the client compare it. */
static bool project_is(const uint8_t *field, const char *product)
{
    for (size_t i = 0; i < 32u; i++) {
        if (field[i] != (uint8_t)product[i]) {
            return false;
        }
        if (product[i] == '\0') {
            return true;
        }
    }
    return product[32] == '\0';
}

/* The rules on the header's own fields, the first three of the image rules: UDSOTA_DL_OK, BAD_HEADER or TOO_BIG. The
 * boot check runs these alone, with its image_length as mem_size. */
static udsota_reason_t header_rules(const udsota_boot_cfg_t *cfg, const uint8_t *hdr, uint32_t mem_size)
{
    if (le32(hdr) != UDSOTA_BARE_HDR_MAGIC || le16(hdr + 4) < 1u ||
        (le16(hdr + 6) & UDSOTA_BARE_HDR_FLAGS_MUST) != 0u) {
        return UDSOTA_DL_BAD_HEADER;
    }
    const uint32_t length = le32(hdr + UDSOTA_BARE_HDR_LENGTH_OFFSET);
    if (length > cfg->slot_size) {
        return UDSOTA_DL_TOO_BIG;
    }
    if (length != mem_size || (length & 3u) != 0u || length < UDSOTA_BARE_HDR_LEN ||
        length - UDSOTA_BARE_HDR_LEN < cfg->image_header_offset) {
        return UDSOTA_DL_BAD_HEADER;
    }
    return UDSOTA_DL_OK;
}

udsota_reason_t udsota_boot_image_rules(const udsota_boot_cfg_t *cfg, const uint8_t *hdr, uint32_t hdr_len,
                                        uint32_t mem_size)
{
    if (hdr_len < UDSOTA_BARE_HDR_LEN) {
        return UDSOTA_DL_BAD_HEADER;
    }
    const udsota_reason_t why = header_rules(cfg, hdr, mem_size);
    if (why != UDSOTA_DL_OK) {
        return why;
    }
    if (!project_is(hdr + BLOCK(UDSOTA_BARE_PROJECT_OFFSET), cfg->product)) {
        return UDSOTA_DL_BAD_PROJECT;
    }
    const uint8_t *d = hdr + BLOCK(0u);
    if (le32(d) != UDSOTA_IMG_DESC_MAGIC || le16(d + 4) == 0u || d[6] != cfg->hw_id) {
        return UDSOTA_DL_BAD_BOARD;
    }
    if (d[7] != cfg->layout_id) {
        return UDSOTA_DL_BAD_LAYOUT;
    }
    if (le16(d + 8) != cfg->request_id || le16(d + 10) != cfg->response_id) {
        return UDSOTA_DL_BAD_DIAG_IDS;
    }
    return UDSOTA_DL_OK;
}

/* ==== 4. The boot rules ==== */

udsota_boot_decision_t udsota_boot_decide(const udsota_boot_cfg_t *cfg, const udsota_boot_inputs_t *in,
                                          uint8_t *count_out)
{
    const uint8_t count = start_count_of(in->count_word, in->cause);
    *count_out = count;
    if (in->handover_ok && in->handover >= 1u && in->handover <= cfg->buses) {
        return UDSOTA_BOOT_DECIDE_HANDOVER;
    }
    if (!in->app_valid) {
        return UDSOTA_BOOT_DECIDE_NO_APP;
    }
    if (count >= cfg->hold_after_starts) {
        return UDSOTA_BOOT_DECIDE_HELD;
    }
    if (in->cause == UDSOTA_BOOT_RESET_POWER_ON && cfg->window_ms != 0u) {
        return UDSOTA_BOOT_DECIDE_WINDOW;
    }
    return UDSOTA_BOOT_DECIDE_START_APP;
}

/* ==== 5. The clock, the buses and the transport ==== */

/* udsota_boot_port_us's differences, the remainder carried, as milliseconds that wrap at 2^32 (udsota_boot.h). */
uint32_t UDSMillis(void)
{
    const uint32_t us = udsota_boot_port_us();
    const uint32_t d = us - B.last_us;
    B.last_us = us;
    B.ms += d / 1000u;
    B.rem_us += d % 1000u;
    if (B.rem_us >= 1000u) {
        B.rem_us -= 1000u;
        B.ms++;
    }
    return B.ms;
}

uint32_t isotp_user_get_us(void) { return udsota_boot_port_us(); }

void isotp_user_debug(const char *message, ...) { (void)message; }

/* Every frame isotp-c sends, an answer's or a flow control, goes on the bus of the request in flight. arg is
 * iso14229's forced ISO_TP_USER_SEND_CAN_ARG, unused. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    (void)arg;
    return udsota_boot_port_can_send(B.bus, arbitration_id, data, size) ? ISOTP_RET_OK : ISOTP_RET_ERROR;
}

/* A request is in flight from its first frame until its whole answer has been handed to can_send: while isotp-c
 * receives or holds it, iso14229 serves it, or isotp-c sends the answer. */
static bool busy(void)
{
    return B.tp.link.receive_status != ISOTP_RECEIVE_STATUS_IDLE || B.srv.requestInProgress ||
           B.tp.link.send_status == ISOTP_SEND_STATUS_INPROGRESS;
}

/* Between two port calls inside one call to the core: the watchdog, and the clock that a short counter extends. */
static void tick(void)
{
    udsota_boot_port_watchdog_reload();
    (void)UDSMillis();
}

/* Every bus but keep (0 for none). */
static void stop_buses(uint8_t keep)
{
    for (uint8_t b = 1; b <= B.cfg->buses; b++) {
        if (b != keep) {
            udsota_boot_port_can_stop(b);
            tick();
        }
    }
}

/* Every bus; one that does not start is absent. */
static void listen_all(void)
{
    for (uint8_t b = 1; b <= B.cfg->buses; b++) {
        (void)udsota_boot_port_can_start(b, B.cfg->request_id);
        tick();
    }
}

static UDSErr_t tp_send(UDSTp_t *hdl, const uint8_t *buf, size_t len, const UDSSDU_t *info)
{
    (void)hdl;
    (void)info;
    return (isotp_send(&B.tp.link, buf, (uint32_t)len) == ISOTP_RET_OK) ? UDS_OK : UDS_ERR_TPORT;
}

/* The next request: the handover's 10 02 once, then what isotp-c has reassembled. Every request is physical, as
 * UDSServerInit left r.info. */
static UDSErr_t tp_recv(UDSTp_t *hdl, uint8_t *buf, size_t bufsiz, size_t *recvlen, UDSSDU_t *info)
{
    uint32_t n = 0;
    (void)hdl;
    (void)info;
    if (B.replay) {
        B.replay = false;
        buf[0] = 0x10u;
        buf[1] = UDS_LEV_DS_PRGS;
        n = 2u;
    } else if (isotp_receive(&B.tp.link, buf, (uint32_t)bufsiz, &n) != ISOTP_RET_OK) {
        n = 0u;
    }
    *recvlen = n;
    return UDS_OK;
}

/* isotp-c's timers and consecutive frames. An answer lost partway (a consecutive frame not sent, no flow control within
 * N_Bs) is simply lost: unlike UDSTpISOTpC_t this reports no error, which the core would ignore anyway. */
static UDSErr_t tp_poll(UDSTp_t *hdl)
{
    (void)hdl;
    isotp_poll(&B.tp.link);
    return UDS_OK;
}

static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg);

/* iso14229 from scratch, as each boot and each return to listening has it, with the state the core writes. */
static void server_init(void)
{
    (void)UDSServerInit(&B.srv);
    B.srv.fn = on_event;
    B.srv.tp = &B.tp.hdl;
    B.srv.p2_ms = P2_MS;
    B.srv.s3_ms = IDLE_MS;
    B.srv.p2_timer = UDSMillis() + P2_MS;
    B.tp.hdl.send = tp_send;
    B.tp.hdl.recv = tp_recv;
    B.tp.hdl.poll = tp_poll;
    isotp_init_link(&B.tp.link, B.cfg->response_id, B.tp.tx, sizeof B.tp.tx, B.tp.rx, sizeof B.tp.rx);
}

/* ==== 6. The slot ==== */

/* The image in the slot: UDSOTA_DL_OK, or why not. For FF01 the image rules against the download's memorySize, else
 * the boot check's header rules; then the CRC over [0, image_length) without the crc32 field, in pieces. */
static udsota_reason_t slot_check(bool ff01)
{
    const udsota_boot_cfg_t *cfg = B.cfg;
    const uint8_t *const slot = udsota_boot_port_slot();
    const uint8_t *hdr = slot + cfg->image_header_offset;
    const uint32_t len = le32(hdr + UDSOTA_BARE_HDR_LENGTH_OFFSET);
    const udsota_reason_t why = ff01 ? udsota_boot_image_rules(cfg, hdr, UDSOTA_BARE_HDR_LEN, B.announced)
                                     : header_rules(cfg, hdr, len);
    if (why != UDSOTA_DL_OK) {
        return why;
    }
    const uint32_t crc_at = cfg->image_header_offset + UDSOTA_BARE_HDR_CRC_OFFSET;
    uint32_t crc = 0, off = 0;
    while (off < len) {
        if (off == crc_at) {
            off += 4u;
            continue;
        }
        const uint32_t end = (off < crc_at) ? crc_at : len;
        const uint32_t n = (end - off < CRC_PIECE) ? end - off : CRC_PIECE;
        crc = udsota_boot_crc32(crc, slot + off, n);
        tick();
        off += n;
    }
    return (crc == le32(hdr + UDSOTA_BARE_HDR_CRC_OFFSET)) ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}

/* One 36's flash work at off: the erase units that start in its range, then n bytes programmed and compared. */
static bool write_block(uint32_t off, const uint8_t *data, uint32_t n)
{
    bool ok = udsota_boot_port_flash_erase(off, n);
    tick();
    ok = ok && udsota_boot_port_flash_program(off, data, n);
    tick();
    return ok && memcmp(udsota_boot_port_slot() + off, data, n) == 0;
}

/* ==== 7. The services ==== */

/* The open download ends, and F1F1 names why. One that has already ended keeps its reason, so a later ABORTED never
 * overwrites an image rule's or a flash failure's. */
static void dl_end(uint8_t why)
{
    if (B.dl == DL_OPEN) {
        B.last_reason = why;
        B.dl = DL_NONE;
    }
}

/* iso14229 ends a transfer without an event (0x24, 0x71, a 36 shorter than 2 bytes): noticed after every poll. */
static void xfer_check(void)
{
    if (B.dl == DL_OPEN && !B.srv.xferIsActive) {
        dl_end(UDSOTA_DL_ABORTED);
    }
}

/* The unit holds: the start count the last decision used is at the threshold. */
static bool held(void) { return B.count >= B.cfg->hold_after_starts; }

/* The valid app's 32-byte descriptor-block field at off, or NULL without a valid app. */
static const uint8_t *installed(uint32_t off)
{
    return B.app_valid ? udsota_boot_port_slot() + B.cfg->image_header_offset + BLOCK(off) : NULL;
}

/* 11 01 and F001: the start count cleared, then the reset RESET_DELAY_MS after the first such poll, which gives the
 * answer time to leave (udsota_boot_poll); a repeat does not postpone it. */
static UDSErr_t leave(void)
{
    udsota_boot_port_keep_write(UDSOTA_KEEP_WORD_COUNT, UDSOTA_START_COUNT_CLEAR);
    if (!B.reset) {
        B.reset = true;
        B.reset_at = UDSMillis();
    }
    return UDS_PositiveResponse;
}

static UDSErr_t read_did(UDSServer_t *srv, const UDSRDBIArgs_t *a)
{
    static const uint8_t k_zeros[32];
    uint8_t b[16];
    const uint8_t *p = b;
    uint16_t n;
    switch (a->dataId) {
    case UDSOTA_DID_BOOT_VERSION: {
        const char *v = B.cfg->boot_version;
        const UDSErr_t rc = (UDSErr_t)a->copy(srv, v, (uint16_t)strlen(v));
        if (rc != UDS_PositiveResponse) {
            return rc;
        }
        p = (const uint8_t *)" udsota/" UDSOTA_VERSION;
        n = (uint16_t)(sizeof " udsota/" UDSOTA_VERSION - 1u);
        break;
    }
    case UDSOTA_DID_ACTIVE_SESSION:
        b[0] = srv->sessionType;
        n = 1u;
        break;
    case UDSOTA_DID_SW_VERSION:
        p = installed(UDSOTA_BARE_VERSION_OFFSET);
        n = p != NULL ? str_len((const char *)p, 32u) : 0u;
        if (n == 0u) {                                   /* no valid app, or one stamped with no version */
            p = (const uint8_t *)"0.0.0";
            n = 5u;
        }
        break;
    case UDSOTA_DID_SERIAL:
        n = (uint16_t)udsota_boot_port_device_id(b);
        if (n > 16u) {                                   /* a port bug, kept off the bus as stack bytes */
            n = 16u;
        }
        break;
    case UDSOTA_DID_STATUS:                              /* one slot: running and boot slot 0, no other slot */
        memset(b, 0, 16u);
        b[1] = B.app_valid ? 3u : 0u;
        b[15] = held() ? UDSOTA_STATUS_BOOT_HELD : 0u;
        n = 16u;
        break;
    case UDSOTA_DID_RESULT:
        b[0] = B.last_reason;
        b[1] = (uint8_t)(B.received >> 24);
        b[2] = (uint8_t)(B.received >> 16);
        b[3] = (uint8_t)(B.received >> 8);
        b[4] = (uint8_t)B.received;
        n = 5u;
        break;
    case UDSOTA_DID_RUNNING_SHA:
        p = installed(UDSOTA_BARE_IMAGE_ID_OFFSET);
        if (p == NULL) {
            p = k_zeros;
        }
        n = 32u;
        break;
    default:                                             /* F1F4 too: only the app answers it */
        return UDS_NRC_RequestOutOfRange;
    }
    return (UDSErr_t)a->copy(srv, p, n);
}

/* 34: in programming, an ALFID whose nibbles are each 1 to 4, address 0, DFI 00, and a memorySize that is the
 * container's multiple of 4 from the header's end up to the slot; any other leaves F1F1 as it was. */
static UDSErr_t request_download(const UDSServer_t *srv, UDSRequestDownloadArgs_t *a)
{
    const udsota_boot_cfg_t *cfg = B.cfg;
    const uint8_t alfid = srv->r.recv_buf[2];            /* not in the event's arguments; iso14229 allows 1 to 8 */
    const uint8_t size_len = alfid >> 4, addr_len = alfid & 0x0Fu;
    if (srv->sessionType != UDS_LEV_DS_PRGS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (size_len < 1u || size_len > 4u || addr_len < 1u || addr_len > 4u || a->addr != 0u ||
        a->dataFormatIdentifier != UDSOTA_DL_DFI || a->size < cfg->image_header_offset + UDSOTA_BARE_HDR_LEN ||
        a->size > cfg->slot_size || (a->size & 3u) != 0u) {
        return UDS_NRC_RequestOutOfRange;
    }
    B.dl = DL_OPEN;
    B.last_reason = UDSOTA_DL_OK;
    B.announced = (uint32_t)a->size;
    B.received = 0u;
    a->maxNumberOfBlockLength = UDS_SERVER_RECV_BUF_SIZE;
    return UDS_PositiveResponse;
}

/* 36: its length (some data, and every block but the last a multiple of the write unit), the image rules on the first
 * block before any erase, then the block, its tail padded to the unit with 0xFF in iso14229's receive buffer, which
 * has room for it. iso14229 has checked the counter and the overrun, and the transport takes no block longer than
 * UDS_SERVER_RECV_BUF_SIZE. */
static UDSErr_t transfer_data(UDSServer_t *srv, const UDSTransferDataArgs_t *a)
{
    const udsota_boot_cfg_t *cfg = B.cfg;
    const uint32_t len = a->len, at = B.received, unit = cfg->slot_write_unit;
    if (len == 0u || (at + len != B.announced && (len & (unit - 1u)) != 0u)) {
        dl_end(UDSOTA_DL_ABORTED);
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    uint8_t *data = &srv->r.recv_buf[2];                 /* a->data, past the SID and the counter, writable */
    if (at == 0u) {
        const uint32_t off = cfg->image_header_offset;
        const uint32_t hdr_len = (len > off) ? len - off : 0u;
        const udsota_reason_t why = udsota_boot_image_rules(cfg, data + off, hdr_len, B.announced);
        if (why != UDSOTA_DL_OK) {
            dl_end(why);
            return UDS_NRC_RequestOutOfRange;
        }
        B.app_valid = false;                             /* the first erase */
    }
    const uint32_t n = (len + unit - 1u) & ~(uint32_t)(unit - 1u);
    memset(data + len, 0xFF, n - len);
    if (!write_block(at, data, n)) {
        dl_end(UDSOTA_DL_FLASH_ERROR);
        return UDS_NRC_GeneralProgrammingFailure;
    }
    B.received = at + len;
    return UDS_PositiveResponse;
}

/* 37: no data, and once every announced byte has arrived. */
static UDSErr_t transfer_exit(const UDSRequestTransferExitArgs_t *a)
{
    if (a->len != 0u || B.received != B.announced) {
        dl_end(UDSOTA_DL_ABORTED);
        return (a->len != 0u) ? UDS_NRC_IncorrectMessageLengthOrInvalidFormat : UDS_NRC_RequestSequenceError;
    }
    B.dl = DL_ENDED;
    return UDS_PositiveResponse;
}

/* 31: FF01 and F001, in programming, start only and with no option record. FF01 after a 37 runs the image rules on
 * the slot's bytes, then the CRC; its status is also F1F1 byte 0, and a pass answers 00 again until the next 34. */
static UDSErr_t routine(UDSServer_t *srv, UDSRoutineCtrlArgs_t *a)
{
    if (srv->sessionType != UDS_LEV_DS_PRGS) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (a->id != UDSOTA_RID_CHECK_PROG_DEPS && a->id != UDSOTA_RID_ACTIVATE_IMAGE) {
        return UDS_NRC_RequestOutOfRange;
    }
    if (a->ctrlType != UDS_LEV_RCTP_STR) {
        return UDS_NRC_SubFunctionNotSupported;
    }
    if (a->len != 0u) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    if (a->id == UDSOTA_RID_ACTIVATE_IMAGE) {
        return (B.dl == DL_VERIFIED) ? leave() : UDS_NRC_RequestSequenceError;
    }
    if (B.dl == DL_ENDED) {
        B.last_reason = (uint8_t)slot_check(true);
        B.app_valid = (B.last_reason == UDSOTA_DL_OK);
        B.dl = B.app_valid ? DL_VERIFIED : DL_NONE;
    } else if (B.dl != DL_VERIFIED) {
        return UDS_NRC_RequestSequenceError;
    }
    return (UDSErr_t)a->copyStatusRecord(srv, &B.last_reason, 1u);
}

/* iso14229's events. Its own refusals of a malformed or untimely request come first; every event the core does not
 * serve answers 0x11, never iso14229's default positive answer. */
static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    const bool prog = (srv->sessionType == UDS_LEV_DS_PRGS);
    switch (ev) {
    case UDS_EVT_Err:                                    /* a lost answer: the next request is still served */
    case UDS_EVT_DoScheduledReset:                       /* 11 01 resets on the core's own delay */
        return UDS_PositiveResponse;
    case UDS_EVT_SessionTimeout:
        dl_end(UDSOTA_DL_ABORTED);
        srv->xferIsActive = false;
        B.state = S3_EXPIRED;
        return UDS_PositiveResponse;
    case UDS_EVT_DiagSessCtrl: {
        UDSDiagSessCtrlArgs_t *a = arg;
        if (a->type != UDS_LEV_DS_DS && a->type != UDS_LEV_DS_PRGS) {
            return UDS_NRC_SubFunctionNotSupported;
        }
        a->p2_star_ms = P2_STAR_MS;
        dl_end(UDSOTA_DL_ABORTED);
        srv->xferIsActive = false;
        return UDS_PositiveResponse;
    }
    case UDS_EVT_EcuReset:
        return !prog                                                    ? UDS_NRC_ServiceNotSupportedInActiveSession
             : (((UDSECUResetArgs_t *)arg)->type != UDS_LEV_RT_HR)      ? UDS_NRC_SubFunctionNotSupported
                                                                        : leave();
    case UDS_EVT_ReadDataByIdent:
        return read_did(srv, arg);
    case UDS_EVT_SecAccessRequestSeed:                   /* 27 is not served */
    case UDS_EVT_SecAccessValidateKey:
        return prog ? UDS_NRC_ServiceNotSupported : UDS_NRC_ServiceNotSupportedInActiveSession;
    case UDS_EVT_RoutineCtrl:
        return routine(srv, arg);
    case UDS_EVT_RequestDownload:
        return request_download(srv, arg);
    case UDS_EVT_TransferData:
        return transfer_data(srv, arg);
    case UDS_EVT_RequestTransferExit:
        return transfer_exit(arg);
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

/* ==== 8. The API ==== */

/* Every invariant udsota_boot_init holds cfg to (udsota_boot.h). */
static bool cfg_ok(const udsota_boot_cfg_t *c)
{
    if (c == NULL) {
        return false;
    }
    const uint32_t unit = c->slot_write_unit;
    return c->request_id <= 0x7FFu && c->response_id <= 0x7FFu && c->request_id != c->response_id &&
           c->buses >= 1u && c->buses <= 15u && c->product != NULL && str_len(c->product, 33u) <= 32u &&
           c->boot_version != NULL && c->hold_after_starts != 0u && unit != 0u && (unit & (unit - 1u)) == 0u &&
           (c->slot_size & (unit - 1u)) == 0u && (DATA_MAX & (unit - 1u)) == 0u &&
           c->image_header_offset <= DATA_MAX - UDSOTA_BARE_HDR_LEN &&
           c->slot_size >= c->image_header_offset + UDSOTA_BARE_HDR_LEN;
}

/* The start of the app: the start count up by one (below 255, since it was below hold_after_starts), the buses
 * stopped, the watchdog started. If start_app returns, the core is stopped. */
static void start_app(void)
{
    udsota_boot_port_keep_write(UDSOTA_KEEP_WORD_COUNT, UDSOTA_START_COUNT_WORD(B.count + 1u));
    stop_buses(0u);
    if (B.cfg->watchdog_ms != 0u) {
        udsota_boot_port_watchdog_start(B.cfg->watchdog_ms);
    }
    B.state = STOPPED;
    udsota_boot_port_start_app();
}

static void reset(void)
{
    B.state = STOPPED;
    udsota_boot_port_reset();
}

/* S3's expiry and the idle exit: a reset when the boot rules would start the app, else listening again on every
 * bus, with iso14229 from scratch, no lock and no window. */
static void session_exit(void)
{
    const udsota_boot_inputs_t in = {.count_word = udsota_boot_port_keep_read(UDSOTA_KEEP_WORD_COUNT),
                                     .cause = UDSOTA_BOOT_RESET_OTHER, .app_valid = B.app_valid};
    if (udsota_boot_decide(B.cfg, &in, &B.count) == UDSOTA_BOOT_DECIDE_START_APP) {
        reset();
        return;
    }
    stop_buses(0u);
    B.state = LISTENING;
    listen_all();
    server_init();
}

udsota_boot_decision_t udsota_boot_init(const udsota_boot_cfg_t *cfg)
{
    memset(&B, 0, sizeof B);
    if (!cfg_ok(cfg)) {
        udsota_boot_port_watchdog_reload();
        return UDSOTA_BOOT_DECIDE_BAD_CFG;
    }
    B.cfg = cfg;
    B.last_us = udsota_boot_port_us();
    udsota_boot_inputs_t in = {.cause = udsota_boot_port_reset_cause()};
    const uint16_t mark = udsota_boot_port_keep_read(UDSOTA_KEEP_WORD_MARK);
    in.handover = udsota_boot_port_keep_read(UDSOTA_KEEP_WORD_HANDOVER);
    if (mark == UDSOTA_HANDOVER_MARK) {
        udsota_boot_port_keep_write(UDSOTA_KEEP_WORD_MARK, 0u);
        udsota_boot_port_keep_write(UDSOTA_KEEP_WORD_HANDOVER, 0u);
        in.handover_ok = udsota_boot_port_keep_read(UDSOTA_KEEP_WORD_MARK) != UDSOTA_HANDOVER_MARK;
    }
    in.app_valid = B.app_valid = (slot_check(false) == UDSOTA_DL_OK);
    in.count_word = udsota_boot_port_keep_read(UDSOTA_KEEP_WORD_COUNT);
    udsota_boot_decision_t d = udsota_boot_decide(cfg, &in, &B.count);
    if (d == UDSOTA_BOOT_DECIDE_HANDOVER) {
        B.bus = (uint8_t)in.handover;
        if (udsota_boot_port_can_start(B.bus, cfg->request_id)) {
            B.replay = true;
        } else {
            in.handover_ok = false;
            d = udsota_boot_decide(cfg, &in, &B.count);
        }
        tick();
    }
    udsota_boot_port_keep_write(UDSOTA_KEEP_WORD_COUNT, UDSOTA_START_COUNT_WORD(B.count));
    if (d == UDSOTA_BOOT_DECIDE_START_APP) {
        B.state = STARTING;
        return d;
    }
    if (d != UDSOTA_BOOT_DECIDE_HANDOVER) {
        listen_all();
    }
    server_init();
    B.since = UDSMillis();                               /* the window's start, or the replayed 10 02's time */
    B.state = (d == UDSOTA_BOOT_DECIDE_HANDOVER) ? TESTER : (d == UDSOTA_BOOT_DECIDE_WINDOW) ? WINDOW : LISTENING;
    return d;
}

/* iso14229 compares its deadlines with UDSTimeAfter, a 32-bit difference read as expired when it is 1 to 2^31 - 1, so
 * a deadline that expired 2^31 ms (24.86 days) ago reads as pending again until 2^32 ms. Its P2 timer would then hold
 * the next answer, and its two 0x27 delays answer 27 with 0x37 or 0x36. Run every poll, this moves each one that has
 * expired to now - 1, which still reads as expired, so none ever gets old enough to wrap; a pending one is left
 * alone. The other deadlines are set afresh before each use. */
static void age_timers(uint32_t now)
{
    uint32_t *const timers[] = {&B.srv.p2_timer, &B.srv.sec_access_boot_delay_timer,
                                &B.srv.sec_access_auth_fail_timer};
    for (size_t i = 0; i < sizeof timers / sizeof timers[0]; i++) {
        if ((uint32_t)(now - *timers[i] - 1u) < 0x7FFFFFFFu) {
            *timers[i] = now - 1u;
        }
    }
}

void udsota_boot_poll(void)
{
    udsota_boot_port_watchdog_reload();
    if (B.state == STARTING) {
        start_app();
        return;
    }
    if (B.state == STOPPED) {
        return;
    }
    UDSServerPoll(&B.srv);
    const uint32_t now = UDSMillis();
    age_timers(now);
    xfer_check();
    if (B.reset) {
        if (now - B.reset_at >= RESET_DELAY_MS) {
            reset();
        }
    } else if (B.state == WINDOW && now - B.since >= B.cfg->window_ms) {
        if (B.app_valid && B.srv.sessionType == UDS_LEV_DS_DS) {
            start_app();
        } else {
            B.state = LISTENING;                         /* a tester at work without a tester frame */
        }
    } else if (B.state == S3_EXPIRED || (B.state == TESTER && B.srv.sessionType == UDS_LEV_DS_DS && !busy() &&
                                         now - B.since >= IDLE_MS)) {
        session_exit();
    }
}

void udsota_boot_rx(uint8_t bus, uint32_t id, const uint8_t *data, uint8_t len)
{
    if (B.state == STOPPED || B.state == STARTING || bus == 0u || bus > B.cfg->buses || len > 8u ||
        id != B.cfg->request_id || ((B.state == TESTER || busy()) && bus != B.bus)) {
        return;
    }
    const uint32_t now = UDSMillis();
    B.bus = bus;
    if (len >= 3u && data[0] == 0x02u &&
        ((data[1] == 0x10u && data[2] == UDS_LEV_DS_PRGS) || (data[1] == 0x3Eu && (data[2] & 0x7Fu) == 0u))) {
        if (B.state != TESTER) {                         /* a tester frame: 02 10 02, 02 3E 00 or 02 3E 80 */
            stop_buses(bus);
        }
        B.state = TESTER;
        B.since = now;
    }
    isotp_on_can_message(&B.tp.link, data, len);
}
