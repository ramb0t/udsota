/* udsota's ISO-TP transport; see udsota_isotp.h. Portable: state lives in udsota_isotp_t, not in
 * file statics, the server's interlocks are reached through udsota_fc_check (which
 * asks the gate), the caller refreshes nothing, and an FC the bus refuses is parked and retried from
 * udsota_isotp_service() for cfg.fc_retry_ms instead of sleeping in the send hook. */
#include <stddef.h>
#include <string.h>
#include "udsota_isotp.h"
#include "udsota_server_wire.h"

#define PCI_CF   0x2u      /* Consecutive Frame: the high nibble of byte 0 */
#define PCI_FC   0x3u      /* Flow Control */
#define CAN_DL   8u
#define PAD      0xAAu     /* ISO_TP_FRAME_PADDING_VALUE */

_Static_assert(offsetof(struct udsota_isotp, link_cfg) == 0, "isotp_port reads the link cfg at offset 0");
_Static_assert(UDSOTA_ISOTP_RX_MAX == UDSOTA_DL_MAX_BLOCK_LEN, "the receive buffer holds one whole 0x36 block");

static const udsota_can_t *s_clock;   /* isotp_user_get_us has no link: the last adapter initialised serves the clock */

/* The STmin an FC can carry for us microseconds, rounded up so the client is never told a shorter gap than asked:
 * 0; 100-900 us in 100 us steps (F1-F9); else whole milliseconds, 127 ms at most (00-7F). The FC sends it and the
 * STmin monitor judges against it, so the two always agree. */
static uint32_t stmin_sendable(uint32_t us)
{
    if (us == 0u) {
        return 0u;
    }
    if (us <= 900u) {
        return (us + 99u) / 100u * 100u;
    }
    if (us >= 127000u) {
        return 127000u;
    }
    return (us + 999u) / 1000u * 1000u;
}

/* Drops a parked FC, counted lost: it belongs to a message that is gone or has a newer FC. */
static void fc_drop(udsota_isotp_t *t)
{
    if (t->fc_parked) {
        t->fc_parked = false;
        t->fc_lost++;
    }
}

/* (Re)initialises the link at receive limit `limit`; any message isotp-c held is gone, and the orphan mark
 * and a parked FC with it. Call only while the send side is idle. */
static void link_init(udsota_isotp_t *t, uint32_t limit)
{
    isotp_init_link(&t->link, t->resp_id, t->buf->tx, UDSOTA_ISOTP_TX_MAX, t->buf->rx, limit);
    t->link.user_send_can_arg = t;        /* isotp_init_link cleared it; link_cfg is t's first member */
    t->rx_limit = limit;
    t->rx_orphan = false;
    fc_drop(t);
}

/* The download limit while a transfer is open, else the idle limit; changed only while both directions are idle. */
static void link_apply_limit(udsota_isotp_t *t)
{
    const uint32_t want = udsota_download_active(t->srv) ? t->rx_limit_dl : t->rx_limit_idle;
    if (want == t->rx_limit || t->link.receive_status != ISOTP_RECEIVE_STATUS_IDLE ||
        t->link.send_status == ISOTP_SEND_STATUS_INPROGRESS) {
        return;
    }
    link_init(t, want);
}

/* True while an answer is parked or its CFs are still going out. */
static bool tx_busy(const udsota_isotp_t *t)
{
    return t->park_len != 0u || t->link.send_status == ISOTP_SEND_STATUS_INPROGRESS;
}

/* Hands the parked answer to isotp-c. NOSPACE (the bus said retry) or INPROGRESS keeps it for the next
 * service, for UDSOTA_ISOTP_PARK_MAX_MS at most; a hard refusal or that limit drops it, counted, and the
 * client retries. The limit keeps a bus that acknowledges nothing from freezing the server, whose poll (S3
 * among it) waits while an answer is parked. */
static void tx_flush(udsota_isotp_t *t)
{
    if (t->park_len == 0u || t->link.send_status == ISOTP_SEND_STATUS_INPROGRESS) {
        return;
    }
    const int ret = isotp_send(&t->link, t->buf->park, (uint32_t)t->park_len);
    if ((ret == ISOTP_RET_NOSPACE || ret == ISOTP_RET_INPROGRESS) &&
        (uint32_t)(t->now_ms - t->park_ms) < UDSOTA_ISOTP_PARK_MAX_MS) {
        return;
    }
    if (ret != ISOTP_RET_OK) {
        t->resp_lost++;
    }
    t->park_len = 0u;
}

/* Parks the server's n-byte answer from buf->resp and sends it at once if isotp-c takes it. */
static void tx_response(udsota_isotp_t *t, size_t n)
{
    if (n == 0u) {
        return;
    }
    if (n > UDSOTA_ISOTP_RESP_MAX) {
        n = UDSOTA_ISOTP_RESP_MAX;
    }
    if (t->park_len != 0u) {
        t->resp_lost++;                   /* unreachable: every caller waits for !tx_busy() */
    }
    memcpy(t->buf->park, t->buf->resp, n);
    t->park_len = n;
    t->park_ms = t->now_ms;
    tx_flush(t);
}

/* Serves the request isotp-c holds, if any; while an answer is still going out it stays in isotp-c (FULL). */
static void take_request(udsota_isotp_t *t, uint32_t now_ms)
{
    if (tx_busy(t)) {
        return;
    }
    uint32_t len = 0;
    if (isotp_receive(&t->link, t->buf->req, UDSOTA_ISOTP_RX_MAX, &len) != ISOTP_RET_OK) {
        return;
    }
    tx_response(t, udsota_on_request(t->srv, t->buf->req, len, t->buf->resp, UDSOTA_ISOTP_RESP_MAX, now_ms));
}

/* Drops the message being reassembled after a withheld FC (the server has counted the stop), and any FC still
 * parked for it. With the send side idle a link re-init drops isotp-c's copy; otherwise isotp-c keeps it as an
 * orphan, is fed none of its CFs (the mirror ignores them), and its N_Cr timeout is not counted. */
static void rx_drop_message(udsota_isotp_t *t)
{
    udsota_rxwatch_reset(&t->rxw);
    fc_drop(t);                           /* the orphan path never reaches link_init */
    if (t->link.receive_status != ISOTP_RECEIVE_STATUS_INPROGRESS) {
        return;                           /* isotp-c holds no part of it: a withheld FF was never fed */
    }
    if (t->link.send_status != ISOTP_SEND_STATUS_INPROGRESS) {
        link_init(t, t->rx_limit);
    } else {
        t->rx_orphan = true;
    }
}

/* FC point (the FF, then every BS-th CF that isn't the last): the server judges it with this message's STmin
 * and the 64-CF median. False = it has counted the stop and ended the session; the frame is never fed. */
static bool fc_point_ok(udsota_isotp_t *t, uint32_t now_ms)
{
    if (udsota_fc_check(t->srv, udsota_rxwatch_median_us(&t->rxw), t->msg_stmin_us, now_ms)) {
        return true;
    }
    rx_drop_message(t);
    return false;
}

/* Keeps an FC the bus refused with UDSOTA_TX_RETRY for the next service (the send hook has dropped any older one). */
static void fc_park(udsota_isotp_t *t, uint16_t id, const uint8_t f[CAN_DL])
{
    memcpy(t->fc_frame, f, CAN_DL);
    t->fc_id = id;
    t->fc_parked = true;
    t->fc_park_ms = t->now_ms;
}

/* Retries a parked FC once per service; after fc_retry_ms (cfg.fc_retry_ms, which should cover two token
 * intervals of the app's response rate cap) or on a hard refusal it is counted lost. isotp-c ignores every FC's
 * send result. */
static void fc_retry(udsota_isotp_t *t)
{
    if (!t->fc_parked) {
        return;
    }
    const int rc = t->can.send(t->can.ctx, t->fc_id, t->fc_frame, CAN_DL);
    if (rc == 0) {
        t->fc_parked = false;
        return;
    }
    if (rc != UDSOTA_TX_RETRY || (uint32_t)(t->now_ms - t->fc_park_ms) >= t->fc_retry_ms) {
        t->fc_parked = false;
        t->fc_lost++;
    }
}

/* How long the caller may sleep: 1 ms while anything waits for the bus, else the server's deadline capped at
 * 10 ms in an open session or mid-message and 100 ms when idle. */
static uint32_t next_wait_ms(const udsota_isotp_t *t, uint32_t now_ms)
{
    if (tx_busy(t) || t->fc_parked) {
        return UDSOTA_ISOTP_WAIT_SEND_MS;
    }
    const uint32_t wait = udsota_ms_to_deadline(t->srv, now_ms);
    const bool open = udsota_phase(t->srv) != UDSOTA_PHASE_IDLE ||
                      t->link.receive_status == ISOTP_RECEIVE_STATUS_INPROGRESS;
    const uint32_t cap = open ? UDSOTA_ISOTP_WAIT_OPEN_MS : UDSOTA_ISOTP_WAIT_IDLE_MS;
    return (wait < cap) ? wait : cap;
}

/* Installed on the server: frames still to leave, the app's driver queue plus a parked answer and a
 * multi-frame send in progress, so a restart never overtakes its own answer. Without can.tx_pending the driver
 * queue is unknown and counts as one frame, so a restart waits the full UDSOTA_RESET_TX_WAIT_MS. */
static uint32_t tp_tx_pending(void *ctx)
{
    const udsota_isotp_t *t = (const udsota_isotp_t *)ctx;
    uint32_t n = (t->can.tx_pending != NULL) ? t->can.tx_pending(t->can.ctx) : 1u;
    n += (t->park_len != 0u) ? 1u : 0u;
    n += (t->link.send_status == ISOTP_SEND_STATUS_INPROGRESS) ? 1u : 0u;
    return n;
}

/* Starts the adapter on s; see udsota_isotp.h. */
void udsota_isotp_init(udsota_isotp_t *t, udsota_server_t *s, const udsota_config_t *cfg,
                       const udsota_hooks_t *hooks, const udsota_can_t *can, udsota_isotp_bufs_t *bufs)
{
    memset(t, 0, sizeof *t);
    t->srv = s;
    t->buf = bufs;
    t->can = *can;
    t->resp_id = cfg->resp_id;
    if (hooks != NULL) {
        t->stmin_us = hooks->stmin_us;
        t->stmin_ctx = hooks->ctx;
    }
    /* BS, STmin and the download limit come from s->cfg, as udsota_init resolved them, so the ISO-TP receive
     * limit is the very maxNumberOfBlockLength that 0x74 announces. The server does not resolve fc_retry_ms. */
    const udsota_config_t *rc = &s->cfg;
    t->stmin_default_us = stmin_sendable(rc->stmin_us);
    t->link_cfg.bs = rc->block_size;
    t->link_cfg.st_min_us = t->stmin_default_us;
    t->fc_retry_ms = (cfg->fc_retry_ms != 0u) ? cfg->fc_retry_ms : UDSOTA_ISOTP_FC_RETRY_MS;
    t->rx_limit_dl = rc->max_block_len;
    t->rx_limit_idle = (t->rx_limit_dl < UDSOTA_ISOTP_RX_LIMIT_IDLE) ? t->rx_limit_dl : UDSOTA_ISOTP_RX_LIMIT_IDLE;
    link_init(t, t->rx_limit_idle);       /* the memset above has already reset rxw */
    s_clock = &t->can;
    udsota_set_tx_pending(s, tp_tx_pending, t);
}

/* One request frame: predict what isotp-c will do, judge FC points, then feed it and take a finished request. */
void udsota_isotp_on_frame(udsota_isotp_t *t, const uint8_t *data, uint8_t dlc, uint32_t rx_us, uint32_t now_ms)
{
    if (data == NULL) {
        return;
    }
    t->now_ms = now_ms;
    link_apply_limit(t);
    const bool was_in_msg = t->rxw.in_msg;
    const udsota_rxw_kind_t k = udsota_rxwatch_frame(&t->rxw, data, dlc, rx_us, t->rx_limit, t->link_cfg.bs);
    switch (k) {
    case UDSOTA_RXW_FIRST:
        t->msg_stmin_us = (t->stmin_us != NULL) ? stmin_sendable(t->stmin_us(t->stmin_ctx)) : t->stmin_default_us;
        t->link_cfg.st_min_us = t->msg_stmin_us;          /* fixed for the whole message */
        udsota_on_rx_first_frame(t->srv, now_ms);
        if (!fc_point_ok(t, now_ms)) {
            return;
        }
        break;
    case UDSOTA_RXW_CONSEC_FC:
        if (!fc_point_ok(t, now_ms)) {
            return;
        }
        break;
    case UDSOTA_RXW_BROKEN:
        udsota_on_rx_timeout(t->srv, now_ms);             /* a wrong SN abandons a request whose FF stopped S3 */
        break;
    case UDSOTA_RXW_REFUSED:
        if (was_in_msg) {
            udsota_on_rx_timeout(t->srv, now_ms);         /* an oversize FF replaced a message in progress */
        }
        break;
    case UDSOTA_RXW_IGNORE:
        if (dlc >= 1u && (data[0] >> 4) == PCI_CF) {
            return;                                       /* a CF the mirror refused is never fed, so never FC'd */
        }
        break;
    default:
        break;
    }
    if (k == UDSOTA_RXW_FIRST || k == UDSOTA_RXW_SINGLE || k == UDSOTA_RXW_REFUSED) {
        t->rx_orphan = false;                             /* isotp-c replaces whatever it held */
    }
    isotp_on_can_message(&t->link, data, dlc);
    take_request(t, now_ms);
}

/* One functional frame (see udsota_isotp.h): a Single Frame of 1 to 7 bytes goes to the server's functional path
 * while both directions are idle; anything else, or anything while the link is busy, is dropped without an FC. */
void udsota_isotp_on_func_frame(udsota_isotp_t *t, const uint8_t *data, uint8_t dlc, uint32_t now_ms)
{
    if (data == NULL || dlc < 2u || dlc > CAN_DL || (data[0] >> 4) != 0u) {
        return;                                           /* only an SF: functional requests never segment */
    }
    const uint8_t n = data[0] & 0x0Fu;
    if (n == 0u || n > dlc - 1u) {
        return;
    }
    t->now_ms = now_ms;
    if (tx_busy(t) || t->link.receive_status != ISOTP_RECEIVE_STATUS_IDLE) {
        return;                                           /* a physical request or answer owns the server */
    }
    tx_response(t, udsota_on_functional_request(t->srv, &data[1], n, t->buf->resp, UDSOTA_ISOTP_RESP_MAX, now_ms));
}

/* isotp-c's timers and CFs, N_Cr, the parked FC and answer, the server's poll, a waiting request and the limit switch. */
uint32_t udsota_isotp_service(udsota_isotp_t *t, uint32_t now_ms)
{
    t->now_ms = now_ms;
    const bool rx_busy = t->link.receive_status == ISOTP_RECEIVE_STATUS_INPROGRESS;
    isotp_poll(&t->link);
    if (rx_busy && t->link.receive_status == ISOTP_RECEIVE_STATUS_IDLE &&
        t->link.receive_protocol_result == ISOTP_PROTOCOL_RESULT_TIMEOUT_CR) {
        udsota_rxwatch_reset(&t->rxw);
        if (t->rx_orphan) {
            t->rx_orphan = false;         /* dropped at a withheld FC, which the server already counted */
        } else {
            udsota_on_rx_timeout(t->srv, now_ms);
        }
    }
    fc_retry(t);
    tx_flush(t);
    if (!tx_busy(t) || udsota_restart_armed(t->srv)) {   /* an armed restart still needs its 100 ms fallback */
        tx_response(t, udsota_poll(t->srv, t->buf->resp, UDSOTA_ISOTP_RESP_MAX, now_ms));
    }
    take_request(t, now_ms);
    link_apply_limit(t);
    return next_wait_ms(t, now_ms);
}

/* See udsota_isotp.h. */
uint32_t udsota_isotp_resp_lost(const udsota_isotp_t *t)
{
    return t->resp_lost;
}

/* See udsota_isotp.h. */
uint32_t udsota_isotp_fc_lost(const udsota_isotp_t *t)
{
    return t->fc_lost;
}

/* isotp-c send hook: one 8-byte frame through the owning adapter's can.send. UDSOTA_TX_RETRY is NOSPACE
 * (isotp_poll retries a CF, tx_flush the answer's SF or FF); a refused FC is parked here because isotp-c
 * ignores FC results (isotp.c:579,597,642). A new FC supersedes a parked one, so no FC leaves out of order. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    udsota_isotp_t *t = (udsota_isotp_t *)arg;
    if (t == NULL || data == NULL || size == 0u || size > CAN_DL) {
        return ISOTP_RET_ERROR;
    }
    const bool fc = (data[0] >> 4) == PCI_FC;
    if (fc) {
        fc_drop(t);
    }
    uint8_t f[CAN_DL];
    memset(f, PAD, sizeof f);
    memcpy(f, data, size);
    const int rc = t->can.send(t->can.ctx, (uint16_t)arbitration_id, f, CAN_DL);
    if (rc == 0) {
        return ISOTP_RET_OK;
    }
    if (fc) {
        if (rc == UDSOTA_TX_RETRY) {
            fc_park(t, (uint16_t)arbitration_id, f);
        } else {
            t->fc_lost++;
        }
    }
    return (rc == UDSOTA_TX_RETRY) ? ISOTP_RET_NOSPACE : ISOTP_RET_ERROR;
}

/* isotp-c clock: the last-initialised adapter's now_us (isotp-c compares wrap-safe); 0 before any init. */
uint32_t isotp_user_get_us(void)
{
    return (s_clock != NULL) ? s_clock->now_us(s_clock->ctx) : 0u;
}

/* isotp-c diagnostic text: the core logs nothing. */
void isotp_user_debug(const char *message, ...)
{
    (void)message;
}
