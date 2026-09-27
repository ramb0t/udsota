/* udsota's ISO-TP transport: the server on one classic-CAN request/response pair through the
 * vendored isotp-c. It predicts isotp-c's flow-control points so the server can withhold an FC, parks an
 * answer the bus refuses and retries it, and serves one request at a time. The caller owns the bus
 * (udsota_can_t), the clock and the buffers, and feeds it request frames it has already filtered by ID.
 *
 * udsota_isotp.c defines isotp-c's platform hooks (isotp_user_send_can, isotp_user_get_us and
 * isotp_user_debug), so no other isotp-c user may link into the same image. isotp_user_get_us takes no
 * link, so every adapter in a process must pass the same clock; the last one initialised serves it. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "isotp.h"
#include "isotp_port.h"
#include "udsota.h"
#include "udsota_rxwatch.h"

#define UDSOTA_TX_RETRY 1                     /* can.send: no room now, keep the frame and retry */

#define UDSOTA_ISOTP_RX_MAX            4095u  /* largest request: one 0x36 block, FF_DL 0xFFF */
#define UDSOTA_ISOTP_RX_LIMIT_IDLE     256u   /* receive limit outside a download */
#define UDSOTA_ISOTP_TX_MAX            512u   /* isotp-c send buffer */
#define UDSOTA_ISOTP_RESP_MAX          256u   /* largest answer the server may build */
#define UDSOTA_ISOTP_WAIT_SEND_MS      1u     /* service() wait while an answer, its CFs or an FC wait for the bus */
#define UDSOTA_ISOTP_WAIT_OPEN_MS      10u    /* longest wait in a non-default session or mid-message */
#define UDSOTA_ISOTP_WAIT_IDLE_MS      100u   /* longest wait otherwise */
#define UDSOTA_ISOTP_FC_RETRY_MS       10u    /* default FC retry window while cfg.fc_retry_ms is 0 */

typedef struct {
    int      (*send)(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len);   /* 0 queued, UDSOTA_TX_RETRY, else dropped */
    uint32_t (*tx_pending)(void *ctx);       /* nullable: frames still queued in the app's CAN driver */
    uint32_t (*now_us)(void *ctx);           /* monotonic microseconds (isotp_user_get_us) */
    void     *ctx;
} udsota_can_t;

/* The adapter's large buffers, 9,214 B; the caller places them (the ESP32 port: PSRAM). Only the adapter touches them. */
typedef struct {
    uint8_t rx[UDSOTA_ISOTP_RX_MAX];         /* isotp-c reassembly */
    uint8_t tx[UDSOTA_ISOTP_TX_MAX];         /* isotp-c send */
    uint8_t req[UDSOTA_ISOTP_RX_MAX];        /* the request being served (engine.write copies before it returns) */
    uint8_t resp[UDSOTA_ISOTP_RESP_MAX];     /* the server's answer */
    uint8_t park[UDSOTA_ISOTP_RESP_MAX];     /* an answer isotp-c could not take yet */
} udsota_isotp_bufs_t;

/* One adapter, caller-allocated (the ESP32 port keeps it in internal RAM). Every member is private to udsota_isotp.c. */
struct udsota_isotp {
    isotp_link_cfg_t     link_cfg;           /* FIRST: isotp_port reads BS and STmin through user_send_can_arg */
    IsoTpLink            link;
    udsota_server_t     *srv;
    udsota_isotp_bufs_t *buf;
    udsota_can_t         can;                /* copied at init */
    uint32_t           (*stmin_us)(void *ctx);   /* hooks.stmin_us, copied at init; NULL = stmin_default_us */
    void                *stmin_ctx;          /* hooks.ctx */
    uint32_t             stmin_default_us;   /* cfg.stmin_us, 0 = UDSOTA_STMIN_DEFAULT_US (udsota.h) */
    uint16_t             resp_id;
    uint32_t             rx_limit_dl;        /* receive limit while a download is open: cfg.max_block_len */
    uint32_t             rx_limit_idle;      /* receive limit otherwise */
    uint32_t             rx_limit;           /* the link's current receive buffer size */
    udsota_rxwatch_t     rxw;                /* isotp-c's receive state, mirrored from the raw frames */
    uint32_t             msg_stmin_us;       /* STmin sent in the current message's first FC */
    bool                 rx_orphan;          /* isotp-c still holds a message dropped at a withheld FC */
    size_t               park_len;           /* bytes in buf->park; 0 = nothing parked */
    uint32_t             resp_lost;          /* answers refused outright by can.send, or replaced unsent */
    bool                 fc_parked;          /* an FC can.send refused with UDSOTA_TX_RETRY waits in fc_frame */
    uint16_t             fc_id;
    uint8_t              fc_frame[8];
    uint32_t             fc_park_ms;         /* when it was parked */
    uint32_t             fc_retry_ms;        /* cfg.fc_retry_ms, 0 = UDSOTA_ISOTP_FC_RETRY_MS */
    uint32_t             fc_lost;            /* FCs refused outright, still refused after fc_retry_ms,
                                              * superseded by a newer FC, or dropped with their message */
    uint32_t             now_ms;             /* this call's time, for the FC retry window */
};
typedef struct udsota_isotp udsota_isotp_t;

/* Starts the adapter on s (call after udsota_init): link at the idle limit, BS cfg->block_size, default STmin
 * cfg->stmin_us, download limit cfg->max_block_len (0 = 4095, capped there), FC retry window cfg->fc_retry_ms
 * (0 = UDSOTA_ISOTP_FC_RETRY_MS). Copies *can and hooks->stmin_us (hooks may be NULL), and installs its own
 * tx_pending on s. */
void     udsota_isotp_init(udsota_isotp_t *t, udsota_server_t *s, const udsota_config_t *cfg,
                           const udsota_hooks_t *hooks, const udsota_can_t *can, udsota_isotp_bufs_t *bufs);
/* One request frame already filtered to cfg.req_id; rx_us is its arrival (for the STmin median). May send an
 * FC or an answer through can.send before it returns. */
void     udsota_isotp_on_frame(udsota_isotp_t *t, const uint8_t *data, uint8_t dlc, uint32_t rx_us, uint32_t now_ms);
/* Runs after every wake: isotp-c's timers and CFs, a parked FC or answer, the server's poll, a waiting
 * request and the receive-limit switch. Returns the milliseconds the caller may sleep (a frame wakes it sooner). */
uint32_t udsota_isotp_service(udsota_isotp_t *t, uint32_t now_ms);
/* Answers dropped: refused outright by can.send, or replaced before they left. */
uint32_t udsota_isotp_resp_lost(const udsota_isotp_t *t);
/* Flow-control frames dropped: refused outright, still refused after the cfg.fc_retry_ms window, superseded by a
 * newer FC, or dropped with their message (link re-init, withheld message). */
uint32_t udsota_isotp_fc_lost(const udsota_isotp_t *t);
