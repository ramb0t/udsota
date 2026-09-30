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
#include "udsota_server.h"
#include "udsota_rxwatch.h"

#define UDSOTA_TX_RETRY 1                     /* can.send: no room now, keep the frame and retry */

/* The two buffer sizes a build may set (-D, alike for every file that includes this header, since they size
 * udsota_isotp_bufs_t), each within its MIN and 4,095, FF_DL's 12 bits. */
#ifndef UDSOTA_ISOTP_RX_MAX
#define UDSOTA_ISOTP_RX_MAX            4095u  /* largest request: one 0x36 block, FF_DL 0xFFF; caps cfg.max_block_len */
#endif
#ifndef UDSOTA_ISOTP_RESP_MAX
#define UDSOTA_ISOTP_RESP_MAX          256u   /* largest answer the server may build: 19 lists (RESP_MAX - 3) / 4 DTCs */
#endif
#define UDSOTA_ISOTP_RX_MIN            66u    /* 27 xx and a 64-byte ECDSA key: the longest fixed request the core parses */
#define UDSOTA_ISOTP_RESP_MIN          35u    /* 62 F1F3 and a SHA-256: the longest fixed answer the core builds */
#define UDSOTA_ISOTP_RX_LIMIT_IDLE     256u   /* receive limit outside a download, or RX_MAX when smaller */
#define UDSOTA_ISOTP_TX_MAX            UDSOTA_ISOTP_RESP_MAX   /* isotp-c send buffer: one whole answer */
#define UDSOTA_ISOTP_WAIT_SEND_MS      1u     /* service() wait while an answer, its CFs or an FC wait for the bus */
#define UDSOTA_ISOTP_WAIT_OPEN_MS      10u    /* longest wait in a non-default session or mid-message */
#define UDSOTA_ISOTP_WAIT_IDLE_MS      100u   /* longest wait otherwise */
#define UDSOTA_ISOTP_FC_RETRY_MS       10u    /* default FC retry window while cfg.fc_retry_ms is 0 */
#define UDSOTA_ISOTP_PARK_MAX_MS       1000u  /* a parked answer the bus keeps refusing is dropped after this long */

_Static_assert(UDSOTA_ISOTP_RX_MAX >= UDSOTA_ISOTP_RX_MIN && UDSOTA_ISOTP_RX_MAX <= UDSOTA_DL_MAX_BLOCK_LEN,
               "UDSOTA_ISOTP_RX_MAX is 66 to 4095: an ECDSA sendKey fits, and FF_DL has 12 bits");
_Static_assert(UDSOTA_ISOTP_RESP_MAX >= UDSOTA_ISOTP_RESP_MIN && UDSOTA_ISOTP_RESP_MAX <= 4095u,
               "UDSOTA_ISOTP_RESP_MAX is 35 to 4095: F1F3's answer fits, and FF_DL has 12 bits");

typedef struct {
    int      (*send)(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len);   /* 11-bit CAN IDs only; 0 queued, UDSOTA_TX_RETRY, else dropped */
    uint32_t (*tx_pending)(void *ctx);       /* nullable: frames still queued in the app's CAN driver; NULL = unknown, so a restart waits the full 100 ms */
    uint32_t (*now_us)(void *ctx);           /* monotonic microseconds (isotp_user_get_us) */
    void     *ctx;
} udsota_can_t;

/* The adapter's large buffers, 2 x RX_MAX + 3 x RESP_MAX: 8,958 B at the defaults; the caller places them (the ESP32
 * port: PSRAM or internal heap). Only the adapter touches them. */
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
    uint32_t             stmin_default_us;   /* s->cfg.stmin_us, rounded up to what an FC carries */
    uint16_t             resp_id;            /* cfg.resp_id (11-bit CAN IDs only) */
    uint32_t             rx_limit_dl;        /* receive limit while a download is open: s->cfg.max_block_len, which
                                                init caps at UDSOTA_ISOTP_RX_MAX */
    uint32_t             rx_limit_idle;      /* receive limit otherwise */
    uint32_t             rx_limit;           /* the link's current receive buffer size */
    udsota_rxwatch_t     rxw;                /* isotp-c's receive state, mirrored from the raw frames */
    uint32_t             msg_stmin_us;       /* STmin sent in the current message's first FC, as encoded (the monitor judges this) */
    bool                 rx_orphan;          /* isotp-c still holds a message dropped at a withheld FC */
    size_t               park_len;           /* bytes in buf->park; 0 = nothing parked */
    uint32_t             park_ms;            /* when the parked answer was parked */
    uint32_t             resp_lost;          /* see udsota_isotp_resp_lost() */
    bool                 fc_parked;          /* an FC can.send refused with UDSOTA_TX_RETRY waits in fc_frame */
    uint16_t             fc_id;
    uint8_t              fc_frame[8];
    uint32_t             fc_park_ms;         /* when it was parked */
    uint32_t             fc_retry_ms;        /* cfg.fc_retry_ms, 0 = UDSOTA_ISOTP_FC_RETRY_MS */
    uint32_t             fc_lost;            /* see udsota_isotp_fc_lost() */
    uint32_t             now_ms;             /* this call's time, for the FC retry window */
};
typedef struct udsota_isotp udsota_isotp_t;

/* Starts the adapter on s (call after udsota_init): link at the idle limit; BS, default STmin and download limit
 * are s->cfg's block_size, stmin_us and max_block_len as udsota_init resolved them, the last first capped at
 * UDSOTA_ISOTP_RX_MAX in s->cfg itself, so 34 never announces a block the receive buffer can't hold. From cfg it
 * takes resp_id and the FC retry window fc_retry_ms (0 = UDSOTA_ISOTP_FC_RETRY_MS). Copies *can and hooks->stmin_us
 * (hooks may be NULL), and installs its own tx_pending on s. */
void     udsota_isotp_init(udsota_isotp_t *t, udsota_server_t *s, const udsota_config_t *cfg,
                           const udsota_hooks_t *hooks, const udsota_can_t *can, udsota_isotp_bufs_t *bufs);
/* One request frame already filtered to cfg.req_id; rx_us is its arrival (for the STmin median). May send an
 * FC or an answer through can.send before it returns. */
void     udsota_isotp_on_frame(udsota_isotp_t *t, const uint8_t *data, uint8_t dlc, uint32_t rx_us, uint32_t now_ms);
/* One frame already filtered to cfg.func_id (functional addressing). Only a Single Frame is served, through
 * udsota_on_functional_request(), and never with an FC; it is dropped while an answer is going out or a physical
 * request is being received or waits, since the server answers one request at a time. May send the answer through
 * can.send before it returns. */
void     udsota_isotp_on_func_frame(udsota_isotp_t *t, const uint8_t *data, uint8_t dlc, uint32_t now_ms);
/* Runs after every wake: isotp-c's timers and CFs, a parked FC or answer, the server's poll, a waiting
 * request and the receive-limit switch. Returns the milliseconds the caller may sleep (a frame wakes it sooner). */
uint32_t udsota_isotp_service(udsota_isotp_t *t, uint32_t now_ms);
/* Answers dropped: refused outright by can.send, still refused after UDSOTA_ISOTP_PARK_MAX_MS, or replaced before they left. */
uint32_t udsota_isotp_resp_lost(const udsota_isotp_t *t);
/* Flow-control frames dropped: refused outright, still refused after the cfg.fc_retry_ms window, superseded by a
 * newer FC, or dropped with their message (link re-init, withheld message, or a message an SF replaced, a wrong SN
 * abandoned, its last CF completed or N_Cr ended while the FC waited). */
uint32_t udsota_isotp_fc_lost(const udsota_isotp_t *t);
