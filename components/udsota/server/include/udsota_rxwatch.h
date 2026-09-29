/* Mirrors isotp-c's receive state for the diag request link from the raw frames (pure, host-tested),
 * so the diag task knows BEFORE feeding a frame whether isotp-c will answer it with a flow control
 * (its FC points; isotp-c sends the FC from inside isotp_on_can_message, isotp.c:597,642). It
 * also keeps the CF-to-CF intervals for the STmin rule. The rules copy the pinned fork 1fc19e2
 * (isotp.c:285 SF, 331 FF, 409 CF, 531 dispatch), classic CAN only, streaming compiled out. */
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define UDSOTA_RXW_WINDOW    64u                      /* CFs the median spans: the last 64 CFs */
#define UDSOTA_RXW_INTERVALS (UDSOTA_RXW_WINDOW - 1u)   /* 63 intervals between them, so the first FC point is judged */
#define UDSOTA_CF_MEDIAN_NONE UINT32_MAX   /* udsota_rxwatch_median_us() before a full 64-CF window: compliance not judged */

typedef enum {
    UDSOTA_RXW_IGNORE = 0,  /* isotp-c changes no receive state: client FC, bad PCI or length, CF outside a message */
    UDSOTA_RXW_SINGLE,      /* valid Single Frame: a complete request (it replaces a message in progress) */
    UDSOTA_RXW_FIRST,       /* accepted FF: isotp-c answers it with an FC (an FC point) */
    UDSOTA_RXW_REFUSED,     /* FF over the receive limit: isotp-c sends an overflow FC and keeps no message */
    UDSOTA_RXW_CONSEC,      /* CF with no FC after it */
    UDSOTA_RXW_CONSEC_FC,   /* CF after which isotp-c sends an FC: every BS-th CF that isn't the last (an FC point) */
    UDSOTA_RXW_LAST,        /* CF that completes the message */
    UDSOTA_RXW_BROKEN,      /* CF with the wrong sequence number: isotp-c abandons the message */
} udsota_rxw_kind_t;

typedef struct {
    bool     in_msg;                    /* a multi-frame message is being reassembled */
    uint32_t msg_len;                   /* FF_DL */
    uint32_t msg_got;                   /* bytes received so far, FF included */
    uint32_t cf_count;                  /* CFs received in this message; the next SN and ring slot follow from it */
    uint32_t last_cf_us;                /* timestamp of this message's previous CF */
    uint32_t iv[UDSOTA_RXW_INTERVALS];    /* ring of CF-to-CF intervals (us), slot (cf_count - 2) % UDSOTA_RXW_INTERVALS */
} udsota_rxwatch_t;

/* Forgets any message in progress and its interval window. */
void udsota_rxwatch_reset(udsota_rxwatch_t *w);
/* Classifies one request frame exactly as isotp-c will treat it and advances the mirror. rx_limit is
 * the link's receive buffer size; bs its block size (0 behaves as 64, as isotp_port_bs() maps it).
 * A frame under 2 bytes or over 8 is IGNORE, as isotp_on_can_message() drops it unread. */
udsota_rxw_kind_t udsota_rxwatch_frame(udsota_rxwatch_t *w, const uint8_t *data, uint8_t dlc,
                                   uint32_t t_us, uint32_t rx_limit, uint8_t bs);
/* Median of the intervals between this message's last UDSOTA_RXW_WINDOW CFs, or UDSOTA_CF_MEDIAN_NONE until
 * that many have arrived. Ready at CF 64, the first FC point; 63 intervals is odd, so it is the middle one. */
uint32_t udsota_rxwatch_median_us(const udsota_rxwatch_t *w);
