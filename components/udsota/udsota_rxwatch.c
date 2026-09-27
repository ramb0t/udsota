/* Byte-level mirror of isotp-c's receive path for the diag link; see udsota_rxwatch.h. Pure. */
#include <string.h>
#include "udsota_rxwatch.h"

#define PCI_SF   0u
#define PCI_FF   1u
#define PCI_CF   2u
#define CAN_DL   8u               /* classic CAN: isotp-c accepts an FF only at DLC 8 */
#define SF_MAX   (CAN_DL - 1u)    /* data bytes in a classic Single Frame */
#define CF_MAX   (CAN_DL - 1u)    /* data bytes in a Consecutive Frame (rx_dl 8) */

_Static_assert(UDSOTA_RXW_INTERVALS % 2u == 1u, "an odd interval count has one middle value");

/* Forgets any message in progress and its interval window. */
void udsota_rxwatch_reset(udsota_rxwatch_t *w)
{
    memset(w, 0, sizeof *w);
}

/* Starts a new message after an accepted FF: len announced, got bytes already in the FF. */
static void start_message(udsota_rxwatch_t *w, uint32_t len, uint32_t got)
{
    udsota_rxwatch_reset(w);
    w->in_msg = true;
    w->msg_len = len;
    w->msg_got = got;
    w->next_sn = 1u;
}

/* Records the interval since this message's previous CF (unsigned, so a clock wrap is harmless). */
static void push_interval(udsota_rxwatch_t *w, uint32_t t_us)
{
    if (w->have_last) {
        w->iv[w->iv_head] = t_us - w->last_cf_us;
        w->iv_head = (uint8_t)((w->iv_head + 1u) % UDSOTA_RXW_INTERVALS);
        if (w->iv_n < UDSOTA_RXW_INTERVALS) {
            w->iv_n++;
        }
    }
    w->last_cf_us = t_us;
    w->have_last = true;
}

/* Single Frame: SF_DL 1..DLC-1 and within the limit is a request, anything else leaves isotp-c unchanged. */
static udsota_rxw_kind_t on_single(udsota_rxwatch_t *w, const uint8_t *d, uint8_t dlc, uint32_t rx_limit)
{
    const uint32_t n = d[0] & 0x0Fu;
    if (n == 0u || n > (uint32_t)dlc - 1u || n > rx_limit) {
        return UDSOTA_RXW_IGNORE;          /* isotp-c: LENGTH or OVERFLOW, receive state unchanged */
    }
    udsota_rxwatch_reset(w);               /* isotp-c: status FULL, any message in progress is gone */
    return UDSOTA_RXW_SINGLE;
}

/* First Frame: short form (12-bit length, 6 data bytes) or escape form (32-bit BE length, 2 data bytes). */
static udsota_rxw_kind_t on_first(udsota_rxwatch_t *w, const uint8_t *d, uint8_t dlc, uint32_t rx_limit)
{
    if (dlc != CAN_DL) {
        return UDSOTA_RXW_IGNORE;          /* isotp-c: LENGTH, a message in progress goes on */
    }
    uint32_t len = ((uint32_t)(d[0] & 0x0Fu) << 8) | d[1];
    uint32_t got = CAN_DL - 2u;
    if (len == 0u) {
        len = ((uint32_t)d[2] << 24) | ((uint32_t)d[3] << 16) | ((uint32_t)d[4] << 8) | d[5];
        got = CAN_DL - 6u;
    }
    if (len <= SF_MAX) {
        return UDSOTA_RXW_IGNORE;          /* isotp-c: "should not use multiple frame transmission" */
    }
    if (len > rx_limit) {
        udsota_rxwatch_reset(w);           /* isotp-c: overflow FC, receive idle */
        return UDSOTA_RXW_REFUSED;
    }
    start_message(w, len, got);
    return UDSOTA_RXW_FIRST;
}

/* Consecutive Frame: sequence check first, then length, then isotp-c's BS countdown (isotp.c:636-642). */
static udsota_rxw_kind_t on_consec(udsota_rxwatch_t *w, const uint8_t *d, uint8_t dlc, uint32_t t_us, uint8_t bs)
{
    if (!w->in_msg) {
        return UDSOTA_RXW_IGNORE;
    }
    if ((d[0] & 0x0Fu) != w->next_sn) {
        udsota_rxwatch_reset(w);           /* isotp-c: WRONG_SN, receive idle */
        return UDSOTA_RXW_BROKEN;
    }
    uint32_t take = w->msg_len - w->msg_got;
    if (take > CF_MAX) {
        take = CF_MAX;
    }
    if (take > (uint32_t)dlc - 1u) {
        return UDSOTA_RXW_IGNORE;          /* isotp-c: "Consecutive frame too short", state unchanged */
    }
    w->msg_got += take;
    w->next_sn = (uint8_t)((w->next_sn + 1u) & 0x0Fu);
    w->cf_count++;
    push_interval(w, t_us);
    if (w->msg_got >= w->msg_len) {
        w->in_msg = false;
        return UDSOTA_RXW_LAST;
    }
    const uint32_t period = (bs != 0u) ? bs : 64u;
    return (w->cf_count % period == 0u) ? UDSOTA_RXW_CONSEC_FC : UDSOTA_RXW_CONSEC;
}

/* Classifies one request frame exactly as isotp-c will treat it and advances the mirror. */
udsota_rxw_kind_t udsota_rxwatch_frame(udsota_rxwatch_t *w, const uint8_t *data, uint8_t dlc,
                                   uint32_t t_us, uint32_t rx_limit, uint8_t bs)
{
    if (data == NULL || dlc < 2u || dlc > CAN_DL) {
        return UDSOTA_RXW_IGNORE;          /* isotp-c drops frames under 2 bytes before its PCI switch (isotp.c:535) */
    }
    switch (data[0] >> 4) {
    case PCI_SF:
        return on_single(w, data, dlc, rx_limit);
    case PCI_FF:
        return on_first(w, data, dlc, rx_limit);
    case PCI_CF:
        return on_consec(w, data, dlc, t_us, bs);
    default:
        return UDSOTA_RXW_IGNORE;          /* the client's FC (our send side) or an invalid PCI */
    }
}

/* Median of the window's 63 intervals, sorted in a local copy (once per FC point). */
uint32_t udsota_rxwatch_median_us(const udsota_rxwatch_t *w)
{
    if (w->iv_n < UDSOTA_RXW_INTERVALS) {
        return UDSOTA_CF_MEDIAN_NONE;
    }
    uint32_t a[UDSOTA_RXW_INTERVALS];
    memcpy(a, w->iv, sizeof a);
    for (uint32_t i = 1u; i < UDSOTA_RXW_INTERVALS; i++) {
        const uint32_t v = a[i];
        uint32_t j = i;
        while (j > 0u && a[j - 1u] > v) {
            a[j] = a[j - 1u];
            j--;
        }
        a[j] = v;
    }
    return a[UDSOTA_RXW_INTERVALS / 2u];
}
