/* Per-link ISO-TP flow-control settings for the vendored isotp-c v1.9.3 (unpatched).
 *
 * isotp-c reads its receive-side block size and STmin from two compile-time macros. isotp_force.h,
 * force-included into isotp-c/isotp.c only, turns those macros into calls to the accessors below,
 * so every link carries its own BS and STmin. The accessors read link->user_send_can_arg, which
 * the owner of each link must point at a struct whose FIRST member is an isotp_link_cfg_t:
 *
 *     typedef struct { isotp_link_cfg_t cfg; ...owner state... } my_link_ctx_t;
 *     isotp_init_link(&link, tx_id, txbuf, sizeof txbuf, rxbuf, sizeof rxbuf);
 *     link.user_send_can_arg = &ctx;            // &ctx == &ctx.cfg
 *
 * Set user_send_can_arg straight after isotp_init_link() (which clears it). Change cfg only from
 * the task that owns the link; a new BS or STmin goes out in the next flow-control frame. */
#pragma once
#include <stdint.h>

/* IsoTpLink's layout depends on these options, so every file that includes isotp.h must be built
 * with the same set (components/isotp/CMakeLists.txt declares them PUBLIC). Stop a mismatch here. */
#ifndef ISO_TP_USER_SEND_CAN_ARG
#error "isotp: ISO_TP_USER_SEND_CAN_ARG must be defined (link against the isotp component)"
#endif
#if defined(ISO_TP_ENABLE_STREAMING) || defined(ISO_TP_TRANSMIT_COMPLETE_CALLBACK) || \
    defined(ISO_TP_RECEIVE_COMPLETE_CALLBACK) || defined(ISO_TP_USER_SEND_CAN_FLAGS)
#error "isotp: streaming, completion callbacks and send-flags change IsoTpLink and are not used"
#endif
#if defined(ISO_TP_MAX_CAN_FRAME_SIZE) && ISO_TP_MAX_CAN_FRAME_SIZE != 8
#error "isotp: classical CAN only (ISO_TP_MAX_CAN_FRAME_SIZE 8)"
#endif

#define ISOTP_PORT_DEFAULT_BS         64u     /* BS for a link with no cfg, and for cfg.bs == 0 */
#define ISOTP_PORT_DEFAULT_ST_MIN_US  5000u   /* STmin for a link with no cfg: the slowest pace used */
#define ISOTP_PORT_ST_MIN_MAX_US      127000u /* largest encodable STmin; larger values are clamped */

/* One link's receive-side flow control. bs: consecutive frames per block, 1..255 (0 is read as
 * ISOTP_PORT_DEFAULT_BS, because BS 0 makes isotp-c's uint8_t receive_bs_count wrap and send a
 * spurious FC every 256 CFs). st_min_us: requested CF separation, and the floor on this link's own
 * CF pacing when it sends. Encodable values are 0, 100..900 in 100 us steps, and 1000..127000 in
 * 1000 us steps; anything else is rounded down by isotp-c (1..99 and 901..999 us become 0). */
typedef struct {
    uint8_t  bs;
    uint32_t st_min_us;
} isotp_link_cfg_t;

struct IsoTpLink;

/* Block size this link advertises in its next FC: cfg.bs, or 64 if the link has no cfg or bs 0. */
uint8_t isotp_port_bs(const struct IsoTpLink *link);

/* STmin in microseconds for this link: cfg.st_min_us clamped to 127000, or 5000 with no cfg. */
uint32_t isotp_port_st_min_us(const struct IsoTpLink *link);
