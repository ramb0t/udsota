/* Per-link BS and STmin accessors that isotp_force.h substitutes into isotp-c. */
#include <stddef.h>
#include "isotp.h"
#include "isotp_port.h"

/* The cfg a link's owner placed first in the struct user_send_can_arg points at, or NULL. */
static const isotp_link_cfg_t *link_cfg(const struct IsoTpLink *link)
{
    return link ? (const isotp_link_cfg_t *)link->user_send_can_arg : NULL;
}

/* Block size this link advertises in its next FC: cfg.bs, or 64 if the link has no cfg or bs 0. */
uint8_t isotp_port_bs(const struct IsoTpLink *link)
{
    const isotp_link_cfg_t *c = link_cfg(link);
    return (c && c->bs) ? c->bs : (uint8_t)ISOTP_PORT_DEFAULT_BS;
}

/* STmin in microseconds for this link: cfg.st_min_us clamped to 127000, or 5000 with no cfg. */
uint32_t isotp_port_st_min_us(const struct IsoTpLink *link)
{
    const isotp_link_cfg_t *c = link_cfg(link);
    if (!c) {
        return ISOTP_PORT_DEFAULT_ST_MIN_US;
    }
    return c->st_min_us > ISOTP_PORT_ST_MIN_MAX_US ? ISOTP_PORT_ST_MIN_MAX_US : c->st_min_us;
}
