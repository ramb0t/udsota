/* Byte codecs for the server's wire layout (F1F2) and big-endian helpers. Pure. The updater's F1F0 and F1F1 are in
 * update/udsota_update_codec.c. */
#include "udsota_server_wire.h"

/* Writes v big-endian into p[0..1]. */
void udsota_put_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Reads a big-endian u16 from p[0..1]. */
uint16_t udsota_get_u16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Writes v big-endian into p[0..3]. */
void udsota_put_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Reads a big-endian u32 from p[0..3]. */
uint32_t udsota_get_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Adds one to an F1F2 counter, holding at 0xFFFF. */
void udsota_sat_inc16(uint16_t *c)
{
    if (*c != 0xFFFFu) {
        (*c)++;
    }
}

/* Packs F1F2 (8 x u16 BE, field order); returns UDSOTA_COUNTERS_LEN, or 0 without writing when short or NULL. */
size_t udsota_pack_counters(uint8_t *out, size_t max, const udsota_counters_t *s)
{
    if (out == NULL || s == NULL || max < UDSOTA_COUNTERS_LEN) {
        return 0;
    }
    const uint16_t v[8] = {s->seq_errors, s->ncr_timeouts, s->repeated_blocks, s->aborts,
                           s->withheld_fcs, s->stmin_violations, s->resp_pending_caps,
                           s->resp_frames_dropped};
    for (size_t i = 0; i < 8; i++) {
        udsota_put_u16be(&out[2 * i], v[i]);
    }
    return UDSOTA_COUNTERS_LEN;
}

/* Unpacks F1F2; false without touching *s when len < UDSOTA_COUNTERS_LEN or a pointer is NULL. */
bool udsota_unpack_counters(const uint8_t *in, size_t len, udsota_counters_t *s)
{
    if (in == NULL || s == NULL || len < UDSOTA_COUNTERS_LEN) {
        return false;
    }
    s->seq_errors = udsota_get_u16be(&in[0]);
    s->ncr_timeouts = udsota_get_u16be(&in[2]);
    s->repeated_blocks = udsota_get_u16be(&in[4]);
    s->aborts = udsota_get_u16be(&in[6]);
    s->withheld_fcs = udsota_get_u16be(&in[8]);
    s->stmin_violations = udsota_get_u16be(&in[10]);
    s->resp_pending_caps = udsota_get_u16be(&in[12]);
    s->resp_frames_dropped = udsota_get_u16be(&in[14]);
    return true;
}
