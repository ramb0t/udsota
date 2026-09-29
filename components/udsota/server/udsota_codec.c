/* Byte codecs for the UDS contract layouts (F1F0, F1F1, F1F2) and big-endian helpers. Pure. */
#include <string.h>
#include "udsota_server_wire.h"
#include "udsota_update_wire.h"   /* F1F0 and F1F1, until update/udsota_update_codec.c takes them */

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

/* Packs F1F0 into out; returns UDSOTA_STATUS_LEN, or 0 without writing when max is short or a pointer is NULL. */
size_t udsota_pack_status(uint8_t *out, size_t max, const udsota_status_t *s)
{
    if (out == NULL || s == NULL || max < UDSOTA_STATUS_LEN) {
        return 0;
    }
    out[0] = s->running_slot;
    out[1] = s->running_state;
    out[2] = s->boot_slot;
    out[3] = s->other_slot_state;
    memcpy(&out[4], s->other_version, 3);
    memcpy(&out[7], s->other_elf_sha_prefix, 8);
    out[15] = s->flags;
    return UDSOTA_STATUS_LEN;
}

/* Unpacks F1F0; false without touching *s when len < UDSOTA_STATUS_LEN or a pointer is NULL. */
bool udsota_unpack_status(const uint8_t *in, size_t len, udsota_status_t *s)
{
    if (in == NULL || s == NULL || len < UDSOTA_STATUS_LEN) {
        return false;
    }
    s->running_slot = in[0];
    s->running_state = in[1];
    s->boot_slot = in[2];
    s->other_slot_state = in[3];
    memcpy(s->other_version, &in[4], 3);
    memcpy(s->other_elf_sha_prefix, &in[7], 8);
    s->flags = in[15];
    return true;
}

/* Packs F1F1 (reason, u32 BE); returns UDSOTA_RESULT_LEN, or 0 without writing when short or NULL. */
size_t udsota_pack_result(uint8_t *out, size_t max, const udsota_result_t *s)
{
    if (out == NULL || s == NULL || max < UDSOTA_RESULT_LEN) {
        return 0;
    }
    out[0] = s->reason_code;
    udsota_put_u32be(&out[1], s->bytes_received);
    return UDSOTA_RESULT_LEN;
}

/* Unpacks F1F1; false without touching *s when len < UDSOTA_RESULT_LEN or a pointer is NULL. */
bool udsota_unpack_result(const uint8_t *in, size_t len, udsota_result_t *s)
{
    if (in == NULL || s == NULL || len < UDSOTA_RESULT_LEN) {
        return false;
    }
    s->reason_code = in[0];
    s->bytes_received = udsota_get_u32be(&in[1]);
    return true;
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
