/* Byte codecs for the updater's wire layouts (F1F0, F1F1). Pure. The big-endian helpers are in
 * server/udsota_codec.c. */
#include <string.h>
#include "udsota_update_wire.h"

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
