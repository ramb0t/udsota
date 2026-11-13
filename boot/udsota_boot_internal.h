/* udsota_boot_internal.h: the bootloader core's pure functions, the boot rules, the image rules and the CRC, for its
 * unit tests. Not for products: udsota_boot.c and the tests include it. */
#pragma once
#include "udsota_boot.h"

/* The inputs of the boot rules, as read. */
typedef struct {
    bool                handover_ok;   /* word 0 was the mark and read back cleared */
    uint16_t            handover;      /* word 1 as read: the bus, which decodes from 1 to cfg.buses */
    uint16_t            count_word;    /* word 2 as read */
    udsota_boot_reset_t cause;
    bool                app_valid;     /* the valid app, below */
} udsota_boot_inputs_t;

/* The valid app is the boot check's result at udsota_boot_init (udsota_boot.h). Afterwards it is the core's flag: a
 * download's first erase clears it and a passing FF01 sets it, and the boot check runs again only at the next
 * udsota_boot_init. F1F0's running state (3 or 0), F189 and F1F3 (0.0.0 and 32 zero bytes without it) and both
 * session exits use the flag. */

/* The boot rules as a pure function. udsota_boot_init calls it with the inputs as read. Both session exits call it
 * with handover_ok false, cause OTHER, app_valid the core's flag and count_word read again from its keep word.
 * *count_out is the start count after the boot rules (before the start's increment). A HANDOVER answer means only that
 * word 1 decoded. If can_start then refuses the bus, udsota_boot_init calls this again with handover_ok false. */
udsota_boot_decision_t udsota_boot_decide(const udsota_boot_cfg_t *cfg, const udsota_boot_inputs_t *in,
                                          uint8_t *count_out);

/* The image rules as a pure function over a header's bytes, wherever they lie: in a first 36's data or in the slot.
 * hdr points at the header and hdr_len says how many of its bytes are at hand: in a first 36, its data past
 * image_header_offset (0 when the data ends before it); in the slot, UDSOTA_BARE_HDR_LEN. It reads no byte at or past
 * hdr_len. mem_size is the memorySize of the 34 that opened the download, which the 34 has already held to a multiple
 * of 4 from the header's end up to slot_size. Returns UDSOTA_DL_OK when every rule passes, else the first that fails,
 * in this order:
 *  - UDSOTA_DL_BAD_HEADER: an hdr_len below UDSOTA_BARE_HDR_LEN, a magic other than UDSOTA_BARE_HDR_MAGIC, a
 *    header_version below 1, or a bit of UDSOTA_BARE_HDR_FLAGS_MUST set (version 1 defines none);
 *  - UDSOTA_DL_TOO_BIG: an image_length past cfg.slot_size;
 *  - UDSOTA_DL_BAD_HEADER: an image_length other than mem_size, not a multiple of 4, or ending before the header does;
 *  - UDSOTA_DL_BAD_PROJECT: a project other than cfg.product;
 *  - UDSOTA_DL_BAD_BOARD: a descriptor magic other than UDSOTA_IMG_DESC_MAGIC, desc_version 0, or a hw_id other than
 *    cfg.hw_id;
 *  - UDSOTA_DL_BAD_LAYOUT: a partition_layout_id other than cfg.layout_id;
 *  - UDSOTA_DL_BAD_DIAG_IDS: a diag_request_id other than cfg.request_id, or a diag_response_id other than
 *    cfg.response_id.
 * There is no version rule: any version is taken, older included, and the descriptor's release flag is not read. It
 * reads no reserved byte, no flag in the low byte, and not the signature. The first 36 runs it before anything is
 * erased, and a failure answers that 36 with 0x31 and puts the reason in F1F1. FF01 runs it on the bytes in the slot,
 * with the download's mem_size, before the CRC, so when both fail its reason is the status. */
udsota_reason_t udsota_boot_image_rules(const udsota_boot_cfg_t *cfg, const uint8_t *hdr, uint32_t hdr_len,
                                        uint32_t mem_size);

/* CRC-32 as zlib computes it (reflected polynomial 0xEDB88320), a nibble at a time from a 16-word table. crc is 0 to
 * start, or what a previous call returned, so calls chain over consecutive pieces as zlib's crc32() does. */
uint32_t udsota_boot_crc32(uint32_t crc, const void *data, uint32_t len);
