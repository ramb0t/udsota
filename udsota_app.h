/* udsota_app.h: the app's side of a udsota bootloader (boot/udsota_boot.h), so an app hands over to its bootloader
 * and reports itself healthy without any UDS stack. Header-only: an app adds this directory to its include path and
 * compiles no udsota source. It includes udsota_wire.h, udsota_image.h and <stdbool.h>, never iso14229 or
 * udsota_boot.h, keeps no state and calls no library function, so an interrupt may use any of it.
 *
 * The app answers exactly two requests, and only on 11-bit frames on its request ID, on any bus:
 *  - 10 02, the handover;
 *  - 22 F1F4, the running image's ID prefix. The app answers it only once it is healthy.
 * It is silent to everything else. Its obligations:
 *  - reload the watchdog the bootloader started, which runs from the jump. Its period is nominal, and a watchdog's own
 *    clock can run well fast of nominal (an STM32F1's nominal 2 s is 1.33 to 2.67 s, boot/README.md), so reload well
 *    inside the shortest period the part's data allows;
 *  - clear the start count before any deliberate reset or standby;
 *  - never reset the store that holds the keep words. */
#pragma once
#include <stdbool.h>
#include "udsota_wire.h"
#include "udsota_image.h"

/* The byte every answer the helper builds is padded with. */
#define UDSOTA_APP_PAD_BYTE 0xAAu

typedef enum {
    UDSOTA_APP_RX_NONE = 0,     /* not an 11-bit frame on the request ID: not the app's */
    UDSOTA_APP_RX_HANDOVER,     /* first bytes 02 10 02, whatever the padding */
    UDSOTA_APP_RX_READ_PREFIX,  /* first bytes 03 22 F1 F4, whatever the padding */
    UDSOTA_APP_RX_OTHER,        /* on the request ID but neither request: the app stays silent */
} udsota_app_rx_t;

/* The app's storage, defined by the app over the same words as udsota_boot_port_keep_*. */
void udsota_app_port_keep_write(uint8_t word, uint16_t value);

/* Classifies one received frame against req_id, the app's request ID; std_id is true for an 11-bit frame. It matches
 * first bytes only and is safe in an interrupt, which should do no more than set a flag. */
static inline udsota_app_rx_t udsota_app_classify(uint32_t req_id, uint32_t id, bool std_id, const uint8_t *data,
                                                  uint8_t len)
{
    if (!std_id || id != req_id) {
        return UDSOTA_APP_RX_NONE;
    }
    if (len >= 3u && data[0] == 0x02u && data[1] == 0x10u && data[2] == 0x02u) {
        return UDSOTA_APP_RX_HANDOVER;
    }
    if (len >= 4u && data[0] == 0x03u && data[1] == 0x22u && data[2] == (uint8_t)(UDSOTA_DID_IMAGE_PREFIX >> 8) &&
        data[3] == (uint8_t)UDSOTA_DID_IMAGE_PREFIX) {
        return UDSOTA_APP_RX_READ_PREFIX;
    }
    return UDSOTA_APP_RX_OTHER;
}

/* The answer to the handover, sent on the response ID within the tester's 150 ms P2, on the bus the request came
 * from: 03 7F 10 78 and UDSOTA_APP_PAD_BYTE to 8 bytes. Then the app waits, with a bound, for the frame to leave,
 * calls udsota_app_write_handover, and makes its deliberate reset. */
static inline void udsota_app_answer_pending(uint8_t out[8])
{
    out[0] = 0x03u;
    out[1] = 0x7Fu;
    out[2] = 0x10u;
    out[3] = 0x78u;
    for (int i = 4; i < 8; i++) {
        out[i] = UDSOTA_APP_PAD_BYTE;
    }
}

/* The answer to 22 F1F4: 07 62 F1 F4 and the first four bytes of the running image's image_id, which the app reads
 * from its placed header (udsota_image_header.image_id, udsota_image.h). Only after the healthy mark, at any time from
 * then on, within the tester's 150 ms P2, on the response ID and on the bus the request came from. */
static inline void udsota_app_answer_prefix(const uint8_t prefix[4], uint8_t out[8])
{
    out[0] = 0x07u;
    out[1] = 0x62u;
    out[2] = (uint8_t)(UDSOTA_DID_IMAGE_PREFIX >> 8);
    out[3] = (uint8_t)UDSOTA_DID_IMAGE_PREFIX;
    for (int i = 0; i < 4; i++) {
        out[4 + i] = prefix[i];
    }
}

/* Writes the handover: word 1 = bus, the bus (1..15) the 10 02 came in on, then word 0 = UDSOTA_HANDOVER_MARK, in that
 * order; a bus outside 1..15 is a product bug. It does not reset; the app's deliberate-reset path, which clears the
 * start count first, follows. */
static inline void udsota_app_write_handover(uint8_t bus)
{
    udsota_app_port_keep_write(UDSOTA_KEEP_WORD_HANDOVER, bus);
    udsota_app_port_keep_write(UDSOTA_KEEP_WORD_MARK, UDSOTA_HANDOVER_MARK);
}

/* Writes UDSOTA_START_COUNT_CLEAR. It is the healthy mark: the app calls it once healthy (example: 30 s in its main
 * loop), and from then on answers 22 F1F4. The app's one named deliberate-reset function calls it just before
 * resetting, and so does any mode that must never be held (example: a production test). Nothing reachable from a
 * fault handler or an assert may call it, or an app that keeps failing is never held. It may be called from any
 * context, an interrupt included, so udsota_app_port_keep_write must be safe there. */
static inline void udsota_app_clear_start_count(void)
{
    udsota_app_port_keep_write(UDSOTA_KEEP_WORD_COUNT, UDSOTA_START_COUNT_CLEAR);
}
