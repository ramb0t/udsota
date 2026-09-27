/* Boot-loop breaker. A VALID image that crashes at boot on a bad
 * config or stored record is never rolled back, so the device counts crash resets in memory that survives
 * a reset and, from the UDSOTA_BOOTLOOP_THRESHOLD-th since the last power-on or healthy mark, boots
 * ignoring config. It writes that memory only, never persistent storage.
 *
 * Reset reasons (udsota_reset_reason_t; each port maps its platform's own):
 *   clear the count   POWERON; an invalid magic (first power-up, RTC lost) also starts from 0
 *   leave it          SW (the device's own restart: keyed 11 01, ActivateImage) and EXT (reset pin,
 *                     deep-sleep wake, SDIO, USB, JTAG): deliberate resets a technician or tool makes
 *   add one           PANIC, WDT, BROWNOUT, OTHER, and any value outside the enum
 * Reaching healthy (the app's health check) also clears it.
 *
 * The port stores the state and reports the decision (status flag UDSOTA_STATUS_BOOT_IGNORED_CONFIG); the
 * app decides which stored config to skip while the flag is set. */
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define UDSOTA_BOOTLOOP_MAGIC      0xB0071007u   /* marks the RTC state as ours; anything else reads as count 0 */
#define UDSOTA_BOOTLOOP_THRESHOLD  3u            /* crash resets since power-on/healthy that make a boot ignore config */

/* This boot's reset reason as the breaker sorts it; OTHER is 0, so an unmapped or zeroed value counts as a crash. */
typedef enum {
    UDSOTA_RST_OTHER = 0,     /* unknown or any other cause: adds one */
    UDSOTA_RST_POWERON,       /* a real power cycle: clears the count */
    UDSOTA_RST_SW,            /* a restart the device asked for itself: leaves it */
    UDSOTA_RST_EXT,           /* a deliberate outside reset (pin, deep-sleep wake, SDIO, USB, JTAG): leaves it */
    UDSOTA_RST_PANIC,         /* adds one */
    UDSOTA_RST_WDT,           /* any watchdog: adds one */
    UDSOTA_RST_BROWNOUT,      /* adds one */
} udsota_reset_reason_t;

typedef struct {
    uint32_t magic;                       /* UDSOTA_BOOTLOOP_MAGIC once written by this code */
    uint32_t count;                       /* crash resets since the last power-on or healthy mark */
} udsota_bootloop_state_t;

typedef struct {
    bool ignore_config;                   /* count >= UDSOTA_BOOTLOOP_THRESHOLD: run this boot on defaults */
    bool cleared;                         /* this call reset count to 0 (power-on or invalid magic) */
} udsota_bootloop_action_t;

/* ---- Pure (udsota_bootloop.c) ---- */

/* Applies this boot's reset reason to *s per the table above and writes the magic; call once per boot. */
udsota_bootloop_action_t udsota_bootloop_on_boot(udsota_bootloop_state_t *s, udsota_reset_reason_t reason, bool magic_valid);
/* Reaching healthy: clears the count and writes the magic. */
void udsota_bootloop_on_healthy(udsota_bootloop_state_t *s);
/* True when s is non-NULL and holds UDSOTA_BOOTLOOP_MAGIC. */
bool udsota_bootloop_magic_valid(const udsota_bootloop_state_t *s);
