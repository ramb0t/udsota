/* udsota ESP32 port without CONFIG_UDSOTA_ESP32_UPDATER: the updater's public functions (udsota_esp32.h) as stubs,
 * and the seam call that starts the server alone. Built in place of udsota_esp32_engine.c and udsota_esp32_image.c,
 * so no engine, flash worker, OTA write path (esp_ota_begin/write/end/set_boot_partition) or core updater code is
 * linked; ESP-IDF's own esp_partition still links esp_ota_get_running_partition. udsota_esp32_image_check() has no
 * stub: a caller gets a link error. */
#include <stdbool.h>
#include <stddef.h>

#include "sdkconfig.h"
#include "udsota_esp32.h"
#include "udsota_esp32_priv.h"

/* No engine: what udsota_init() takes as "no updater". */
const udsota_engine_t *udsota_esp32_engine(void)
{
    return NULL;
}

/* Never busy: there is no worker. */
bool udsota_esp32_engine_busy(void)
{
    return false;
}

/* Always false: nothing here reads the OTA state, so this says nothing about an image another updater wrote. With
 * rollback on, that updater confirms it (esp_ota_mark_app_valid_cancel_rollback()). */
bool udsota_esp32_image_unconfirmed(void)
{
    return false;
}

/* No slots (the engine's own value before its boot read) and the flags the port owns, as
 * udsota_esp32_engine.c's status_flags() sets them, so flag 0x02 means the same in both builds. */
void udsota_esp32_status(udsota_status_t *out)
{
    if (out == NULL) {
        return;
    }
    *out = (udsota_status_t){.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE};
#if CONFIG_SECURE_SIGNED_ON_UPDATE
    out->flags |= UDSOTA_STATUS_SIG_CHECKED;
#endif
    if (udsota_esp32_bootloop_reported()) {
        out->flags |= UDSOTA_STATUS_BOOT_IGNORED_CONFIG;
    }
}

/* See udsota_esp32_priv.h: the server alone. udsota_core_init(), never udsota_init() with a NULL engine, which
 * would link the whole updater. There is no worker to wake. */
bool udsota_esp32_server_init(udsota_server_t *srv, const udsota_config_t *cfg, const udsota_security_t *sec,
                              const udsota_hooks_t *hooks, void (*wake)(void))
{
    (void)wake;
    return udsota_core_init(srv, cfg, sec, hooks);
}
