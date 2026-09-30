/* The ESP32 port's start for a UDS server the app runs (udsota_esp32.h): the device ID, 0x27 security and the
 * engine, in that order, as udsota_esp32_start() did before the server moved out of udsota. */
#include <stdbool.h>
#include "esp_err.h"
#include "esp_log.h"
#include "udsota_esp32.h"
#include "udsota_esp32_devid.h"
#include "udsota_esp32_priv.h"
#include "udsota_esp32_sa.h"

static const char *TAG = "udsota";

/* See udsota_esp32.h. */
esp_err_t udsota_esp32_updater_start(const udsota_config_t *cfg, void (*wake)(void), udsota_esp32_updater_t *out)
{
    static bool started;
    if (cfg == NULL || out == NULL || !udsota_esp32_devid_len_ok(cfg->device_id, cfg->device_id_len) ||
        (cfg->key_pubkey != NULL && !udsota_esp32_sa_pubkey_ok(cfg->key_pubkey, cfg->key_pubkey_len))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (started) {
        return ESP_ERR_INVALID_STATE;
    }
    started = true;
    /* Fixed before security, which then hashes it; an ID an earlier udsota_esp32_security() call fixed wins. */
    const udsota_esp32_devid_t *dev = NULL;
    if (udsota_esp32_id_fix(cfg->device_id, cfg->device_id_len, &dev) == UDSOTA_ESP32_DEVID_OTHER) {
        ESP_LOGW(TAG, "cfg.device_id ignored: udsota_esp32_security() already fixed another device ID");
    }
    udsota_esp32_psa_lock_init();                /* before the first PSA user, security on or off */
    bool master_ignored = false;
    const udsota_esp32_sa_mode_t mode = udsota_esp32_sa_mode(cfg, &master_ignored);
    if (master_ignored) {
        ESP_LOGW(TAG, "cfg.key_master ignored: cfg.key_pubkey selects the ECDSA mode; leave the master out");
    }
    out->security =
        (mode == UDSOTA_ESP32_SA_ECDSA) ? udsota_esp32_security_ecdsa(cfg->key_pubkey, cfg->key_pubkey_len,
                                                                      cfg->device_id, cfg->device_id_len)
        : (mode == UDSOTA_ESP32_SA_HMAC) ? udsota_esp32_security(cfg->key_label, cfg->key_master,
                                                                 cfg->key_master_len, cfg->device_id,
                                                                 cfg->device_id_len)
        : NULL;
    if (out->security == NULL) {
        ESP_LOGW(TAG, "security off: any tester on the bus may program this unit");
    }
    out->device_id = udsota_esp32_device_id(&out->device_id_len);
    udsota_esp32_engine_start(cfg, wake);
    out->engine = udsota_esp32_engine();
    return ESP_OK;
}

/* See udsota_esp32_priv.h. The incoming-version snapshot lived in the removed diag task's control block. */
void udsota_esp32_first_block_checked(udsota_reason_t r, const uint8_t *first, size_t len)
{
    (void)r;
    (void)first;
    (void)len;
}

/* See udsota_esp32_priv.h. */
void udsota_esp32_zbegin_refused(void)
{
}
