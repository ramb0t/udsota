/* The ESP32 port's device ID and K_dev (udsota_esp32_devid.h). Pure C11, no ESP-IDF. */
#include <string.h>
#include "udsota_esp32_devid.h"

_Static_assert(UDSOTA_ESP32_DEVICE_ID_LEN <= UDSOTA_KEYS_ID_MAX, "the base MAC fits the derivation's ID");

/* See udsota_esp32_devid.h. */
bool udsota_esp32_devid_len_ok(const uint8_t *id, size_t id_len)
{
    return id == NULL || (id_len >= 1u && id_len <= UDSOTA_KEYS_ID_MAX);
}

/* See udsota_esp32_devid.h. */
udsota_esp32_devid_fix_t udsota_esp32_devid_fix(udsota_esp32_devid_t *d, const uint8_t *id, size_t id_len,
                                               const uint8_t *mac, bool mac_ok)
{
    if (id != NULL && id == mac) {
        id = NULL;                          /* the MAC pointer handed back: the MAC case */
    }
    if (d == NULL || !udsota_esp32_devid_len_ok(id, id_len) || (id == NULL && mac == NULL)) {
        return UDSOTA_ESP32_DEVID_BAD;
    }
    const uint8_t *src = (id != NULL) ? id : mac;
    const size_t n = (id != NULL) ? id_len : UDSOTA_ESP32_DEVICE_ID_LEN;
    if (atomic_load_explicit(&d->fixed, memory_order_acquire)) {
        return (n == d->id_len && memcmp(src, d->id, n) == 0) ? UDSOTA_ESP32_DEVID_KEPT : UDSOTA_ESP32_DEVID_OTHER;
    }
    memcpy(d->id, src, n);
    d->id_len = n;
    d->is_mac = (id == NULL);
    d->mac_ok = mac_ok;
    d->kdev_ok = false;
    atomic_store_explicit(&d->fixed, true, memory_order_release);
    return UDSOTA_ESP32_DEVID_FIXED;
}

/* See udsota_esp32_devid.h. */
bool udsota_esp32_devid_derive_kdev(udsota_esp32_devid_t *d, udsota_hmac_fn hmac, const uint8_t *master,
                                    size_t master_len, const char *label)
{
    if (d == NULL) {
        return false;
    }
    d->kdev_ok = false;
    if (!atomic_load_explicit(&d->fixed, memory_order_acquire) || (d->is_mac && !d->mac_ok)) {
        memset(d->kdev, 0, sizeof d->kdev);
        return false;
    }
    d->kdev_ok = udsota_keys_derive_kdev(hmac, master, master_len, label, d->id, d->id_len, d->kdev);
    return d->kdev_ok;
}

/* See udsota_esp32_devid.h. */
bool udsota_esp32_devid_key(const udsota_esp32_devid_t *d, udsota_hmac_fn hmac,
                            const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                            uint8_t key[UDSOTA_KEYS_KEY_LEN])
{
    if (key == NULL) {
        return false;
    }
    if (d == NULL || !d->kdev_ok) {
        memset(key, 0, UDSOTA_KEYS_KEY_LEN);
        return false;
    }
    return udsota_keys_derive_key(hmac, d->kdev, seed, level, d->id, d->id_len, key);
}

/* See udsota_esp32_devid.h. */
void udsota_esp32_devid_serve(const udsota_esp32_devid_t *d, udsota_config_t *cfg)
{
    cfg->device_id = d->id;
    cfg->device_id_len = d->id_len;
}
