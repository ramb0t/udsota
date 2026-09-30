/* The ESP32 port's 0x27 mode choice and the ECDSA mode's sendKey check (udsota_esp32_sa.h). Pure C11, no ESP-IDF. */
#include <stdatomic.h>
#include "udsota_esp32_sa.h"

/* See udsota_esp32_sa.h. */
udsota_esp32_sa_mode_t udsota_esp32_sa_mode(const udsota_config_t *cfg, bool *master_ignored)
{
    const udsota_esp32_sa_mode_t mode = (cfg == NULL)               ? UDSOTA_ESP32_SA_OFF
                                        : (cfg->key_pubkey != NULL) ? UDSOTA_ESP32_SA_ECDSA
                                        : (cfg->key_label != NULL)  ? UDSOTA_ESP32_SA_HMAC
                                                                    : UDSOTA_ESP32_SA_OFF;
    if (master_ignored != NULL) {
        *master_ignored = (mode == UDSOTA_ESP32_SA_ECDSA && cfg->key_master != NULL);
    }
    return mode;
}

/* See udsota_esp32_sa.h. */
bool udsota_esp32_sa_pubkey_ok(const uint8_t *pubkey, size_t len)
{
    return pubkey != NULL && len == UDSOTA_KEYS_PUBKEY_LEN && pubkey[0] == 0x04u;
}

/* See udsota_esp32_sa.h. */
int udsota_esp32_sa_check(const udsota_esp32_devid_t *d, udsota_esp32_sa_verify_fn verify, void *ctx,
                          const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level, const uint8_t *key,
                          size_t key_len)
{
    if (verify == NULL || d == NULL || !atomic_load_explicit(&d->fixed, memory_order_acquire) ||
        (d->is_mac && !d->mac_ok)) {
        return -1;
    }
    if (key == NULL || key_len != UDSOTA_KEYS_SIG_LEN) {
        return 0;
    }
    uint8_t msg[UDSOTA_KEYS_SIG_MSG_MAX];
    const size_t n = udsota_keys_sig_msg(seed, level, d->id, d->id_len, msg);
    if (n == 0u) {
        return -1;
    }
    const int verdict = verify(ctx, msg, n, key);
    return (verdict < 0) ? -1 : (verdict == 1 ? 1 : 0);
}
