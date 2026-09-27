/* 0x27 security for the udsota ESP32 port (udsota_esp32.h): seeds from the hardware RNG, and keys from the
 * core's default derivation (udsota_keys.h) over PSA HMAC-SHA256. The device ID they hash is fixed once,
 * cfg.device_id when set and else the base MAC, and kept in s_dev (udsota_esp32_devid.h), which F18C
 * serves too. The SAR-ADC entropy source is switched on at the first udsota_esp32_security() call and
 * never off, so esp_fill_random() is a true RNG (IDF random.rst: an app that uses no ADC, Wi-Fi or BT may leave it on).
 * Start code, then the server's task, call the security functions, which the PSA lock serialises.
 * udsota_esp32_device_id() may run on any task: it reads the base MAC and the fixed ID behind their
 * release/acquire flags. */
#include <stdatomic.h>
#include <string.h>
#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "udsota_esp32.h"
#include "udsota_esp32_devid.h"
#include "udsota_esp32_priv.h"
#include "udsota_keys.h"

static const char *TAG = "udsota_keys";

#define SEED_DRAWS   4     /* redraws allowed before a seed request fails */
#define KEY_LOCK_MS  40u   /* key()'s wait for the PSA lock, inside P2: only an orphaned worker verify holds it longer */

static bool                 s_inited;
static bool                 s_rng_on;
static atomic_bool          s_mac_read;   /* stored last (release): s_mac and s_mac_ok are filled in */
static bool                 s_mac_ok;
static uint8_t              s_mac[UDSOTA_ESP32_DEVICE_ID_LEN];
static udsota_esp32_devid_t s_dev;        /* the ID in use, fixed once, and its K_dev */
static uint8_t              s_last_seed[UDSOTA_KEYS_SEED_LEN];

/* HMAC-SHA256 through PSA with a volatile key imported for this call and destroyed (PSA wipes its copy)
 * after it. On any failure, including a failed destroy, out is zeroed and false returned. */
static bool psa_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                            uint8_t out[UDSOTA_KEYS_HMAC_LEN])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t st = psa_import_key(&attr, key, key_len, &id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key: %d", (int)st);
        mbedtls_platform_zeroize(out, UDSOTA_KEYS_HMAC_LEN);
        return false;
    }
    size_t n = 0;
    st = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len, out, UDSOTA_KEYS_HMAC_LEN, &n);
    const psa_status_t dst = psa_destroy_key(id);
    if (st != PSA_SUCCESS || n != UDSOTA_KEYS_HMAC_LEN || dst != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_mac_compute: %d (len %u), psa_destroy_key: %d", (int)st, (unsigned)n, (int)dst);
        mbedtls_platform_zeroize(out, UDSOTA_KEYS_HMAC_LEN);
        return false;
    }
    return true;
}

/* True when all n bytes of p are zero. */
static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

/* The base MAC, read into a local and published with a release store; all-zero if the read failed. Two
 * first callers racing both read it and store the same bytes. */
static const uint8_t *base_mac(void)
{
    if (!atomic_load_explicit(&s_mac_read, memory_order_acquire)) {
        uint8_t mac[UDSOTA_ESP32_DEVICE_ID_LEN];
        const esp_err_t err = esp_read_mac(mac, ESP_MAC_BASE);
        if (err != ESP_OK) {
            memset(mac, 0, sizeof mac);
            ESP_LOGE(TAG, "esp_read_mac: %s", esp_err_to_name(err));
        }
        memcpy(s_mac, mac, sizeof s_mac);
        s_mac_ok = (err == ESP_OK);
        atomic_store_explicit(&s_mac_read, true, memory_order_release);
    }
    return s_mac;
}

/* Fixes the device ID once; see udsota_esp32_priv.h. */
udsota_esp32_devid_fix_t udsota_esp32_id_fix(const uint8_t *id, size_t id_len, const udsota_esp32_devid_t **dev)
{
    const uint8_t *mac = base_mac();
    if (dev != NULL) {
        *dev = &s_dev;
    }
    return udsota_esp32_devid_fix(&s_dev, id, id_len, mac, s_mac_ok);
}

/* The fixed device ID, or the base MAC while none is fixed; see udsota_esp32.h. */
const uint8_t *udsota_esp32_device_id(size_t *len)
{
    if (atomic_load_explicit(&s_dev.fixed, memory_order_acquire)) {
        if (len != NULL) {
            *len = s_dev.id_len;
        }
        return s_dev.id;
    }
    if (len != NULL) {
        *len = UDSOTA_ESP32_DEVICE_ID_LEN;
    }
    return base_mac();
}

/* udsota_security_t.rng16: 16 fresh bytes, never all-zero and never the previous seed; false (zeroed) otherwise. */
static bool sec_rng16(void *ctx, uint8_t out[UDSOTA_KEYS_SEED_LEN])
{
    (void)ctx;
    if (out == NULL) {
        return false;
    }
    if (s_rng_on) {
        for (int i = 0; i < SEED_DRAWS; i++) {
            esp_fill_random(out, UDSOTA_KEYS_SEED_LEN);
            if (!all_zero(out, UDSOTA_KEYS_SEED_LEN) && memcmp(out, s_last_seed, UDSOTA_KEYS_SEED_LEN) != 0) {
                memcpy(s_last_seed, out, UDSOTA_KEYS_SEED_LEN);
                return true;
            }
        }
        ESP_LOGE(TAG, "RNG gave %d unusable seeds in a row", SEED_DRAWS);
    }
    memset(out, 0, UDSOTA_KEYS_SEED_LEN);
    return false;
}

/* udsota_security_t.key: the expected key for seed at requestSeed level, under the PSA lock. False (key
 * zeroed) without K_dev, on a derivation failure, or when the lock stays busy for KEY_LOCK_MS. */
static bool sec_key(void *ctx, const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                    uint8_t out[UDSOTA_KEYS_KEY_LEN])
{
    (void)ctx;
    if (out == NULL) {
        return false;
    }
    if (!s_dev.kdev_ok || !udsota_esp32_psa_lock(KEY_LOCK_MS)) {
        memset(out, 0, UDSOTA_KEYS_KEY_LEN);
        return false;
    }
    const bool ok = udsota_esp32_devid_key(&s_dev, psa_hmac_sha256, seed, level, out);
    udsota_esp32_psa_unlock();
    return ok;
}

static const udsota_security_t s_security = { .rng16 = sec_rng16, .key = sec_key, .ctx = NULL };

/* Switches the RNG on, fixes the device ID, self-tests PSA HMAC and derives K_dev once; see udsota_esp32.h. */
const udsota_security_t *udsota_esp32_security(const char *label, const uint8_t *master, size_t master_len,
                                               const uint8_t *id, size_t id_len)
{
    if (label == NULL) {
        return NULL;
    }
    if (s_inited) {
        return &s_security;
    }
    s_inited = true;
    udsota_esp32_psa_lock_init();
    bootloader_random_enable();              /* never disabled; the README gives the ADC/Wi-Fi/BT caveat */
    s_rng_on = true;
    /* From here on security is on; every early return leaves no key that can match. */
    if (udsota_esp32_id_fix(id, id_len, NULL) == UDSOTA_ESP32_DEVID_BAD) {
        ESP_LOGE(TAG, "device ID of %u B (1 to %d allowed); 0x27 unlock disabled", (unsigned)id_len,
                 UDSOTA_KEYS_ID_MAX);
        return &s_security;
    }
    if (s_dev.is_mac && !s_dev.mac_ok) {
        ESP_LOGE(TAG, "no base MAC for the device ID; 0x27 unlock disabled");
        return &s_security;
    }
    if (master == NULL || master_len == 0u) {
        return &s_security;
    }
    (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);
    const bool ok = udsota_keys_self_test(psa_hmac_sha256) &&
                    udsota_esp32_devid_derive_kdev(&s_dev, psa_hmac_sha256, master, master_len, label);
    udsota_esp32_psa_unlock();
    if (!ok) {
        s_dev.kdev_ok = false;
        mbedtls_platform_zeroize(s_dev.kdev, sizeof s_dev.kdev);
        ESP_LOGE(TAG, "HMAC self-test or K_dev derivation failed; 0x27 unlock disabled");
        return &s_security;
    }
    ESP_LOGD(TAG, "0x27 keys ready");
    return &s_security;
}
