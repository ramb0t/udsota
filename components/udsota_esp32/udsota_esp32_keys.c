/* 0x27 security for the udsota ESP32 port (udsota_esp32.h): seeds from the hardware RNG, and either keys
 * from the core's default derivation (udsota_keys.h) over PSA HMAC-SHA256, or, in the ECDSA mode, a PSA
 * ECDSA P-256 verify of the tester's signature under its public key, imported once. The device ID they hash
 * is fixed once, cfg.device_id when set and else the base MAC, and kept in s_dev (udsota_esp32_devid.h),
 * which F18C serves too. The SAR-ADC entropy source is switched on at the first udsota_esp32_security() or
 * udsota_esp32_security_ecdsa() call and never off, so esp_fill_random() is a true RNG (IDF random.rst: an
 * app that uses no ADC, Wi-Fi or BT may leave it on). The first of those calls fixes the mode.
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
#include "udsota_esp32_sa.h"
#include "udsota_keys.h"

static const char *TAG = "udsota_keys";

#define SEED_DRAWS   4     /* redraws allowed before a seed request fails */
#define KEY_LOCK_MS  40u   /* key()'s and verify()'s wait for the PSA lock, inside P2: only an orphaned worker verify
                              holds it longer */

static bool                 s_inited;
static bool                 s_rng_on;
static atomic_bool          s_mac_read;   /* stored last (release): s_mac and s_mac_ok are filled in */
static bool                 s_mac_ok;
static uint8_t              s_mac[UDSOTA_ESP32_DEVICE_ID_LEN];
static udsota_esp32_devid_t s_dev;        /* the ID in use, fixed once, and its K_dev */
static uint8_t              s_last_seed[UDSOTA_KEYS_SEED_LEN];
static psa_key_id_t         s_pub;        /* ECDSA mode: the tester's public key, imported once */
static bool                 s_pub_ok;     /* s_pub imported and the ECDSA self-test passed */
static const udsota_security_t *s_sec;    /* the mode the first call fixed: s_security or s_security_ecdsa */

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

/* Imports pubkey (UDSOTA_KEYS_PUBKEY_LEN bytes, 04 || X || Y) as a volatile P-256 public key for
 * ECDSA(SHA-256) hash verifies; PSA checks the point is on the curve. PSA_KEY_ID_NULL on a failure. */
static psa_key_id_t psa_import_pubkey(const uint8_t *pubkey)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    const psa_status_t st = psa_import_key(&attr, pubkey, UDSOTA_KEYS_PUBKEY_LEN, &id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key (P-256 public key): %d", (int)st);
        return PSA_KEY_ID_NULL;
    }
    return id;
}

/* ECDSA P-256 verify through PSA of sig (r || s) over SHA-256(msg) under key id: 1 valid, 0 for any verify
 * failure (so that no signature can dodge the attempt count), -1 when the hash fails. */
static int psa_ecdsa_verify_id(psa_key_id_t id, const uint8_t *msg, size_t msg_len,
                               const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t n = 0;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof hash, &n);
    if (st != PSA_SUCCESS || n != sizeof hash) {
        ESP_LOGE(TAG, "psa_hash_compute: %d (len %u)", (int)st, (unsigned)n);
        return -1;
    }
    st = psa_verify_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, n, sig, UDSOTA_KEYS_SIG_LEN);
    if (st != PSA_SUCCESS && st != PSA_ERROR_INVALID_SIGNATURE) {
        ESP_LOGW(TAG, "psa_verify_hash: %d", (int)st);
    }
    /* A failure no signature can cause (memory, hardware, state) is no verdict (0x22, not an attempt), so a
     * valid key under heap pressure is never counted wrong; anything a signature can cause counts. */
    if (st == PSA_ERROR_INSUFFICIENT_MEMORY || st == PSA_ERROR_HARDWARE_FAILURE || st == PSA_ERROR_BAD_STATE ||
        st == PSA_ERROR_COMMUNICATION_FAILURE || st == PSA_ERROR_CORRUPTION_DETECTED) {
        return -1;
    }
    return (st == PSA_SUCCESS) ? 1 : 0;
}

/* udsota_ecdsa_verify_fn for the self-test: pubkey imported for this call and destroyed after it; -1 when the
 * import or the destroy fails. */
static int psa_ecdsa_verify_pub(const uint8_t *pubkey, const uint8_t *msg, size_t msg_len,
                                const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    const psa_key_id_t id = psa_import_pubkey(pubkey);
    if (id == PSA_KEY_ID_NULL) {
        return -1;
    }
    const int verdict = psa_ecdsa_verify_id(id, msg, msg_len, sig);
    const psa_status_t dst = psa_destroy_key(id);
    if (dst != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_destroy_key: %d", (int)dst);
        return -1;
    }
    return verdict;
}

/* udsota_esp32_sa_verify_fn over the tester's imported key, which ctx points at. */
static int sig_verify(void *ctx, const uint8_t *msg, size_t msg_len, const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    return psa_ecdsa_verify_id(*(const psa_key_id_t *)ctx, msg, msg_len, sig);
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

/* udsota_security_t.verify (the ECDSA mode): checks the signature under the tester's key, under the PSA lock.
 * -1 (no verdict) without the key, or when the lock stays busy for KEY_LOCK_MS. */
static int sec_verify(void *ctx, const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level, const uint8_t *key,
                      size_t key_len)
{
    (void)ctx;
    if (!s_pub_ok || !udsota_esp32_psa_lock(KEY_LOCK_MS)) {
        return -1;
    }
    const int verdict = udsota_esp32_sa_check(&s_dev, sig_verify, &s_pub, seed, level, key, key_len);
    udsota_esp32_psa_unlock();
    return verdict;
}

static const udsota_security_t s_security = { .rng16 = sec_rng16, .key = sec_key, .ctx = NULL };
static const udsota_security_t s_security_ecdsa = {
    .rng16 = sec_rng16, .key = NULL, .ctx = NULL, .verify = sec_verify, .key_len = UDSOTA_KEYS_SIG_LEN,
};

/* The first call's shared start: fixes the mode as sec, switches the RNG on and fixes the device ID. True
 * when the ID can be hashed; false (logged) leaves security on with no key that can match. */
static bool security_begin(const udsota_security_t *sec, const uint8_t *id, size_t id_len)
{
    s_inited = true;
    s_sec = sec;
    udsota_esp32_psa_lock_init();
    bootloader_random_enable();              /* never disabled; the README gives the ADC/Wi-Fi/BT caveat */
    s_rng_on = true;
    /* From here on security is on; every early return leaves no key that can match. */
    if (udsota_esp32_id_fix(id, id_len, NULL) == UDSOTA_ESP32_DEVID_BAD) {
        ESP_LOGE(TAG, "device ID of %u B (1 to %d allowed); 0x27 unlock disabled", (unsigned)id_len,
                 UDSOTA_KEYS_ID_MAX);
        return false;
    }
    if (s_dev.is_mac && !s_dev.mac_ok) {
        ESP_LOGE(TAG, "no base MAC for the device ID; 0x27 unlock disabled");
        return false;
    }
    return true;
}

/* Switches the RNG on, fixes the device ID, self-tests PSA ECDSA and imports the tester's key once; see
 * udsota_esp32.h. */
const udsota_security_t *udsota_esp32_security_ecdsa(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *id,
                                                     size_t id_len)
{
    if (pubkey == NULL) {
        return NULL;
    }
    if (s_inited) {
        return s_sec;
    }
    if (!security_begin(&s_security_ecdsa, id, id_len)) {
        return s_sec;
    }
    if (!udsota_esp32_sa_pubkey_ok(pubkey, pubkey_len)) {
        ESP_LOGE(TAG, "public key of %u B is not a %d-byte uncompressed P-256 point; 0x27 unlock disabled",
                 (unsigned)pubkey_len, UDSOTA_KEYS_PUBKEY_LEN);
        return s_sec;
    }
    (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);
    const bool kat = udsota_keys_sig_self_test(psa_ecdsa_verify_pub);
    s_pub = kat ? psa_import_pubkey(pubkey) : PSA_KEY_ID_NULL;
    udsota_esp32_psa_unlock();
    if (!kat) {
        ESP_LOGE(TAG, "ECDSA self-test failed; 0x27 unlock disabled");
        return s_sec;
    }
    if (s_pub == PSA_KEY_ID_NULL) {
        ESP_LOGE(TAG, "public key refused by PSA (not a P-256 point); 0x27 unlock disabled");
        return s_sec;
    }
    s_pub_ok = true;
    ESP_LOGD(TAG, "0x27 ECDSA key ready");
    return s_sec;
}

/* Switches the RNG on, fixes the device ID, self-tests PSA HMAC and derives K_dev once; see udsota_esp32.h. */
const udsota_security_t *udsota_esp32_security(const char *label, const uint8_t *master, size_t master_len,
                                               const uint8_t *id, size_t id_len)
{
    if (label == NULL) {
        return NULL;
    }
    if (s_inited) {
        return s_sec;
    }
    if (!security_begin(&s_security, id, id_len)) {
        return s_sec;
    }
    if (master == NULL || master_len == 0u) {
        return s_sec;
    }
    (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);
    const bool ok = udsota_keys_self_test(psa_hmac_sha256) &&
                    udsota_esp32_devid_derive_kdev(&s_dev, psa_hmac_sha256, master, master_len, label);
    udsota_esp32_psa_unlock();
    if (!ok) {
        s_dev.kdev_ok = false;
        mbedtls_platform_zeroize(s_dev.kdev, sizeof s_dev.kdev);
        ESP_LOGE(TAG, "HMAC self-test or K_dev derivation failed; 0x27 unlock disabled");
        return s_sec;
    }
    ESP_LOGD(TAG, "0x27 keys ready");
    return s_sec;
}
