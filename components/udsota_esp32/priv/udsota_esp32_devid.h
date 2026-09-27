/* The ESP32 port's device ID and the K_dev derived from it. F18C serves the stored ID and the 0x27 key
 * hashes the same stored bytes, so the two cannot disagree. Pure C11 with the HMAC injected:
 * udsota_esp32_keys.c keeps one instance and passes PSA HMAC-SHA256; host-tested by test_udsota_esp32_devid. */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"
#include "udsota_esp32.h"
#include "udsota_keys.h"

typedef struct {
    uint8_t     id[UDSOTA_KEYS_ID_MAX];     /* the ID in use */
    size_t      id_len;                     /* 0 until fixed */
    bool        is_mac;                     /* the ID is the base MAC */
    bool        mac_ok;                     /* the base MAC read succeeded (no key over a failed one) */
    uint8_t     kdev[UDSOTA_KEYS_KDEV_LEN];
    bool        kdev_ok;                    /* K_dev derived over id */
    atomic_bool fixed;                      /* stored last (release), so a reader that sees it sees the ID */
} udsota_esp32_devid_t;

/* What udsota_esp32_devid_fix() did. */
typedef enum {
    UDSOTA_ESP32_DEVID_BAD = 0,   /* bad length, or no ID and no MAC: nothing changed */
    UDSOTA_ESP32_DEVID_FIXED,     /* this call fixed the ID */
    UDSOTA_ESP32_DEVID_KEPT,      /* already fixed to the same bytes */
    UDSOTA_ESP32_DEVID_OTHER,     /* already fixed to other bytes, which stay */
} udsota_esp32_devid_fix_t;

/* True when id is NULL (the base MAC; id_len ignored) or has 1..UDSOTA_KEYS_ID_MAX bytes. */
bool udsota_esp32_devid_len_ok(const uint8_t *id, size_t id_len);
/* Fixes d's ID once: a copy of id, or of the UDSOTA_ESP32_DEVICE_ID_LEN-byte mac when id is NULL or is mac
 * itself (udsota_esp32_device_id()'s pointer handed back), with mac_ok recorded for that case. Later calls
 * change nothing and say whether they asked for the same bytes. d starts zeroed. One writer at a time. */
udsota_esp32_devid_fix_t udsota_esp32_devid_fix(udsota_esp32_devid_t *d, const uint8_t *id, size_t id_len,
                                               const uint8_t *mac, bool mac_ok);
/* Derives K_dev = HMAC(master, label || d's ID) into d; false (K_dev zeroed) before the ID is fixed, for a
 * MAC ID whose read failed, or on a derivation failure (udsota_keys_derive_kdev). */
bool udsota_esp32_devid_derive_kdev(udsota_esp32_devid_t *d, udsota_hmac_fn hmac, const uint8_t *master,
                                    size_t master_len, const char *label);
/* The expected key for seed at requestSeed level over d's K_dev and ID; false (key zeroed) without K_dev
 * or on a derivation failure (udsota_keys_derive_key). */
bool udsota_esp32_devid_key(const udsota_esp32_devid_t *d, udsota_hmac_fn hmac,
                            const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                            uint8_t key[UDSOTA_KEYS_KEY_LEN]);
/* Points cfg's device_id at d's stored ID, so F18C serves exactly the bytes the key hashes. */
void udsota_esp32_devid_serve(const udsota_esp32_devid_t *d, udsota_config_t *cfg);
