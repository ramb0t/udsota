/* Default 0x27 key derivation (pure): K_dev = HMAC-SHA256(master, label || device_id) and
 * key = first 16 bytes of HMAC-SHA256(K_dev, seed || level || device_id). The HMAC is injected:
 * udsota_esp32_keys.c passes PSA HMAC-SHA256, the host tests a fake. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDSOTA_KEYS_KDEV_LEN   32
#define UDSOTA_KEYS_SEED_LEN   16
#define UDSOTA_KEYS_KEY_LEN    16
#define UDSOTA_KEYS_HMAC_LEN   32
#define UDSOTA_KEYS_LABEL_MAX  32   /* longest label, in bytes without its terminator */
#define UDSOTA_KEYS_ID_MAX     16   /* longest device ID */

/* HMAC-SHA256(key, msg) into out[32]; returns false on any crypto failure. */
typedef bool (*udsota_hmac_fn)(const uint8_t *key, size_t key_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t out[UDSOTA_KEYS_HMAC_LEN]);

/* K_dev = HMAC-SHA256(master, label || id): the label without its terminator, then id_len ID bytes.
 * False (kdev zeroed, no HMAC call) on a NULL argument, master_len 0, a label over UDSOTA_KEYS_LABEL_MAX
 * or id_len over UDSOTA_KEYS_ID_MAX; false (kdev zeroed) on an HMAC failure. */
bool udsota_keys_derive_kdev(udsota_hmac_fn hmac, const uint8_t *master, size_t master_len, const char *label,
                             const uint8_t *id, size_t id_len, uint8_t kdev[UDSOTA_KEYS_KDEV_LEN]);

/* Expected key = first 16 bytes of HMAC-SHA256(kdev, seed || level || id). level is the requestSeed byte:
 * odd, 0x01..0x7D (0x7F's sendKey would carry the suppress bit); anything else, a NULL argument or id_len over UDSOTA_KEYS_ID_MAX returns false with key
 * zeroed and no HMAC call. */
bool udsota_keys_derive_key(udsota_hmac_fn hmac, const uint8_t kdev[UDSOTA_KEYS_KDEV_LEN],
                            const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                            const uint8_t *id, size_t id_len, uint8_t key[UDSOTA_KEYS_KEY_LEN]);

/* Known-answer test of hmac and both derivations: RFC 4231 TC2, then master 00..1F, label "udsota-kat",
 * ID 02 00 00 00 00 01 and seed 10..1F at levels 0x01 and 0x03. True only if every byte matches. */
bool udsota_keys_self_test(udsota_hmac_fn hmac);
