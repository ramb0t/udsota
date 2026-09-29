/* 0x27 keys (pure). The HMAC mode, the default: K_dev = HMAC-SHA256(master, label || device_id) and
 * key = first 16 bytes of HMAC-SHA256(K_dev, seed || level || device_id). The HMAC is injected:
 * udsota_esp32_keys.c passes PSA HMAC-SHA256, the host tests a fake.
 * The ECDSA mode: the key is a P-256 ECDSA signature, made by the tester's private key, over SHA-256 of the
 * message udsota_keys_sig_msg() builds; the device holds only the public key, so nothing it stores unlocks it or
 * any other device. The verify is injected: udsota_esp32_keys.c passes PSA ECDSA. */
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

/* ---- The ECDSA mode ---- */

#define UDSOTA_KEYS_SIG_TAG      "udsota-27-ecdsa-v1"   /* the message's first bytes, without a terminator */
#define UDSOTA_KEYS_SIG_TAG_LEN  18
#define UDSOTA_KEYS_SIG_MSG_MAX  (UDSOTA_KEYS_SIG_TAG_LEN + UDSOTA_KEYS_SEED_LEN + 2 + UDSOTA_KEYS_ID_MAX)   /* 52 */
#define UDSOTA_KEYS_SIG_LEN      64   /* the sendKey key: the signature as r || s, 32 big-endian bytes each */
#define UDSOTA_KEYS_PUBKEY_LEN   65   /* the public key: an uncompressed SEC1 point, 04 || X || Y */

/* ECDSA P-256 verify of sig (r || s) over SHA-256(msg) under pubkey (UDSOTA_KEYS_PUBKEY_LEN bytes): 1 valid,
 * 0 invalid, -1 when it could not check. */
typedef int (*udsota_ecdsa_verify_fn)(const uint8_t *pubkey, const uint8_t *msg, size_t msg_len,
                                      const uint8_t sig[UDSOTA_KEYS_SIG_LEN]);

/* The signed message, into out: UDSOTA_KEYS_SIG_TAG || seed || level || id_len || id, one byte each for level
 * and id_len. level is the requestSeed byte and id the F18C bytes, so a signature unlocks one level of one
 * device, for one seed. Returns its length (36 + id_len), or 0, writing nothing, on a
 * NULL argument, id_len over UDSOTA_KEYS_ID_MAX or a level udsota_keys_derive_key() refuses. Any S is accepted,
 * low or high: a seed is single-use, so a second valid signature for it gains nothing. */
size_t udsota_keys_sig_msg(const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level, const uint8_t *id,
                           size_t id_len, uint8_t out[UDSOTA_KEYS_SIG_MSG_MAX]);

/* Known-answer test of verify and the message: the udsota_keys_self_test() seed and ID at level 0x03, signed by
 * a published test key (private scalar 01 02 .. 20), must verify, and the same signature over the level-0x01
 * message must not. True only if both hold. */
bool udsota_keys_sig_self_test(udsota_ecdsa_verify_fn verify);
