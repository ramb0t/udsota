/* The ESP32 port's choice of 0x27 mode from its config, and the ECDSA mode's sendKey check over the port's
 * device ID. Pure C11 with the verify injected: udsota_esp32_keys.c passes PSA ECDSA over the tester's
 * imported public key; host-tested by test_udsota_esp32_sa. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"
#include "udsota_esp32_devid.h"
#include "udsota_keys.h"

/* The 0x27 security udsota_esp32_start() builds. */
typedef enum {
    UDSOTA_ESP32_SA_OFF = 0,   /* neither key_pubkey nor key_label: 0x27 answers 0x11 */
    UDSOTA_ESP32_SA_HMAC,      /* key_label: keys from K_dev = HMAC(key_master, label || device ID) */
    UDSOTA_ESP32_SA_ECDSA,     /* key_pubkey: signatures under the tester's public key; wins over key_label */
} udsota_esp32_sa_mode_t;

/* ECDSA P-256 verify of sig (r || s) over SHA-256(msg) under the key ctx names: 1 valid, 0 invalid, -1 when
 * it could not check. */
typedef int (*udsota_esp32_sa_verify_fn)(void *ctx, const uint8_t *msg, size_t msg_len,
                                         const uint8_t sig[UDSOTA_KEYS_SIG_LEN]);

/* The mode cfg selects: ECDSA when key_pubkey is set, else HMAC when key_label is set, else off. *master_ignored
 * (master_ignored may be NULL) is true when the ECDSA mode wins over a key_master that is then never used. */
udsota_esp32_sa_mode_t udsota_esp32_sa_mode(const udsota_config_t *cfg, bool *master_ignored);
/* True for UDSOTA_KEYS_PUBKEY_LEN bytes in the uncompressed form (first byte 0x04); whether the point is on
 * P-256 is PSA's import to check. */
bool udsota_esp32_sa_pubkey_ok(const uint8_t *pubkey, size_t len);
/* The ECDSA mode's sendKey check: key must be a UDSOTA_KEYS_SIG_LEN-byte signature over udsota_keys_sig_msg()
 * of seed, the requestSeed level and d's ID. Returns verify's answer (1 valid, 0 invalid, any negative as -1);
 * 0 for a key of another length; -1 without verify, before d's ID is fixed, for a MAC ID whose read failed or
 * for a level the message refuses. */
int udsota_esp32_sa_check(const udsota_esp32_devid_t *d, udsota_esp32_sa_verify_fn verify, void *ctx,
                          const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level, const uint8_t *key,
                          size_t key_len);
