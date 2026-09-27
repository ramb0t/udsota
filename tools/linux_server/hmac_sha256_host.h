/* HMAC-SHA256 (RFC 2104) on sha256_host, for the Linux demo server's 0x27 keys. Host only: not
 * constant-time and not for firmware, where the ESP32 port uses PSA. Its signature is udsota_hmac_fn. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Writes HMAC-SHA256(key, msg) to out. False on a NULL pointer with a non-zero length, a NULL out, or no memory. */
bool hmac_sha256_host(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);
