/* HMAC-SHA256 (RFC 2104) on sha256_host, for udsota_lite_server's 0x27 keys (udsota_plat_hmac). Host only: not
 * constant-time and not for firmware, where the ESP32 port uses PSA. From udsota main 0.13.0
 * (tools/linux_server/hmac_sha256_host.h), MIT, the same project. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Writes HMAC-SHA256(key, msg) to out. False on a NULL pointer with a non-zero length, a NULL out, or no memory. */
bool hmac_sha256_host(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);
