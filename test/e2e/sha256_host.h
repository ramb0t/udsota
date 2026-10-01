/* Minimal SHA-256 (FIPS 180-4) for udsota_lite_server's image checks, config hash and HMAC, so it needs no crypto
 * library. Not constant-time and not for firmware: the ESP32 port uses PSA. From udsota main 0.13.0
 * (components/udsota/test/sha256_host.h), MIT, the same project. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Writes SHA-256(data[0..len)) to out. False only when data is NULL with len > 0, or out is NULL. */
bool sha256_host(const uint8_t *data, size_t len, uint8_t out[32]);
