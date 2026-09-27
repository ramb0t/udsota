/* Minimal SHA-256 (FIPS 180-4) for host tools and tests, so fake_engine needs no crypto library.
 * Not constant-time and not for firmware: the ESP32 port uses PSA. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Writes SHA-256(data[0..len)) to out. False only when data is NULL with len > 0, or out is NULL. */
bool sha256_host(const uint8_t *data, size_t len, uint8_t out[32]);
