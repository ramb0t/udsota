/* udsota_priv.h: what udsota_esp.c, the ESP-IDF platform, calls back into udsota.c for. Not part of the API: an app
 * does not include it. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"

#define IMAGE_MIN 320u       /* image header 24 + segment header 8 + esp_app_desc_t 256 + descriptor 32 */

/* The image rules on an image's first IMAGE_MIN bytes (or the whole of a smaller image of `size` bytes). */
udsota_reason_t udsota_check_first(const uint8_t *b, size_t len, uint32_t size);
/* Parses "[v]M.m.p" ending in NUL, '-' or '+' within n bytes; *clean: NUL follows, a release. */
bool udsota_parse_version(const char *s, size_t n, uint8_t out[3], bool *clean);
/* Zeroes n bytes where the compiler cannot drop it. */
void udsota_wipe(void *p, size_t n);
/* Creates the PSA lock, before udsota_init's key setup: the platform's. */
void udsota_psa_lock_init(void);
