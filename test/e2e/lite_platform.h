/* udsota_lite_server's platform under udsota (the udsota_plat_* functions in udsota.h): two RAM slots that boot as
 * ESP-IDF's bootloader does with rollback on, jobs whose results come 100 ms after they are queued (so iso14229
 * answers 0x78 first, as on the device), the running slot's image as this app's identity, and HMAC-SHA256 keys. No
 * ECDSA. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LITE_SLOT_SIZE 0x1E0000u   /* each slot: the example profile's slot_size */

/* Puts image in slot 0 as the running, confirmed app. False when it is not an ESP-IDF app image whose checksum and
 * appended SHA-256 hold, or it does not fit. */
bool lite_plat_load(const uint8_t *image, size_t len);
/* A reset, before udsota_init: an activated slot boots pending verify, and a running image still pending verify is
 * rolled back to the other slot, which ESP-IDF's bootloader marks aborted. Logs what boots on stderr. */
void lite_plat_boot(unsigned boot_no);
/* Frees the slots. */
void lite_plat_close(void);
