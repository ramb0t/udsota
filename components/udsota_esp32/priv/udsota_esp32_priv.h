/* Private to components/udsota_esp32: the start hooks udsota_esp32_start() (udsota_esp32.c) calls, and what
 * one port file needs from another. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"
#include "udsota_esp32_devid.h"

/* Creates the PSA mutex in static storage (cannot fail); idempotent. The start code calls it first, with
 * security on or off; udsota_esp32_security() and udsota_esp32_engine_start() call it too. */
void udsota_esp32_psa_lock_init(void);
/* Fixes the port's device ID once (udsota_esp32_devid_fix() over the base MAC): a copy of id when non-NULL
 * (1 to UDSOTA_KEYS_ID_MAX bytes), else of the base MAC. *dev (dev may be NULL) gets the stored ID, which
 * F18C serves and the 0x27 key hashes. Start code only (udsota_esp32_start() and udsota_esp32_security()). */
udsota_esp32_devid_fix_t udsota_esp32_id_fix(const uint8_t *id, size_t id_len, const udsota_esp32_devid_t **dev);
/* Starts the engine once, before anything uses it. Creates the flash worker (Kconfig core, priority and
 * stack; internal RAM; off the task watchdog), its 4 KB block buffer and job queue. Takes the image identity
 * from cfg (product, hw_id, layout_id, req_id, resp_id; the product string must stay valid), the running
 * version from esp_app_desc and the release flag from udsota_image_desc, and puts the inactive slot's size
 * in udsota_esp32_engine()->slot_size. Queues the boot-time read of the OTA state. Idempotent. A failed
 * allocation or a missing inactive slot is logged, and every download is then refused. Links against
 * udsota_image_desc, so the app places one with UDSOTA_ESP32_IMAGE_DESC. */
void udsota_esp32_engine_start(const udsota_config_t *cfg);
/* Installs the function the flash worker calls after each finished job, from the worker's task, so the diag
 * task answers at once instead of at its next poll. Call before udsota_esp32_engine_start(); NULL = none. */
void udsota_esp32_engine_set_wake(void (*wake)(void));
/* The engine's first-block check, on whichever task runs it, when it accepts an image: stores the first max
 * bytes of its esp_app_desc_t.version as the incoming version (udsota_esp32_ctl_set_version). */
void udsota_esp32_set_incoming_version(const char *v, size_t max);
/* True when the app ran udsota_esp32_bootloop_init() this boot and the boot step chose to ignore config
 * (status flag 0x02). Never runs the boot step itself, so an app without the counter never sees the flag. */
bool udsota_esp32_bootloop_reported(void);
