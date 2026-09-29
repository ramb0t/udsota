/* Private to components/udsota_esp32: the start hooks udsota_esp32_start() (udsota_esp32.c) calls, among them
 * the one seam call into the updater (udsota_esp32_server_init), and what one port file needs from another. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"
#include "udsota_esp32_devid.h"

/* Creates the PSA mutex in static storage (cannot fail); idempotent. The start code calls it first, with
 * security on or off; udsota_esp32_security() calls it too. */
void udsota_esp32_psa_lock_init(void);
/* Fixes the port's device ID once (udsota_esp32_devid_fix() over the base MAC): a copy of id when non-NULL
 * (1 to UDSOTA_KEYS_ID_MAX bytes), else of the base MAC. *dev (dev may be NULL) gets the stored ID, which
 * F18C serves and the 0x27 key hashes. Start code only (udsota_esp32_start() and udsota_esp32_security()). */
udsota_esp32_devid_fix_t udsota_esp32_id_fix(const uint8_t *id, size_t id_len, const udsota_esp32_devid_t **dev);
/* Initialises the server once per boot, from udsota_esp32_start() before the diag task exists. With
 * CONFIG_UDSOTA_ESP32_UPDATER (udsota_esp32_engine.c) it installs wake (the function the flash worker calls after
 * each finished job, from its own task, so the diag task answers at once), starts the engine and calls
 * udsota_init() with udsota_esp32_engine(); without it (udsota_esp32_noupdater.c) it calls udsota_core_init(), so
 * no updater is registered or linked, and ignores wake. Returns what that init returns. */
bool udsota_esp32_server_init(udsota_server_t *srv, const udsota_config_t *cfg, const udsota_security_t *sec,
                              const udsota_hooks_t *hooks, void (*wake)(void));
/* The engine's first-block check, on whichever task runs it, once it has judged a first block with reason r: the
 * control block keeps an accepted block's version as the incoming version (udsota_esp32_ctl_first_block). */
void udsota_esp32_first_block_checked(udsota_reason_t r, const uint8_t *first, size_t len);
/* The engine, on the diag task, when zbegin refuses a compressed 34: empties the incoming version
 * (udsota_esp32_ctl_clear_version). */
void udsota_esp32_zbegin_refused(void);
/* True when the app ran udsota_esp32_bootloop_init() this boot and the boot step chose to ignore config
 * (status flag 0x02). Never runs the boot step itself, so an app without the counter never sees the flag. */
bool udsota_esp32_bootloop_reported(void);
