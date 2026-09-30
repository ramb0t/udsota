/* udsota ESP32 port (ESP-IDF v6.1), without a UDS server: the update engine on esp_ota_* (flash worker and OTA
 * state cache), 0x27 security on PSA HMAC-SHA256 or PSA ECDSA and the hardware RNG, the PSA lock they share with the
 * app, the boot-loop counter in RTC memory and the image descriptor placement. The app runs the UDS server
 * (iso14229, with udsota_iso14229.h) and hands it what udsota_esp32_updater_start() returns. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "udsota.h"
#include "udsota_image_desc.h"

#define UDSOTA_ESP32_DEVICE_ID_LEN     6u           /* the base MAC: the device ID when cfg.device_id is NULL */
#define UDSOTA_ESP32_PSA_WAIT_FOREVER  UINT32_MAX   /* udsota_esp32_psa_lock(): no time limit */

/* ---- Engine (udsota_esp32_engine.c) ---- */

/* The engine for the updater (udsota_upd_init, or udsota_iso14229_cfg_t.engine). Its jobs run on the worker: the ops queue them and
 * return UDSOTA_PENDING, and poll() reports the result. One task (the server's) calls its ops. Before the
 * port has started the engine (or when it has no worker or inactive slot), check_first answers
 * UDSOTA_DL_FLASH_ERROR, begin, write, verify and activate refuse with a negative error, as does confirm with
 * rollback on (without rollback confirm returns 0 as always), and abort does nothing. poll reads 0 (nothing queued),
 * status reads UDSOTA_SLOT_NONE and slot_size 0 (UDSOTA_SLOT_SIZE_DEFAULT). The updater never calls confirm
 * then: it refuses ConfirmImage while the running slot reads UDSOTA_SLOT_NONE. */
const udsota_engine_t *udsota_esp32_engine(void);
/* The status DID (0xF1F0) from the RAM cache, never otadata: slots and states, the other slot's version and
 * SHA prefix, flag 0x01 (IDF checks update signatures) and 0x02 (this boot ignored config). Any task, not
 * from an ISR, and safe before the engine starts: the slots read UDSOTA_SLOT_NONE until the boot read has
 * finished. With rollback off the running state is never PENDING_VERIFY. */
void udsota_esp32_status(udsota_status_t *out);
/* True when the running image is PENDING_VERIFY and is the boot slot; from the cache, any task. */
bool udsota_esp32_image_unconfirmed(void);
/* True while an engine job is queued or running, or the started worker's boot read has not finished; false when
 * the engine never started. Any task. */
bool udsota_esp32_engine_busy(void);

/* ---- Security (udsota_esp32_keys.c) ---- */

/* 0x27 security with the core's default derivation (udsota_keys.h): seeds from the hardware RNG, and keys
 * from K_dev = HMAC-SHA256(master, label || device ID), derived once here, computed under the PSA lock.
 * The device ID is id (id_len bytes, 1 to UDSOTA_KEYS_ID_MAX) or, with id NULL, the base MAC; an ID that
 * udsota_esp32_updater_start() or an earlier call already fixed wins. Serve the same bytes as F18C
 * (udsota_esp32_device_id() returns them); start does. The first call switches the SAR-ADC entropy source
 * on for good, fixes the device ID, self-tests PSA HMAC and derives K_dev. Later calls of this or
 * udsota_esp32_security_ecdsa() return the struct the first built and ignore their arguments. label NULL:
 * returns NULL (no security). A bad id_len, a failed MAC
 * read for a MAC ID, master NULL or master_len 0, or a failed self-test: security is on and no key matches.
 * Call it from start code, before the server's task runs. */
const udsota_security_t *udsota_esp32_security(const char *label, const uint8_t *master, size_t master_len,
                                               const uint8_t *id, size_t id_len);
/* 0x27 security in the ECDSA mode (udsota_keys.h): seeds from the hardware RNG, and the key a sendKey carries
 * is a UDSOTA_KEYS_SIG_LEN-byte P-256 signature over the seed, level and device ID, verified with PSA under
 * pubkey, the tester's public key (UDSOTA_KEYS_PUBKEY_LEN bytes, 04 || X || Y; the device needs no secret).
 * The device ID is chosen as for udsota_esp32_security(). The first call switches the SAR-ADC entropy source
 * on for good, fixes the device ID, self-tests PSA ECDSA (two P-256 verifies) and imports pubkey once as a
 * volatile key. The first call of this or udsota_esp32_security() fixes the mode: later calls of either
 * return the same struct and ignore their arguments. pubkey NULL: returns NULL (no security). A bad id_len, a
 * failed MAC read for a MAC ID, a pubkey that is not a P-256 point or a failed self-test: security is on and
 * no key matches (sendKey answers 0x22). Call it from start code, before the server's task runs. */
const udsota_security_t *udsota_esp32_security_ecdsa(const uint8_t *pubkey, size_t pubkey_len, const uint8_t *id,
                                                     size_t id_len);
/* The device ID the port serves as F18C and the keys hash, with its length in *len (len may be NULL). Until
 * udsota_esp32_updater_start() or udsota_esp32_security() fixes it, this is the base MAC (UDSOTA_ESP32_DEVICE_ID_LEN
 * bytes), and calling it fixes nothing. The MAC is all-zero if its read failed. Any task may call it. */
const uint8_t *udsota_esp32_device_id(size_t *len);

/* ---- PSA lock (udsota_esp32_psa.c) ---- */

/* Takes the mutex that serialises PSA crypto between the port (its key setup and self-tests, the 0x27 HMAC or
 * ECDSA check, the worker's esp_ota_end and set_boot, and the slot-state refresh's invalid-image lookup) and the
 * app's own PSA users. IDF v6.1's PSA is thread-safe for key management only, not for
 * one-shot or multi-part operations. Waits up to wait_ms (UDSOTA_ESP32_PSA_WAIT_FOREVER: no limit);
 * true when held. Before the port has created the lock, returns true without locking. */
bool udsota_esp32_psa_lock(uint32_t wait_ms);
/* Releases the mutex udsota_esp32_psa_lock() took on the same task. */
void udsota_esp32_psa_unlock(void);

/* ---- Boot-loop counter (udsota_esp32_bootloop.c): state in RTC_NOINIT memory, safe from any task ---- */

/* Runs the boot step once per boot; call it first in app_main, before anything reads stored config. */
void udsota_esp32_bootloop_init(void);
/* True when this boot ignores stored config after repeated crash resets; latched for the whole boot. The
 * app checks it before it reads any stored config (NVS or otherwise) and runs on its defaults while set. */
bool udsota_esp32_bootloop_config_ignored(void);
/* Clears the crash count once the app is healthy; this boot's ignore flag stays latched. */
void udsota_esp32_bootloop_mark_healthy(void);

/* ---- Image descriptor ---- */

/* The running image's descriptor, which the app defines with UDSOTA_ESP32_IMAGE_DESC. The engine reads its release
 * flag. */
extern const udsota_image_desc_t udsota_image_desc;

#ifndef UDSOTA_ESP32_IMG_RELEASE
#define UDSOTA_ESP32_IMG_RELEASE 0   /* udsota_esp32_image_desc() defines it: 1 for a clean-tag PROJECT_VER */
#endif

/* Defines udsota_image_desc in IDF's .rodata_custom_desc section, which sections.ld.in places right after
 * esp_app_desc, at image offset UDSOTA_IMG_DESC_OFFSET (288). Use it once, at file scope and followed by
 * ';', in a source of the component whose CMakeLists.txt calls udsota_esp32_image_desc(${COMPONENT_LIB}). */
#define UDSOTA_ESP32_IMAGE_DESC(hw, layout, req_id, resp_id)                                         \
    const __attribute__((section(".rodata_custom_desc"))) udsota_image_desc_t udsota_image_desc = { \
        .magic               = UDSOTA_IMG_DESC_MAGIC,                                                \
        .desc_version        = UDSOTA_IMG_DESC_VERSION,                                              \
        .hw_id               = (uint8_t)(hw),                                                        \
        .partition_layout_id = (uint8_t)(layout),                                                    \
        .diag_request_id     = (uint16_t)(req_id),                                                   \
        .diag_response_id    = (uint16_t)(resp_id),                                                  \
        .flags               = UDSOTA_ESP32_IMG_RELEASE ? UDSOTA_IMG_FLAG_RELEASE : 0u,              \
        .reserved            = {0},                                                                  \
    }

/* ---- Start (udsota_esp32_updater.c) ---- */

#define UDSOTA_ESP32_VERSION_MAX 32u   /* esp_app_desc_t.version's size: up to 31 characters and a NUL */

/* What udsota_esp32_updater_start() hands the host server's binding (udsota_iso14229_cfg_t takes each field). */
typedef struct {
    const udsota_engine_t   *engine;
    const udsota_security_t *security;       /* NULL: security off (neither key_pubkey nor key_label) */
    const uint8_t           *device_id;      /* the stored ID: serve it as F18C; the 0x27 key hashes these bytes */
    size_t                   device_id_len;
} udsota_esp32_updater_t;

/* Starts the updater's ESP32 half once, for a UDS server the app runs (iso14229 on this branch): fixes the device
 * ID (cfg->device_id, else the base MAC), turns 0x27 security on as cfg says (the ECDSA mode with key_pubkey, else
 * the HMAC mode with key_label, else off), and starts the engine's flash worker with cfg's image identity (product,
 * hw_id, layout_id, req_id, resp_id; the strings cfg points to must outlive the port). wake (nullable) runs on the
 * worker after each finished job, so the server's task can answer at once. Fills *out. ESP_ERR_INVALID_ARG for a
 * NULL cfg or out, a bad device_id_len or a malformed key_pubkey; ESP_ERR_INVALID_STATE on a second call. */
esp_err_t udsota_esp32_updater_start(const udsota_config_t *cfg, void (*wake)(void), udsota_esp32_updater_t *out);
