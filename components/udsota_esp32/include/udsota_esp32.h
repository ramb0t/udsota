/* udsota ESP32 port (ESP-IDF v6.1): the diag task that owns the ISO-TP link and the UDS server
 * (udsota_esp32_start), the update engine on esp_ota_* (flash worker and OTA state cache), 0x27 security
 * on PSA HMAC-SHA256 or PSA ECDSA and the hardware RNG, the PSA lock they share with the app, the boot-loop
 * counter in RTC memory and the image descriptor placement. Host code may include it: it needs only the core
 * headers and esp_err.h (test/stubs has one). */
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

/* The engine for udsota_init() or another front end. Its jobs run on the worker: the ops queue them and
 * return UDSOTA_PENDING, and poll() reports the result. One task (the server's) calls its ops. Before the
 * port has started the engine (or when it has no worker or inactive slot), check_first answers
 * UDSOTA_DL_FLASH_ERROR, begin, write, verify and activate refuse with a negative error, as does confirm with
 * rollback on (without rollback confirm returns 0 as always), and abort does nothing. poll reads 0 (nothing queued),
 * status reads UDSOTA_SLOT_NONE and slot_size 0 (UDSOTA_SLOT_SIZE_DEFAULT). The core never calls confirm
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
 * udsota_esp32_start() or an earlier call already fixed wins. Serve the same bytes as F18C
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
 * udsota_esp32_start() or udsota_esp32_security() fixes it, this is the base MAC (UDSOTA_ESP32_DEVICE_ID_LEN
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

/* The running image's descriptor, which the app defines with UDSOTA_ESP32_IMAGE_DESC. */
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

/* ---- Task and app API (udsota_esp32.c) ---- */

/* The app's CAN transport; every member runs on the diag task. can_send queues one frame and never
 * blocks: ESP_OK queued, ESP_ERR_NO_MEM no room now (the port keeps the frame and retries), anything else
 * dropped. tx_pending (nullable) counts frames still in the app's driver, so a restart waits for its
 * answer to leave. tx_dropped (nullable) counts response-ID frames the driver dropped after it queued them;
 * the status counters report it (resp_frames_dropped). */
typedef struct {
    esp_err_t (*can_send)(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len);
    uint32_t  (*tx_pending)(void *ctx);
    uint32_t  (*tx_dropped)(void *ctx);
    void      *ctx;
} udsota_esp32_can_t;

/* Starts udsota once. It copies *cfg (the strings and arrays cfg points to must outlive the port), fixes
 * the device ID (a copy of cfg->device_id when set, else the base MAC) and serves it as F18C, turns security
 * on with keys over that same ID, starts the engine, and creates the buffers,
 * the frame queue and the diag task (Kconfig UDSOTA_ESP32_*). Security is the ECDSA mode
 * (udsota_esp32_security_ecdsa) when cfg->key_pubkey is set, else the HMAC mode (udsota_esp32_security)
 * when cfg->key_label is set, else off; a key_master given with a key_pubkey is ignored, with a warning,
 * and should be left out of the image. hooks may be NULL; the diag task calls every hook the app sets with
 * hooks->ctx, and a NULL hooks->reset restarts with esp_restart(). Returns ESP_ERR_INVALID_ARG for a NULL
 * cfg, can or can_send, or a set device_id whose device_id_len is not 1 to UDSOTA_KEYS_ID_MAX (16), a set
 * key_pubkey that is not a 65-byte uncompressed point (04 || X || Y), or a set func_id equal to req_id or
 * resp_id; ESP_ERR_INVALID_STATE on a second call; and ESP_ERR_NO_MEM when an allocation or the task fails.
 * Only a bad-argument failure may be retried: after ESP_ERR_NO_MEM the updater stays off for this boot, and
 * a second call returns ESP_ERR_INVALID_STATE. When the buffers or frame queue cannot be allocated nothing
 * else was started; when the diag task cannot be created, what start already set up stays behind: the flash
 * worker with its buffer and queue and, with security on, the derived key or the imported public key in RAM
 * and the SAR-ADC entropy source, left on. */
esp_err_t udsota_esp32_start(const udsota_config_t *cfg, const udsota_hooks_t *hooks, const udsota_esp32_can_t *can);
/* Any task: queues one frame on cfg->req_id, or on cfg->func_id when set (a functional request), with its receive
 * time in microseconds; never blocks. Other IDs, frames before start and frames past a full queue are dropped (the
 * last counted). */
void udsota_esp32_on_frame(uint16_t id, const uint8_t *data, uint8_t dlc, uint32_t rx_us);
/* Any task, an app hook included: asks the diag task to end the session (udsota_end_session) after the
 * request it is serving, or after a running job's answer; requests before it runs count once. No-op
 * before start. */
void udsota_esp32_end_session(void);
/* Any task, an app hook included: the phase as of the server's last change; one atomic read, IDLE before start. */
udsota_phase_t udsota_esp32_phase(void);
/* Any task, an app hook included: the download's progress as the server last reported it (udsota_progress_t),
 * copied under a spinlock, so a UI task can draw it without touching the server; IDLE before start. The port
 * keeps the snapshot by wrapping hooks.progress, and still calls the app's own with its ctx. */
void udsota_esp32_progress(udsota_progress_t *out);

#define UDSOTA_ESP32_VERSION_MAX 32u   /* esp_app_desc_t.version's size: up to 31 characters and a NUL */

/* Any task, an app hook included: the version of the image being downloaded, copied into out (not NULL, with room
 * for UDSOTA_ESP32_VERSION_MAX bytes) with a NUL, from a snapshot under the progress snapshot's spinlock; returns
 * its length. "" before any download, from an accepted 34 until that download's first block passes the first-block
 * check, and after a compressed 34 refused for memory. This and udsota_esp32_progress() take the lock separately:
 * to pair the version with a progress (its last_reason, say), read the progress, then this, then the progress
 * again, and read all three again if the stage or last_reason changed. */
size_t udsota_esp32_incoming_version(char out[UDSOTA_ESP32_VERSION_MAX]);
