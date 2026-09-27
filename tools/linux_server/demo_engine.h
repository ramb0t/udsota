/* The Linux demo server's update engine: udsota_engine_t over fake_engine's two file-backed A/B slots.
 * check_first runs the ESP32 port's header check and the core's udsota_image_check rules on the first
 * block; FF01 is fake_ota_end (segment walk and a real SHA-256 over the image), then the same first-block
 * rules again on the bytes in the slot, as the port does. A simulated reset (demo_engine_boot) runs the
 * boot slot: an activated image boots PENDING_VERIFY, and one rebooted before ConfirmImage rolls back.
 * With job_ms set, begin, verify, activate and confirm (and the writes queued behind an erase) answer
 * UDSOTA_PENDING and finish job_ms later, like the port's flash worker, so the server sends 0x78. Host only. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fake_engine.h"
#include "udsota.h"
#include "udsota_image.h"

#define DEMO_SEED_PAYLOAD 1024u   /* segment 0 bytes of the image seeded into a fresh slot 0 */

typedef struct {
    fake_ota_t         ota;
    udsota_image_ctx_t rules;         /* first-block rules: cfg's identity, the running image's version */
    uint16_t           chip_id;       /* esp_image_header_t.chip_id an image must carry */
    uint32_t           job_ms;        /* 0 = every op answers at once */
    bool               job_open;      /* a worker job is "running" until job_end_ms */
    uint64_t           job_end_ms;
    int                job_result;    /* 0 or the first failure of the ops in the job */
    int                last_result;   /* engine.poll's answer once no job runs */
} demo_engine_t;

/* Opens the slots under dir (fresh: wipe them first) and boots. A running slot without an image is seeded
 * with a valid one at seed_version for cfg's product, hw_id, layout and IDs, so F189, F1F3 and the version
 * rule have a running image. False on an I/O error or an image that cannot be built. */
bool demo_engine_open(demo_engine_t *e, const char *dir, uint32_t slot_size, bool fresh, const udsota_config_t *cfg,
                      const char *seed_version, uint16_t chip_id, uint32_t job_ms);
/* Simulated reset: fake_ota_boot (NEW -> PENDING_VERIFY, an unconfirmed PENDING_VERIFY rolls back), then the
 * version rule is re-read from the image now running. Drops any job. */
void demo_engine_boot(demo_engine_t *e);
/* Closes the slot files. */
void demo_engine_close(demo_engine_t *e);
/* The engine op table for udsota_init, with ctx e and slot_size set. */
udsota_engine_t demo_engine_ops(demo_engine_t *e);
/* The running image's esp_app_desc_t version (NUL-terminated) into out[33]; "" when the slot holds none. */
void demo_engine_version(const demo_engine_t *e, char out[33]);

/* Builds an image that passes the demo's first-block rules and FF01: fake_ota_build_image's one-segment image
 * (hw_id, version, payload_len bytes of segment 0), restamped with cfg's product, layout and IDs and resealed
 * (checksum byte and appended SHA-256). Returns its length, or 0 on a bad argument or a short out. */
size_t demo_image_build(uint8_t *out, size_t cap, const char *version, const udsota_config_t *cfg,
                        uint32_t payload_len);
