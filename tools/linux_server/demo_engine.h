/* The Linux demo server's update engine: udsota_engine_t over fake_engine's two file-backed A/B slots.
 * check_first runs the ESP32 port's header check and the core's udsota_image_check rules on the first
 * block; FF01 is fake_ota_end (segment walk and a real SHA-256 over the image), then the same first-block
 * rules again on the bytes in the slot, as the port does. A simulated reset (demo_engine_boot) runs the
 * boot slot: an activated image boots PENDING_VERIFY, and one rebooted before ConfirmImage rolls back.
 * With job_ms set, begin, verify, activate, confirm, zwrite and zend (and the writes queued behind an erase) answer
 * UDSOTA_PENDING and finish job_ms later, like the port's flash worker, so the server sends 0x78. With compress set it
 * also serves compressed downloads (DFI 0x10), and with delta set too delta ones (0x20, 0x30) rebuilt from the
 * running slot: zbegin, zwrite and zend run udsota_coded over the vendored tinfl and detools into the same
 * first-block rules, erase and writes. Host only. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fake_engine.h"
#include "udsota.h"
#include "udsota_image.h"
#include "udsota_coded.h"
#include "udsota_detools.h"
#include "udsota_tinfl.h"

#define DEMO_SEED_PAYLOAD 1024u   /* segment 0 bytes of the image seeded into a fresh slot 0 */
#define DEMO_Z_OUT        4096u   /* a coded download's write buffer: one flash sector */
#define DEMO_P_BUF        1024u   /* DFI 0x30's inflated-patch buffer */

typedef struct {
    fake_ota_t         ota;
    udsota_image_ctx_t rules;         /* first-block rules: cfg's identity, the running image's version */
    uint16_t           chip_id;       /* esp_image_header_t.chip_id an image must carry */
    uint32_t           job_ms;        /* 0 = every op answers at once */
    bool               job_open;      /* a worker job is "running" until job_end_ms */
    uint64_t           job_end_ms;
    int                job_result;    /* 0 or the first failure of the ops in the job */
    int                last_result;   /* engine.poll's answer once no job runs */
    bool               compress;      /* serve DFI 0x10; set after demo_engine_open, before demo_engine_ops */
    bool               delta;         /* with compress, serve DFI 0x20 and 0x30 too; set as compress is */
    udsota_coded_t     cd;            /* the coded download, from zbegin to zend or abort */
    udsota_tinfl_t     tinfl;         /* its inflater: malloc'd at zbegin, freed at zend or abort */
    udsota_detools_t   detools;       /* its patch decoder, likewise */
    uint8_t            zout[DEMO_Z_OUT];
    uint8_t            pbuf[DEMO_P_BUF];
    uint8_t            base_hash[32]; /* the running image's appended SHA-256, once base_hash_ok */
    bool               base_hash_ok;  /* computed since the last boot */
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
/* The engine op table for udsota_init, with ctx e and slot_size set, and the z ops when e->compress is set (zformats
 * naming 0x10, and 0x20 and 0x30 with e->delta). */
udsota_engine_t demo_engine_ops(demo_engine_t *e);
/* The running image's esp_app_desc_t version (NUL-terminated) into out[33]; "" when the slot holds none. */
void demo_engine_version(const demo_engine_t *e, char out[33]);

/* Builds an image that passes the demo's first-block rules and FF01: fake_ota_build_image's one-segment image
 * (hw_id, version, payload_len bytes of segment 0), restamped with cfg's product, layout and IDs and resealed
 * (checksum byte and appended SHA-256). Returns its length, or 0 on a bad argument or a short out. */
size_t demo_image_build(uint8_t *out, size_t cap, const char *version, const udsota_config_t *cfg,
                        uint32_t payload_len);
