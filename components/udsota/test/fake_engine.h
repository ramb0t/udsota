/* File-backed fake of an ESP32 device's two OTA slots and otadata, for host tools (a SocketCAN demo
 * server is future work) and test_fake_engine. It models what the pure UDS server can observe through the
 * ESP32 port's engine: esp_ota_begin erasing the image extent, sequential writes, esp_ota_end's image check
 * (segment walk + appended SHA-256; no RSA signature, so F1F0 bit 0 stays clear), set_boot, mark-valid,
 * and the bootloader's rollback of an image that reboots while still PENDING_VERIFY. State survives a
 * SIGKILL (a power cut). Host only (POSIX). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_wire.h"

#define FAKE_OTA_SECTOR          4096u
#define FAKE_OTA_SLOT_SIZE       0x400000u   /* a 4 MB ota_0/ota_1 partition */
#define FAKE_OTA_MIN_PAYLOAD     288u        /* segment 0 must hold esp_app_desc_t + udsota_image_desc_t */
#define FAKE_OTA_VERSION_OFS     48u         /* esp_app_desc_t.version (32 B) in the image */
#define FAKE_OTA_ELF_SHA_OFS     176u        /* esp_app_desc_t.app_elf_sha256 (32 B) in the image */
#define FAKE_OTA_LAYOUT_ID       1u          /* partition layout the fake's images carry */
#define FAKE_OTA_PROJECT         "example"   /* esp_app_desc_t.project_name of the fake's images */
#define FAKE_OTA_REQ_ID          0x710u      /* diag request ID the fake's images carry */
#define FAKE_OTA_RESP_ID         0x718u      /* diag response ID the fake's images carry */

typedef struct {
    char     dir[240];         /* holds ota_0.bin, ota_1.bin and otadata.txt */
    uint32_t slot_size;
    int      fd[2];            /* slot files, open from fake_ota_open to fake_ota_close */
    uint8_t  boot_slot;        /* otadata's boot target, 0 or 1 */
    uint8_t  running_slot;     /* the slot this simulated boot runs */
    uint8_t  state[2];         /* udsota_img_state_t of each slot, as otadata would hold it */
    bool     writing;          /* between fake_ota_begin and fake_ota_end/fake_ota_abort */
    bool     verified;         /* fake_ota_end passed since the last begin, unverify or boot */
    bool     no_rollback;      /* CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE off: activate writes UNDEFINED, confirm
                                * does nothing. A build setting, not otadata: set it after fake_ota_open */
    uint32_t written;          /* bytes written since fake_ota_begin */
    unsigned writes;           /* fake_ota_write calls since open (tests count rewrites with it) */
} fake_ota_t;

/* Opens (or with fresh, recreates) the slot files and otadata under dir, then simulates a boot.
 * A new slot file is filled with 0xFF (erased flash); new otadata runs slot 0 as VALID. False on any I/O error. */
bool fake_ota_open(fake_ota_t *f, const char *dir, uint32_t slot_size, bool fresh);
/* Closes the slot files; otadata is already on disk after every state change. */
void fake_ota_close(fake_ota_t *f);
/* Simulated reset: NEW -> PENDING_VERIFY and run it; a PENDING_VERIFY boot target that never got
 * confirmed -> ABORTED and run the other slot (IDF rollback). Clears any open write and "verified". */
void fake_ota_boot(fake_ota_t *f);
/* Writes a whole image into slot (to seed a running image); erases the slot first. 0, or -1 on error. */
int  fake_ota_load_slot(fake_ota_t *f, uint8_t slot, const uint8_t *data, size_t len);
/* The inactive slot: the one a download writes. */
uint8_t fake_ota_other(const fake_ota_t *f);

/* esp_ota_begin(other, size): erases ALIGN_UP(size, 4096) bytes to 0xFF. 0, or -1 for size 0, size > slot or I/O. */
int  fake_ota_begin(fake_ota_t *f, uint32_t size);
/* esp_ota_write: appends; the first byte written must be 0xE9. 0, or -1 when not open, past the slot or bad magic. */
int  fake_ota_write(fake_ota_t *f, const uint8_t *data, size_t len);
/* esp_ota_end: closes the write and checks the image; returns UDSOTA_DL_OK or UDSOTA_DL_VERIFY_FAILED (the FF01 result). */
int  fake_ota_end(fake_ota_t *f);
/* esp_ota_abort: drops the open write, keeps the partial slot; a no-op when nothing is open. Always 0. */
int  fake_ota_abort(fake_ota_t *f);
/* udsota_engine_t.unverify: the other slot stops counting as verified; the open write, if any, stays. */
void fake_ota_unverify(fake_ota_t *f);
/* esp_ota_set_boot_partition(other): needs a verified slot; marks it the boot target, NEW (UNDEFINED with
 * no_rollback, which the fake bootloader never rolls back). 0 or -1. */
int  fake_ota_activate(fake_ota_t *f);
/* esp_ota_mark_app_valid_cancel_rollback: PENDING_VERIFY -> VALID on the running slot. Always 0, like IDF;
 * with no_rollback it changes nothing (the port's engine.confirm). */
int  fake_ota_confirm(fake_ota_t *f);

/* Reads a slot's esp_app_desc_t version (NUL-terminated, <= 32 chars) and app_elf_sha256; false if its magic is absent. */
bool fake_ota_slot_desc(const fake_ota_t *f, uint8_t slot, char version[33], uint8_t elf_sha[32]);
/* True when the slot holds a udsota descriptor (magic and desc_version) with UDSOTA_IMG_FLAG_RELEASE set. */
bool fake_ota_slot_release(const fake_ota_t *f, uint8_t slot);
/* F1F0 from the fake's state. flags carries nothing. */
void fake_ota_fill_status(const fake_ota_t *f, udsota_status_t *out);
/* Stateless resume point of the inactive slot (for a future resume): C = S - 4096 for the first all-0xFF
 * sector S, clamped at 0; slot_size - 4096 when no sector is blank. */
uint32_t fake_ota_resume_point(const fake_ota_t *f);

/* The fake's esp_ota_end check over a whole image: header, segment walk, checksum byte and the
 * appended SHA-256 (hash_appended must be 1). UDSOTA_DL_OK or UDSOTA_DL_VERIFY_FAILED. */
udsota_reason_t fake_ota_verify_image(const uint8_t *img, size_t len);
/* Builds a minimal image that passes udsota_image_check and fake_ota_verify_image: one segment of
 * payload_len bytes (>= 288, multiple of 4) holding esp_app_desc_t (project FAKE_OTA_PROJECT, this version) and
 * the udsota descriptor for hw_id at 288, release-flagged exactly when version matches ^v?[0-9]+\.[0-9]+\.[0-9]+$.
 * Returns the image length, or 0 if cap is short, an argument is bad or the SHA-256 fails. */
size_t fake_ota_build_image(uint8_t *out, size_t cap, const char *version, uint8_t hw_id, uint32_t payload_len);
