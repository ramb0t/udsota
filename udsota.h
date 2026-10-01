/* udsota: safe A/B firmware updates over UDS (ISO 14229) for an ESP32 that runs iso14229's server.
 *
 * The app owns iso14229: its server, transport, task and event callback. udsota is a guest in that callback. Call
 * udsota_init() once, then udsota_event() first thing in the callback; it answers the events that belong to an
 * update and returns false for everything else, which the app serves as before.
 *
 *     UDSOTA_IMAGE_DESC(1, 1, 0x7E6, 0x7EE);          // hw_id, partition layout, request ID, response ID
 *     udsota_init(&(udsota_cfg_t){ .key_pubkey = pub, .key_pubkey_len = sizeof pub });
 *     static UDSErr_t fn(UDSServer_t *srv, UDSEvent_t ev, void *arg) {
 *         UDSErr_t rc;
 *         if (udsota_event(srv, ev, arg, &rc)) return rc;
 *         ...                                          // the app's own services
 *     }
 *
 * What udsota answers: 10 01/02/03, 11 01, 27 at levels 01/02 and 03/04 (only when keys are configured), 22 for
 * F186, F189, F18C and F1F0/F1F1/F1F3, 31 01 for FF01, F000, F001 and F002, a 34 to address 0, and the 36s and 37 of
 * its own transfer. Every other service, DID, routine, session, security level and transfer (a 34 elsewhere, 35, 38)
 * is the app's. An app that wants one of udsota's events first handles it before calling udsota_event, and one that
 * needs to know of a session change checks for UDS_EVT_DiagSessCtrl when udsota_event returns true.
 *
 * An update: 10 02, 27 03/04, 34 (DFI 00 plain or 10 raw DEFLATE), 36..., 37, 31 01 FF01 (verify), 31 01 F001
 * (activate: the device restarts), then 10 03 and 31 01 F002 (confirm). The image's first 320 bytes are checked
 * (project, board, partition layout, CAN IDs, version, chip) before anything is erased, and with
 * CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE an image that is never confirmed rolls back at the next reset. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "iso14229.h"

/* ---- The image descriptor ----
 * Every image says which board, partition layout and CAN IDs it is for, at offset 288 (right after ESP-IDF's
 * esp_app_desc_t), so a device refuses a wrong image before erasing anything. Place it once, at file scope in the
 * app, with UDSOTA_IMAGE_DESC; udsota reads the running image's own copy as this device's identity. */
typedef struct {
    uint32_t magic;               /* "UDSO": flash bytes 4F 53 44 55 */
    uint16_t desc_version;        /* 1 */
    uint8_t  hw_id;               /* the board (one number per board variant) */
    uint8_t  partition_layout_id; /* the partition table */
    uint16_t diag_request_id;     /* the CAN IDs the image answers UDS on */
    uint16_t diag_response_id;
    uint8_t  flags;               /* 0x01: a release build (PROJECT_VER is a clean [v]X.Y.Z) */
    uint8_t  reserved[19];
} udsota_image_desc_t;

#ifndef UDSOTA_IMG_RELEASE
#define UDSOTA_IMG_RELEASE 0      /* udsota's CMakeLists sets it from PROJECT_VER */
#endif
#if defined(ESP_PLATFORM)
#define UDSOTA_DESC_SECTION __attribute__((section(".rodata_custom_desc")))
#else
#define UDSOTA_DESC_SECTION
#endif
#define UDSOTA_IMAGE_DESC(hw, layout, req_id, resp_id)                                                   \
    const UDSOTA_DESC_SECTION udsota_image_desc_t udsota_image_desc = {                                  \
        .magic = 0x5544534Fu, .desc_version = 1u, .hw_id = (uint8_t)(hw),                                \
        .partition_layout_id = (uint8_t)(layout), .diag_request_id = (uint16_t)(req_id),                 \
        .diag_response_id = (uint16_t)(resp_id), .flags = UDSOTA_IMG_RELEASE ? 0x01u : 0x00u,            \
    }
extern const udsota_image_desc_t udsota_image_desc;

/* ---- Configuration ---- */

/* The update steps the app's gate may refuse. */
typedef enum {
    UDSOTA_OP_ENTER_EXTENDED = 1,   /* 10 03 */
    UDSOTA_OP_ENTER_PROGRAMMING,    /* 10 02 */
    UDSOTA_OP_START_DOWNLOAD,       /* 34 */
    UDSOTA_OP_CONTINUE_TRANSFER,    /* every 36; any refusal ends the transfer, and one but 0x21 the session too */
    UDSOTA_OP_ACTIVATE,             /* 31 01 F001 */
    UDSOTA_OP_RESET,                /* 11 01 */
    UDSOTA_OP_CONFIRM,              /* 31 01 F002 */
} udsota_op_t;

/* Why the last download ended: F1F1's reason and FF01's status byte. Wire values. */
typedef enum {
    UDSOTA_DL_OK = 0,
    UDSOTA_DL_BAD_HEADER,           /* 1: not an ESP-IDF image for this chip, or an unparseable version */
    UDSOTA_DL_BAD_PROJECT,          /* 2: another project name */
    UDSOTA_DL_BAD_BOARD,            /* 3: no udsota descriptor, or another hw_id */
    UDSOTA_DL_BAD_LAYOUT,           /* 4: another partition layout */
    UDSOTA_DL_BAD_DIAG_IDS,         /* 5: the image would answer on other CAN IDs */
    UDSOTA_DL_NOT_NEWER,            /* 6: a release not newer than the running image, or a dev build older */
    UDSOTA_DL_TOO_BIG,              /* 7: larger than the slot */
    UDSOTA_DL_VERIFY_FAILED,        /* 8: hash or signature check failed */
    UDSOTA_DL_SIG_FAILED,           /* 9: reserved */
    UDSOTA_DL_WORKER_TIMEOUT,       /* 10: a flash job passed 90 s, or its session ended while it ran */
    UDSOTA_DL_ABORTED,              /* 11: ended early: a session change, S3, the gate, an overrun, or iso14229 */
    UDSOTA_DL_FLASH_ERROR,          /* 12: erase or write failed, or no inactive slot */
    UDSOTA_DL_BAD_STREAM,           /* 13: a compressed download did not inflate to exactly the image */
    UDSOTA_DL_NO_MEMORY,            /* 14: no memory for the inflater */
    UDSOTA_DL_BAD_BASE,             /* 15: reserved (delta downloads) */
} udsota_reason_t;

/* A download's progress, for a display. done and total are image bytes (0 outside ERASING and WRITING). */
typedef enum {
    UDSOTA_STAGE_IDLE = 0, UDSOTA_STAGE_ERASING, UDSOTA_STAGE_WRITING, UDSOTA_STAGE_VERIFYING,
    UDSOTA_STAGE_ACTIVATING,
} udsota_stage_t;
typedef struct {
    udsota_stage_t stage;
    uint32_t       done, total;
    uint8_t        last_reason;     /* udsota_reason_t of the last download; read it in IDLE */
} udsota_progress_t;

typedef struct {
    /* 0x27 keys; neither set leaves 0x27 to the app, and then downloads need no key (any node can update).
     * ECDSA: the tester signs the seed; the device holds only this public key (`udsota keygen` writes it). */
    const uint8_t *key_pubkey;              /* 65 bytes: 04 || X || Y, P-256 */
    size_t         key_pubkey_len;
    /* HMAC: each device's key is HMAC-SHA256(key_master, key_label || device ID), so every image carries the master. */
    const char    *key_label;
    const uint8_t *key_master;
    size_t         key_master_len;
    const uint8_t *device_id;               /* F18C, and what the keys bind to; NULL = the base MAC */
    size_t         device_id_len;           /* 1..16 */
    const char    *product;                 /* the project name an image must carry; NULL = this image's own */
    bool           allow_downgrade;         /* take an older or same-version image too (a dev unit's choice; a release
                                               build leaves it off); every other image rule still applies */
    uint8_t      (*gate)(void *ctx, udsota_op_t op);                  /* nullable: 0 = allow, else the NRC */
    void         (*progress)(void *ctx, const udsota_progress_t *p);  /* nullable; from the server's task */
    void         (*reset)(void *ctx);       /* restarts after 11 01 or F001; NULL = esp_restart() */
    void          *ctx;
} udsota_cfg_t;

/* ---- API ---- */

/* Starts udsota once: reads this image's identity, starts the flash worker and sets up the keys. 0, or -1 (logged)
 * when there is no inactive OTA slot or no memory; the updater then refuses downloads but still answers. */
int      udsota_init(const udsota_cfg_t *cfg);
/* From iso14229's event callback, before the app's own handling, on the server's task: true when udsota answered
 * the event, with *rc for the callback to return; false when the event is the app's. */
bool     udsota_event(UDSServer_t *srv, UDSEvent_t ev, void *arg, UDSErr_t *rc);
/* Ends a non-default session for the app (say, on hearing another tester), with udsota's own abort and relock: an
 * open download ends and F1F1 says ABORTED. The server's task only, between UDSServerPoll calls, never from the event
 * callback. While iso14229 has a request in progress (a job answering 0x78, or an answer still to send) it does
 * nothing and returns false: call it again after the next poll. True once the session is the default one, or a reset
 * is scheduled. The app gets no SessionTimeout event, and a transfer the app owns ends too. */
bool     udsota_end_session(UDSServer_t *srv);
/* True while a flash job runs or a download is open, as of the last event udsota saw. Any task. */
bool     udsota_busy(void);
/* The current download's progress. The server's task. */
void     udsota_progress(udsota_progress_t *out);
/* True while the running image waits for 31 01 F002 (with rollback on, a reset would roll it back). Any task. */
bool     udsota_unconfirmed(void);

/* ---- Porting and host tests ----
 * The platform under the updater. On ESP-IDF udsota.c defines these; anywhere else the build supplies them (the
 * host test does, and so would a port to another MCU). Jobs run on a worker task; the flash functions run inside
 * jobs and return a udsota_reason_t. */
#define UDSOTA_PENDING 0x7FFFFFFF                 /* a job is still running */

/* F1F0: the A/B slots. Wire layout; enum values as the updater reads them. */
enum { UDSOTA_SLOT_OTA0 = 0, UDSOTA_SLOT_OTA1 = 1, UDSOTA_SLOT_NONE = 0xFF };
enum { UDSOTA_IMG_UNDEFINED, UDSOTA_IMG_NEW, UDSOTA_IMG_PENDING_VERIFY, UDSOTA_IMG_VALID, UDSOTA_IMG_INVALID,
       UDSOTA_IMG_ABORTED };
enum { UDSOTA_OTHER_EMPTY, UDSOTA_OTHER_UNVERIFIED, UDSOTA_OTHER_WRITING, UDSOTA_OTHER_VERIFIED,
       UDSOTA_OTHER_INVALID };
typedef struct {
    uint8_t running_slot, running_state, boot_slot, other_slot_state;
    uint8_t other_version[3], other_elf_sha_prefix[8], flags;
} udsota_status_t;

int         udsota_plat_start(void);                               /* 0 or -1 */
int         udsota_plat_run(int (*job)(void));                     /* UDSOTA_PENDING once queued, else -1 */
int         udsota_plat_poll(void);                                /* UDSOTA_PENDING, or the last job's result */
void        udsota_plat_abort(void);                               /* close an open image; deferred if a job runs */
bool        udsota_plat_compatible(const uint8_t *first, size_t len);   /* chip revision etc. vs the running app */
int         udsota_plat_begin(uint32_t size);                      /* open the inactive slot for size bytes */
int         udsota_plat_write(const uint8_t *d, size_t n);         /* append; erases as it goes */
int         udsota_plat_end(void);                                 /* FF01: close and verify the image */
int         udsota_plat_activate(void);                            /* make it the boot slot */
int         udsota_plat_confirm(void);                             /* mark the running image valid */
void        udsota_plat_unverify(void);                            /* a new download: the slot is not verified */
void        udsota_plat_status(udsota_status_t *out);
uint32_t    udsota_plat_slot_size(void);
const char *udsota_plat_version(void);                             /* the running image's, NUL-terminated */
const char *udsota_plat_project(void);
const uint8_t *udsota_plat_sha(void);                              /* the running image's app_elf_sha256 */
size_t      udsota_plat_mac(uint8_t out[16]);
bool        udsota_plat_rng16(uint8_t out[16]);
bool        udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);
int         udsota_plat_ecdsa_key(const uint8_t *pubkey);          /* 0 once the key is usable */
int         udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[64]);   /* 1 valid, 0 not, -1 unknown */
