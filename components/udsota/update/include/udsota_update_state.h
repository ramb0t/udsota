/* The updater's types the server context embeds or names: its state (udsota_update_t), the engine, the download
 * reason codes, the F1F0 and F1F1 records and the progress report. Self-contained (only stdint, stddef and stdbool), so a server-only build
 * can take this one updater header alone. udsota_update_wire.h holds the rest of the updater's wire contract. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Download result: F1F1 reason and FF01 status byte. Wire values; append only. ---- */
typedef enum {
    UDSOTA_DL_OK = 0,
    UDSOTA_DL_BAD_HEADER,        /* 1: esp_image_header_t / esp_app_desc_t magic, chip or flash mode; an unparseable
                           *    version; or the release flag and the version string disagree */
    UDSOTA_DL_BAD_PROJECT,       /* 2: product name differs (esp_app_desc_t project_name) */
    UDSOTA_DL_BAD_BOARD,         /* 3: descriptor missing, bad magic or desc_version, or hw_id is not this board */
    UDSOTA_DL_BAD_LAYOUT,        /* 4: partition_layout_id differs */
    UDSOTA_DL_BAD_DIAG_IDS,      /* 5: the image would not answer on the configured request/response IDs */
    UDSOTA_DL_NOT_NEWER,         /* 6: release build not strictly newer than the running one, or dev build older */
    UDSOTA_DL_TOO_BIG,           /* 7: announced size exceeds the slot */
    UDSOTA_DL_VERIFY_FAILED,     /* 8: the engine's image check failed (on the ESP32 port, esp_ota_end's SHA-256 or signature) */
    UDSOTA_DL_SIG_FAILED,        /* 9: reserved; the ESP32 port never emits it: IDF v6.1's esp_ota_end returns one code for a
                           *    hash or a signature failure, so both report 8 */
    UDSOTA_DL_WORKER_TIMEOUT,    /* 10: a flash job passed the 90 s cap */
    UDSOTA_DL_ABORTED,           /* 11: ended early: S3 fallback, any accepted 10 xx, an interlock or end_session stop
                           *     at a 0x36 or FC point, or an overrun (0x71). Not a flash failure (12) or the
                           *     90 s cap (10) */
    UDSOTA_DL_FLASH_ERROR,       /* 12: the worker's ota_begin (erase) or ota_write failed or could not be queued (0x72),
                           *     or at the first-block check there is no worker or no inactive slot (0x31); for a
                           *     compressed download, no worker or slot at the 34 (0x22), and an erase or write
                           *     failure at a 36 (0x72) */
    UDSOTA_DL_BAD_STREAM,        /* 13: a coded download did not decode to exactly memorySize bytes: a corrupt stream
                           *     or patch, a delta header with the wrong magic, a patch for another size, a read of the
                           *     base outside it, or output past memorySize (36: 0x31); or at 37 a stream or patch
                           *     that had not ended, ended short or carried data after its end (0x72) */
    UDSOTA_DL_NO_MEMORY,         /* 14: a coded 34 found no memory for its decoder (0x22) */
    UDSOTA_DL_BAD_BASE,          /* 15: a delta patch made from an image other than the running one, or the running
                           *     image could not be identified (36: 0x31); a full download still works */
    UDSOTA_DL_REASON_COUNT       /* not a reason and never on the wire: the bound for range checks; append new reasons above it */
} udsota_reason_t;

/* ---- F1F0 device state (engine.status; the ESP32 port answers from a cache, never esp_ota_* at read time) ---- */
typedef struct {
    uint8_t running_slot;                /* UDSOTA_SLOT_* */
    uint8_t running_state;               /* udsota_img_state_t */
    uint8_t boot_slot;                   /* UDSOTA_SLOT_*: the otadata boot target */
    uint8_t other_slot_state;            /* udsota_other_state_t */
    uint8_t other_version[3];            /* major, minor, patch; 0,0,0 when empty; the rolled-back image's when INVALID */
    uint8_t other_elf_sha_prefix[8];     /* first 8 bytes of the other slot's app_elf_sha256; the rolled-back image's when INVALID */
    uint8_t flags;                       /* UDSOTA_STATUS_* */
} udsota_status_t;

/* ---- F1F1 last download result ---- */
typedef struct {
    uint8_t  reason_code;                /* udsota_reason_t */
    uint32_t bytes_received;             /* data bytes accepted by 0x36 */
} udsota_result_t;

/* The download's stage, finer than the phase, for an app's progress display. The core derives it from its own state. */
typedef enum {
    UDSOTA_STAGE_IDLE = 0,          /* everything below does not hold: no download, or it ended (last_reason says how) */
    UDSOTA_STAGE_ERASING,           /* from an accepted 34 until the first 36 is accepted: the first-block check and
                                       the erase run in that 36's job (a coded one may write nothing yet) */
    UDSOTA_STAGE_WRITING,           /* from the first accepted 36 until FF01 starts; done == total after the 37 */
    UDSOTA_STAGE_VERIFYING,         /* while the FF01 job runs */
    UDSOTA_STAGE_ACTIVATING,        /* the phase of the same name: from a positive ActivateImage until the restart */
} udsota_stage_t;

/* What udsota_progress() reads and hooks.progress gets. done and total are image bytes; both are 0 outside
 * ERASING and WRITING, where total is 34's memorySize and done only grows, never past total. */
typedef struct {
    udsota_stage_t stage;
    uint32_t       done;
    uint32_t       total;
    uint8_t        last_reason;     /* udsota_reason_t of the last download, as F1F1 reports it. It describes a finished
                                       download, so read it only in IDLE: during FF01 it reads UDSOTA_DL_WORKER_TIMEOUT
                                       until the verdict replaces it */
} udsota_progress_t;

typedef struct {   /* required; only unverify, status, running_sha, version and the z ops may be NULL */
    int    (*check_first)(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why); /* first 36 block, before any erase; 0 = ok */
    int    (*begin)(void *ctx, uint32_t size);                                  /* erase; may return UDSOTA_PENDING */
    int    (*write)(void *ctx, uint32_t off, const uint8_t *d, size_t n);       /* may return UDSOTA_PENDING */
    int    (*verify)(void *ctx);            /* FF01; result 0 or a udsota_reason_t; may return UDSOTA_PENDING */
    int    (*activate)(void *ctx);          /* set the boot slot; the restart follows via hooks.reset */
    int    (*confirm)(void *ctx);           /* no-op returning 0 when the platform has no rollback */
    void   (*abort)(void *ctx);             /* never blocks: queue it if a worker is busy; also frees zbegin's decoder */
    void   (*unverify)(void *ctx);          /* nullable: every accepted 34 calls it */
    int    (*poll)(void *ctx);              /* UDSOTA_PENDING while any worker job is queued or running, else the last result */
    void   (*status)(void *ctx, udsota_status_t *out);                       /* 0xF1F0; nullable:
                                                                                 then the core skips its slot conditions */
    size_t (*running_sha)(void *ctx, uint8_t *out, size_t max);              /* nullable: 0xF1F3 */
    size_t (*version)(void *ctx, char *out, size_t max);                     /* nullable: F189 */
    uint32_t slot_size;                     /* bytes a 34 may announce; 0 = UDSOTA_SLOT_SIZE_DEFAULT (0x400000) */
    void  *ctx;
    /* Coded downloads: DFI 0x10 (raw DEFLATE), 0x20 (a delta patch) and 0x30 (a delta patch as raw DEFLATE). zbegin,
     * zwrite and zend, all or none, and zwritten for progress; zformats names the DFIs served. A DFI the engine does
     * not serve answers 0x31 as an unknown one does, before anything changes. memorySize is the image's size, so the
     * slot rule, the erase and the image rules see the image as before; udsota_zstream.h, udsota_patch.h and
     * udsota_isink.h do the decoding behind these ops wherever the engine writes flash. */
    int    (*zbegin)(void *ctx, uint32_t size, uint8_t dfi);   /* accepted 34 with a DFI in zformats, after any abort
                                                     it queues: allocate the decoder for dfi and a size-byte image;
                                                     0, or a udsota_reason_t (34 answers 0x22 and F1F1 records it;
                                                     anything else records UDSOTA_DL_NO_MEMORY). Then abort also frees
                                                     the decoder */
    int    (*zwrite)(void *ctx, const uint8_t *d, size_t n);   /* one 36's coded bytes, in order; copies d before it
                                                     returns. Decodes them, runs check_first once the image's first 320
                                                     bytes are out, then begin, then writes at image offsets. 0, a
                                                     udsota_reason_t or UDSOTA_PENDING */
    int    (*zend)(void *ctx);                    /* 37: 0 when the stream or patch ended at exactly size bytes, all
                                                     written, with nothing after it, else a udsota_reason_t; frees the
                                                     decoder either way. May return UDSOTA_PENDING, as zwrite does:
                                                     a delta patch's decoder may still hold the image's last bytes,
                                                     so its end can read and write flash */
    uint32_t (*zwritten)(void *ctx);              /* nullable, with or without the others: the image bytes the open
                                                     download has written so far (udsota_isink_t.written), read after
                                                     each coded 76 for progress. NULL: done stays 0 until the 37 sets
                                                     it to total */
    uint16_t zformats;                            /* the coded DFIs served: UDSOTA_DL_FMT(0x10) | ...; 0 serves none,
                                                     whatever zbegin is */
} udsota_engine_t;

/* The updater's state, the server context's `update` member. */
typedef struct {
    udsota_engine_t   engine;            /* udsota_init's engine, copied */
    udsota_result_t   last_dl;           /* F1F1, answered by the server itself */
    uint32_t          dl_announced;      /* memorySize from 0x34 */
    uint32_t          dl_received;       /* data bytes accepted; the offset engine.write gets (coded bytes with
                                            dl_compressed) */
    uint32_t          dl_written;        /* image bytes written in this download, udsota_progress_t.done: set by the
                                            34 and advanced with dl_received after each 76. A download whose 36s carry
                                            other than image bytes (a coded one) sets it from the engine's count */
    uint32_t          cf_median_us;      /* 64-CF median from the last FC point (UDSOTA_CF_MEDIAN_NONE before one) */
    uint32_t          cf_stmin_us;       /* the STmin that FC point judged it against */
    bool              download_active;   /* between an accepted 0x34 and 0x37 or an abort */
    bool              ota_open;          /* the engine holds an open image: from the first 0x36's begin (from the 34's
                                            zbegin when coded) to FF01 or an abort */
    bool              dl_compressed;     /* the 34 had a coded DFI (10, 20 or 30): 36 goes to engine.zwrite and 37
                                            asks engine.zend */
    bool              slot_verified;     /* FF01 passed since the last download or reboot; survives session changes */
    bool              dl_complete;       /* 0x37 accepted: FF01 may verify the open image */
    bool              progress_block;    /* a block was written since the last report */
    uint8_t           next_bsc;          /* expected blockSequenceCounter (1 after 0x34, wraps 0xFF->0x00) */
    uint8_t           progress_stage;    /* udsota_stage_t last reported to hooks.progress */
    uint8_t           progress_reason;   /* last_reason last reported to hooks.progress: a coded 34 refused for
                                            memory changes it without changing the stage */
} udsota_update_t;
