/* udsota's firmware updater on an iso14229 server (github.com/driftregion/iso14229). An app that already runs
 * iso14229 keeps its server, transport and event callback, and calls udsota_iso14229_event() first from that
 * callback: the updater answers 34, 36, 37, its RIDs (FF01, F000-F002) and DIDs (F189, F1F0, F1F1, F1F3, F18C,
 * F186), 0x27 at its two levels when it has security, 10 01/02/03 and 11 01, and passes every other event back.
 * iso14229 keeps timing, S3, the 0x78 cadence, the 0x27 attempt delays and ISO-TP. Pure C: no ESP-IDF. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "iso14229.h"
#include "udsota.h"

typedef struct {
    const udsota_engine_t   *engine;          /* required */
    const udsota_security_t *security;        /* NULL: 0x27 passes to the app, and download needs no key */
    const uint8_t *device_id;                 /* served as F18C; the bytes the 0x27 key hashes. NULL: F18C passes */
    size_t         device_id_len;
    uint8_t        level_extended;            /* requestSeed level in the extended session; 0 = 0x01 */
    uint8_t        level_programming;         /* requestSeed level in the programming session; 0 = 0x03 */
    uint16_t       max_block_len;             /* 34's maxNumberOfBlockLength; 0 = 4095 */
    uint8_t      (*gate)(void *ctx, udsota_op_t op);                  /* nullable: 0 = allow, else the NRC */
    void         (*progress)(void *ctx, const udsota_progress_t *p);  /* nullable */
    void         (*reset)(void *ctx);         /* restarts, on UDS_EVT_DoScheduledReset (11 01 and ActivateImage).
                                                 NULL: 11 01 and that event pass to the app, and ActivateImage
                                                 answers without a restart */
    void          *ctx;
} udsota_iso14229_cfg_t;

typedef struct {
    udsota_iso14229_cfg_t cfg;                /* levels resolved */
    udsota_updater_t      upd;
    uint8_t               job_sid;            /* the SID a pending updater job answers */
    uint32_t              job_ms;             /* when it started: the wait ends in 0x72 after 90 s */
    bool                  seed_valid;         /* a seed is outstanding (single use, UDSOTA_SA_SEED_VALID_MS) */
    uint8_t               seed_level;
    uint8_t               seed[UDSOTA_SEED_LEN];
    uint32_t              seed_ms;
} udsota_iso14229_t;

/* Resets b and copies cfg. */
void     udsota_iso14229_init(udsota_iso14229_t *b, const udsota_iso14229_cfg_t *cfg);
/* From the server's fn, before the app's own handling: true when the updater answered the event, with *rc for fn
 * to return; false when the event is the app's (UDS_EVT_SessionTimeout is seen here and still passed). */
bool     udsota_iso14229_event(udsota_iso14229_t *b, UDSServer_t *srv, UDSEvent_t ev, void *arg, UDSErr_t *rc);
/* Before every UDSServerPoll, on the server's task. Keeps passed deadlines passed, since iso14229 compares them
 * with a signed 32-bit difference (without this, 0x27 answers 0x37 from 24.9 to 49.7 days of uptime, and a server
 * silent that long holds its next answer), and widens iso14229's transfer size to a coded download's bound. */
void     udsota_iso14229_poll(udsota_iso14229_t *b, UDSServer_t *srv);
/* The download's progress (udsota_progress_t), for a display. The server's task only. */
void     udsota_iso14229_progress(const udsota_iso14229_t *b, udsota_progress_t *out);
