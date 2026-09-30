/* The firmware updater, free of any UDS server: 0x34, 0x36 and 0x37, the RIDs FF01 and F000-F002, the DIDs F189,
 * F1F0, F1F1 and F1F3, the 10 02 slot rule and download progress, over an engine (udsota_update_state.h). The host
 * server parses and frames; each call here gets the request's parameters and the session state, and returns 0 (the
 * server writes its positive answer), an NRC, or UDSOTA_PENDING (the server answers 0x78 and calls
 * udsota_upd_resume until it stops). One task calls every function on a given updater. udsota_iso14229.h binds it
 * to iso14229's event callback; its wire contract is udsota_update_wire.h. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_common.h"
#include "udsota_update_state.h"

#define UDSOTA_SLOT_SIZE_DEFAULT  0x400000u  /* bytes a 34 may announce while engine.slot_size is 0 */
#define UDSOTA_UPD_PASS           (-1)       /* not the updater's RID: the host serves it or refuses it */
#define UDSOTA_UPD_DID_PASS       ((size_t)-1)   /* not the updater's DID */

/* 1: the updater serves coded downloads (DFI 0x10, 0x20, 0x30) when the engine sets zbegin, zwrite and zend and
 * names the format in zformats. 0: none of that is compiled in. Only update/udsota_update.c reads it. */
#ifndef UDSOTA_COMPRESSION
#define UDSOTA_COMPRESSION 1
#endif

/* The session state the host server reports with each request. */
typedef struct {
    uint8_t session;     /* UDSOTA_SESSION_* */
    bool    unlocked;    /* the programming level is unlocked, or the server has no security */
} udsota_upd_access_t;

typedef struct {
    uint16_t max_block_len;                              /* 0 = 4095 (UDSOTA_DL_MAX_BLOCK_LEN) */
    uint8_t (*gate)(void *ctx, udsota_op_t op);          /* nullable: 0 = allow, else the NRC */
    void    (*progress)(void *ctx, const udsota_progress_t *p);   /* nullable; at the end of a call that changed it */
    void    *ctx;
} udsota_upd_config_t;

struct udsota_updater;
/* Builds a job's final answer from its result: 0 (positive, with *status_len status bytes for a routine) or an NRC. */
typedef int (*udsota_upd_done_fn)(struct udsota_updater *u, int result, uint8_t *status, size_t status_max,
                                  size_t *status_len);

typedef struct udsota_updater {
    udsota_upd_config_t cfg;          /* max_block_len resolved */
    udsota_update_t     st;           /* engine, last result and the open download */
    bool                activating;   /* ActivateImage answered positive: the host restarts once the answer is out */
    bool                end_session;  /* the gate refused a 36: the host ends the session (udsota_upd_take_end_session) */
    bool                job_running;  /* a worker job owns the pending answer; udsota_upd_resume finishes it */
    uint32_t            job_arg;      /* the job's data, e.g. a 36's block length */
    udsota_upd_done_fn  job_done;
} udsota_updater_t;

/* Resets u and copies engine (required) and cfg (NULL = no gate, no progress, 4095-byte blocks). */
void     udsota_upd_init(udsota_updater_t *u, const udsota_engine_t *engine, const udsota_upd_config_t *cfg);

/* 0x34 with its decoded parameters: 0 and *max_block_len, or an NRC (7F, 33, 22, 31). */
int      udsota_upd_request_download(udsota_updater_t *u, udsota_upd_access_t a, uint8_t dfi, uint32_t addr,
                                     uint32_t size, uint16_t *max_block_len);
/* 0x36: bsc and len data bytes. 0, an NRC or UDSOTA_PENDING. */
int      udsota_upd_transfer_data(udsota_updater_t *u, udsota_upd_access_t a, uint8_t bsc, const uint8_t *data,
                                  size_t len);
/* 0x37 with extra_len bytes after the SID (0 is the only length served). 0, an NRC or UDSOTA_PENDING. */
int      udsota_upd_transfer_exit(udsota_updater_t *u, udsota_upd_access_t a, size_t extra_len);
/* 0x31 control ctrl (the suppress bit cleared) for rid with opt_len option bytes: UDSOTA_UPD_PASS for a RID that
 * isn't the updater's, else 0 with *status_len status bytes (after 71 <ctrl> <rid>), an NRC or UDSOTA_PENDING. */
int      udsota_upd_routine(udsota_updater_t *u, udsota_upd_access_t a, uint8_t ctrl, uint16_t rid, size_t opt_len,
                            uint8_t *status, size_t status_max, size_t *status_len);
/* While a job runs: UDSOTA_PENDING, or its final answer as the call that started it would have returned it. */
int      udsota_upd_resume(udsota_updater_t *u, uint8_t *status, size_t status_max, size_t *status_len);
/* The updater's DIDs into out: the length, 0 when the source failed or out is short (0x31), UDSOTA_UPD_DID_PASS. */
size_t   udsota_upd_read_did(udsota_updater_t *u, uint16_t did, uint8_t *out, size_t room);

/* 10 xx: 0 to allow entering session, else the NRC (10 02: slots settled, no job and no transfer, then the gate). */
uint8_t  udsota_upd_session_nrc(const udsota_updater_t *u, uint8_t session);
/* Every session entry and S3 timeout: aborts an open download (slot_verified survives) and stops waiting on a
 * running job, whose worker still finishes it (udsota_upd_busy stays true until then). */
void     udsota_upd_on_session(udsota_updater_t *u);
/* The host's cap on a job's wait passed (udsota's server answered 0x72 at 90 s): stops waiting, aborts the download,
 * and F1F1 records UDSOTA_DL_WORKER_TIMEOUT for a download or an FF01 that was running. */
void     udsota_upd_job_expired(udsota_updater_t *u);
/* True once after the gate refused a 36 with anything but 0x21: the host ends the session, as udsota's server did. */
bool     udsota_upd_take_end_session(udsota_updater_t *u);
/* The host server ended the transfer on its own (iso14229 does after any 36 or 37 NRC): aborts it if still open. */
void     udsota_upd_transfer_ended(udsota_updater_t *u);
/* 11 01's condition: 0x22 while a job or worker runs, else the gate's answer for RESET. */
uint8_t  udsota_upd_reset_nrc(const udsota_updater_t *u);
/* True while a job or any worker job runs. */
bool     udsota_upd_busy(const udsota_updater_t *u);
/* True while a transfer is open (between an accepted 34 and 37 or an abort). */
bool     udsota_upd_download_active(const udsota_updater_t *u);

/* The download's stage, bytes and last reason (udsota_progress_t); a pure read. */
void     udsota_progress(const udsota_updater_t *u, udsota_progress_t *out);
/* done / total in permille (0..1000); 0 when total is 0. */
uint16_t udsota_progress_permille(const udsota_progress_t *p);
