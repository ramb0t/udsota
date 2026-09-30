/* The firmware updater as the UDS server's one registered service (udsota_service.h): 0x34, 0x36 and 0x37, the
 * RIDs FF01 and F000-F002, the DIDs F189, F1F0, F1F1 and F1F3, the slot rule 10 02 asks, and download progress, over
 * the engine udsota_init was given. It reaches the core only through udsota_service.h and the core's public headers
 * (udsota_rxwatch.h, for UDSOTA_CF_MEDIAN_NONE); the core never calls it. */
#include <string.h>
#include "udsota_service.h"
#include "udsota_update.h"
#include "udsota_update_wire.h"
#include "udsota_rxwatch.h"   /* UDSOTA_CF_MEDIAN_NONE */

/* engine.status into *st, zeroed first; only called when engine.status is set. */
static void status_now(const udsota_server_t *s, udsota_status_t *st)
{
    memset(st, 0, sizeof *st);
    s->update.engine.status(s->update.engine.ctx, st);
}

/* Core slot rule for 10 02 and 34: the boot slot is the running slot (both known) and the running image is not
 * PENDING_VERIFY. True without engine.status (not used = not checked). */
static bool slots_settled(const udsota_server_t *s)
{
    if (s->update.engine.status == NULL) {
        return true;
    }
    udsota_status_t st;
    status_now(s, &st);
    return st.running_slot != UDSOTA_SLOT_NONE && st.boot_slot == st.running_slot &&
           st.running_state != UDSOTA_IMG_PENDING_VERIFY;
}

/* What ConfirmImage does once the gate has allowed it. */
typedef enum { CONFIRM_REFUSE, CONFIRM_RUN, CONFIRM_ALREADY } confirm_action_t;

/* Core ConfirmImage rule: the boot slot must be the running one (both known); a PENDING_VERIFY image goes to
 * engine.confirm; one already VALID, or UNDEFINED as builds without rollback report, is confirmed already
 * (confirm is idempotent); any other state is refused. Without engine.status the engine decides. */
static confirm_action_t confirm_action(const udsota_server_t *s)
{
    if (s->update.engine.status == NULL) {
        return CONFIRM_RUN;
    }
    udsota_status_t st;
    status_now(s, &st);
    if (st.running_slot == UDSOTA_SLOT_NONE || st.boot_slot != st.running_slot) {
        return CONFIRM_REFUSE;
    }
    switch (st.running_state) {
    case UDSOTA_IMG_PENDING_VERIFY:
        return CONFIRM_RUN;
    case UDSOTA_IMG_VALID:
    case UDSOTA_IMG_UNDEFINED:
        return CONFIRM_ALREADY;
    default:
        return CONFIRM_REFUSE;
    }
}

/* START_DOWNLOAD: slots settled, worker idle and no transfer open, then the gate. */
static uint8_t download_nrc(const udsota_server_t *s, udsota_op_t op)
{
    if (!slots_settled(s) || udsota_worker_busy(s) || s->update.download_active) {
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return udsota_gate(s, op);
}

/* CONTINUE_TRANSFER at a 36 or an FC point: the STmin monitor (when on), then the gate, which is asked either way
 * so that an STmin violation is counted only when timing alone failed. Judges s->update.cf_median_us and cf_stmin_us, the
 * last FC point's timing. 0 or the NRC. */
static uint8_t transfer_nrc(udsota_server_t *s)
{
    const bool slow_enough = !s->cfg.stmin_monitor ||
                             (uint64_t)s->update.cf_median_us * 5u >= (uint64_t)s->update.cf_stmin_us * 4u;   /* NONE always passes */
    const uint8_t g = udsota_gate(s, UDSOTA_OP_CONTINUE_TRANSFER);
    if (!slow_enough) {
        if (g == 0u) {
            udsota_sat_inc16(&udsota_counters(s)->stmin_violations);
        }
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return g;
}

/* Ends a download or an open, unverified image: queues ota_abort on the worker without waiting
 * (the partial slot stays, for a future resume) and records UDSOTA_DL_ABORTED in F1F1 and F1F2. dl_complete is
 * cleared either way, so FF01 never sees a closed transfer without its handle. */
static void abort_download(udsota_server_t *s)
{
    s->update.dl_complete = false;
    if (!s->update.download_active && !s->update.ota_open) {
        return;
    }
    if (s->update.ota_open) {
        s->update.engine.abort(s->update.engine.ctx);
    }
    s->update.download_active = false;
    s->update.ota_open = false;
    s->update.last_dl.reason_code = UDSOTA_DL_ABORTED;
    s->update.last_dl.bytes_received = s->update.dl_received;
    udsota_sat_inc16(&udsota_counters(s)->aborts);
}

/* The updater's on_session: every session entry aborts an open download; at the 90 s cap of the updater's own job
 * F1F1 then records UDSOTA_DL_WORKER_TIMEOUT rather than UDSOTA_DL_ABORTED. slot_verified survives, so ActivateImage
 * can follow in a later session. */
static void upd_on_session(udsota_server_t *s, bool job_capped)
{
    const bool was = s->update.download_active || s->update.ota_open;
    abort_download(s);
    if (job_capped && was) {
        s->update.last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;
    }
}

/* The updater's download_active: between an accepted 34 and 37 or an abort. */
static bool upd_download_active(const udsota_server_t *s)
{
    return s->update.download_active;
}

/* ==== Download: 0x34 RequestDownload, 0x36 TransferData, 0x37 RequestTransferExit ==== */

/* Session and key gate shared by 0x34/0x36/0x37: 0x7F outside programming, 0x33 without level 03, else 0. */
static uint8_t dl_access_nrc(const udsota_server_t *s)
{
    const udsota_svc_access_t a = udsota_access_check(s, s->cfg.level_programming);
    if (a.session != UDSOTA_SESSION_PROGRAMMING) {
        return UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    }
    if (!a.unlocked) {
        return UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    }
    return 0;
}

/* Size a 34 may announce: the engine's slot, or UDSOTA_SLOT_SIZE_DEFAULT while it reports 0. */
static uint32_t dl_slot_size(const udsota_server_t *s)
{
    return s->update.engine.slot_size != 0u ? s->update.engine.slot_size : UDSOTA_SLOT_SIZE_DEFAULT;
}

/* Ends a download whose erase or write failed on the worker: aborts it, then records UDSOTA_DL_FLASH_ERROR. */
static void dl_flash_failed(udsota_server_t *s)
{
    abort_download(s);
    s->update.last_dl.reason_code = UDSOTA_DL_FLASH_ERROR;
}

/* True for a coded dataFormatIdentifier: 10 (raw DEFLATE), 20 (delta) or 30 (delta as raw DEFLATE). */
static bool dl_dfi_coded(uint8_t dfi)
{
    return dfi == UDSOTA_DL_DFI_DEFLATE || dfi == UDSOTA_DL_DFI_DELTA || dfi == UDSOTA_DL_DFI_DELTA_DEFLATE;
}

/* True for a dataFormatIdentifier the server takes: 00, and a coded one the engine names in zformats while it has
 * zbegin and UDSOTA_COMPRESSION is on. */
static bool dl_dfi_ok(const udsota_server_t *s, uint8_t dfi)
{
    return dfi == UDSOTA_DL_DFI || (UDSOTA_COMPRESSION && dl_dfi_coded(dfi) && s->update.engine.zbegin != NULL &&
                                    (s->update.engine.zformats & UDSOTA_DL_FMT(dfi)) != 0u);
}

/* True while the open download is coded. A macro, so that with UDSOTA_COMPRESSION 0 it is the constant 0 at any
 * optimisation level and every coded branch compiles away. */
#define DL_Z(s) (UDSOTA_COMPRESSION && (s)->update.dl_compressed)

/* Bytes the 36s of this download may carry: memorySize, or UDSOTA_DL_Z_BOUND of it when coded. */
static uint32_t dl_limit(const udsota_server_t *s)
{
    if (!DL_Z(s)) {
        return s->update.dl_announced;
    }
    const uint64_t bound = UDSOTA_DL_Z_BOUND(s->update.dl_announced);
    return bound > UINT32_MAX ? UINT32_MAX : (uint32_t)bound;
}

/* A reason code from an engine result: r itself when it names one, else fallback. */
static uint8_t dl_reason(int r, udsota_reason_t fallback)
{
    return (r >= (int)UDSOTA_DL_OK && r < (int)UDSOTA_DL_REASON_COUNT) ? (uint8_t)r : (uint8_t)fallback;
}

/* Bytes of a 34 field an ALFID nibble gives: 1..UDSOTA_DL_FIELD_MAX, else 0 (an ALFID the server refuses). */
static size_t dl_field_len(uint8_t nibble)
{
    return (nibble >= 1u && nibble <= UDSOTA_DL_FIELD_MAX) ? nibble : 0u;
}

/* Reads a big-endian field of n bytes (1..UDSOTA_DL_FIELD_MAX) from p. */
static uint32_t dl_get_field(const uint8_t *p, size_t n)
{
    uint32_t v = 0u;
    for (size_t i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

/* 0x34: DFI 00 (or 10, 20 or 30 when engine.zformats names it), any ALFID with 1..4-byte fields (the client sends
 * 44), address 0 (no resume point), 0 < size <= slot, gated like 10 02; 74 20 0F FF. Check order: access, length
 * (under 3 bytes, or with a valid ALFID not exactly its fields: 0x13), conditions, then format and range (0x31). An
 * invalid ALFID sizes no fields, so it skips the exact length and gets the conditions' answer, then 0x31. With a
 * coded DFI a failed zbegin answers 0x22 before anything else changes, save an unverified image the same 34
 * released. */
static size_t handle_request_download(udsota_server_t *s, const uint8_t *req, size_t req_len,
                                      uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_REQUEST_DOWNLOAD;
    const uint8_t access = dl_access_nrc(s);
    if (access != 0u) {
        return udsota_nrc(resp, resp_max, sid, access);
    }
    if (req_len < UDSOTA_DL_REQ_MIN) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const size_t addr_len = dl_field_len(req[2] & 0x0Fu);
    const size_t size_len = dl_field_len((uint8_t)(req[2] >> 4));
    const bool alfid_ok = addr_len != 0u && size_len != 0u;
    if (alfid_ok && req_len != UDSOTA_DL_REQ_MIN + addr_len + size_len) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t cond = download_nrc(s, UDSOTA_OP_START_DOWNLOAD);   /* before the format check */
    if (cond != 0u) {
        return udsota_nrc(resp, resp_max, sid, cond);
    }
    if (!alfid_ok || !dl_dfi_ok(s, req[1])) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    const uint32_t addr = dl_get_field(&req[UDSOTA_DL_REQ_MIN], addr_len);
    const uint32_t size = dl_get_field(&req[UDSOTA_DL_REQ_MIN + addr_len], size_len);
    if (addr != 0u || size == 0u || size > dl_slot_size(s)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (resp_max < 4u) {
        return 0;
    }
    const bool compressed = UDSOTA_COMPRESSION && dl_dfi_coded(req[1]);
    if (compressed) {
        if (s->update.ota_open) {                        /* released first, so its abort cannot free the new decoder */
            s->update.engine.abort(s->update.engine.ctx);
            s->update.ota_open = false;
        }
        const int rc = s->update.engine.zbegin(s->update.engine.ctx, size, req[1]);
        if (rc != 0) {
            s->update.last_dl.reason_code = dl_reason(rc, UDSOTA_DL_NO_MEMORY);
            s->update.last_dl.bytes_received = 0u;
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
        }
    }
    /* Accepted. The other slot stops counting as verified before anything is queued. */
    if (s->update.engine.unverify != NULL) {
        s->update.engine.unverify(s->update.engine.ctx);
    }
    s->update.slot_verified = false;                     /* a new download clears FF01's pass */
    if (s->update.ota_open) {                            /* a finished image that never passed FF01: release its handle */
        s->update.engine.abort(s->update.engine.ctx);
        s->update.ota_open = false;
    }
    s->update.download_active = true;
    s->update.ota_open = compressed;                     /* the engine holds the decoder from here */
    s->update.dl_compressed = compressed;
    s->update.dl_complete = false;
    s->update.next_bsc = 1u;
    s->update.dl_announced = size;
    s->update.dl_received = 0u;
    s->update.dl_written = 0u;                           /* where done starts: a resumed download would start it at its offset */
    s->update.cf_median_us = UDSOTA_CF_MEDIAN_NONE;
    s->update.cf_stmin_us = 0u;
    s->update.last_dl.reason_code = UDSOTA_DL_OK;
    s->update.last_dl.bytes_received = 0u;
    resp[0] = UDSOTA_POS(sid);
    resp[1] = UDSOTA_DL_LFID;
    udsota_put_u16be(&resp[2], s->cfg.max_block_len);
    return 4;
}

/* True for a coded block's result that refuses the data rather than the flash: a first-block rule
 * (UDSOTA_DL_BAD_HEADER to UDSOTA_DL_TOO_BIG), UDSOTA_DL_BAD_STREAM or UDSOTA_DL_BAD_BASE. */
static bool dl_z_refused(int result)
{
    return (result >= (int)UDSOTA_DL_BAD_HEADER && result <= (int)UDSOTA_DL_TOO_BIG) ||
           result == (int)UDSOTA_DL_BAD_STREAM || result == (int)UDSOTA_DL_BAD_BASE;
}

/* Final answer for a 0x36 job (udsota_job_done_fn): 76 BSC once the worker wrote the block, else 0x72 and the
 * download ends with UDSOTA_DL_FLASH_ERROR. A coded block the engine refused (dl_z_refused) ends it with 0x31
 * and that reason instead, as a first-block refusal does. job_arg is the block's data length. */
static size_t dl_block_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    const uint8_t bsc = s->update.next_bsc;              /* unchanged since the 36 matched it: no 34 runs during a job */
    if (result != 0 && DL_Z(s) && dl_z_refused(result)) {
        abort_download(s);
        s->update.last_dl.reason_code = (uint8_t)result;
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_DATA, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (result != 0) {
        dl_flash_failed(s);
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_DATA, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    s->update.dl_received += udsota_job_arg(s);
    if (!DL_Z(s)) {
        s->update.dl_written += udsota_job_arg(s);              /* the block's bytes are image bytes */
    } else if (s->update.engine.zwritten != NULL) {
        const uint32_t written = s->update.engine.zwritten(s->update.engine.ctx);   /* coded: what the stream wrote */
        if (written > s->update.dl_written) {
            s->update.dl_written = written;              /* done never shrinks, whatever the engine says */
        }
    }
    s->update.progress_block = true;
    s->update.next_bsc = (uint8_t)(bsc + 1u);            /* 0xFF wraps to 0x00 */
    s->update.last_dl.bytes_received = s->update.dl_received;
    if (resp_max < 2u) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_TRANSFER_DATA);
    resp[1] = bsc;
    return 2;
}

/* 0x36: conditions (the STmin monitor, then gate(CONTINUE_TRANSFER)), repeat (76, no rewrite), counter (0x73),
 * overrun (0x71), first-block check (0x31), then the erase (first block) and the write go to the worker;
 * dl_block_done answers. The gate's 0x21 is "retry": the transfer stays open; any other refusal ends it and the
 * session. A coded block goes whole to engine.zwrite after the overrun check, which bounds it by
 * UDSOTA_DL_Z_BOUND; the engine runs the first-block check once enough is decoded. */
static size_t handle_transfer_data(udsota_server_t *s, const uint8_t *req, size_t req_len,
                                   uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_TRANSFER_DATA;
    const uint8_t access = dl_access_nrc(s);
    if (access != 0u) {
        return udsota_nrc(resp, resp_max, sid, access);
    }
    if (req_len < UDSOTA_TD_MIN_LEN || req_len > s->cfg.max_block_len) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (!s->update.download_active) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    }
    if (resp_max < 3u) {
        return 0;
    }
    const uint8_t cond = transfer_nrc(s);
    if (cond != 0u) {
        if (cond != UDSOTA_NRC_BUSY_REPEAT) {
            udsota_end_session_now(s);   /* aborts, records UDSOTA_DL_ABORTED, relocks */
        }
        return udsota_nrc(resp, resp_max, sid, cond);
    }
    const uint8_t bsc = req[1];
    const uint8_t *data = &req[2];
    const size_t len = req_len - 2u;
    /* Repeat before overrun: the resend of a final block whose 76 was lost must still get 76.
     * dl_received > 0 means a block was accepted in this download, so there is a "last" counter to repeat. */
    if (s->update.dl_received > 0u && bsc == (uint8_t)(s->update.next_bsc - 1u)) {
        udsota_sat_inc16(&udsota_counters(s)->repeated_blocks);
        resp[0] = UDSOTA_POS(sid);
        resp[1] = bsc;
        return 2;
    }
    if (bsc != s->update.next_bsc) {
        udsota_sat_inc16(&udsota_counters(s)->seq_errors);
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER);
    }
    if (len > dl_limit(s) - s->update.dl_received) {
        abort_download(s);                        /* iso14229 server.c:1060-1062: 0x71 ends the transfer */
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_TRANSFER_DATA_SUSPENDED);
    }
    if (!DL_Z(s) && !s->update.ota_open) {
        /* First block: check the image before anything is erased. */
        udsota_reason_t why = UDSOTA_DL_OK;
        if (s->update.engine.check_first(s->update.engine.ctx, data, len, &why) != 0) {
            abort_download(s);
            s->update.last_dl.reason_code = (uint8_t)(why != UDSOTA_DL_OK ? why : UDSOTA_DL_BAD_HEADER);
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
        }
        const int rc = s->update.engine.begin(s->update.engine.ctx, s->update.dl_announced);
        if (rc != 0 && rc != UDSOTA_PENDING) {   /* not even queued: no handle is open */
            dl_flash_failed(s);
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
        }
        s->update.ota_open = true;
    }
    /* Queued behind the erase on the first block; write and zwrite copy data before they return. */
    const int rc = DL_Z(s) ? s->update.engine.zwrite(s->update.engine.ctx, data, len)
                           : s->update.engine.write(s->update.engine.ctx, s->update.dl_received, data, len);
    return udsota_job_start(s, sid, false, rc, dl_block_done, (uint32_t)len, resp, resp_max, now_ms);
}

/* The 37's positive tail: the transfer closes, FF01 may verify the open image, F1F1 reads OK; 77. */
static size_t dl_exit_ok(udsota_server_t *s, uint8_t *resp)
{
    s->update.download_active = false;
    s->update.dl_complete = true;                        /* FF01 may now verify the open handle */
    s->update.last_dl.reason_code = UDSOTA_DL_OK;
    s->update.last_dl.bytes_received = s->update.dl_received;
    resp[0] = UDSOTA_POS(UDSOTA_SID_TRANSFER_EXIT);
    return 1;
}

/* Final answer for a coded 0x37 (udsota_job_done_fn): 77 once engine.zend found the stream or patch ended at
 * exactly memorySize, all written, with nothing after it; else 0x72, the download ends and F1F1 records zend's
 * reason (UDSOTA_DL_BAD_STREAM when it names none). */
static size_t dl_exit_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    if (result != 0) {
        abort_download(s);
        s->update.last_dl.reason_code = dl_reason(result, UDSOTA_DL_BAD_STREAM);
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_EXIT, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    if (resp_max < 1u) {
        return 0;
    }
    if (s->update.dl_written != s->update.dl_announced) {       /* the stream ended at memorySize: every byte is written */
        s->update.dl_written = s->update.dl_announced;
        s->update.progress_block = true;
    }
    return dl_exit_ok(s, resp);
}

/* 0x37: closes the transfer once every announced byte has arrived (else 0x24, still open); 77. The OTA
 * handle stays open for FF01. A coded transfer asks engine.zend, which may run as a worker job (0x78 meanwhile),
 * whether the stream or patch ended at exactly memorySize with nothing after it; dl_exit_done answers. */
static size_t handle_transfer_exit(udsota_server_t *s, size_t req_len, uint8_t *resp, size_t resp_max,
                                   uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_TRANSFER_EXIT;
    const uint8_t access = dl_access_nrc(s);
    if (access != 0u) {
        return udsota_nrc(resp, resp_max, sid, access);
    }
    if (req_len != 1u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (!s->update.download_active || (!DL_Z(s) && s->update.dl_received != s->update.dl_announced)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    }
    if (resp_max < 1u) {
        return 0;
    }
    if (DL_Z(s)) {
        return udsota_job_start(s, sid, false, s->update.engine.zend(s->update.engine.ctx), dl_exit_done, 0, resp, resp_max, now_ms);
    }
    return dl_exit_ok(s, resp);
}

/* The updater's fc_point: records the FC point's timing and asks transfer_nrc (the STmin monitor, then the gate);
 * true allows the FC. */
static bool upd_fc_point(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us)
{
    s->update.cf_median_us = median_cf_us;
    s->update.cf_stmin_us = stmin_us;
    return transfer_nrc(s) == 0u;
}

/* Writes 71 01 <rid> then status_len status bytes; returns the length, or 0 when resp is too small. */
static size_t routine_pos(uint8_t *resp, size_t resp_max, uint16_t rid, const uint8_t *status, size_t status_len)
{
    if (resp_max < 4u + status_len) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_ROUTINE);
    resp[1] = UDSOTA_RC_START;
    udsota_put_u16be(&resp[2], rid);
    if (status_len != 0u) {
        memcpy(&resp[4], status, status_len);
    }
    return 4u + status_len;
}

/* FF01 verdict: status byte = the worker's udsota_reason_t (anything else is UDSOTA_DL_VERIFY_FAILED); a pass
 * marks the slot verified until the next 0x34 or reboot, and F1F1 records the reason either way. */
static size_t check_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    const uint8_t reason = dl_reason(result, UDSOTA_DL_VERIFY_FAILED);
    s->update.slot_verified = (reason == UDSOTA_DL_OK);
    s->update.last_dl.reason_code = reason;
    return routine_pos(resp, resp_max, UDSOTA_RID_CHECK_PROG_DEPS, &reason, 1);
}

/* ActivateImage result: the boot slot is set, so answer and, with a reset hook, arm the restart (phase ACTIVATING);
 * without one the new image boots at the next power cycle. A failure is 0x72 and needs FF01 again. */
static size_t activate_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (result != 0) {
        s->update.slot_verified = false;
        return udsota_nrc(resp, resp_max, UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    (void)udsota_restart_arm(s, UDSOTA_RESTART_ACTIVATE, now_ms);   /* armed even if SPRMIB drops the answer */
    return routine_pos(resp, resp_max, UDSOTA_RID_ACTIVATE_IMAGE, NULL, 0);
}

/* F002 result: the running image is now VALID, or 0x72. */
static size_t confirm_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)s;
    (void)now_ms;
    if (result != 0) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    return routine_pos(resp, resp_max, UDSOTA_RID_CONFIRM_IMAGE, NULL, 0);
}

/* The updater's RIDs: FF01, F000, F001 and F002, in every session and whatever the sub-function. */
static bool upd_owns_rid(const udsota_server_t *s, uint16_t rid)
{
    (void)s;
    return rid == UDSOTA_RID_CHECK_PROG_DEPS || rid == UDSOTA_RID_GET_RESUME_POINT ||
           rid == UDSOTA_RID_ACTIVATE_IMAGE || rid == UDSOTA_RID_CONFIRM_IMAGE;
}

/* The updater's routine: its own RIDs (upd_owns_rid); any other is passed back (UDSOTA_SVC_PASS) before any check.
 * For its own, after the core's session, length and sub-function checks: RID in this session 31, key 33, exact
 * length 13, then per RID the sequence (24) before the conditions (22). */
static size_t upd_routine(udsota_server_t *s, uint16_t rid, const uint8_t *req, size_t len, bool spr,
                          uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)req;
    const uint8_t sid = UDSOTA_SID_ROUTINE;
    const bool confirm = (rid == UDSOTA_RID_CONFIRM_IMAGE);   /* extended, no key; the other three programming, keyed */
    if (!upd_owns_rid(s, rid)) {
        return UDSOTA_SVC_PASS;
    }
    const udsota_svc_access_t access = udsota_access_check(s, s->cfg.level_programming);
    if (access.session != (confirm ? UDSOTA_SESSION_EXTENDED : UDSOTA_SESSION_PROGRAMMING)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (!confirm && !access.unlocked) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    }
    if (len != 4u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    switch (rid) {
    case UDSOTA_RID_CHECK_PROG_DEPS:
        if (s->update.slot_verified && !s->update.ota_open) {        /* passed, no new download since: repeat the verdict */
            const uint8_t status = UDSOTA_DL_OK;
            return spr ? 0 : routine_pos(resp, resp_max, rid, &status, 1);
        }
        if (!s->update.dl_complete || !s->update.ota_open) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
        }
        s->update.dl_complete = false;                        /* the engine's verify frees the handle whatever it finds, */
        s->update.ota_open = false;                           /* so FF01 again is 0x24, or 00 after a pass */
        s->update.slot_verified = false;
        s->update.last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;    /* check_done overwrites it; stays if the 90 s cap fires */
        return udsota_job_start(s, sid, spr, s->update.engine.verify(s->update.engine.ctx), check_done, 0, resp, resp_max, now_ms);
    case UDSOTA_RID_GET_RESUME_POINT: {
        const uint8_t status = UDSOTA_RESUME_NOT_AVAILABLE;   /* resume is not implemented: always not available */
        return spr ? 0 : routine_pos(resp, resp_max, rid, &status, 1);
    }
    case UDSOTA_RID_ACTIVATE_IMAGE: {
        if (!s->update.slot_verified) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
        }
        const uint8_t cond = udsota_restart_nrc(s, UDSOTA_OP_ACTIVATE);
        if (cond != 0u) {
            return udsota_nrc(resp, resp_max, sid, cond);
        }
        return udsota_job_start(s, sid, spr, s->update.engine.activate(s->update.engine.ctx), activate_done, 0, resp, resp_max, now_ms);
    }
    default: {   /* UDSOTA_RID_CONFIRM_IMAGE: the gate first, then the core rule */
        const uint8_t cond = udsota_gate(s, UDSOTA_OP_CONFIRM);
        if (cond != 0u) {
            return udsota_nrc(resp, resp_max, sid, cond);
        }
        switch (confirm_action(s)) {
        case CONFIRM_RUN:
            return udsota_job_start(s, sid, spr, s->update.engine.confirm(s->update.engine.ctx), confirm_done, 0,
                                    resp, resp_max, now_ms);
        case CONFIRM_ALREADY:
            return spr ? 0 : routine_pos(resp, resp_max, rid, NULL, 0);   /* already confirmed: idempotent */
        default:
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
        }
    }
    }
}

/* ---- Progress: the stage and bytes udsota_progress reads and hooks.progress gets ---- */

/* The progress the server's state implies (see udsota_stage_t); reads nothing but s. */
static udsota_progress_t progress_of(const udsota_server_t *s)
{
    udsota_progress_t p = {.stage = UDSOTA_STAGE_IDLE, .done = 0u, .total = 0u,
                           .last_reason = s->update.last_dl.reason_code};
    if (udsota_activating(s)) {
        p.stage = UDSOTA_STAGE_ACTIVATING;
    } else if (udsota_job_waiting_on(s, check_done)) {
        p.stage = UDSOTA_STAGE_VERIFYING;              /* engines report no hash progress: 0 of 0 */
    } else if (s->update.download_active || (s->update.dl_complete && s->update.ota_open)) {
        const bool erasing = s->update.download_active && s->update.dl_received == 0u;   /* no 36 accepted yet */
        p.stage = erasing ? UDSOTA_STAGE_ERASING : UDSOTA_STAGE_WRITING;
        p.total = s->update.dl_announced;
        p.done = (s->update.dl_written < p.total) ? s->update.dl_written : p.total;
    }
    return p;
}

/* Reports progress to hooks.progress, once, at the end of the server call that changed the stage or the last reason,
 * or wrote a block. */
static void progress_sync(udsota_server_t *s)
{
    const udsota_progress_t p = progress_of(s);
    const bool block = s->update.progress_block;
    s->update.progress_block = false;
    if ((uint8_t)p.stage == s->update.progress_stage && !block && p.last_reason == s->update.progress_reason) {
        return;
    }
    s->update.progress_stage = (uint8_t)p.stage;
    s->update.progress_reason = p.last_reason;
    if (s->hooks.progress != NULL) {
        s->hooks.progress(s->hooks.ctx, &p);
    }
}

/* See udsota_update.h: the progress of the server's state as it is now. */
void udsota_progress(const udsota_server_t *s, udsota_progress_t *out)
{
    *out = progress_of(s);
}

/* See udsota_update.h: done / total in permille, 0 without a total. */
uint16_t udsota_progress_permille(const udsota_progress_t *p)
{
    if (p->total == 0u) {
        return 0u;
    }
    const uint64_t done = (p->done < p->total) ? p->done : p->total;
    return (uint16_t)(done * 1000u / p->total);
}

/* ---- The updater as the server's service (udsota_service.h) ---- */

/* The updater's request: 0x34, 0x36 and 0x37; any other SID is passed back. */
static size_t upd_request(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max,
                          uint32_t now_ms)
{
    switch (req[0]) {
    case UDSOTA_SID_REQUEST_DOWNLOAD:
        return handle_request_download(s, req, len, resp, resp_max);
    case UDSOTA_SID_TRANSFER_DATA:
        return handle_transfer_data(s, req, len, resp, resp_max, now_ms);
    case UDSOTA_SID_TRANSFER_EXIT:
        return handle_transfer_exit(s, len, resp, resp_max, now_ms);
    default:
        return UDSOTA_SVC_PASS;
    }
}

/* The updater's DIDs: F1F1 from its own state; F189, F1F0 and F1F3 from engine.version, engine.status and
 * engine.running_sha, each passed back (to hooks.did_read) while its source is NULL. F1F0 and F1F1 return their
 * length when room is short, as an engine op returns its own, and the server answers 0x14. An engine's
 * SIZE_MAX answers 0x31, as before, and never reaches the app's hook. */
static size_t upd_read_did(const udsota_server_t *s, uint16_t did, uint8_t *out, size_t room)
{
    size_t n;
    if (did == UDSOTA_DID_RESULT) {
        n = room < UDSOTA_RESULT_LEN ? UDSOTA_RESULT_LEN : udsota_pack_result(out, room, &s->update.last_dl);
    } else if (did == UDSOTA_DID_SW_VERSION && s->update.engine.version != NULL) {
        n = s->update.engine.version(s->update.engine.ctx, (char *)out, room);
    } else if (did == UDSOTA_DID_STATUS && s->update.engine.status != NULL) {
        if (room < UDSOTA_STATUS_LEN) {
            return UDSOTA_STATUS_LEN;
        }
        udsota_status_t st;
        status_now(s, &st);
        n = udsota_pack_status(out, room, &st);
    } else if (did == UDSOTA_DID_RUNNING_SHA && s->update.engine.running_sha != NULL) {
        n = s->update.engine.running_sha(s->update.engine.ctx, out, room);
    } else {
        return UDSOTA_SVC_PASS;
    }
    return n == UDSOTA_SVC_PASS ? 0u : n;
}

/* The updater's poll: engine.poll. */
static int upd_poll(const udsota_server_t *s)
{
    return s->update.engine.poll(s->update.engine.ctx);
}

static const udsota_service_t k_update_service = {
    .request = upd_request,
    .routine = upd_routine,
    .owns_rid = upd_owns_rid,
    .read_did = upd_read_did,
    .on_session = upd_on_session,
    .settled = slots_settled,
    .download_active = upd_download_active,
    .poll = upd_poll,
    .fc_point = upd_fc_point,
    .sync = progress_sync,
};

/* See udsota_update.h: copies the engine and registers the updater as s's service. */
void udsota_update_init(udsota_server_t *s, const udsota_engine_t *engine)
{
    s->update.engine = *engine;
    udsota_register_service(s, &k_update_service);
}

/* See udsota_update.h: udsota_core_init, then, with an engine, udsota_update_init. Without one the server runs
 * without the updater: its SIDs (34, 36 and 37), RIDs and DIDs go to the app's hooks, request among them. */
bool udsota_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_engine_t *engine,
                 const udsota_security_t *security, const udsota_hooks_t *hooks)
{
    const bool ok = udsota_core_init(s, cfg, security, hooks);
    if (engine != NULL) {
        udsota_update_init(s, engine);
    }
    return ok;
}
