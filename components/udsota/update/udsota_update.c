/* The firmware updater (udsota_update.h), free of any UDS server: 0x34, 0x36 and 0x37, the RIDs FF01 and F000-F002,
 * the DIDs F189, F1F0, F1F1 and F1F3, the 10 02 slot rule and download progress, over the engine udsota_upd_init was
 * given. The rules and their NRC order are those udsota's own server applied; what a host server already checks
 * (framing, the 36 block counter, the transfer's byte count) it simply checks again. */
#include <string.h>
#include "udsota_update.h"
#include "udsota_update_wire.h"

/* engine.status into *st, zeroed first; only called when engine.status is set. */
static void status_now(const udsota_updater_t *u, udsota_status_t *st)
{
    memset(st, 0, sizeof *st);
    u->st.engine.status(u->st.engine.ctx, st);
}

/* Slot rule for 10 02 and 34: the boot slot is the running slot (both known) and the running image is not
 * PENDING_VERIFY. True without engine.status (not used = not checked). */
static bool slots_settled(const udsota_updater_t *u)
{
    if (u->st.engine.status == NULL) {
        return true;
    }
    udsota_status_t st;
    status_now(u, &st);
    return st.running_slot != UDSOTA_SLOT_NONE && st.boot_slot == st.running_slot &&
           st.running_state != UDSOTA_IMG_PENDING_VERIFY;
}

/* What ConfirmImage does once the gate has allowed it. */
typedef enum { CONFIRM_REFUSE, CONFIRM_RUN, CONFIRM_ALREADY } confirm_action_t;

/* ConfirmImage rule: the boot slot must be the running one (both known); a PENDING_VERIFY image goes to
 * engine.confirm; one already VALID, or UNDEFINED as builds without rollback report, is confirmed already; any
 * other state is refused. Without engine.status the engine decides. */
static confirm_action_t confirm_action(const udsota_updater_t *u)
{
    if (u->st.engine.status == NULL) {
        return CONFIRM_RUN;
    }
    udsota_status_t st;
    status_now(u, &st);
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

/* The app's gate for op: 0 (allow, also without a gate) or its NRC. */
static uint8_t gate(const udsota_updater_t *u, udsota_op_t op)
{
    return (u->cfg.gate != NULL) ? u->cfg.gate(u->cfg.ctx, op) : 0u;
}

bool udsota_upd_busy(const udsota_updater_t *u)
{
    return u->job_running || u->st.engine.poll(u->st.engine.ctx) == UDSOTA_PENDING;
}

bool udsota_upd_download_active(const udsota_updater_t *u)
{
    return u->st.download_active;
}

/* START_DOWNLOAD: slots settled, worker idle and no transfer open, then the gate. */
static uint8_t download_nrc(const udsota_updater_t *u)
{
    if (!slots_settled(u) || udsota_upd_busy(u) || u->st.download_active) {
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return gate(u, UDSOTA_OP_START_DOWNLOAD);
}

/* Ends a download or an open, unverified image: queues the engine's abort without waiting and records
 * UDSOTA_DL_ABORTED in F1F1. dl_complete is cleared either way, so FF01 never sees a closed transfer without its
 * handle. */
static void abort_download(udsota_updater_t *u)
{
    u->st.dl_complete = false;
    if (!u->st.download_active && !u->st.ota_open) {
        return;
    }
    if (u->st.ota_open) {
        u->st.engine.abort(u->st.engine.ctx);
    }
    u->st.download_active = false;
    u->st.ota_open = false;
    u->st.last_dl.reason_code = UDSOTA_DL_ABORTED;
    u->st.last_dl.bytes_received = u->st.dl_received;
}

/* ---- Progress: the stage and bytes udsota_progress reads and cfg.progress gets ---- */

static int check_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len);

/* The progress the updater's state implies (see udsota_stage_t); reads nothing but u. */
static udsota_progress_t progress_of(const udsota_updater_t *u)
{
    udsota_progress_t p = {.stage = UDSOTA_STAGE_IDLE, .done = 0u, .total = 0u,
                           .last_reason = u->st.last_dl.reason_code};
    if (u->activating) {
        p.stage = UDSOTA_STAGE_ACTIVATING;
    } else if (u->job_running && u->job_done == check_done) {
        p.stage = UDSOTA_STAGE_VERIFYING;
    } else if (u->st.download_active || (u->st.dl_complete && u->st.ota_open)) {
        const bool erasing = u->st.download_active && u->st.dl_received == 0u;   /* no 36 accepted yet */
        p.stage = erasing ? UDSOTA_STAGE_ERASING : UDSOTA_STAGE_WRITING;
        p.total = u->st.dl_announced;
        p.done = (u->st.dl_written < p.total) ? u->st.dl_written : p.total;
    }
    return p;
}

/* Reports progress to cfg.progress, once, at the end of the call that changed the stage or the last reason, or
 * wrote a block. Every public entry point that changes state ends here. */
static void progress_sync(udsota_updater_t *u)
{
    const udsota_progress_t p = progress_of(u);
    const bool block = u->st.progress_block;
    u->st.progress_block = false;
    if ((uint8_t)p.stage == u->st.progress_stage && !block && p.last_reason == u->st.progress_reason) {
        return;
    }
    u->st.progress_stage = (uint8_t)p.stage;
    u->st.progress_reason = p.last_reason;
    if (u->cfg.progress != NULL) {
        u->cfg.progress(u->cfg.ctx, &p);
    }
}

void udsota_progress(const udsota_updater_t *u, udsota_progress_t *out)
{
    *out = progress_of(u);
}

uint16_t udsota_progress_permille(const udsota_progress_t *p)
{
    if (p->total == 0u) {
        return 0u;
    }
    const uint64_t done = (p->done < p->total) ? p->done : p->total;
    return (uint16_t)(done * 1000u / p->total);
}

/* ---- The worker-job wait ---- */

/* Finishes a handler whose engine op may have queued worker work: UDSOTA_PENDING stores done and arg for
 * udsota_upd_resume and returns UDSOTA_PENDING; any other rc calls done(rc) now. */
static int job_start(udsota_updater_t *u, int rc, udsota_upd_done_fn done, uint32_t arg, uint8_t *status,
                     size_t status_max, size_t *status_len)
{
    u->job_arg = arg;
    if (rc == UDSOTA_PENDING) {
        u->job_running = true;
        u->job_done = done;
        return UDSOTA_PENDING;
    }
    return done(u, rc, status, status_max, status_len);
}

int udsota_upd_resume(udsota_updater_t *u, uint8_t *status, size_t status_max, size_t *status_len)
{
    *status_len = 0;
    if (!u->job_running) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    const int r = u->st.engine.poll(u->st.engine.ctx);
    if (r == UDSOTA_PENDING) {
        return UDSOTA_PENDING;
    }
    const int rc = u->job_done(u, r, status, status_max, status_len);
    u->job_running = false;
    progress_sync(u);
    return rc;
}

/* ==== Download: 0x34 RequestDownload, 0x36 TransferData, 0x37 RequestTransferExit ==== */

/* Session and key rule shared by 0x34/0x36/0x37: 0x7F outside programming, 0x33 without the programming level. */
static uint8_t dl_access_nrc(udsota_upd_access_t a)
{
    if (a.session != UDSOTA_SESSION_PROGRAMMING) {
        return UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    }
    if (!a.unlocked) {
        return UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    }
    return 0;
}

/* Size a 34 may announce: the engine's slot, or UDSOTA_SLOT_SIZE_DEFAULT while it reports 0. */
static uint32_t dl_slot_size(const udsota_updater_t *u)
{
    return u->st.engine.slot_size != 0u ? u->st.engine.slot_size : UDSOTA_SLOT_SIZE_DEFAULT;
}

/* Ends a download whose erase or write failed on the worker: aborts it, then records UDSOTA_DL_FLASH_ERROR. */
static void dl_flash_failed(udsota_updater_t *u)
{
    abort_download(u);
    u->st.last_dl.reason_code = UDSOTA_DL_FLASH_ERROR;
}

/* True for a coded dataFormatIdentifier: 10 (raw DEFLATE), 20 (delta) or 30 (delta as raw DEFLATE). */
static bool dl_dfi_coded(uint8_t dfi)
{
    return dfi == UDSOTA_DL_DFI_DEFLATE || dfi == UDSOTA_DL_DFI_DELTA || dfi == UDSOTA_DL_DFI_DELTA_DEFLATE;
}

/* True for a dataFormatIdentifier the updater takes: 00, and a coded one the engine names in zformats. */
static bool dl_dfi_ok(const udsota_updater_t *u, uint8_t dfi)
{
    return dfi == UDSOTA_DL_DFI || (UDSOTA_COMPRESSION && dl_dfi_coded(dfi) && u->st.engine.zbegin != NULL &&
                                    (u->st.engine.zformats & UDSOTA_DL_FMT(dfi)) != 0u);
}

/* True while the open download is coded; a macro, so every coded branch compiles away without compression. */
#define DL_Z(u) (UDSOTA_COMPRESSION && (u)->st.dl_compressed)

/* Bytes the 36s of this download may carry: memorySize, or UDSOTA_DL_Z_BOUND of it when coded. */
static uint32_t dl_limit(const udsota_updater_t *u)
{
    if (!DL_Z(u)) {
        return u->st.dl_announced;
    }
    const uint64_t bound = UDSOTA_DL_Z_BOUND(u->st.dl_announced);
    return bound > UINT32_MAX ? UINT32_MAX : (uint32_t)bound;
}

/* A reason code from an engine result: r itself when it names one, else fallback. */
static uint8_t dl_reason(int r, udsota_reason_t fallback)
{
    return (r >= (int)UDSOTA_DL_OK && r < (int)UDSOTA_DL_REASON_COUNT) ? (uint8_t)r : (uint8_t)fallback;
}

/* 0x34: access, conditions (settled, idle, no transfer, gate), then DFI 00 (or a coded one the engine serves),
 * address 0 and 0 < size <= slot. The host decoded the address and length format. With a coded DFI a failed zbegin
 * answers 0x22 before anything else changes. */
int udsota_upd_request_download(udsota_updater_t *u, udsota_upd_access_t a, uint8_t dfi, uint32_t addr,
                                uint32_t size, uint16_t *max_block_len)
{
    const uint8_t access = dl_access_nrc(a);
    if (access != 0u) {
        return access;
    }
    const uint8_t cond = download_nrc(u);
    if (cond != 0u) {
        return cond;
    }
    if (!dl_dfi_ok(u, dfi) || addr != 0u || size == 0u || size > dl_slot_size(u)) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    const bool compressed = UDSOTA_COMPRESSION && dl_dfi_coded(dfi);
    if (compressed) {
        if (u->st.ota_open) {                            /* released first, so its abort cannot free the new decoder */
            u->st.engine.abort(u->st.engine.ctx);
            u->st.ota_open = false;
        }
        const int rc = u->st.engine.zbegin(u->st.engine.ctx, size, dfi);
        if (rc != 0) {
            u->st.last_dl.reason_code = dl_reason(rc, UDSOTA_DL_NO_MEMORY);
            u->st.last_dl.bytes_received = 0u;
            progress_sync(u);
            return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
        }
    }
    /* Accepted. The other slot stops counting as verified before anything is queued. */
    if (u->st.engine.unverify != NULL) {
        u->st.engine.unverify(u->st.engine.ctx);
    }
    u->st.slot_verified = false;
    if (u->st.ota_open) {                                /* a finished image that never passed FF01: release its handle */
        u->st.engine.abort(u->st.engine.ctx);
        u->st.ota_open = false;
    }
    u->st.download_active = true;
    u->st.ota_open = compressed;                         /* the engine holds the decoder from here */
    u->st.dl_compressed = compressed;
    u->st.dl_complete = false;
    u->st.next_bsc = 1u;
    u->st.dl_announced = size;
    u->st.dl_received = 0u;
    u->st.dl_written = 0u;
    u->st.last_dl.reason_code = UDSOTA_DL_OK;
    u->st.last_dl.bytes_received = 0u;
    *max_block_len = u->cfg.max_block_len;
    progress_sync(u);
    return 0;
}

/* True for a coded block's result that refuses the data rather than the flash. */
static bool dl_z_refused(int result)
{
    return (result >= (int)UDSOTA_DL_BAD_HEADER && result <= (int)UDSOTA_DL_TOO_BIG) ||
           result == (int)UDSOTA_DL_BAD_STREAM || result == (int)UDSOTA_DL_BAD_BASE;
}

/* Final answer for a 0x36 job: positive once the worker wrote the block, else 0x72 and the download ends with
 * UDSOTA_DL_FLASH_ERROR; a coded block the engine refused ends it with 0x31 and that reason. job_arg is the block's
 * data length. */
static int dl_block_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len)
{
    (void)status;
    (void)status_max;
    *status_len = 0;
    if (result != 0 && DL_Z(u) && dl_z_refused(result)) {
        abort_download(u);
        u->st.last_dl.reason_code = (uint8_t)result;
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    if (result != 0) {
        dl_flash_failed(u);
        return UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE;
    }
    u->st.dl_received += u->job_arg;
    if (!DL_Z(u)) {
        u->st.dl_written += u->job_arg;
    } else if (u->st.engine.zwritten != NULL) {
        const uint32_t written = u->st.engine.zwritten(u->st.engine.ctx);
        if (written > u->st.dl_written) {
            u->st.dl_written = written;                  /* done never shrinks */
        }
    }
    u->st.progress_block = true;
    u->st.next_bsc = (uint8_t)(u->st.next_bsc + 1u);    /* 0xFF wraps to 0x00 */
    u->st.last_dl.bytes_received = u->st.dl_received;
    return 0;
}

/* 0x36: access, length, sequence (0x24 without a transfer), the gate (any refusal but 0x21 ends the transfer),
 * the block counter (a repeat of the last one is answered without a rewrite, else 0x73), overrun (0x71), the
 * first-block check (0x31), then the erase (first block) and the write go to the worker. */
int udsota_upd_transfer_data(udsota_updater_t *u, udsota_upd_access_t a, uint8_t bsc, const uint8_t *data,
                             size_t len)
{
    int rc = dl_access_nrc(a);
    if (rc != 0) {
        return rc;
    }
    if (len < 1u || len + 2u > u->cfg.max_block_len) {
        return UDSOTA_NRC_INCORRECT_LENGTH;
    }
    if (!u->st.download_active) {
        return UDSOTA_NRC_REQUEST_SEQUENCE_ERROR;
    }
    const uint8_t cond = gate(u, UDSOTA_OP_CONTINUE_TRANSFER);
    if (cond != 0u) {
        if (cond != UDSOTA_NRC_BUSY_REPEAT) {
            abort_download(u);
            u->end_session = true;                       /* ends the session and relocks, as before */
            progress_sync(u);
        }
        return cond;
    }
    if (u->st.dl_received > 0u && bsc == (uint8_t)(u->st.next_bsc - 1u)) {
        return 0;                                        /* the resend of a block whose answer was lost */
    }
    if (bsc != u->st.next_bsc) {
        return UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER;
    }
    if (len > dl_limit(u) - u->st.dl_received) {
        abort_download(u);
        progress_sync(u);
        return UDSOTA_NRC_TRANSFER_DATA_SUSPENDED;
    }
    if (!DL_Z(u) && !u->st.ota_open) {
        /* First block: check the image before anything is erased. */
        udsota_reason_t why = UDSOTA_DL_OK;
        if (u->st.engine.check_first(u->st.engine.ctx, data, len, &why) != 0) {
            abort_download(u);
            u->st.last_dl.reason_code = (uint8_t)(why != UDSOTA_DL_OK ? why : UDSOTA_DL_BAD_HEADER);
            progress_sync(u);
            return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
        }
        rc = u->st.engine.begin(u->st.engine.ctx, u->st.dl_announced);
        if (rc != 0 && rc != UDSOTA_PENDING) {           /* not even queued: no handle is open */
            dl_flash_failed(u);
            progress_sync(u);
            return UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE;
        }
        u->st.ota_open = true;
    }
    /* Queued behind the erase on the first block; write and zwrite copy data before they return. */
    rc = DL_Z(u) ? u->st.engine.zwrite(u->st.engine.ctx, data, len)
                 : u->st.engine.write(u->st.engine.ctx, u->st.dl_received, data, len);
    size_t none = 0;
    rc = job_start(u, rc, dl_block_done, (uint32_t)len, NULL, 0, &none);
    progress_sync(u);
    return rc;
}

/* The 37's positive tail: the transfer closes, FF01 may verify the open image, F1F1 reads OK. */
static int dl_exit_ok(udsota_updater_t *u)
{
    u->st.download_active = false;
    u->st.dl_complete = true;
    u->st.last_dl.reason_code = UDSOTA_DL_OK;
    u->st.last_dl.bytes_received = u->st.dl_received;
    return 0;
}

/* Final answer for a coded 0x37: positive once engine.zend found the stream ended at exactly memorySize, all
 * written, with nothing after it; else 0x72, and the download ends with zend's reason. */
static int dl_exit_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len)
{
    (void)status;
    (void)status_max;
    *status_len = 0;
    if (result != 0) {
        abort_download(u);
        u->st.last_dl.reason_code = dl_reason(result, UDSOTA_DL_BAD_STREAM);
        return UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE;
    }
    if (u->st.dl_written != u->st.dl_announced) {
        u->st.dl_written = u->st.dl_announced;
        u->st.progress_block = true;
    }
    return dl_exit_ok(u);
}

/* 0x37: closes the transfer once every announced byte has arrived (else 0x24). The engine's handle stays open for
 * FF01. A coded transfer asks engine.zend, which may run as a worker job. */
int udsota_upd_transfer_exit(udsota_updater_t *u, udsota_upd_access_t a, size_t extra_len)
{
    const uint8_t access = dl_access_nrc(a);
    if (access != 0u) {
        return access;
    }
    if (extra_len != 0u) {
        return UDSOTA_NRC_INCORRECT_LENGTH;
    }
    if (!u->st.download_active || (!DL_Z(u) && u->st.dl_received != u->st.dl_announced)) {
        return UDSOTA_NRC_REQUEST_SEQUENCE_ERROR;
    }
    size_t none = 0;
    const int rc = DL_Z(u) ? job_start(u, u->st.engine.zend(u->st.engine.ctx), dl_exit_done, 0, NULL, 0, &none)
                           : dl_exit_ok(u);
    progress_sync(u);
    return rc;
}

/* ==== 0x31 RoutineControl ==== */

/* One status byte into status; 0x10 (never expected) when there is no room. */
static int status_byte(uint8_t *status, size_t status_max, size_t *status_len, uint8_t b)
{
    if (status_max < 1u) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    status[0] = b;
    *status_len = 1;
    return 0;
}

/* FF01 verdict: status byte = the worker's udsota_reason_t (anything else is UDSOTA_DL_VERIFY_FAILED); a pass marks
 * the slot verified until the next 0x34 or reboot, and F1F1 records the reason either way. */
static int check_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len)
{
    const uint8_t reason = dl_reason(result, UDSOTA_DL_VERIFY_FAILED);
    u->st.slot_verified = (reason == UDSOTA_DL_OK);
    u->st.last_dl.reason_code = reason;
    return status_byte(status, status_max, status_len, reason);
}

/* ActivateImage result: the boot slot is set, so answer and mark the restart (the host restarts once the answer
 * has left); a failure is 0x72 and needs FF01 again. */
static int activate_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len)
{
    (void)status;
    (void)status_max;
    *status_len = 0;
    if (result != 0) {
        u->st.slot_verified = false;
        return UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE;
    }
    u->activating = true;
    return 0;
}

/* F002 result: the running image is now VALID, or 0x72. */
static int confirm_done(udsota_updater_t *u, int result, uint8_t *status, size_t status_max, size_t *status_len)
{
    (void)u;
    (void)status;
    (void)status_max;
    *status_len = 0;
    return (result != 0) ? UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE : 0;
}

/* FF01, F000, F001 and F002; any other RID passes before any check. For the updater's own: 7F in the default
 * session, 12 for a control other than startRoutine, then the RID's session 31, key 33, exact length 13, then per
 * RID the sequence (24) before the conditions (22). */
static int routine(udsota_updater_t *u, udsota_upd_access_t a, uint8_t ctrl, uint16_t rid, size_t opt_len,
                   uint8_t *status, size_t status_max, size_t *status_len)
{
    const bool confirm = (rid == UDSOTA_RID_CONFIRM_IMAGE);   /* extended, no key; the other three programming, keyed */
    if (!confirm && rid != UDSOTA_RID_CHECK_PROG_DEPS && rid != UDSOTA_RID_GET_RESUME_POINT &&
        rid != UDSOTA_RID_ACTIVATE_IMAGE) {
        return UDSOTA_UPD_PASS;
    }
    if (a.session == UDSOTA_SESSION_DEFAULT) {
        return UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    }
    if (ctrl != UDSOTA_RC_START) {
        return UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED;
    }
    if (a.session != (confirm ? UDSOTA_SESSION_EXTENDED : UDSOTA_SESSION_PROGRAMMING)) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    if (!confirm && !a.unlocked) {
        return UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    }
    if (opt_len != 0u) {
        return UDSOTA_NRC_INCORRECT_LENGTH;
    }
    switch (rid) {
    case UDSOTA_RID_CHECK_PROG_DEPS:
        if (u->st.slot_verified && !u->st.ota_open) {           /* passed, no new download since: repeat the verdict */
            return status_byte(status, status_max, status_len, UDSOTA_DL_OK);
        }
        if (!u->st.dl_complete || !u->st.ota_open) {
            return UDSOTA_NRC_REQUEST_SEQUENCE_ERROR;
        }
        u->st.dl_complete = false;                        /* the engine's verify frees the handle whatever it finds */
        u->st.ota_open = false;
        u->st.slot_verified = false;
        u->st.last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;   /* check_done overwrites it */
        return job_start(u, u->st.engine.verify(u->st.engine.ctx), check_done, 0, status, status_max, status_len);
    case UDSOTA_RID_GET_RESUME_POINT:
        return status_byte(status, status_max, status_len, UDSOTA_RESUME_NOT_AVAILABLE);
    case UDSOTA_RID_ACTIVATE_IMAGE: {
        if (!u->st.slot_verified) {
            return UDSOTA_NRC_REQUEST_SEQUENCE_ERROR;
        }
        const uint8_t cond = udsota_upd_busy(u) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : gate(u, UDSOTA_OP_ACTIVATE);
        if (cond != 0u) {
            return cond;
        }
        return job_start(u, u->st.engine.activate(u->st.engine.ctx), activate_done, 0, status, status_max,
                         status_len);
    }
    default: {   /* UDSOTA_RID_CONFIRM_IMAGE: the gate first, then the rule */
        const uint8_t cond = gate(u, UDSOTA_OP_CONFIRM);
        if (cond != 0u) {
            return cond;
        }
        switch (confirm_action(u)) {
        case CONFIRM_RUN:
            return job_start(u, u->st.engine.confirm(u->st.engine.ctx), confirm_done, 0, status, status_max,
                             status_len);
        case CONFIRM_ALREADY:
            return 0;                                     /* already confirmed: idempotent */
        default:
            return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
        }
    }
    }
}

int udsota_upd_routine(udsota_updater_t *u, udsota_upd_access_t a, uint8_t ctrl, uint16_t rid, size_t opt_len,
                       uint8_t *status, size_t status_max, size_t *status_len)
{
    *status_len = 0;
    const int rc = routine(u, a, ctrl, rid, opt_len, status, status_max, status_len);
    progress_sync(u);
    return rc;
}

/* ==== The rest of the host's calls ==== */

/* F1F1 from the updater's own state; F189, F1F0 and F1F3 from engine.version, engine.status and
 * engine.running_sha, each passed while its source is NULL. */
size_t udsota_upd_read_did(udsota_updater_t *u, uint16_t did, uint8_t *out, size_t room)
{
    size_t n;
    if (did == UDSOTA_DID_RESULT) {
        n = udsota_pack_result(out, room, &u->st.last_dl);
    } else if (did == UDSOTA_DID_SW_VERSION && u->st.engine.version != NULL) {
        n = u->st.engine.version(u->st.engine.ctx, (char *)out, room);
    } else if (did == UDSOTA_DID_STATUS && u->st.engine.status != NULL) {
        udsota_status_t st;
        status_now(u, &st);
        n = udsota_pack_status(out, room, &st);
    } else if (did == UDSOTA_DID_RUNNING_SHA && u->st.engine.running_sha != NULL) {
        n = u->st.engine.running_sha(u->st.engine.ctx, out, room);
    } else {
        return UDSOTA_UPD_DID_PASS;
    }
    return n == UDSOTA_UPD_DID_PASS ? 0u : n;
}

uint8_t udsota_upd_session_nrc(const udsota_updater_t *u, uint8_t session)
{
    if (session == UDSOTA_SESSION_PROGRAMMING) {
        if (!slots_settled(u) || udsota_upd_busy(u) || u->st.download_active) {
            return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
        }
        return gate(u, UDSOTA_OP_ENTER_PROGRAMMING);
    }
    return (session == UDSOTA_SESSION_EXTENDED) ? gate(u, UDSOTA_OP_ENTER_EXTENDED) : 0u;
}

void udsota_upd_on_session(udsota_updater_t *u)
{
    u->job_running = false;
    abort_download(u);
    progress_sync(u);
}

void udsota_upd_job_expired(udsota_updater_t *u)
{
    const bool was = u->st.download_active || u->st.ota_open;
    u->job_running = false;
    abort_download(u);
    if (was) {
        u->st.last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;   /* an FF01's placeholder already reads it */
    }
    progress_sync(u);
}

bool udsota_upd_take_end_session(udsota_updater_t *u)
{
    const bool end = u->end_session;
    u->end_session = false;
    return end;
}

void udsota_upd_transfer_ended(udsota_updater_t *u)
{
    if (u->st.download_active) {
        abort_download(u);
        progress_sync(u);
    }
}

uint8_t udsota_upd_reset_nrc(const udsota_updater_t *u)
{
    return udsota_upd_busy(u) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : gate(u, UDSOTA_OP_RESET);
}

void udsota_upd_init(udsota_updater_t *u, const udsota_engine_t *engine, const udsota_upd_config_t *cfg)
{
    memset(u, 0, sizeof *u);
    if (cfg != NULL) {
        u->cfg = *cfg;
    }
    if (u->cfg.max_block_len == 0u || u->cfg.max_block_len > UDSOTA_DL_MAX_BLOCK_LEN) {
        u->cfg.max_block_len = UDSOTA_DL_MAX_BLOCK_LEN;
    }
    u->st.engine = *engine;
}
