/* udsota's updater on iso14229's server (udsota_iso14229.h). iso14229 parses, frames, times and suppresses; this
 * file maps each event to the updater with the session state iso14229 keeps (sessionType, securityLevel), and adds
 * the rules udsota's own server kept that iso14229 leaves to the app: relock and abort on every session change,
 * the 10 02 slot rule, the updater's key check, the 90 s job cap, and S3 restarted by every request, not only 10 and
 * 3E. udsota_iso14229_poll works around two iso14229 limits: timers that wrap after 2^31 ms, and a download size
 * check that cannot know a coded download's bound. */
#include <string.h>
#include "udsota_iso14229.h"

#define JOB_CAP_MS  90000u   /* udsota's server answered 0x72 here and ended the session */

/* The updater's view of the session iso14229 is in. */
static udsota_upd_access_t access_of(const udsota_iso14229_t *b, const UDSServer_t *srv)
{
    const bool unlocked = b->cfg.security == NULL || srv->securityLevel == b->cfg.level_programming;
    return (udsota_upd_access_t){ .session = srv->sessionType, .unlocked = unlocked };
}

/* An updater answer as iso14229's error type: 0, the NRC, or 0x78 for UDSOTA_PENDING. */
static UDSErr_t as_err(int rc)
{
    return (rc == UDSOTA_PENDING) ? UDS_NRC_RequestCorrectlyReceived_ResponsePending : (UDSErr_t)rc;
}

/* A call that may have started a job, for the SID it answers: records when, for the cap. */
static UDSErr_t started(udsota_iso14229_t *b, uint8_t sid, int rc)
{
    if (rc == UDSOTA_PENDING) {
        b->job_sid = sid;
        b->job_ms = UDSMillis();
    }
    return as_err(rc);
}

/* Zeroes n bytes where the compiler cannot drop it. */
static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n-- > 0u) {
        *v++ = 0u;
    }
}

/* After an answer that may have finished ActivateImage: once the updater is activating, schedule iso14229's reset as
 * its own 11 01 does, late enough for an answer held for P2 to leave first. Without cfg.reset nothing restarts, so
 * the updater stops reporting ACTIVATING. */
static void activation_check(udsota_iso14229_t *b, UDSServer_t *srv)
{
    if (!b->upd.activating || srv->ecuResetScheduled != 0u) {
        return;
    }
    if (b->cfg.reset == NULL) {
        b->upd.activating = false;
        return;
    }
    srv->ecuResetScheduled = UDS_LEV_RT_HR;
    srv->ecuResetTimer = UDSMillis() + srv->p2_ms + UDS_SERVER_DEFAULT_POWER_DOWN_TIME_MS;
}

/* Every session entry and S3: the transfer ends on both sides, the seed dies and security relocks. */
static void session_changed(udsota_iso14229_t *b, UDSServer_t *srv)
{
    udsota_upd_on_session(&b->upd);
    b->seed_valid = false;
    wipe(b->seed, sizeof b->seed);
    srv->securityLevel = 0u;
    srv->xferIsActive = false;
}

/* The default session now, as iso14229's S3 would leave it. */
static void end_session(udsota_iso14229_t *b, UDSServer_t *srv)
{
    session_changed(b, srv);
    srv->sessionType = UDSOTA_SESSION_DEFAULT;
}

/* A pending job's next answer, for the event its SID raised again; 0x21 for any other while it runs. At the cap the
 * wait ends in 0x72 and the default session, as udsota's server did; the worker finishes the job on its own. */
static UDSErr_t resume(udsota_iso14229_t *b, UDSServer_t *srv, uint8_t sid, uint8_t *status, size_t status_max,
                       size_t *status_len)
{
    if (sid != b->job_sid) {
        return UDS_NRC_BusyRepeatRequest;
    }
    if ((uint32_t)(UDSMillis() - b->job_ms) >= JOB_CAP_MS) {
        udsota_upd_job_expired(&b->upd);
        end_session(b, srv);
        return UDS_NRC_GeneralProgrammingFailure;
    }
    const int rc = udsota_upd_resume(&b->upd, status, status_max, status_len);
    activation_check(b, srv);
    return as_err(rc);
}

/* 10 01/02/03: the updater's rule for the session (10 02 needs settled slots, no job and no transfer, then the
 * gate), then the change and iso14229's own timing in the answer (it would send its client defaults). */
static UDSErr_t on_session(udsota_iso14229_t *b, UDSServer_t *srv, UDSDiagSessCtrlArgs_t *a, bool *mine)
{
    if (a->type != UDSOTA_SESSION_DEFAULT && a->type != UDSOTA_SESSION_PROGRAMMING &&
        a->type != UDSOTA_SESSION_EXTENDED) {
        *mine = false;
        return UDS_OK;
    }
    const uint8_t nrc = udsota_upd_session_nrc(&b->upd, a->type);
    if (nrc != 0u) {
        return (UDSErr_t)nrc;
    }
    session_changed(b, srv);
    a->p2_ms = srv->p2_ms;
    a->p2_star_ms = srv->p2_star_ms;
    return UDS_PositiveResponse;
}

/* 11 01 (only with cfg.reset): not in the default session, hard reset only, keyed at either level when secured,
 * then no job and the gate. iso14229 then answers and raises UDS_EVT_DoScheduledReset. */
static UDSErr_t on_reset(udsota_iso14229_t *b, const UDSServer_t *srv, const UDSECUResetArgs_t *a)
{
    if (srv->sessionType == UDSOTA_SESSION_DEFAULT) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (a->type != UDS_LEV_RT_HR) {
        return UDS_NRC_SubFunctionNotSupported;
    }
    if (b->cfg.security != NULL && srv->securityLevel == 0u) {
        return UDS_NRC_SecurityAccessDenied;
    }
    return (UDSErr_t)udsota_upd_reset_nrc(&b->upd);
}

/* The session a requestSeed level belongs to; 0 for a level that isn't the updater's. */
static uint8_t level_session(const udsota_iso14229_t *b, uint8_t level)
{
    return (level == b->cfg.level_programming) ? UDSOTA_SESSION_PROGRAMMING
         : (level == b->cfg.level_extended)    ? UDSOTA_SESSION_EXTENDED
                                               : 0u;
}

/* 27 requestSeed at one of the updater's levels, in that level's session: a fresh 16-byte seed, single use. A
 * security without rng16 answers 0x22, so nothing unlocks. */
static UDSErr_t on_seed(udsota_iso14229_t *b, UDSServer_t *srv, UDSSecAccessRequestSeedArgs_t *a)
{
    const uint8_t need = level_session(b, a->level);
    if (srv->sessionType == UDSOTA_SESSION_DEFAULT) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (srv->sessionType != need) {
        return UDS_NRC_SubFunctionNotSupportedInActiveSession;
    }
    if (a->len != 0u) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    const udsota_security_t *sec = b->cfg.security;
    if (sec->rng16 == NULL || !sec->rng16(sec->ctx, b->seed)) {
        b->seed_valid = false;
        wipe(b->seed, sizeof b->seed);
        return UDS_NRC_ConditionsNotCorrect;
    }
    b->seed_valid = true;
    b->seed_level = a->level;
    b->seed_ms = UDSMillis();
    return (UDSErr_t)a->copySeed(srv, b->seed, UDSOTA_SEED_LEN);
}

/* Constant-time equality of n bytes. */
static bool same(const uint8_t *x, const uint8_t *y, size_t n)
{
    volatile uint8_t d = 0;
    for (size_t i = 0; i < n; i++) {
        d |= (uint8_t)(x[i] ^ y[i]);
    }
    return d == 0u;
}

/* 27 sendKey for the outstanding seed: 0x13 for the wrong length (the seed stays), 0x24 without a seed (or an
 * expired one), 0x22 when no verdict is possible now, 0x35 for a wrong key. A checked key spends the seed; iso14229
 * then delays the next 27 after any refusal and records the level after a success. */
static UDSErr_t on_key(udsota_iso14229_t *b, const UDSServer_t *srv, const UDSSecAccessValidateKeyArgs_t *a)
{
    const uint8_t need = level_session(b, a->level);
    if (srv->sessionType == UDSOTA_SESSION_DEFAULT) {
        return UDS_NRC_ServiceNotSupportedInActiveSession;
    }
    if (srv->sessionType != need) {
        return UDS_NRC_SubFunctionNotSupportedInActiveSession;
    }
    const udsota_security_t *sec = b->cfg.security;
    const size_t want = (sec->verify != NULL && sec->key_len != 0u) ? sec->key_len : UDSOTA_KEY_LEN;
    if (a->len != want) {
        return UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
    }
    const bool fresh = b->seed_valid && b->seed_level == a->level &&
                       (uint32_t)(UDSMillis() - b->seed_ms) < UDSOTA_SA_SEED_VALID_MS;
    b->seed_valid = false;
    if (!fresh) {
        wipe(b->seed, sizeof b->seed);
        return UDS_NRC_RequestSequenceError;
    }
    UDSErr_t rc;
    if (sec->verify != NULL) {
        const int v = sec->verify(sec->ctx, b->seed, a->level, a->key, a->len);
        rc = (v == 1) ? UDS_PositiveResponse : (v < 0) ? UDS_NRC_ConditionsNotCorrect : UDS_NRC_InvalidKey;
    } else {
        uint8_t expect[UDSOTA_KEY_LEN];
        if (sec->key == NULL || !sec->key(sec->ctx, b->seed, a->level, expect)) {
            rc = UDS_NRC_ConditionsNotCorrect;
        } else {
            rc = same(expect, a->key, UDSOTA_KEY_LEN) ? UDS_PositiveResponse : UDS_NRC_InvalidKey;
        }
        wipe(expect, sizeof expect);
    }
    wipe(b->seed, sizeof b->seed);
    return rc;
}

/* 22 for one DID: F18C and F186 here, the updater's own there; false for any other. */
static bool on_read_did(udsota_iso14229_t *b, UDSServer_t *srv, UDSRDBIArgs_t *a, UDSErr_t *rc)
{
    uint8_t buf[64];
    if (a->dataId == UDSOTA_DID_SERIAL && b->cfg.device_id != NULL) {
        *rc = (UDSErr_t)a->copy(srv, b->cfg.device_id, (uint16_t)b->cfg.device_id_len);
        return true;
    }
    if (a->dataId == UDSOTA_DID_ACTIVE_SESSION) {
        const uint8_t s = srv->sessionType;
        *rc = (UDSErr_t)a->copy(srv, &s, 1u);
        return true;
    }
    const size_t n = udsota_upd_read_did(&b->upd, a->dataId, buf, sizeof buf);
    if (n == UDSOTA_UPD_DID_PASS) {
        return false;
    }
    *rc = (n == 0u) ? UDS_NRC_RequestOutOfRange : (UDSErr_t)a->copy(srv, buf, (uint16_t)n);
    return true;
}

/* 31: the updater's RIDs, their status record appended after iso14229's 71 <ctrl> <rid>; false for another RID. */
static bool on_routine(udsota_iso14229_t *b, UDSServer_t *srv, UDSRoutineCtrlArgs_t *a, UDSErr_t *rc)
{
    uint8_t status[8];
    size_t status_len = 0;
    if (b->upd.job_running) {
        *rc = resume(b, srv, UDSOTA_SID_ROUTINE, status, sizeof status, &status_len);
    } else {
        const int r = udsota_upd_routine(&b->upd, access_of(b, srv), a->ctrlType, a->id, a->len, status,
                                         sizeof status, &status_len);
        if (r == UDSOTA_UPD_PASS) {
            return false;
        }
        activation_check(b, srv);
        *rc = started(b, UDSOTA_SID_ROUTINE, r);
    }
    if (*rc == UDS_PositiveResponse && status_len != 0u) {
        *rc = (UDSErr_t)a->copyStatusRecord(srv, status, (uint16_t)status_len);
    }
    return true;
}

/* True when v fits the updater's 32-bit address and size; uint64_t, so a 32-bit size_t compiles without a warning. */
static bool fits_u32(uint64_t v)
{
    return v <= UINT32_MAX;
}

/* 34 with iso14229's decoded address and size; the positive answer carries the updater's block length. */
static UDSErr_t on_download(udsota_iso14229_t *b, UDSServer_t *srv, UDSRequestDownloadArgs_t *a)
{
    if (!fits_u32(a->addr) || !fits_u32(a->size)) {
        return UDS_NRC_RequestOutOfRange;
    }
    uint16_t mbl = 0;
    const int rc = udsota_upd_request_download(&b->upd, access_of(b, srv), a->dataFormatIdentifier,
                                               (uint32_t)a->addr, (uint32_t)a->size, &mbl);
    if (rc == 0) {
        a->maxNumberOfBlockLength = mbl;
    }
    return as_err(rc);
}

/* 36 and 37. iso14229 ends its transfer on any NRC but 0x78, so the updater ends its own too; a gate refusal also
 * ends the session. */
static UDSErr_t on_transfer(udsota_iso14229_t *b, UDSServer_t *srv, UDSEvent_t ev, const void *arg)
{
    const uint8_t sid = (ev == UDS_EVT_TransferData) ? UDSOTA_SID_TRANSFER_DATA : UDSOTA_SID_TRANSFER_EXIT;
    size_t none = 0;
    UDSErr_t rc;
    if (b->upd.job_running) {
        rc = resume(b, srv, sid, NULL, 0, &none);
    } else if (ev == UDS_EVT_TransferData) {
        const UDSTransferDataArgs_t *a = arg;
        rc = started(b, sid, udsota_upd_transfer_data(&b->upd, access_of(b, srv), srv->r.recv_buf[1], a->data,
                                                      a->len));
    } else {
        const UDSRequestTransferExitArgs_t *a = arg;
        rc = started(b, sid, udsota_upd_transfer_exit(&b->upd, access_of(b, srv), a->len));
    }
    if (rc != UDS_PositiveResponse && rc != UDS_NRC_RequestCorrectlyReceived_ResponsePending) {
        udsota_upd_transfer_ended(&b->upd);
    }
    if (udsota_upd_take_end_session(&b->upd)) {
        end_session(b, srv);
    }
    return rc;
}

bool udsota_iso14229_event(udsota_iso14229_t *b, UDSServer_t *srv, UDSEvent_t ev, void *arg, UDSErr_t *rc)
{
    bool mine = true;
    *rc = UDS_PositiveResponse;
    /* iso14229 refuses some 36s itself (the block counter's 0x24, 0x70 with no transfer, 0x71 past the size) and
     * ends its transfer without raising an event; the updater follows at the next one. */
    if (!srv->xferIsActive && udsota_upd_download_active(&b->upd)) {
        udsota_upd_transfer_ended(&b->upd);
    }
    switch (ev) {
    case UDS_EVT_SessionTimeout:
        session_changed(b, srv);
        return false;                                     /* the app may want it too */
    case UDS_EVT_DoScheduledReset:
        if (b->cfg.reset == NULL) {
            return false;
        }
        b->cfg.reset(b->cfg.ctx);
        return true;
    case UDS_EVT_Err:
        return false;
    default:
        break;
    }
    /* A request. Between a positive ActivateImage and the restart, none is served. */
    if (b->upd.activating && srv->ecuResetScheduled != 0u) {
        *rc = UDS_NRC_ConditionsNotCorrect;
        return true;
    }
    /* ISO 14229-2 restarts S3 on every request; iso14229 does only for 10 and 3E. */
    if (srv->sessionType != UDSOTA_SESSION_DEFAULT) {
        srv->s3_session_timeout_timer = UDSMillis() + srv->s3_ms;
    }
    switch (ev) {
    case UDS_EVT_DiagSessCtrl:
        *rc = on_session(b, srv, arg, &mine);
        return mine;
    case UDS_EVT_EcuReset:
        if (b->cfg.reset == NULL) {
            return false;
        }
        *rc = on_reset(b, srv, arg);
        return true;
    case UDS_EVT_SecAccessRequestSeed:
        if (b->cfg.security == NULL || level_session(b, ((UDSSecAccessRequestSeedArgs_t *)arg)->level) == 0u) {
            return false;
        }
        *rc = on_seed(b, srv, arg);
        return true;
    case UDS_EVT_SecAccessValidateKey:
        if (b->cfg.security == NULL || level_session(b, ((UDSSecAccessValidateKeyArgs_t *)arg)->level) == 0u) {
            return false;
        }
        *rc = on_key(b, srv, arg);
        return true;
    case UDS_EVT_ReadDataByIdent:
        return on_read_did(b, srv, arg, rc);
    case UDS_EVT_RoutineCtrl:
        return on_routine(b, srv, arg, rc);
    case UDS_EVT_RequestDownload:
        *rc = on_download(b, srv, arg);
        return true;
    case UDS_EVT_TransferData:
    case UDS_EVT_RequestTransferExit:
        *rc = on_transfer(b, srv, ev, arg);
        return true;
    default:
        return false;
    }
}

/* A deadline that has passed stays passed: t moves up to one before now. iso14229 compares deadlines with a signed
 * 32-bit difference and sets some only once, so without this a deadline 2^31 ms old reads as the future again. */
static void pin(uint32_t *t, uint32_t now)
{
    if ((int32_t)(now - *t) > 0) {                        /* iso14229's UDSTimeAfter(now, *t) */
        *t = now - 1u;
    }
}

void udsota_iso14229_poll(udsota_iso14229_t *b, UDSServer_t *srv)
{
    const uint32_t now = UDSMillis();
    pin(&srv->sec_access_boot_delay_timer, now);
    pin(&srv->sec_access_auth_fail_timer, now);
    if (!srv->requestInProgress) {
        pin(&srv->p2_timer, now);
    }
    /* iso14229 sizes a transfer by memorySize; a coded download may carry up to UDSOTA_DL_Z_BOUND of it. */
    if (srv->xferIsActive && b->upd.st.download_active && b->upd.st.dl_compressed) {
        const uint64_t bound = UDSOTA_DL_Z_BOUND(b->upd.st.dl_announced);
        srv->xferTotalBytes = (bound > SIZE_MAX) ? SIZE_MAX : (size_t)bound;
    }
}

void udsota_iso14229_progress(const udsota_iso14229_t *b, udsota_progress_t *out)
{
    udsota_progress(&b->upd, out);
}

void udsota_iso14229_init(udsota_iso14229_t *b, const udsota_iso14229_cfg_t *cfg)
{
    memset(b, 0, sizeof *b);
    b->cfg = *cfg;
    if (b->cfg.level_extended == 0u) {
        b->cfg.level_extended = UDSOTA_SA_SEED_EXTENDED;
    }
    if (b->cfg.level_programming == 0u) {
        b->cfg.level_programming = UDSOTA_SA_SEED_PROGRAMMING;
    }
    const udsota_upd_config_t ucfg = {
        .max_block_len = cfg->max_block_len, .gate = cfg->gate, .progress = cfg->progress, .ctx = cfg->ctx,
    };
    udsota_upd_init(&b->upd, cfg->engine, &ucfg);
}
