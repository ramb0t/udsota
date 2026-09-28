/* Pure UDS server core: sessions, S3, SecurityAccess, download, routines, reset, 0x2E through the app's hook,
 * and the worker-job wait, behind the engine, security and hooks the integrator passes to udsota_init. No
 * ESP-IDF: the transport feeds it reassembled requests, reception events and now_ms, and sends whatever it
 * returns. */
#include <string.h>
#include "udsota.h"
#include "udsota_priv.h"
#include "udsota_rxwatch.h"   /* UDSOTA_CF_MEDIAN_NONE */

/* ---- SecurityAccess 0x27: seed, then an HMAC key or a verified one (sec.verify), lockout, relock. RAM only. ---- */

/* Zeroes n bytes through a volatile pointer so wiping a seed or key is not optimised away. */
static void sa_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

/* True when all 16 bytes are zero; a locked level must never be handed a zero seed. */
static bool sa_is_zero(const uint8_t *b)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < UDSOTA_SEED_LEN; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

/* Compares two 16-byte keys in time independent of where (or whether) they differ. */
static bool sa_keys_equal(const uint8_t *a, const uint8_t *b)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < UDSOTA_KEY_LEN; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* The exact key length a sendKey carries: sec.key_len with a verifier (0 = 16), else the 16-byte HMAC key. */
static size_t sa_key_len(const udsota_server_t *s)
{
    return (s->sec.verify != NULL && s->sec.key_len != 0u) ? s->sec.key_len : UDSOTA_KEY_LEN;
}

/* Drops the outstanding seed, if any, and wipes it. */
static void sa_forget_seed(udsota_server_t *s)
{
    sa_wipe(s->sa_seed, sizeof s->sa_seed);
    s->sa_seed_valid = false;
    s->sa_seed_level = 0;
}

/* Relocks (level and seed cleared; attempt count and delay kept); call before every session change. */
static void sa_relock(udsota_server_t *s)
{
    /* The count and delay survive so that hopping sessions cannot reset a lockout. */
    s->security = 0;
    sa_forget_seed(s);
}

/* Boot state: locked, no seed, no failed attempts, and the post-boot delay running from clock 0. */
static void sa_init(udsota_server_t *s)
{
    sa_relock(s);
    s->sa_failed = 0;
    s->sa_delay_active = true;
    s->sa_delay_start_ms = 0;
}

/* True while the boot or lockout delay runs (wrap-safe); clears the flag once it has passed. */
static bool sa_delay_running(udsota_server_t *s, uint32_t now_ms)
{
    if (s->sa_delay_active && (uint32_t)(now_ms - s->sa_delay_start_ms) < UDSOTA_SA_DELAY_MS) {
        return true;
    }
    s->sa_delay_active = false;
    return false;
}

/* 27 01 / 27 03: answers a fresh single-use seed, or 16 zero bytes when the level is already unlocked. */
static size_t sa_request_seed(udsota_server_t *s, uint8_t level, bool suppress,
                              uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (resp_max < 2u + UDSOTA_SEED_LEN) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_GENERAL_REJECT);
    }
    if (s->security == level) {
        memset(&resp[2], 0, UDSOTA_SEED_LEN);                  /* ISO 14229-1: zero seed = already unlocked */
    } else {
        sa_forget_seed(s);                                  /* a new request replaces any outstanding seed */
        if (s->sec.rng16 == NULL ||                        /* init refused this security: no seed, ever */
            !s->sec.rng16(s->sec.ctx, s->sa_seed) || sa_is_zero(s->sa_seed)) {
            sa_forget_seed(s);
            return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
        }
        s->sa_seed_valid = true;
        s->sa_seed_level = level;
        s->sa_seed_ms = now_ms;
        memcpy(&resp[2], s->sa_seed, UDSOTA_SEED_LEN);
    }
    if (suppress) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_SECURITY);
    resp[1] = level;
    return 2u + UDSOTA_SEED_LEN;
}

/* The HMAC check: sec.key's expected key for the outstanding seed, compared in constant time. 1 match, 0 wrong,
 * -1 no key available now. */
static int sa_key_matches(udsota_server_t *s, uint8_t level, const uint8_t *key)
{
    uint8_t expected[UDSOTA_KEY_LEN];
    const bool have = s->sec.key(s->sec.ctx, s->sa_seed, level, expected);
    const int verdict = !have ? -1 : (sa_keys_equal(key, expected) ? 1 : 0);
    sa_wipe(expected, sizeof expected);
    return verdict;
}

/* 27 02 / 27 04: checks the key_len-byte key against the outstanding seed, through sec.verify when set and else
 * sec.key; the seed is consumed either way. No verdict -> 0x22 (not an attempt); 3rd wrong key -> 0x36 + delay. */
static size_t sa_send_key(udsota_server_t *s, uint8_t level, const uint8_t *key, size_t key_len, bool suppress,
                          uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (!s->sa_seed_valid || s->sa_seed_level != level ||
        (uint32_t)(now_ms - s->sa_seed_ms) >= UDSOTA_SA_SEED_VALID_MS) {
        sa_forget_seed(s);                                  /* key without (a live) seed: not an attempt */
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    }
    const int verdict = (s->sec.verify != NULL) ? s->sec.verify(s->sec.ctx, s->sa_seed, level, key, key_len)
                        : (s->sec.key != NULL)  ? sa_key_matches(s, level, key)
                                                : -1;       /* init refused this security: never unlocks */
    sa_forget_seed(s);                                      /* single use, whatever the outcome */
    if (verdict < 0) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    }
    if (verdict != 1) {                                     /* only 1 unlocks: any other verdict is a wrong key */
        s->sa_failed++;
        if (s->sa_failed >= UDSOTA_SA_MAX_ATTEMPTS) {
            s->sa_failed = 0;                               /* three fresh attempts once the delay ends */
            s->sa_delay_active = true;
            s->sa_delay_start_ms = now_ms;
            return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_EXCEEDED_ATTEMPTS);
        }
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_INVALID_KEY);
    }
    s->sa_failed = 0;
    s->security = level;
    if (suppress || resp_max < 2u) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_SECURITY);
    resp[1] = (uint8_t)(level + 1u);
    return 2;
}

/* Serves 0x27 in NRC order 7F, 13, 12, 7E, 13 (exact length), 37; reads req only within req_len. */
static size_t sa_handle(udsota_server_t *s, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (req_len < 2u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t sub = (uint8_t)(req[1] & (uint8_t)~UDSOTA_SPRMIB);
    const bool suppress = (req[1] & UDSOTA_SPRMIB) != 0;
    const uint8_t lx = s->cfg.level_extended;
    const uint8_t lp = s->cfg.level_programming;
    uint8_t level;                                            /* the requestSeed byte */
    if (sub == lx || sub == (uint8_t)(lx + 1u)) {
        level = lx;
    } else if (sub == lp || sub == (uint8_t)(lp + 1u)) {
        level = lp;
    } else {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    const uint8_t need = (level == lp) ? UDSOTA_SESSION_PROGRAMMING : UDSOTA_SESSION_EXTENDED;
    if (s->session != need) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION);
    }
    const bool is_seed = (sub == level);
    const size_t key_len = sa_key_len(s);
    if (req_len != (is_seed ? 2u : 2u + key_len)) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (sa_delay_running(s, now_ms)) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_TIME_DELAY_NOT_EXPIRED);
    }
    return is_seed ? sa_request_seed(s, level, suppress, resp, resp_max, now_ms)
                   : sa_send_key(s, level, &req[2], key_len, suppress, resp, resp_max, now_ms);
}

/* Writes 7F <sid> <nrc>; returns 3, or 0 without writing when resp_max < 3. */
size_t udsota_nrc(uint8_t *resp, size_t resp_max, uint8_t sid, uint8_t nrc)
{
    if (resp == NULL || resp_max < 3) {
        return 0;
    }
    resp[0] = UDSOTA_NEG_RESPONSE;
    resp[1] = sid;
    resp[2] = nrc;
    return 3;
}

/* True when n bytes in resp form a positive response, which SPRMIB may suppress. */
static bool is_positive(const uint8_t *resp, size_t n)
{
    return n > 0 && resp[0] != UDSOTA_NEG_RESPONSE;
}

static void enter_session(udsota_server_t *s, uint8_t session);
static void progress_sync(udsota_server_t *s);

/* Asks hooks.gate about op: 0 = allow (also when no gate is registered), else the NRC to send. */
static uint8_t gate(const udsota_server_t *s, udsota_op_t op)
{
    return s->hooks.gate != NULL ? s->hooks.gate(s->hooks.ctx, op) : 0u;
}

/* The access state an app hook gets: the session, the unlocked level (0 when locked, and always without
 * security) and the session epoch. */
static udsota_access_t access_of(const udsota_server_t *s)
{
    const udsota_access_t a = {.session = s->session, .unlocked_level = s->security, .epoch = s->session_epoch};
    return a;
}

/* True while the worker owns a job: one the server waits on, an orphan (the engine's or an app routine's), or
 * anything engine.poll() still reports queued (a fire-and-forget abort included). */
static bool worker_busy(const udsota_server_t *s)
{
    return s->job_running || s->worker_orphan || s->app_orphan || s->engine.poll(s->engine.ctx) == UDSOTA_PENDING;
}

/* engine.status into *st, zeroed first; only called when engine.status is set. */
static void status_now(const udsota_server_t *s, udsota_status_t *st)
{
    memset(st, 0, sizeof *st);
    s->engine.status(s->engine.ctx, st);
}

/* Core slot rule for 10 02 and 34: the boot slot is the running slot (both known) and the running image is not
 * PENDING_VERIFY. True without engine.status (not used = not checked). */
static bool slots_settled(const udsota_server_t *s)
{
    if (s->engine.status == NULL) {
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
    if (s->engine.status == NULL) {
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

/* ENTER_PROGRAMMING and START_DOWNLOAD: slots settled, worker idle and no transfer open, then the gate. */
static uint8_t download_nrc(const udsota_server_t *s, udsota_op_t op)
{
    if (!slots_settled(s) || worker_busy(s) || s->download_active) {
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return gate(s, op);
}

/* ACTIVATE and RESET: the worker is idle, then the gate. */
static uint8_t restart_nrc(const udsota_server_t *s, udsota_op_t op)
{
    return worker_busy(s) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : gate(s, op);
}

/* CONTINUE_TRANSFER at a 36 or an FC point: the STmin monitor (when on), then the gate, which is asked either way
 * so that an STmin violation is counted only when timing alone failed. Judges s->cf_median_us and cf_stmin_us, the
 * last FC point's timing. 0 or the NRC. */
static uint8_t transfer_nrc(udsota_server_t *s)
{
    const bool slow_enough = !s->cfg.stmin_monitor ||
                             (uint64_t)s->cf_median_us * 5u >= (uint64_t)s->cf_stmin_us * 4u;   /* NONE always passes */
    const uint8_t g = gate(s, UDSOTA_OP_CONTINUE_TRANSFER);
    if (!slow_enough) {
        if (g == 0u) {
            udsota_sat_inc16(&s->counters.stmin_violations);
        }
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return g;
}

/* A DID the app serves: hooks.did_read, or 0 (NRC 0x31) when none is registered. */
static size_t app_did(const udsota_server_t *s, uint16_t did, uint8_t *out, size_t room)
{
    return s->hooks.did_read != NULL ? s->hooks.did_read(s->hooks.ctx, did, out, room) : 0u;
}

/* Copies n bytes of src to out; 0 (NRC 0x31) when out has less room. */
static size_t copy_did(uint8_t *out, size_t room, const uint8_t *src, size_t n)
{
    if (n > room) {
        return 0;
    }
    memcpy(out, src, n);
    return n;
}

/* The phase the server's state implies. */
static udsota_phase_t phase_of(const udsota_server_t *s)
{
    if (s->activating) {
        return UDSOTA_PHASE_ACTIVATING;
    }
    switch (s->session) {
    case UDSOTA_SESSION_EXTENDED:
        return UDSOTA_PHASE_EXTENDED;
    case UDSOTA_SESSION_PROGRAMMING:
        return s->download_active ? UDSOTA_PHASE_TRANSFERRING : UDSOTA_PHASE_PROGRAMMING;
    default:
        return UDSOTA_PHASE_IDLE;
    }
}

/* Reports a phase change to hooks.phase, once, at the end of the public call that made it, and also right
 * after a latched end_session is applied, so a request dispatched in the same call sees IDLE first. */
static void phase_sync(udsota_server_t *s)
{
    const udsota_phase_t p = phase_of(s);
    if ((uint8_t)p == s->phase) {
        return;
    }
    s->phase = (uint8_t)p;
    if (s->hooks.phase != NULL) {
        s->hooks.phase(s->hooks.ctx, p);
    }
}

/* Stops waiting on the running job; its owner keeps it as an orphan: the engine's until engine.poll() stops
 * reporting UDSOTA_PENDING, an app routine's until hooks.routine_poll() does. No answer for it is ever sent. */
static void orphan_job(udsota_server_t *s)
{
    if (s->job_app) {
        s->app_orphan = true;
    } else {
        s->worker_orphan = true;
    }
    s->job_running = false;
    s->job_done = NULL;
    s->job_app = false;
}

/* Applies an udsota_end_session latched while a job ran, once no job runs: abort, relock, default session
 * (enter_session clears the latch, as any session change fulfils it). */
static void apply_end_pending(udsota_server_t *s)
{
    if (s->end_pending && !s->job_running) {
        enter_session(s, UDSOTA_SESSION_DEFAULT);
    }
}

/* P2 in `session`: cfg.p2_prog_ms in the programming session (cfg_resolve fills it), else cfg.p2_ms. */
static uint16_t p2_in(const udsota_server_t *s, uint8_t session)
{
    return session == UDSOTA_SESSION_PROGRAMMING ? s->cfg.p2_prog_ms : s->cfg.p2_ms;
}

/* P2* in `session`, as p2_in. */
static uint16_t p2star_in(const udsota_server_t *s, uint8_t session)
{
    return session == UDSOTA_SESSION_PROGRAMMING ? s->cfg.p2star_prog_ms : s->cfg.p2star_ms;
}

/* First 0x78 of a job: four fifths of the session's P2 (40 ms at the default 50 ms), so it leaves inside P2. */
static uint32_t pending_first_ms(const udsota_server_t *s)
{
    return (uint32_t)p2_in(s, s->session) * 4u / 5u;
}

/* 0x78 repeat period: three tenths of the session's P2* (1.5 s at the default 5 s), well inside P2*. */
static uint32_t pending_repeat_ms(const udsota_server_t *s)
{
    return (uint32_t)p2star_in(s, s->session) * 3u / 10u;
}

/* True once the transport reports nothing left to send; always false without a tx_pending source. */
static bool tx_drained(const udsota_server_t *s)
{
    return s->tx_pending != NULL && s->tx_pending(s->tx_pending_ctx) == 0u;
}

/* Restarts S3 after a request is answered; in the default session S3 does not run. */
static void answered(udsota_server_t *s, uint32_t now_ms)
{
    s->s3_running = (s->session != UDSOTA_SESSION_DEFAULT);
    s->s3_start_ms = now_ms;
}

/* Ends a download or an open, unverified image: queues ota_abort on the worker without waiting
 * (the partial slot stays, for a future resume) and records UDSOTA_DL_ABORTED in F1F1 and F1F2. dl_complete is
 * cleared either way, so FF01 never sees a closed transfer without its handle. */
static void abort_download(udsota_server_t *s)
{
    s->dl_complete = false;
    if (!s->download_active && !s->ota_open) {
        return;
    }
    if (s->ota_open) {
        s->engine.abort(s->engine.ctx);
    }
    s->download_active = false;
    s->ota_open = false;
    s->last_dl.reason_code = UDSOTA_DL_ABORTED;
    s->last_dl.bytes_received = s->dl_received;
    udsota_sat_inc16(&s->counters.aborts);
}

/* Back in the default session: what 28 and 85 changed is undone (ISO 14229-1), through the same hooks. */
static void restore_default_comm(udsota_server_t *s)
{
    if (s->comm_changed) {
        s->comm_changed = false;
        (void)s->hooks.comm_control(s->hooks.ctx, UDSOTA_CC_ENABLE_RX_TX, UDSOTA_CC_TYPE_ALL);
    }
    if (s->dtc_off) {
        s->dtc_off = false;
        s->hooks.dtc_setting(s->hooks.ctx, true);
    }
}

/* Enters `session`: every session entry comes through here (an accepted 10 xx, S3, the 90 s cap, the restart, an
 * app's end_session request, a refused 36 and a withheld FC point). Any open download is aborted, security relocks
 * and the session epoch advances, the same session included (ISO 14229-1 re-initialises it); udsota_init restarts
 * the epoch at 0. slot_verified survives, so ActivateImage can follow in a later session. */
static void enter_session(udsota_server_t *s, uint8_t session)
{
    abort_download(s);
    sa_relock(s);              /* level and pending seed cleared; attempt count and delay kept */
    s->session_epoch++;        /* app state tied to the old epoch is stale from here on */
    s->end_pending = false;   /* any session change fulfils a latched end_session */
    s->session = session;
    s->s3_running = false;     /* answered() restarts it in a non-default session */
    if (session == UDSOTA_SESSION_DEFAULT) {
        restore_default_comm(s);
    }
}

/* 0x10 DiagnosticSessionControl: 01/02/03. 02 needs the core's download conditions, then gate(ENTER_PROGRAMMING);
 * 03 needs gate(ENTER_EXTENDED). The positive answer carries the new session's P2 and P2* (10 ms units). */
static size_t handle_session(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    if (len < 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t sub = req[1] & (uint8_t)~UDSOTA_SPRMIB;
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    if (sub != UDSOTA_SESSION_DEFAULT && sub != UDSOTA_SESSION_PROGRAMMING && sub != UDSOTA_SESSION_EXTENDED) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (len != 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    uint8_t nrc = 0;
    if (sub == UDSOTA_SESSION_PROGRAMMING) {
        nrc = download_nrc(s, UDSOTA_OP_ENTER_PROGRAMMING);
    } else if (sub == UDSOTA_SESSION_EXTENDED) {
        nrc = gate(s, UDSOTA_OP_ENTER_EXTENDED);
    }
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, nrc);
    }
    if (resp_max < 6) {
        return 0;
    }
    enter_session(s, sub);
    resp[0] = UDSOTA_POS(UDSOTA_SID_SESSION);
    resp[1] = sub;
    udsota_put_u16be(&resp[2], p2_in(s, sub));
    udsota_put_u16be(&resp[4], (uint16_t)(p2star_in(s, sub) / 10u));
    return spr ? 0 : 6;
}

/* 0x3E TesterPresent: sub-function 00 only; 3E 80 is answered silently. Also served during a job. */
static size_t handle_tester_present(const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    if (len < 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TESTER_PRESENT, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if ((req[1] & (uint8_t)~UDSOTA_SPRMIB) != UDSOTA_TP_ZERO_SUBFUNC) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TESTER_PRESENT, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (len != 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TESTER_PRESENT, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if ((req[1] & UDSOTA_SPRMIB) != 0 || resp_max < 2) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_TESTER_PRESENT);
    resp[1] = UDSOTA_TP_ZERO_SUBFUNC;
    return 2;
}

/* 0x22 ReadDataByIdentifier, one DID per request. F186, F1F1 and F1F2 come from the server's own state; F189,
 * F18C, F1F0 and F1F3 from engine.version, cfg.device_id, engine.status and engine.running_sha. Any of those four
 * whose source is NULL, and every other DID, goes to hooks.did_read; 0 bytes means NRC 0x31. */
static size_t handle_read_did(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    if (len != 1u + 2u * UDSOTA_READ_DID_MAX) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_READ_DID, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (resp_max < 4) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_READ_DID, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    const uint16_t did = udsota_get_u16be(&req[1]);
    uint8_t *out = &resp[3];
    const size_t room = resp_max - 3;
    size_t n;
    if (did == UDSOTA_DID_ACTIVE_SESSION) {
        out[0] = s->session;
        n = 1;
    } else if (did == UDSOTA_DID_RESULT) {
        n = udsota_pack_result(out, room, &s->last_dl);
    } else if (did == UDSOTA_DID_COUNTERS) {
        n = udsota_pack_counters(out, room, &s->counters);
    } else if (did == UDSOTA_DID_SW_VERSION && s->engine.version != NULL) {
        n = s->engine.version(s->engine.ctx, (char *)out, room);
    } else if (did == UDSOTA_DID_SERIAL && s->cfg.device_id != NULL && s->cfg.device_id_len != 0u) {
        n = copy_did(out, room, s->cfg.device_id, s->cfg.device_id_len);
    } else if (did == UDSOTA_DID_STATUS && s->engine.status != NULL) {
        udsota_status_t st;
        status_now(s, &st);
        n = udsota_pack_status(out, room, &st);
    } else if (did == UDSOTA_DID_RUNNING_SHA && s->engine.running_sha != NULL) {
        n = s->engine.running_sha(s->engine.ctx, out, room);
    } else {
        n = app_did(s, did, out, room);
    }
    if (n == 0 || n > room) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_READ_DID, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_READ_DID);
    udsota_put_u16be(&resp[1], did);
    return 3 + n;
}

/* 0x2E WriteDataByIdentifier, only with hooks.did_write (dispatch answers 0x11 without it). Check order: session
 * 7F, length 13 (the DID and at least one data byte), then the hook decides: 0 answers 6E <did>, anything else is
 * sent as the NRC. The hook is not asked when resp has no room for its answer. */
static size_t handle_write_did(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_WRITE_DID;
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (len < UDSOTA_WRITE_DID_MIN_LEN) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (resp_max < 3u) {
        return 0;
    }
    const uint16_t did = udsota_get_u16be(&req[1]);
    const uint8_t nrc = s->hooks.did_write(s->hooks.ctx, did, &req[3], len - 3u, access_of(s));
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, sid, nrc);
    }
    resp[0] = UDSOTA_POS(sid);
    udsota_put_u16be(&resp[1], did);
    return 3;
}

/* ==== Download: 0x34 RequestDownload, 0x36 TransferData, 0x37 RequestTransferExit ==== */

/* Session and key gate shared by 0x34/0x36/0x37: 0x7F outside programming, 0x33 without level 03, else 0. */
static uint8_t dl_access_nrc(const udsota_server_t *s)
{
    if (s->session != UDSOTA_SESSION_PROGRAMMING) {
        return UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION;
    }
    if (s->secured && s->security != s->cfg.level_programming) {
        return UDSOTA_NRC_SECURITY_ACCESS_DENIED;
    }
    return 0;
}

/* Size a 34 may announce: the engine's slot, or UDSOTA_SLOT_SIZE_DEFAULT while it reports 0. */
static uint32_t dl_slot_size(const udsota_server_t *s)
{
    return s->engine.slot_size != 0u ? s->engine.slot_size : UDSOTA_SLOT_SIZE_DEFAULT;
}

/* Ends a download whose erase or write failed on the worker: aborts it, then records UDSOTA_DL_FLASH_ERROR. */
static void dl_flash_failed(udsota_server_t *s)
{
    abort_download(s);
    s->last_dl.reason_code = UDSOTA_DL_FLASH_ERROR;
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
    return dfi == UDSOTA_DL_DFI || (UDSOTA_COMPRESSION && dl_dfi_coded(dfi) && s->engine.zbegin != NULL &&
                                    (s->engine.zformats & UDSOTA_DL_FMT(dfi)) != 0u);
}

/* True while the open download is coded. A macro, so that with UDSOTA_COMPRESSION 0 it is the constant 0 at any
 * optimisation level and every coded branch compiles away. */
#define DL_Z(s) (UDSOTA_COMPRESSION && (s)->dl_compressed)

/* Bytes the 36s of this download may carry: memorySize, or UDSOTA_DL_Z_BOUND of it when coded. */
static uint32_t dl_limit(const udsota_server_t *s)
{
    if (!DL_Z(s)) {
        return s->dl_announced;
    }
    const uint64_t bound = UDSOTA_DL_Z_BOUND(s->dl_announced);
    return bound > UINT32_MAX ? UINT32_MAX : (uint32_t)bound;
}

/* A reason code from an engine result: r itself when it names one, else fallback. */
static uint8_t dl_reason(int r, udsota_reason_t fallback)
{
    return (r > (int)UDSOTA_DL_OK && r < (int)UDSOTA_DL_REASON_COUNT) ? (uint8_t)r : (uint8_t)fallback;
}

/* 0x34: DFI 00 (or 10, 20 or 30 when engine.zformats names it), ALFID 44, address 0 (no resume point), 0 < size <=
 * slot, gated like 10 02; 74 20 0F FF. With a coded DFI a failed zbegin answers 0x22 before anything else changes,
 * save an unverified image the same 34 released. */
static size_t handle_request_download(udsota_server_t *s, const uint8_t *req, size_t req_len,
                                      uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_REQUEST_DOWNLOAD;
    const uint8_t access = dl_access_nrc(s);
    if (access != 0u) {
        return udsota_nrc(resp, resp_max, sid, access);
    }
    if (req_len != UDSOTA_DL_REQ_LEN) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t cond = download_nrc(s, UDSOTA_OP_START_DOWNLOAD);   /* before the format check */
    if (cond != 0u) {
        return udsota_nrc(resp, resp_max, sid, cond);
    }
    const uint32_t addr = udsota_get_u32be(&req[3]);
    const uint32_t size = udsota_get_u32be(&req[7]);
    if (!dl_dfi_ok(s, req[1]) || req[2] != UDSOTA_DL_ALFID || addr != 0u || size == 0u || size > dl_slot_size(s)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (resp_max < 4u) {
        return 0;
    }
    const bool compressed = UDSOTA_COMPRESSION && dl_dfi_coded(req[1]);
    if (compressed) {
        if (s->ota_open) {                        /* released first, so its abort cannot free the new decoder */
            s->engine.abort(s->engine.ctx);
            s->ota_open = false;
        }
        const int rc = s->engine.zbegin(s->engine.ctx, size, req[1]);
        if (rc != 0) {
            s->last_dl.reason_code = dl_reason(rc, UDSOTA_DL_NO_MEMORY);
            s->last_dl.bytes_received = 0u;
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
        }
    }
    /* Accepted. The other slot stops counting as verified before anything is queued. */
    if (s->engine.unverify != NULL) {
        s->engine.unverify(s->engine.ctx);
    }
    s->slot_verified = false;                     /* a new download clears FF01's pass */
    if (s->ota_open) {                            /* a finished image that never passed FF01: release its handle */
        s->engine.abort(s->engine.ctx);
        s->ota_open = false;
    }
    s->download_active = true;
    s->ota_open = compressed;                     /* the engine holds the decoder from here */
    s->dl_compressed = compressed;
    s->dl_complete = false;
    s->next_bsc = 1u;
    s->dl_announced = size;
    s->dl_received = 0u;
    s->dl_written = 0u;                           /* where done starts: a resumed download would start it at its offset */
    s->cf_median_us = UDSOTA_CF_MEDIAN_NONE;
    s->cf_stmin_us = 0u;
    s->last_dl.reason_code = UDSOTA_DL_OK;
    s->last_dl.bytes_received = 0u;
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
 * and that reason instead, as a first-block refusal does. job_arg carries the block's data length in bits 8..20 and
 * its BSC in bits 0..7. */
static size_t dl_block_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    const uint8_t bsc = (uint8_t)(s->job_arg & 0xFFu);
    if (result != 0 && DL_Z(s) && dl_z_refused(result)) {
        abort_download(s);
        s->last_dl.reason_code = (uint8_t)result;
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_DATA, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (result != 0) {
        dl_flash_failed(s);
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_DATA, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    s->dl_received += s->job_arg >> 8;
    if (!DL_Z(s)) {
        s->dl_written += s->job_arg >> 8;         /* the block's bytes are image bytes */
    } else if (s->engine.zwritten != NULL) {
        const uint32_t written = s->engine.zwritten(s->engine.ctx);   /* coded: what the stream wrote */
        if (written > s->dl_written) {
            s->dl_written = written;              /* done never shrinks, whatever the engine says */
        }
    }
    s->progress_block = true;
    s->next_bsc = (uint8_t)(bsc + 1u);            /* 0xFF wraps to 0x00 */
    s->last_dl.bytes_received = s->dl_received;
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
    if (!s->download_active) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    }
    if (resp_max < 3u) {
        return 0;
    }
    const uint8_t cond = transfer_nrc(s);
    if (cond != 0u) {
        if (cond != UDSOTA_NRC_BUSY_REPEAT) {
            enter_session(s, UDSOTA_SESSION_DEFAULT);   /* aborts, records UDSOTA_DL_ABORTED, relocks */
        }
        return udsota_nrc(resp, resp_max, sid, cond);
    }
    const uint8_t bsc = req[1];
    const uint8_t *data = &req[2];
    const size_t len = req_len - 2u;
    /* Repeat before overrun: the resend of a final block whose 76 was lost must still get 76.
     * dl_received > 0 means a block was accepted in this download, so there is a "last" counter to repeat. */
    if (s->dl_received > 0u && bsc == (uint8_t)(s->next_bsc - 1u)) {
        udsota_sat_inc16(&s->counters.repeated_blocks);
        resp[0] = UDSOTA_POS(sid);
        resp[1] = bsc;
        return 2;
    }
    if (bsc != s->next_bsc) {
        udsota_sat_inc16(&s->counters.seq_errors);
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER);
    }
    if (len > dl_limit(s) - s->dl_received) {
        abort_download(s);                        /* iso14229 server.c:1060-1062: 0x71 ends the transfer */
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_TRANSFER_DATA_SUSPENDED);
    }
    if (DL_Z(s)) {
        return udsota_job_start(s, sid, false, s->engine.zwrite(s->engine.ctx, data, len), dl_block_done,
                                ((uint32_t)len << 8) | bsc, resp, resp_max, now_ms);
    }
    if (!s->ota_open) {
        /* First block: check the image before anything is erased. */
        udsota_reason_t why = UDSOTA_DL_OK;
        if (s->engine.check_first(s->engine.ctx, data, len, &why) != 0) {
            abort_download(s);
            s->last_dl.reason_code = (uint8_t)(why != UDSOTA_DL_OK ? why : UDSOTA_DL_BAD_HEADER);
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
        }
        const int rc = s->engine.begin(s->engine.ctx, s->dl_announced);
        if (rc != 0 && rc != UDSOTA_PENDING) {   /* not even queued: no handle is open */
            dl_flash_failed(s);
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
        }
        s->ota_open = true;
    }
    /* Queued behind the erase on the first block; engine.write copies data before it returns. */
    return udsota_job_start(s, sid, false, s->engine.write(s->engine.ctx, s->dl_received, data, len), dl_block_done,
                            ((uint32_t)len << 8) | bsc, resp, resp_max, now_ms);
}

/* The 37's positive tail: the transfer closes, FF01 may verify the open image, F1F1 reads OK; 77. */
static size_t dl_exit_ok(udsota_server_t *s, uint8_t *resp)
{
    s->download_active = false;
    s->dl_complete = true;                        /* FF01 may now verify the open handle */
    s->last_dl.reason_code = UDSOTA_DL_OK;
    s->last_dl.bytes_received = s->dl_received;
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
        s->last_dl.reason_code = dl_reason(result, UDSOTA_DL_BAD_STREAM);
        return udsota_nrc(resp, resp_max, UDSOTA_SID_TRANSFER_EXIT, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    if (resp_max < 1u) {
        return 0;
    }
    if (s->dl_written != s->dl_announced) {       /* the stream ended at memorySize: every byte is written */
        s->dl_written = s->dl_announced;
        s->progress_block = true;
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
    if (!s->download_active || (!DL_Z(s) && s->dl_received != s->dl_announced)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    }
    if (resp_max < 1u) {
        return 0;
    }
    if (DL_Z(s)) {
        return udsota_job_start(s, sid, false, s->engine.zend(s->engine.ctx), dl_exit_done, 0, resp, resp_max, now_ms);
    }
    return dl_exit_ok(s, resp);
}

/* FC-point check (see udsota.h). Not judged while a job runs (the client waits); a latched end_session or any
 * refusal withholds the FC. */
bool udsota_fc_check(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us, uint32_t now_ms)
{
    (void)now_ms;
    if (!s->download_active || s->job_running) {
        return true;
    }
    if (!s->end_pending) {                        /* latched: the job answered but no poll has applied the end yet */
        s->cf_median_us = median_cf_us;
        s->cf_stmin_us = stmin_us;
        if (transfer_nrc(s) == 0u) {
            return true;
        }
    }
    udsota_sat_inc16(&s->counters.withheld_fcs);
    enter_session(s, UDSOTA_SESSION_DEFAULT);     /* also fulfils the latch */
    phase_sync(s);
    progress_sync(s);
    return false;
}

/* ==== RoutineControl 0x31 and the respond-then-restart step ==== */

#define RESET_IDLE   0u
#define RESET_ARMED  1u   /* the answer is built; restart once tx_pending()==0 or UDSOTA_RESET_TX_WAIT_MS passed */
#define RESET_FIRED  2u   /* hooks.reset called (it returns on the host): stay silent from here on */

/* Where a routine is served: its session and whether it needs the programming level (when security is on). */
typedef struct {
    uint16_t rid;
    uint8_t  session;   /* udsota_session_t */
    bool     keyed;     /* needs cfg.level_programming unlocked */
} routine_rule_t;

/* Every RID udsota serves itself. Any other RID goes to hooks.routine, or answers 0x31 without one. */
static const routine_rule_t ROUTINE_RULES[] = {
    {UDSOTA_RID_CHECK_PROG_DEPS,  UDSOTA_SESSION_PROGRAMMING, true},
    {UDSOTA_RID_GET_RESUME_POINT, UDSOTA_SESSION_PROGRAMMING, true},
    {UDSOTA_RID_ACTIVATE_IMAGE,   UDSOTA_SESSION_PROGRAMMING, true},
    {UDSOTA_RID_CONFIRM_IMAGE,    UDSOTA_SESSION_EXTENDED,    false},
};

/* Returns the rule for rid, or NULL when udsota does not serve it. */
static const routine_rule_t *routine_rule(uint16_t rid)
{
    for (size_t i = 0; i < sizeof ROUTINE_RULES / sizeof ROUTINE_RULES[0]; i++) {
        if (ROUTINE_RULES[i].rid == rid) {
            return &ROUTINE_RULES[i];
        }
    }
    return NULL;
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

/* Arms the respond-then-restart step shared by F001 and 11 01. Called while the answer is being
 * built, so the restart can fire no earlier than the next udsota_poll, after that answer was handed out. */
static void reset_arm(udsota_server_t *s, uint32_t now_ms)
{
    s->reset_phase = RESET_ARMED;
    s->reset_armed_ms = now_ms;
}

/* Runs at the top of udsota_poll while a restart is armed or fired: once the answer has left (or 100 ms), relocks,
 * drops to default and calls hooks.reset at most once; a failed reset re-opens the server. Returns 0. */
static size_t reset_poll(udsota_server_t *s, uint32_t now_ms)
{
    if (s->reset_phase == RESET_ARMED &&
        (tx_drained(s) || (uint32_t)(now_ms - s->reset_armed_ms) >= UDSOTA_RESET_TX_WAIT_MS)) {
        s->reset_phase = RESET_FIRED;
        enter_session(s, UDSOTA_SESSION_DEFAULT);    /* relock first: a restart that returns leaves nothing open */
        if (!s->hooks.reset(s->hooks.ctx)) {          /* armed only when hooks.reset is set */
            s->reset_phase = RESET_IDLE;             /* the restart failed: serve requests again, default and locked */
            s->activating = false;
        }
    }
    return 0;
}

/* FF01 verdict: status byte = the worker's udsota_reason_t (anything else is UDSOTA_DL_VERIFY_FAILED); a pass
 * marks the slot verified until the next 0x34 or reboot, and F1F1 records the reason either way. */
static size_t check_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    const uint8_t reason = (result >= (int)UDSOTA_DL_OK && result < (int)UDSOTA_DL_REASON_COUNT)
                         ? (uint8_t)result : (uint8_t)UDSOTA_DL_VERIFY_FAILED;
    s->slot_verified = (reason == UDSOTA_DL_OK);
    s->last_dl.reason_code = reason;
    return routine_pos(resp, resp_max, UDSOTA_RID_CHECK_PROG_DEPS, &reason, 1);
}

/* ActivateImage result: the boot slot is set, so answer and, with a reset hook, arm the restart (phase ACTIVATING);
 * without one the new image boots at the next power cycle. A failure is 0x72 and needs FF01 again. */
static size_t activate_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (result != 0) {
        s->slot_verified = false;
        return udsota_nrc(resp, resp_max, UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    if (s->hooks.reset != NULL) {
        s->activating = true;
        reset_arm(s, now_ms);                         /* armed even if SPRMIB drops the answer */
    }
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

/* hooks.routine_poll with the room after 71 01 <rid> (resp and 0 when resp_max < 4, so no pointer runs past the
 * buffer); its out_len lands in job_out_len. UDSOTA_NRC_GENERAL_REJECT when the app registered none. */
static int app_poll(udsota_server_t *s, uint8_t *resp, size_t resp_max)
{
    s->job_out_len = 0u;
    if (s->hooks.routine_poll == NULL) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    const bool room = resp_max >= 4u;
    return s->hooks.routine_poll(s->hooks.ctx, room ? &resp[4] : resp, room ? resp_max - 4u : 0u, &s->job_out_len);
}

/* An app routine's result (udsota_job_done_fn): 0 is 71 01 <rid> and the job_out_len bytes the app wrote at
 * resp[4]; 1..0xFF is that NRC; anything else, or an out record longer than its room, is 0x10. job_arg is the RID. */
static size_t app_routine_done(udsota_server_t *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    (void)now_ms;
    if (result > 0 && result <= 0xFF) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_ROUTINE, (uint8_t)result);
    }
    if (result != 0 || resp_max < 4u || s->job_out_len > resp_max - 4u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_REJECT);
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_ROUTINE);
    resp[1] = UDSOTA_RC_START;
    udsota_put_u16be(&resp[2], (uint16_t)s->job_arg);
    return 4u + s->job_out_len;
}

/* 31 01 for a RID the core does not own, after the session, length and sub-function checks: 0x31 without
 * hooks.routine; 0x22 while an app orphan runs (routine_poll speaks for one routine at a time); nothing when
 * there is no room for 71 01 <rid>; else the app's answer, now or, for UDSOTA_PENDING, from udsota_poll after
 * 0x78s. The option record after the RID is the app's to check. */
static size_t handle_app_routine(udsota_server_t *s, uint16_t rid, const uint8_t *req, size_t len, bool spr,
                                 uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_ROUTINE;
    if (s->hooks.routine == NULL) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (s->app_orphan) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    }
    if (resp_max < 4u) {
        return 0;
    }
    const udsota_access_t access = access_of(s);   /* the same access state did_write gets */
    size_t out_len = 0u;
    const int rc = s->hooks.routine(s->hooks.ctx, rid, &req[4], len - 4u, &resp[4], resp_max - 4u, &out_len, access);
    s->job_out_len = out_len;
    s->job_app = (rc == UDSOTA_PENDING);
    return udsota_job_start(s, sid, spr, rc, app_routine_done, rid, resp, resp_max, now_ms);
}

/* 0x31 startRoutine. Check order: session 7F, length 13, sub-function 12; a RID the core does not own then goes
 * to handle_app_routine. For the core's own: RID in this session 31, key 33, exact length 13, then per RID the
 * sequence (24) before the conditions (22). */
static size_t handle_routine(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max,
                             uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_ROUTINE;
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (len < 4u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    if ((req[1] & (uint8_t)~UDSOTA_SPRMIB) != UDSOTA_RC_START) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    const uint16_t rid = udsota_get_u16be(&req[2]);
    const routine_rule_t *rule = routine_rule(rid);
    if (rule == NULL) {
        return handle_app_routine(s, rid, req, len, spr, resp, resp_max, now_ms);
    }
    if (rule->session != s->session) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (rule->keyed && s->secured && s->security != s->cfg.level_programming) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    }
    if (len != 4u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    switch (rid) {
    case UDSOTA_RID_CHECK_PROG_DEPS:
        if (s->slot_verified && !s->ota_open) {        /* passed, no new download since: repeat the verdict */
            const uint8_t status = UDSOTA_DL_OK;
            return spr ? 0 : routine_pos(resp, resp_max, rid, &status, 1);
        }
        if (!s->dl_complete || !s->ota_open) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
        }
        s->dl_complete = false;                        /* the engine's verify frees the handle whatever it finds, */
        s->ota_open = false;                           /* so FF01 again is 0x24, or 00 after a pass */
        s->slot_verified = false;
        s->last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;    /* check_done overwrites it; stays if the 90 s cap fires */
        return udsota_job_start(s, sid, spr, s->engine.verify(s->engine.ctx), check_done, 0, resp, resp_max, now_ms);
    case UDSOTA_RID_GET_RESUME_POINT: {
        const uint8_t status = UDSOTA_RESUME_NOT_AVAILABLE;   /* resume is not implemented: always not available */
        return spr ? 0 : routine_pos(resp, resp_max, rid, &status, 1);
    }
    case UDSOTA_RID_ACTIVATE_IMAGE: {
        if (!s->slot_verified) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
        }
        const uint8_t cond = restart_nrc(s, UDSOTA_OP_ACTIVATE);
        if (cond != 0u) {
            return udsota_nrc(resp, resp_max, sid, cond);
        }
        return udsota_job_start(s, sid, spr, s->engine.activate(s->engine.ctx), activate_done, 0, resp, resp_max, now_ms);
    }
    default: {   /* UDSOTA_RID_CONFIRM_IMAGE: the gate first, then the core rule */
        const uint8_t cond = gate(s, UDSOTA_OP_CONFIRM);
        if (cond != 0u) {
            return udsota_nrc(resp, resp_max, sid, cond);
        }
        switch (confirm_action(s)) {
        case CONFIRM_RUN:
            return udsota_job_start(s, sid, spr, s->engine.confirm(s->engine.ctx), confirm_done, 0,
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
                           .last_reason = s->last_dl.reason_code};
    if (s->activating) {
        p.stage = UDSOTA_STAGE_ACTIVATING;
    } else if (s->job_running && s->job_done == check_done) {
        p.stage = UDSOTA_STAGE_VERIFYING;              /* engines report no hash progress: 0 of 0 */
    } else if (s->download_active || (s->dl_complete && s->ota_open)) {
        const bool erasing = s->download_active && s->dl_received == 0u;   /* no 36 accepted yet */
        p.stage = erasing ? UDSOTA_STAGE_ERASING : UDSOTA_STAGE_WRITING;
        p.total = s->dl_announced;
        p.done = (s->dl_written < p.total) ? s->dl_written : p.total;
    }
    return p;
}

/* Reports progress to hooks.progress, once, at the end of the server call that changed the stage or the last reason,
 * or wrote a block. */
static void progress_sync(udsota_server_t *s)
{
    const udsota_progress_t p = progress_of(s);
    const bool block = s->progress_block;
    s->progress_block = false;
    if ((uint8_t)p.stage == s->progress_stage && !block && p.last_reason == s->progress_reason) {
        return;
    }
    s->progress_stage = (uint8_t)p.stage;
    s->progress_reason = p.last_reason;
    if (s->hooks.progress != NULL) {
        s->hooks.progress(s->hooks.ctx, &p);
    }
}

/* See udsota.h: the progress of the server's state as it is now. */
void udsota_progress(const udsota_server_t *s, udsota_progress_t *out)
{
    *out = progress_of(s);
}

/* See udsota.h: done / total in permille, 0 without a total. */
uint16_t udsota_progress_permille(const udsota_progress_t *p)
{
    if (p->total == 0u) {
        return 0u;
    }
    const uint64_t done = (p->done < p->total) ? p->done : p->total;
    return (uint16_t)(done * 1000u / p->total);
}

/* ---- 0x11 ECUReset ---- */

/* 11 01 hardReset, keyed: extended or programming with either level unlocked, then the reset rule: the core's
 * worker-idle rule, then gate(RESET).
 * Answers 51 01 and restarts once that answer has left, through reset_arm. Check order: session
 * 7F, length 13, sub-function 12, key 33, exact length 13, conditions 22. A running job's 0x21 comes
 * earlier, from udsota_on_request. */
static size_t handle_ecu_reset(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max,
                               uint32_t now_ms)
{
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (len < 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    if ((req[1] & (uint8_t)~UDSOTA_SPRMIB) != UDSOTA_RESET_HARD) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (s->secured && s->security == 0) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    }
    if (len != 2) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t cond = restart_nrc(s, UDSOTA_OP_RESET);
    if (cond != 0u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, cond);
    }
    if (!spr && resp_max < 2) {
        return 0;                              /* no room for 51 01: don't restart without answering */
    }
    reset_arm(s, now_ms);
    if (spr) {
        return 0;
    }
    resp[0] = UDSOTA_POS(UDSOTA_SID_RESET);
    resp[1] = UDSOTA_RESET_HARD;
    return 2;
}

/* 0x28 CommunicationControl (only with hooks.comm_control): controlType 00-03 with a communicationType, in the
 * extended or programming session; the hook decides. Check order: session 7F, length 13, sub-function 12, exact
 * length 13, communicationType 31 (no message type named), then the hook's NRC. 68 <controlType>. */
static size_t handle_comm_control(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_COMM_CONTROL;
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (len < 2u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t control = req[1] & (uint8_t)~UDSOTA_SPRMIB;
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    if (control > UDSOTA_CC_DISABLE_RX_TX) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (len != 3u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t comm_type = req[2];
    if ((comm_type & UDSOTA_CC_TYPE_ALL) == 0u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    const uint8_t nrc = s->hooks.comm_control(s->hooks.ctx, control, comm_type);
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, sid, nrc);
    }
    /* Only 28 00 for every message type and subnet leaves nothing to undo; a partial enable still owes one. */
    s->comm_changed = !(control == UDSOTA_CC_ENABLE_RX_TX && comm_type == UDSOTA_CC_TYPE_ALL);
    if (spr || resp_max < 2u) {
        return 0;
    }
    resp[0] = UDSOTA_POS(sid);
    resp[1] = control;
    return 2;
}

/* 0x85 ControlDTCSetting (only with hooks.dtc_setting): 01 on, 02 off, in the extended or programming session, with
 * any option record; answers C5 <sub> and tells the hook. Check order: session 7F, length 13, sub-function 12. */
static size_t handle_dtc_setting(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_DTC_SETTING;
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    }
    if (len < 2u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t sub = req[1] & (uint8_t)~UDSOTA_SPRMIB;
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    if (sub != UDSOTA_DTC_ON && sub != UDSOTA_DTC_OFF) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    s->dtc_off = (sub == UDSOTA_DTC_OFF);
    s->hooks.dtc_setting(s->hooks.ctx, sub == UDSOTA_DTC_ON);
    if (spr || resp_max < 2u) {
        return 0;
    }
    resp[0] = UDSOTA_POS(sid);
    resp[1] = sub;
    return 2;
}

/* Routes one request (no job running) to its service handler; unknown SIDs get NRC 0x11. */
static size_t dispatch(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max,
                       uint32_t now_ms)
{
    switch (req[0]) {
    case UDSOTA_SID_SESSION:
        return handle_session(s, req, len, resp, resp_max);
    case UDSOTA_SID_TESTER_PRESENT:
        return handle_tester_present(req, len, resp, resp_max);
    case UDSOTA_SID_READ_DID:
        return handle_read_did(s, req, len, resp, resp_max);
    case UDSOTA_SID_SECURITY:            /* no security: 0x11 before anything else */
        return s->secured ? sa_handle(s, req, len, resp, resp_max, now_ms)
                          : udsota_nrc(resp, resp_max, UDSOTA_SID_SECURITY, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    case UDSOTA_SID_REQUEST_DOWNLOAD:
        return handle_request_download(s, req, len, resp, resp_max);
    case UDSOTA_SID_TRANSFER_DATA:
        return handle_transfer_data(s, req, len, resp, resp_max, now_ms);
    case UDSOTA_SID_TRANSFER_EXIT:
        return handle_transfer_exit(s, len, resp, resp_max, now_ms);
    case UDSOTA_SID_ROUTINE:
        return handle_routine(s, req, len, resp, resp_max, now_ms);
    case UDSOTA_SID_RESET:               /* no reset hook: 0x11 before anything else */
        return s->hooks.reset != NULL ? handle_ecu_reset(s, req, len, resp, resp_max, now_ms)
                                      : udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    case UDSOTA_SID_COMM_CONTROL:        /* no comm_control hook: 0x11 before anything else */
        return s->hooks.comm_control != NULL ? handle_comm_control(s, req, len, resp, resp_max)
                                             : udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    case UDSOTA_SID_DTC_SETTING:         /* no dtc_setting hook: 0x11 before anything else */
        return s->hooks.dtc_setting != NULL ? handle_dtc_setting(s, req, len, resp, resp_max)
                                            : udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    case UDSOTA_SID_WRITE_DID:           /* no did_write hook: 0x11 before anything else */
        return s->hooks.did_write != NULL ? handle_write_did(s, req, len, resp, resp_max)
                                          : udsota_nrc(resp, resp_max, UDSOTA_SID_WRITE_DID,
                                                       UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    default:
        return udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    }
}

/* cfg with every zero field replaced by its default (NULL = all defaults) and max_block_len capped at 4095. */
static udsota_config_t cfg_resolve(const udsota_config_t *in)
{
    udsota_config_t c;
    if (in != NULL) {
        c = *in;
    } else {
        memset(&c, 0, sizeof c);
    }
    if (c.p2_ms == 0u) c.p2_ms = UDSOTA_P2_MS;
    if (c.p2star_ms == 0u) c.p2star_ms = UDSOTA_P2STAR_MS;
    if (c.p2_prog_ms == 0u) c.p2_prog_ms = c.p2_ms;
    if (c.p2star_prog_ms == 0u) c.p2star_prog_ms = c.p2star_ms;
    if (c.s3_ms == 0u) c.s3_ms = UDSOTA_S3_MS;
    if (c.max_block_len == 0u || c.max_block_len > UDSOTA_DL_MAX_BLOCK_LEN) c.max_block_len = UDSOTA_DL_MAX_BLOCK_LEN;
    if (c.stmin_us == 0u) c.stmin_us = UDSOTA_STMIN_DEFAULT_US;
    if (c.block_size == 0u) c.block_size = UDSOTA_BLOCK_SIZE_DEFAULT;
    if (c.level_extended == 0u) c.level_extended = UDSOTA_SA_SEED_EXTENDED;
    if (c.level_programming == 0u) c.level_programming = UDSOTA_SA_SEED_PROGRAMMING;
    return c;
}

/* Resets s to the default session, locked and idle, and copies the four structs (see udsota.h); false for a
 * security with no rng16 or with neither key nor verify, which is then kept on and never unlocks. */
bool udsota_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_engine_t *engine,
                 const udsota_security_t *security, const udsota_hooks_t *hooks)
{
    memset(s, 0, sizeof *s);
    s->cfg = cfg_resolve(cfg);
    if (engine != NULL) {
        s->engine = *engine;
    }
    if (security != NULL) {
        s->sec = *security;
        s->secured = true;
    }
    if (hooks != NULL) {
        s->hooks = *hooks;
    }
    s->session = UDSOTA_SESSION_DEFAULT;
    s->phase = UDSOTA_PHASE_IDLE;
    s->progress_stage = UDSOTA_STAGE_IDLE;
    s->next_bsc = 1;
    sa_init(s);
    return security == NULL || (security->rng16 != NULL && (security->key != NULL || security->verify != NULL));
}

/* Installs the transport's tx_pending source; call after udsota_init. */
void udsota_set_tx_pending(udsota_server_t *s, uint32_t (*tx_pending)(void *ctx), void *ctx)
{
    s->tx_pending = tx_pending;
    s->tx_pending_ctx = ctx;
}

/* Ends the session from the app (see udsota.h): at once, or latched until a running job has answered, so no job
 * loses its final answer. */
void udsota_end_session(udsota_server_t *s, uint32_t now_ms)
{
    (void)now_ms;
    if (s->reset_phase != RESET_IDLE) {
        return;                                    /* the restart ends the session itself */
    }
    if (s->job_running) {
        s->end_pending = true;                     /* applied by apply_end_pending after the job's answer */
        return;
    }
    enter_session(s, UDSOTA_SESSION_DEFAULT);
    phase_sync(s);
    progress_sync(s);
}

/* The phase last reported to hooks.phase. */
udsota_phase_t udsota_phase(const udsota_server_t *s)
{
    return (udsota_phase_t)s->phase;
}

/* True between an accepted 34 and 37 or an abort. */
bool udsota_download_active(const udsota_server_t *s)
{
    return s->download_active;
}

/* Finishes a handler whose op may have queued worker work (see udsota_priv.h). */
size_t udsota_job_start(udsota_server_t *s, uint8_t sid, bool suppress_pos, int rc, udsota_job_done_fn done,
                     uint32_t arg, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    s->job_arg = arg;
    s->job_sid = sid;
    if (rc != UDSOTA_PENDING) {
        const size_t n = done(s, rc, resp, resp_max, now_ms);
        return (suppress_pos && is_positive(resp, n)) ? 0 : n;
    }
    s->job_running = true;
    s->job_pending_sent = false;
    s->job_suppress_pos = suppress_pos;
    s->job_start_ms = now_ms;
    s->last_pending_ms = now_ms;
    s->job_done = done;
    s->s3_running = false;
    return 0;
}

/* Handles one reassembled request. While a job runs only TesterPresent is served; anything else is
 * NRC 0x21 and changes nothing. Once a restart is armed nothing is answered. S3 stops on receipt and
 * restarts once the request is answered. */
size_t udsota_on_request(udsota_server_t *s, const uint8_t *req, size_t req_len,
                             uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (req == NULL || req_len == 0 || resp == NULL) {
        return 0;
    }
    if (s->reset_phase != RESET_IDLE) {
        return 0;                                  /* restarting: answer nothing, start nothing */
    }
    if (s->job_running) {
        if (req[0] == UDSOTA_SID_TESTER_PRESENT) {
            return handle_tester_present(req, req_len, resp, resp_max);
        }
        return udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_BUSY_REPEAT);
    }
    apply_end_pending(s);                          /* a request before the next poll sees the ended session */
    phase_sync(s);                                 /* and its hooks see IDLE before dispatch asks the gate */
    s->s3_running = false;
    const size_t n = dispatch(s, req, req_len, resp, resp_max, now_ms);
    if (!s->job_running) {
        answered(s, now_ms);
    }
    phase_sync(s);
    progress_sync(s);
    return n;
}

/* True for a request udsota serves functionally: 10 01, 10 03, 3E, 22, 28 and 85 (a 10 02 is sent physically, to the
 * one device being programmed). */
static bool functional_served(const uint8_t *req, size_t len)
{
    switch (req[0]) {
    case UDSOTA_SID_SESSION: {
        const uint8_t sub = (len >= 2u) ? (uint8_t)(req[1] & (uint8_t)~UDSOTA_SPRMIB) : 0u;
        return sub == UDSOTA_SESSION_DEFAULT || sub == UDSOTA_SESSION_EXTENDED;
    }
    case UDSOTA_SID_TESTER_PRESENT:
    case UDSOTA_SID_READ_DID:
    case UDSOTA_SID_COMM_CONTROL:
    case UDSOTA_SID_DTC_SETTING:
        return true;
    default:
        return false;
    }
}

/* True when n bytes in resp are an NRC that ISO 14229-1 suppresses for a functional request: 0x11, 0x12, 0x31, 0x7E
 * or 0x7F. */
static bool functional_suppressed(const uint8_t *resp, size_t n)
{
    if (n != 3u || resp[0] != UDSOTA_NEG_RESPONSE) {
        return false;
    }
    switch (resp[2]) {
    case UDSOTA_NRC_SERVICE_NOT_SUPPORTED:
    case UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED:
    case UDSOTA_NRC_REQUEST_OUT_OF_RANGE:
    case UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION:
    case UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION:
        return true;
    default:
        return false;
    }
}

/* See udsota.h: the functional subset, through the same path as a physical request, with the functional NRCs
 * suppressed. While a job runs only 3E is served (a busy 0x21 to a broadcast would be noise). */
size_t udsota_on_functional_request(udsota_server_t *s, const uint8_t *req, size_t req_len,
                                    uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (req == NULL || req_len == 0 || resp == NULL || !functional_served(req, req_len)) {
        return 0;
    }
    if (s->job_running && req[0] != UDSOTA_SID_TESTER_PRESENT) {
        return 0;
    }
    const size_t n = udsota_on_request(s, req, req_len, resp, resp_max, now_ms);
    return functional_suppressed(resp, n) ? 0 : n;
}

/* Takes a finished job's result: clears the job, builds its answer, applies SPRMIB and restarts S3. */
static size_t finish_job(udsota_server_t *s, int rc, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const udsota_job_done_fn done = s->job_done;
    const bool drop_pos = s->job_suppress_pos && !s->job_pending_sent;
    s->job_running = false;
    s->job_done = NULL;
    const size_t n = done(s, rc, resp, resp_max, now_ms);
    answered(s, now_ms);
    return (drop_pos && is_positive(resp, n)) ? 0 : n;
}

/* Advances a running job through its own poll (engine.poll, or routine_poll for an app routine): its final answer,
 * the 90 s cap (0x72, session ends), or the 0x78 cadence. */
static size_t poll_job(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const int rc = s->job_app ? app_poll(s, resp, resp_max) : s->engine.poll(s->engine.ctx);
    if (rc != UDSOTA_PENDING) {
        s->job_app = false;
        return finish_job(s, rc, resp, resp_max, now_ms);
    }
    const uint32_t elapsed = now_ms - s->job_start_ms;
    if (elapsed >= UDSOTA_JOB_CAP_MS) {
        const uint8_t sid = s->job_sid;
        const bool was_download = !s->job_app && (s->download_active || s->ota_open);
        orphan_job(s);   /* its owner still runs it; 10 02 waits for it */
        udsota_sat_inc16(&s->counters.resp_pending_caps);
        enter_session(s, UDSOTA_SESSION_DEFAULT);
        if (was_download) {
            s->last_dl.reason_code = UDSOTA_DL_WORKER_TIMEOUT;
        }
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    const bool due = s->job_pending_sent ? (now_ms - s->last_pending_ms) >= pending_repeat_ms(s)
                                         : elapsed >= pending_first_ms(s);
    if (!due) {
        return 0;
    }
    s->job_pending_sent = true;
    s->last_pending_ms = now_ms;
    return udsota_nrc(resp, resp_max, s->job_sid, UDSOTA_NRC_RESPONSE_PENDING);
}

/* Advances the job wait, the orphaned-job watch, a latched end_session and S3; returns a response length to send (a
 * 0x78, 0x72 or a job's final answer), or 0. An app that must end a session (a second device on the IDs, say) calls udsota_end_session. */
static size_t poll_step(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (s->reset_phase != RESET_IDLE) {
        return reset_poll(s, now_ms);
    }
    if (s->worker_orphan && !s->job_running && s->engine.poll(s->engine.ctx) != UDSOTA_PENDING) {
        s->worker_orphan = false;
    }
    if (s->app_orphan && app_poll(s, resp, resp_max) != UDSOTA_PENDING) {
        s->app_orphan = false;                        /* only routine_poll ends an app orphan, never engine.poll */
    }
    if (s->job_running) {
        return poll_job(s, resp, resp_max, now_ms);   /* a job's final answer is built and sent here first */
    }
    apply_end_pending(s);                             /* then, at the next poll, a latched end_session */
    phase_sync(s);                                    /* reported at once, as on_request does */
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return 0;
    }
    if (s->s3_running && (now_ms - s->s3_start_ms) >= s->cfg.s3_ms) {
        enter_session(s, UDSOTA_SESSION_DEFAULT);
    }
    return 0;
}

/* See udsota.h: one poll step, then the phase hook if the phase changed and the progress hook if the stage changed
 * or a block was written. */
size_t udsota_poll(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const size_t n = poll_step(s, resp, resp_max, now_ms);
    phase_sync(s);
    progress_sync(s);
    return n;
}

/* A First Frame arrived on the request ID: S3 stops until that request is answered or abandoned. */
void udsota_on_rx_first_frame(udsota_server_t *s, uint32_t now_ms)
{
    (void)now_ms;
    s->s3_running = false;
}

/* A multi-frame request was abandoned (N_Cr): counts it in F1F2 and restarts S3 from now. */
void udsota_on_rx_timeout(udsota_server_t *s, uint32_t now_ms)
{
    udsota_sat_inc16(&s->counters.ncr_timeouts);
    if (!s->job_running) {
        answered(s, now_ms);
    }
}

/* True between reset_arm() and the restart firing (RESET_ARMED). */
bool udsota_restart_armed(const udsota_server_t *s)
{
    return s->reset_phase == RESET_ARMED;
}

/* Milliseconds until udsota_poll next has work: UDSOTA_JOB_POLL_MS during or after a job or while a
 * restart is armed, the S3 remainder capped at UDSOTA_IDLE_POLL_MS in a non-default session, else
 * UINT32_MAX (also once the restart has fired). */
uint32_t udsota_ms_to_deadline(const udsota_server_t *s, uint32_t now_ms)
{
    if (s->reset_phase != RESET_IDLE) {
        return s->reset_phase == RESET_ARMED ? UDSOTA_JOB_POLL_MS : UINT32_MAX;
    }
    if (s->job_running || s->worker_orphan || s->app_orphan) {
        return UDSOTA_JOB_POLL_MS;
    }
    if (s->session == UDSOTA_SESSION_DEFAULT) {
        return UINT32_MAX;
    }
    uint32_t wait = UDSOTA_IDLE_POLL_MS;
    if (s->s3_running) {
        const uint32_t elapsed = now_ms - s->s3_start_ms;
        const uint32_t left = elapsed >= s->cfg.s3_ms ? 0u : s->cfg.s3_ms - elapsed;
        if (left < wait) {
            wait = left;
        }
    }
    return wait;
}
