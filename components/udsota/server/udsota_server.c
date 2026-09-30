/* Pure UDS server core: sessions, S3, SecurityAccess, routines, reset, 0x2E, 0x19 and 0x14 through the app's hooks,
 * and the worker-job wait, behind the security and hooks the integrator passes to udsota_core_init; SIDs, RIDs and
 * DIDs the core doesn't own go to the one registered service (udsota_service.h), such as the firmware updater
 * (update/udsota_update.c). The core never names a service. No ESP-IDF: the transport feeds it reassembled requests,
 * reception events and now_ms, and sends whatever it returns. */
#include <assert.h>
#include <string.h>
#include "udsota_server.h"
#include "udsota_service.h"

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

/* Relocks: level and seed cleared; the attempt count and delay survive, so hopping sessions cannot reset a lockout.
 * Call before every session change. */
static void sa_relock(udsota_server_t *s)
{
    s->security = 0;
    sa_forget_seed(s);
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

static void enter_session(udsota_server_t *s, uint8_t session, bool job_capped);

/* The service's poll: UDSOTA_PENDING while it has work queued, else its last result. UDSOTA_NRC_GENERAL_REJECT with no
 * service, as app_poll without routine_poll. */
static int svc_poll(const udsota_server_t *s)
{
    return s->svc != NULL ? s->svc->poll(s) : UDSOTA_NRC_GENERAL_REJECT;
}

/* True while the service has a transfer open; false with no service. */
static bool svc_download_active(const udsota_server_t *s)
{
    return s->svc != NULL && s->svc->download_active(s);
}

/* The service's end-of-call report (the updater's progress); nothing with no service. */
static void svc_sync(udsota_server_t *s)
{
    if (s->svc != NULL) {
        s->svc->sync(s);
    }
}

/* See udsota_service.h. The core calls a registered service's members without a NULL check. */
void udsota_register_service(udsota_server_t *s, const udsota_service_t *svc)
{
    assert(svc == NULL || (svc->request != NULL && svc->routine != NULL && svc->owns_rid != NULL &&
                           svc->read_did != NULL && svc->on_session != NULL && svc->settled != NULL &&
                           svc->download_active != NULL && svc->poll != NULL && svc->fc_point != NULL &&
                           svc->sync != NULL));
    s->svc = svc;
}

/* Asks hooks.gate about op: 0 = allow (also when no gate is registered), else the NRC to send. */
uint8_t udsota_gate(const udsota_server_t *s, udsota_op_t op)
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

/* True while the worker owns a job: one the server waits on, an orphan (the service's or an app routine's), or
 * anything the service's poll still reports queued (the updater's fire-and-forget abort included). */
bool udsota_worker_busy(const udsota_server_t *s)
{
    return s->job_running || s->worker_orphan || s->app_orphan || svc_poll(s) == UDSOTA_PENDING;
}

/* 10 02, with a service registered: its slot rule, the worker idle and no transfer open (in that order, as the
 * updater's own 34 asks them), then gate(ENTER_PROGRAMMING). */
static uint8_t program_nrc(const udsota_server_t *s)
{
    if (!s->svc->settled(s) || udsota_worker_busy(s) || s->svc->download_active(s)) {
        return UDSOTA_NRC_CONDITIONS_NOT_CORRECT;
    }
    return udsota_gate(s, UDSOTA_OP_ENTER_PROGRAMMING);
}

/* ACTIVATE and RESET: the worker is idle, then the gate. */
uint8_t udsota_restart_nrc(const udsota_server_t *s, udsota_op_t op)
{
    return udsota_worker_busy(s) ? UDSOTA_NRC_CONDITIONS_NOT_CORRECT : udsota_gate(s, op);
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
        return svc_download_active(s) ? UDSOTA_PHASE_TRANSFERRING : UDSOTA_PHASE_PROGRAMMING;
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

/* Stops waiting on the running job; its owner keeps it as an orphan: the service's until its poll stops
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
        enter_session(s, UDSOTA_SESSION_DEFAULT, false);
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
 * app's end_session request, a refused 36 and a withheld FC point). The service hears of it first (job_capped: the
 * 90 s cap ended the service's own job), and the updater aborts any open download; then security relocks and the
 * session epoch advances, the same session included (ISO 14229-1 re-initialises it); udsota_core_init restarts the
 * epoch at 0. */
static void enter_session(udsota_server_t *s, uint8_t session, bool job_capped)
{
    if (s->svc != NULL) {
        s->svc->on_session(s, job_capped);
    }
    sa_relock(s);
    s->session_epoch++;        /* app state tied to the old epoch is stale from here on */
    s->end_pending = false;   /* any session change fulfils a latched end_session */
    s->session = session;
    s->s3_running = false;     /* answered() restarts it in a non-default session */
    if (session == UDSOTA_SESSION_DEFAULT) {
        restore_default_comm(s);
    }
}

/* See udsota_service.h: the default session now, as a refused 36 needs; the caller's public call reports the phase. */
void udsota_end_session_now(udsota_server_t *s)
{
    enter_session(s, UDSOTA_SESSION_DEFAULT, false);
}

/* 0x10 DiagnosticSessionControl: 01/02/03. 02 needs a registered service (0x12 without one: nothing is programmed
 * there), then program_nrc (the service's conditions and an idle worker) and gate(ENTER_PROGRAMMING); 03 needs
 * gate(ENTER_EXTENDED). The positive answer carries the new session's P2 and P2* (10 ms units). */
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
    if (sub == UDSOTA_SESSION_PROGRAMMING && s->svc == NULL) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    uint8_t nrc = 0;
    if (sub == UDSOTA_SESSION_PROGRAMMING) {
        nrc = program_nrc(s);
    } else if (sub == UDSOTA_SESSION_EXTENDED) {
        nrc = udsota_gate(s, UDSOTA_OP_ENTER_EXTENDED);
    }
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_SESSION, nrc);
    }
    if (resp_max < 6) {
        return 0;
    }
    enter_session(s, sub, false);
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

/* hooks.did_read_ex for a DID the core and the service leave to the app, into the room after 62 <did>: 0 with *len
 * in 1..room is the answer, 0 with *len 0 or past room 0x10, and any other return the NRC to send. */
static size_t app_read_did_ex(udsota_server_t *s, uint16_t did, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_READ_DID;
    const size_t room = resp_max - 3u;
    size_t len = 0u;
    const uint8_t nrc = s->hooks.did_read_ex(s->hooks.ctx, did, &resp[3], room, &len, access_of(s));
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, sid, nrc);
    }
    if (len == 0u || len > room) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_GENERAL_REJECT);
    }
    resp[0] = UDSOTA_POS(sid);
    udsota_put_u16be(&resp[1], did);
    return 3u + len;
}

/* 0x22 ReadDataByIdentifier, one DID per request. F186 and F1F2 come from the server's own state and F18C from
 * cfg.device_id; every other DID (and F18C without a device ID) goes to the service, and one it passes, or every one
 * with no service, to hooks.did_read_ex when set (app_read_did_ex), else to hooks.did_read; 0 bytes means NRC 0x31,
 * and an answer longer than room 0x14. */
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
    size_t n = 0;                                 /* 0: no one serves the DID, 0x31 */
    if (did == UDSOTA_DID_ACTIVE_SESSION) {
        out[0] = s->session;
        n = 1;
    } else if (did == UDSOTA_DID_COUNTERS) {
        n = room < UDSOTA_COUNTERS_LEN ? UDSOTA_COUNTERS_LEN : udsota_pack_counters(out, room, &s->counters);
    } else if (did == UDSOTA_DID_SERIAL && s->cfg.device_id != NULL && s->cfg.device_id_len != 0u) {
        n = s->cfg.device_id_len;
        if (n <= room) {
            memcpy(out, s->cfg.device_id, n);     /* longer: 0x14 below */
        }
    } else {
        n = (s->svc != NULL) ? s->svc->read_did(s, did, out, room) : UDSOTA_SVC_PASS;
        if (n == UDSOTA_SVC_PASS && s->hooks.did_read_ex != NULL) {
            return app_read_did_ex(s, did, resp, resp_max);
        }
        if (n == UDSOTA_SVC_PASS) {
            n = (s->hooks.did_read != NULL) ? s->hooks.did_read(s->hooks.ctx, did, out, room) : 0u;
        }
    }
    if (n == 0) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_READ_DID, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (n > room) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_READ_DID, UDSOTA_NRC_RESPONSE_TOO_LONG);
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

/* FC-point check (see udsota_server.h). Judged only while the service has a transfer open, and not while a job runs
 * (the client waits); a latched end_session or the service's refusal withholds the FC. */
bool udsota_fc_check(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us, uint32_t now_ms)
{
    (void)now_ms;
    if (!svc_download_active(s) || s->job_running) {
        return true;
    }
    if (!s->end_pending && s->svc->fc_point(s, median_cf_us, stmin_us)) {   /* not latched: the service decides */
        return true;
    }
    /* A latched end_session (answered, no poll yet) is withheld without the gate; enter_session fulfils it. */
    udsota_sat_inc16(&s->counters.withheld_fcs);
    enter_session(s, UDSOTA_SESSION_DEFAULT, false);
    phase_sync(s);
    svc_sync(s);
    return false;
}

/* ==== RoutineControl 0x31 and the respond-then-restart step ==== */

#define RESET_IDLE   0u
#define RESET_ARMED  1u   /* the answer is built; restart once tx_pending()==0 or UDSOTA_RESET_TX_WAIT_MS passed */
#define RESET_FIRED  2u   /* hooks.reset called (it returns on the host): stay silent from here on */

/* Arms the respond-then-restart step shared by F001 and 11 01. Called while the answer is being
 * built, so the restart can fire no earlier than the next udsota_poll, after that answer was handed out. */
static void reset_arm(udsota_server_t *s, uint32_t now_ms)
{
    s->reset_phase = RESET_ARMED;
    s->reset_armed_ms = now_ms;
}

/* See udsota_service.h: arms the restart through hooks.reset (false, nothing armed, without one); ACTIVATE also shows
 * the phase ACTIVATING until the restart. */
bool udsota_restart_arm(udsota_server_t *s, udsota_restart_t why, uint32_t now_ms)
{
    if (s->hooks.reset == NULL) {
        return false;
    }
    if (why == UDSOTA_RESTART_ACTIVATE) {
        s->activating = true;
    }
    reset_arm(s, now_ms);
    return true;
}

/* Runs at the top of udsota_poll while a restart is armed or fired: once the answer has left (or 100 ms), relocks,
 * drops to default and calls hooks.reset at most once; a failed reset re-opens the server. Returns 0. */
static size_t reset_poll(udsota_server_t *s, uint32_t now_ms)
{
    if (s->reset_phase == RESET_ARMED &&
        (tx_drained(s) || (uint32_t)(now_ms - s->reset_armed_ms) >= UDSOTA_RESET_TX_WAIT_MS)) {
        s->reset_phase = RESET_FIRED;
        enter_session(s, UDSOTA_SESSION_DEFAULT, false);    /* relock first: a restart that returns leaves nothing open */
        if (!s->hooks.reset(s->hooks.ctx)) {          /* armed only when hooks.reset is set */
            s->reset_phase = RESET_IDLE;             /* the restart failed: serve requests again, default and locked */
            s->activating = false;
        }
    }
    return 0;
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

/* An app routine's result (udsota_job_done_fn): 0 is 71 <sub> <rid> and the job_out_len bytes the app wrote at
 * resp[4]; 1..0xFF is that NRC; anything else, or an out record longer than its room, is 0x10. job_arg is the RID,
 * with the sub-function in bits 16-23. */
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
    resp[1] = (uint8_t)(s->job_arg >> 16);
    udsota_put_u16be(&resp[2], (uint16_t)s->job_arg);
    return 4u + s->job_out_len;
}

/* 31 <sub> for a RID the core does not own, after the core's checks: 0x31 without hooks.routine_ex or routine; 0x22
 * while an app orphan runs (routine_poll speaks for one routine at a time); nothing when there is no room for 71 <sub>
 * <rid>; else the answer of routine_ex, or of routine (sub 01 only), now or, for UDSOTA_PENDING, from udsota_poll after
 * 0x78s. The option record after the RID is the app's to check. */
static size_t handle_app_routine(udsota_server_t *s, uint8_t sub, uint16_t rid, const uint8_t *req, size_t len,
                                 bool spr, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_ROUTINE;
    if (s->hooks.routine_ex == NULL && s->hooks.routine == NULL) {
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
    const int rc = (s->hooks.routine_ex != NULL)
        ? s->hooks.routine_ex(s->hooks.ctx, sub, rid, &req[4], len - 4u, &resp[4], resp_max - 4u, &out_len, access)
        : s->hooks.routine(s->hooks.ctx, rid, &req[4], len - 4u, &resp[4], resp_max - 4u, &out_len, access);
    s->job_out_len = out_len;
    s->job_app = (rc == UDSOTA_PENDING);
    return udsota_job_start(s, sid, spr, rc, app_routine_done, ((uint32_t)sub << 16) | rid, resp, resp_max, now_ms);
}

/* 0x31 RoutineControl. With hooks.routine_ex, length 13 comes first; a RID the service owns then takes the path
 * below, as without the hook, and any other, in every session, the sub-function check (01, 02 or 03, else 12) and
 * handle_app_routine. Otherwise: session 7F, length 13, sub-function 12 (01 only); the service then takes its own
 * RIDs, and any other goes to handle_app_routine. */
static size_t handle_routine(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max,
                             uint32_t now_ms)
{
    const uint8_t sid = UDSOTA_SID_ROUTINE;
    if (s->hooks.routine_ex != NULL) {
        if (len < 4u) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
        }
        const uint16_t rid = udsota_get_u16be(&req[2]);
        if (s->svc == NULL || !s->svc->owns_rid(s, rid)) {
            const uint8_t sub = req[1] & (uint8_t)~UDSOTA_SPRMIB;
            if (sub != UDSOTA_RC_START && sub != UDSOTA_RC_STOP && sub != UDSOTA_RC_RESULTS) {
                return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
            }
            return handle_app_routine(s, sub, rid, req, len, (req[1] & UDSOTA_SPRMIB) != 0, resp, resp_max, now_ms);
        }
    }
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
    if (s->svc != NULL) {
        const size_t n = s->svc->routine(s, rid, req, len, spr, resp, resp_max, now_ms);
        if (n != UDSOTA_SVC_PASS) {
            return n;
        }
    }
    return handle_app_routine(s, UDSOTA_RC_START, rid, req, len, spr, resp, resp_max, now_ms);
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
    const uint8_t cond = udsota_restart_nrc(s, UDSOTA_OP_RESET);
    if (cond != 0u) {
        return udsota_nrc(resp, resp_max, UDSOTA_SID_RESET, cond);
    }
    if (!spr && resp_max < 2) {
        return 0;                              /* no room for 51 01: don't restart without answering */
    }
    (void)udsota_restart_arm(s, UDSOTA_RESTART_RESET, now_ms);   /* dispatch serves 11 only with hooks.reset */
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

/* ---- 0x19 ReadDTCInformation and 0x14 ClearDiagnosticInformation: the app's DTCs through hooks.dtc_get,
 * dtc_ext_data and dtc_clear; the core owns the lengths, sub-functions, mask filter, framing and size cap ---- */

#define DTC_BITS  0xFFFFFFu   /* a DTC's three bytes: udsota_dtc_t.dtc's top byte is ignored */

/* Writes the low 24 bits of v big-endian into p[0..2]. */
static void put_u24be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

/* Reads a big-endian 24-bit value from p[0..2]. */
static uint32_t get_u24be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* hooks.dtc_get for the i-th DTC, never asked at UDSOTA_DTC_INDEX_MAX or past it; false there or past the last. */
static bool dtc_at(const udsota_server_t *s, size_t i, udsota_dtc_t *out)
{
    return i < UDSOTA_DTC_INDEX_MAX && s->hooks.dtc_get(s->hooks.ctx, i, out);
}

/* 19 01, 02 and 0A after the length checks: walks dtc_get from 0 and counts (01) or lists (02) each DTC whose
 * status & mask & availability is non-zero, or lists every DTC (0A), each status sent as status & availability.
 * Room is judged on resp_max: 0x14 when 59 01's six bytes or 59 xx <avail> don't fit, or at the first listed DTC
 * that would pass resp_max, which ends the walk. */
static size_t rdtc_list(udsota_server_t *s, uint8_t sub, uint8_t mask, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_READ_DTC;
    const uint8_t avail = s->cfg.dtc_availability_mask;
    const bool count = (sub == UDSOTA_RDTC_COUNT_BY_MASK);
    if (resp_max < (count ? 6u : 3u)) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_RESPONSE_TOO_LONG);
    }
    size_t n = 3u;
    uint16_t matches = 0u;                          /* at most UDSOTA_DTC_INDEX_MAX: dtc_at stops below it */
    udsota_dtc_t d = {0};
    for (size_t i = 0; dtc_at(s, i, &d); i++) {
        const uint8_t status = d.status & avail;
        if (sub != UDSOTA_RDTC_SUPPORTED && (status & mask) == 0u) {
            continue;
        }
        if (count) {
            matches++;
            continue;
        }
        if (resp_max - n < 4u) {
            return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_RESPONSE_TOO_LONG);
        }
        put_u24be(&resp[n], d.dtc);
        resp[n + 3u] = status;
        n += 4u;
    }
    resp[0] = UDSOTA_POS(sid);
    resp[1] = sub;
    resp[2] = avail;
    if (count) {
        resp[3] = s->cfg.dtc_format;
        udsota_put_u16be(&resp[4], matches);
        return 6u;
    }
    return n;
}

/* 19 06 <DTC> <record> after the length checks: record 00 is 0x31; the first DTC dtc_get reports with the request's
 * 24 bits gives the status, and none is 0x31; 0x14 when 59 06 <DTC> <status> doesn't fit; then dtc_ext_data writes
 * the records after it, and its NRC is sent as given, or 0x10 for a *len over its room. */
static size_t rdtc_ext_data(udsota_server_t *s, const uint8_t *req, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_READ_DTC;
    const uint32_t dtc = get_u24be(&req[2]);
    const uint8_t record = req[5];
    if (record == 0u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    udsota_dtc_t d = {0};
    bool found = false;
    for (size_t i = 0; !found && dtc_at(s, i, &d); i++) {
        found = (d.dtc & DTC_BITS) == dtc;
    }
    if (!found) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (resp_max < 6u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_RESPONSE_TOO_LONG);
    }
    const size_t room = resp_max - 6u;
    size_t len = 0u;
    const uint8_t nrc = s->hooks.dtc_ext_data(s->hooks.ctx, dtc, record, &resp[6], room, &len);
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, sid, nrc);
    }
    if (len > room) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_GENERAL_REJECT);
    }
    resp[0] = UDSOTA_POS(sid);
    resp[1] = UDSOTA_RDTC_EXT_DATA;
    put_u24be(&resp[2], dtc);
    resp[5] = d.status & s->cfg.dtc_availability_mask;
    return 6u + len;
}

/* 0x19 ReadDTCInformation (only with hooks.dtc_get), in every session and with no key. Check order: length 13,
 * sub-function 12 (01, 02, 06 and 0A; 06 only with hooks.dtc_ext_data), exact length 13, then rdtc_list's room 14,
 * or rdtc_ext_data's record and DTC 31, room 14 and the hook's NRC. SPRMIB drops only a positive answer: every NRC,
 * 0x14 included, is sent as without it. */
static size_t handle_read_dtc(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_READ_DTC;
    if (len < 2u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const uint8_t sub = req[1] & (uint8_t)~UDSOTA_SPRMIB;
    const bool spr = (req[1] & UDSOTA_SPRMIB) != 0;
    size_t want = 0u;                               /* the sub-function's exact length; 0 = not served */
    if (sub == UDSOTA_RDTC_COUNT_BY_MASK || sub == UDSOTA_RDTC_BY_MASK) {
        want = 3u;
    } else if (sub == UDSOTA_RDTC_SUPPORTED) {
        want = 2u;
    } else if (sub == UDSOTA_RDTC_EXT_DATA && s->hooks.dtc_ext_data != NULL) {
        want = 6u;
    }
    if (want == 0u) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (len != want) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    const size_t n = (sub == UDSOTA_RDTC_EXT_DATA) ? rdtc_ext_data(s, req, resp, resp_max)
                     : rdtc_list(s, sub, (sub == UDSOTA_RDTC_SUPPORTED) ? 0u : req[2], resp, resp_max);
    return (spr && is_positive(resp, n)) ? 0 : n;
}

/* 0x14 ClearDiagnosticInformation (only with hooks.dtc_clear), physical only, in any session: the session and key
 * rules are the hook's. Check order: exact length 13 (14 and a 3-byte groupOfDTC, so the 2020 edition's
 * memorySelection byte is 0x13 too), then the hook's NRC, which it checks in ISO order (7F, 33, 31); 0 answers 54.
 * The hook is not asked when resp has no room at all. */
static size_t handle_clear_dtc(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t resp_max)
{
    const uint8_t sid = UDSOTA_SID_CLEAR_DTC;
    if (len != UDSOTA_CLEAR_DTC_LEN) {
        return udsota_nrc(resp, resp_max, sid, UDSOTA_NRC_INCORRECT_LENGTH);
    }
    if (resp_max < 1u) {
        return 0;
    }
    const uint8_t nrc = s->hooks.dtc_clear(s->hooks.ctx, get_u24be(&req[1]), access_of(s));
    if (nrc != 0u) {
        return udsota_nrc(resp, resp_max, sid, nrc);
    }
    resp[0] = UDSOTA_POS(sid);
    return 1;
}

/* Routes one request (no job running) to its service handler; a SID the core doesn't own goes to the service, and
 * one it passes, or every one with no service, gets NRC 0x11. */
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
    case UDSOTA_SID_READ_DTC:            /* no dtc_get hook: 0x11 before anything else */
        return s->hooks.dtc_get != NULL ? handle_read_dtc(s, req, len, resp, resp_max)
                                        : udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    case UDSOTA_SID_CLEAR_DTC:           /* no dtc_clear hook: 0x11 before anything else */
        return s->hooks.dtc_clear != NULL ? handle_clear_dtc(s, req, len, resp, resp_max)
                                          : udsota_nrc(resp, resp_max, req[0], UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    default:
        if (s->svc != NULL) {
            const size_t n = s->svc->request(s, req, len, resp, resp_max, now_ms);
            if (n != UDSOTA_SVC_PASS) {
                return n;
            }
        }
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
    if (c.dtc_availability_mask == 0u) c.dtc_availability_mask = 0xFFu;
    return c;
}

/* Resets s to the default session, locked and idle, with no service, and copies cfg, security and hooks (see
 * udsota_server.h); false for a security with no rng16 or with neither key nor verify, which is then kept on and
 * never unlocks. */
bool udsota_core_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_security_t *security,
                      const udsota_hooks_t *hooks)
{
    memset(s, 0, sizeof *s);
    s->cfg = cfg_resolve(cfg);
    if (security != NULL) {
        s->sec = *security;
        s->secured = true;
    }
    if (hooks != NULL) {
        s->hooks = *hooks;
    }
    s->session = UDSOTA_SESSION_DEFAULT;
    s->sa_delay_active = true;   /* boot: locked, no seed, and the post-boot 0x27 delay runs from clock 0 */
    return security == NULL || (security->rng16 != NULL && (security->key != NULL || security->verify != NULL));
}

/* Installs the transport's tx_pending source; call after udsota_init. */
void udsota_set_tx_pending(udsota_server_t *s, uint32_t (*tx_pending)(void *ctx), void *ctx)
{
    s->tx_pending = tx_pending;
    s->tx_pending_ctx = ctx;
}

/* Ends the session from the app (see udsota_server.h): at once, or latched until a running job has answered, so no job
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
    enter_session(s, UDSOTA_SESSION_DEFAULT, false);
    phase_sync(s);
    svc_sync(s);
}

/* The phase last reported to hooks.phase. */
udsota_phase_t udsota_phase(const udsota_server_t *s)
{
    return (udsota_phase_t)s->phase;
}

/* True while the service has a transfer open (the updater: between an accepted 34 and 37 or an abort). */
bool udsota_download_active(const udsota_server_t *s)
{
    return svc_download_active(s);
}

/* Finishes a handler whose op may have queued worker work (see udsota_service.h). */
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
    svc_sync(s);
    return n;
}

/* True for a request udsota serves functionally: 10 01, 10 03, 3E, 19 (every sub-function), 22, 28 and 85; 14 stays
 * physical, since clearing needs a per-node unlock (and a 10 02 is sent physically, to the one device being
 * programmed). */
static bool functional_served(const uint8_t *req, size_t len)
{
    switch (req[0]) {
    case UDSOTA_SID_SESSION: {
        const uint8_t sub = (len >= 2u) ? (uint8_t)(req[1] & (uint8_t)~UDSOTA_SPRMIB) : 0u;
        return sub == UDSOTA_SESSION_DEFAULT || sub == UDSOTA_SESSION_EXTENDED;
    }
    case UDSOTA_SID_TESTER_PRESENT:
    case UDSOTA_SID_READ_DTC:
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

/* See udsota_server.h: the functional subset, through the same path as a physical request, with the functional NRCs
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

/* Advances a running job through its own poll (the service's, or routine_poll for an app routine): its final answer,
 * the 90 s cap (0x72, or 0x10 for an app routine, which programs nothing; the session ends), or the 0x78 cadence. */
static size_t poll_job(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const int rc = s->job_app ? app_poll(s, resp, resp_max) : svc_poll(s);
    if (rc != UDSOTA_PENDING) {
        s->job_app = false;
        return finish_job(s, rc, resp, resp_max, now_ms);
    }
    const uint32_t elapsed = now_ms - s->job_start_ms;
    if (elapsed >= UDSOTA_JOB_CAP_MS) {
        const uint8_t sid = s->job_sid;
        const bool mine = !s->job_app;   /* the service's job: its on_session hears the cap */
        const uint8_t nrc = mine ? UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE : UDSOTA_NRC_GENERAL_REJECT;
        orphan_job(s);   /* its owner still runs it; 10 02 waits for it */
        udsota_sat_inc16(&s->counters.resp_pending_caps);
        enter_session(s, UDSOTA_SESSION_DEFAULT, mine);
        return udsota_nrc(resp, resp_max, sid, nrc);
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
 * 0x78, the cap's 0x72 or 0x10, or a job's final answer), or 0. An app that must end a session (a second device on the IDs, say) calls udsota_end_session. */
static size_t poll_step(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    if (s->reset_phase != RESET_IDLE) {
        return reset_poll(s, now_ms);
    }
    if (s->worker_orphan && !s->job_running && svc_poll(s) != UDSOTA_PENDING) {
        s->worker_orphan = false;
    }
    if (s->app_orphan && app_poll(s, resp, resp_max) != UDSOTA_PENDING) {
        s->app_orphan = false;                        /* only routine_poll ends an app orphan, never the service's poll */
    }
    if (s->job_running) {
        return poll_job(s, resp, resp_max, now_ms);   /* a job's final answer is built and sent here first */
    }
    apply_end_pending(s);                             /* then, at the next poll, a latched end_session */
    phase_sync(s);                                    /* reported at once, as on_request does */
    if (s->s3_running && (now_ms - s->s3_start_ms) >= s->cfg.s3_ms) {   /* never running in default */
        enter_session(s, UDSOTA_SESSION_DEFAULT, false);
    }
    return 0;
}

/* See udsota_server.h: one poll step, then the phase hook if the phase changed and the progress hook if the stage
 * changed or a block was written. */
size_t udsota_poll(udsota_server_t *s, uint8_t *resp, size_t resp_max, uint32_t now_ms)
{
    const size_t n = poll_step(s, resp, resp_max, now_ms);
    phase_sync(s);
    svc_sync(s);
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
