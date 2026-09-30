/* What a service builds on: the UDS server's calls for one that serves SIDs, RIDs and DIDs the core doesn't own
 * (the firmware updater is one), NRC framing and the worker-job wait (0x78 cadence, 90 s cap). The core never
 * names a service; a service reaches the core only through this header. Not part of the public diag API. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_server.h"                 /* udsota_server_t, udsota_op_t, udsota_job_done_fn */

/* A service's "not mine": never a response or DID length (both are bounded by resp_max). */
#define UDSOTA_SVC_PASS ((size_t)-1)

typedef struct udsota_service {            /* const, registered once right after udsota_core_init; every member required */
    size_t (*request)(udsota_server_t *s, const uint8_t *req, size_t len,
                      uint8_t *resp, size_t resp_max, uint32_t now_ms);          /* SIDs the core doesn't own */
    size_t (*routine)(udsota_server_t *s, uint16_t rid, const uint8_t *req, size_t len, bool spr,
                      uint8_t *resp, size_t resp_max, uint32_t now_ms);          /* 31 01, after the core's 7F/13/12 */
    bool   (*owns_rid)(const udsota_server_t *s, uint16_t rid);                /* routine's RIDs, in any session */
    size_t (*read_did)(const udsota_server_t *s, uint16_t did, uint8_t *out, size_t room);  /* 0 = 0x31, over room 0x14 */
    void   (*on_session)(udsota_server_t *s, bool job_capped);                  /* every session entry, first */
    bool   (*settled)(const udsota_server_t *s);                                /* 10 02 slot rule */
    bool   (*download_active)(const udsota_server_t *s);                        /* transfer open */
    int    (*poll)(const udsota_server_t *s);                                   /* UDSOTA_PENDING while queued, else last result */
    bool   (*fc_point)(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us);   /* true = allow the FC */
    void   (*sync)(udsota_server_t *s);                                         /* end-of-call report (progress) */
} udsota_service_t;

typedef enum { UDSOTA_RESTART_RESET = 0, UDSOTA_RESTART_ACTIVATE } udsota_restart_t;
typedef struct { uint8_t session; bool unlocked; } udsota_svc_access_t;

/* Registers svc on s; once, right after udsota_core_init: registering while a job or orphan exists would change
 * which poll answers it. NULL registers none; a non-NULL svc with a NULL member fails an assert(). */
void    udsota_register_service(udsota_server_t *s, const udsota_service_t *svc);
/* Writes 7F <sid> <nrc>; returns 3, or 0 without writing when resp_max < 3. */
size_t  udsota_nrc(uint8_t *resp, size_t resp_max, uint8_t sid, uint8_t nrc);
/* Finishes a handler whose op may have queued worker work. rc == UDSOTA_PENDING starts the wait
 * (poll sends 0x78 from 4/5 of the session's P2, answers 0x72 at 90 s, 0x10 for an app job, and calls done
 * once the service's poll, or routine_poll for an app job, reports a result) and returns 0; any other rc calls
 * done(rc) now and returns its answer. arg is stored for done (udsota_job_arg).
 * suppress_pos drops a positive final answer unless a 0x78 went out first. */
size_t  udsota_job_start(udsota_server_t *s, uint8_t sid, bool suppress_pos, int rc, udsota_job_done_fn done,
                         uint32_t arg, uint8_t *resp, size_t resp_max, uint32_t now_ms);
/* Asks hooks.gate about op: 0 = allow (also when no gate is registered), else the NRC to send. */
uint8_t udsota_gate(const udsota_server_t *s, udsota_op_t op);
bool    udsota_worker_busy(const udsota_server_t *s);         /* core job/orphan flags, then svc->poll */
uint8_t udsota_restart_nrc(const udsota_server_t *s, udsota_op_t op);   /* worker idle, then gate */
void    udsota_end_session_now(udsota_server_t *s);           /* immediate enter_session(DEFAULT); no syncs */
bool    udsota_restart_arm(udsota_server_t *s, udsota_restart_t why, uint32_t now_ms);   /* false without hooks.reset */

static inline udsota_svc_access_t udsota_access_check(const udsota_server_t *s, uint8_t level)
{ return (udsota_svc_access_t){ .session = s->session, .unlocked = !s->secured || s->security == level }; }
static inline bool udsota_activating(const udsota_server_t *s) { return s->activating; }
static inline bool udsota_job_waiting_on(const udsota_server_t *s, udsota_job_done_fn f)
{ return s->job_running && s->job_done == f; }
static inline uint32_t udsota_job_arg(const udsota_server_t *s) { return s->job_arg; }
static inline udsota_counters_t *udsota_counters(udsota_server_t *s) { return &s->counters; }
