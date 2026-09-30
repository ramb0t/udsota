/* The UDS server's API: the security, hooks and config the integrator passes to udsota_core_init (or udsota_init,
 * udsota_update.h), the server context and its entry points, over the wire contract in udsota_server_wire.h. Pure C:
 * shared by the host tests and the firmware. A service such as the firmware updater builds on udsota_service.h. */
#pragma once
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_server_wire.h"
#include "udsota_update_state.h"   /* udsota_update_t and udsota_progress_t, which the context names */

/* ---- Server-internal timing and limits (not on the wire) ---- */
#define UDSOTA_JOB_CAP_MS         90000u    /* 0x78 stops here: NRC 0x72 (0x10 for an app job) and the session
                                                ends (twice the worst-case erase) */
#define UDSOTA_JOB_POLL_MS        5u        /* udsota_poll period while a worker job runs */
#define UDSOTA_IDLE_POLL_MS       100u      /* longest poll gap in a non-default session (S3) */
#define UDSOTA_READ_DID_MAX       1u        /* DIDs per 0x22 request; more is NRC 0x13 (ISO 14229-1 0x22 NRC table) */
#define UDSOTA_RESET_TX_WAIT_MS   100u      /* ActivateImage and 11 01: restart once tx_pending()==0, or after this long */
#define UDSOTA_DTC_INDEX_MAX      0xFFFFu   /* hooks.dtc_get is asked for i below this only: 19 01 counts in a u16 */

/* A handler of the registered service (udsota_service.h) whose work is still queued passes UDSOTA_PENDING to
 * udsota_job_start instead of a result; the server then waits on the service's poll (the updater's: engine.poll).
 * hooks.routine, routine_ex, request and routine_poll return it too, for an app job still running; the server then
 * waits on routine_poll. INT32_MAX: never an esp_err_t, never 0. */
#define UDSOTA_PENDING  0x7FFFFFFF
_Static_assert(INT_MAX >= UDSOTA_PENDING, "UDSOTA_PENDING is returned through int");
/* hooks.request returns UDSOTA_NO_ANSWER to send nothing: its way to honour SPRMIB on a positive answer to a service
 * of its own with a sub-function, since the core can't tell which SIDs have one. Only for that, and only from
 * request: from routine, routine_ex or routine_poll it is a hook fault (0x10). INT32_MAX - 1: never UDSOTA_PENDING, an
 * NRC or 0. */
#define UDSOTA_NO_ANSWER  0x7FFFFFFE
_Static_assert(INT_MAX >= UDSOTA_NO_ANSWER && UDSOTA_NO_ANSWER != UDSOTA_PENDING && UDSOTA_NO_ANSWER > 0xFF,
               "UDSOTA_NO_ANSWER is returned through int, apart from UDSOTA_PENDING and every NRC");

#define UDSOTA_STMIN_DEFAULT_US    2000u      /* the transport's FC STmin while cfg.stmin_us is 0 */
#define UDSOTA_BLOCK_SIZE_DEFAULT  64u        /* the transport's FC BS while cfg.block_size is 0 */

typedef enum {
    UDSOTA_OP_ENTER_EXTENDED = 1,   /* 10 03 */
    UDSOTA_OP_ENTER_PROGRAMMING,    /* 10 02 */
    UDSOTA_OP_START_DOWNLOAD,       /* 34 */
    UDSOTA_OP_CONTINUE_TRANSFER,    /* every 36 and every ISO-TP FC point of a 36 */
    UDSOTA_OP_ACTIVATE,             /* 31 01 ActivateImage (0xF001) */
    UDSOTA_OP_RESET,                /* 11 01 */
    UDSOTA_OP_CONFIRM,              /* 31 01 ConfirmImage (0xF002) */
} udsota_op_t;

typedef enum {
    UDSOTA_PHASE_IDLE = 0,          /* default session */
    UDSOTA_PHASE_EXTENDED,
    UDSOTA_PHASE_PROGRAMMING,       /* programming session, no transfer open */
    UDSOTA_PHASE_TRANSFERRING,      /* from an accepted 34 until 37, an abort or a session change */
    UDSOTA_PHASE_ACTIVATING,        /* from a positive ActivateImage answer until the restart */
} udsota_phase_t;

typedef struct {   /* udsota_init() with security == NULL: 27 answers 0x11, and nothing needs a key */
    bool  (*rng16)(void *ctx, uint8_t out[16]);
    bool  (*key)(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16]);  /* false = no key available now (0x22; not an attempt);
                                                                                          unused (may be NULL) when verify is set */
    void  *ctx;
    /* Optional verifier, for a key the server cannot compute (the ECDSA mode: a signature over the seed, udsota_keys.h).
     * When set, the server asks it instead of calling key and comparing: 1 = the key is right, -1 = no verdict
     * now (0x22; not an attempt), anything else = wrong. Counting, lockout, single use and expiry are the same. */
    int   (*verify)(void *ctx, const uint8_t seed[16], uint8_t level, const uint8_t *key, size_t key_len);
    uint16_t key_len;   /* with verify set, the exact key length a sendKey carries (0 = 16; at most 254, the ISO-TP
                           receive limit outside a download less 27 xx, and at most cfg.max_block_len - 2, which caps
                           that limit; a longer key can never arrive, so no key unlocks); ignored without verify,
                           whose key is 16 bytes */
} udsota_security_t;

/* The session state the server passes to an app hook that serves a service on its behalf. */
typedef struct {
    uint8_t  session;         /* UDSOTA_SESSION_* now in force */
    uint8_t  unlocked_level;  /* the requestSeed level unlocked in this session; 0 = none (always 0 without security) */
    uint32_t epoch;           /* +1 on every session entry, whatever causes it: 10 0x including a repeat, S3,
                                 udsota_end_session (at once or latched), the 90 s cap, the restart, a 36 the gate
                                 or the STmin monitor refuses with anything but 0x21, and a withheld FC point. A
                                 value an app saved in one session never matches in a later one. udsota_init
                                 restarts it at 0, so an app must not keep staged state across a re-init */
} udsota_access_t;

/* One DTC as hooks.dtc_get reports it. */
typedef struct {
    uint32_t dtc;      /* the 3-byte DTC in the low 24 bits, the top byte ignored: for DTCFormatIdentifier 0x00 the
                          2-byte SAE J2012 code and the failure-type byte, so U0073 with FTB 00 is 0xC07300 */
    uint8_t  status;   /* its ISO 14229-1 statusOfDTC now; the core sends status & cfg.dtc_availability_mask */
} udsota_dtc_t;

typedef struct {   /* all optional */
    uint8_t  (*gate)(void *ctx, udsota_op_t op);   /* 0 = allow, else the NRC to send (0x22, 0x88, 0x21, ...) */
    void     (*phase)(void *ctx, udsota_phase_t p);/* on every change, from the server's context; it may read
                                                      udsota_phase() but must not call other udsota functions */
    size_t   (*did_read)(void *ctx, uint16_t did, uint8_t *buf, size_t max);  /* 0 = no such DID (0x31); a DID
                                                      longer than max returns its length, unwritten (0x14). Never
                                                      called while did_read_ex is set */
    uint32_t (*stmin_us)(void *ctx);               /* STmin for the next message's first FC; NULL = cfg.stmin_us */
    bool     (*reset)(void *ctx);                  /* restart; returns only on failure (false), then the server re-opens.
                                                      NULL: 11 01 answers 0x11 and ActivateImage answers positive
                                                      without a restart (the new image boots on the next power cycle) */
    uint8_t  (*comm_control)(void *ctx, uint8_t control, uint8_t comm_type);
                                                   /* 28 <control 00-03> <comm_type>: 0 = done, else the NRC. Called
                                                      again with 00 and UDSOTA_CC_TYPE_ALL when the session returns to
                                                      default after a change. NULL: 28 answers 0x11 */
    void     (*dtc_setting)(void *ctx, bool on);   /* after an accepted 85 01 / 85 02, and with true when the session
                                                      returns to default after 85 02. NULL: 85 answers 0x11, as
                                                      before */
    void     *ctx;
    /* Callbacks added after ctx, so every earlier field keeps its offset. */
    uint8_t  (*did_write)(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access);
                                                   /* 0x2E. NULL: 2E answers 0x11 in every session. Core: 0x7F in the
                                                      default session, then 0x13 when the request is under 4 bytes;
                                                      else data/len are the bytes after the DID (len >= 1, valid only
                                                      during the call) and the hook returns 0 to answer 6E <did>, or
                                                      the NRC to send. It answers at once: never 0x78. It may read
                                                      udsota_phase() but must not call other udsota functions */
    int      (*routine)(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access);
                                                   /* 31 01 for a RID the core doesn't own; in is the option record
                                                      after the RID and out the room after 71 01 <rid>, both valid
                                                      only during the call (a pending routine copies what it needs).
                                                      NULL: 0x31, as for any RID nobody serves. Returns 0 (71 01 <rid>
                                                      out), an NRC (1..0xFF, never 0x78), or UDSOTA_PENDING (0x78
                                                      until routine_poll stops returning pending; 0x10 at the 90 s
                                                      cap, and the routine is then an orphan until routine_poll
                                                      finishes it). Any other value, or *out_len > out_max, is 0x10.
                                                      While an orphan runs, a 31 01 for an app RID is 0x22 without a
                                                      call. It may read udsota_phase() but must not call other udsota
                                                      functions. Never called while routine_ex is set */
    int      (*routine_poll)(void *ctx, uint8_t *out, size_t out_max, size_t *out_len);
                                                   /* the app job's poll: on every udsota_poll while an app routine or
                                                      request is pending or orphaned (one at a time); returns as the
                                                      hook that started it does, UDSOTA_NO_ANSWER aside (0x10), and
                                                      out, the room after the header the core framed for that hook (71
                                                      <sub> <rid>, or a request's response SID), is again valid only
                                                      during the call. NULL: an app job that returns UDSOTA_PENDING
                                                      ends in 0x10 at the first poll. It may read udsota_phase() but
                                                      must not call other udsota functions */
    void     (*progress)(void *ctx, const udsota_progress_t *p);
                                                   /* at the end of a request, poll or other server call that changed
                                                      the stage or last_reason, or wrote a block (about once a second at
                                                      4 KB blocks), and at most once per call; p is valid only during
                                                      the call. It
                                                      must not call udsota functions or block. NULL: nothing changes,
                                                      and udsota_progress() still reads the same values */
    bool     (*dtc_get)(void *ctx, size_t i, udsota_dtc_t *out);
                                                   /* 0x19: the i-th supported DTC and its status now; false past the
                                                      last. i names the same DTC for as long as the server runs, and
                                                      only its status may change. Asked from 0 up for each 19 01, 02,
                                                      0A and 06 that passes the core's own checks first, never for i
                                                      at UDSOTA_DTC_INDEX_MAX or past it. The walk ends at false, at
                                                      the DTC a 19 06 asks for, or at the first DTC that would
                                                      overflow a 19 02 or 0A (0x14), so a hook must not rely on being
                                                      asked until false. A DTC reported at two indexes is counted and
                                                      listed twice, and 19 06 answers with the first one's status.
                                                      NULL: 19 answers 0x11, as before. It answers at once, may read
                                                      udsota_phase() but must not call other udsota functions */
    uint8_t  (*dtc_ext_data)(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len);
                                                   /* 19 06, for a DTC dtc_get reports (the core answers 0x31 for any
                                                      other, and for record 00, without a call); dtc is the request's
                                                      24 bits, top byte 0, whatever top byte dtc_get gave it; record
                                                      01-FE, or FF for every one. Writes <record> <data>... into buf,
                                                      at most max bytes (the room after 59 06 <DTC> <status>, possibly
                                                      0; buf is valid only during the call), sets *len and returns 0;
                                                      *len 0 is a record held with no data. Else returns the NRC: 0x31
                                                      no such record, 0x14 the records don't fit max; never 0x78. A
                                                      *len over max is 0x10. NULL: 19 06 answers 0x12. Called as
                                                      dtc_get */
    uint8_t  (*dtc_clear)(void *ctx, uint32_t group, udsota_access_t access);
                                                   /* 0x14 with exactly a 3-byte groupOfDTC (else 0x13 without a
                                                      call), physical only, in any session; group in the low 24 bits
                                                      (UDSOTA_DTC_GROUP_ALL is every DTC). Returns 0 to answer 54, or
                                                      the NRC, checked in ISO order: its session rule (0x7F), then its
                                                      key rule (0x33), then 0x31 for a group it doesn't clear; never
                                                      0x78. NULL: 14 answers 0x11, as before. Called as dtc_get */
    uint8_t  (*did_read_ex)(void *ctx, uint16_t did, uint8_t *buf, size_t max, size_t *len, udsota_access_t access);
                                                   /* did_read with the session's access, for the same DIDs (every one
                                                      the core doesn't serve and the service passes); when set,
                                                      did_read is never called. Writes the DID's bytes into buf, at
                                                      most max (the room after 62 <did>; buf is valid only during the
                                                      call), sets *len and returns 0; a *len of 0 or over max is 0x10.
                                                      Else returns the NRC, never 0x78: 0x31 no such DID, 0x7F not in
                                                      this session, 0x33 locked, 0x22, 0x14 too long for max, ... A
                                                      functional 22 drops 0x31 and 0x7F as any other NRC suppressed
                                                      there. NULL: did_read, as before. Called as dtc_get */
    int      (*routine_ex)(void *ctx, uint8_t sub, uint16_t rid, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access);
                                                   /* routine with the sub-function, in every session: when set, a 31
                                                      of at least 4 bytes (else 0x13) on a RID the service doesn't own
                                                      comes here with sub 01 startRoutine, 02 stopRoutine or 03
                                                      requestRoutineResults (SPRMIB cleared; any other sub is 0x12
                                                      without a call), even in the default session, so the app owns
                                                      the session rule as did_write does; the service's RIDs answer as
                                                      without it, and routine is never called. Returns as routine
                                                      does, and the answer is 71 <sub> <rid> out, from routine_poll
                                                      too. NULL: routine, as before */
    int      (*request)(void *ctx, const uint8_t *req, size_t len, uint8_t *out, size_t out_max, size_t *out_len,
                        udsota_access_t access);
                                                   /* the app's own services: a physical request whose SID neither the
                                                      core nor the service serves (so with the updater never 34, 36 or
                                                      37, without it those too), where 0x11 was sent, never while a
                                                      job runs (0x21 first). A response SID (40-7F, C0-FF) is 0x11,
                                                      and 0x22 while an app orphan runs, both without a call; a
                                                      functional request never comes here. req is the whole request,
                                                      SID included (len >= 1), and length, session, sub-function and
                                                      key are the app's to check. The core writes the response SID
                                                      (req[0] + 0x40) at resp[0] and out is the room after it; req,
                                                      out and access are valid only during the call, so a pending
                                                      request copies what it needs. Returns 0 to answer the response
                                                      SID and *out_len bytes of out (0 is valid; over out_max is
                                                      0x10), an NRC (1..0xFF, never 0x78; sent whatever SPRMIB says),
                                                      UDSOTA_NO_ANSWER for nothing (only for a positive answer with
                                                      SPRMIB set), or UDSOTA_PENDING, an app job as a routine's (0x78,
                                                      0x21, 0x10 at the 90 s cap, finished by routine_poll), whose
                                                      final answer is always sent. Any other value is 0x10. NULL, or
                                                      no room for the response SID: 0x11, as before. It may read
                                                      udsota_phase() but must not call other udsota functions */
} udsota_hooks_t;

typedef struct {
    uint16_t    req_id, resp_id;       /* ISO-TP adapter, 11-bit CAN IDs only; the server ignores them */
    uint16_t    func_id;               /* the port: functional request ID (OBD's is 0x7DF; 11-bit CAN IDs only), whose
                                          single frames go to udsota_isotp_on_func_frame(); 0 = no functional
                                          addressing */
    uint16_t    p2_ms, p2star_ms, s3_ms;   /* 0 = 50 / 5000 / 5000 */
    uint16_t    p2_prog_ms, p2star_prog_ms;   /* P2 and P2* in the programming session; 0 = p2_ms and p2star_ms */
    uint16_t    max_block_len;         /* 34's maxNumberOfBlockLength and the 36 length limit; 0 = 4095, and more is
                                          clamped to 4095 (UDSOTA_DL_MAX_BLOCK_LEN), and by the ISO-TP adapter to
                                          its receive buffer (UDSOTA_ISOTP_RX_MAX, 4095 by default). With
                                          udsota_image_check behind check_first, at least 322: the first block
                                          holds 36 <bsc> and UDSOTA_IMAGE_MIN_LEN (320) image bytes */
    uint32_t    stmin_us;              /* default FC STmin; 0 = 2000 */
    uint8_t     block_size;            /* FC BS; 0 = 64 */
    uint16_t    fc_retry_ms;           /* ISO-TP adapter: how long an FC the bus refuses is retried, 1 ms apart,
                                          before it is dropped; 0 = 10. Cover two token intervals of the app's
                                          response rate cap, e.g. ceil(2000 / rate) */
    bool        stmin_monitor;         /* refuse CONTINUE_TRANSFER when the median CF gap < 0.8 x STmin */
    uint8_t     level_extended;        /* 27 requestSeed sub-function unlocking 11 01; 0 = 0x01 */
    uint8_t     level_programming;     /* unlocks 34/36/37, FF01, ActivateImage and 11 01; 0 = 0x03 */
                                       /* both levels: odd requestSeed values 0x01..0x7D (sendKey is level + 1), distinct */
    /* The server never reads the fields below except device_id, device_id_len and the dtc_ fields: it takes security
     * from udsota_init's security argument and leaves the image rules to engine.check_first. The ESP32 port reads
     * them: key_* for its udsota_security_t, product, hw_id and layout_id for the udsota_image_check rules its engine
     * runs. */
    const char *key_label;             /* port: security on; K_dev = HMAC(master, label || device_id) */
    const uint8_t *key_master;         /* port: with key_label set and this NULL, security is on and no key matches */
    size_t      key_master_len;        /* port */
    const uint8_t *device_id;          /* the core serves it as F18C; the ESP32 port hashes the same bytes into the
                                          0x27 key and takes 1 to 16 of them, or the base MAC when NULL */
    size_t      device_id_len;
    const char *product;               /* port: image identity, esp_app_desc project name; NULL = not checked */
    uint8_t     hw_id, layout_id;      /* port: descriptor values the image must carry */
    const uint8_t *key_pubkey;         /* port: security on in the ECDSA mode (udsota_keys.h): the tester's P-256 public
                                          key, an uncompressed SEC1 point (04 || X || Y). It wins over key_label and
                                          key_master. udsota_esp32_start() refuses a malformed one (ESP_ERR_INVALID_ARG);
                                          one PSA refuses leaves security on with no key that matches */
    size_t      key_pubkey_len;        /* port: UDSOTA_KEYS_PUBKEY_LEN (65) */
    /* Fields added after key_pubkey_len, so every earlier field keeps its offset. */
    uint8_t     dtc_availability_mask; /* 19's DTCStatusAvailabilityMask, the status bits the app supports: every
                                          status sent is ANDed with it, and a DTC matches a status mask when status &
                                          mask & this is non-zero; 0 = 0xFF (cfg_resolve) */
    uint8_t     dtc_format;            /* 59 01's DTCFormatIdentifier, sent as given: 0x00 SAE J2012-DA format 00
                                          (OBD codes such as U0073 with a failure-type byte), 0x01 ISO 14229-1 */
} udsota_config_t;

struct udsota_server;
struct udsota_service;                   /* udsota_service.h */
/* Builds the final answer of a worker job from its result (0 = ok); returns the response length, 0 for none. */
typedef size_t (*udsota_job_done_fn)(struct udsota_server *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms);

/* ---- Server context. One owner (the transport's task) calls every function below on it. ---- */
typedef struct udsota_server {
    /* What udsota_init() was given: copies, with every 0 in cfg resolved to its default (cfg's pointers stay the caller's). */
    udsota_config_t   cfg;
    udsota_security_t sec;               /* used only when secured */
    bool              secured;           /* init got a security struct: 0x27 served and keys required */
    udsota_hooks_t    hooks;             /* all NULL when init got NULL */
    uint32_t        (*tx_pending)(void *ctx);   /* udsota_set_tx_pending(); NULL = a restart waits the full 100 ms */
    void             *tx_pending_ctx;
    const struct udsota_service *svc;    /* udsota_register_service(); NULL = no service, the core alone */
    /* Session, phase and S3. */
    uint8_t           session;           /* udsota_session_t */
    uint8_t           security;          /* 0 locked, else the unlocked requestSeed level */
    uint8_t           phase;             /* udsota_phase_t last reported to hooks.phase */
    bool              activating;        /* ActivateImage answered positive and a restart follows */
    bool              s3_running;        /* false in default, during a request and during a job */
    bool              comm_changed;      /* hooks.comm_control accepted a 28 other than 00 03 in this session */
    bool              dtc_off;           /* an 85 02 was accepted in this session */
    uint32_t          s3_start_ms;       /* S3 restarts when a request is answered */
    uint32_t          session_epoch;     /* udsota_access_t.epoch: 0 after init, +1 on every session entry */
    /* The worker-job wait. */
    bool              job_running;       /* a worker job owns the pending response */
    bool              job_pending_sent;  /* at least one 0x78 has gone out for this job */
    bool              job_suppress_pos;  /* the job's request had SPRMIB set */
    uint8_t           job_sid;           /* SID being answered with 0x78 */
    uint32_t          job_start_ms;      /* for the first 0x78 and the 90 s cap */
    uint32_t          last_pending_ms;   /* last 0x78 sent */
    uint32_t          job_arg;           /* handler data for job_done, e.g. a 36's block length, or an app routine's
                                            RID with its sub-function in bits 16-23 */
    udsota_job_done_fn job_done;         /* builds the final answer when the job's poll (the service's, or
                                            hooks.routine_poll for an app job) reports a result */
    bool              worker_orphan;     /* a service's job the server stopped waiting on at the 90 s cap still runs;
                                            only the service's poll clears it */
    bool              job_app;           /* the running job is the app's, a routine or a request: polled through
                                            hooks.routine_poll, never the service's poll */
    bool              app_orphan;        /* an app job the server stopped waiting on at the 90 s cap still runs;
                                            only hooks.routine_poll clears it */
    uint8_t           app_hdr;           /* the header the core frames before the app job's out record: 4 for
                                            71 <sub> <rid>, 1 for a request's response SID; kept for an orphan */
    size_t            job_out_len;       /* app job: bytes of its out record, written at resp[app_hdr] */
    bool              end_pending;       /* udsota_end_session arrived during a job: applied once the job has answered */
    udsota_update_t   update;            /* the firmware updater's state (udsota_update_state.h), engine included */
    udsota_counters_t counters;          /* F1F2, answered by the server itself; the transport bumps its counters here */
    /* SecurityAccess. RAM only: a reset re-arms the boot delay instead. */
    bool              sa_seed_valid;
    uint8_t           sa_seed_level;
    uint8_t           sa_seed[UDSOTA_SEED_LEN];
    uint32_t          sa_seed_ms;
    uint8_t           sa_failed;
    bool              sa_delay_active;
    uint32_t          sa_delay_start_ms;
    /* Respond-then-restart. */
    uint8_t           reset_phase;       /* 0 idle, 1 armed (the answer is leaving), 2 fired */
    uint32_t          reset_armed_ms;
} udsota_server_t;

/* udsota_init without the updater: resets s to the default session, locked and idle, and copies cfg (NULL = every
 * default), security (NULL = none: 0x27 answers 0x11 and nothing needs a key) and hooks (NULL = none). Silent: no
 * phase call. Returns false for a security with no rng16, or with neither key nor verify; s is still initialised,
 * with security on and every requestSeed (no rng16) or sendKey (no key or verify) answered 0x22, so nothing unlocks.
 * A service (udsota_service.h) registers right after it.
 * Every now_ms below is milliseconds since boot (wrapping at 2^32): the post-boot 0x27 delay is measured from
 * now_ms 0, so a clock that starts elsewhere shortens or skips it. */
bool   udsota_core_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_security_t *security,
                        const udsota_hooks_t *hooks);
/* The transport installs its tx_pending source after udsota_init (which clears it); NULL = a restart waits the full
 * UDSOTA_RESET_TX_WAIT_MS (100 ms). */
void   udsota_set_tx_pending(udsota_server_t *s, uint32_t (*tx_pending)(void *ctx), void *ctx);
/* Server context only: aborts any transfer, relocks and returns to the default session. While a worker job runs
 * the end is latched and applied at the first poll, request or download FC point after the job's final answer,
 * which is still sent, so no job is orphaned; a worker orphan does not delay it. Ignored while a restart is armed. */
void   udsota_end_session(udsota_server_t *s, uint32_t now_ms);
/* The phase last reported to hooks.phase (IDLE after init). */
udsota_phase_t udsota_phase(const udsota_server_t *s);
/* Handles one reassembled request; returns the response length written to resp (0 = no response). */
size_t udsota_on_request(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t max, uint32_t now_ms);
/* Handles one functionally addressed request (a single frame on cfg.func_id), answered on the response ID like
 * any other. Only 10 01, 10 03, 3E, 19, 22, 28 and 85 are served that way; anything else, and anything while a job
 * runs (3E aside), gets no answer. NRCs 0x11, 0x12, 0x31, 0x7E and 0x7F are suppressed, as ISO 14229-1 asks for
 * functional requests, and the suppress bit applies as usual. Returns the response length (0 = none). */
size_t udsota_on_functional_request(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t max,
                                    uint32_t now_ms);
/* Advances S3, the 0x78 cadence, job completion and an armed restart; returns a response length to send, or 0. */
size_t udsota_poll(udsota_server_t *s, uint8_t *resp, size_t max, uint32_t now_ms);
/* Milliseconds until udsota_poll next has work (0 = now); UDSOTA_JOB_POLL_MS while a job runs, a worker or app
 * orphan runs (in any session) or a restart is armed; UINT32_MAX when idle in the default session with no orphan,
 * or once the restart has fired. */
uint32_t udsota_ms_to_deadline(const udsota_server_t *s, uint32_t now_ms);
/* A First Frame arrived on the request ID: S3 stops until that request is answered or abandoned. */
void   udsota_on_rx_first_frame(udsota_server_t *s, uint32_t now_ms);
/* A multi-frame request was abandoned (N_Cr or receive error): counts it and restarts S3. */
void   udsota_on_rx_timeout(udsota_server_t *s, uint32_t now_ms);
/* True while ActivateImage or 11 01 has armed the restart and waits for its answer to leave. */
bool   udsota_restart_armed(const udsota_server_t *s);
/* FC-point check while the registered service has a transfer open (udsota_download_active) and no job runs: a
 * latched udsota_end_session withholds the FC, else the service's fc_point decides (the updater records the CF timing,
 * applies the STmin monitor and asks gate(CONTINUE_TRANSFER)). False = withhold the FC; the session has ended (and
 * with it the transfer) and F1F2 counts it. True, counting nothing, with no service or no transfer open. */
bool   udsota_fc_check(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us, uint32_t now_ms);
/* True while the registered service has a transfer open (the updater: between an accepted 34 and 37 or an abort);
 * always false with no service. The transport's receive-limit switch. */
bool   udsota_download_active(const udsota_server_t *s);
