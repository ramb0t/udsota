/* udsota server API: the engine, security, hooks and config the integrator passes to udsota_init, the
 * server context and its entry points, over the wire contract in udsota_wire.h. Pure C: shared by the
 * host tests and the firmware. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_wire.h"

/* ---- Server-internal timing and limits (not on the wire) ---- */
#define UDSOTA_JOB_CAP_MS         90000u    /* 0x78 stops here: NRC 0x72 and the session ends (twice the worst-case erase) */
#define UDSOTA_JOB_POLL_MS        5u        /* udsota_poll period while a worker job runs */
#define UDSOTA_IDLE_POLL_MS       100u      /* longest poll gap in a non-default session (S3) */
#define UDSOTA_READ_DID_MAX       1u        /* DIDs per 0x22 request; more is NRC 0x13 (ISO 14229-1 0x22 NRC table) */
#define UDSOTA_RESET_TX_WAIT_MS   100u      /* ActivateImage and 11 01: restart once tx_pending()==0, or after this long */

#define UDSOTA_SLOT_SIZE_DEFAULT  0x400000u  /* bytes a 34 may announce while engine.slot_size is 0 */

/* An engine op that queued work on the flash worker returns UDSOTA_PENDING instead of a result; the server
 * then waits on engine.poll. INT32_MAX: never an esp_err_t, never 0. */
#define UDSOTA_PENDING  0x7FFFFFFF

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

typedef struct {   /* required; only unverify, status, running_sha and version may be NULL */
    int    (*check_first)(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why); /* first 36 block, before any erase; 0 = ok */
    int    (*begin)(void *ctx, uint32_t size);                                  /* erase; may return UDSOTA_PENDING */
    int    (*write)(void *ctx, uint32_t off, const uint8_t *d, size_t n);       /* may return UDSOTA_PENDING */
    int    (*verify)(void *ctx);            /* FF01; result 0 or a udsota_reason_t; may return UDSOTA_PENDING */
    int    (*activate)(void *ctx);          /* set the boot slot; the restart follows via hooks.reset */
    int    (*confirm)(void *ctx);           /* no-op returning 0 when the platform has no rollback */
    void   (*abort)(void *ctx);             /* never blocks: queue it if a worker is busy */
    void   (*unverify)(void *ctx);          /* nullable: every accepted 34 calls it */
    int    (*poll)(void *ctx);              /* UDSOTA_PENDING while any worker job is queued or running, else the last result */
    void   (*status)(void *ctx, udsota_status_t *out);                       /* 0xF1F0; nullable:
                                                                                 then the core skips its slot conditions */
    size_t (*running_sha)(void *ctx, uint8_t *out, size_t max);              /* nullable: 0xF1F3 */
    size_t (*version)(void *ctx, char *out, size_t max);                     /* nullable: F189 */
    uint32_t slot_size;                     /* bytes a 34 may announce; 0 = UDSOTA_SLOT_SIZE_DEFAULT (0x400000) */
    void  *ctx;
} udsota_engine_t;

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
                                 udsota_end_session (at once or latched), the 90 s cap, the restart, a refused 36
                                 and a withheld FC point. A value an app saved in one session never matches in a
                                 later one. udsota_init restarts it at 0, so an app must not keep staged state
                                 across a re-init */
} udsota_access_t;

typedef struct {   /* all optional */
    uint8_t  (*gate)(void *ctx, udsota_op_t op);   /* 0 = allow, else the NRC to send (0x22, 0x88, 0x21, ...) */
    void     (*phase)(void *ctx, udsota_phase_t p);/* on every change, from the server's context; it may read
                                                      udsota_phase() but must not call other udsota functions */
    size_t   (*did_read)(void *ctx, uint16_t did, uint8_t *buf, size_t max);  /* 0 = no such DID (0x31) */
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
                                                      after the RID and out the room after 71 01 <rid>. NULL: 0x31,
                                                      as for any RID nobody serves. Returns 0 (71 01 <rid> out), an NRC
                                                      (1..0xFF), or UDSOTA_PENDING (0x78 until routine_poll stops
                                                      returning pending; 0x72 at the 90 s cap, and the routine is
                                                      then an orphan until routine_poll finishes it). Any other
                                                      value, or *out_len > out_max, is 0x10. While an orphan runs, a
                                                      31 01 for an app RID is 0x22 without a call. It may read
                                                      udsota_phase() but must not call other udsota functions */
    int      (*routine_poll)(void *ctx, uint8_t *out, size_t out_max, size_t *out_len);
                                                   /* on every udsota_poll while an app routine is pending or
                                                      orphaned; returns as routine does. NULL: a routine that
                                                      returns UDSOTA_PENDING ends in 0x10 at the first poll. It may
                                                      read udsota_phase() but must not call other udsota functions */
} udsota_hooks_t;

typedef struct {
    uint16_t    req_id, resp_id;       /* ISO-TP adapter; the server ignores them */
    uint16_t    func_id;               /* the port: functional request ID (OBD's is 0x7DF), whose single frames go to
                                          udsota_isotp_on_func_frame(); 0 = no functional addressing */
    uint16_t    p2_ms, p2star_ms, s3_ms;   /* 0 = 50 / 5000 / 5000 */
    uint16_t    p2_prog_ms, p2star_prog_ms;   /* P2 and P2* in the programming session; 0 = p2_ms and p2star_ms */
    uint16_t    max_block_len;         /* 34's maxNumberOfBlockLength and the 36 length limit; 0 = 4095, and more is
                                          clamped to 4095 (UDSOTA_DL_MAX_BLOCK_LEN, as the ISO-TP adapter). With
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
    /* The server never reads the fields below except device_id and device_id_len: it takes security from udsota_init's security
     * argument and leaves the image rules to engine.check_first. The ESP32 port reads them: key_* for its
     * udsota_security_t, product, hw_id and layout_id for the udsota_image_check rules its engine runs. */
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
} udsota_config_t;

struct udsota_server;
/* Builds the final answer of a worker job from its result (0 = ok); returns the response length, 0 for none. */
typedef size_t (*udsota_job_done_fn)(struct udsota_server *s, int result, uint8_t *resp, size_t resp_max, uint32_t now_ms);

/* ---- Server context. One owner (the transport's task) calls every function below on it. ---- */
typedef struct udsota_server {
    /* What udsota_init() was given: copies, with every 0 in cfg resolved to its default (cfg's pointers stay the caller's). */
    udsota_config_t   cfg;
    udsota_engine_t   engine;
    udsota_security_t sec;               /* used only when secured */
    bool              secured;           /* init got a security struct: 0x27 served and keys required */
    udsota_hooks_t    hooks;             /* all NULL when init got NULL */
    uint32_t        (*tx_pending)(void *ctx);   /* udsota_set_tx_pending(); NULL = a restart waits the full 100 ms */
    void             *tx_pending_ctx;
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
    uint32_t          job_arg;           /* handler data for job_done, e.g. the BSC to echo */
    udsota_job_done_fn job_done;         /* builds the final answer when the job's poll (engine.poll, or
                                            hooks.routine_poll for an app routine) reports a result */
    bool              worker_orphan;     /* a job the server stopped waiting on at the 90 s cap still runs */
    bool              job_app;           /* the running job is an app routine: polled through hooks.routine_poll,
                                            never engine.poll */
    bool              app_orphan;        /* an app routine the server stopped waiting on at the 90 s cap still
                                            runs; only hooks.routine_poll clears it */
    size_t            job_out_len;       /* app routine: bytes of its out record, written at resp[4] */
    bool              end_pending;       /* udsota_end_session arrived during a job: applied once the job has answered */
    /* Download. */
    bool              download_active;   /* between an accepted 0x34 and 0x37 or an abort */
    bool              ota_open;          /* the engine holds an open image: from the first 0x36's begin to FF01 or an abort */
    uint8_t           next_bsc;          /* expected blockSequenceCounter (1 after 0x34, wraps 0xFF->0x00) */
    uint32_t          dl_announced;      /* memorySize from 0x34 */
    uint32_t          dl_received;       /* data bytes accepted; the offset engine.write gets */
    bool              slot_verified;     /* FF01 passed since the last download or reboot; survives session changes */
    bool              dl_complete;       /* 0x37 accepted: FF01 may verify the open image */
    uint32_t          cf_median_us;      /* 64-CF median from the last FC point (UDSOTA_CF_MEDIAN_NONE before one) */
    uint32_t          cf_stmin_us;       /* the STmin that FC point judged it against */
    udsota_result_t   last_dl;           /* F1F1, answered by the server itself */
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

/* Resets s to the default session, locked and idle, and copies cfg (NULL = every default), engine (required),
 * security (NULL = none: 0x27 answers 0x11 and nothing needs a key) and hooks (NULL = none). Silent: no phase call.
 * Returns false for a security with no rng16, or with neither key nor verify; s is still initialised, with
 * security on and every requestSeed (no rng16) or sendKey (no key or verify) answered 0x22, so nothing unlocks.
 * Every now_ms below is milliseconds since boot (wrapping at 2^32): the post-boot 0x27 delay is measured from
 * now_ms 0, so a clock that starts elsewhere shortens or skips it. */
bool   udsota_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_engine_t *engine,
                   const udsota_security_t *security, const udsota_hooks_t *hooks);
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
 * any other. Only 10 01, 10 03, 3E, 22, 28 and 85 are served that way; anything else, and anything while a job
 * runs (3E aside), gets no answer. NRCs 0x11, 0x12, 0x31, 0x7E and 0x7F are suppressed, as ISO 14229-1 asks for
 * functional requests, and the suppress bit applies as usual. Returns the response length (0 = none). */
size_t udsota_on_functional_request(udsota_server_t *s, const uint8_t *req, size_t len, uint8_t *resp, size_t max,
                                    uint32_t now_ms);
/* Advances S3, the 0x78 cadence, job completion and an armed restart; returns a response length to send, or 0. */
size_t udsota_poll(udsota_server_t *s, uint8_t *resp, size_t max, uint32_t now_ms);
/* Milliseconds until udsota_poll next has work (0 = now); UDSOTA_JOB_POLL_MS while a job runs or a restart is
 * armed; UINT32_MAX when idle in the default session or once the restart has fired. */
uint32_t udsota_ms_to_deadline(const udsota_server_t *s, uint32_t now_ms);
/* A First Frame arrived on the request ID: S3 stops until that request is answered or abandoned. */
void   udsota_on_rx_first_frame(udsota_server_t *s, uint32_t now_ms);
/* A multi-frame request was abandoned (N_Cr or receive error): counts it and restarts S3. */
void   udsota_on_rx_timeout(udsota_server_t *s, uint32_t now_ms);
/* True while ActivateImage or 11 01 has armed the restart and waits for its answer to leave. */
bool   udsota_restart_armed(const udsota_server_t *s);
/* FC-point check during a download: applies a latched udsota_end_session, else records the CF timing, applies the
 * STmin monitor and asks gate(CONTINUE_TRANSFER). False = withhold the FC; the download and the session have ended
 * and F1F2 counts it. */
bool   udsota_fc_check(udsota_server_t *s, uint32_t median_cf_us, uint32_t stmin_us, uint32_t now_ms);
/* True between an accepted 34 and 37 or an abort (the transport's receive-limit switch). */
bool   udsota_download_active(const udsota_server_t *s);
