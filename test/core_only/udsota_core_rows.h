/* Groups A to G of the no-updater tests (docs/plans/2026-09-29-seam-tests.md), and I (19 and 14,
 * docs/plans/2026-09-29-dtc-services.md): the server with no service registered, so 34, 36 and 37 answer 0x11, the
 * updater's RIDs and DIDs go to the app's hooks, 10 02 answers 0x12, 11 01 asks only the core's worker rule and the
 * gate, 19 and 14 are served through their hooks, and nothing reaches a service. Two tests include these same rows: the no-engine test
 * (udsota_init with a NULL engine) and the core-only test (udsota_core_init, built without the updater), which proves
 * the two paths answer alike. Core headers only, with its own mock hooks and security, so it compiles without any
 * updater header but udsota_update_state.h.
 *
 * Define CORE_ROWS_INIT(s, cfg, security, hooks) as the init under test before including it; list CORE_ROWS in the
 * test table and run it with core_rows_main. The header defines Unity's setUp and tearDown. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "udsota_server.h"

#ifndef CORE_ROWS_INIT
#error "define CORE_ROWS_INIT(s, cfg, security, hooks) before including udsota_core_rows.h"
#endif

#define T0         60000u   /* past the 10 s post-boot 0x27 delay */
#define NRC_SPEED  0x88u    /* vehicleSpeedTooHigh: an NRC only a gate sends */
#define APP_RID    0x1234u  /* an app routine's RID */
#define APP_BYTE   0x5Au    /* the app routine's one status byte */
#define HI(v)      (uint8_t)((v) >> 8)
#define LO(v)      (uint8_t)((v) & 0xFFu)

/* The updater's RIDs and DIDs as numbers: their names live in udsota_update_wire.h, which a core-only build can't
 * include. The no-engine test checks each against its name. */
#define ROWS_RID_CHECK_PROG_DEPS   0xFF01u
#define ROWS_RID_GET_RESUME_POINT  0xF000u
#define ROWS_RID_ACTIVATE_IMAGE    0xF001u
#define ROWS_RID_CONFIRM_IMAGE     0xF002u
#define ROWS_DID_SW_VERSION        0xF189u
#define ROWS_DID_STATUS            0xF1F0u
#define ROWS_DID_RESULT            0xF1F1u
#define ROWS_DID_RUNNING_SHA       0xF1F3u

/* ---- The mock: a gate that answers per op and counts what it was asked, a phase log, a reset hook, a did_read
 * that counts, and a SecurityAccess with a known key ---- */

#define ROWS_MOCK_OPS      8u    /* udsota_op_t runs 1..7; index 0 is unused */
#define ROWS_MOCK_LOG_MAX  64u

typedef struct {
    uint8_t   gate_nrc[ROWS_MOCK_OPS];     /* what gate(op) answers: 0 allows */
    unsigned  gate_calls[ROWS_MOCK_OPS];   /* times gate(op) was asked */
    int       phases[ROWS_MOCK_LOG_MAX];   /* every phase the hook reported, in order */
    size_t    phase_n;
    bool      reset_ok;                    /* hooks.reset result */
    unsigned  resets;                      /* hooks.reset calls */
    size_t  (*app_did)(uint16_t did, uint8_t *buf, size_t max);   /* the test's own DIDs; NULL = none */
    unsigned  did_reads;                   /* hooks.did_read calls */
    uint16_t  last_did;                    /* DID of the last hooks.did_read call */
} rows_mock_t;

/* Clears m: the gate allows everything, a reset succeeds. */
static inline void rows_mock_clear(rows_mock_t *m)
{
    memset(m, 0, sizeof *m);
    m->reset_ok = true;
}

/* hooks.gate: counts the question and answers gate_nrc[op]; an op outside udsota_op_t gets 0x10 so the test fails. */
static inline uint8_t rows_mock_gate(void *ctx, udsota_op_t op)
{
    rows_mock_t *m = ctx;
    if ((unsigned)op == 0u || (unsigned)op >= ROWS_MOCK_OPS) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    m->gate_calls[op]++;
    return m->gate_nrc[op];
}

/* hooks.phase: appends p to the log. */
static inline void rows_mock_phase(void *ctx, udsota_phase_t p)
{
    rows_mock_t *m = ctx;
    if (m->phase_n < ROWS_MOCK_LOG_MAX) {
        m->phases[m->phase_n++] = (int)p;
    }
}

/* hooks.reset: counts the restart and returns reset_ok (a real restart never returns). */
static inline bool rows_mock_reset(void *ctx)
{
    rows_mock_t *m = ctx;
    m->resets++;
    return m->reset_ok;
}

/* hooks.did_read: counts the call and asks the test's app_did, if any; 0 = no such DID (NRC 0x31). */
static inline size_t rows_mock_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    rows_mock_t *m = ctx;
    m->did_reads++;
    m->last_did = did;
    return m->app_did != NULL ? m->app_did(did, buf, max) : 0u;
}

/* The mock's hooks, with m as ctx: gate, phase, did_read and reset. */
static inline udsota_hooks_t rows_mock_hooks(rows_mock_t *m)
{
    udsota_hooks_t h = {
        .gate = rows_mock_gate, .phase = rows_mock_phase, .did_read = rows_mock_did_read,
        .reset = rows_mock_reset, .ctx = m,
    };
    return h;
}

/* The rows' server config: every timing and level default, the STmin monitor on, device ID 02 00 00 00 00 01 (F18C). */
static inline udsota_config_t rows_mock_cfg(void)
{
    static const uint8_t serial[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    udsota_config_t c;
    memset(&c, 0, sizeof c);
    c.stmin_monitor = true;
    c.device_id = serial;
    c.device_id_len = sizeof serial;
    return c;
}

/* The rows' stand-in for the port's HMAC: key[i] = seed[i] ^ level ^ 0xA5. */
static inline void rows_key_for(const uint8_t *seed, uint8_t level, uint8_t *out)
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5u);
    }
}

/* security.rng16: always 10 11 .. 1F (non-zero, so SecurityAccess accepts it). */
static inline bool rows_rng16(void *ctx, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return true;
}

/* security.key: rows_key_for. */
static inline bool rows_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    rows_key_for(seed, level, out);
    return true;
}

/* The rows' security: rows_rng16 and rows_key, no ctx. */
static inline const udsota_security_t *rows_security(void)
{
    static const udsota_security_t sec = {.rng16 = rows_rng16, .key = rows_key};
    return &sec;
}

/* ---- The server under test and the app behind its hooks ---- */

/* The server states the groups run in. Programming is entered by writing s.session: 10 02 answers 0x12 without the
 * updater (D1), yet the rows still check what the core does in that session. */
typedef enum { ST_DEF, ST_EXT, ST_EXT01, ST_PROG, ST_PROG03, ST_N } state_t;
static const char *const k_state_name[ST_N] = {"default", "extended", "extended+01", "programming", "programming+03"};
static const uint8_t k_state_session[ST_N] = {UDSOTA_SESSION_DEFAULT, UDSOTA_SESSION_EXTENDED,
                                              UDSOTA_SESSION_EXTENDED, UDSOTA_SESSION_PROGRAMMING,
                                              UDSOTA_SESSION_PROGRAMMING};

/* The updater's RIDs and DIDs, which the app serves or not. */
static const uint16_t k_upd_rids[4] = {ROWS_RID_CHECK_PROG_DEPS, ROWS_RID_GET_RESUME_POINT, ROWS_RID_ACTIVATE_IMAGE,
                                       ROWS_RID_CONFIRM_IMAGE};
static const uint16_t k_upd_dids[4] = {ROWS_DID_SW_VERSION, ROWS_DID_STATUS, ROWS_DID_RESULT, ROWS_DID_RUNNING_SHA};

/* The app behind the hooks: none (did_read answers nothing, no routine hook) or serves (AA BB for the updater's DIDs,
 * 71 01 <rid> 5A for any routine). */
typedef struct {
    bool            serves;
    int             routine_rc;        /* what hooks.routine returns: 0, or UDSOTA_PENDING */
    unsigned        routine_calls;
    uint16_t        routine_rid;
    size_t          routine_in_len;
    udsota_access_t routine_access;
    bool            poll_pending;      /* hooks.routine_poll keeps returning UDSOTA_PENDING */
    unsigned        progress_calls;
    unsigned        comm_calls;
    uint8_t         comm_control, comm_type;
    unsigned        dtc_calls;
    bool            dtc_on;
    unsigned        dtc_gets, dtc_exts, dtc_clears;
    uint32_t        clear_group;
    udsota_access_t clear_access;
    uint32_t        tx_pending;        /* what the installed tx_pending returns */
} app_t;

static app_t           app;
static rows_mock_t     g_mock;
static udsota_config_t g_cfg;
static udsota_hooks_t  g_hooks;
static udsota_server_t s;
static uint8_t         resp[64];
static size_t          rlen;
static uint32_t        now;
static char            msg[96];

/* hooks.did_read's app part: AA BB for the updater's four DIDs while the app serves, else nothing. */
static size_t app_did(uint16_t did, uint8_t *buf, size_t max)
{
    if (!app.serves || max < 2u) {
        return 0;
    }
    for (size_t i = 0; i < 4u; i++) {
        if (did == k_upd_dids[i]) {
            buf[0] = 0xAA;
            buf[1] = 0xBB;
            return 2;
        }
    }
    return 0;
}

/* hooks.routine: records the call; answers 5A now, or UDSOTA_PENDING when routine_rc says so. */
static int app_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max,
                       size_t *out_len, udsota_access_t access)
{
    app.routine_calls++;
    app.routine_rid = rid;
    app.routine_in_len = in_len;
    app.routine_access = access;
    if (app.routine_rc == UDSOTA_PENDING) {
        return UDSOTA_PENDING;
    }
    out[0] = APP_BYTE;
    *out_len = 1;
    return 0;
}

/* hooks.routine_poll: pending while poll_pending, then 5A. */
static int app_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    if (app.poll_pending) {
        return UDSOTA_PENDING;
    }
    if (out_max < 1u) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    out[0] = APP_BYTE;
    *out_len = 1;
    return 0;
}

/* hooks.progress: counts; with no updater it must never run. */
static void app_progress(void *ctx, const udsota_progress_t *p) { app.progress_calls++; }

/* hooks.comm_control: records and accepts. */
static uint8_t app_comm(void *ctx, uint8_t control, uint8_t comm_type)
{
    app.comm_calls++;
    app.comm_control = control;
    app.comm_type = comm_type;
    return 0;
}

/* hooks.dtc_setting: records. */
static void app_dtc(void *ctx, bool on)
{
    app.dtc_calls++;
    app.dtc_on = on;
}

/* The app's two DTCs: U0073 (status 2F) and P0562 (status 28). */
static const udsota_dtc_t k_dtcs[2] = {{0xC07300u, 0x2Fu}, {0x056200u, 0x28u}};

/* hooks.dtc_get: k_dtcs. */
static bool app_dtc_get(void *ctx, size_t i, udsota_dtc_t *out)
{
    app.dtc_gets++;
    if (i >= sizeof k_dtcs / sizeof k_dtcs[0]) {
        return false;
    }
    *out = k_dtcs[i];
    return true;
}

/* hooks.dtc_ext_data: record 01 is 01 07 for either DTC, any other 0x31. */
static uint8_t app_dtc_ext(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len)
{
    app.dtc_exts++;
    if (record != 0x01u || max < 2u) {
        return UDSOTA_NRC_REQUEST_OUT_OF_RANGE;
    }
    buf[0] = 0x01;
    buf[1] = 0x07;
    *len = 2u;
    return 0u;
}

/* hooks.dtc_clear: records the group and access and clears. */
static uint8_t app_dtc_clear(void *ctx, uint32_t group, udsota_access_t access)
{
    app.dtc_clears++;
    app.clear_group = group;
    app.clear_access = access;
    return 0u;
}

/* hooks.did_write: accepts. */
static uint8_t app_did_write(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access)
{
    return 0;
}

/* The transport's tx_pending source. */
static uint32_t app_tx_pending(void *ctx) { return app.tx_pending; }

/* Boots a server through CORE_ROWS_INIT with the mock security and every hook (routine only while the app serves). */
static void boot(bool serves)
{
    app.serves = serves;
    g_hooks = rows_mock_hooks(&g_mock);
    g_hooks.comm_control = app_comm;
    g_hooks.dtc_setting = app_dtc;
    g_hooks.did_write = app_did_write;
    g_hooks.routine = serves ? app_routine : NULL;
    g_hooks.routine_poll = app_routine_poll;
    g_hooks.progress = app_progress;
    g_hooks.dtc_get = app_dtc_get;
    g_hooks.dtc_ext_data = app_dtc_ext;
    g_hooks.dtc_clear = app_dtc_clear;
    TEST_ASSERT_TRUE(CORE_ROWS_INIT(&s, &g_cfg, rows_security(), &g_hooks));
    udsota_set_tx_pending(&s, app_tx_pending, NULL);
    now = T0;
}

/* Sends one request at now; the answer lands in resp[0..rlen). */
static void req(const uint8_t *r, size_t n)
{
    rlen = udsota_on_request(&s, r, n, resp, sizeof resp, now);
}

/* One poll at now; the answer lands in resp[0..rlen). */
static void poll_at(uint32_t t)
{
    now = t;
    rlen = udsota_poll(&s, resp, sizeof resp, now);
}

/* Checks resp[0..rlen) is exactly e[0..n). */
static void expect(const uint8_t *e, size_t n)
{
    TEST_ASSERT_EQUAL_size_t_MESSAGE(n, rlen, msg);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(e, resp, n, msg);
}

#define REQ(...)    do { const uint8_t r_[] = {__VA_ARGS__}; req(r_, sizeof r_); } while (0)
#define EXPECT(...) do { const uint8_t e_[] = {__VA_ARGS__}; expect(e_, sizeof e_); } while (0)
#define NRC(sid, n) EXPECT(0x7F, (sid), (n))

/* 27 <level> then the mock's key: the level unlocks. */
static void unlock(uint8_t level)
{
    REQ(0x27, level);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(2u + UDSOTA_SEED_LEN, rlen, msg);
    uint8_t key[2u + UDSOTA_KEY_LEN] = {0x27, (uint8_t)(level + 1u)};
    rows_key_for(&resp[2], level, &key[2]);
    req(key, sizeof key);
    EXPECT(0x67, (uint8_t)(level + 1u));
}

/* Unity hook: fresh mock and app, the rows' config. */
void setUp(void)
{
    memset(&app, 0, sizeof app);
    rows_mock_clear(&g_mock);
    g_mock.app_did = app_did;
    g_cfg = rows_mock_cfg();
    msg[0] = '\0';
}

void tearDown(void) {}

/* Starts afresh (setUp), boots (app none or serves) and brings the server to st. */
static void enter(state_t st, bool serves)
{
    setUp();
    boot(serves);
    snprintf(msg, sizeof msg, "state %s", k_state_name[st]);
    if (st == ST_EXT || st == ST_EXT01) {
        REQ(0x10, 0x03);
        EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
        if (st == ST_EXT01) {
            unlock(UDSOTA_SA_SEED_EXTENDED);
        }
    } else if (st == ST_PROG || st == ST_PROG03) {
        s.session = UDSOTA_SESSION_PROGRAMMING;
        if (st == ST_PROG03) {
            unlock(UDSOTA_SA_SEED_PROGRAMMING);
        }
    }
}

/* Starts app routine 1234 pending in the extended session (app serves). */
static void start_pending_app_routine(void)
{
    app.routine_rc = UDSOTA_PENDING;
    app.poll_pending = true;
    REQ(0x31, 0x01, HI(APP_RID), LO(APP_RID));
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_TRUE(s.job_running);
}

/* Starts app routine 1234 in the extended session and lets it run into the 90 s cap: 7F 31 10, an app orphan. */
static void orphan_app_routine(void)
{
    enter(ST_EXT, true);
    start_pending_app_routine();
    poll_at(now + UDSOTA_JOB_CAP_MS);
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_TRUE(s.app_orphan);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
}

/* 22 F1F2 into *c. */
static void read_counters(udsota_counters_t *c)
{
    REQ(0x22, 0xF1, 0xF2);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(3u + UDSOTA_COUNTERS_LEN, rlen, msg);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(((const uint8_t[]){0x62, 0xF1, 0xF2}), resp, 3, msg);
    TEST_ASSERT_TRUE(udsota_unpack_counters(&resp[3], rlen - 3u, c));
}

/* True when hooks.phase ever reported p. */
static bool phase_seen(udsota_phase_t p)
{
    for (size_t i = 0; i < g_mock.phase_n; i++) {
        if (g_mock.phases[i] == (int)p) {
            return true;
        }
    }
    return false;
}

/* ---- A: 34, 36, 37 ---- */

/* A1: 34 is 0x11 in every session, keyed or not. */
static void test_A1_request_download_not_supported(void)
{
    const state_t states[] = {ST_DEF, ST_EXT, ST_PROG, ST_PROG03};
    for (size_t i = 0; i < sizeof states / sizeof states[0]; i++) {
        enter(states[i], false);
        REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40);
        NRC(0x34, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    }
}

/* Sends A2's five requests and checks each is 0x11. */
static void a2_requests(void)
{
    REQ(0x34);
    NRC(0x34, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x36, 0x01, 0xAA);
    NRC(0x36, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x36);
    NRC(0x36, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x37);
    NRC(0x37, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x37, 0x00);
    NRC(0x37, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
}

/* A2: 0x11 before the length and session checks. */
static void test_A2_not_supported_before_length_and_session(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, false);
        a2_requests();
    }
}

/* A3: after A1 and A2, nothing of a download happened: no gate question, no counter, no TRANSFERRING, no transfer. */
static void test_A3_no_download_side_effects(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, false);
        REQ(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x40);
        a2_requests();
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_calls[UDSOTA_OP_START_DOWNLOAD], msg);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_calls[UDSOTA_OP_CONTINUE_TRANSFER], msg);
        udsota_counters_t c;
        read_counters(&c);
        TEST_ASSERT_EQUAL_UINT16(0, c.seq_errors);
        TEST_ASSERT_EQUAL_UINT16(0, c.repeated_blocks);
        TEST_ASSERT_EQUAL_UINT16(0, c.aborts);
        TEST_ASSERT_EQUAL_UINT16(0, c.withheld_fcs);
        TEST_ASSERT_EQUAL_UINT16(0, c.stmin_violations);
        TEST_ASSERT_FALSE_MESSAGE(phase_seen(UDSOTA_PHASE_TRANSFERRING), msg);
        TEST_ASSERT_FALSE_MESSAGE(udsota_download_active(&s), msg);
    }
}

/* ---- B: the updater's RIDs ---- */

/* B6: the gate is never asked ACTIVATE or CONFIRM. */
static void assert_no_updater_gate(void)
{
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_calls[UDSOTA_OP_ACTIVATE], msg);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_calls[UDSOTA_OP_CONFIRM], msg);
}

/* 31 01 <rid> with no app routine: 0x31. */
static void b1_row(state_t st, uint16_t rid)
{
    enter(st, false);
    snprintf(msg, sizeof msg, "state %s, 31 01 %04X", k_state_name[st], rid);
    REQ(0x31, 0x01, HI(rid), LO(rid));
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    assert_no_updater_gate();
}

/* 31 01 <rid> with the app serving: its answer, and the hook saw the RID and the session. */
static void b2_row(state_t st, uint16_t rid)
{
    enter(st, true);
    snprintf(msg, sizeof msg, "state %s, 31 01 %04X", k_state_name[st], rid);
    REQ(0x31, 0x01, HI(rid), LO(rid));
    EXPECT(0x71, 0x01, HI(rid), LO(rid), APP_BYTE);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, app.routine_calls, msg);
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(rid, app.routine_rid, msg);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(k_state_session[st], app.routine_access.session, msg);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, app.routine_in_len, msg);
    assert_no_updater_gate();
}

/* B1: FF01, F000 and F001 in extended and programming+03, and F002 in programming+03, with no app routine: 0x31. */
static void test_B1_updater_rids_without_app(void)
{
    const state_t states[] = {ST_EXT, ST_PROG03};
    for (size_t i = 0; i < 2u; i++) {
        for (size_t r = 0; r < 3u; r++) {
            b1_row(states[i], k_upd_rids[r]);
        }
    }
    b1_row(ST_PROG03, ROWS_RID_CONFIRM_IMAGE);
}

/* B2: FF01, F000 and F001 in extended, programming locked and programming+03, and F002 in both programming states,
 * reach the app routine; no 0x33 from the core while locked. */
static void test_B2_updater_rids_reach_app(void)
{
    const state_t states[] = {ST_EXT, ST_PROG, ST_PROG03};
    for (size_t i = 0; i < 3u; i++) {
        for (size_t r = 0; r < 3u; r++) {
            b2_row(states[i], k_upd_rids[r]);
        }
    }
    b2_row(ST_PROG, ROWS_RID_CONFIRM_IMAGE);
    b2_row(ST_PROG03, ROWS_RID_CONFIRM_IMAGE);
}

/* B3: FF01 with an option byte reaches the app with it, in extended. */
static void test_B3_option_record_reaches_app(void)
{
    enter(ST_EXT, true);
    REQ(0x31, 0x01, 0xFF, 0x01, 0x07);
    EXPECT(0x71, 0x01, 0xFF, 0x01, APP_BYTE);
    TEST_ASSERT_EQUAL_size_t(1, app.routine_in_len);
    TEST_ASSERT_EQUAL_HEX16(ROWS_RID_CHECK_PROG_DEPS, app.routine_rid);
    assert_no_updater_gate();
}

/* B4: the core's session check comes first: F002 in default is 0x7F. */
static void test_B4_session_check_first(void)
{
    enter(ST_DEF, true);
    REQ(0x31, 0x01, 0xF0, 0x02);
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    TEST_ASSERT_EQUAL_UINT(0, app.routine_calls);
    assert_no_updater_gate();
}

/* B5: a sub-function other than 01 is 0x12. */
static void test_B5_subfunction_check(void)
{
    enter(ST_EXT, true);
    REQ(0x31, 0x03, 0xFF, 0x01);
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(0, app.routine_calls);
    assert_no_updater_gate();
}

/* B1 and B2's F002 in extended (0.8.0 reaches the NULL engine.confirm here). */
static void test_B_F002_in_extended(void)
{
    b1_row(ST_EXT, ROWS_RID_CONFIRM_IMAGE);
    b2_row(ST_EXT, ROWS_RID_CONFIRM_IMAGE);
}

/* ---- C: DIDs ---- */

/* C1: the updater's DIDs with nothing serving them: 0x31, after one did_read with that DID. */
static void test_C1_updater_dids_without_app(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        for (size_t d = 0; d < 4u; d++) {
            enter(st, false);
            snprintf(msg, sizeof msg, "state %s, 22 %04X", k_state_name[st], k_upd_dids[d]);
            REQ(0x22, HI(k_upd_dids[d]), LO(k_upd_dids[d]));
            NRC(UDSOTA_SID_READ_DID, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
            TEST_ASSERT_EQUAL_UINT_MESSAGE(1, g_mock.did_reads, msg);
            TEST_ASSERT_EQUAL_HEX16_MESSAGE(k_upd_dids[d], g_mock.last_did, msg);
        }
    }
}

/* C2: the updater's DIDs served by the app. */
static void test_C2_updater_dids_from_app(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        for (size_t d = 0; d < 4u; d++) {
            enter(st, true);
            snprintf(msg, sizeof msg, "state %s, 22 %04X", k_state_name[st], k_upd_dids[d]);
            REQ(0x22, HI(k_upd_dids[d]), LO(k_upd_dids[d]));
            EXPECT(0x62, HI(k_upd_dids[d]), LO(k_upd_dids[d]), 0xAA, 0xBB);
        }
    }
}

/* C3: F1F2 is the core's: never the app's hook; the updater's counters stay 0, the core's still count. */
static void test_C3_counters_are_the_cores(void)
{
    orphan_app_routine();                      /* resp_pending_caps 1 */
    udsota_on_rx_timeout(&s, now);             /* ncr_timeouts 1 */
    const unsigned reads = g_mock.did_reads;
    udsota_counters_t c;
    read_counters(&c);
    TEST_ASSERT_EQUAL_UINT(reads, g_mock.did_reads);
    TEST_ASSERT_EQUAL_UINT16(0, c.seq_errors);
    TEST_ASSERT_EQUAL_UINT16(1, c.ncr_timeouts);
    TEST_ASSERT_EQUAL_UINT16(0, c.repeated_blocks);
    TEST_ASSERT_EQUAL_UINT16(0, c.aborts);
    TEST_ASSERT_EQUAL_UINT16(0, c.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(0, c.stmin_violations);
    TEST_ASSERT_EQUAL_UINT16(1, c.resp_pending_caps);
    TEST_ASSERT_EQUAL_UINT16(0, c.resp_frames_dropped);
}

/* C4: F186 and F18C are the core's. */
static void test_C4_session_and_serial(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, true);
        REQ(0x22, 0xF1, 0x86);
        EXPECT(0x62, 0xF1, 0x86, k_state_session[st]);
        REQ(0x22, 0xF1, 0x8C);
        EXPECT(0x62, 0xF1, 0x8C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.did_reads, msg);
    }
}

/* ---- D: 10 02, which has no programming to enter ---- */

/* D1: 10 02 answers 0x12 from every state, 10 82 too, without asking the gate, and nothing changes: no session
 * entry, no epoch step, no relock. */
static void test_D1_programming_not_supported(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, false);
        const uint32_t epoch = s.session_epoch;
        const uint8_t level = s.security;
        REQ(0x10, 0x02);
        NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
        REQ(0x10, 0x82);
        NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING], msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(k_state_session[st], s.session, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(level, s.security, msg);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(epoch, s.session_epoch, msg);
    }
}

/* D2: the length checks come first, as for any 10: 0x13 for 10 alone and for 10 02 00; the gate's NRC is never
 * reached. */
static void test_D2_length_before_the_refusal(void)
{
    enter(ST_DEF, false);
    g_mock.gate_nrc[UDSOTA_OP_ENTER_PROGRAMMING] = NRC_SPEED;
    REQ(0x10);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_INCORRECT_LENGTH);
    REQ(0x10, 0x02, 0x00);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_INCORRECT_LENGTH);
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING]);
}

/* D3: an app routine pending: 0x21, which the core answers before any 10. */
static void test_D3_busy_while_app_routine_runs(void)
{
    enter(ST_EXT, true);
    start_pending_app_routine();
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_BUSY_REPEAT);
}

/* D4: an app orphan after the 90 s cap changes nothing: 0x12 while it runs and after routine_poll finishes it. */
static void test_D4_app_orphan_still_0x12(void)
{
    orphan_app_routine();
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    app.poll_pending = false;
    poll_at(now + UDSOTA_JOB_POLL_MS);
    TEST_ASSERT_FALSE(s.app_orphan);
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING]);
}

/* D5: the programming level's requestSeed needs the programming session, now out of reach: 27 03 answers 0x7E in
 * the extended session, and 10 01 and 10 03 still answer. */
static void test_D5_programming_seed_unreachable(void)
{
    enter(ST_EXT, false);
    REQ(0x27, UDSOTA_SA_SEED_PROGRAMMING);
    NRC(UDSOTA_SID_SECURITY, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION);
    REQ(0x27, UDSOTA_SA_KEY_PROGRAMMING);
    NRC(UDSOTA_SID_SECURITY, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION);
    REQ(0x10, 0x03);
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    REQ(0x10, 0x01);
    EXPECT(0x50, 0x01, 0x00, 0x32, 0x01, 0xF4);
}

/* D6: functionally, 10 02 is never served: no answer in any state, as with the updater. */
static void test_D6_functional_programming_silent(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, false);
        const uint8_t r[] = {0x10, 0x02};
        rlen = udsota_on_functional_request(&s, r, sizeof r, resp, sizeof resp, now);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(0, rlen, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(k_state_session[st], s.session, msg);
    }
}

/* ---- E: 11 01 ---- */

/* E1: locked: 0x33. */
static void test_E1_reset_locked(void)
{
    enter(ST_EXT, false);
    REQ(0x11, 0x01);
    NRC(UDSOTA_SID_RESET, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
}

/* E2: unlocked: 51 01, the restart is armed and fires once the answer has left, back in default. */
static void test_E2_reset_restarts(void)
{
    const state_t states[] = {ST_EXT01, ST_PROG03};
    for (size_t i = 0; i < 2u; i++) {
        enter(states[i], false);
        REQ(0x11, 0x01);
        EXPECT(0x51, 0x01);
        TEST_ASSERT_TRUE_MESSAGE(udsota_restart_armed(&s), msg);
        app.tx_pending = 0;
        poll_at(now + 1u);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(1, g_mock.resets, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(UDSOTA_SESSION_DEFAULT, s.session, msg);
    }
}

/* E3: an app orphan is 0x22; the gate's NRC verbatim; a failed reset re-opens default without ACTIVATING; no reset
 * hook is 0x11. */
static void test_E3_reset_refusals(void)
{
    orphan_app_routine();
    REQ(0x10, 0x03);
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    REQ(0x11, 0x01);
    NRC(UDSOTA_SID_RESET, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_RESET]);

    enter(ST_EXT01, false);
    g_mock.gate_nrc[UDSOTA_OP_RESET] = NRC_SPEED;
    REQ(0x11, 0x01);
    NRC(UDSOTA_SID_RESET, NRC_SPEED);

    enter(ST_EXT01, false);
    g_mock.reset_ok = false;
    REQ(0x11, 0x01);
    EXPECT(0x51, 0x01);
    poll_at(now + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_FALSE(udsota_restart_armed(&s));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_FALSE(phase_seen(UDSOTA_PHASE_ACTIVATING));
    REQ(0x3E, 0x00);
    EXPECT(0x7E, 0x00);

    setUp();
    boot(false);
    g_hooks.reset = NULL;
    TEST_ASSERT_TRUE(CORE_ROWS_INIT(&s, &g_cfg, rows_security(), &g_hooks));
    REQ(0x10, 0x03);
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    REQ(0x11, 0x01);
    NRC(UDSOTA_SID_RESET, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
}

/* ---- F: the rest of the core, unchanged ---- */

/* F1: 27 unlocks both levels in their sessions; 0x7F in default. */
static void test_F1_security_access(void)
{
    enter(ST_DEF, false);
    REQ(0x27, 0x01);
    NRC(UDSOTA_SID_SECURITY, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
    enter(ST_EXT01, false);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_EXTENDED, s.security);
    enter(ST_PROG03, false);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SA_SEED_PROGRAMMING, s.security);
}

/* F2: 28, 85, 2E and 3E through their hooks; 28 and 85 undone back in default. */
static void test_F2_app_services(void)
{
    enter(ST_EXT, false);
    REQ(0x28, 0x03, 0x03);
    EXPECT(0x68, 0x03);
    REQ(0x85, 0x02);
    EXPECT(0xC5, 0x02);
    REQ(0x2E, 0x12, 0x34, 0xAA);
    EXPECT(0x6E, 0x12, 0x34);
    REQ(0x3E, 0x00);
    EXPECT(0x7E, 0x00);
    TEST_ASSERT_EQUAL_UINT(1, app.comm_calls);
    TEST_ASSERT_EQUAL_UINT(1, app.dtc_calls);
    REQ(0x10, 0x01);
    EXPECT(0x50, 0x01, 0x00, 0x32, 0x01, 0xF4);
    TEST_ASSERT_EQUAL_UINT(2, app.comm_calls);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_ENABLE_RX_TX, app.comm_control);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_CC_TYPE_ALL, app.comm_type);
    TEST_ASSERT_EQUAL_UINT(2, app.dtc_calls);
    TEST_ASSERT_TRUE(app.dtc_on);
}

/* F3: an app routine pending: 0x78 at 40 ms, its answer on the poll after it finishes; at 90 s 0x10 and an orphan. */
static void test_F3_app_routine_job(void)
{
    enter(ST_EXT, true);
    start_pending_app_routine();
    const uint32_t t = now;
    poll_at(t + 39u);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    poll_at(t + 40u);
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_RESPONSE_PENDING);
    app.poll_pending = false;
    poll_at(t + 45u);
    EXPECT(0x71, 0x01, HI(APP_RID), LO(APP_RID), APP_BYTE);
    TEST_ASSERT_FALSE(s.job_running);

    start_pending_app_routine();
    poll_at(now + UDSOTA_JOB_CAP_MS);
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_TRUE(s.app_orphan);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_JOB_POLL_MS, udsota_ms_to_deadline(&s, now));
}

/* F4: S3, and udsota_end_session at once and latched during a job, from extended and from programming, end in
 * default with the phase IDLE. */
static void test_F4_session_ends(void)
{
    enter(ST_PROG, false);
    REQ(0x3E, 0x00);                           /* answered: S3 runs */
    EXPECT(0x7E, 0x00);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&s));
    poll_at(now + UDSOTA_S3_MS);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));

    const state_t states[] = {ST_EXT, ST_PROG};
    const udsota_phase_t phases[] = {UDSOTA_PHASE_EXTENDED, UDSOTA_PHASE_PROGRAMMING};
    for (size_t i = 0; i < 2u; i++) {
        enter(states[i], false);
        REQ(0x3E, 0x00);                       /* reports the session's phase */
        TEST_ASSERT_EQUAL_INT_MESSAGE(phases[i], udsota_phase(&s), msg);
        udsota_end_session(&s, now);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(UDSOTA_SESSION_DEFAULT, s.session, msg);
        TEST_ASSERT_EQUAL_INT_MESSAGE(UDSOTA_PHASE_IDLE, udsota_phase(&s), msg);

        enter(states[i], true);
        REQ(0x3E, 0x00);
        TEST_ASSERT_EQUAL_INT_MESSAGE(phases[i], udsota_phase(&s), msg);
        start_pending_app_routine();
        udsota_end_session(&s, now);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(k_state_session[states[i]], s.session, msg);   /* latched: the job answers */
        app.poll_pending = false;
        poll_at(now + UDSOTA_JOB_POLL_MS);
        EXPECT(0x71, 0x01, HI(APP_RID), LO(APP_RID), APP_BYTE);
        poll_at(now + UDSOTA_JOB_POLL_MS);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(UDSOTA_SESSION_DEFAULT, s.session, msg);
        TEST_ASSERT_EQUAL_INT_MESSAGE(UDSOTA_PHASE_IDLE, udsota_phase(&s), msg);
    }
}

/* F5: the transport's FC check allows and counts nothing, and hooks.progress never runs (udsota_progress() itself is
 * the updater's: the no-engine test reads it). */
static void test_F5_fc_check_and_progress(void)
{
    const state_t states[] = {ST_DEF, ST_PROG03};
    for (size_t i = 0; i < 2u; i++) {
        enter(states[i], false);
        TEST_ASSERT_TRUE(udsota_fc_check(&s, 100, 2000, now));
        TEST_ASSERT_EQUAL_UINT16(0, s.counters.withheld_fcs);
        TEST_ASSERT_EQUAL_UINT(0, app.progress_calls);
    }
}

/* ---- G: every SID in every state ---- */

/* True for a SID this server serves with every hook set and security on. */
static bool g_served(uint8_t sid)
{
    switch (sid) {
    case UDSOTA_SID_SESSION:
    case UDSOTA_SID_RESET:
    case UDSOTA_SID_READ_DID:
    case UDSOTA_SID_SECURITY:
    case UDSOTA_SID_COMM_CONTROL:
    case UDSOTA_SID_WRITE_DID:
    case UDSOTA_SID_ROUTINE:
    case UDSOTA_SID_TESTER_PRESENT:
    case UDSOTA_SID_DTC_SETTING:
    case UDSOTA_SID_READ_DTC:
    case UDSOTA_SID_CLEAR_DTC:
        return true;
    default:
        return false;
    }
}

/* Checks one answer: empty, positive for sid, or 7F sid <nrc>, within resp_max; exactly 7F sid 11 for an unserved
 * SID when it answers a request. */
static void g_check(uint8_t sid, bool is_request)
{
    TEST_ASSERT_TRUE_MESSAGE(rlen <= sizeof resp, msg);
    if (rlen == 0u) {
        TEST_ASSERT_TRUE_MESSAGE(!is_request || g_served(sid), msg);
        return;
    }
    if (resp[0] == UDSOTA_NEG_RESPONSE) {
        TEST_ASSERT_EQUAL_size_t_MESSAGE(3, rlen, msg);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(sid, resp[1], msg);
    } else {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(UDSOTA_POS(sid), resp[0], msg);
    }
    if (is_request && !g_served(sid)) {
        NRC(sid, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    }
}

/* G: 5 states x SID 00-FF x length {1, 2, 3, 4, 11}, each on a fresh server, then a poll 100 ms later. */
static void test_G_every_sid_every_state(void)
{
    static const size_t lens[] = {1, 2, 3, 4, 11};
    for (state_t st = ST_DEF; st < ST_N; st++) {
        for (unsigned sid = 0; sid <= 0xFFu; sid++) {
            for (size_t l = 0; l < sizeof lens / sizeof lens[0]; l++) {
                enter(st, false);
                uint8_t r[11] = {(uint8_t)sid, 0x01, 0xF1, 0x86, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
                snprintf(msg, sizeof msg, "state %s, SID %02X, length %u", k_state_name[st], sid, (unsigned)lens[l]);
                req(r, lens[l]);
                g_check((uint8_t)sid, true);
                poll_at(now + 100u);
                g_check((uint8_t)sid, false);
            }
        }
    }
}

/* ---- I: 19 and 14, core services that need no service ---- */

/* I1: 19 02, 19 06 and 14 through their hooks in every state, with no service registered: 19 in every session (the
 * availability read as 0xFF), 14 reaching the hook with the state's access. */
static void test_I1_dtc_services_without_a_service(void)
{
    for (state_t st = ST_DEF; st < ST_N; st++) {
        enter(st, false);
        REQ(0x19, 0x02, 0x08);
        EXPECT(0x59, 0x02, 0xFF, 0xC0, 0x73, 0x00, 0x2F, 0x05, 0x62, 0x00, 0x28);
        REQ(0x19, 0x06, 0x05, 0x62, 0x00, 0x01);
        EXPECT(0x59, 0x06, 0x05, 0x62, 0x00, 0x28, 0x01, 0x07);
        REQ(0x14, 0xFF, 0xFF, 0xFF);
        EXPECT(0x54);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(1, app.dtc_exts, msg);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(1, app.dtc_clears, msg);
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xFFFFFFu, app.clear_group, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(k_state_session[st], app.clear_access.session, msg);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(s.security, app.clear_access.unlocked_level, msg);
        TEST_ASSERT_FALSE_MESSAGE(udsota_download_active(&s), msg);
    }
}

/* I2: without the DTC hooks, 19 and 14 answer 0x11 as any unserved SID. */
static void test_I2_dtc_services_need_their_hooks(void)
{
    enter(ST_EXT, false);
    g_hooks.dtc_get = NULL;
    g_hooks.dtc_clear = NULL;
    TEST_ASSERT_TRUE(CORE_ROWS_INIT(&s, &g_cfg, rows_security(), &g_hooks));
    REQ(0x19, 0x02, 0xFF);
    NRC(0x19, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    REQ(0x14, 0xFF, 0xFF, 0xFF);
    NRC(0x14, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(0, app.dtc_gets + app.dtc_clears);
}

/* ---- The table and main ---- */

typedef struct {
    const char *name;
    void      (*fn)(void);
    int         line;
} test_row_t;
#define ROW(f) {#f, f, __LINE__}

/* Groups A to G, in the order that ran the 0.8.0 tree furthest before its first crash: A, B without F002, C, then
 * F002, D, E, F, G; then I. */
#define CORE_ROWS                                                                                                    \
    ROW(test_A1_request_download_not_supported), ROW(test_A2_not_supported_before_length_and_session),              \
    ROW(test_A3_no_download_side_effects), ROW(test_B1_updater_rids_without_app),                                   \
    ROW(test_B2_updater_rids_reach_app), ROW(test_B3_option_record_reaches_app), ROW(test_B4_session_check_first), \
    ROW(test_B5_subfunction_check), ROW(test_C1_updater_dids_without_app), ROW(test_C2_updater_dids_from_app),      \
    ROW(test_C3_counters_are_the_cores), ROW(test_C4_session_and_serial), ROW(test_B_F002_in_extended),             \
    ROW(test_D1_programming_not_supported), ROW(test_D2_length_before_the_refusal),                                \
    ROW(test_D3_busy_while_app_routine_runs), ROW(test_D4_app_orphan_still_0x12),                                  \
    ROW(test_D5_programming_seed_unreachable), ROW(test_D6_functional_programming_silent), ROW(test_E1_reset_locked), \
    ROW(test_E2_reset_restarts), ROW(test_E3_reset_refusals), ROW(test_F1_security_access),                         \
    ROW(test_F2_app_services), ROW(test_F3_app_routine_job), ROW(test_F4_session_ends),                             \
    ROW(test_F5_fc_check_and_progress), ROW(test_G_every_sid_every_state),                                         \
    ROW(test_I1_dtc_services_without_a_service), ROW(test_I2_dtc_services_need_their_hooks)

/* Runs every test in tests[0..n), or only the one named in argv[1] (so a failure can be shown alone). */
static int core_rows_main(int argc, char **argv, const test_row_t *tests, size_t n)
{
    UNITY_BEGIN();
    unsigned ran = 0;
    for (size_t i = 0; i < n; i++) {
        if (argc < 2 || strcmp(argv[1], tests[i].name) == 0) {
            UnityDefaultTestRun(tests[i].fn, tests[i].name, tests[i].line);
            ran++;
        }
    }
    if (ran == 0u) {
        printf("no test named %s\n", argv[1]);
        return 1;
    }
    return UNITY_END();
}
