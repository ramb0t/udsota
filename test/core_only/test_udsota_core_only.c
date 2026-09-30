/* The UDS server without the updater, built from server/ alone: this file and the objects it links see only
 * server/include, isotp and udsota_update_state.h (CMakeLists.txt, udsota_server_only), so an updater include in the
 * core fails to compile and an updater call fails to link. It runs the no-updater rows (udsota_core_rows.h) through
 * udsota_core_init, the service seam through a test-local service, and one request through the ISO-TP adapter. Pass
 * a test's name to run it alone. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "udsota_server.h"
#include "udsota_service.h"
#include "udsota_isotp.h"

#define CORE_ROWS_INIT(srv, cfg, security, hooks) udsota_core_init((srv), (cfg), (security), (hooks))
#include "udsota_core_rows.h"

/* udsota_core_init returns what udsota_init does for each kind of security: true for a working one and for none,
 * false for one with no rng16 (the no-engine test compares the two byte for byte). */
static void test_core_init_returns(void)
{
    static const udsota_security_t no_rng = {.rng16 = NULL, .key = rows_key};
    static const udsota_security_t no_key = {.rng16 = rows_rng16};
    g_hooks = rows_mock_hooks(&g_mock);
    TEST_ASSERT_TRUE(udsota_core_init(&s, &g_cfg, rows_security(), &g_hooks));
    TEST_ASSERT_TRUE(udsota_core_init(&s, &g_cfg, NULL, &g_hooks));
    TEST_ASSERT_FALSE(udsota_core_init(&s, &g_cfg, &no_rng, &g_hooks));
    TEST_ASSERT_FALSE(udsota_core_init(&s, &g_cfg, &no_key, &g_hooks));
    TEST_ASSERT_NULL(s.svc);
}

/* ---- The seam: a test-local service ---- */

#define SVC_RID    0xFF01u   /* the RID it claims */
#define SVC_DID    0xF1F1u   /* the DID it claims */
#define SVC_SID    0x34u     /* the SID it claims: 34 00 answers at once, 34 01 starts a job, 34 02 counts an abort */

/* What the service answers and what it was asked. */
typedef struct {
    bool     unsettled;        /* settled() answers false */
    bool     dl_active;        /* download_active() */
    int      poll_rc;          /* poll(): UDSOTA_PENDING while its work is queued, else its last result */
    bool     fc_refuse;        /* fc_point() refuses */
    unsigned requests, routines, read_dids, polls, fc_points, syncs;
    unsigned sessions, capped;   /* on_session calls, and those with job_capped */
} svc_t;

static svc_t v;

/* 34 01's job done: 74 CD <arg>. */
static size_t svc_job_done(udsota_server_t *srv, int result, uint8_t *out, size_t out_max, uint32_t t)
{
    if (result != 0) {
        return udsota_nrc(out, out_max, SVC_SID, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    }
    out[0] = UDSOTA_POS(SVC_SID);
    out[1] = 0xCD;
    out[2] = (uint8_t)udsota_job_arg(srv);
    return 3;
}

/* request: SID 34 only. */
static size_t svc_request(udsota_server_t *srv, const uint8_t *r, size_t len, uint8_t *out, size_t out_max,
                          uint32_t t)
{
    v.requests++;
    if (r[0] != SVC_SID) {
        return UDSOTA_SVC_PASS;
    }
    if (len >= 2u && r[1] == 0x01u) {
        return udsota_job_start(srv, SVC_SID, false, UDSOTA_PENDING, svc_job_done, 7u, out, out_max, t);
    }
    if (len >= 2u && r[1] == 0x02u) {
        udsota_sat_inc16(&udsota_counters(srv)->aborts);
    }
    out[0] = UDSOTA_POS(SVC_SID);
    out[1] = 0xAB;
    return 2;
}

/* routine: FF01 only, answered 71 01 FF 01 EE. */
static size_t svc_routine(udsota_server_t *srv, uint16_t rid, const uint8_t *r, size_t len, bool spr, uint8_t *out,
                          size_t out_max, uint32_t t)
{
    v.routines++;
    if (rid != SVC_RID) {
        return UDSOTA_SVC_PASS;
    }
    out[0] = UDSOTA_POS(UDSOTA_SID_ROUTINE);
    out[1] = UDSOTA_RC_START;
    out[2] = HI(SVC_RID);
    out[3] = LO(SVC_RID);
    out[4] = 0xEE;
    return 5;
}

/* owns_rid: FF01 only, as routine claims. */
static bool svc_owns_rid(const udsota_server_t *srv, uint16_t rid) { return rid == SVC_RID; }

/* read_did: F1F1 only, AA CC. */
static size_t svc_read_did(const udsota_server_t *srv, uint16_t did, uint8_t *out, size_t room)
{
    v.read_dids++;
    if (did != SVC_DID) {
        return UDSOTA_SVC_PASS;
    }
    out[0] = 0xAA;
    out[1] = 0xCC;
    return 2;
}

static void svc_on_session(udsota_server_t *srv, bool job_capped)
{
    v.sessions++;
    v.capped += job_capped ? 1u : 0u;
}
static bool svc_settled(const udsota_server_t *srv) { return !v.unsettled; }
static bool svc_download_active(const udsota_server_t *srv) { return v.dl_active; }
static int svc_poll(const udsota_server_t *srv)
{
    v.polls++;
    return v.poll_rc;
}
static bool svc_fc_point(udsota_server_t *srv, uint32_t median, uint32_t stmin)
{
    v.fc_points++;
    return !v.fc_refuse;
}
static void svc_sync(udsota_server_t *srv) { v.syncs++; }

static const udsota_service_t k_svc = {
    .request = svc_request, .routine = svc_routine, .owns_rid = svc_owns_rid, .read_did = svc_read_did,
    .on_session = svc_on_session, .settled = svc_settled, .download_active = svc_download_active, .poll = svc_poll,
    .fc_point = svc_fc_point, .sync = svc_sync,
};

/* The rows' server (app none) with the test service registered, in st. */
static void enter_svc(state_t st)
{
    enter(st, false);
    memset(&v, 0, sizeof v);
    udsota_register_service(&s, &k_svc);
}

/* The service gets the SID, RID and DID it claims; what it passes reaches 0x11 or the app's hook, and the sentinel
 * never comes out. */
static void test_seam_claims_and_passes(void)
{
    enter_svc(ST_DEF);
    REQ(0x22, 0xF1, 0xF1);
    EXPECT(0x62, 0xF1, 0xF1, 0xAA, 0xCC);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.did_reads);
    REQ(0x22, 0xF1, 0x89);                                    /* passed: to hooks.did_read, which serves nothing */
    NRC(UDSOTA_SID_READ_DID, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.did_reads);
    TEST_ASSERT_EQUAL_HEX16(0xF189, g_mock.last_did);
    REQ(0x22, 0xF1, 0x86);                                    /* the core's own: the service isn't asked */
    EXPECT(0x62, 0xF1, 0x86, UDSOTA_SESSION_DEFAULT);
    TEST_ASSERT_EQUAL_UINT(2, v.read_dids);
    REQ(SVC_SID, 0x00);
    EXPECT(0x74, 0xAB);
    REQ(0x35, 0x00);                                          /* passed: 0x11 */
    NRC(0x35, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(2, v.requests);

    enter_svc(ST_EXT);
    REQ(0x31, 0x01, HI(SVC_RID), LO(SVC_RID));
    EXPECT(0x71, 0x01, HI(SVC_RID), LO(SVC_RID), 0xEE);
    REQ(0x31, 0x01, 0xF0, 0x02);                              /* passed: no app routine, 0x31 */
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    TEST_ASSERT_EQUAL_UINT(2, v.routines);
    REQ(0x31, 0x03, HI(SVC_RID), LO(SVC_RID));               /* the core's sub-function check comes first */
    NRC(UDSOTA_SID_ROUTINE, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_UINT(2, v.routines);
    TEST_ASSERT_TRUE(v.syncs > 0u);                           /* the end-of-call report runs */
}

/* on_session runs on every session entry: 10 xx, S3, udsota_end_session and udsota_end_session_now; never capped. */
static void test_seam_on_session(void)
{
    enter_svc(ST_DEF);
    REQ(0x10, 0x03);
    EXPECT(0x50, 0x03, 0x00, 0x32, 0x01, 0xF4);
    TEST_ASSERT_EQUAL_UINT(1, v.sessions);
    poll_at(now + UDSOTA_S3_MS);                              /* S3 */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT(2, v.sessions);
    REQ(0x10, 0x03);
    udsota_end_session(&s, now);
    TEST_ASSERT_EQUAL_UINT(4, v.sessions);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    REQ(0x10, 0x03);
    const uint32_t epoch = s.session_epoch;
    udsota_end_session_now(&s);
    TEST_ASSERT_EQUAL_UINT(6, v.sessions);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT32(epoch + 1u, s.session_epoch);
    TEST_ASSERT_EQUAL_UINT(0, v.capped);
}

/* 10 02: settled's refusal and a pending poll are 0x22 before the gate is asked, and so is an open transfer; 11 01
 * too while the poll is pending. download_active shows PHASE_TRANSFERRING in programming. */
static void test_seam_programming_conditions(void)
{
    enter_svc(ST_DEF);
    v.unsettled = true;
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    v.unsettled = false;
    v.poll_rc = UDSOTA_PENDING;
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING]);

    REQ(0x10, 0x03);
    unlock(UDSOTA_SA_SEED_EXTENDED);
    REQ(0x11, 0x01);
    NRC(UDSOTA_SID_RESET, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(0, g_mock.gate_calls[UDSOTA_OP_RESET]);

    v.poll_rc = 0;
    REQ(0x10, 0x02);
    EXPECT(0x50, 0x02, 0x00, 0x32, 0x01, 0xF4);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_PROGRAMMING, udsota_phase(&s));
    v.dl_active = true;
    REQ(0x10, 0x02);                                          /* a transfer open: 0x22 */
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.gate_calls[UDSOTA_OP_ENTER_PROGRAMMING]);
    TEST_ASSERT_TRUE(udsota_download_active(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, udsota_phase(&s));
}

/* A job the service starts with udsota_job_start(PENDING) is polled through its poll: 0x78, then its answer; at the
 * 90 s cap 0x72, on_session(s, true), and worker_orphan until the poll stops reporting pending. */
static void test_seam_job_and_cap(void)
{
    enter_svc(ST_EXT);
    v.poll_rc = UDSOTA_PENDING;
    REQ(SVC_SID, 0x01);
    TEST_ASSERT_EQUAL_size_t(0, rlen);
    TEST_ASSERT_TRUE(s.job_running);
    const uint32_t t = now;
    poll_at(t + 40u);
    NRC(SVC_SID, UDSOTA_NRC_RESPONSE_PENDING);
    v.poll_rc = 0;
    poll_at(t + 45u);
    EXPECT(0x74, 0xCD, 7);
    TEST_ASSERT_FALSE(s.job_running);

    v.poll_rc = UDSOTA_PENDING;
    REQ(SVC_SID, 0x01);
    const unsigned polls = v.polls;
    poll_at(now + UDSOTA_JOB_CAP_MS);
    NRC(SVC_SID, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_TRUE(v.polls > polls);
    TEST_ASSERT_EQUAL_UINT(1, v.capped);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_TRUE(s.worker_orphan);
    poll_at(now + UDSOTA_JOB_POLL_MS);
    TEST_ASSERT_TRUE(s.worker_orphan);                        /* still pending */
    REQ(0x10, 0x02);
    NRC(UDSOTA_SID_SESSION, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    v.poll_rc = 0;
    poll_at(now + UDSOTA_JOB_POLL_MS);
    TEST_ASSERT_FALSE(s.worker_orphan);
    REQ(0x10, 0x02);
    EXPECT(0x50, 0x02, 0x00, 0x32, 0x01, 0xF4);
}

/* udsota_fc_check asks fc_point only while download_active; a refusal withholds the FC, counts it in withheld_fcs and
 * returns to default. */
static void test_seam_fc_point(void)
{
    enter_svc(ST_PROG03);
    TEST_ASSERT_TRUE(udsota_fc_check(&s, 100, 2000, now));
    TEST_ASSERT_EQUAL_UINT(0, v.fc_points);
    v.dl_active = true;
    TEST_ASSERT_TRUE(udsota_fc_check(&s, 100, 2000, now));
    TEST_ASSERT_EQUAL_UINT(1, v.fc_points);
    TEST_ASSERT_EQUAL_UINT16(0, s.counters.withheld_fcs);
    v.fc_refuse = true;
    const unsigned sessions = v.sessions;
    TEST_ASSERT_FALSE(udsota_fc_check(&s, 100, 2000, now));
    TEST_ASSERT_EQUAL_UINT16(1, s.counters.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s.session);
    TEST_ASSERT_EQUAL_UINT(sessions + 1u, v.sessions);
}

/* udsota_restart_arm: false without a reset hook; with one, ACTIVATE shows the phase ACTIVATING and the restart
 * fires; a failed restart clears ACTIVATING. */
static void test_seam_restart_arm(void)
{
    setUp();
    g_hooks = rows_mock_hooks(&g_mock);
    g_hooks.reset = NULL;
    udsota_core_init(&s, &g_cfg, rows_security(), &g_hooks);
    udsota_register_service(&s, &k_svc);
    now = T0;
    TEST_ASSERT_FALSE(udsota_restart_arm(&s, UDSOTA_RESTART_ACTIVATE, now));
    TEST_ASSERT_FALSE(udsota_restart_armed(&s));
    TEST_ASSERT_FALSE(udsota_activating(&s));

    enter_svc(ST_EXT);
    app.tx_pending = 1u;                                      /* the answer hasn't left: the restart waits 100 ms */
    TEST_ASSERT_TRUE(udsota_restart_arm(&s, UDSOTA_RESTART_ACTIVATE, now));
    TEST_ASSERT_TRUE(udsota_activating(&s));
    poll_at(now + 1u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_ACTIVATING, udsota_phase(&s));
    TEST_ASSERT_EQUAL_UINT(0, g_mock.resets);
    poll_at(now + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);

    enter_svc(ST_EXT);
    app.tx_pending = 1u;
    g_mock.reset_ok = false;
    TEST_ASSERT_TRUE(udsota_restart_arm(&s, UDSOTA_RESTART_ACTIVATE, now));
    poll_at(now + 1u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_ACTIVATING, udsota_phase(&s));
    poll_at(now + UDSOTA_RESET_TX_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(1, g_mock.resets);
    TEST_ASSERT_FALSE(udsota_activating(&s));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, udsota_phase(&s));

    enter_svc(ST_EXT);                                        /* RESET never shows ACTIVATING */
    TEST_ASSERT_TRUE(udsota_restart_arm(&s, UDSOTA_RESTART_RESET, now));
    TEST_ASSERT_FALSE(udsota_activating(&s));
}

/* udsota_access_check: without security every level counts as unlocked; with it, locked until that level is. */
static void test_seam_access_check(void)
{
    setUp();
    g_hooks = rows_mock_hooks(&g_mock);
    udsota_core_init(&s, &g_cfg, NULL, &g_hooks);
    s.session = UDSOTA_SESSION_PROGRAMMING;
    udsota_svc_access_t a = udsota_access_check(&s, UDSOTA_SA_SEED_PROGRAMMING);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_PROGRAMMING, a.session);
    TEST_ASSERT_TRUE(a.unlocked);

    enter_svc(ST_PROG);
    a = udsota_access_check(&s, UDSOTA_SA_SEED_PROGRAMMING);
    TEST_ASSERT_FALSE(a.unlocked);
    unlock(UDSOTA_SA_SEED_PROGRAMMING);
    TEST_ASSERT_TRUE(udsota_access_check(&s, UDSOTA_SA_SEED_PROGRAMMING).unlocked);
    TEST_ASSERT_FALSE(udsota_access_check(&s, UDSOTA_SA_SEED_EXTENDED).unlocked);
}

/* A counter the service bumps through udsota_counters shows in the core's F1F2. */
static void test_seam_counters(void)
{
    enter_svc(ST_DEF);
    REQ(SVC_SID, 0x02);
    EXPECT(0x74, 0xAB);
    udsota_counters_t c;
    read_counters(&c);
    TEST_ASSERT_EQUAL_UINT16(1, c.aborts);
    TEST_ASSERT_EQUAL_UINT16(0, c.withheld_fcs);
}

/* ---- The transport: one single-frame 22 F186 through the ISO-TP adapter ---- */

#define REQ_ID   0x710u
#define RESP_ID  0x718u

static uint8_t  tp_frame[8];
static uint16_t tp_id;
static unsigned tp_sent;

/* can.send: records the frame. */
static int tp_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    tp_id = id;
    memcpy(tp_frame, data, len);
    tp_sent++;
    return 0;
}
/* can.now_us: the rows' clock. */
static uint32_t tp_now_us(void *ctx) { return now * 1000u; }

/* 03 22 F1 86 on the request ID answers 04 62 F1 86 01 on the response ID, with no service, on the idle receive
 * limit: the transport links and runs without the updater. */
static void test_isotp_read_session(void)
{
    static udsota_isotp_t tp;
    static udsota_isotp_bufs_t bufs;
    setUp();
    g_cfg.req_id = REQ_ID;
    g_cfg.resp_id = RESP_ID;
    boot(false);
    tp_sent = 0;
    const udsota_can_t can = {.send = tp_send, .now_us = tp_now_us};
    udsota_isotp_init(&tp, &s, &g_cfg, &g_hooks, &can, &bufs);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_RX_LIMIT_IDLE, tp.rx_limit);
    const uint8_t sf[8] = {0x03, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00, 0x00};
    udsota_isotp_on_frame(&tp, sf, 8, now * 1000u, now);
    for (int i = 0; i < 5 && tp_sent == 0u; i++) {
        now += 1u;
        (void)udsota_isotp_service(&tp, now);
    }
    TEST_ASSERT_EQUAL_UINT(1, tp_sent);
    TEST_ASSERT_EQUAL_HEX16(RESP_ID, tp_id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){0x04, 0x62, 0xF1, 0x86, UDSOTA_SESSION_DEFAULT}), tp_frame, 5);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_RX_LIMIT_IDLE, tp.rx_limit);
    TEST_ASSERT_FALSE(udsota_download_active(&s));
}

static const test_row_t k_tests[] = {
    CORE_ROWS,
    ROW(test_core_init_returns),
    ROW(test_seam_claims_and_passes),
    ROW(test_seam_on_session),
    ROW(test_seam_programming_conditions),
    ROW(test_seam_job_and_cap),
    ROW(test_seam_fc_point),
    ROW(test_seam_restart_arm),
    ROW(test_seam_access_check),
    ROW(test_seam_counters),
    ROW(test_isotp_read_session),
};

/* Runs every test, or only the one named in argv[1]. */
int main(int argc, char **argv)
{
    return core_rows_main(argc, argv, k_tests, sizeof k_tests / sizeof k_tests[0]);
}
