/* Host tests for udsota_isotp: the real adapter, server and isotp-c on a fake bus with one fake clock.
 * The test is the client and hand-encodes its frames, because the adapter owns isotp-c's platform hooks
 * in this executable. Each call mirrors the diag task: feed a frame, then service. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_wire.h"
#include "udsota_isotp.h"

#define REQ_ID    0x710u
#define RESP_ID   0x718u
#define LOG_MAX   4096u
#define BLOCK_LEN 4095u                   /* 36 BSC + 4,093 data bytes: FF_DL 0xFFF */
#define DATA_LEN  (BLOCK_LEN - 2u)
#define CF_GAP_US 2000u                   /* the client honours STmin 2 ms */

static const uint8_t k_dev_id[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

/* Fake clock, bus and client state. */
static uint32_t s_now_us;
static uint8_t  s_log[LOG_MAX][8];        /* every frame the adapter got onto the bus */
static unsigned s_log_n;
static unsigned s_refuse;                 /* the next sends answer UDSOTA_TX_RETRY */
static unsigned s_hard_fail;              /* the next sends fail outright */
static uint32_t s_driver_pending;         /* can.tx_pending: frames still in the app's driver */
static bool     s_auto_fc;                /* the client answers the adapter's FF with FC CTS */
static bool     s_fc_owed;                /* that FC waits to be fed at the next service */
static unsigned s_fc_n, s_fc_odd;         /* FCs the adapter sent, and how many differed from s_fc_want */
static uint8_t  s_fc_last[3], s_fc_want[3];
static uint8_t  s_resp[512];
static uint32_t s_resp_len, s_resp_got;
static bool     s_resp_done;
static uint8_t  s_block[BLOCK_LEN];

/* Mock engine and hooks state. */
static int         s_write_rc, s_poll_rc;
static uint32_t    s_written;
static bool        s_data_ok;
static unsigned    s_aborts, s_resets, s_hook_calls;
static udsota_op_t s_gate_op;
static uint8_t     s_gate_nrc;
static udsota_phase_t s_phase;
static uint32_t    s_hook_stmin;
static uint16_t    s_fc_retry_ms;             /* cfg.fc_retry_ms for the next init_all (0 = the default) */

static udsota_server_t     s_srv;
static udsota_isotp_t      s_tp;
static udsota_isotp_bufs_t s_bufs;
static udsota_config_t     s_cfg;
static udsota_engine_t     s_eng;
static udsota_hooks_t      s_hooks;
static udsota_can_t        s_can;

/* The fake clock in milliseconds, as the caller hands it to the core. */
static uint32_t now_ms(void) { return s_now_us / 1000u; }
/* Deterministic block byte i. */
static uint8_t pattern(uint32_t i) { return (uint8_t)(i * 13u + 5u); }

/* engine.check_first: every first block passes. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    *why = UDSOTA_DL_OK;
    return 0;
}
/* engine.begin: the erase succeeds at once. */
static int eng_begin(void *ctx, uint32_t size) { return 0; }
/* engine.write: checks the bytes against pattern() and returns s_write_rc (0 or UDSOTA_PENDING). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (d[i] != pattern(off + (uint32_t)i)) {
            s_data_ok = false;
        }
    }
    s_written += (uint32_t)n;
    return s_write_rc;
}
/* engine.verify: passes. */
static int eng_verify(void *ctx) { return 0; }
/* engine.activate: sets the boot slot. */
static int eng_activate(void *ctx) { return 0; }
/* engine.confirm: no-op. */
static int eng_confirm(void *ctx) { return 0; }
/* engine.abort: counted. */
static void eng_abort(void *ctx) { s_aborts++; }
/* engine.poll: s_poll_rc (UDSOTA_PENDING while the fake worker runs). */
static int eng_poll(void *ctx) { return s_poll_rc; }
/* engine.status: running slot 0 is the boot slot and VALID, the other slot empty. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->running_slot = UDSOTA_SLOT_OTA0;
    out->boot_slot = UDSOTA_SLOT_OTA0;
    out->running_state = UDSOTA_IMG_VALID;
    out->other_slot_state = UDSOTA_OTHER_EMPTY;
}
/* hooks.gate: s_gate_nrc for s_gate_op, else allow. */
static uint8_t hook_gate(void *ctx, udsota_op_t op) { return op == s_gate_op ? s_gate_nrc : 0u; }
/* hooks.phase: records the latest phase. */
static void hook_phase(void *ctx, udsota_phase_t p) { s_phase = p; }
/* hooks.stmin_us: s_hook_stmin, counting calls. */
static uint32_t hook_stmin(void *ctx) { s_hook_calls++; return s_hook_stmin; }
/* hooks.reset: records the restart and returns as a failed one (the server re-opens). */
static bool hook_reset(void *ctx) { s_resets++; return false; }

/* Client side of every frame the adapter sends: reassembles answers, owes an FC for an FF, records FCs. */
static void client_rx(const uint8_t *d)
{
    uint32_t take;
    switch (d[0] >> 4) {
    case 0x0:                                       /* SF: a whole answer */
        s_resp_len = d[0] & 0x0Fu;
        memcpy(s_resp, &d[1], s_resp_len);
        s_resp_done = true;
        break;
    case 0x1:                                       /* FF: the start of a long answer */
        s_resp_len = ((uint32_t)(d[0] & 0x0Fu) << 8) | d[1];
        TEST_ASSERT_TRUE(s_resp_len <= sizeof s_resp);
        memcpy(s_resp, &d[2], 6);
        s_resp_got = 6;
        s_resp_done = false;
        s_fc_owed = s_auto_fc;
        break;
    case 0x2:                                       /* CF of that answer */
        take = s_resp_len - s_resp_got;
        take = take > 7u ? 7u : take;
        memcpy(&s_resp[s_resp_got], &d[1], take);
        s_resp_got += take;
        s_resp_done = s_resp_got >= s_resp_len;
        break;
    case 0x3:                                       /* FC for the client's own request */
        s_fc_n++;
        memcpy(s_fc_last, d, 3);
        if (memcmp(d, s_fc_want, 3) != 0) {
            s_fc_odd++;
        }
        break;
    default:
        break;
    }
}

/* can.send: logs the frame and hands it to the client, unless a refusal is armed. */
static int can_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    TEST_ASSERT_EQUAL_HEX16(RESP_ID, id);
    TEST_ASSERT_EQUAL_UINT8(8, len);
    if (s_hard_fail > 0u) {
        s_hard_fail--;
        return -1;
    }
    if (s_refuse > 0u) {
        s_refuse--;
        return UDSOTA_TX_RETRY;
    }
    TEST_ASSERT_TRUE(s_log_n < LOG_MAX);
    memcpy(s_log[s_log_n++], data, 8);
    client_rx(data);
    return 0;
}
/* can.tx_pending: the fake driver's queue. */
static uint32_t can_tx_pending(void *ctx) { return s_driver_pending; }
/* can.now_us: the one fake clock, shared by isotp-c and the server. */
static uint32_t can_now_us(void *ctx) { return s_now_us; }

/* Builds the server and adapter: no security, the mock engine, gate, phase and reset hooks, the fake bus. */
static void init_all(void)
{
    s_cfg = (udsota_config_t){ .req_id = REQ_ID, .resp_id = RESP_ID, .stmin_monitor = true,
                               .device_id = k_dev_id, .device_id_len = sizeof k_dev_id,
                               .fc_retry_ms = s_fc_retry_ms };
    s_eng = (udsota_engine_t){ .check_first = eng_check_first, .begin = eng_begin, .write = eng_write,
                               .verify = eng_verify, .activate = eng_activate, .confirm = eng_confirm,
                               .abort = eng_abort, .poll = eng_poll, .status = eng_status };
    s_hooks.gate = hook_gate;
    s_hooks.phase = hook_phase;
    s_hooks.reset = hook_reset;
    s_can = (udsota_can_t){ .send = can_send, .tx_pending = can_tx_pending, .now_us = can_now_us };
    udsota_init(&s_srv, &s_cfg, &s_eng, NULL, &s_hooks);
    udsota_isotp_init(&s_tp, &s_srv, &s_cfg, &s_hooks, &s_can, &s_bufs);
}

/* Unity hook: a fresh bus, client, mocks and adapter at t = 1 s. */
void setUp(void)
{
    s_now_us = 1000000u;
    s_log_n = s_refuse = s_hard_fail = 0u;
    s_driver_pending = 0u;
    s_auto_fc = true;
    s_fc_owed = false;
    s_fc_n = s_fc_odd = 0u;
    memset(s_fc_last, 0, sizeof s_fc_last);
    memcpy(s_fc_want, (const uint8_t[3]){0x30, 0x40, 0x02}, 3);    /* CTS, BS 64, STmin 2 ms */
    s_resp_len = s_resp_got = 0u;
    s_resp_done = false;
    s_write_rc = s_poll_rc = 0;
    s_written = 0u;
    s_data_ok = true;
    s_aborts = s_resets = s_hook_calls = 0u;
    s_gate_op = (udsota_op_t)0;                                    /* matches no op: the gate allows */
    s_gate_nrc = 0u;
    s_phase = UDSOTA_PHASE_IDLE;
    s_hook_stmin = 0u;
    s_fc_retry_ms = 0u;
    memset(&s_hooks, 0, sizeof s_hooks);
    init_all();
}
/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Feeds one client frame, padded to 8 with 0xAA, to the adapter at the current time. */
static void feed(const uint8_t *d, uint8_t n)
{
    uint8_t f[8];
    memset(f, 0xAA, sizeof f);
    memcpy(f, d, n);
    udsota_isotp_on_frame(&s_tp, f, 8, s_now_us, now_ms());
}
/* The diag task's wake: the client's owed FC first (its queue), then the adapter's service. */
static uint32_t service(void)
{
    if (s_fc_owed) {
        static const uint8_t fc[3] = {0x30, 0x00, 0x00};        /* CTS, BS 0, STmin 0 */
        s_fc_owed = false;
        feed(fc, sizeof fc);
    }
    return udsota_isotp_service(&s_tp, now_ms());
}
/* Advances the clock ms milliseconds, servicing after each. */
static void run_ms(uint32_t ms)
{
    for (uint32_t i = 0; i < ms; i++) {
        s_now_us += 1000u;
        service();
    }
}
/* Runs up to ms_max milliseconds until an answer completes; true if one did. */
static bool run_until_response(uint32_t ms_max)
{
    for (uint32_t i = 0; i < ms_max && !s_resp_done; i++) {
        s_now_us += 1000u;
        service();
    }
    return s_resp_done;
}
/* Forgets the last answer. */
static void resp_clear(void)
{
    s_resp_done = false;
    s_resp_len = s_resp_got = 0u;
}
/* Sends n <= 7 request bytes as a Single Frame, services once, then runs up to ms_max ms for the answer; its length or 0. */
static uint32_t request_sf(const uint8_t *req, uint8_t n, uint32_t ms_max)
{
    uint8_t f[8];
    f[0] = n;
    memcpy(&f[1], req, n);
    resp_clear();
    feed(f, (uint8_t)(n + 1u));
    service();
    return run_until_response(ms_max) ? s_resp_len : 0u;
}
/* Sends n > 7 request bytes as an FF and CFs gap_us apart, servicing after each frame. From CF deny_cf on
 * (0 = never) the gate refuses CONTINUE_TRANSFER. It keeps sending whatever the adapter does. */
static void request_mf(const uint8_t *req, uint32_t n, uint32_t gap_us, uint32_t deny_cf)
{
    uint8_t f[8];
    f[0] = (uint8_t)(0x10u | (n >> 8));
    f[1] = (uint8_t)(n & 0xFFu);
    memcpy(&f[2], req, 6);
    resp_clear();
    feed(f, 8);
    service();
    uint32_t off = 6u, cf = 0u;
    uint8_t sn = 1u;
    while (off < n) {
        s_now_us += gap_us;
        const uint32_t take = (n - off < 7u) ? n - off : 7u;
        memset(f, 0xAA, sizeof f);
        f[0] = (uint8_t)(0x20u | sn);
        memcpy(&f[1], &req[off], take);
        if (++cf == deny_cf) {
            s_gate_op = UDSOTA_OP_CONTINUE_TRANSFER;
            s_gate_nrc = 0x22u;
        }
        feed(f, 8);
        service();
        off += take;
        sn = (uint8_t)((sn + 1u) & 0x0Fu);
    }
}
/* Fills s_block with 36 <bsc> and DATA_LEN pattern bytes. */
static void build_block(uint8_t bsc)
{
    s_block[0] = 0x36;
    s_block[1] = bsc;
    for (uint32_t i = 0; i < DATA_LEN; i++) {
        s_block[2u + i] = pattern(i);
    }
}
/* Enters the programming session and opens a download of size bytes (no key: security is NULL). */
static void open_download(uint32_t size)
{
    static const uint8_t prog[] = {0x10, 0x02};
    TEST_ASSERT_EQUAL_UINT32(6, request_sf(prog, sizeof prog, 50));
    TEST_ASSERT_EQUAL_HEX8(0x50, s_resp[0]);
    const uint8_t req[11] = {0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(size >> 24), (uint8_t)(size >> 16),
                             (uint8_t)(size >> 8), (uint8_t)size};
    request_mf(req, sizeof req, CF_GAP_US, 0u);
    TEST_ASSERT_TRUE(run_until_response(50));
    static const uint8_t pos[] = {0x74, 0x20, 0x0F, 0xFF};
    TEST_ASSERT_EQUAL_UINT32(sizeof pos, s_resp_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(pos, s_resp, sizeof pos);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, s_phase);
    service();                           /* the next wake: the receive limit rises to 4,095 */
}
/* Enters the extended session. */
static void enter_extended(void)
{
    static const uint8_t ext[] = {0x10, 0x03};
    TEST_ASSERT_EQUAL_UINT32(6, request_sf(ext, sizeof ext, 50));
    TEST_ASSERT_EQUAL_HEX8(0x50, s_resp[0]);
}
/* Reads the server's counters DID through the adapter (a multi-frame answer). */
static udsota_counters_t read_counters(void)
{
    const uint8_t req[] = {0x22, (uint8_t)(UDSOTA_DID_COUNTERS >> 8), (uint8_t)(UDSOTA_DID_COUNTERS & 0xFFu)};
    TEST_ASSERT_EQUAL_UINT32(3u + UDSOTA_COUNTERS_LEN, request_sf(req, sizeof req, 100));
    udsota_counters_t c;
    TEST_ASSERT_TRUE(udsota_unpack_counters(&s_resp[3], s_resp_len - 3u, &c));
    return c;
}
/* Reads F186 (active session, 1 = default). */
static uint8_t read_session(void)
{
    static const uint8_t req[] = {0x22, 0xF1, 0x86};
    TEST_ASSERT_EQUAL_UINT32(4, request_sf(req, sizeof req, 50));
    return s_resp[3];
}

/* Feeds one functional frame, padded to 8 with 0xAA, then services once. */
static void feed_func(const uint8_t *d, uint8_t n)
{
    uint8_t f[8];
    memset(f, 0xAA, sizeof f);
    memcpy(f, d, n);
    resp_clear();
    udsota_isotp_on_func_frame(&s_tp, f, 8, now_ms());
    service();
}

/* A functional SF is answered on the response ID; a functional FF gets no FC and no answer, a CF or an FC is
 * ignored, and nothing is counted. */
static void test_functional_single_frame_only(void)
{
    static const uint8_t sf[] = {0x02, 0x3E, 0x00};
    feed_func(sf, sizeof sf);
    TEST_ASSERT_TRUE(s_resp_done);
    TEST_ASSERT_EQUAL_HEX8(0x7E, s_resp[0]);
    const unsigned frames = s_log_n;
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};
    feed_func(ff, sizeof ff);
    static const uint8_t cf[] = {0x21, 0x00};
    feed_func(cf, sizeof cf);
    static const uint8_t fc[] = {0x30, 0x00, 0x00};
    feed_func(fc, sizeof fc);
    static const uint8_t sf0[] = {0x00, 0x3E};
    feed_func(sf0, sizeof sf0);
    run_ms(5);
    TEST_ASSERT_EQUAL_UINT(frames, s_log_n);             /* nothing sent: no FC, no answer */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_resp_lost(&s_tp));
}

/* A functional request while a physical one is mid-message is dropped, and the physical one completes. */
static void test_functional_dropped_during_a_physical_request(void)
{
    static const uint8_t ff[8] = {0x10, 0x08, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* 22 F1 86 + 5 bytes: 0x13 */
    feed(ff, sizeof ff);
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);
    static const uint8_t sf[] = {0x02, 0x3E, 0x00};
    feed_func(sf, sizeof sf);
    TEST_ASSERT_FALSE(s_resp_done);
    static const uint8_t cf[] = {0x21, 0x00, 0x00};
    feed(cf, sizeof cf);
    TEST_ASSERT_TRUE(run_until_response(10));
    static const uint8_t nrc[] = {0x7F, 0x22, 0x13};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(nrc, s_resp, sizeof nrc);
}

/* Single-frame requests get single-frame answers on the response ID, padded with 0xAA. */
static void test_single_frame_request_and_response(void)
{
    static const uint8_t tp[] = {0x3E, 0x00};
    TEST_ASSERT_EQUAL_UINT32(2, request_sf(tp, sizeof tp, 0));
    TEST_ASSERT_EQUAL_HEX8(0x7E, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, s_resp[1]);
    static const uint8_t pad[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(pad, &s_log[s_log_n - 1u][3], sizeof pad);
    TEST_ASSERT_EQUAL_UINT8(1, read_session());
}

/* A 4,095-byte 36 arrives with an FC after the FF and after every 64th CF (10 in all, each 30 40 02), and
 * the engine gets all 4,093 bytes. */
static void test_4095_byte_block_with_fc_every_64_cfs(void)
{
    open_download(DATA_LEN);
    build_block(1);
    s_fc_n = s_fc_odd = 0u;
    request_mf(s_block, BLOCK_LEN, CF_GAP_US, 0u);
    TEST_ASSERT_EQUAL_UINT(10, s_fc_n);                  /* FF, then CF 64, 128, ..., 576 of 585 */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_odd);
    TEST_ASSERT_TRUE(s_resp_done);
    TEST_ASSERT_EQUAL_UINT32(2, s_resp_len);
    TEST_ASSERT_EQUAL_HEX8(0x76, s_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, s_resp[1]);
    TEST_ASSERT_EQUAL_UINT32(DATA_LEN, s_written);
    TEST_ASSERT_TRUE(s_data_ok);
}

/* Outside a download the receive limit is 256: an FF of 257 gets the overflow FC, one of 256 is served;
 * with a download open an FF of 257 is accepted. */
static void test_receive_limit_256_outside_a_download(void)
{
    static const uint8_t ff257[8] = {0x11, 0x01, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};
    feed(ff257, sizeof ff257);
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);
    TEST_ASSERT_EQUAL_HEX8(0x32, s_fc_last[0]);          /* FS 2: overflow */
    static uint8_t req256[256];
    memset(req256, 0x01, sizeof req256);
    req256[0] = 0x22;                                    /* an odd-length 0x22: the server answers 0x13 */
    request_mf(req256, sizeof req256, CF_GAP_US, 0u);
    TEST_ASSERT_EQUAL_HEX8(0x30, s_fc_last[0]);
    TEST_ASSERT_TRUE(run_until_response(50));
    static const uint8_t nrc[] = {0x7F, 0x22, 0x13};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(nrc, s_resp, sizeof nrc);
    open_download(DATA_LEN);
    feed(ff257, sizeof ff257);
    TEST_ASSERT_EQUAL_HEX8(0x30, s_fc_last[0]);          /* 4,095 now */
}

/* An answer the bus refuses with UDSOTA_TX_RETRY is parked and retried each service (1 ms waits); a hard
 * refusal drops it and counts it. */
static void test_parked_response_retried_after_tx_retry(void)
{
    static const uint8_t tp[] = {0x3E, 0x00};
    s_refuse = 3u;
    TEST_ASSERT_EQUAL_UINT32(0, request_sf(tp, sizeof tp, 0));   /* the feed's send and one service: two refusals */
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_WAIT_SEND_MS, service()); /* the third: still parked */
    TEST_ASSERT_FALSE(s_resp_done);
    service();
    TEST_ASSERT_TRUE(s_resp_done);
    TEST_ASSERT_EQUAL_HEX8(0x7E, s_resp[0]);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_resp_lost(&s_tp));
    s_hard_fail = 1u;
    TEST_ASSERT_EQUAL_UINT32(0, request_sf(tp, sizeof tp, 20));
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_resp_lost(&s_tp));
}

/* A bus that refuses every frame (no node acknowledges) holds a parked answer for UDSOTA_ISOTP_PARK_MAX_MS, then
 * the answer is dropped and counted, and the server's timers run again: S3 ends the open session. */
static void test_parked_answer_dropped_after_limit_and_s3_still_runs(void)
{
    enter_extended();
    static const uint8_t tp[] = {0x3E, 0x00};
    s_refuse = 0xFFFFFFFFu;
    (void)request_sf(tp, sizeof tp, 0);
    run_ms(UDSOTA_ISOTP_PARK_MAX_MS - 10u);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_resp_lost(&s_tp));
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_WAIT_SEND_MS, service());
    run_ms(20);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_resp_lost(&s_tp));
    TEST_ASSERT_FALSE(s_resp_done);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_EXTENDED, s_srv.session);
    run_ms(UDSOTA_S3_MS);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SESSION_DEFAULT, s_srv.session);   /* while the bus still refuses */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, s_phase);
}

/* 11 01's restart waits while its answer is parked, then while the app's driver still holds frames, and
 * fires once both are empty, before the 100 ms fallback. */
static void test_tx_pending_counts_parked_response(void)
{
    enter_extended();
    static const uint8_t reset[] = {0x11, 0x01};
    s_refuse = 1000u;
    (void)request_sf(reset, sizeof reset, 0);
    run_ms(50);
    TEST_ASSERT_EQUAL_UINT(0, s_resets);                 /* the parked 51 01 counts */
    s_refuse = 0u;
    s_driver_pending = 2u;
    run_ms(1);
    TEST_ASSERT_TRUE(s_resp_done);
    TEST_ASSERT_EQUAL_HEX8(0x51, s_resp[0]);
    run_ms(20);
    TEST_ASSERT_EQUAL_UINT(0, s_resets);                 /* the driver's frames count */
    s_driver_pending = 0u;
    run_ms(5);
    TEST_ASSERT_EQUAL_UINT(1, s_resets);                 /* about 72 ms after arming: not the fallback */
}

/* Without can.tx_pending the driver's queue is unknown: 11 01's answer reaches can.send at once, and the restart
 * still waits the full 100 ms, so the answer is not lost in the driver's queue. */
static void test_restart_waits_100_ms_without_tx_pending(void)
{
    s_can.tx_pending = NULL;
    udsota_isotp_init(&s_tp, &s_srv, &s_cfg, &s_hooks, &s_can, &s_bufs);
    enter_extended();
    static const uint8_t reset[] = {0x11, 0x01};
    TEST_ASSERT_EQUAL_UINT32(2, request_sf(reset, sizeof reset, 0));
    run_ms(95);
    TEST_ASSERT_EQUAL_UINT(0, s_resets);
    run_ms(10);
    TEST_ASSERT_EQUAL_UINT(1, s_resets);
}

/* While a restart is armed the adapter polls the server even though the answer is still parked, so the
 * 100 ms fallback fires. */
static void test_armed_restart_falls_back_after_100_ms(void)
{
    enter_extended();
    static const uint8_t reset[] = {0x11, 0x01};
    s_refuse = 100000u;
    (void)request_sf(reset, sizeof reset, 0);
    run_ms(98);
    TEST_ASSERT_EQUAL_UINT(0, s_resets);
    run_ms(3);
    TEST_ASSERT_EQUAL_UINT(1, s_resets);
    TEST_ASSERT_FALSE(s_resp_done);                      /* the answer never left */
}

/* hooks.stmin_us is asked at each message's first FC and sets that FC's STmin. */
static void test_stmin_hook_sets_each_first_fc(void)
{
    s_hooks.stmin_us = hook_stmin;
    init_all();
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* FF of 20 bytes */
    s_hook_stmin = 5000u;
    feed(ff, sizeof ff);
    TEST_ASSERT_EQUAL_HEX8(0x30, s_fc_last[0]);
    TEST_ASSERT_EQUAL_HEX8(0x40, s_fc_last[1]);
    TEST_ASSERT_EQUAL_HEX8(0x05, s_fc_last[2]);
    s_hook_stmin = 2000u;
    feed(ff, sizeof ff);                                 /* a new FF replaces the message */
    TEST_ASSERT_EQUAL_HEX8(0x02, s_fc_last[2]);
    TEST_ASSERT_EQUAL_UINT(2, s_hook_calls);
}

/* An STmin the FC cannot carry is rounded up to one it can: 150 us -> F2, 950 us -> 1 ms, 1.5 ms -> 2 ms,
 * 200 ms -> 127 ms (7F). */
static void test_stmin_rounded_up_to_an_encodable_value(void)
{
    static const struct { uint32_t us; uint8_t fc; } cases[] = {
        {150u, 0xF2}, {900u, 0xF9}, {950u, 0x01}, {1500u, 0x02}, {127000u, 0x7F}, {200000u, 0x7F},
    };
    s_hooks.stmin_us = hook_stmin;
    init_all();
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* FF of 20 bytes */
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        s_hook_stmin = cases[i].us;
        feed(ff, sizeof ff);
        TEST_ASSERT_EQUAL_HEX8(0x30, s_fc_last[0]);
        TEST_ASSERT_EQUAL_HEX8(cases[i].fc, s_fc_last[2]);
    }
}

/* The STmin monitor judges the STmin the FC sent: asked for 200 ms, the FC says 127 ms, and a client that keeps
 * 127 ms gaps finishes the block; asked for 950 us, the FC says 1 ms, and a client at 1 ms passes. */
static void test_stmin_monitor_judges_the_sent_stmin(void)
{
    s_hooks.stmin_us = hook_stmin;
    init_all();
    open_download(DATA_LEN + 700u);
    build_block(1);
    s_hook_stmin = 200000u;
    request_mf(s_block, BLOCK_LEN, 127000u, 0u);
    TEST_ASSERT_TRUE(s_resp_done);
    TEST_ASSERT_EQUAL_HEX8(0x76, s_resp[0]);
    build_block(2);
    s_hook_stmin = 950u;
    s_written = 0u;
    request_mf(s_block, 2u + 700u, 1000u, 0u);           /* 99 CFs: the FC at CF 64 is judged */
    TEST_ASSERT_TRUE(run_until_response(50));
    TEST_ASSERT_EQUAL_HEX8(0x76, s_resp[0]);
    TEST_ASSERT_EQUAL_UINT16(0, read_counters().withheld_fcs);
}

/* The gate refuses CONTINUE_TRANSFER at CF 64. The FC is withheld, the rest of the block is
 * ignored, the transfer and session end and are counted, and the next request is served normally. */
static void test_gate_deny_at_fc_point_withholds_fc(void)
{
    open_download(DATA_LEN);
    build_block(1);
    s_fc_n = 0u;
    request_mf(s_block, BLOCK_LEN, CF_GAP_US, 64u);
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);                   /* the FF's only */
    TEST_ASSERT_FALSE(s_resp_done);
    TEST_ASSERT_EQUAL_UINT32(0, s_written);
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, s_phase);
    s_gate_op = (udsota_op_t)0;
    TEST_ASSERT_EQUAL_UINT8(1, read_session());
    const udsota_counters_t c = read_counters();
    TEST_ASSERT_EQUAL_UINT16(1, c.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(1, c.aborts);
}

/* Counts the frames logged from index `from` on whose first n bytes equal want. */
static unsigned frames_since(unsigned from, const uint8_t *want, size_t n)
{
    unsigned c = 0;
    for (unsigned i = from; i < s_log_n; i++) {
        if (memcmp(s_log[i], want, n) == 0) {
            c++;
        }
    }
    return c;
}

/* end_session while the worker's write is PENDING. The core latches it: the job keeps its
 * 0x78 and its 76, then the session ends at the next poll, which aborts the transfer and drops the limit to 256. */
static void test_end_session_while_write_pending(void)
{
    open_download(DATA_LEN);
    build_block(1);
    s_write_rc = UDSOTA_PENDING;
    s_poll_rc = UDSOTA_PENDING;
    request_mf(s_block, BLOCK_LEN, CF_GAP_US, 0u);
    TEST_ASSERT_EQUAL_UINT32(DATA_LEN, s_written);
    TEST_ASSERT_FALSE(s_resp_done);
    udsota_end_session(&s_srv, now_ms());
    const unsigned mark = s_log_n;
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_TRANSFERRING, s_phase);   /* latched, not applied */
    TEST_ASSERT_EQUAL_UINT(0, s_aborts);
    run_ms(50);
    static const uint8_t pending[4] = {0x03, 0x7F, 0x36, 0x78};
    TEST_ASSERT_EQUAL_UINT(1, frames_since(mark, pending, sizeof pending));
    TEST_ASSERT_EQUAL_UINT(mark + 1u, s_log_n);
    resp_clear();
    s_poll_rc = 0;                                       /* the write finishes */
    s_write_rc = 0;
    TEST_ASSERT_TRUE(run_until_response(20));
    static const uint8_t pos[] = {0x76, 0x01};
    TEST_ASSERT_EQUAL_UINT32(sizeof pos, s_resp_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(pos, s_resp, sizeof pos);
    service();                                           /* the next poll applies the latch */
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, s_phase);
    TEST_ASSERT_EQUAL_UINT(1, s_aborts);
    static const uint8_t ff300[8] = {0x11, 0x2C, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};
    feed(ff300, sizeof ff300);
    TEST_ASSERT_EQUAL_HEX8(0x32, s_fc_last[0]);          /* back to the 256 limit */
    TEST_ASSERT_EQUAL_UINT8(1, read_session());
    static const uint8_t td[] = {0x36, 0x02, 0xAB};
    TEST_ASSERT_EQUAL_UINT32(3, request_sf(td, sizeof td, 20));
    static const uint8_t nrc[] = {0x7F, 0x36, 0x7F};     /* not supported in the default session */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(nrc, s_resp, sizeof nrc);
}

/* A FC withheld while an answer is still sending leaves isotp-c's copy as an orphan: its N_Cr is not
 * counted. A plain abandoned message still counts one. */
static void test_withheld_fc_during_send_orphan_ncr_not_counted(void)
{
    open_download(DATA_LEN);
    static const uint8_t f18c[] = {0x22, 0xF1, 0x8C};    /* a 9-byte answer: FF, then CFs after our FC */
    s_auto_fc = false;
    (void)request_sf(f18c, sizeof f18c, 0);
    build_block(1);
    request_mf(s_block, BLOCK_LEN, CF_GAP_US, 64u);      /* the adapter's send is still in progress at CF 64 */
    run_ms(1200);                                        /* N_Bs ends that send, N_Cr ends the orphan */
    s_auto_fc = true;
    s_gate_op = (udsota_op_t)0;
    udsota_counters_t c = read_counters();
    TEST_ASSERT_EQUAL_UINT16(1, c.withheld_fcs);
    TEST_ASSERT_EQUAL_UINT16(0, c.ncr_timeouts);
    static const uint8_t ff20[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};
    feed(ff20, sizeof ff20);
    run_ms(1100);
    c = read_counters();
    TEST_ASSERT_EQUAL_UINT16(1, c.ncr_timeouts);
}

/* Intake: a request that arrives while the previous answer is still parked waits in isotp-c and is served only
 * once that answer has left, so neither answer is replaced. */
static void test_request_waits_for_parked_answer(void)
{
    static const uint8_t tp[] = {0x3E, 0x00};
    s_refuse = 2u;
    TEST_ASSERT_EQUAL_UINT32(0, request_sf(tp, sizeof tp, 0));   /* the feed's send and one service: parked */
    static const uint8_t sf[4] = {0x03, 0x22, 0xF1, 0x86};
    feed(sf, sizeof sf);                                          /* waits: the 7E is still parked */
    TEST_ASSERT_EQUAL_UINT(0, s_log_n);
    service();
    TEST_ASSERT_EQUAL_UINT(2, s_log_n);
    static const uint8_t first[3] = {0x02, 0x7E, 0x00};
    static const uint8_t second[5] = {0x04, 0x62, 0xF1, 0x86, 0x01};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first, s_log[0], sizeof first);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(second, s_log[1], sizeof second);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_resp_lost(&s_tp));
}

/* An FC the bus refuses with UDSOTA_TX_RETRY is parked and retried each service (1 ms waits); one still refused
 * UDSOTA_ISOTP_FC_RETRY_MS after it was parked, or refused outright, is counted lost. */
static void test_refused_fc_parked_and_retried(void)
{
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* FF of 20 bytes */
    s_refuse = 3u;
    feed(ff, sizeof ff);                                 /* refused once */
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_WAIT_SEND_MS, service());   /* twice, still parked */
    run_ms(1);                                           /* three times */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    run_ms(1);
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(s_fc_want, s_fc_last, 3);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_fc_lost(&s_tp));

    init_all();
    s_refuse = 100000u;
    feed(ff, sizeof ff);
    service();
    run_ms(UDSOTA_ISOTP_FC_RETRY_MS - 1u);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_fc_lost(&s_tp));
    run_ms(1);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);                   /* no second FC reached the bus */

    init_all();
    s_refuse = 0u;
    s_hard_fail = 1u;
    feed(ff, sizeof ff);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_WAIT_OPEN_MS, service());   /* nothing parked: mid-message wait */
}

/* cfg.fc_retry_ms sets the window (40 ms here, as for a 50 frames/s response cap). The cadence is unchanged, one
 * attempt per service: a bus that frees on the attempt at +40 ms still gets the FC, and one that never frees has
 * the FC counted lost at +40 ms, not at the default 10. */
static void test_fc_retry_window_follows_cfg(void)
{
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* FF of 20 bytes */
    s_fc_retry_ms = 40u;
    init_all();
    s_refuse = 2u + 39u;                                 /* the feed, the service at +0, then +1 .. +39 ms */
    feed(ff, sizeof ff);
    service();
    run_ms(39);
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_fc_lost(&s_tp));
    run_ms(1);                                           /* +40 ms: the last attempt in the window goes out */
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(s_fc_want, s_fc_last, 3);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_fc_lost(&s_tp));

    init_all();
    s_fc_n = 0u;
    s_refuse = 100000u;
    feed(ff, sizeof ff);
    service();
    run_ms(39);
    TEST_ASSERT_EQUAL_UINT32(0, udsota_isotp_fc_lost(&s_tp));   /* past the default 10 ms, still parked */
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_ISOTP_WAIT_SEND_MS, service());
    run_ms(1);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
    s_refuse = 0u;                                       /* the bus frees, too late */
    run_ms(20);
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);                   /* dropped: never retried after +40 ms */
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
}

/* A parked FC is superseded by a newer FC: once a later FF's FC has gone out directly, the stale one (STmin 5 ms)
 * is dropped and counted, never sent after it. */
static void test_parked_fc_never_sent_after_newer_fc(void)
{
    s_hooks.stmin_us = hook_stmin;
    init_all();
    static const uint8_t ff[8] = {0x10, 0x14, 0x22, 0xF1, 0x86, 0x00, 0x00, 0x00};   /* FF of 20 bytes */
    s_hook_stmin = 5000u;
    s_refuse = 1u;
    feed(ff, sizeof ff);                                 /* FC 30 40 05 refused: parked */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    s_hook_stmin = 2000u;
    feed(ff, sizeof ff);                                 /* a new FF: FC 30 40 02 goes out at once */
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);
    run_ms(UDSOTA_ISOTP_FC_RETRY_MS + 5u);
    TEST_ASSERT_EQUAL_UINT(1, s_fc_n);                   /* the stale 30 40 05 never follows it */
    TEST_ASSERT_EQUAL_HEX8(0x02, s_fc_last[2]);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
}

/* A parked FC dies with its link: a second FF withheld at the gate re-initialises the link, and the first FF's
 * parked CTS is dropped and counted instead of inviting CFs for a message the adapter no longer holds. */
static void test_link_init_drops_parked_fc(void)
{
    open_download(DATA_LEN);
    build_block(1);
    const uint8_t ff[8] = {0x1F, 0xFF, s_block[0], s_block[1], s_block[2], s_block[3], s_block[4], s_block[5]};
    s_fc_n = 0u;
    s_refuse = 1u;
    feed(ff, sizeof ff);                                 /* FF of the 4,095-byte 36: its FC refused, parked */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    s_gate_op = UDSOTA_OP_CONTINUE_TRANSFER;
    s_gate_nrc = 0x22u;
    feed(ff, sizeof ff);                                 /* the FF again, withheld: the link is re-initialised */
    run_ms(UDSOTA_ISOTP_FC_RETRY_MS + 5u);
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, s_phase);
}

/* A parked FC dies with an orphaned message too: FF1's CTS is parked while our multi-frame answer is still going
 * out, then the gate withholds FF2, which leaves isotp-c's copy as an orphan without a link re-init. The parked
 * CTS must never go out. */
static void test_orphan_drops_parked_fc(void)
{
    open_download(DATA_LEN);
    static const uint8_t f18c[] = {0x22, 0xF1, 0x8C};    /* a 9-byte answer: FF, then CFs after our FC */
    s_auto_fc = false;
    (void)request_sf(f18c, sizeof f18c, 0);              /* its send stays in progress */
    build_block(1);
    const uint8_t ff[8] = {0x1F, 0xFF, s_block[0], s_block[1], s_block[2], s_block[3], s_block[4], s_block[5]};
    s_fc_n = 0u;
    s_refuse = 1u;
    feed(ff, sizeof ff);                                 /* FF1: its CTS refused, parked */
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    s_gate_op = UDSOTA_OP_CONTINUE_TRANSFER;
    s_gate_nrc = 0x22u;
    feed(ff, sizeof ff);                                 /* FF2, withheld: isotp-c's copy becomes an orphan */
    run_ms(UDSOTA_ISOTP_FC_RETRY_MS + 5u);
    TEST_ASSERT_EQUAL_UINT(0, s_fc_n);
    TEST_ASSERT_EQUAL_UINT32(1, udsota_isotp_fc_lost(&s_tp));
    TEST_ASSERT_EQUAL_INT(UDSOTA_PHASE_IDLE, s_phase);
}

/* Unity runner. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_single_frame_request_and_response);
    RUN_TEST(test_functional_single_frame_only);
    RUN_TEST(test_functional_dropped_during_a_physical_request);
    RUN_TEST(test_4095_byte_block_with_fc_every_64_cfs);
    RUN_TEST(test_receive_limit_256_outside_a_download);
    RUN_TEST(test_parked_response_retried_after_tx_retry);
    RUN_TEST(test_parked_answer_dropped_after_limit_and_s3_still_runs);
    RUN_TEST(test_tx_pending_counts_parked_response);
    RUN_TEST(test_armed_restart_falls_back_after_100_ms);
    RUN_TEST(test_restart_waits_100_ms_without_tx_pending);
    RUN_TEST(test_stmin_hook_sets_each_first_fc);
    RUN_TEST(test_stmin_rounded_up_to_an_encodable_value);
    RUN_TEST(test_stmin_monitor_judges_the_sent_stmin);
    RUN_TEST(test_gate_deny_at_fc_point_withholds_fc);
    RUN_TEST(test_end_session_while_write_pending);
    RUN_TEST(test_withheld_fc_during_send_orphan_ncr_not_counted);
    RUN_TEST(test_request_waits_for_parked_answer);
    RUN_TEST(test_refused_fc_parked_and_retried);
    RUN_TEST(test_fc_retry_window_follows_cfg);
    RUN_TEST(test_parked_fc_never_sent_after_newer_fc);
    RUN_TEST(test_link_init_drops_parked_fc);
    RUN_TEST(test_orphan_drops_parked_fc);
    return UNITY_END();
}
