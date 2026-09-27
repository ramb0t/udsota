/* Host loopback tests for components/isotp: a tester link and a server link (the device) run back
 * to back over an in-memory bus the test pumps, with a fake microsecond clock. Pins the per-link
 * BS/STmin port, the 1 s N_Cr, the overflow FC and the NOSPACE retry of the unpatched fork. */
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "isotp.h"
#include "isotp_port.h"

#define REQ_ID   0x710u   /* tester -> server (diag request) */
#define RESP_ID  0x718u   /* server -> tester (diag response) */
#define STEP_US  100u     /* fake clock advance per pump step */
#define MAX_STEPS 200000u /* pump cap: fail instead of hanging */
#define QCAP     64u
#define LOGCAP   2048u

enum { NODE_TESTER = 0, NODE_SERVER = 1 };

/* Link owner context: cfg MUST be the first member (isotp_port reads user_send_can_arg as cfg). */
typedef struct {
    isotp_link_cfg_t cfg;
    int              node;
} test_link_ctx_t;

typedef struct {
    uint32_t id;
    uint8_t  len;
    uint8_t  data[8];
    uint32_t t_us;
} frame_t;

static uint32_t s_now_us;
static frame_t  s_q[QCAP];            /* frames on the wire, not yet delivered */
static unsigned s_q_head, s_q_tail;
static frame_t  s_log[LOGCAP];        /* every frame accepted onto the bus, in order */
static unsigned s_log_n;
static unsigned s_send_calls[2];      /* send attempts per node, NOSPACE included */
static unsigned s_nospace_at[2];      /* 1-based attempt number that returns NOSPACE; 0 = never */
static unsigned s_nospace_hits;

static IsoTpLink       s_tester, s_server;
static test_link_ctx_t s_tester_ctx, s_server_ctx;
static uint8_t         s_tester_tx[4200], s_tester_rx[4200];
static uint8_t         s_server_tx[4200], s_server_rx[4200];

/* isotp-c platform hook: diagnostics are ignored on the host. */
void isotp_user_debug(const char *message, ...)
{
    (void)message;
}

/* isotp-c platform hook: the fake clock. */
uint32_t isotp_user_get_us(void)
{
    return s_now_us;
}

/* isotp-c platform hook: put one frame on the fake bus, or report NOSPACE once when armed. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    const test_link_ctx_t *ctx = (const test_link_ctx_t *)arg;
    TEST_ASSERT_NOT_NULL_MESSAGE(ctx, "user_send_can_arg not set");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(8, size, "ISO_TP_FRAME_PADDING must pad every frame to 8");
    unsigned n = ++s_send_calls[ctx->node];
    if (s_nospace_at[ctx->node] == n) {
        s_nospace_hits++;
        return ISOTP_RET_NOSPACE;
    }
    TEST_ASSERT_TRUE_MESSAGE(s_q_tail - s_q_head < QCAP, "fake bus queue full");
    frame_t f = {.id = arbitration_id, .len = size, .t_us = s_now_us};
    memcpy(f.data, data, size);
    s_q[s_q_tail++ % QCAP] = f;
    TEST_ASSERT_TRUE_MESSAGE(s_log_n < LOGCAP, "frame log full");
    s_log[s_log_n++] = f;
    return ISOTP_RET_OK;
}

/* Initialise both links: tester sends on REQ_ID, server on RESP_ID, each with its own cfg. */
static void links_init(uint32_t server_rx_size, isotp_link_cfg_t server_cfg, isotp_link_cfg_t tester_cfg)
{
    isotp_init_link(&s_tester, REQ_ID, s_tester_tx, sizeof s_tester_tx, s_tester_rx, sizeof s_tester_rx);
    isotp_init_link(&s_server, RESP_ID, s_server_tx, sizeof s_server_tx, s_server_rx, server_rx_size);
    s_tester_ctx = (test_link_ctx_t){.cfg = tester_cfg, .node = NODE_TESTER};
    s_server_ctx = (test_link_ctx_t){.cfg = server_cfg, .node = NODE_SERVER};
    s_tester.user_send_can_arg = &s_tester_ctx;
    s_server.user_send_can_arg = &s_server_ctx;
}

/* Deliver every queued frame, one at a time (a delivery can queue an FC), to the link it addresses. */
static void deliver_all(void)
{
    while (s_q_head != s_q_tail) {
        frame_t f = s_q[s_q_head++ % QCAP];
        isotp_on_can_message(f.id == REQ_ID ? &s_server : &s_tester, f.data, f.len);
    }
}

/* Pump the bus: deliver, advance the clock, poll both links, until neither link is busy. */
static void pump(void)
{
    for (unsigned step = 0; step < MAX_STEPS; step++) {
        deliver_all();
        if (s_tester.send_status != ISOTP_SEND_STATUS_INPROGRESS &&
            s_server.send_status != ISOTP_SEND_STATUS_INPROGRESS &&
            s_tester.receive_status != ISOTP_RECEIVE_STATUS_INPROGRESS &&
            s_server.receive_status != ISOTP_RECEIVE_STATUS_INPROGRESS) {
            return;
        }
        s_now_us += STEP_US;
        isotp_poll(&s_tester);
        isotp_poll(&s_server);
    }
    TEST_FAIL_MESSAGE("pump: transfer did not finish within MAX_STEPS");
}

/* Deterministic payload byte i. */
static uint8_t pattern(uint32_t i)
{
    return (uint8_t)(i * 7u + 3u);
}

/* Tester sends n pattern bytes; the pump runs until both links are idle. */
static void tester_send(uint32_t n)
{
    static uint8_t msg[4200];
    for (uint32_t i = 0; i < n; i++) {
        msg[i] = pattern(i);
    }
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_send(&s_tester, msg, n));
    pump();
}

/* Count frames in the log with this ID whose first nibble is this PCI type. */
static unsigned count_frames(uint32_t id, uint8_t pci_type)
{
    unsigned n = 0;
    for (unsigned i = 0; i < s_log_n; i++) {
        if (s_log[i].id == id && (s_log[i].data[0] >> 4) == pci_type) {
            n++;
        }
    }
    return n;
}

/* Reset the fake clock, bus, log and NOSPACE injection before each test. */
void setUp(void)
{
    s_now_us = 1000u;
    s_q_head = s_q_tail = 0;
    s_log_n = 0;
    memset(s_send_calls, 0, sizeof s_send_calls);
    memset(s_nospace_at, 0, sizeof s_nospace_at);
    s_nospace_hits = 0;
}

/* Nothing to release after a test. */
void tearDown(void) {}

static const isotp_link_cfg_t FAST_CFG = {.bs = 64, .st_min_us = 2000};
static const isotp_link_cfg_t SLOW_CFG = {.bs = 64, .st_min_us = 5000};
static const isotp_link_cfg_t TESTER = {.bs = 8, .st_min_us = 0};

/* Receive the server's completed message and check it is n pattern bytes. */
static void assert_server_got(uint32_t n)
{
    static uint8_t got[4200];
    uint32_t got_n = 0;
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_receive(&s_server, got, sizeof got, &got_n));
    TEST_ASSERT_EQUAL_UINT32(n, got_n);
    for (uint32_t i = 0; i < n; i++) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(pattern(i), got[i], "payload byte mismatch");
    }
    TEST_ASSERT_EQUAL_INT(ISOTP_SEND_STATUS_IDLE, s_tester.send_status);
    TEST_ASSERT_EQUAL_INT(ISOTP_PROTOCOL_RESULT_OK, s_tester.send_protocol_result);
}

/* A 4093-byte message (the largest 0x36 data field) reassembles byte for byte. */
static void test_4093_byte_message_reassembles(void)
{
    links_init(4095, FAST_CFG, TESTER);
    tester_send(4093);
    assert_server_got(4093);
    /* FF carries 6 bytes; 4087 more at 7 per CF is 584 CFs. */
    TEST_ASSERT_EQUAL_UINT(584, count_frames(REQ_ID, 2));
}

/* Assert the server's FCs: BS 64, this STmin byte, 0xAA padding, one after the FF and then one
 * after every 64th CF only; return how many there were. */
static unsigned assert_one_fc_per_64_cfs(uint8_t st_min_byte)
{
    unsigned cfs = 0, fcs = 0;
    for (unsigned i = 0; i < s_log_n; i++) {
        const frame_t *f = &s_log[i];
        if (f->id == REQ_ID && (f->data[0] >> 4) == 2) {
            cfs++;
        } else if (f->id == RESP_ID) {
            const uint8_t want[8] = {0x30, 0x40, st_min_byte, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
            TEST_ASSERT_EQUAL_HEX8_ARRAY(want, f->data, 8);
            TEST_ASSERT_EQUAL_UINT_MESSAGE(fcs * 64u, cfs, "FC not on a 64-CF boundary");
            fcs++;
        }
    }
    return fcs;
}

/* Exactly one FC per 64 CFs at BS 64: 4093 bytes is 584 CFs, so the FF's FC plus 9 more. */
static void test_one_fc_per_64_cfs(void)
{
    links_init(4095, FAST_CFG, TESTER);
    tester_send(4093);
    TEST_ASSERT_EQUAL_UINT(10, assert_one_fc_per_64_cfs(0x02));
}

/* A full 0x36 on the wire (36 ctr + 4093 data = 4095 bytes, FF_DL 0xFFF) fills a 4095-byte buffer:
 * 585 CFs and 10 FCs. */
static void test_4095_byte_block_fills_buffer(void)
{
    links_init(4095, FAST_CFG, TESTER);
    tester_send(4095);
    assert_server_got(4095);
    TEST_ASSERT_EQUAL_HEX8(0x1F, s_log[0].data[0]);   /* FF, FF_DL high nibble 0xF */
    TEST_ASSERT_EQUAL_HEX8(0xFF, s_log[0].data[1]);
    TEST_ASSERT_EQUAL_UINT(585, count_frames(REQ_ID, 2));
    TEST_ASSERT_EQUAL_UINT(10, assert_one_fc_per_64_cfs(0x02));
}

/* Each link advertises its own BS and STmin: the server (BS 64, 5 ms) and the tester (BS 8, 0). */
static void test_per_link_bs_and_st_min(void)
{
    links_init(4095, SLOW_CFG, TESTER);
    tester_send(100);
    assert_server_got(100);
    TEST_ASSERT_EQUAL_UINT(1, assert_one_fc_per_64_cfs(0x05));   /* 94 bytes = 14 CFs, one FC */

    /* Server answers 100 bytes; the tester's FC carries the tester's own BS 8 and STmin 0. */
    static uint8_t resp[100];
    memset(resp, 0x5A, sizeof resp);
    unsigned first = s_log_n;
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_send(&s_server, resp, sizeof resp));
    pump();
    unsigned tester_fcs = 0;
    uint32_t last_cf_t = 0;
    for (unsigned i = first; i < s_log_n; i++) {
        const frame_t *f = &s_log[i];
        if (f->id == REQ_ID) {
            const uint8_t want[8] = {0x30, 0x08, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
            TEST_ASSERT_EQUAL_HEX8_ARRAY(want, f->data, 8);
            tester_fcs++;
        } else if ((f->data[0] >> 4) == 2) {
            /* The server paces its own CFs at max(peer STmin 0, own 5 ms) (isotp.c:684-686). */
            if (last_cf_t) {
                TEST_ASSERT_GREATER_OR_EQUAL_UINT32(5000u, f->t_us - last_cf_t);
            }
            last_cf_t = f->t_us;
        }
    }
    TEST_ASSERT_EQUAL_UINT(2, tester_fcs);   /* 94 bytes = 14 CFs at BS 8: FF's FC + one after CF 8 */
    uint8_t got[100];
    uint32_t got_n = 0;
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_receive(&s_tester, got, sizeof got, &got_n));
    TEST_ASSERT_EQUAL_UINT32(100, got_n);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x5A, got, 100);
}

/* A cfg change is used from the next FC: STmin 2 ms becomes 5 ms between messages. */
static void test_cfg_change_applies_to_next_message(void)
{
    links_init(4095, FAST_CFG, TESTER);
    tester_send(20);
    TEST_ASSERT_EQUAL_HEX8(0x02, s_log[1].data[2]);
    s_server_ctx.cfg = SLOW_CFG;
    unsigned first = s_log_n;
    tester_send(20);
    TEST_ASSERT_EQUAL_UINT32(RESP_ID, s_log[first + 1].id);
    TEST_ASSERT_EQUAL_HEX8(0x05, s_log[first + 1].data[2]);
}

/* An FF larger than the receive buffer gets one overflow FC (FS 2) and no CF follows. */
static void test_oversized_ff_gets_overflow_fc(void)
{
    links_init(256, FAST_CFG, TESTER);
    tester_send(300);
    TEST_ASSERT_EQUAL_UINT(2, s_log_n);   /* the FF and the overflow FC, nothing else */
    const uint8_t want[8] = {0x32, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    TEST_ASSERT_EQUAL_UINT32(RESP_ID, s_log[1].id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, s_log[1].data, 8);
    TEST_ASSERT_EQUAL_INT(ISOTP_RECEIVE_STATUS_IDLE, s_server.receive_status);
    TEST_ASSERT_EQUAL_INT(ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW, s_server.receive_protocol_result);
    TEST_ASSERT_EQUAL_INT(ISOTP_SEND_STATUS_ERROR, s_tester.send_status);
    TEST_ASSERT_EQUAL_INT(ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW, s_tester.send_protocol_result);
}

/* 4096 bytes takes the long-FF escape (FF_DL 0 + 32-bit length) and still gets the overflow FC. */
static void test_long_ff_4096_gets_overflow_fc(void)
{
    links_init(4095, FAST_CFG, TESTER);
    tester_send(4096);
    const uint8_t ff_head[6] = {0x10, 0x00, 0x00, 0x00, 0x10, 0x00};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ff_head, s_log[0].data, 6);
    TEST_ASSERT_EQUAL_UINT(2, s_log_n);
    TEST_ASSERT_EQUAL_HEX8(0x32, s_log[1].data[0]);
    TEST_ASSERT_EQUAL_INT(ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW, s_server.receive_protocol_result);
}

/* A NOSPACE from the driver on a CF is retried with the same SN on the very next poll. */
static void test_nospace_retries_the_cf_next_poll(void)
{
    links_init(4095, FAST_CFG, TESTER);
    s_nospace_at[NODE_TESTER] = 3;   /* attempt 1 = FF, 2 = CF SN 1, 3 = CF SN 2 */
    static uint8_t msg[200];
    for (uint32_t i = 0; i < sizeof msg; i++) {
        msg[i] = pattern(i);
    }
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_send(&s_tester, msg, sizeof msg));
    deliver_all();                              /* FF in, FC out, FC in */
    s_now_us += 2001u;
    isotp_poll(&s_tester);                      /* CF SN 1 */
    s_now_us += 2001u;
    isotp_poll(&s_tester);                      /* CF SN 2 -> NOSPACE */
    TEST_ASSERT_EQUAL_UINT(1, s_nospace_hits);
    TEST_ASSERT_EQUAL_HEX8(0x21, s_log[s_log_n - 1].data[0]);
    isotp_poll(&s_tester);                      /* same time: retried, SN 2 */
    TEST_ASSERT_EQUAL_UINT(4, s_send_calls[NODE_TESTER]);
    TEST_ASSERT_EQUAL_HEX8(0x22, s_log[s_log_n - 1].data[0]);
    TEST_ASSERT_EQUAL_INT(ISOTP_SEND_STATUS_INPROGRESS, s_tester.send_status);
    pump();
    assert_server_got(200);
    TEST_ASSERT_EQUAL_UINT(28, count_frames(REQ_ID, 2));   /* 194 bytes / 7 = 28 CFs, none lost */
}

/* N_Cr is 1 s (ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US): still receiving at FF + 1 000 000 us, timed
 * out 1 us later (IsoTpTimeAfter is strict). */
static void test_n_cr_is_one_second(void)
{
    links_init(4095, FAST_CFG, TESTER);
    static uint8_t msg[100];
    TEST_ASSERT_EQUAL_INT(ISOTP_RET_OK, isotp_send(&s_tester, msg, sizeof msg));
    uint32_t t_ff = s_now_us;
    deliver_all();                              /* server takes the FF and sends its FC */
    TEST_ASSERT_EQUAL_INT(ISOTP_RECEIVE_STATUS_INPROGRESS, s_server.receive_status);
    s_now_us = t_ff + 1000000u;
    isotp_poll(&s_server);
    TEST_ASSERT_EQUAL_INT(ISOTP_RECEIVE_STATUS_INPROGRESS, s_server.receive_status);
    s_now_us = t_ff + 1000001u;
    isotp_poll(&s_server);
    TEST_ASSERT_EQUAL_INT(ISOTP_RECEIVE_STATUS_IDLE, s_server.receive_status);
    TEST_ASSERT_EQUAL_INT(ISOTP_PROTOCOL_RESULT_TIMEOUT_CR, s_server.receive_protocol_result);
}

/* Accessor fallbacks: no cfg -> BS 64 / STmin 5000; bs 0 -> 64; STmin above 127 ms clamps. */
static void test_port_accessor_fallbacks(void)
{
    IsoTpLink l;
    isotp_init_link(&l, RESP_ID, s_server_tx, sizeof s_server_tx, s_server_rx, 256);
    TEST_ASSERT_NULL(l.user_send_can_arg);
    TEST_ASSERT_EQUAL_UINT8(64, isotp_port_bs(&l));
    TEST_ASSERT_EQUAL_UINT32(5000, isotp_port_st_min_us(&l));
    TEST_ASSERT_EQUAL_UINT8(64, isotp_port_bs(NULL));
    TEST_ASSERT_EQUAL_UINT32(5000, isotp_port_st_min_us(NULL));

    test_link_ctx_t ctx = {.cfg = {.bs = 0, .st_min_us = 200000}, .node = NODE_SERVER};
    l.user_send_can_arg = &ctx;
    TEST_ASSERT_EQUAL_UINT8(64, isotp_port_bs(&l));
    TEST_ASSERT_EQUAL_UINT32(127000, isotp_port_st_min_us(&l));
    ctx.cfg = (isotp_link_cfg_t){.bs = 16, .st_min_us = 2000};
    TEST_ASSERT_EQUAL_UINT8(16, isotp_port_bs(&l));
    TEST_ASSERT_EQUAL_UINT32(2000, isotp_port_st_min_us(&l));
}

/* Runs every ISO-TP loopback test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_4093_byte_message_reassembles);
    RUN_TEST(test_one_fc_per_64_cfs);
    RUN_TEST(test_4095_byte_block_fills_buffer);
    RUN_TEST(test_per_link_bs_and_st_min);
    RUN_TEST(test_cfg_change_applies_to_next_message);
    RUN_TEST(test_oversized_ff_gets_overflow_fc);
    RUN_TEST(test_long_ff_4096_gets_overflow_fc);
    RUN_TEST(test_nospace_retries_the_cf_next_poll);
    RUN_TEST(test_n_cr_is_one_second);
    RUN_TEST(test_port_accessor_fallbacks);
    return UNITY_END();
}
