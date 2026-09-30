/* End-to-end host test of the proof of concept: iso14229's server on its mock transport, udsota_iso14229 binding the
 * updater, and a RAM engine whose jobs stay pending for a few polls as the ESP32 worker's do. A tester transport
 * sends raw requests; the clock is the test's (UDS_CUSTOM_MILLIS). It covers a whole update (10 02, 27 03/04, 34,
 * 36s through 0x78, 37, FF01, F001 and the restart, F002 after it) and the edges where the binding keeps the two
 * sides in step: a resent block, S3 across a long session, relock on a session change, 10 02 during a transfer. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iso14229.h"
#include "udsota.h"
#include "udsota_iso14229.h"

#define TESTER 0x7E0u
#define SERVER 0x7E8u

static uint32_t g_now = 1000u;
uint32_t UDSMillis(void)
{
    return g_now;
}

static int g_failures;
#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                   \
            g_failures++;                                                                                \
        }                                                                                                \
    } while (0)

/* ---- RAM engine: every flash op is a job that stays pending for a few polls ---- */

#define SLOT_SIZE (256u * 1024u)
static uint8_t  s_slot[SLOT_SIZE];
static const uint8_t *s_expect;       /* the image the test sends; verify compares against it */
static bool s_hang;                   /* verify never finishes: the worker hangs */
static struct {
    int      polls_left, result;
    uint32_t size;
    uint8_t  running_slot, boot_slot, running_state;
    int      aborts, activations, confirms;
} E;

static int queue(int result, int polls)
{
    E.result = (E.polls_left > 0 && E.result != 0) ? E.result : result;
    E.polls_left += polls;
    return UDSOTA_PENDING;
}
static int eng_check_first(void *c, const uint8_t *f, size_t n, udsota_reason_t *why)
{
    (void)c; (void)f; (void)n; (void)why;
    return 0;
}
static int eng_begin(void *c, uint32_t size)
{
    (void)c;
    E.size = size;
    memset(s_slot, 0xFF, sizeof s_slot);
    return queue(0, 80);                    /* an erase: long enough that iso14229 sends 0x78 */
}
static int eng_write(void *c, uint32_t off, const uint8_t *d, size_t n)
{
    (void)c;
    if ((size_t)off + n > sizeof s_slot) {
        return -1;
    }
    memcpy(&s_slot[off], d, n);
    return queue(0, 2);
}
static int eng_verify(void *c)
{
    (void)c;
    const bool same = s_expect != NULL && memcmp(s_slot, s_expect, E.size) == 0;
    return queue(same ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED, s_hang ? 100000000 : 80);
}
static int eng_activate(void *c)
{
    (void)c;
    E.boot_slot = (uint8_t)(1u - E.running_slot);
    E.activations++;
    return queue(0, 2);
}
static int eng_confirm(void *c)
{
    (void)c;
    E.running_state = UDSOTA_IMG_VALID;
    E.confirms++;
    return 0;
}
static void eng_abort(void *c)
{
    (void)c;
    E.aborts++;
}
static int eng_poll(void *c)
{
    (void)c;
    if (E.polls_left > 0) {
        E.polls_left--;
        return UDSOTA_PENDING;
    }
    return E.result;
}
static void eng_status(void *c, udsota_status_t *st)
{
    (void)c;
    st->running_slot = E.running_slot;
    st->boot_slot = E.boot_slot;
    st->running_state = E.running_state;
}
static size_t eng_version(void *c, char *out, size_t max)
{
    (void)c;
    static const char v[] = "test-1.0";
    if (max < sizeof v - 1u) {
        return 0;
    }
    memcpy(out, v, sizeof v - 1u);
    return sizeof v - 1u;
}
static const udsota_engine_t k_engine = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_verify,
    .activate = eng_activate, .confirm = eng_confirm, .abort = eng_abort, .poll = eng_poll, .status = eng_status,
    .version = eng_version, .slot_size = SLOT_SIZE,
};

/* ---- Test security: the key is the seed XOR the level ---- */

static uint8_t s_seed_ctr;
static bool sec_rng16(void *c, uint8_t out[16])
{
    (void)c;
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0xA0u + s_seed_ctr + i);
    }
    s_seed_ctr++;
    return true;
}
static bool sec_key(void *c, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    (void)c;
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level);
    }
    return true;
}
static const udsota_security_t k_sec = { .rng16 = sec_rng16, .key = sec_key };

/* ---- The server, as an app runs it ---- */

static const uint8_t k_devid[6] = {0x02, 0, 0, 0, 0, 0x01};
static UDSServer_t       s_srv;
static udsota_iso14229_t s_upd;
static UDSTp_t          *s_tester;
static UDSTp_t          *s_server_tp;
static int               s_resets;

static UDSErr_t app_fn(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_iso14229_event(&s_upd, srv, ev, arg, &rc)) {
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent:
        return UDS_NRC_RequestOutOfRange;
    case UDS_EVT_SessionTimeout:
    case UDS_EVT_Err:
        return UDS_OK;
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

static uint8_t s_gate_36;             /* the gate's answer to CONTINUE_TRANSFER */
static uint8_t gate(void *ctx, udsota_op_t op)
{
    (void)ctx;
    return (op == UDSOTA_OP_CONTINUE_TRANSFER) ? s_gate_36 : 0u;
}

static void do_reset(void *ctx)
{
    (void)ctx;
    s_resets++;
}

/* A fresh server over the engine's current state, as after a boot. */
static void boot(void)
{
    ISOTPMockReset();
    const ISOTPMockArgs_t sa = { .sa_phys = SERVER, .ta_phys = TESTER };
    const ISOTPMockArgs_t ta = { .sa_phys = TESTER, .ta_phys = SERVER };
    s_server_tp = ISOTPMockNew("server", &sa);
    s_tester = ISOTPMockNew("tester", &ta);
    assert(UDSServerInit(&s_srv) == UDS_OK);
    s_srv.tp = s_server_tp;
    s_srv.fn = app_fn;
    const udsota_iso14229_cfg_t cfg = {
        .engine = &k_engine, .security = &k_sec, .device_id = k_devid, .device_id_len = sizeof k_devid,
        .max_block_len = 4095u, .reset = do_reset, .gate = gate,
    };
    udsota_iso14229_init(&s_upd, &cfg);
    g_now += 1500u;                          /* past iso14229's 1 s boot delay for 0x27 */
}

/* One pass of the app's server task at time g_now. */
static void tick(void)
{
    udsota_iso14229_poll(&s_upd, &s_srv);
    UDSServerPoll(&s_srv);
}

static int s_pendings;                        /* 0x78s seen by the last xfer */

/* Sends req and returns the final answer's length (0x78s skipped and counted); -1 without one in 100 s. */
static int xfer(const uint8_t *req, size_t len, uint8_t *resp, size_t max)
{
    UDSSDU_t info = { .A_TA_Type = UDS_A_TA_TYPE_PHYSICAL };
    s_pendings = 0;
    assert(UDSTpSend(s_tester, req, len, &info) == UDS_OK);
    for (int ms = 0; ms < 100000; ms++) {
        g_now++;
        tick();
        (void)UDSTpPoll(s_tester);
        size_t n = 0;
        if (UDSTpRecv(s_tester, resp, max, &n, NULL) == UDS_OK && n > 0u) {
            if (n == 3u && resp[0] == 0x7Fu && resp[2] == 0x78u) {
                s_pendings++;
                continue;
            }
            return (int)n;
        }
    }
    return -1;
}

/* Sends req and checks the answer begins with want (want_len bytes). */
#define EXPECT(req, want)                                                                                \
    do {                                                                                                 \
        static const uint8_t r_[] = req, w_[] = want;                                                    \
        uint8_t b_[64];                                                                                  \
        const int n_ = xfer(r_, sizeof r_, b_, sizeof b_);                                               \
        CHECK(n_ >= (int)sizeof w_ && memcmp(b_, w_, sizeof w_) == 0);                                   \
        if (!(n_ >= (int)sizeof w_ && memcmp(b_, w_, sizeof w_) == 0)) {                                \
            fprintf(stderr, "  got %d bytes:", n_);                                                      \
            for (int i_ = 0; i_ < n_ && i_ < 8; i_++) fprintf(stderr, " %02X", b_[i_]);                 \
            fprintf(stderr, "\n");                                                                       \
        }                                                                                                \
    } while (0)
#define B(...) {__VA_ARGS__}

/* 27 <level> then 27 <level+1> with the right key. */
static void unlock(uint8_t level)
{
    uint8_t req[2 + 16] = {0x27, level}, resp[64];
    int n = xfer(req, 2, resp, sizeof resp);
    CHECK(n == 18 && resp[0] == 0x67 && resp[1] == level);
    req[1] = (uint8_t)(level + 1u);
    for (int i = 0; i < 16; i++) {
        req[2 + i] = (uint8_t)(resp[2 + i] ^ level);
    }
    n = xfer(req, sizeof req, resp, sizeof resp);
    CHECK(n == 2 && resp[0] == 0x67 && resp[1] == (uint8_t)(level + 1u));
}

static void request_download(uint32_t size)
{
    const uint8_t req[] = {0x34, 0x00, 0x44, 0, 0, 0, 0, (uint8_t)(size >> 24), (uint8_t)(size >> 16),
                           (uint8_t)(size >> 8), (uint8_t)size};
    uint8_t resp[64];
    const int n = xfer(req, sizeof req, resp, sizeof resp);
    CHECK(n == 4 && resp[0] == 0x74 && resp[1] == 0x20 && resp[2] == 0x0F && resp[3] == 0xFF);
}

/* 36 <bsc> with len bytes of img from off: the final answer's length, the answer in resp. */
static int block(uint8_t bsc, const uint8_t *img, size_t off, size_t len, uint8_t *resp, size_t max)
{
    static uint8_t req[4095];
    req[0] = 0x36;
    req[1] = bsc;
    memcpy(&req[2], &img[off], len);
    return xfer(req, len + 2u, resp, max);
}

int main(void)
{
    static uint8_t img[100000];
    for (size_t i = 0; i < sizeof img; i++) {
        img[i] = (uint8_t)(i * 7u + (i >> 9));
    }
    s_expect = img;
    E.running_slot = 0;
    E.boot_slot = 0;
    E.running_state = UDSOTA_IMG_VALID;
    boot();
    uint8_t resp[64];

    /* Identity in the default session; the app's fallback answers the rest. */
    EXPECT(B(0x22, 0xF1, 0x8C), B(0x62, 0xF1, 0x8C, 0x02, 0, 0, 0, 0, 0x01));
    EXPECT(B(0x22, 0xF1, 0x89), B(0x62, 0xF1, 0x89, 't', 'e', 's', 't'));
    EXPECT(B(0x22, 0xF1, 0xF0), B(0x62, 0xF1, 0xF0, 0x00, UDSOTA_IMG_VALID, 0x00));
    EXPECT(B(0x22, 0x12, 0x34), B(0x7F, 0x22, 0x31));
    EXPECT(B(0x2F, 0x12, 0x34, 0x00), B(0x7F, 0x2F, 0x11));
    EXPECT(B(0x11, 0x01), B(0x7F, 0x11, 0x7F));
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x7F));

    /* 10 02 answers the server's own P2/P2* (50 ms, 5000 ms), not iso14229's client defaults. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02, 0x00, 0x32, 0x01, 0xF4));
    EXPECT(B(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x10, 0), B(0x7F, 0x34, 0x33));
    EXPECT(B(0x27, 0x01), B(0x7F, 0x27, 0x7E));          /* the extended level, in programming */
    EXPECT(B(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), B(0x7F, 0x27, 0x24));
    g_now += 1100u;                                      /* iso14229's delay after a refused key */
    EXPECT(B(0x27, 0x03), B(0x67, 0x03));
    EXPECT(B(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), B(0x7F, 0x27, 0x35));
    g_now += 1100u;
    unlock(0x03);

    /* A resent block: iso14229 answers 0x24 and ends its transfer; the updater follows, so the next 36 is 0x70 and
     * a fresh 34 is taken. */
    request_download(sizeof img);
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 2 && resp[0] == 0x76 && resp[1] == 1);
    CHECK(s_pendings >= 1);                              /* the erase and write ran as a job: 0x78 first */
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x24);
    CHECK(block(2, img, 4093, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x70);
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));                /* the updater followed: 10 02 is taken, and relocks */
    CHECK(!udsota_upd_download_active(&s_upd.upd));
    EXPECT(B(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x10, 0), B(0x7F, 0x34, 0x33));
    unlock(0x03);

    /* 10 02 is refused while a transfer is open; 37 before every byte is 0x24 and ends the transfer. */
    request_download(sizeof img);
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));
    EXPECT(B(0x37), B(0x7F, 0x37, 0x24));
    CHECK(!udsota_upd_download_active(&s_upd.upd));

    /* The whole update, with S3 kept alive by the requests themselves: 3 s between blocks, no 3E. */
    request_download(sizeof img);
    uint8_t bsc = 1;
    for (size_t off = 0; off < sizeof img; off += 4093u, bsc++) {
        const size_t len = (sizeof img - off < 4093u) ? sizeof img - off : 4093u;
        const int n = block(bsc, img, off, len, resp, sizeof resp);
        CHECK(n == 2 && resp[0] == 0x76 && resp[1] == bsc);
        g_now += 3000u;
    }
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x02));   /* still programming after ~75 s */
    EXPECT(B(0x37), B(0x77));
    EXPECT(B(0x31, 0x01, 0xF0, 0x01), B(0x7F, 0x31, 0x24));   /* not verified yet */
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x71, 0x01, 0xFF, 0x01, 0x00));
    CHECK(s_pendings >= 1);
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_OK));
    EXPECT(B(0x31, 0x01, 0xF0, 0x01), B(0x71, 0x01, 0xF0, 0x01));
    CHECK(E.activations == 1 && E.boot_slot == 1);
    EXPECT(B(0x22, 0xF1, 0x86), B(0x7F, 0x22, 0x22));   /* nothing is served until the restart */
    for (int ms = 0; ms < 200; ms++) {                  /* the restart is iso14229's scheduled reset */
        g_now++;
        tick();
    }
    CHECK(s_resets >= 1);

    /* After the restart: the new image runs pending verify; F002 in the extended session confirms it. */
    E.running_slot = 1;
    E.running_state = UDSOTA_IMG_PENDING_VERIFY;
    boot();
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));          /* slots not settled: no programming session */
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    EXPECT(B(0x31, 0x01, 0xF0, 0x02), B(0x71, 0x01, 0xF0, 0x02));
    CHECK(E.confirms == 1 && E.running_state == UDSOTA_IMG_VALID);
    EXPECT(B(0x31, 0x01, 0xF0, 0x02), B(0x71, 0x01, 0xF0, 0x02));   /* idempotent */
    unlock(0x01);
    EXPECT(B(0x11, 0x01), B(0x51, 0x01));
    for (int ms = 0; ms < 200; ms++) {
        g_now++;
        tick();
    }
    CHECK(s_resets >= 2);

    /* A wrong-length key keeps the seed; the right key for it still unlocks. */
    boot();
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    {
        uint8_t req[2 + 16] = {0x27, 0x01}, seed[64];
        CHECK(xfer(req, 2, seed, sizeof seed) == 18);
        req[1] = 0x02;
        CHECK(xfer(req, 2 + 15, resp, sizeof resp) == 3 && resp[2] == 0x13);
        g_now += 1100u;                                  /* iso14229's delay after any refused key */
        for (int i = 0; i < 16; i++) {
            req[2 + i] = (uint8_t)(seed[2 + i] ^ 0x01u);
        }
        CHECK(xfer(req, sizeof req, resp, sizeof resp) == 2 && resp[0] == 0x67);
    }

    /* The gate refuses a 36: the transfer and the session end, and security relocks. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    unlock(0x03);
    request_download(sizeof img);
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 2 && resp[0] == 0x76);
    s_gate_36 = 0x22;
    CHECK(block(2, img, 4093, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x22);
    s_gate_36 = 0;
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_ABORTED));

    /* A worker that never finishes: FF01's wait ends in 0x72 at 90 s, in the default session, with F1F1 saying why;
     * the programming session stays refused until the worker is idle again. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    unlock(0x03);
    request_download(sizeof img);
    bsc = 1;
    for (size_t off = 0; off < sizeof img; off += 4093u, bsc++) {
        const size_t len = (sizeof img - off < 4093u) ? sizeof img - off : 4093u;
        CHECK(block(bsc, img, off, len, resp, sizeof resp) == 2);
    }
    EXPECT(B(0x37), B(0x77));
    s_hang = true;
    const uint32_t t0 = g_now;
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x72));
    CHECK(g_now - t0 >= 90000u && s_pendings >= 50);
    s_hang = false;
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_WORKER_TIMEOUT));
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));
    E.polls_left = 0;                                    /* the worker finishes */
    E.result = 0;
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));

    /* 25 days up with the server task running: iso14229's 0x27 delay and P2 deadlines must still read as passed. */
    boot();
    for (int h = 0; h < 25 * 24; h++) {
        g_now += 3600u * 1000u;
        tick();
    }
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    unlock(0x01);

    /* S3: a non-default session with no requests ends after 5.1 s, and relocks. */
    boot();
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    for (int ms = 0; ms < 5300; ms++) {
        g_now++;
        tick();
    }
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));

    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_poc_e2e: all checks passed\n");
    return 0;
}
