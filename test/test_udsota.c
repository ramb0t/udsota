/* End-to-end host test: iso14229's server on its mock transport, udsota in the app's event callback, and a platform
 * of this file's own (a RAM slot, jobs that stay pending a while as the ESP32 worker's do, a stand-in HMAC). A tester
 * sends raw requests on a clock the test sets. It covers a whole update (10 02, 27 03/04, 34, 36s through 0x78, 37,
 * FF01, F001 and the restart, F002 after it), a compressed one, the image rules, and the edges where udsota keeps
 * itself in step with iso14229. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iso14229.h"
#include "miniz.h"
#include "udsota.h"

#define TESTER 0x7E0u
#define SERVER 0x7E8u
#define SLOT   (256u * 1024u)

UDSOTA_IMAGE_DESC(1, 1, TESTER, SERVER);
void udsota_test_reboot(void);

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

/* ---- The platform: a RAM slot and a worker whose jobs finish after P.delay polls ---- */

static struct {
    int (*job)(void);
    int      countdown, result, delay;
    bool     hang, open, verified;
    uint8_t  slot[SLOT];
    size_t   pos;
    const uint8_t *expect;
    size_t   expect_len;
    udsota_status_t st;
    int      aborts, activations, confirms;
    uint8_t  seed_ctr;
} P = {.delay = 80};

int udsota_plat_start(void) { return 0; }
int udsota_plat_run(int (*job)(void))
{
    if (P.job != NULL) {
        return -1;
    }
    P.job = job;
    P.countdown = P.delay;
    return UDSOTA_PENDING;
}
int udsota_plat_poll(void)
{
    if (P.job == NULL) {
        return P.result;
    }
    if (P.hang || P.countdown-- > 0) {
        return UDSOTA_PENDING;
    }
    int (*job)(void) = P.job;
    P.job = NULL;
    P.result = job();
    return P.result;
}
void udsota_plat_abort(void)
{
    P.aborts++;
    P.open = false;
}
bool udsota_plat_compatible(const uint8_t *first, size_t len) { (void)first; (void)len; return true; }
int udsota_plat_begin(uint32_t size)
{
    if (size > SLOT || P.st.boot_slot != P.st.running_slot) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    memset(P.slot, 0xFF, sizeof P.slot);
    P.pos = 0;
    P.open = true;
    P.verified = false;
    return UDSOTA_DL_OK;
}
int udsota_plat_write(const uint8_t *d, size_t n)
{
    if (!P.open || P.pos + n > SLOT) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    memcpy(&P.slot[P.pos], d, n);
    P.pos += n;
    return UDSOTA_DL_OK;
}
int udsota_plat_end(void)
{
    if (!P.open) {
        return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    P.open = false;
    P.verified = P.pos == P.expect_len && memcmp(P.slot, P.expect, P.pos) == 0;
    return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}
int udsota_plat_activate(void)
{
    if (!P.verified) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    P.st.boot_slot = (uint8_t)(1u - P.st.running_slot);
    P.activations++;
    return UDSOTA_DL_OK;
}
int udsota_plat_confirm(void)
{
    P.st.running_state = UDSOTA_IMG_VALID;
    P.confirms++;
    return UDSOTA_DL_OK;
}
void udsota_plat_unverify(void) { P.verified = false; }
void udsota_plat_status(udsota_status_t *out) { *out = P.st; }
uint32_t udsota_plat_slot_size(void) { return SLOT; }
const char *udsota_plat_version(void) { return "0.4.1-lite.1"; }
const char *udsota_plat_project(void) { return "udsota-test"; }
const uint8_t *udsota_plat_sha(void)
{
    static const uint8_t sha[32] = {0xAB, 0xCD};
    return sha;
}
size_t udsota_plat_mac(uint8_t out[16])
{
    static const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 0x01};
    memcpy(out, mac, sizeof mac);
    return sizeof mac;
}
bool udsota_plat_rng16(uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(0xA0u + P.seed_ctr + i);
    }
    P.seed_ctr++;
    return true;
}
/* A stand-in for HMAC-SHA256: udsota only needs the same function on both sides. */
bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < key_len; i++) {
        h = (h ^ key[i]) * 16777619u;
    }
    for (size_t i = 0; i < msg_len; i++) {
        h = (h ^ msg[i]) * 16777619u;
    }
    for (int i = 0; i < 32; i++) {
        h = (h ^ (uint8_t)i) * 16777619u;
        out[i] = (uint8_t)(h >> 24);
    }
    return true;
}
int udsota_plat_ecdsa_key(const uint8_t *pubkey) { (void)pubkey; return -1; }
int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[64]) { (void)msg; (void)n; (void)sig; return -1; }

/* ---- The app ---- */

static const char    k_label[] = "udsota-test";
static const uint8_t k_master[32] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t k_id[6] = {0x02, 0, 0, 0, 0, 0x01};
static UDSServer_t s_srv;
static UDSTp_t    *s_tester;
static int         s_resets;
static uint8_t     s_gate_36;             /* the gate's answer to CONTINUE_TRANSFER */
static bool        s_allow_downgrade;     /* cfg.allow_downgrade at the next boot */

static UDSErr_t app_fn(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent:
        return UDS_NRC_RequestOutOfRange;
    case UDS_EVT_DiagSessCtrl:
        return UDS_NRC_SubFunctionNotSupported;
    case UDS_EVT_SessionTimeout:
    case UDS_EVT_Err:
        return UDS_OK;
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

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

/* A fresh server and udsota over the platform's current state, as after a boot. */
static void boot(void)
{
    udsota_test_reboot();
    ISOTPMockReset();
    const ISOTPMockArgs_t sa = {.sa_phys = SERVER, .ta_phys = TESTER};
    const ISOTPMockArgs_t ta = {.sa_phys = TESTER, .ta_phys = SERVER};
    UDSTp_t *server_tp = ISOTPMockNew("server", &sa);
    s_tester = ISOTPMockNew("tester", &ta);
    assert(UDSServerInit(&s_srv) == UDS_OK);
    s_srv.tp = server_tp;
    s_srv.fn = app_fn;
    const udsota_cfg_t cfg = {.key_label = k_label, .key_master = k_master, .key_master_len = sizeof k_master,
                              .gate = gate, .reset = do_reset, .allow_downgrade = s_allow_downgrade};
    assert(udsota_init(&cfg) == 0);
    g_now += 1500u;                               /* past iso14229's 1 s boot delay for 0x27 */
}

static void tick(void)
{
    UDSServerPoll(&s_srv);
}

static int s_pendings;                            /* 0x78s the last xfer saw */

/* Sends req and returns the final answer's length (0x78s counted); -1 without one in 100 s. */
static int xfer(const uint8_t *req, size_t len, uint8_t *resp, size_t max)
{
    UDSSDU_t info = {.A_TA_Type = UDS_A_TA_TYPE_PHYSICAL};
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

#define EXPECT(req, want)                                                                                \
    do {                                                                                                 \
        static const uint8_t r_[] = req, w_[] = want;                                                    \
        uint8_t b_[64];                                                                                  \
        const int n_ = xfer(r_, sizeof r_, b_, sizeof b_);                                               \
        const bool ok_ = n_ >= (int)sizeof w_ && memcmp(b_, w_, sizeof w_) == 0;                        \
        CHECK(ok_);                                                                                      \
        if (!ok_) {                                                                                      \
            fprintf(stderr, "  got %d bytes:", n_);                                                      \
            for (int i_ = 0; i_ < n_ && i_ < 8; i_++) fprintf(stderr, " %02X", b_[i_]);                 \
            fprintf(stderr, "\n");                                                                       \
        }                                                                                                \
    } while (0)
#define B(...) {__VA_ARGS__}

/* The key the tester computes: HMAC(HMAC(master, label || ID), seed || level || ID)[0..15]. */
static void tester_key(const uint8_t *seed, uint8_t level, uint8_t key[16])
{
    uint8_t kdev[32], msg[64], full[32];
    memcpy(msg, k_label, sizeof k_label - 1u);
    memcpy(&msg[sizeof k_label - 1u], k_id, sizeof k_id);
    udsota_plat_hmac(k_master, sizeof k_master, msg, sizeof k_label - 1u + sizeof k_id, kdev);
    memcpy(msg, seed, 16);
    msg[16] = level;
    memcpy(&msg[17], k_id, sizeof k_id);
    udsota_plat_hmac(kdev, sizeof kdev, msg, 17u + sizeof k_id, full);
    memcpy(key, full, 16);
}

/* 27 <level> then 27 <level+1> with the right key. */
static void unlock(uint8_t level)
{
    uint8_t req[2 + 16] = {0x27, level}, resp[64];
    int n = xfer(req, 2, resp, sizeof resp);
    CHECK(n == 18 && resp[0] == 0x67 && resp[1] == level);
    req[1] = (uint8_t)(level + 1u);
    tester_key(&resp[2], level, &req[2]);
    n = xfer(req, sizeof req, resp, sizeof resp);
    CHECK(n == 2 && resp[0] == 0x67 && resp[1] == (uint8_t)(level + 1u));
}

static void request_download(uint32_t size, uint8_t dfi)
{
    const uint8_t req[] = {0x34, dfi, 0x44, 0, 0, 0, 0, (uint8_t)(size >> 24), (uint8_t)(size >> 16),
                           (uint8_t)(size >> 8), (uint8_t)size};
    uint8_t resp[64];
    const int n = xfer(req, sizeof req, resp, sizeof resp);
    CHECK(n == 4 && resp[0] == 0x74 && resp[1] == 0x20 && resp[2] == 0x0F && resp[3] == 0xFF);
}

/* 36 <bsc> with len bytes of data from off: the final answer's length, the answer in resp. */
static int block(uint8_t bsc, const uint8_t *data, size_t off, size_t len, uint8_t *resp, size_t max)
{
    static uint8_t req[4095];
    req[0] = 0x36;
    req[1] = bsc;
    memcpy(&req[2], &data[off], len);
    return xfer(req, len + 2u, resp, max);
}

/* Every block of data, each answered 76; a 3E between blocks keeps the session (iso14229's S3 counts 10 and 3E). */
static void send_all(const uint8_t *data, size_t len)
{
    uint8_t resp[64], bsc = 1;
    for (size_t off = 0; off < len; off += 4093u, bsc++) {
        const size_t n = (len - off < 4093u) ? len - off : 4093u;
        CHECK(block(bsc, data, off, n, resp, sizeof resp) == 2 && resp[0] == 0x76 && resp[1] == bsc);
        EXPECT(B(0x3E, 0x00), B(0x7E, 0x00));
        g_now += 1500u;
    }
}

/* An ESP-IDF image header, app descriptor and udsota descriptor, as the image rules read them. */
static void stamp_as(uint8_t *img, const char *version, const char *project, uint8_t hw, uint8_t layout, uint16_t req,
                     uint8_t flags)
{
    const uint8_t desc[13] = {0x4F, 0x53, 0x44, 0x55, 1, 0, hw, layout, (uint8_t)req, (uint8_t)(req >> 8),
                              SERVER & 0xFF, SERVER >> 8, flags};
    memset(img, 0, 320);
    img[0] = 0xE9;                                /* magic */
    img[1] = 4;                                   /* segments */
    img[2] = 2;                                   /* SPI mode */
    img[12] = 9;                                  /* ESP32-S3 */
    img[29] = 0x20;                               /* segment 0: 0x2000 bytes */
    img[32] = 0x32, img[33] = 0x54, img[34] = 0xCD, img[35] = 0xAB;   /* esp_app_desc_t magic */
    memcpy(&img[48], version, strlen(version));
    memcpy(&img[80], project, strlen(project));
    memcpy(&img[288], desc, sizeof desc);
}

static void stamp(uint8_t *img, const char *version, const char *project)
{
    stamp_as(img, version, project, 1, 1, TESTER, 0);
}

/* A download of img is refused at its first block, before anything is erased, and F1F1 gives reason. */
static void refused(const uint8_t *img, uint8_t reason)
{
    uint8_t resp[64];
    const uint8_t want[] = {0x62, 0xF1, 0xF1, reason, 0, 0, 0, 0};
    request_download(8192, 0x00);
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x31);
    const uint8_t req[] = {0x22, 0xF1, 0xF1};
    CHECK(xfer(req, sizeof req, resp, sizeof resp) == 8 && memcmp(resp, want, sizeof want) == 0);
}

int main(void)
{
    static uint8_t img[100000], other[8192];
    for (size_t i = 0; i < sizeof img; i++) {
        img[i] = (uint8_t)(i * 7u + (i >> 9));
    }
    stamp(img, "0.4.1-lite.2", "udsota-test");
    memcpy(other, img, sizeof other);
    stamp(other, "0.4.1-lite.2", "another-project");
    P.expect = img;
    P.expect_len = sizeof img;
    P.st = (udsota_status_t){.running_slot = 0, .boot_slot = 0, .running_state = UDSOTA_IMG_VALID};
    boot();
    uint8_t resp[64];

    /* Identity in the default session; the app answers the rest. */
    EXPECT(B(0x22, 0xF1, 0x8C), B(0x62, 0xF1, 0x8C, 0x02, 0, 0, 0, 0, 0x01));
    EXPECT(B(0x22, 0xF1, 0x89), B(0x62, 0xF1, 0x89, '0', '.', '4', '.', '1'));
    EXPECT(B(0x22, 0xF1, 0xF0), B(0x62, 0xF1, 0xF0, 0x00, UDSOTA_IMG_VALID, 0x00, UDSOTA_OTHER_EMPTY, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0x00));
    EXPECT(B(0x34, 0x00, 0x44, 0, 0, 0x10, 0, 0, 0, 0x10, 0), B(0x7F, 0x34, 0x11));   /* not address 0: the app's */
    EXPECT(B(0x22, 0x12, 0x34), B(0x7F, 0x22, 0x31));
    EXPECT(B(0x2F, 0x12, 0x34, 0x00), B(0x7F, 0x2F, 0x11));
    EXPECT(B(0x10, 0x04), B(0x7F, 0x10, 0x12));   /* a session udsota doesn't know is the app's */
    EXPECT(B(0x11, 0x01), B(0x7F, 0x11, 0x7F));
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x7F));

    /* The programming session, then its lock. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    EXPECT(B(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x10, 0), B(0x7F, 0x34, 0x33));
    EXPECT(B(0x27, 0x01), B(0x7F, 0x27, 0x7E));   /* the extended level, in programming */
    EXPECT(B(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), B(0x7F, 0x27, 0x24));
    g_now += 1100u;                               /* iso14229's delay after a refused key */
    EXPECT(B(0x27, 0x03), B(0x67, 0x03));
    EXPECT(B(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), B(0x7F, 0x27, 0x35));
    g_now += 1100u;
    unlock(0x03);

    /* A resent block: iso14229 answers 0x24 and ends its transfer; udsota follows, so the next 36 is 0x70. */
    request_download(sizeof img, 0x00);
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 2 && resp[0] == 0x76 && resp[1] == 1);
    CHECK(s_pendings >= 1);                       /* the write ran as a job: 0x78 first */
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x24);
    CHECK(block(2, img, 4093, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x70);
    const int aborts = P.aborts;
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));        /* the next event brings udsota in step */
    CHECK(!udsota_busy() && P.aborts == aborts + 1);
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_ABORTED, 0, 0, 0x0F, 0xFD));
    unlock(0x03);                                 /* every 10 relocks */

    /* 10 02 is refused while a transfer is open; 37 before every byte is 0x24 and ends it. */
    request_download(sizeof img, 0x00);
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));
    EXPECT(B(0x37), B(0x7F, 0x37, 0x24));
    CHECK(!udsota_busy());

    /* The image rules: each wrong image is refused at its first block, before anything is erased. */
    refused(other, UDSOTA_DL_BAD_PROJECT);
    stamp(other, "0.4.0-lite.9", "udsota-test");
    refused(other, UDSOTA_DL_NOT_NEWER);             /* a dev build older than the running one */
    stamp_as(other, "0.4.2", "udsota-test", 1, 1, TESTER, 0);
    refused(other, UDSOTA_DL_BAD_HEADER);            /* a clean version without the release flag */
    stamp_as(other, "0.4.1-lite.2", "udsota-test", 2, 1, TESTER, 0);
    refused(other, UDSOTA_DL_BAD_BOARD);
    stamp_as(other, "0.4.1-lite.2", "udsota-test", 1, 2, TESTER, 0);
    refused(other, UDSOTA_DL_BAD_LAYOUT);
    stamp_as(other, "0.4.1-lite.2", "udsota-test", 1, 1, 0x7E1, 0);
    refused(other, UDSOTA_DL_BAD_DIAG_IDS);
    CHECK(P.pos == 0 || !P.open);                    /* nothing was written */

    /* The whole update, the session kept by 3E between blocks. */
    request_download(sizeof img, 0x00);
    send_all(img, sizeof img);
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x02));
    EXPECT(B(0x37), B(0x77));
    EXPECT(B(0x31, 0x01, 0xF0, 0x01), B(0x7F, 0x31, 0x24));   /* not verified yet */
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x71, 0x01, 0xFF, 0x01, 0x00));
    CHECK(s_pendings >= 1);
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_OK));
    EXPECT(B(0x31, 0x01, 0xF0, 0x01), B(0x71, 0x01, 0xF0, 0x01));
    CHECK(P.activations == 1 && P.st.boot_slot == 1);
    for (int ms = 0; ms < 200; ms++) {            /* the restart is iso14229's scheduled reset */
        g_now++;
        tick();
    }
    CHECK(s_resets >= 1);

    /* After the restart: the new image runs pending verify; F002 in the extended session confirms it. */
    P.st.running_slot = 1;
    P.st.running_state = UDSOTA_IMG_PENDING_VERIFY;
    boot();
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));   /* slots not settled */
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    EXPECT(B(0x31, 0x01, 0xF0, 0x02), B(0x71, 0x01, 0xF0, 0x02));
    CHECK(P.confirms == 1 && P.st.running_state == UDSOTA_IMG_VALID);
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
        g_now += 1100u;
        tester_key(&seed[2], 0x01, &req[2]);
        CHECK(xfer(req, sizeof req, resp, sizeof resp) == 2 && resp[0] == 0x67);
    }

    /* The gate refuses a 36: the transfer and the session end. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    unlock(0x03);
    request_download(sizeof img, 0x00);
    CHECK(block(1, img, 0, 4093, resp, sizeof resp) == 2 && resp[0] == 0x76);
    s_gate_36 = 0x22;
    CHECK(block(2, img, 4093, 4093, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x22);
    s_gate_36 = 0;
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_ABORTED, 0, 0, 0x0F, 0xFD));
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    EXPECT(B(0x11, 0x01), B(0x7F, 0x11, 0x33));      /* the gate's end of the session relocked */

    /* A compressed download (DFI 0x10, raw DEFLATE): the stream inflates to exactly the image, which verifies. */
    {
        size_t zlen = 0;
        uint8_t *z = tdefl_compress_mem_to_heap(img, sizeof img, &zlen, TDEFL_DEFAULT_MAX_PROBES);
        assert(z != NULL && zlen < sizeof img);
        EXPECT(B(0x10, 0x02), B(0x50, 0x02));
        unlock(0x03);
        request_download(sizeof img, 0x10);
        send_all(z, zlen);
        EXPECT(B(0x37), B(0x77));
        EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x71, 0x01, 0xFF, 0x01, 0x00));
        CHECK(P.pos == sizeof img && memcmp(P.slot, img, sizeof img) == 0);
        mz_free(z);
    }

    /* A worker that never finishes: udsota holds the session through FF01's 0x78s until its 90 s cap answers 0x72;
     * F1F1 says why, and the programming session stays refused until the worker is idle again. */
    EXPECT(B(0x10, 0x01), B(0x50, 0x01));        /* every 10 relocks: the level-03 unlock above ends at 10 01 */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    EXPECT(B(0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0x10, 0), B(0x7F, 0x34, 0x33));
    unlock(0x03);
    request_download(sizeof img, 0x00);
    send_all(img, sizeof img);
    EXPECT(B(0x37), B(0x77));
    P.hang = true;
    const uint32_t t0 = g_now;
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x72));
    CHECK(g_now - t0 >= 90000u && s_pendings >= 50);
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_WORKER_TIMEOUT));
    EXPECT(B(0x10, 0x02), B(0x7F, 0x10, 0x22));
    P.hang = false;                               /* the worker finishes */
    P.countdown = 0;
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));

    /* S3: a session with no 10 or 3E ends after 5.1 s. */
    boot();
    EXPECT(B(0x10, 0x03), B(0x50, 0x03));
    for (int ms = 0; ms < 5300; ms++) {
        g_now++;
        tick();
    }
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));

    /* allow_downgrade: an older dev build installs; the release-flag and board rules still refuse. */
    s_allow_downgrade = true;
    P.st = (udsota_status_t){.running_slot = 0, .boot_slot = 0, .running_state = UDSOTA_IMG_VALID};
    boot();
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    unlock(0x03);
    memcpy(other, img, sizeof other);
    stamp_as(other, "0.3.0", "udsota-test", 1, 1, TESTER, 0);
    refused(other, UDSOTA_DL_BAD_HEADER);            /* a clean version without the release flag */
    stamp_as(other, "0.4.0-lite.9", "udsota-test", 2, 1, TESTER, 0);
    refused(other, UDSOTA_DL_BAD_BOARD);
    stamp(other, "0.4.0-lite.9", "udsota-test");
    P.expect = other;
    P.expect_len = sizeof other;
    request_download(sizeof other, 0x00);
    send_all(other, sizeof other);
    EXPECT(B(0x37), B(0x77));
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x71, 0x01, 0xFF, 0x01, 0x00));
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_OK, 0, 0, 0x20, 0x00));

    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_udsota: all checks passed\n");
    return 0;
}
