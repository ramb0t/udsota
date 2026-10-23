/* End-to-end host test: iso14229's server on its mock transport, udsota in the app's event callback, and a platform
 * of this file's own (a RAM slot, jobs that stay pending a while as the ESP32 worker's do, stand-ins for HMAC and
 * ECDSA). A tester sends raw requests on a clock the test sets. It covers a whole update (10 02, 27 03/04, 34, 36s
 * through 0x78, 37, FF01, F001 and the restart, F002 after it), a compressed one, the image rules (case by case on
 * the first block too), a corrupt and a short compressed stream, security off, the message the ECDSA mode verifies,
 * the PSA lock, and the edges where udsota keeps itself in step with iso14229. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
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
int  udsota_test_psa_depth(void);
udsota_reason_t udsota_test_check_first(const uint8_t *b, size_t len, uint32_t size);

/* The descriptor's layout is wire: every unit's image rules and the client (client/udsota/image.py) read it at these
 * offsets from byte 288 of an image. */
_Static_assert(sizeof(udsota_image_desc_t) == 32u, "udsota_image_desc_t is 32 bytes");
_Static_assert(offsetof(udsota_image_desc_t, magic) == 0u && offsetof(udsota_image_desc_t, desc_version) == 4u &&
               offsetof(udsota_image_desc_t, hw_id) == 6u && offsetof(udsota_image_desc_t, partition_layout_id) == 7u &&
               offsetof(udsota_image_desc_t, diag_request_id) == 8u &&
               offsetof(udsota_image_desc_t, diag_response_id) == 10u && offsetof(udsota_image_desc_t, flags) == 12u &&
               offsetof(udsota_image_desc_t, reserved) == 13u, "udsota_image_desc_t's fields at their wire offsets");

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

/* The platform calls that run PSA on ESP-IDF: each must run under udsota's PSA lock. */
enum { PSA_HMAC, PSA_ECDSA_KEY, PSA_ECDSA, PSA_END, PSA_ACTIVATE, PSA_CALLS };

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
    bool     seed_kat;                 /* seeds are 10 11 .. 1F, the client's known-answer SEED */
    int      psa_calls[PSA_CALLS], psa_unlocked;
    uint8_t  ecdsa_msg[64];            /* the last message the ECDSA check verified */
    size_t   ecdsa_len;
    const char *version;               /* the running image's version */
} P = {.delay = 80, .version = "0.4.1-lite.1"};

static void psa_call(int which)
{
    P.psa_calls[which]++;
    if (udsota_test_psa_depth() != 1) {
        P.psa_unlocked++;
    }
}

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
    psa_call(PSA_END);
    if (!P.open) {
        return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    P.open = false;
    P.verified = P.pos == P.expect_len && memcmp(P.slot, P.expect, P.pos) == 0;
    return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}
int udsota_plat_activate(void)
{
    psa_call(PSA_ACTIVATE);
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
const char *udsota_plat_version(void) { return P.version; }
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
        out[i] = (uint8_t)(P.seed_kat ? 0x10u + i : 0xA0u + P.seed_ctr + i);
    }
    P.seed_ctr++;
    return true;
}
/* A stand-in for HMAC-SHA256: udsota only needs the same function on both sides. */
static void stand_in_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
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
}
bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    psa_call(PSA_HMAC);
    stand_in_hmac(key, key_len, msg, msg_len, out);
    return true;
}
/* A stand-in for ECDSA: any key imports, and a signature that starts 5A is valid. */
int udsota_plat_ecdsa_key(const uint8_t *pubkey)
{
    (void)pubkey;
    psa_call(PSA_ECDSA_KEY);
    return 0;
}
int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[64])
{
    psa_call(PSA_ECDSA);
    P.ecdsa_len = (n <= sizeof P.ecdsa_msg) ? n : 0u;
    memcpy(P.ecdsa_msg, msg, P.ecdsa_len);
    return (sig[0] == 0x5Au) ? 1 : 0;
}

/* ---- The app ---- */

static const char    k_label[] = "udsota-test";
static const uint8_t k_master[32] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t k_id[6] = {0x02, 0, 0, 0, 0, 0x01};
static const uint8_t k_pub[65] = {0x04};
static UDSServer_t s_srv;
static UDSTp_t    *s_tester;
static int         s_resets;
static uint8_t     s_gate_36;             /* the gate's answer to CONTINUE_TRANSFER */
static bool        s_allow_downgrade;     /* cfg.allow_downgrade at the next boot */
static bool        s_ecdsa;               /* the ECDSA mode at the next boot, with k_pub */
static bool        s_no_keys;             /* no keys at the next boot: security off */
static int         s_app_psa;             /* 1 while the app holds the PSA lock */
static int         s_app_27;              /* 27s that reached the app */

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
    case UDS_EVT_SecAccessRequestSeed:
    case UDS_EVT_SecAccessValidateKey:
        s_app_27++;
        return UDS_NRC_RequestOutOfRange;
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
    s_srv.p2_ms = 5;                              /* as the examples set it */
    udsota_cfg_t cfg = {.key_label = k_label, .key_master = k_master, .key_master_len = sizeof k_master,
                        .gate = gate, .reset = do_reset, .allow_downgrade = s_allow_downgrade};
    if (s_no_keys) {
        cfg.key_label = NULL;
        cfg.key_master = NULL;
        cfg.key_master_len = 0;
    } else if (s_ecdsa) {
        cfg.key_pubkey = k_pub;
        cfg.key_pubkey_len = sizeof k_pub;
    }
    assert(udsota_init(&cfg) == 0);
    CHECK(udsota_test_psa_depth() == 0);
    g_now += 1500u;                               /* past iso14229's 1 s boot delay for 0x27 */
}

static bool s_pin = true;                         /* udsota_poll after each pass, as an app's server task does */

static void tick(void)
{
    UDSServerPoll(&s_srv);
    if (s_pin) {
        udsota_poll(&s_srv);
    }
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
            CHECK(udsota_test_psa_depth() == s_app_psa);   /* udsota's locks and unlocks balance */
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
    stand_in_hmac(k_master, sizeof k_master, msg, sizeof k_label - 1u + sizeof k_id, kdev);
    memcpy(msg, seed, 16);
    msg[16] = level;
    memcpy(&msg[17], k_id, sizeof k_id);
    stand_in_hmac(kdev, sizeof kdev, msg, 17u + sizeof k_id, full);
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

/* ---- The first-block rules, case by case ----
 * Each case starts udsota on a running image of its version and runs the image rules on a first block from stamp_as:
 * a dev build 0.4.1-lite.2 of udsota-test for the ESP32-S3 and this board (hw 1, layout 1, TESTER and SERVER), with
 * the case's changes. The names are those of the v0.14.2 tests whose rules these keep (test_udsota_image.c and
 * test_udsota_esp32_image.c). */
#define FULL32 "abcdefghijklmnopqrstuvwxyz012345"   /* a project name that fills its 32-byte field */
#define POKE(...) .poke = {__VA_ARGS__}, .pokes = (int)(sizeof((struct poke_s[]){__VA_ARGS__}) / sizeof(struct poke_s))
struct poke_s {
    uint16_t at;
    uint8_t  val;
};
typedef struct {
    const char     *name;
    const char     *running;        /* the running image's version; NULL = 0.4.1-lite.1 */
    const char     *version;        /* the image's; NULL = 0.4.1-lite.2 */
    uint8_t         flags;          /* the image descriptor's: 0x01 a release */
    const char     *project;        /* the image's; NULL = udsota-test */
    const char     *product;        /* cfg.product; NULL = the running image's project, udsota-test */
    bool            allow_downgrade;
    struct poke_s   poke[2];        /* bytes set after stamping */
    int             pokes;
    size_t          len;            /* bytes the rules get; 0 = 320 */
    uint32_t        size;           /* the 34's memorySize; 0 = 8192 */
    udsota_reason_t want;
} first_case_t;

static const first_case_t k_first[] = {
    {"first_block_passes", .want = UDSOTA_DL_OK},
    {"size: the slot", .size = SLOT, .want = UDSOTA_DL_OK},
    {"size: a byte over the slot", .size = SLOT + 1u, .want = UDSOTA_DL_TOO_BIG},
    {"size: under 320", .size = 319u, .want = UDSOTA_DL_BAD_HEADER},
    {"short_or_null: 319 bytes", .len = 319u, .want = UDSOTA_DL_BAD_HEADER},
    {"bad_image_magic", POKE({0, 0xEA}), .want = UDSOTA_DL_BAD_HEADER},
    {"wrong_chip: ESP32-S2", POKE({12, 0x02}), .want = UDSOTA_DL_BAD_HEADER},
    {"wrong_chip: its high byte", POKE({13, 0x01}), .want = UDSOTA_DL_BAD_HEADER},
    {"spi_mode: 5", POKE({2, 5}), .want = UDSOTA_DL_OK},
    {"spi_mode: 6", POKE({2, 6}), .want = UDSOTA_DL_BAD_HEADER},
    {"segment_count: 16", POKE({1, 16}), .want = UDSOTA_DL_OK},
    {"segment_count: 0", POKE({1, 0}), .want = UDSOTA_DL_BAD_HEADER},
    {"segment_count: 17", POKE({1, 17}), .want = UDSOTA_DL_BAD_HEADER},
    {"seg0_too_short: 288", POKE({28, 0x20}, {29, 0x01}), .want = UDSOTA_DL_OK},
    {"seg0_too_short: 287", POKE({28, 0x1F}, {29, 0x01}), .want = UDSOTA_DL_BAD_HEADER},
    {"seg0_too_short: 0x01000000", POKE({29, 0x00}, {31, 0x01}), .want = UDSOTA_DL_OK},
    {"bad_app_desc_magic", POKE({32, 0x33}), .want = UDSOTA_DL_BAD_HEADER},
    {"bad_app_desc_magic: its top byte", POKE({35, 0xAC}), .want = UDSOTA_DL_BAD_HEADER},
    {"wrong_project: one letter", .project = "udsota-tesu", .want = UDSOTA_DL_BAD_PROJECT},
    {"wrong_project: longer", .project = "udsota-test2", .want = UDSOTA_DL_BAD_PROJECT},
    {"wrong_project: shorter", .project = "udsota-tes", .want = UDSOTA_DL_BAD_PROJECT},
    {"product_from_cfg", .product = "widget", .project = "widget", .want = UDSOTA_DL_OK},
    {"product_from_cfg: not the running project", .product = "widget", .want = UDSOTA_DL_BAD_PROJECT},
    {"product_fills_field", .project = FULL32, .product = FULL32, .want = UDSOTA_DL_OK},
    {"product_fills_field: a longer product", .project = FULL32, .product = FULL32 "6", .want = UDSOTA_DL_BAD_PROJECT},
    {"bad_desc_magic", POKE({288, 0x4E}), .want = UDSOTA_DL_BAD_BOARD},
    {"bad_desc_magic: its top byte", POKE({291, 0x56}), .want = UDSOTA_DL_BAD_BOARD},
    {"desc_version: 0", POKE({292, 0}), .want = UDSOTA_DL_BAD_BOARD},
    {"desc_version: 2", POKE({292, 2}), .want = UDSOTA_DL_OK},
    {"desc_version: 0x0100", POKE({292, 0}, {293, 1}), .want = UDSOTA_DL_OK},
    {"wrong_board", POKE({294, 3}), .want = UDSOTA_DL_BAD_BOARD},
    {"wrong_layout", POKE({295, 2}), .want = UDSOTA_DL_BAD_LAYOUT},
    {"wrong_diag_ids: request", POKE({296, 0xE1}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"wrong_diag_ids: request's high byte", POKE({297, 0x08}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"wrong_diag_ids: response", POKE({298, 0xE9}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"wrong_diag_ids: response's high byte", POKE({299, 0x08}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"other_flag_bits_ignored: a release", .version = "0.5.0", .flags = 0xFF, .want = UDSOTA_DL_OK},
    {"other_flag_bits_ignored: a dev build", .flags = 0xFE, .want = UDSOTA_DL_OK},
    {"release_equal_not_newer", .running = "1.2.3", .version = "v1.2.3", .flags = 1, .want = UDSOTA_DL_NOT_NEWER},
    {"release_older_not_newer: patch", .running = "1.2.3", .version = "v1.2.2", .flags = 1,
     .want = UDSOTA_DL_NOT_NEWER},
    {"release_older_not_newer: minor", .running = "1.2.3", .version = "1.1.9", .flags = 1,
     .want = UDSOTA_DL_NOT_NEWER},
    {"release_older_not_newer: major", .running = "1.2.3", .version = "v0.255.255", .flags = 1,
     .want = UDSOTA_DL_NOT_NEWER},
    {"release_newer_ok: patch", .running = "1.2.3", .version = "v1.2.4", .flags = 1, .want = UDSOTA_DL_OK},
    {"release_newer_ok: minor", .running = "1.2.3", .version = "1.3.0", .flags = 1, .want = UDSOTA_DL_OK},
    {"release_newer_ok: major", .running = "1.255.255", .version = "v2.0.0", .flags = 1, .want = UDSOTA_DL_OK},
    {"dev_equal_ok: describe", .running = "0.1.0-dev", .version = "v0.1.0-3-gabc1234", .want = UDSOTA_DL_OK},
    {"dev_equal_ok: dirty", .running = "0.1.0-dev", .version = "v0.1.0-dirty", .want = UDSOTA_DL_OK},
    {"dev_equal_ok: build metadata", .running = "0.1.0-dev", .version = "0.1.0+devkit", .want = UDSOTA_DL_OK},
    {"dev_older_not_newer", .running = "0.2.0-dev", .version = "v0.1.9-12-gabc1234-dirty",
     .want = UDSOTA_DL_NOT_NEWER},
    {"release_over_running_rc_same_core_ok", .running = "1.2.3-rc1", .version = "v1.2.3", .flags = 1,
     .want = UDSOTA_DL_OK},
    {"release_older_than_running_rc_not_newer", .running = "1.2.3-rc1", .version = "v1.2.2", .flags = 1,
     .want = UDSOTA_DL_NOT_NEWER},
    {"dev_rc_over_rc_ok", .running = "1.2.3-rc1", .version = "v1.2.3-rc2", .want = UDSOTA_DL_OK},
    {"dev_rc_over_rc_ok: an rc over an older release", .running = "1.2.2", .version = "v1.2.3-rc1",
     .want = UDSOTA_DL_OK},
    {"dev_newer_ok", .running = "0.1.0-dev", .version = "v0.2.0-1-gabc1234", .want = UDSOTA_DL_OK},
    {"unparseable_running_fails_open: a release", .running = "abcdef0", .version = "v0.0.1", .flags = 1,
     .want = UDSOTA_DL_OK},
    {"unparseable_running_fails_open: a dev build", .running = "abcdef0", .version = "0.0.0-x", .want = UDSOTA_DL_OK},
    {"unparseable_running_fails_open: runs as a dev build", .running = "abcdef0", .version = "v0.0.0", .flags = 1,
     .want = UDSOTA_DL_OK},
    {"flag_set_dev_string: describe", .version = "v1.2.3-4-gabc", .flags = 1, .want = UDSOTA_DL_BAD_HEADER},
    {"flag_set_dev_string: build metadata", .version = "v1.2.3+devkit", .flags = 1, .want = UDSOTA_DL_BAD_HEADER},
    {"flag_clear_release_string", .version = "v1.2.3", .want = UDSOTA_DL_BAD_HEADER},
    {"flag_clear_release_string: no v", .version = "1.2.3", .want = UDSOTA_DL_BAD_HEADER},
    {"release_component_over_255: major", .version = "v256.0.0", .flags = 1, .want = UDSOTA_DL_BAD_HEADER},
    {"release_component_over_255: patch", .version = "v1.2.256", .flags = 1, .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: a hash", .version = "abcdef0", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: a dirty hash", .version = "1a2b3c4-dirty", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: digits", .version = "1234567", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: 1", .version = "1", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: 1.2", .version = "1.2", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: 1.2.300", .version = "1.2.300", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: 1.2.3x", .version = "1.2.3x", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: 1..3", .version = "1..3", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: empty", .version = "", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: v", .version = "v", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: V1.2.3", .version = "V1.2.3", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: a leading space", .version = " 1.2.3", .want = UDSOTA_DL_BAD_HEADER},
    {"unparseable_version: no terminator", .version = "0000000000000000000000000001.2.3",
     .want = UDSOTA_DL_BAD_HEADER},
    {"header_then_core_rules", .project = "other", POKE({0, 0xEA}), .want = UDSOTA_DL_BAD_HEADER},
    {"first_failure_wins: project before board", .project = "other", POKE({294, 3}), .want = UDSOTA_DL_BAD_PROJECT},
    {"first_failure_wins: board before size", POKE({294, 3}), .size = SLOT + 1u, .want = UDSOTA_DL_BAD_BOARD},
    {"first_failure_wins: newer before size", .running = "0.1.0", .version = "v0.1.0", .flags = 1, .size = SLOT + 1u,
     .want = UDSOTA_DL_NOT_NEWER},
    {"first_failure_wins: a parse failure before size", .version = "1.2", .size = SLOT + 1u,
     .want = UDSOTA_DL_BAD_HEADER},
    {"allow_older_release_older_ok", .allow_downgrade = true, .running = "1.2.3", .version = "v1.2.2", .flags = 1,
     .want = UDSOTA_DL_OK},
    {"allow_older_release_equal_ok", .allow_downgrade = true, .running = "1.2.3", .version = "v1.2.3", .flags = 1,
     .want = UDSOTA_DL_OK},
    {"allow_older_dev_older_ok", .allow_downgrade = true, .running = "0.2.0-dev", .version = "0.1.0-dev",
     .want = UDSOTA_DL_OK},
    {"allow_older_other_rules_hold: board", .allow_downgrade = true, .running = "1.2.3", .version = "v1.2.2",
     .flags = 1, POKE({294, 3}), .want = UDSOTA_DL_BAD_BOARD},
    {"allow_older_other_rules_hold: release flag", .allow_downgrade = true, .running = "1.2.3", .version = "1.2.2",
     .want = UDSOTA_DL_BAD_HEADER},
    {"allow_older_other_rules_hold: size", .allow_downgrade = true, .size = SLOT + 1u, .want = UDSOTA_DL_TOO_BIG},
};

static void first_block_cases(void)
{
    static uint8_t b[320];
    for (size_t i = 0; i < sizeof k_first / sizeof k_first[0]; i++) {
        const first_case_t *c = &k_first[i];
        P.version = (c->running != NULL) ? c->running : "0.4.1-lite.1";
        udsota_test_reboot();
        assert(udsota_init(&(udsota_cfg_t){.product = c->product, .allow_downgrade = c->allow_downgrade}) == 0);
        stamp_as(b, (c->version != NULL) ? c->version : "0.4.1-lite.2",
                 (c->project != NULL) ? c->project : "udsota-test", 1, 1, TESTER, c->flags);
        for (int k = 0; k < c->pokes; k++) {
            b[c->poke[k].at] = c->poke[k].val;
        }
        const udsota_reason_t got = udsota_test_check_first(b, (c->len != 0u) ? c->len : sizeof b,
                                                            (c->size != 0u) ? c->size : 8192u);
        if (got != c->want) {
            fprintf(stderr, "%s:%d: first block %s: reason %d, want %d\n", __FILE__, __LINE__, c->name, (int)got,
                    (int)c->want);
            g_failures++;
        }
    }
    P.version = "0.4.1-lite.1";
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
    first_block_cases();
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
    EXPECT(B(0x27, 0x03), B(0x7F, 0x27, 0x36));   /* inside that delay: udsota_poll leaves a pending timer alone */
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
    CHECK(udsota_end_session(&s_srv) && s_srv.sessionType == UDS_LEV_DS_PRGS);   /* the reset is already scheduled */
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
    CHECK(g_now - t0 >= 90000u && s_pendings >= 50 && s_pendings <= 61);   /* every 1.5 s: P2 timers kept */
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

    /* 50 xx carries the server's P2* (5000 ms, in 10 ms units) beside iso14229's P2 of 150 ms. */
    s_allow_downgrade = false;
    P.st = (udsota_status_t){.running_slot = 0, .boot_slot = 0, .running_state = UDSOTA_IMG_VALID};
    P.expect = img;
    P.expect_len = sizeof img;
    boot();
    EXPECT(B(0x10, 0x03), B(0x50, 0x03, 0x00, 0x96, 0x01, 0xF4));

    /* udsota_end_session: an idle session ends at once, locked; the default session needs nothing. */
    unlock(0x01);
    CHECK(udsota_end_session(&s_srv) && s_srv.sessionType == UDS_LEV_DS_DS && s_srv.securityLevel == 0);
    CHECK(udsota_end_session(&s_srv));
    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));

    /* While a block's job runs it refuses, and the block is still answered; then the open download ends, ABORTED. */
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    unlock(0x03);
    request_download(sizeof img, 0x00);
    {
        static uint8_t req[2 + 4093];
        uint8_t resp[64];
        req[0] = 0x36;
        req[1] = 1;
        memcpy(&req[2], img, 4093);
        UDSSDU_t info = {.A_TA_Type = UDS_A_TA_TYPE_PHYSICAL};
        assert(UDSTpSend(s_tester, req, sizeof req, &info) == UDS_OK);
        int refusals = 0, n = -1;
        for (int ms = 0; ms < 10000 && n < 0; ms++) {
            g_now++;
            tick();
            if (s_srv.requestInProgress) {
                CHECK(!udsota_end_session(&s_srv));
                refusals++;
            }
            (void)UDSTpPoll(s_tester);
            size_t got = 0;
            if (UDSTpRecv(s_tester, resp, sizeof resp, &got, NULL) == UDS_OK && got > 0u &&
                !(got == 3u && resp[0] == 0x7Fu && resp[2] == 0x78u)) {
                n = (int)got;
            }
        }
        CHECK(refusals > 0 && n == 2 && resp[0] == 0x76 && resp[1] == 1);
    }
    CHECK(udsota_busy());
    CHECK(udsota_end_session(&s_srv) && s_srv.sessionType == UDS_LEV_DS_DS && !udsota_busy());
    EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_ABORTED, 0, 0, 0x0F, 0xFD));
    EXPECT(B(0x36, 0x02, 0x00), B(0x7F, 0x36, 0x70));

    /* With udsota not started, it still ends the app's session, lock and transfer. */
    udsota_test_reboot();
    s_srv.sessionType = UDS_LEV_DS_EXTDS;
    s_srv.securityLevel = 1;
    s_srv.xferIsActive = true;
    CHECK(udsota_end_session(&s_srv) && s_srv.sessionType == UDS_LEV_DS_DS && s_srv.securityLevel == 0 &&
          !s_srv.xferIsActive);

    /* udsota_poll leaves iso14229's 1 s boot delay alone while it runs: a 27 just after UDSServerInit gets 0x37. */
    boot();
    g_now -= 1500u;                               /* back to just after UDSServerInit */
    EXPECT(B(0x27, 0x01), B(0x7F, 0x27, 0x37));
    g_now += 1500u;

    /* udsota_poll: after 25.5 days of passes 2^20 ms apart (past 2^31 ms, the wrap), idle or answering a read on every
     * pass, a read, the programming session and a seed are answered at once. The controls run without it: an idle
     * server holds the read's answer, and a busy one answers 27 with 0x37, the boot delay read as pending again. */
    for (int pin = 1; pin >= 0; pin--) {
        for (int busy = 0; busy <= 1; busy++) {
            s_pin = pin != 0;
            boot();
            for (uint32_t i = 0; i < 2100u; i++) {
                g_now += 1u << 20;
                tick();
                if (busy) {
                    EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
                }
            }
            if (pin && !busy) {                  /* now - 1 reads as expired in the same millisecond; now would not */
                CHECK(s_srv.p2_timer == g_now - 1u && s_srv.sec_access_boot_delay_timer == g_now - 1u &&
                      s_srv.sec_access_auth_fail_timer == g_now - 1u);
            }
            if (!pin && !busy) {
                static const uint8_t read[] = {0x22, 0xF1, 0x86};
                CHECK(xfer(read, sizeof read, resp, sizeof resp) == -1);
                continue;
            }
            EXPECT(B(0x22, 0xF1, 0x86), B(0x62, 0xF1, 0x86, 0x01));
            EXPECT(B(0x10, 0x02), B(0x50, 0x02));
            if (pin) {
                EXPECT(B(0x27, 0x03), B(0x67, 0x03));
            } else {
                EXPECT(B(0x27, 0x03), B(0x7F, 0x27, 0x37));
            }
        }
    }
    s_pin = true;

    /* The PSA lock held by the app: a key answers 0x22 without running the crypto, and the seed is spent; once the
     * lock is free, the next seed's key unlocks. The same in the ECDSA mode, where a good signature unlocks. */
    for (int ecdsa = 0; ecdsa <= 1; ecdsa++) {
        s_ecdsa = ecdsa != 0;
        boot();
        EXPECT(B(0x10, 0x03), B(0x50, 0x03));
        uint8_t req[2 + 64] = {0x27, 0x01}, seed[64];
        const size_t key_len = ecdsa ? 64u : 16u;
        const int calls = P.psa_calls[ecdsa ? PSA_ECDSA : PSA_HMAC];
        CHECK(xfer(req, 2, seed, sizeof seed) == 18);
        req[1] = 0x02;
        if (ecdsa) {
            req[2] = 0x5A;
        } else {
            tester_key(&seed[2], 0x01, &req[2]);
        }
        CHECK(udsota_psa_lock(0));
        s_app_psa = 1;
        CHECK(xfer(req, 2 + key_len, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x22);
        CHECK(P.psa_calls[ecdsa ? PSA_ECDSA : PSA_HMAC] == calls);
        udsota_psa_unlock();
        s_app_psa = 0;
        g_now += 1100u;                           /* iso14229's delay after a refused key */
        req[1] = 0x01;
        CHECK(xfer(req, 2, seed, sizeof seed) == 18);
        req[1] = 0x02;
        if (!ecdsa) {
            tester_key(&seed[2], 0x01, &req[2]);
        }
        CHECK(xfer(req, 2 + key_len, resp, sizeof resp) == 2 && resp[0] == 0x67 && resp[1] == 0x02);
    }
    s_ecdsa = false;

    /* The ECDSA mode verifies UDSOTA_KEYS_SIG_TAG || seed || level || ID length || ID. For the client's known seed
     * (10..1F), level 03 and this device's MAC that is the client's SIG_MSG_L3 (client/tests/test_udsota.py), the bytes
     * it signs. */
    {
        static const uint8_t sig_msg_l3[] = {
            0x75, 0x64, 0x73, 0x6f, 0x74, 0x61, 0x2d, 0x32, 0x37, 0x2d, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x76, 0x31,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x03, 0x06,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        s_ecdsa = true;
        P.seed_kat = true;
        boot();
        EXPECT(B(0x10, 0x02), B(0x50, 0x02));
        uint8_t req[2 + 64] = {0x27, 0x03}, seed[64];
        CHECK(xfer(req, 2, seed, sizeof seed) == 18 && memcmp(&seed[2], &sig_msg_l3[18], 16) == 0);
        req[1] = 0x04;
        req[2] = 0x5A;                            /* the stand-in's valid signature */
        P.ecdsa_len = 0;
        CHECK(xfer(req, sizeof req, resp, sizeof resp) == 2 && resp[0] == 0x67 && resp[1] == 0x04);
        CHECK(P.ecdsa_len == sizeof sig_msg_l3 && memcmp(P.ecdsa_msg, sig_msg_l3, sizeof sig_msg_l3) == 0);
        s_ecdsa = false;
        P.seed_kat = false;
    }

    /* Security off (no keys, as examples/esp32 runs): every 27 is the app's, and a download needs no key, so 34, the
     * blocks, 37 and FF01 pass without one. */
    s_no_keys = true;
    boot();
    EXPECT(B(0x10, 0x02), B(0x50, 0x02));
    {
        const int app_27 = s_app_27;
        EXPECT(B(0x27, 0x03), B(0x7F, 0x27, 0x31));
        EXPECT(B(0x27, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), B(0x7F, 0x27, 0x31));
        CHECK(s_app_27 == app_27 + 2 && s_srv.securityLevel == 0);
    }
    memcpy(other, img, sizeof other);
    stamp(other, "0.4.1-lite.2", "udsota-test");
    P.expect = other;
    P.expect_len = sizeof other;
    request_download(sizeof other, 0x00);
    send_all(other, sizeof other);
    EXPECT(B(0x37), B(0x77));
    EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x71, 0x01, 0xFF, 0x01, 0x00));
    P.expect = img;
    P.expect_len = sizeof img;
    s_no_keys = false;

    /* A corrupt and a short compressed stream each end BAD_STREAM, the corrupt one at its 36 (0x31) and the short one
     * at the 37 (0x72), and neither image is verified: FF01 is out of sequence and the platform's end never runs. */
    {
        static uint8_t bad[5 + 1000 + 1] = {0x00, 0xE8, 0x03, 0x17, 0xFC};   /* a stored block of 1000 bytes, */
        memcpy(&bad[5], img, 1000);
        bad[sizeof bad - 1u] = 0x07;                                         /* then a final one of the reserved type */
        size_t zlen = 0;
        uint8_t *z = tdefl_compress_mem_to_heap(img, sizeof img, &zlen, TDEFL_DEFAULT_MAX_PROBES);
        assert(z != NULL && zlen > 2u * 320u);
        boot();
        const int ends = P.psa_calls[PSA_END];
        EXPECT(B(0x10, 0x02), B(0x50, 0x02));
        unlock(0x03);
        request_download(sizeof img, 0x10);
        CHECK(block(1, bad, 0, sizeof bad, resp, sizeof resp) == 3 && resp[0] == 0x7F && resp[2] == 0x31);
        EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_BAD_STREAM));
        EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x24));
        request_download(sizeof img, 0x10);
        send_all(z, zlen / 2u);
        EXPECT(B(0x37), B(0x7F, 0x37, 0x72));
        EXPECT(B(0x22, 0xF1, 0xF1), B(0x62, 0xF1, 0xF1, UDSOTA_DL_BAD_STREAM));
        EXPECT(B(0x31, 0x01, 0xFF, 0x01), B(0x7F, 0x31, 0x24));
        CHECK(P.psa_calls[PSA_END] == ends);
        mz_free(z);
    }

    /* Every PSA call of the run held the lock, and each kind ran. */
    CHECK(P.psa_unlocked == 0 && udsota_test_psa_depth() == 0);
    for (int i = 0; i < PSA_CALLS; i++) {
        CHECK(P.psa_calls[i] > 0);
    }

    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_udsota: all checks passed\n");
    return 0;
}
