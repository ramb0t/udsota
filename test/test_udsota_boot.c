/* Frame-level test of the bootloader core (boot/udsota_boot.c) on iso14229, compiled as a product compiles it, and the
 * fake port (test/boot/fake_port.c). A tester sends each request as ISO-TP frames through udsota_boot_rx, honouring
 * the core's flow control, and reassembles the answers the core hands to can_send, on a clock the test advances.
 * Each test starts at power-on with an erased slot and k_cfg, and ends with no breach of the port's contract and no
 * 0x78. A reboot is udsota_boot_init again: the fake's reset and start_app return, and the core is then stopped. The
 * twelve cases the core must carry are the functions named test_must_*. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "udsota_boot_internal.h"
#include "boot/fake_port.h"
#include "udsota.h"                 /* UDSOTA_VERSION, which F180 carries */
#include "fixtures/boot_fixtures.h"

static int g_failures;
static const char *g_test;
#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            fprintf(stderr, "%s:%d: %s: CHECK failed: %s\n", __FILE__, __LINE__, g_test, #cond);       \
            g_failures++;                                                                                \
        }                                                                                                \
    } while (0)

#define HDR        BOOT_IMAGE_HEADER_OFFSET                     /* the header in every image here */
#define KEEP_COUNT fake.keep[UDSOTA_KEEP_WORD_COUNT]
#define COUNT(n)   UDSOTA_START_COUNT_WORD(n)
#define BIT(b)     (1u << (b))
#define BOTH       (BIT(1) | BIT(2))
#define POWER_ON   UDSOTA_BOOT_RESET_POWER_ON
#define PIN        UDSOTA_BOOT_RESET_PIN
#define OTHER      UDSOTA_BOOT_RESET_OTHER
#define HANDOVER   UDSOTA_BOOT_DECIDE_HANDOVER
#define NO_APP     UDSOTA_BOOT_DECIDE_NO_APP
#define HELD       UDSOTA_BOOT_DECIDE_HELD
#define WINDOW     UDSOTA_BOOT_DECIDE_WINDOW
#define START_APP  UDSOTA_BOOT_DECIDE_START_APP
#define BAD_CFG    UDSOTA_BOOT_DECIDE_BAD_CFG

/* udsota's example identity, the fixture's, on two buses, with a 0x20000 slot and a write unit of 2. */
static const udsota_boot_cfg_t k_cfg = {
    .request_id = 0x710u, .response_id = 0x718u, .product = "example", .hw_id = 1u, .layout_id = 1u,
    .boot_version = "1.0.0", .buses = 2u, .slot_size = 0x20000u, .slot_write_unit = 2u,
    .image_header_offset = HDR, .window_ms = 100u, .hold_after_starts = 5u, .watchdog_ms = 1000u,
};
static const udsota_boot_cfg_t *g_cfg = &k_cfg;
static const uint8_t k_zeros[32];

/* ---- Images ---- */

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* The CRC field after any change to an image's bytes. */
static void restamp(uint8_t *img, uint32_t len)
{
    const uint32_t at = HDR + UDSOTA_BARE_HDR_CRC_OFFSET;
    put32(img + at, udsota_boot_crc32(udsota_boot_crc32(0u, img, at), img + at + 4u, len - at - 4u));
}

/* A valid image of len bytes: the fixture's header with that length and an image ID from seed, a body from seed. */
static void make_image(uint8_t *img, uint32_t len, uint8_t seed)
{
    for (uint32_t i = 0; i < len; i++) {
        img[i] = (uint8_t)(i * 13u + seed + (i >> 9));
    }
    memcpy(img + HDR, BOOT_IMAGE + HDR, UDSOTA_BARE_HDR_LEN);
    put32(img + HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET, len);
    for (uint32_t k = 0; k < 32u; k++) {
        img[HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_IMAGE_ID_OFFSET + k] = (uint8_t)(seed + k);
    }
    restamp(img, len);
}

static const uint8_t *image_id(const uint8_t *img)
{
    return img + HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_IMAGE_ID_OFFSET;
}

static uint8_t g_old[0x8000], g_new[0x8000];

/* An image in the slot as an SWD install would leave it. */
static void install(const uint8_t *img, uint32_t len)
{
    memset(fake.slot, 0xFF, fake.slot_size);
    memcpy(fake.slot, img, len);
}

/* A valid 2052-byte app from seed, in g_old and installed. */
static void install_app(uint8_t seed)
{
    make_image(g_old, 2052u, seed);
    install(g_old, 2052u);
}

/* ---- The clock and boots ---- */

static size_t   g_seen;            /* the core's frames the tester has read */
static int      g_78s;             /* 0x78 answers seen: the core never sends one */
static uint32_t g_sent_us;         /* when the tester's last request was complete */

static void step_us(uint32_t us)
{
    fake.us += us;
    udsota_boot_poll();
}

static void wait_ms(uint32_t ms)
{
    while (ms-- > 0u) {
        step_us(1000u);
    }
}

/* A boot with this cause: the buses stopped, as a reset leaves them, and the core's state from scratch. */
static udsota_boot_decision_t boot(udsota_boot_reset_t cause)
{
    fake.cause = cause;
    fake.started = 0u;
    g_seen = fake.n_frames;
    return udsota_boot_init(g_cfg);
}

/* The keep words of an app that took a 10 02 on bus. */
static void handover_to(uint8_t bus)
{
    fake.keep[UDSOTA_KEEP_WORD_HANDOVER] = bus;
    fake.keep[UDSOTA_KEEP_WORD_MARK] = UDSOTA_HANDOVER_MARK;
}

/* A boot held at the threshold. */
static bool boot_held(void)
{
    KEEP_COUNT = COUNT(5);
    return boot(OTHER) == HELD;
}

/* ---- The tester ---- */

static uint8_t  g_ans[4096];
static int      g_len;             /* the last answer's length, -1 for none */
static uint8_t  g_ans_bus;
static uint32_t g_ans_us;          /* when its first frame was handed to can_send */

static void frame_on(uint8_t bus, const uint8_t *d, uint8_t n)
{
    udsota_boot_rx(bus, g_cfg->request_id, d, n);
}

/* The next frame the core sent on its response ID, polling 1 ms at a time for up to ms; NULL if none. */
static const fake_frame_t *next_frame(uint32_t ms)
{
    for (uint32_t t = 0;; t++) {
        while (g_seen < fake.n_frames) {
            const fake_frame_t *f = &fake.frames[g_seen++];
            if (f->id == g_cfg->response_id) {
                return f;
            }
        }
        if (t >= ms) {
            return NULL;
        }
        step_us(1000u);
    }
}

/* req as ISO-TP frames on bus, padded with 0xAA, each block after the core's flow control. False when a flow control
 * the request needs did not come. */
static bool send_on(uint8_t bus, const uint8_t *req, size_t len)
{
    uint8_t f[8];
    memset(f, 0xAA, sizeof f);
    if (len <= 7u) {
        f[0] = (uint8_t)len;
        memcpy(f + 1, req, len);
        frame_on(bus, f, 8u);
        g_sent_us = fake.us;
        return true;
    }
    f[0] = (uint8_t)(0x10u | (len >> 8));
    f[1] = (uint8_t)len;
    memcpy(f + 2, req, 6u);
    frame_on(bus, f, 8u);
    size_t off = 6u;
    uint8_t sn = 1u;
    while (off < len) {
        const fake_frame_t *fc = next_frame(0u);
        if (fc == NULL || fc->data[0] != 0x30u || fc->bus != bus) {
            return false;
        }
        const uint8_t bs = fc->data[1];
        for (unsigned k = 0; (bs == 0u || k < bs) && off < len; k++) {
            const size_t n = (len - off < 7u) ? len - off : 7u;
            memset(f, 0xAA, sizeof f);
            f[0] = (uint8_t)(0x20u | sn);
            sn = (uint8_t)((sn + 1u) & 0x0Fu);
            memcpy(f + 1, req + off, n);
            frame_on(bus, f, 8u);
            off += n;
        }
    }
    g_sent_us = fake.us;
    return true;
}

/* The rest of a multi-frame answer whose first frame f is: the tester's flow control (BS 0, STmin 0), then the
 * consecutive frames, into g_ans. */
static bool answer_rest(const fake_frame_t *f)
{
    const int total = ((f->data[0] & 0x0F) << 8) | f->data[1];
    int got = 6;
    memcpy(g_ans, f->data + 2, 6u);
    frame_on(f->bus, (const uint8_t[]){0x30, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 8u);
    while (got < total) {
        f = next_frame(100u);
        if (f == NULL || (f->data[0] >> 4) != 2u) {
            return false;
        }
        const int n = (total - got < 7) ? total - got : 7;
        memcpy(g_ans + got, f->data + 1, (size_t)n);
        got += n;
    }
    g_len = total;
    return true;
}

/* The core's next answer, within ms, into g_ans. */
static bool answer(uint32_t ms)
{
    g_len = -1;
    const fake_frame_t *f = next_frame(ms);
    if (f == NULL) {
        return false;
    }
    g_ans_bus = f->bus;
    g_ans_us = f->us;
    if ((f->data[0] >> 4) == 0u) {
        g_len = f->data[0] & 0x0F;
        memcpy(g_ans, f->data + 1, (size_t)g_len);
    } else if ((f->data[0] >> 4) != 1u || !answer_rest(f)) {
        return false;
    }
    g_78s += (g_len == 3 && g_ans[0] == 0x7Fu && g_ans[2] == 0x78u);
    return true;
}

static bool ask_on(uint8_t bus, const uint8_t *req, size_t len)
{
    return send_on(bus, req, len) && answer(200u);
}

static bool ask(const uint8_t *req, size_t len) { return ask_on(1u, req, len); }

static bool is_ans(const uint8_t *want, size_t n) { return g_len == (int)n && memcmp(g_ans, want, n) == 0; }

static bool is_nrc(uint8_t sid, uint8_t nrc)
{
    return g_len == 3 && g_ans[0] == 0x7Fu && g_ans[1] == sid && g_ans[2] == nrc;
}

#define REQ(...)   (const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__})
#define ASK(...)   ask(REQ(__VA_ARGS__))
#define ANS(...)   is_ans(REQ(__VA_ARGS__))
#define NRC(s, n)  is_nrc((s), (n))
#define SESSION_ANSWER(t) ANS(0x50, (t), 0x00, 0x96, 0x01, 0xF4)   /* P2 150 ms, P2* 5000 ms */

/* ---- Requests ---- */

static bool programming(void) { return ASK(0x10, 0x02) && SESSION_ANSWER(0x02); }

static bool ask34(uint8_t dfi, uint8_t alfid, uint32_t addr, uint32_t size)
{
    uint8_t r[3 + 15 + 15] = {0x34, dfi, alfid};
    size_t n = 3u;
    for (unsigned i = alfid & 0x0Fu; i-- > 0u;) {
        r[n++] = (i < 4u) ? (uint8_t)(addr >> (8u * i)) : 0u;
    }
    for (unsigned i = alfid >> 4; i-- > 0u;) {
        r[n++] = (i < 4u) ? (uint8_t)(size >> (8u * i)) : 0u;
    }
    return ask(r, n);
}

/* 34 for a size-byte image, the usual way, and its positive answer. */
static bool open_download(uint32_t size) { return ask34(0x00, 0x44, 0u, size) && ANS(0x74, 0x20, 0x04, 0x02); }

static bool ask36(uint8_t counter, const uint8_t *data, size_t n)
{
    static uint8_t r[4096];
    r[0] = 0x36;
    r[1] = counter;
    memcpy(r + 2, data, n);
    return ask(r, n + 2u);
}

/* 34, 36s of block bytes and 37 for img, each answered positively. */
static bool send_image(const uint8_t *img, uint32_t len, uint32_t block)
{
    if (!open_download(len)) {
        return false;
    }
    uint8_t counter = 1u;
    for (uint32_t off = 0; off < len; off += block, counter++) {
        const uint32_t n = (len - off < block) ? len - off : block;
        if (!ask36(counter, img + off, n) || !ANS(0x76, counter)) {
            return false;
        }
    }
    return ASK(0x37) && ANS(0x77);
}

/* FF01's status, or -1 without a status. */
static int ff01(void)
{
    return (ASK(0x31, 0x01, 0xFF, 0x01) && g_len == 5 && g_ans[0] == 0x71u) ? g_ans[4] : -1;
}

/* send_image, then FF01's status; -1 where a step was not answered positively. */
static int download(const uint8_t *img, uint32_t len, uint32_t block)
{
    return send_image(img, len, block) ? ff01() : -1;
}

static bool activate(void) { return ASK(0x31, 0x01, 0xF0, 0x01) && ANS(0x71, 0x01, 0xF0, 0x01); }

/* F1F1 is reason and bytes. */
static bool result_is(uint8_t reason, uint32_t bytes)
{
    return ASK(0x22, 0xF1, 0xF1) &&
           ANS(0x62, 0xF1, 0xF1, reason, (uint8_t)(bytes >> 24), (uint8_t)(bytes >> 16), (uint8_t)(bytes >> 8),
               (uint8_t)bytes);
}

/* F1F0's running state (byte 1) and flags (byte 15), as one number: state << 8 | flags; -1 for no answer. */
static int status_of(void)
{
    if (!ASK(0x22, 0xF1, 0xF0) || g_len != 19 || g_ans[0] != 0x62u) {
        return -1;
    }
    return (g_ans[4] << 8) | g_ans[18];
}

static bool sw_version_is(const char *v)
{
    return ASK(0x22, 0xF1, 0x89) && g_len == 3 + (int)strlen(v) && memcmp(g_ans + 3, v, strlen(v)) == 0;
}

static bool image_id_is(const uint8_t *id)
{
    return ASK(0x22, 0xF1, 0xF3) && g_len == 35 && memcmp(g_ans + 3, id, 32u) == 0;
}

/* The core resets 60 ms after the poll that served the last request, the first after it was sent, polled every
 * poll_us. */
static bool resets_after_the_delay_at(uint32_t poll_us)
{
    const int before = fake.resets;
    while (fake.resets == before && fake.us - g_sent_us < 200000u) {
        step_us(poll_us);
    }
    const uint32_t after = fake.reset_us - g_sent_us;
    return fake.resets == before + 1 && after >= 60000u && after <= 62000u;
}

static bool resets_after_the_delay(void) { return resets_after_the_delay_at(1000u); }

/* ==== Whole updates ==== */

static void test_full_update_from_an_empty_slot(void)
{
    make_image(g_new, 2052u, 0x40);
    CHECK(boot(POWER_ON) == NO_APP && fake.started == BOTH);
    CHECK(ASK(0x22, 0xF1, 0xF4) && NRC(0x22, 0x31));             /* the client's first read: not the app */
    CHECK(programming());
    CHECK(status_of() == 0x0000);                                /* no valid app, not held */
    CHECK(sw_version_is("0.0.0") && image_id_is(k_zeros));
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(memcmp(fake.slot, g_new, 2052u) == 0);
    CHECK(result_is(UDSOTA_DL_OK, 2052u) && status_of() == 0x0300);
    CHECK(image_id_is(image_id(g_new)) && sw_version_is("1.0.0"));
    CHECK(activate() && KEEP_COUNT == UDSOTA_START_COUNT_CLEAR);
    CHECK(resets_after_the_delay());
    step_us(1000u);
    CHECK(fake.resets == 1);                                     /* stopped once it has reset */

    CHECK(boot(OTHER) == START_APP && fake.started == 0u && fake.starts == 0);   /* no bus for a start */
    step_us(1000u);
    CHECK(fake.starts == 1 && KEEP_COUNT == COUNT(1) && fake.wd_starts == 1 && fake.wd_period == 1000u);
    CHECK(fake.started_at_start == 0u && fake.wd_starts_at_start == 1);
}

static void test_full_update_over_a_valid_app(void)
{
    make_image(g_old, 3000u, 0x11);
    make_image(g_new, 4100u, 0x77);
    install(g_old, 3000u);
    handover_to(1u);
    CHECK(boot(OTHER) == HANDOVER);
    CHECK(answer(20u) && SESSION_ANSWER(0x02));                  /* the app's 10 02, answered by the core */
    CHECK(status_of() == 0x0300 && image_id_is(image_id(g_old)));
    CHECK(ASK(0x22, 0xF1, 0x8C) && g_len == 15 && g_ans[3] == 0xD0u && g_ans[14] == 0xDBu);
    CHECK(open_download(4100u));
    CHECK(ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(status_of() == 0x0000 && result_is(UDSOTA_DL_OK, 1024u));   /* the first erase: no valid app */
    uint8_t counter = 2u;
    for (uint32_t off = 1024u; off < 4100u; off += 1024u, counter++) {
        const uint32_t n = (4100u - off < 1024u) ? 4100u - off : 1024u;
        CHECK(ask36(counter, g_new + off, n) && ANS(0x76, counter));
    }
    CHECK(ASK(0x37) && ANS(0x77));
    CHECK(ff01() == UDSOTA_DL_OK && image_id_is(image_id(g_new)));
    CHECK(activate() && resets_after_the_delay());
    CHECK(boot(OTHER) == START_APP);
}

/* ==== Every service and refusal ==== */

static void test_session_control(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(programming());
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
    CHECK(programming());                                        /* again, in the session */
    CHECK(ASK(0x10, 0x03) && NRC(0x10, 0x12));
    CHECK(ASK(0x10, 0x04) && NRC(0x10, 0x12));
    CHECK(ASK(0x10, 0x60) && NRC(0x10, 0x12));
    CHECK(ASK(0x10) && NRC(0x10, 0x13));                         /* iso14229's */
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(send_on(1u, REQ(0x10, 0x82)) && !answer(50u));         /* suppressed, and taken */
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
}

static void test_tester_present(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x3E, 0x00) && ANS(0x7E, 0x00));
    CHECK(send_on(1u, REQ(0x3E, 0x80)) && !answer(50u));
    CHECK(ASK(0x3E, 0x01) && NRC(0x3E, 0x12));
    CHECK(programming());
    for (int i = 0; i < 4; i++) {                                /* 3E holds S3 for 12 s */
        wait_ms(3000u);
        CHECK(ASK(0x3E, 0x00) && ANS(0x7E, 0x00));
    }
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
}

static void test_ecu_reset(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x11, 0x01) && NRC(0x11, 0x7F));                   /* default session */
    CHECK(programming());
    CHECK(ASK(0x11, 0x02) && NRC(0x11, 0x12));
    CHECK(ASK(0x11, 0x03) && NRC(0x11, 0x12));
    CHECK(ASK(0x11) && NRC(0x11, 0x13));                         /* iso14229's */
    KEEP_COUNT = COUNT(4);
    CHECK(ASK(0x11, 0x01) && ANS(0x51, 0x01) && KEEP_COUNT == UDSOTA_START_COUNT_CLEAR);
    CHECK(resets_after_the_delay());
    CHECK(send_on(1u, REQ(0x22, 0xF1, 0x86)) && !answer(20u));   /* stopped */

    CHECK(boot(OTHER) == NO_APP && programming());               /* 11 81: no answer, the same reset */
    CHECK(send_on(1u, REQ(0x11, 0x81)) && resets_after_the_delay());
}

/* A repeated 11 01 or F001 inside the delay is answered and does not postpone the reset. */
static void test_a_repeat_inside_the_reset_delay_keeps_its_time(void)
{
    make_image(g_new, 2052u, 0x45);
    CHECK(boot(POWER_ON) == NO_APP && programming() && download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(activate());
    const uint32_t first = g_sent_us;
    while (fake.us - first < 40000u) {
        step_us(1000u);
    }
    CHECK(ASK(0x11, 0x01) && ANS(0x51, 0x01));
    while (fake.resets == 0 && fake.us - first < 200000u) {
        step_us(1000u);
    }
    CHECK(fake.resets == 1 && fake.reset_us - first >= 60000u && fake.reset_us - first <= 62000u);
}

static void test_dids_with_a_valid_app(void)
{
    install_app(0x22);
    handover_to(1u);
    CHECK(boot(OTHER) == HANDOVER);
    CHECK(answer(20u) && SESSION_ANSWER(0x02));
    static const char f180[] = "1.0.0 udsota/" UDSOTA_VERSION;
    CHECK(ASK(0x22, 0xF1, 0x80) && g_len == 3 + (int)strlen(f180) && memcmp(g_ans + 3, f180, strlen(f180)) == 0);
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
    CHECK(sw_version_is("1.0.0"));
    CHECK(ASK(0x22, 0xF1, 0x8C) && g_len == 15);
    CHECK(ASK(0x22, 0xF1, 0xF0) && ANS(0x62, 0xF1, 0xF0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    CHECK(result_is(UDSOTA_DL_OK, 0u));
    CHECK(image_id_is(image_id(g_old)));
    CHECK(ASK(0x22, 0xF1, 0xF4) && NRC(0x22, 0x31));             /* only the app answers it */
    CHECK(ASK(0x22, 0xF1, 0x91) && NRC(0x22, 0x31));             /* no board DID */
    CHECK(ASK(0x22, 0xF1, 0x90) && NRC(0x22, 0x31));
    CHECK(ASK(0x22, 0xF1, 0xF2) && NRC(0x22, 0x31));
    CHECK(ASK(0x22, 0x00, 0x00) && NRC(0x22, 0x31));
    CHECK(ASK(0x22, 0xF1) && NRC(0x22, 0x13));                   /* iso14229's */
    CHECK(ASK(0x22, 0xF1, 0x86, 0xF1, 0xF1) &&                   /* two in one */
          ANS(0x62, 0xF1, 0x86, 0x02, 0xF1, 0xF1, 0, 0, 0, 0, 0));
    CHECK(ASK(0x22, 0xF1, 0x86, 0xF1, 0x00) && NRC(0x22, 0x31));
    CHECK(ASK(0x22, 0xF1, 0xF3, 0xF1, 0xF3) && NRC(0x22, 0x14)); /* past the 64-byte answer buffer: iso14229's */
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));
    CHECK(ASK(0x22, 0xF1, 0x80) && g_len == 3 + (int)strlen(f180));   /* in any session */
    fake.devid_len = 32u;                                        /* a port that claims more than 16 bytes */
    CHECK(ASK(0x22, 0xF1, 0x8C) && g_len == 19 && memcmp(g_ans + 3, fake.devid, 16u) == 0);
}

/* Another boot_version in F180, and a version that fills its field answered whole. */
static void test_f180_and_a_full_version_field(void)
{
    static const udsota_boot_cfg_t other = {
        .request_id = 0x710u, .response_id = 0x718u, .product = "example", .hw_id = 1u, .layout_id = 1u,
        .boot_version = "2.3.4-rc1", .buses = 1u, .slot_size = 0x20000u, .slot_write_unit = 2u,
        .image_header_offset = HDR, .hold_after_starts = 5u,
    };
    g_cfg = &other;
    install_app(0x24);
    memset(fake.slot + HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_VERSION_OFFSET, 'v', 32u);
    restamp(fake.slot, 2052u);
    CHECK(boot(PIN) == START_APP);
    handover_to(1u);
    CHECK(boot(OTHER) == HANDOVER && answer(20u));
    CHECK(ASK(0x22, 0xF1, 0x89) && g_len == 35 && g_ans[3] == 'v' && g_ans[34] == 'v');
    CHECK(ASK(0x22, 0xF1, 0x80) && g_len == 3 + 9 + 8 + (int)strlen(UDSOTA_VERSION) &&
          memcmp(g_ans + 3, "2.3.4-rc1 udsota/", 17u) == 0);
}

static void test_request_download_refusals(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ask34(0x00, 0x44, 0u, 2052u) && NRC(0x34, 0x7F));      /* default session */
    CHECK(programming() && result_is(UDSOTA_DL_OK, 0u));
    CHECK(ask34(0x10, 0x44, 0u, 2052u) && NRC(0x34, 0x31));      /* DFI 10, 20, 30 */
    CHECK(ask34(0x20, 0x44, 0u, 2052u) && NRC(0x34, 0x31));
    CHECK(ask34(0x30, 0x44, 0u, 2052u) && NRC(0x34, 0x31));
    CHECK(ask34(0x01, 0x44, 0u, 2052u) && NRC(0x34, 0x31));
    CHECK(ask34(0x00, 0x44, 4u, 2052u) && NRC(0x34, 0x31));      /* address */
    CHECK(ask34(0x00, 0x44, 0u, 2050u) && NRC(0x34, 0x31));      /* not a multiple of 4 */
    CHECK(ask34(0x00, 0x44, 0u, 0u) && NRC(0x34, 0x31));
    CHECK(ask34(0x00, 0x44, 0u, HDR + UDSOTA_BARE_HDR_LEN - 4u) && NRC(0x34, 0x31));   /* ends before the header */
    CHECK(ask34(0x00, 0x44, 0u, 0x20004u) && NRC(0x34, 0x31));   /* past the slot */
    CHECK(ask34(0x00, 0x44, 0u, 0x40000u) && NRC(0x34, 0x31));
    CHECK(ASK(0x34, 0x00) && NRC(0x34, 0x13));                   /* iso14229's */
    CHECK(result_is(UDSOTA_DL_OK, 0u));                          /* F1F1 as it was */
    CHECK(open_download(0x20000u));                              /* the slot's size */
    CHECK(ask34(0x00, 0x44, 0u, 2052u) && NRC(0x34, 0x22));      /* a transfer is open: iso14229's */
    CHECK(programming() && open_download(HDR + UDSOTA_BARE_HDR_LEN));
    CHECK(fake.erase_calls == 0);
}

/* A 36 with no data, or not the last and off the write unit, answers 0x13 and ends the transfer, erasing nothing. */
static void test_36_refusals_end_the_transfer(void)
{
    make_image(g_new, 2052u, 0x33);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(ask36(1u, g_new, 1024u) && NRC(0x36, 0x70));           /* no transfer: iso14229's */
    CHECK(open_download(2052u));
    CHECK(ASK(0x36, 0x01) && NRC(0x36, 0x13));
    CHECK(result_is(UDSOTA_DL_ABORTED, 0u));
    CHECK(ask36(1u, g_new, 1024u) && NRC(0x36, 0x70));
    CHECK(open_download(2052u));
    CHECK(ask36(1u, g_new, 1023u) && NRC(0x36, 0x13));
    CHECK(result_is(UDSOTA_DL_ABORTED, 0u) && fake.erase_calls == 0);
}

/* A 37 with data, or before every announced byte, ends the transfer; FF01 then has no finished download. */
static void test_37_refusals(void)
{
    make_image(g_new, 2052u, 0x34);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(ASK(0x37) && NRC(0x37, 0x70));                         /* no transfer: iso14229's */
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ASK(0x37, 0x00) && NRC(0x37, 0x13));
    CHECK(result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ASK(0x37) && NRC(0x37, 0x24));
    CHECK(result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x24));
}

/* A resent 36 answers iso14229's 0x24 and a resent 37 0x70, and a resent FF01 after a pass 00 again. */
static void test_resent_36_37_and_ff01(void)
{
    make_image(g_new, 2052u, 0x35);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ask36(1u, g_new, 1024u) && NRC(0x36, 0x24));
    CHECK(open_download(2052u));
    CHECK(download(g_new, 2052u, 1024u) == -1);                  /* a transfer is open: 0x22 */
    CHECK(ASK(0x37) && NRC(0x37, 0x24));
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(ASK(0x37) && NRC(0x37, 0x70));
    CHECK(ff01() == UDSOTA_DL_OK);
}

/* A 36 longer than the block length: the transport refuses it with an overflow flow control. */
static void test_36_longer_than_the_block(void)
{
    make_image(g_new, 2052u, 0x36);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(open_download(2052u));
    CHECK(!ask36(1u, g_new, 1025u) && fake.frames[fake.n_frames - 1u].data[0] == 0x32u);
    CHECK(ASK(0x37) && NRC(0x37, 0x24));
    CHECK(download(g_new, 2052u, 512u) == UDSOTA_DL_OK);
}

static void test_routines(void)
{
    make_image(g_new, 2052u, 0x44);
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x7F));       /* default session, every RID */
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x7F));
    CHECK(ASK(0x31, 0x01, 0x12, 0x34) && NRC(0x31, 0x7F));
    CHECK(programming());
    CHECK(ASK(0x31, 0x02, 0xFF, 0x01) && NRC(0x31, 0x12));
    CHECK(ASK(0x31, 0x03, 0xF0, 0x01) && NRC(0x31, 0x12));
    CHECK(ASK(0x31, 0x04, 0xFF, 0x01) && NRC(0x31, 0x31));       /* iso14229's */
    CHECK(ASK(0x31, 0x01, 0xF0, 0x00) && NRC(0x31, 0x31));       /* F000, F002 and others: no such RID */
    CHECK(ASK(0x31, 0x01, 0xF0, 0x02) && NRC(0x31, 0x31));
    CHECK(ASK(0x31, 0x01, 0x12, 0x34) && NRC(0x31, 0x31));
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01, 0x00) && NRC(0x31, 0x13)); /* an option record */
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01, 0x00) && NRC(0x31, 0x13));
    CHECK(ASK(0x31, 0x01, 0xFF) && NRC(0x31, 0x13));             /* iso14229's */
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x24));       /* no finished download */
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x24));       /* no passing FF01 */
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));              /* the pass holds across sessions */
    CHECK(programming() && ff01() == UDSOTA_DL_OK);
    CHECK(ask34(0x00, 0x44, 0u, 2052u));                         /* until the next 34 */
    CHECK(ASK(0x37) && NRC(0x37, 0x24));
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x24));
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x24));
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(activate());
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02)); /* requests are read until the reset */
    wait_ms(70u);
    CHECK(fake.resets == 1);
}

static void test_security_access_is_not_served(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x27, 0x01) && NRC(0x27, 0x37));                   /* within 1 s of init: iso14229's */
    wait_ms(1000u);
    CHECK(ASK(0x27, 0x01) && NRC(0x27, 0x7F));
    CHECK(ASK(0x27, 0x03) && NRC(0x27, 0x7F));
    CHECK(programming());
    CHECK(ASK(0x27, 0x03) && NRC(0x27, 0x11));
    CHECK(ASK(0x27, 0x04, 0x00, 0x01) && NRC(0x27, 0x11));
    CHECK(ASK(0x27, 0x03) && NRC(0x27, 0x36));                   /* within 1 s of a refused key: iso14229's */
    CHECK(ASK(0x27) && NRC(0x27, 0x13));
}

/* ==== The twelve the core must carry ==== */

/* 1. A periodic request that is not a tester frame neither holds the window nor delays the idle exit, and a held or
 * app-less unit answers it with no 10 before it. */
static void test_must_not_hold_the_window_or_delay_the_idle_exit_for_a_periodic_request(void)
{
    install_app(0x01);
    CHECK(boot(POWER_ON) == WINDOW);
    const uint32_t t0 = fake.us;
    for (uint32_t i = 1; i <= 20u && fake.starts == 0; i++) {    /* 22 F1F4 every 20 ms */
        if (ASK(0x22, 0xF1, 0xF4)) {
            CHECK(NRC(0x22, 0x31));
        }
        while (fake.starts == 0 && fake.us - t0 < i * 20000u) {
            step_us(1000u);
        }
    }
    CHECK(fake.starts == 1 && fake.start_us - t0 >= 100000u && fake.start_us - t0 <= 102000u);

    CHECK(boot(POWER_ON) == WINDOW);                             /* the idle exit, with 22 F1F4 every second */
    CHECK(ASK(0x3E, 0x00) && ANS(0x7E, 0x00));
    const uint32_t tester = g_sent_us;
    while (fake.resets == 0 && fake.us - tester < 8000000u) {
        if (ASK(0x22, 0xF1, 0xF4)) {
            CHECK(NRC(0x22, 0x31));
        }
        for (int k = 0; k < 1000 && fake.resets == 0; k++) {
            step_us(1000u);
        }
    }
    CHECK(fake.resets == 1 && fake.reset_us - tester >= 5100000u && fake.reset_us - tester <= 5110000u);

    CHECK(boot_held() && status_of() == 0x0304);                 /* held, and with no app: no 10 first */
    for (int i = 0; i < 10; i++) {
        CHECK(ASK(0x22, 0xF1, 0xF4) && NRC(0x22, 0x31));
        wait_ms(1000u);
    }
    CHECK(fake.resets == 1 && fake.starts == 1 && fake.started == BOTH);
    memset(fake.slot, 0xFF, fake.slot_size);
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ASK(0x22, 0xF1, 0xF4) && NRC(0x22, 0x31) && status_of() == 0x0000);
}

/* 2. A handover mark that does not clear is not taken, so it cannot make every reset a handover boot. */
static void test_must_ignore_a_handover_mark_that_does_not_clear(void)
{
    install_app(0x02);
    fake.keep_stuck = BIT(UDSOTA_KEEP_WORD_MARK);
    for (int i = 0; i < 3; i++) {
        handover_to(1u);
        CHECK(boot(OTHER) == START_APP && fake.keep[UDSOTA_KEEP_WORD_MARK] == UDSOTA_HANDOVER_MARK);
        step_us(1000u);
    }
    CHECK(fake.starts == 3 && fake.start_calls == 0);
    memset(fake.slot, 0xFF, fake.slot_size);                     /* and with no app, the next rule */
    handover_to(1u);
    CHECK(boot(OTHER) == NO_APP && fake.started == BOTH);

    install(g_old, 2052u);                                       /* a mark that clears is taken once */
    fake.keep_stuck = 0u;
    handover_to(1u);
    CHECK(boot(OTHER) == HANDOVER);
    CHECK(fake.keep[UDSOTA_KEEP_WORD_MARK] == 0u && fake.keep[UDSOTA_KEEP_WORD_HANDOVER] == 0u);
    CHECK(boot(OTHER) == START_APP);
}

/* 3. An image rule's reason or a flash failure stays in F1F1 when the core later sees that iso14229 ended the
 * transfer. */
static void test_must_keep_a_recorded_reason_over_a_later_abort(void)
{
    make_image(g_new, 2052u, 0x03);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    static uint8_t bad[2052];
    memcpy(bad, g_new, sizeof bad);
    bad[HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET] = 'X';
    const struct {
        bool erase, program, flip, project;
        uint8_t nrc, reason;
    } cases[] = {
        {.project = true, .nrc = 0x31, .reason = UDSOTA_DL_BAD_PROJECT},
        {.erase = true, .nrc = 0x72, .reason = UDSOTA_DL_FLASH_ERROR},
        {.program = true, .nrc = 0x72, .reason = UDSOTA_DL_FLASH_ERROR},
        {.flip = true, .nrc = 0x72, .reason = UDSOTA_DL_FLASH_ERROR},          /* the compare fails */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK(open_download(2052u));
        fake.erase_fails = cases[i].erase;
        fake.program_fails = cases[i].program;
        fake.program_flips = cases[i].flip;
        CHECK(ask36(1u, cases[i].project ? bad : g_new, 1024u) && NRC(0x36, cases[i].nrc));
        fake.erase_fails = fake.program_fails = fake.program_flips = false;
        wait_ms(10u);
        CHECK(ask36(2u, g_new + 1024u, 1024u) && NRC(0x36, 0x70));
        CHECK(result_is(cases[i].reason, 0u));
        CHECK(programming() && result_is(cases[i].reason, 0u));  /* an accepted 10 */
    }
    CHECK(open_download(2052u));                                 /* and S3 */
    fake.program_fails = true;
    CHECK(ask36(1u, g_new, 1024u) && NRC(0x36, 0x72));
    fake.program_fails = false;
    wait_ms(5200u);
    CHECK(result_is(UDSOTA_DL_FLASH_ERROR, 0u));
}

/* 4. 10 02 during a download ends it, and the next 34 is taken; a 34 while a transfer is open gets iso14229's 0x22. */
static void test_must_end_a_download_on_10_02_and_take_the_next_34(void)
{
    make_image(g_new, 2052u, 0x04);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ask34(0x00, 0x44, 0u, 2052u) && NRC(0x34, 0x22));
    CHECK(programming() && result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(ask36(2u, g_new + 1024u, 1024u) && NRC(0x36, 0x70));
    CHECK(open_download(2052u) && result_is(UDSOTA_DL_OK, 0u));
    CHECK(ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));              /* 10 01 too */
    CHECK(result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(programming() && download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
}

/* 5. A refused first block erases nothing, and the installed image still validates. */
static void test_must_erase_nothing_for_a_refused_first_block(void)
{
    install_app(0x05);
    make_image(g_new, 2052u, 0x55);
    CHECK(boot_held() && programming());
    const struct {
        uint16_t at;
        uint8_t  val;
        uint8_t  reason;
    } pokes[] = {
        {HDR + 0u, 0x00, UDSOTA_DL_BAD_HEADER},
        {HDR + 7u, 0x01, UDSOTA_DL_BAD_HEADER},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET, 'E', UDSOTA_DL_BAD_PROJECT},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 6u, 2u, UDSOTA_DL_BAD_BOARD},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 7u, 2u, UDSOTA_DL_BAD_LAYOUT},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 8u, 0x11, UDSOTA_DL_BAD_DIAG_IDS},
        {HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET + 2u, 0x02, UDSOTA_DL_TOO_BIG},
    };
    static uint8_t bad[2052];
    for (size_t i = 0; i < sizeof pokes / sizeof pokes[0]; i++) {
        memcpy(bad, g_new, sizeof bad);
        bad[pokes[i].at] = pokes[i].val;
        CHECK(open_download(2052u));
        CHECK(ask36(1u, bad, 1024u) && NRC(0x36, 0x31));
        CHECK(result_is(pokes[i].reason, 0u));
    }
    CHECK(open_download(2056u));                                 /* image_length other than memorySize */
    CHECK(ask36(1u, g_new, 1024u) && NRC(0x36, 0x31));
    CHECK(result_is(UDSOTA_DL_BAD_HEADER, 0u));
    CHECK(open_download(2052u));                                 /* a first block that ends inside the header */
    CHECK(ask36(1u, g_new, HDR + 100u) && NRC(0x36, 0x31));
    CHECK(result_is(UDSOTA_DL_BAD_HEADER, 0u));
    CHECK(fake.erase_calls == 0 && fake.program_calls == 0);
    CHECK(memcmp(fake.slot, g_old, 2052u) == 0 && status_of() == 0x0304);
    KEEP_COUNT = COUNT(0);
    CHECK(boot(OTHER) == START_APP);
}

/* 6. The start count rises once per start, clears on a power-on, a pin-only reset, F001 and 11 01, holds the unit at
 * the threshold, and both session exits reset only when the boot rules would start the app. */
static void count_rises_once_per_start_and_holds(void)
{
    CHECK(boot(POWER_ON) == WINDOW && KEEP_COUNT == COUNT(0));
    wait_ms(110u);
    CHECK(fake.starts == 1 && KEEP_COUNT == COUNT(1));
    for (int i = 1; i < 5; i++) {
        CHECK(boot(OTHER) == START_APP && KEEP_COUNT == COUNT(i));
        wait_ms(2u);
        CHECK(fake.starts == i + 1 && KEEP_COUNT == COUNT(i + 1));
    }
    CHECK(boot(OTHER) == HELD);
    wait_ms(10u);
    CHECK(fake.starts == 5 && KEEP_COUNT == COUNT(5) && status_of() == 0x0304);
    CHECK(boot(PIN) == START_APP && KEEP_COUNT == COUNT(0));      /* a pin-only reset clears it */
    step_us(1000u);
    CHECK(KEEP_COUNT == COUNT(1));
    KEEP_COUNT = COUNT(9);
    CHECK(boot(POWER_ON) == WINDOW && KEEP_COUNT == COUNT(0));    /* and a power-on */
}

static void count_clears_on_11_01_and_f001(void)
{
    CHECK(boot_held() && programming());
    CHECK(ASK(0x11, 0x01) && ANS(0x51, 0x01) && resets_after_the_delay());
    CHECK(KEEP_COUNT == UDSOTA_START_COUNT_CLEAR && boot(OTHER) == START_APP);
    KEEP_COUNT = COUNT(7);
    CHECK(boot(OTHER) == HELD && programming() && download(g_old, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(KEEP_COUNT == COUNT(7) && status_of() == 0x0304);
    CHECK(activate() && resets_after_the_delay() && KEEP_COUNT == UDSOTA_START_COUNT_CLEAR);
}

static void session_exits_reset_only_to_start_the_app(void)
{
    const int resets = fake.resets;
    CHECK(boot_held());                                          /* held: back to listening on every bus */
    CHECK(ask_on(2u, REQ(0x10, 0x02)) && SESSION_ANSWER(0x02) && fake.started == BIT(2));
    const int start_calls = fake.start_calls;
    wait_ms(5200u);                                              /* S3 */
    CHECK(fake.resets == resets && fake.started == BOTH && fake.start_calls == start_calls + 2);
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01) && g_ans_bus == 1u);
    CHECK(ask_on(2u, REQ(0x3E, 0x00)) && ANS(0x7E, 0x00));
    wait_ms(5200u);                                              /* the idle exit */
    CHECK(fake.resets == resets && fake.started == BOTH);
    CHECK(ask_on(2u, REQ(0x10, 0x02)) && SESSION_ANSWER(0x02));
    KEEP_COUNT = UDSOTA_START_COUNT_CLEAR;                       /* the app's healthy mark, as the app writes it */
    wait_ms(5200u);
    CHECK(fake.resets == resets + 1);

    const int starts = fake.starts;                              /* when the app would start: a reset */
    CHECK(boot(POWER_ON) == WINDOW && programming());
    wait_ms(5200u);
    CHECK(fake.resets == resets + 2 && fake.starts == starts && KEEP_COUNT == COUNT(0));
    CHECK(boot(POWER_ON) == WINDOW && programming() && ASK(0x10, 0x01) && SESSION_ANSWER(0x01));
    wait_ms(5200u);
    CHECK(fake.resets == resets + 3 && fake.starts == starts);
}

static void count_saturates_and_a_lost_increment_still_starts(void)
{
    static const udsota_boot_cfg_t hold_255 = {
        .request_id = 0x710u, .response_id = 0x718u, .product = "example", .boot_version = "1", .buses = 1u,
        .slot_size = 0x20000u, .slot_write_unit = 2u, .image_header_offset = HDR, .hold_after_starts = 255u,
    };
    g_cfg = &hold_255;
    KEEP_COUNT = COUNT(255);
    CHECK(boot(OTHER) == HELD);
    KEEP_COUNT = COUNT(254);
    const int wd_starts = fake.wd_starts;
    CHECK(boot(OTHER) == START_APP);
    step_us(1000u);
    CHECK(KEEP_COUNT == COUNT(255) && fake.wd_starts == wd_starts);   /* watchdog_ms 0: none started */
    g_cfg = &k_cfg;
    const int starts = fake.starts;
    KEEP_COUNT = COUNT(4);
    fake.keep_stuck = BIT(UDSOTA_KEEP_WORD_COUNT);
    for (int i = 0; i < 3; i++) {
        CHECK(boot(OTHER) == START_APP);
        step_us(1000u);
    }
    CHECK(fake.starts == starts + 3 && KEEP_COUNT == COUNT(4));
    KEEP_COUNT = COUNT(9);                                       /* F1F0's flag is the decision's count */
    memset(fake.slot, 0xFF, fake.slot_size);
    CHECK(boot(POWER_ON) == NO_APP && KEEP_COUNT == COUNT(9) && status_of() == 0x0000);
}

static void test_must_count_starts_clear_them_and_hold_at_the_threshold(void)
{
    install_app(0x06);
    count_rises_once_per_start_and_holds();
    count_clears_on_11_01_and_f001();
    session_exits_reset_only_to_start_the_app();
    count_saturates_and_a_lost_increment_still_starts();
}

/* 7. The handover's 50 02 leaves about 6 ms after init, so its bus runs before the first poll; a send that fails loses
 * that answer, not the next. */
static void test_must_send_the_handover_answer_6_ms_after_init_on_a_started_bus(void)
{
    install_app(0x07);
    handover_to(2u);
    CHECK(boot(OTHER) == HANDOVER);
    const uint32_t t0 = fake.us;
    CHECK(fake.started == BIT(2) && fake.start_calls == 1);
    CHECK(answer(20u) && SESSION_ANSWER(0x02) && g_ans_bus == 2u);
    CHECK(g_ans_us - t0 >= 5000u && g_ans_us - t0 <= 7000u);
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0x86)) && ANS(0x62, 0xF1, 0x86, 0x02));
    const int sends = fake.send_calls;
    CHECK(send_on(1u, REQ(0x22, 0xF1, 0x86)) && !answer(20u) && fake.send_calls == sends);   /* that bus only */
    CHECK(KEEP_COUNT == COUNT(0));                               /* a handover boot adds nothing */

    handover_to(1u);                                             /* a send that fails loses that answer */
    CHECK(boot(OTHER) == HANDOVER);
    fake.send_fails = true;
    CHECK(!answer(20u));
    fake.send_fails = false;
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
    fake.send_fails = true;                                      /* a multi-frame answer's first frame */
    CHECK(send_on(1u, REQ(0x22, 0xF1, 0xF0)) && !answer(20u));
    fake.send_fails = false;
    CHECK(status_of() == 0x0300);

    handover_to(2u);                                             /* a bus that does not start: the next rule */
    fake.absent = BIT(2);
    CHECK(boot(OTHER) == START_APP);
    handover_to(2u);
    memset(fake.slot, 0xFF, fake.slot_size);
    CHECK(boot(OTHER) == NO_APP && fake.started == BIT(1));
    CHECK(ASK(0x22, 0xF1, 0x86) && g_ans_bus == 1u);
}

/* 8. A clock carried with its remainder advances in a loop faster than 1 ms, and the three millisecond timers are
 * aged, so a unit that sits in its bootloader past 24.86 days still answers at once. */
static void test_must_carry_the_clock_remainder_and_age_the_timers(void)
{
    CHECK(boot(OTHER) == NO_APP && programming() && ASK(0x11, 0x01) && ANS(0x51, 0x01));
    CHECK(resets_after_the_delay_at(300u));                      /* a poll every 0.3 ms */
    CHECK(boot(OTHER) == NO_APP && programming() && ASK(0x11, 0x01) && ANS(0x51, 0x01));
    CHECK(resets_after_the_delay_at(7u));                        /* a poll every 7 us */

    CHECK(boot(OTHER) == NO_APP);
    wait_ms(1000u);
    CHECK(ASK(0x27, 0x02) && NRC(0x27, 0x7F));                   /* sets iso14229's failed-key delay */
    for (uint32_t i = 0; i < 25u * 24u * 60u; i++) {             /* 25 days, a poll a minute */
        step_us(60000000u);
    }
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01) && g_ans_us - g_sent_us <= 7000u);   /* P2 aged */
    CHECK(ASK(0x27, 0x01) && NRC(0x27, 0x7F));                   /* neither 0x37 nor 0x36: both delays aged */
    CHECK(programming() && ASK(0x27, 0x03) && NRC(0x27, 0x11));
}

/* 9. FF01 runs the image rules on the bytes in the slot before the CRC, so when both fail the rule's reason is the
 * status, and writes its status to F1F1 byte 0 with the byte count as it was. */
static void test_must_report_ff01_in_f1f1_with_the_image_rules_before_the_crc(void)
{
    make_image(g_new, 2052u, 0x09);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    const struct {
        uint32_t at;
        uint8_t  status;
    } cases[] = {
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET + 1u, UDSOTA_DL_BAD_PROJECT},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 7u, UDSOTA_DL_BAD_LAYOUT},
        {HDR + 0u, UDSOTA_DL_BAD_HEADER},
        {HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET + 1u, UDSOTA_DL_BAD_HEADER},   /* image_length against memorySize */
        {2000u, UDSOTA_DL_VERIFY_FAILED},                                   /* the body: the CRC alone */
        {HDR + UDSOTA_BARE_HDR_CRC_OFFSET, UDSOTA_DL_VERIFY_FAILED},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK(send_image(g_new, 2052u, 1024u));
        fake.slot[cases[i].at] ^= 0x10u;                         /* changed in the slot after the 37 */
        if (cases[i].status != UDSOTA_DL_VERIFY_FAILED) {
            fake.slot[1500u] ^= 0x01u;                           /* and the CRC broken too */
        }
        CHECK(ff01() == cases[i].status && result_is(cases[i].status, 2052u));
        CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x24));   /* after a failure */
        CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x24));
        CHECK(status_of() == 0x0000);
    }
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(result_is(UDSOTA_DL_OK, 2052u) && status_of() == 0x0300);
}

/* 10. A transfer iso14229 ended without an event (0x24, 0x71, a 36 shorter than 2 bytes) is noticed at the end of
 * that poll: F1F1 reads ABORTED. */
static void test_must_notice_a_transfer_iso14229_ended_without_an_event(void)
{
    make_image(g_new, 2052u, 0x10);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u));
    CHECK(ask36(3u, g_new + 1024u, 1024u) && NRC(0x36, 0x24));
    CHECK(result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ask36(2u, g_new + 1024u, 1024u));
    CHECK(ask36(3u, g_new + 2048u, 8u) && NRC(0x36, 0x71));
    CHECK(result_is(UDSOTA_DL_ABORTED, 2048u));
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u));
    CHECK(ASK(0x36) && NRC(0x36, 0x13));
    wait_ms(10u);                                                /* polls only, then the read */
    CHECK(result_is(UDSOTA_DL_ABORTED, 1024u));
    CHECK(ASK(0x37) && NRC(0x37, 0x70));
    CHECK(ASK(0x31, 0x01, 0xFF, 0x01) && NRC(0x31, 0x24));
}

/* 11. Every 10 02 in the power-up window is answered, repeats included. */
static void test_must_answer_every_10_02_in_the_window(void)
{
    install_app(0x11);
    CHECK(boot(POWER_ON) == WINDOW);
    int answered = 0;
    for (int i = 0; i < 20; i++) {                               /* every 10 ms, through and past the window */
        CHECK(send_on(1u, REQ(0x10, 0x02)));
        answered += answer(10u) && SESSION_ANSWER(0x02);
        while (fake.us % 10000u != 0u) {
            step_us(1000u - fake.us % 1000u);
        }
    }
    CHECK(answered == 20 && fake.starts == 0);
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
}

/* 12. An event the core does not serve answers 0x11, never iso14229's default positive answer, and the 34's ALFID
 * nibbles are held to 1-4 by the core, since iso14229's bound is sizeof(size_t). */
static void test_must_refuse_unserved_events_with_0x11_and_check_the_alfid(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    for (int session = 1; session <= 2; session++) {
        CHECK(ASK(0x10, (uint8_t)session) && SESSION_ANSWER(session));
        CHECK(ASK(0x14, 0xFF, 0xFF, 0xFF) && NRC(0x14, 0x11));
        CHECK(ASK(0x19, 0x01, 0xFF) && NRC(0x19, 0x11));
        CHECK(ASK(0x19, 0x0A) && NRC(0x19, 0x11));
        CHECK(ASK(0x23, 0x11, 0x00, 0x01) && NRC(0x23, 0x11));
        CHECK(ASK(0x28, 0x00, 0x01) && NRC(0x28, 0x11));
        CHECK(ASK(0x2C, 0x03, 0xF2, 0x00) && NRC(0x2C, 0x11));
        CHECK(ASK(0x2E, 0xF1, 0x90, 0x01) && NRC(0x2E, 0x11));
        CHECK(ASK(0x2F, 0xF1, 0x90, 0x00) && NRC(0x2F, 0x11));
        CHECK(ASK(0x35, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 0, 16) && NRC(0x35, 0x11));
        CHECK(ASK(0x3D, 0x11, 0x00, 0x01, 0xAA) && NRC(0x3D, 0x11));
        CHECK(ASK(0x85, 0x01) && NRC(0x85, 0x11));
        CHECK(ASK(0x87, 0x01, 0x01) && NRC(0x87, 0x11));
        CHECK(ASK(0xBA, 0x01) && NRC(0xBA, 0x11));                /* iso14229's custom event */
        CHECK(ASK(0x00) && NRC(0x00, 0x11));
        CHECK(ASK(0xC5) && NRC(0xC5, 0x11));                      /* iso14229's own */
    }
    const uint8_t bad[] = {0x45, 0x54, 0x55, 0x48, 0x84, 0x88, 0x04, 0x40, 0x00, 0x0F, 0xF4};
    for (size_t i = 0; i < sizeof bad; i++) {
        CHECK(ask34(0x00, bad[i], 0u, 2052u) && NRC(0x34, 0x31));
    }
    const uint8_t good[] = {0x44, 0x24, 0x34, 0x21, 0x41, 0x42, 0x22, 0x33};
    for (size_t i = 0; i < sizeof good; i++) {
        CHECK(ask34(0x00, good[i], 0u, 2052u) && ANS(0x74, 0x20, 0x04, 0x02));
        CHECK(programming());
    }
    CHECK(ask34(0x00, 0x11, 0u, 0xFFu) && NRC(0x34, 0x31));      /* a 1-byte size that ends before the header */
}

/* ==== The boot check ==== */

static void test_boot_check(void)
{
    make_image(g_old, 0x8000u, 0x21);                            /* 32 KB: eight CRC pieces */
    const struct {
        uint32_t at;
        uint8_t  val;
        bool     valid;
    } cases[] = {
        {0u, 0u, true},
        {0x7FFFu, 0x5A, false},                                  /* the body */
        {HDR + 0u, 0x00, false},                                 /* magic */
        {HDR + 4u, 0x00, false},                                 /* header_version 0 */
        {HDR + 4u, 0x02, true},                                  /* 2 */
        {HDR + 6u, 0x01, true},                                  /* a low-byte flag */
        {HDR + 7u, 0x01, false},                                 /* a high-byte flag */
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET, 'Z', true},   /* no identity rule */
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 6u, 9u, true},
        {HDR + UDSOTA_BARE_HDR_DESC_OFFSET + 8u, 0x00, true},
        {HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET + 0u, 0x02, false}, /* not a multiple of 4 */
        {HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET + 2u, 0x02, false}, /* past the slot */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        install(g_old, 0x8000u);
        fake.slot[cases[i].at] = (cases[i].at == 0u) ? g_old[0] : cases[i].val;
        if (cases[i].valid) {
            restamp(fake.slot, 0x8000u);
        }
        const int reloads = fake.wd_reloads;
        CHECK(boot(OTHER) == (cases[i].valid ? START_APP : NO_APP));
        if (i == 0u) {
            CHECK(fake.wd_reloads - reloads >= 8);               /* the watchdog reloaded between the pieces */
        }
    }
    install(g_old, 0x8000u);
    put32(fake.slot + HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET, HDR + UDSOTA_BARE_HDR_LEN);   /* the shortest image */
    restamp(fake.slot, HDR + UDSOTA_BARE_HDR_LEN);
    CHECK(boot(OTHER) == START_APP);
    put32(fake.slot + HDR + UDSOTA_BARE_HDR_LENGTH_OFFSET, HDR + UDSOTA_BARE_HDR_LEN - 4u);
    restamp(fake.slot, HDR + UDSOTA_BARE_HDR_LEN);
    CHECK(boot(OTHER) == NO_APP);
    CHECK(boot(PIN) == NO_APP && fake.cause_calls == 15);
    install(BOOT_IMAGE, BOOT_IMAGE_SIZE);
    CHECK(boot(OTHER) == START_APP);                             /* the client's stamp, checked by the core */
}

/* ==== The buses ==== */

/* Before a lock, each request is answered on its own bus, and no bus is stopped. */
static void test_each_request_is_answered_on_its_bus(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0x86)) && g_ans_bus == 2u);
    CHECK(ask_on(1u, REQ(0x22, 0xF1, 0x86)) && g_ans_bus == 1u);
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0xF0)) && g_len == 19 && g_ans_bus == 2u);
    CHECK(fake.started == BOTH);
}

/* From a request's first frame until its whole answer has gone, another bus's frames are dropped, a tester frame's
 * included; a first frame chooses no bus. */
static void test_a_request_holds_its_bus_until_answered(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    frame_on(1u, (const uint8_t[]){0x10, 0x09, 0x22, 0xF1, 0x86, 0xF1, 0x89, 0xF1}, 8u);
    const fake_frame_t *fc = next_frame(0u);
    CHECK(fc != NULL && fc->data[0] == 0x30u && fc->bus == 1u);
    CHECK(send_on(2u, REQ(0x3E, 0x00)) && !answer(0u));          /* dropped: no lock either */
    frame_on(1u, (const uint8_t[]){0x21, 0x8C, 0xF1, 0xF0, 0xAA, 0xAA, 0xAA, 0xAA}, 8u);
    const fake_frame_t *ff = next_frame(20u);                    /* a multi-frame answer's first frame */
    CHECK(ff != NULL && ff->bus == 1u && (ff->data[0] >> 4) == 1u);
    CHECK(send_on(2u, REQ(0x22, 0xF1, 0x86)));                   /* dropped while the answer is sent */
    CHECK(ff != NULL && answer_rest(ff) && g_len == 3 + 1 + 2 + 5 + 2 + 12 + 2 + 16);
    CHECK(!answer(20u) && fake.started == BOTH);
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0x86)) && g_ans_bus == 2u);
}

/* A complete request that waits for the next poll holds its bus too, and so does one iso14229 has taken and holds for
 * P2: another bus's frame neither replaces it nor takes its answer. */
static void test_a_waiting_request_holds_its_bus(void)
{
    static const uint8_t f186[8] = {0x03, 0x22, 0xF1, 0x86, 0xAA, 0xAA, 0xAA, 0xAA};
    static const uint8_t f189[8] = {0x03, 0x22, 0xF1, 0x89, 0xAA, 0xAA, 0xAA, 0xAA};
    CHECK(boot(POWER_ON) == NO_APP);
    frame_on(1u, f186, 8u);
    frame_on(2u, f189, 8u);
    CHECK(answer(20u) && g_ans_bus == 1u && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(!answer(20u));
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0x86)) && g_ans_bus == 2u);
    frame_on(2u, f186, 8u);                                      /* served at once, answered P2 after the last */
    step_us(1000u);
    frame_on(1u, f189, 8u);
    CHECK(answer(20u) && g_ans_bus == 2u && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(!answer(20u));
}

/* A tester frame, 10 02, 3E 00 or 3E 80, locks its bus and stops the others until the core listens again. */
static void test_a_tester_frame_locks_its_bus_until_listening_again(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    CHECK(ask_on(2u, REQ(0x10, 0x02)) && SESSION_ANSWER(0x02) && g_ans_bus == 2u && fake.started == BIT(2));
    CHECK(send_on(1u, REQ(0x10, 0x01)) && !answer(20u));         /* queued before the stop: not served */
    CHECK(ask_on(2u, REQ(0x22, 0xF1, 0x86)) && ANS(0x62, 0xF1, 0x86, 0x02));
    CHECK(send_on(1u, REQ(0x10, 0x02)) && !answer(20u));
    CHECK(ask_on(2u, REQ(0x10, 0x01)) && SESSION_ANSWER(0x01));
    wait_ms(5100u);                                              /* the idle exit, 5.1 s after the 10 02 */
    CHECK(fake.started == BOTH && fake.resets == 0);
    CHECK(send_on(1u, REQ(0x3E, 0x80)) && !answer(20u) && fake.started == BIT(1));
    CHECK(ask_on(1u, REQ(0x22, 0xF1, 0x86)) && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(boot(POWER_ON) == NO_APP);                             /* an unpadded one */
    frame_on(2u, (const uint8_t[]){0x02, 0x3E, 0x00}, 3u);
    CHECK(answer(20u) && ANS(0x7E, 0x00) && fake.started == BIT(2));
    CHECK(boot(POWER_ON) == NO_APP);                             /* no tester frames: 10 82, 10 02 with a byte */
    CHECK(send_on(2u, REQ(0x10, 0x82)) && !answer(20u));
    CHECK(ask_on(2u, REQ(0x10, 0x02, 0x00)) && ask_on(2u, REQ(0x22, 0xF1, 0x86)) && fake.started == BOTH);
}

/* The idle exit waits for a request in flight: a 22 F1F0 sent 3 ms before it, whose answer is still being sent when
 * the exit falls due, gets its whole answer, and the exit follows in the poll that sent the last frame. */
static void test_the_idle_exit_waits_for_a_request_in_flight(void)
{
    CHECK(boot(POWER_ON) == NO_APP && ASK(0x3E, 0x00) && ANS(0x7E, 0x00) && fake.started == BIT(1));
    const uint32_t tester = g_sent_us;
    while (fake.us - tester < 5097000u) {
        step_us(1000u);
    }
    CHECK(ASK(0x22, 0xF1, 0xF0) && g_len == 19 && g_ans_us - tester < 5100000u);
    CHECK(fake.started == BOTH && fake.us - tester <= 5102000u + 2u * fake.can_start_us);   /* then the exit */
}

/* The idle exit runs in the default session only; outside it S3 decides, which 10 restarts as well. */
static void test_the_idle_exit_runs_in_the_default_session_only(void)
{
    CHECK(boot(POWER_ON) == NO_APP && programming() && fake.started == BIT(1));
    wait_ms(3000u);
    CHECK(send_on(1u, REQ(0x10, 0x82)) && !answer(20u));         /* no tester frame, but S3 restarts */
    wait_ms(2500u);                                              /* 5.5 s after the tester frame */
    CHECK(fake.started == BIT(1) && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
    wait_ms(3000u);                                              /* S3 */
    CHECK(fake.started == BOTH && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
}

static void test_ignored_frames(void)
{
    CHECK(boot(POWER_ON) == NO_APP);
    const uint8_t sf[8] = {0x02, 0x10, 0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    udsota_boot_rx(1u, 0x711u, sf, 8u);                          /* another ID */
    udsota_boot_rx(3u, 0x710u, sf, 8u);                          /* a bus past cfg.buses */
    udsota_boot_rx(0u, 0x710u, sf, 8u);
    udsota_boot_rx(1u, 0x710u, sf, 9u);                          /* longer than 8 */
    CHECK(!answer(20u) && fake.started == BOTH);
    install_app(0x12);                                           /* before the first poll of a start */
    CHECK(boot(OTHER) == START_APP);
    udsota_boot_rx(1u, 0x710u, sf, 8u);
    step_us(1000u);
    CHECK(fake.starts == 1 && fake.n_frames == 0u);
}

/* ==== The window, the configurations, the geometries ==== */

static void test_window(void)
{
    install_app(0x31);
    CHECK(boot(POWER_ON) == WINDOW && fake.started == BOTH);
    const uint32_t t0 = fake.us;
    wait_ms(99u);
    CHECK(fake.starts == 0);
    wait_ms(2u);
    CHECK(fake.starts == 1 && fake.start_us - t0 >= 100000u && fake.started_at_start == 0u);
    CHECK(fake.wd_starts == 1 && KEEP_COUNT == COUNT(1));
    CHECK(boot(PIN) == START_APP);                               /* no window */
    CHECK(boot(POWER_ON) == WINDOW);                             /* a tester frame holds it */
    CHECK(ask_on(2u, REQ(0x10, 0x02)) && SESSION_ANSWER(0x02));
    wait_ms(1000u);
    CHECK(fake.starts == 1 && fake.started == BIT(2));
}

/* The window's end starts the app only while it is valid and the session is the default. A download, or a session
 * entered without a tester frame (10 82, 10 02 with a byte more), keeps the unit listening. */
static void test_the_window_ends_in_a_start_only_for_a_valid_app_in_the_default_session(void)
{
    make_image(g_new, 2052u, 0x32);
    install_app(0x31);
    CHECK(boot(POWER_ON) == WINDOW && send_on(1u, REQ(0x10, 0x82)) && !answer(10u));
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    CHECK(ASK(0x10, 0x01) && SESSION_ANSWER(0x01));              /* the default session, the app erased */
    wait_ms(100u);
    CHECK(fake.starts == 0 && status_of() == 0x0000 && fake.started == BOTH);

    install(g_old, 2052u);                                       /* a valid app, the programming session */
    CHECK(boot(POWER_ON) == WINDOW && send_on(1u, REQ(0x10, 0x82)) && !answer(10u));
    wait_ms(100u);
    CHECK(fake.starts == 0 && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x02));
    CHECK(boot(POWER_ON) == WINDOW && ASK(0x10, 0x02, 0x00) && SESSION_ANSWER(0x02));
    CHECK(open_download(2052u) && ask36(1u, g_new, 1024u) && ANS(0x76, 0x01));
    wait_ms(100u);
    CHECK(fake.starts == 0 && fake.started == BOTH);
    wait_ms(5200u);                                              /* S3: no valid app, so listening */
    CHECK(fake.starts == 0 && fake.resets == 0 && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
}

/* Each condition that makes a configuration BAD_CFG, with no port call but the watchdog's, and the edges that pass. */
static void test_bad_cfg_for_each_condition(void)
{
    typedef struct {
        const char *name;
        udsota_boot_cfg_t cfg;
        bool ok;
    } cfg_case_t;
    cfg_case_t cases[32];
    size_t n = 0;
#define CASE(nm, ok_, change)                                                                            \
    do {                                                                                                 \
        cases[n] = (cfg_case_t){nm, k_cfg, ok_};                                                         \
        udsota_boot_cfg_t *c = &cases[n++].cfg;                                                          \
        change;                                                                                          \
    } while (0)
    CASE("request_id past 11 bits", false, c->request_id = 0x800u);
    CASE("response_id past 11 bits", false, c->response_id = 0xFFFFu);
    CASE("the same IDs", false, c->response_id = c->request_id);
    CASE("no bus", false, c->buses = 0u);
    CASE("16 buses", false, c->buses = 16u);
    CASE("write unit 0", false, c->slot_write_unit = 0u);
    CASE("write unit 6", false, c->slot_write_unit = 6u);
    CASE("slot not a multiple of the unit", false, c->slot_size = 0x20001u);
    CASE("slot shorter than the header's end", false, c->slot_size = HDR + UDSOTA_BARE_HDR_LEN - 2u);
    CASE("block not a multiple of the unit", false, c->slot_write_unit = 2048u);
    CASE("header ends past the block", false, c->image_header_offset = 1024u - UDSOTA_BARE_HDR_LEN + 2u);
    CASE("header past the slot", false, c->image_header_offset = 0xFFFFFFF0u);
    CASE("no product", false, c->product = NULL);
    CASE("product past the header's 32 bytes", false, c->product = "abcdefghijklmnopqrstuvwxyz0123456");
    CASE("no boot_version", false, c->boot_version = NULL);
    CASE("hold after 0 starts", false, c->hold_after_starts = 0u);
    CASE("k_cfg", true, (void)c);
    CASE("IDs 0 and 0x7FF", true, c->request_id = 0u; c->response_id = 0x7FFu);
    CASE("15 buses", true, c->buses = 15u);
    CASE("write unit 1", true, c->slot_write_unit = 1u; c->slot_size = 0x1FFFFu);
    CASE("write unit 1024", true, c->slot_write_unit = 1024u);
    CASE("header ends at the block's end", true, c->image_header_offset = 1024u - UDSOTA_BARE_HDR_LEN);
    CASE("slot the header's end", true, c->slot_size = HDR + UDSOTA_BARE_HDR_LEN);
    CASE("header at 0", true, c->image_header_offset = 0u);
    CASE("hold after 1 start", true, c->hold_after_starts = 1u);
    CASE("product of 32 characters", true, c->product = "abcdefghijklmnopqrstuvwxyz012345");
#undef CASE
    for (size_t i = 0; i < n; i++) {
        fake_reset();
        handover_to(1u);
        const udsota_boot_decision_t d = udsota_boot_init(&cases[i].cfg);
        if ((d == BAD_CFG) == cases[i].ok) {
            fprintf(stderr, "%s:%d: %s: %s decided %d\n", __FILE__, __LINE__, g_test, cases[i].name, (int)d);
            g_failures++;
        }
        if (!cases[i].ok) {
            CHECK(fake.calls == 0 && fake.wd_reloads == 1);
            step_us(1000u);
            udsota_boot_rx(1u, cases[i].cfg.request_id, (const uint8_t[]){0x02, 0x10, 0x02}, 3u);
            step_us(1000u);
            CHECK(fake.calls == 0 && fake.wd_reloads == 3);
            CHECK(fake.keep[UDSOTA_KEEP_WORD_MARK] == UDSOTA_HANDOVER_MARK);
        }
    }
    fake_reset();
    CHECK(udsota_boot_init(NULL) == BAD_CFG && fake.calls == 0);
}

/* A slot whose write unit is 8: the last block padded with 0xFF to the unit, every other a multiple of it. */
static void test_write_unit_8(void)
{
    fake_geometry(0x20000u, 8u, (const uint32_t[]){2048u}, 1u);
    udsota_boot_cfg_t cfg = k_cfg;
    cfg.slot_write_unit = 8u;
    g_cfg = &cfg;
    make_image(g_new, 2052u, 0x81);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    CHECK(open_download(2052u) && ask36(1u, g_new, 1020u) && NRC(0x36, 0x13));
    CHECK(result_is(UDSOTA_DL_ABORTED, 0u) && fake.erase_calls == 0);
    CHECK(download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(memcmp(fake.slot, g_new, 2052u) == 0 && fake.slot[2052] == 0xFFu && fake.slot[2055] == 0xFFu);
    CHECK(result_is(UDSOTA_DL_OK, 2052u));                       /* the bytes carried, not the padding */
    CHECK(download(g_new, 2052u, 488u) == UDSOTA_DL_OK);          /* 61 units a block, the last 100 bytes padded */
    CHECK(fake.slot[2052] == 0xFFu && fake.slot[2055] == 0xFFu);
    make_image(g_new, 2056u, 0x82);                              /* a last block of a whole unit */
    CHECK(download(g_new, 2056u, 1024u) == UDSOTA_DL_OK);
    CHECK(fake.erased[0] == 3 && fake.erased[1] == 3);
}

/* Erase units of several sizes, smaller and larger than a block: each erased once, before its first byte is written. */
static void test_non_uniform_erase_units(void)
{
    const uint32_t sizes[] = {256u, 256u, 512u, 2048u, 3072u, 128u, 128u, 16384u};
    fake_geometry(0x20000u, 2u, sizes, sizeof sizes / sizeof sizes[0]);
    make_image(g_new, 0x5004u, 0x91);
    CHECK(boot(POWER_ON) == NO_APP && programming());
    const uint32_t blocks[] = {1024u, 488u};                     /* 488: blocks across unit edges */
    for (size_t b = 0; b < sizeof blocks / sizeof blocks[0]; b++) {
        fake_erases_clear();
        CHECK(download(g_new, 0x5004u, blocks[b]) == UDSOTA_DL_OK && memcmp(fake.slot, g_new, 0x5004u) == 0);
        for (size_t u = 0; u < fake.units; u++) {
            CHECK(fake.erased[u] == ((fake.unit_at[u] < 0x5004u) ? 1u : 0u));
        }
    }
    CHECK(boot(OTHER) == START_APP);
}

/* A unit that sits in its bootloader past 24.86 days of fake time still answers and still updates. */
static void test_update_after_25_days_in_the_bootloader(void)
{
    make_image(g_new, 4100u, 0xB1);
    CHECK(boot(POWER_ON) == NO_APP);
    for (uint32_t i = 0; i < 26u * 24u * 60u; i++) {
        step_us(60000000u);
        if (i % (24u * 60u) == 0u) {                             /* a read a day */
            CHECK(ASK(0x22, 0xF1, 0xF0) && g_len == 19);
        }
    }
    CHECK(programming() && g_ans_us - g_sent_us <= 7000u);
    CHECK(download(g_new, 4100u, 1024u) == UDSOTA_DL_OK);
    CHECK(activate() && resets_after_the_delay());
}

/* ==== udsota_boot_init again: each call is a boot, with nothing kept from before ==== */

static const udsota_boot_cfg_t k_bad = {.request_id = 0x710u, .response_id = 0x710u};

static void test_init_again_after_bad_cfg_and_before_a_start(void)
{
    CHECK(udsota_boot_init(&k_bad) == BAD_CFG);
    CHECK(boot(POWER_ON) == NO_APP && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
    install_app(0xC1);
    CHECK(boot(OTHER) == START_APP);
    CHECK(udsota_boot_init(&k_bad) == BAD_CFG);
    step_us(1000u);
    CHECK(fake.starts == 0);
}

static void test_init_again_in_the_window(void)
{
    install_app(0xC2);
    CHECK(boot(POWER_ON) == WINDOW);
    wait_ms(50u);
    CHECK(boot(POWER_ON) == WINDOW);
    const uint32_t t0 = fake.us;
    wait_ms(120u);
    CHECK(fake.starts == 1 && fake.start_us - t0 >= 100000u);    /* the window from the second init */
    step_us(1000u);
    CHECK(fake.starts == 1);
    CHECK(send_on(1u, REQ(0x22, 0xF1, 0x86)) && !answer(20u));   /* stopped after start_app returned */
}

static void test_init_again_mid_reception_and_mid_download(void)
{
    install_app(0xC3);
    make_image(g_new, 2052u, 0xC4);
    CHECK(boot_held() && programming() && open_download(2052u) && ask36(1u, g_new, 1024u));
    frame_on(1u, (const uint8_t[]){0x10, 0x0C, 0x36, 0x02, 1, 2, 3, 4}, 8u);
    CHECK(boot(OTHER) == NO_APP);                                /* the first block's erase */
    frame_on(1u, (const uint8_t[]){0x21, 5, 6, 7, 8, 9, 10, 11}, 8u);
    CHECK(!answer(20u));
    CHECK(result_is(UDSOTA_DL_OK, 0u) && ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01));
    CHECK(ask36(2u, g_new + 1024u, 1024u) && NRC(0x36, 0x70));
    CHECK(programming() && ask36(2u, g_new + 1024u, 1024u) && NRC(0x36, 0x70));
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x24));
}

static void test_init_again_in_the_reset_delay(void)
{
    make_image(g_new, 2052u, 0xC5);
    CHECK(boot(POWER_ON) == NO_APP && programming() && download(g_new, 2052u, 1024u) == UDSOTA_DL_OK);
    CHECK(activate());
    wait_ms(30u);
    CHECK(boot(OTHER) == START_APP);
    CHECK(boot_held());
    wait_ms(100u);
    CHECK(fake.resets == 0);
    CHECK(ASK(0x31, 0x01, 0xF0, 0x01) && NRC(0x31, 0x7F));       /* no pass kept */
}

/* After port_reset returned the core is stopped until the next init: it reloads the watchdog and nothing else. */
static void test_stopped_after_a_reset_returns(void)
{
    CHECK(boot(POWER_ON) == NO_APP && programming() && ASK(0x11, 0x01) && resets_after_the_delay());
    const int reloads = fake.wd_reloads, calls = fake.calls;
    step_us(1000u);
    CHECK(send_on(1u, REQ(0x22, 0xF1, 0x86)) && !answer(10u));
    CHECK(fake.wd_reloads == reloads + 11 && fake.calls == calls);
}

/* Another configuration at the next init: other IDs and one bus. */
static void test_init_again_with_another_configuration(void)
{
    static const udsota_boot_cfg_t other = {
        .request_id = 0x720u, .response_id = 0x728u, .product = "example", .hw_id = 1u, .layout_id = 1u,
        .boot_version = "9", .buses = 1u, .slot_size = 0x10000u, .slot_write_unit = 4u, .image_header_offset = HDR,
        .hold_after_starts = 5u,
    };
    install_app(0xC6);
    CHECK(boot(OTHER) == START_APP);
    g_cfg = &other;
    CHECK(boot(OTHER) == START_APP);
    memset(fake.slot, 0xFF, fake.slot_size);
    CHECK(boot(OTHER) == NO_APP && fake.started == BIT(1));
    CHECK(ASK(0x22, 0xF1, 0x86) && ANS(0x62, 0xF1, 0x86, 0x01) && fake.frames[fake.n_frames - 1u].id == 0x728u);
    udsota_boot_rx(1u, 0x710u, (const uint8_t[]){0x03, 0x22, 0xF1, 0x86, 0, 0, 0, 0}, 8u);
    CHECK(!answer(20u));
}

#define TEST(fn) {#fn, fn}
static const struct {
    const char *name;
    void (*fn)(void);
} k_tests[] = {
    TEST(test_full_update_from_an_empty_slot),
    TEST(test_full_update_over_a_valid_app),
    TEST(test_session_control),
    TEST(test_tester_present),
    TEST(test_ecu_reset),
    TEST(test_a_repeat_inside_the_reset_delay_keeps_its_time),
    TEST(test_dids_with_a_valid_app),
    TEST(test_f180_and_a_full_version_field),
    TEST(test_request_download_refusals),
    TEST(test_36_refusals_end_the_transfer),
    TEST(test_37_refusals),
    TEST(test_resent_36_37_and_ff01),
    TEST(test_36_longer_than_the_block),
    TEST(test_routines),
    TEST(test_security_access_is_not_served),
    TEST(test_must_not_hold_the_window_or_delay_the_idle_exit_for_a_periodic_request),
    TEST(test_must_ignore_a_handover_mark_that_does_not_clear),
    TEST(test_must_keep_a_recorded_reason_over_a_later_abort),
    TEST(test_must_end_a_download_on_10_02_and_take_the_next_34),
    TEST(test_must_erase_nothing_for_a_refused_first_block),
    TEST(test_must_count_starts_clear_them_and_hold_at_the_threshold),
    TEST(test_must_send_the_handover_answer_6_ms_after_init_on_a_started_bus),
    TEST(test_must_carry_the_clock_remainder_and_age_the_timers),
    TEST(test_must_report_ff01_in_f1f1_with_the_image_rules_before_the_crc),
    TEST(test_must_notice_a_transfer_iso14229_ended_without_an_event),
    TEST(test_must_answer_every_10_02_in_the_window),
    TEST(test_must_refuse_unserved_events_with_0x11_and_check_the_alfid),
    TEST(test_boot_check),
    TEST(test_each_request_is_answered_on_its_bus),
    TEST(test_a_request_holds_its_bus_until_answered),
    TEST(test_a_waiting_request_holds_its_bus),
    TEST(test_a_tester_frame_locks_its_bus_until_listening_again),
    TEST(test_the_idle_exit_waits_for_a_request_in_flight),
    TEST(test_the_idle_exit_runs_in_the_default_session_only),
    TEST(test_ignored_frames),
    TEST(test_window),
    TEST(test_the_window_ends_in_a_start_only_for_a_valid_app_in_the_default_session),
    TEST(test_bad_cfg_for_each_condition),
    TEST(test_write_unit_8),
    TEST(test_non_uniform_erase_units),
    TEST(test_update_after_25_days_in_the_bootloader),
    TEST(test_init_again_after_bad_cfg_and_before_a_start),
    TEST(test_init_again_in_the_window),
    TEST(test_init_again_mid_reception_and_mid_download),
    TEST(test_init_again_in_the_reset_delay),
    TEST(test_stopped_after_a_reset_returns),
    TEST(test_init_again_with_another_configuration),
};

int main(void)
{
    for (size_t i = 0; i < sizeof k_tests / sizeof k_tests[0]; i++) {
        g_test = k_tests[i].name;                                /* power-on, an erased slot, k_cfg */
        fake_reset();
        g_cfg = &k_cfg;
        g_seen = 0;
        g_78s = 0;
        k_tests[i].fn();
        CHECK(fake.bad == 0);
        CHECK(g_78s == 0);
    }
    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_udsota_boot: all checks passed\n");
    return 0;
}
