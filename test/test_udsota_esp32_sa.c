/* Host tests for the ESP32 port's 0x27 mode choice and ECDSA key check (components/udsota_esp32/udsota_esp32_sa.c)
 * with the real server, key messages and device ID: which mode a config selects, the public-key form, and a
 * signature a client makes over F18C's bytes unlocking, while one for another device, level or seed does not.
 * The verify is a stand-in: the "signature" of a message is its SHA-256 twice, the second copy inverted, so it
 * depends on every message byte as a real one does. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "sha256_host.h"
#include "udsota.h"
#include "udsota_keys.h"
#include "udsota_esp32_devid.h"
#include "udsota_esp32_sa.h"
#include "udsota_mock.h"

#define T0 20000u     /* 20 s after boot: past the 10 s post-boot delay */

static const uint8_t MAC[UDSOTA_ESP32_DEVICE_ID_LEN] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC3};
static const uint8_t CUSTOM[10] = {'S', 'N', '-', '0', '0', '4', '2', 0x00, 0x7F, 0xFF};
static const uint8_t MASTER[32] = {1};

static udsota_esp32_devid_t s_dev;
static udsota_mock_t        s_mock;
static udsota_server_t      s_srv;
static uint8_t              R[4095];
static size_t               RL;
static int                  s_forced;    /* 0: fake_verify checks; else it answers this */
static int                  s_vcalls;
static int                  s_key_ctx;   /* stands in for the port's imported key id */

/* The stand-in signature of msg: SHA-256(msg), then its bitwise inverse. */
static void fake_sign(const uint8_t *msg, size_t n, uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    TEST_ASSERT_TRUE(sha256_host(msg, n, sig));
    for (int i = 0; i < 32; i++) {
        sig[32 + i] = (uint8_t)~sig[i];
    }
}

/* udsota_esp32_sa_verify_fn stand-in: 1 when sig is fake_sign(msg), else 0; s_forced overrides. ctx must be the
 * key the port passes. */
static int fake_verify(void *ctx, const uint8_t *msg, size_t msg_len, const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    s_vcalls++;
    TEST_ASSERT_EQUAL_PTR(&s_key_ctx, ctx);
    if (s_forced != 0) {
        return s_forced;
    }
    uint8_t want[UDSOTA_KEYS_SIG_LEN];
    fake_sign(msg, msg_len, want);
    return memcmp(sig, want, sizeof want) == 0 ? 1 : 0;
}

/* The key a tester sends: the stand-in signature over the message for seed, level and id. */
static void tester_sig(const uint8_t *seed, uint8_t level, const uint8_t *id, size_t id_len,
                       uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    uint8_t msg[UDSOTA_KEYS_SIG_MSG_MAX];
    const size_t n = udsota_keys_sig_msg(seed, level, id, id_len, msg);
    TEST_ASSERT_NOT_EQUAL(0, n);
    fake_sign(msg, n, sig);
}

/* security.rng16: a new non-zero seed each call. */
static bool test_rng16(void *ctx, uint8_t out[UDSOTA_KEYS_SEED_LEN])
{
    static uint8_t base = 0x10;
    for (int i = 0; i < UDSOTA_KEYS_SEED_LEN; i++) {
        out[i] = (uint8_t)(base + i);
    }
    base = (uint8_t)(base + 0x20);
    return true;
}

/* security.verify: udsota_esp32_keys.c's sec_verify without the PSA lock, over the struct in ctx. */
static int test_verify(void *ctx, const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level, const uint8_t *key,
                       size_t key_len)
{
    return udsota_esp32_sa_check(ctx, fake_verify, &s_key_ctx, seed, level, key, key_len);
}

/* Engine op that succeeds at once; no test here reaches the engine. */
static int noop(void *ctx) { return 0; }
/* Engine begin stub. */
static int noop_begin(void *ctx, uint32_t size) { return 0; }
/* Engine write stub. */
static int noop_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return 0; }
/* Engine abort stub. */
static void noop_abort(void *ctx) {}
/* Engine first-block stub. */
static int noop_check(void *ctx, const uint8_t *f, size_t n, udsota_reason_t *r) { *r = UDSOTA_DL_OK; return 0; }

static const udsota_engine_t ENGINE = {
    .check_first = noop_check, .begin = noop_begin, .write = noop_write, .verify = noop, .activate = noop,
    .confirm = noop, .abort = noop_abort, .poll = noop, .status = udsota_mock_status, .ctx = &s_mock,
};

/* Unity hook: an empty device ID, a cleared mock and a checking verify. */
void setUp(void)
{
    memset(&s_dev, 0, sizeof s_dev);
    memset(&s_srv, 0, sizeof s_srv);
    udsota_mock_clear(&s_mock);
    s_forced = 0;
    s_vcalls = 0;
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* As udsota_esp32_start() does in the ECDSA mode with cfg.device_id = id: fixes the ID, serves it as F18C and
 * boots the server with the port's verifier and 64-byte keys. */
static void port_start(const uint8_t *id, size_t id_len)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, id, id_len, MAC, true));
    udsota_config_t cfg = udsota_mock_cfg();
    udsota_esp32_devid_serve(&s_dev, &cfg);
    const udsota_hooks_t hooks = udsota_mock_hooks(&s_mock);
    static udsota_security_t sec;
    sec = (udsota_security_t){.rng16 = test_rng16, .key = NULL, .ctx = &s_dev,
                              .verify = test_verify, .key_len = UDSOTA_KEYS_SIG_LEN};
    udsota_init(&s_srv, &cfg, &ENGINE, &sec, &hooks);
}

/* Sends one request at now; the response is left in R/RL. */
static void txreq(const uint8_t *req, size_t n, uint32_t now)
{
    RL = udsota_on_request(&s_srv, req, n, R, sizeof R, now);
}

/* Reads 22 F18C and copies its data into out; returns its length. */
static size_t read_f18c(uint8_t out[UDSOTA_KEYS_ID_MAX])
{
    const uint8_t req[3] = {0x22, 0xF1, 0x8C};
    txreq(req, sizeof req, T0);
    TEST_ASSERT_TRUE(RL >= 4 && RL - 3 <= UDSOTA_KEYS_ID_MAX);
    TEST_ASSERT_EQUAL_HEX8(0x62, R[0]);
    memcpy(out, &R[3], RL - 3);
    return RL - 3;
}

/* Enters the programming session and requests a level-03 seed into seed. */
static void programming_seed(uint32_t now, uint8_t seed[UDSOTA_KEYS_SEED_LEN])
{
    const uint8_t prog[2] = {0x10, 0x02}, seed_req[2] = {0x27, 0x03};
    txreq(prog, sizeof prog, now);
    TEST_ASSERT_EQUAL_HEX8(0x50, R[0]);
    txreq(seed_req, sizeof seed_req, now + 1);
    TEST_ASSERT_EQUAL_UINT(18, RL);
    memcpy(seed, &R[2], UDSOTA_KEYS_SEED_LEN);
}

/* Sends 27 04 with sig at now. */
static void send_sig(const uint8_t sig[UDSOTA_KEYS_SIG_LEN], uint32_t now)
{
    uint8_t req[2 + UDSOTA_KEYS_SIG_LEN] = {0x27, 0x04};
    memcpy(&req[2], sig, UDSOTA_KEYS_SIG_LEN);
    txreq(req, sizeof req, now);
}

/* Asserts the last response is 7F 27 <nrc>. */
static void assert_nrc(uint8_t nrc)
{
    TEST_ASSERT_EQUAL_UINT(3, RL);
    TEST_ASSERT_EQUAL_HEX8(0x7F, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x27, R[1]);
    TEST_ASSERT_EQUAL_HEX8(nrc, R[2]);
}

/* key_pubkey selects ECDSA and wins over key_label; key_label alone is HMAC; neither is off. A master given
 * with a public key is reported as ignored, a label alone is not. */
static void test_mode_choice_and_precedence(void)
{
    static const uint8_t pub[UDSOTA_KEYS_PUBKEY_LEN] = {0x04};
    bool ignored = true;
    udsota_config_t cfg = {0};
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_OFF, udsota_esp32_sa_mode(&cfg, &ignored));
    TEST_ASSERT_FALSE(ignored);
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_OFF, udsota_esp32_sa_mode(NULL, &ignored));
    cfg.key_label = "udsota-test";
    cfg.key_master = MASTER;
    cfg.key_master_len = sizeof MASTER;
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_HMAC, udsota_esp32_sa_mode(&cfg, &ignored));
    TEST_ASSERT_FALSE(ignored);
    cfg.key_pubkey = pub;
    cfg.key_pubkey_len = sizeof pub;
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_ECDSA, udsota_esp32_sa_mode(&cfg, &ignored));
    TEST_ASSERT_TRUE(ignored);
    cfg.key_master = NULL;
    cfg.key_master_len = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_ECDSA, udsota_esp32_sa_mode(&cfg, &ignored));
    TEST_ASSERT_FALSE(ignored);
    cfg.key_label = NULL;
    cfg.key_pubkey_len = 0;                                         /* set but empty: still ECDSA, then refused */
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_SA_ECDSA, udsota_esp32_sa_mode(&cfg, NULL));
}

/* Only a 65-byte uncompressed point passes the form check. */
static void test_pubkey_form(void)
{
    uint8_t pub[UDSOTA_KEYS_PUBKEY_LEN + 1] = {0x04};
    TEST_ASSERT_TRUE(udsota_esp32_sa_pubkey_ok(pub, UDSOTA_KEYS_PUBKEY_LEN));
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(pub, UDSOTA_KEYS_PUBKEY_LEN - 1));
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(pub, UDSOTA_KEYS_PUBKEY_LEN + 1));
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(pub, 0));
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(NULL, UDSOTA_KEYS_PUBKEY_LEN));
    pub[0] = 0x02;                                                  /* compressed */
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(pub, 33));
    TEST_ASSERT_FALSE(udsota_esp32_sa_pubkey_ok(pub, UDSOTA_KEYS_PUBKEY_LEN));
}

/* The check's verdicts: no verdict before the ID is fixed, over a failed MAC or without verify; 0 for another
 * length; verify's answer otherwise, any negative as -1 and anything but 1 as wrong. */
static void test_check_verdicts(void)
{
    uint8_t seed[UDSOTA_KEYS_SEED_LEN] = {0x10}, sig[UDSOTA_KEYS_SIG_LEN];
    tester_sig(seed, 0x03, CUSTOM, sizeof CUSTOM, sig);
    TEST_ASSERT_EQUAL_INT(-1, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, sig, sizeof sig));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, CUSTOM, sizeof CUSTOM, MAC, true));
    TEST_ASSERT_EQUAL_INT(-1, udsota_esp32_sa_check(&s_dev, NULL, &s_key_ctx, seed, 0x03, sig, sizeof sig));
    TEST_ASSERT_EQUAL_INT(0, s_vcalls);
    TEST_ASSERT_EQUAL_INT(1, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, sig, sizeof sig));
    TEST_ASSERT_EQUAL_INT(0, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x01, sig, sizeof sig));
    TEST_ASSERT_EQUAL_INT(0, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, sig, 63));
    TEST_ASSERT_EQUAL_INT(0, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, NULL, 64));
    TEST_ASSERT_EQUAL_INT(-1, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x7F, sig, sizeof sig));
    TEST_ASSERT_EQUAL_INT(2, s_vcalls);                             /* only the two full-length, valid-level checks */
    const int forced[] = {-1, -7, 2, 0};
    const int want[] = {-1, -1, 0, 1};
    for (size_t i = 0; i < 4; i++) {
        s_forced = forced[i];
        TEST_ASSERT_EQUAL_INT(want[i], udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, sig,
                                                             sizeof sig));
    }

    memset(&s_dev, 0, sizeof s_dev);
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, NULL, 0, MAC, false));
    TEST_ASSERT_EQUAL_INT(-1, udsota_esp32_sa_check(&s_dev, fake_verify, &s_key_ctx, seed, 0x03, sig, sizeof sig));
}

/* A custom ID: a signature over the seed, level 03 and F18C's bytes unlocks programming, through the server. */
static void test_signature_over_f18c_unlocks(void)
{
    uint8_t f18c[UDSOTA_KEYS_ID_MAX], seed[UDSOTA_KEYS_SEED_LEN], sig[UDSOTA_KEYS_SIG_LEN];
    port_start(CUSTOM, sizeof CUSTOM);
    const size_t n = read_f18c(f18c);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(CUSTOM, f18c, n);
    programming_seed(T0 + 1, seed);
    tester_sig(seed, 0x03, f18c, n, sig);
    send_sig(sig, T0 + 3);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x04, R[1]);
    TEST_ASSERT_EQUAL_HEX8(0x03, s_srv.security);
}

/* The base MAC as the ID (what an app without cfg.device_id gets) unlocks the same way. */
static void test_signature_over_the_mac_unlocks(void)
{
    uint8_t f18c[UDSOTA_KEYS_ID_MAX], seed[UDSOTA_KEYS_SEED_LEN], sig[UDSOTA_KEYS_SIG_LEN];
    port_start(NULL, 0);
    const size_t n = read_f18c(f18c);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_ESP32_DEVICE_ID_LEN, n);
    programming_seed(T0 + 1, seed);
    tester_sig(seed, 0x03, MAC, sizeof MAC, sig);
    send_sig(sig, T0 + 3);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
}

/* A signature made for another device (the MAC instead of the custom ID), for the other level or for an
 * earlier seed is a wrong key (0x35), and the third one locks out (0x36). */
static void test_signature_for_another_device_level_or_seed_is_refused(void)
{
    uint8_t seed[UDSOTA_KEYS_SEED_LEN], old[UDSOTA_KEYS_SEED_LEN], sig[UDSOTA_KEYS_SIG_LEN];
    port_start(CUSTOM, sizeof CUSTOM);
    programming_seed(T0, seed);
    tester_sig(seed, 0x03, MAC, sizeof MAC, sig);
    send_sig(sig, T0 + 2);
    assert_nrc(0x35);
    programming_seed(T0 + 10, seed);
    tester_sig(seed, 0x01, CUSTOM, sizeof CUSTOM, sig);
    send_sig(sig, T0 + 12);
    assert_nrc(0x35);
    memcpy(old, seed, sizeof old);
    programming_seed(T0 + 20, seed);
    tester_sig(old, 0x03, CUSTOM, sizeof CUSTOM, sig);
    send_sig(sig, T0 + 22);
    assert_nrc(0x36);
    TEST_ASSERT_EQUAL_HEX8(0x00, s_srv.security);
}

/* The sendKey carries exactly 64 key bytes: the HMAC mode's 16 answers 0x13 and reaches no verify. A verify
 * with no verdict answers 0x22 and is not an attempt. */
static void test_length_and_no_verdict(void)
{
    uint8_t seed[UDSOTA_KEYS_SEED_LEN], sig[UDSOTA_KEYS_SIG_LEN];
    port_start(CUSTOM, sizeof CUSTOM);
    programming_seed(T0, seed);
    tester_sig(seed, 0x03, CUSTOM, sizeof CUSTOM, sig);
    uint8_t short_req[18] = {0x27, 0x04};
    memcpy(&short_req[2], sig, 16);
    txreq(short_req, sizeof short_req, T0 + 2);
    assert_nrc(0x13);
    TEST_ASSERT_EQUAL_INT(0, s_vcalls);
    s_forced = -1;
    for (uint32_t i = 0; i < 3; i++) {
        programming_seed(T0 + 10 + 10 * i, seed);
        tester_sig(seed, 0x03, CUSTOM, sizeof CUSTOM, sig);
        send_sig(sig, T0 + 12 + 10 * i);
        assert_nrc(0x22);
    }
    s_forced = 0;
    programming_seed(T0 + 50, seed);
    tester_sig(seed, 0x03, CUSTOM, sizeof CUSTOM, sig);
    send_sig(sig, T0 + 52);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);                             /* no lockout: the 0x22s were not attempts */
}

/* Runs every test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mode_choice_and_precedence);
    RUN_TEST(test_pubkey_form);
    RUN_TEST(test_check_verdicts);
    RUN_TEST(test_signature_over_f18c_unlocks);
    RUN_TEST(test_signature_over_the_mac_unlocks);
    RUN_TEST(test_signature_for_another_device_level_or_seed_is_refused);
    RUN_TEST(test_length_and_no_verdict);
    return UNITY_END();
}
