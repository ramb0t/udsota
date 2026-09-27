/* Host tests for the core key derivation (udsota_keys.c): the exact HMAC inputs, the level rule, the
 * label and device-ID bounds, fail-closed outputs, and the self-test against real HMAC answers; then the
 * ECDSA mode's signed message against known bytes and its verify self-test. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "sha256_host.h"
#include "udsota_keys.h"

/* ---- recording fake: stores each call's key and message, answers a fixed pattern ---- */

#define REC_MAX 4
typedef struct {
    uint8_t key[64];
    size_t  key_len;
    uint8_t msg[64];
    size_t  msg_len;
} rec_call_t;

static rec_call_t g_calls[REC_MAX];
static int        g_ncalls;
static bool       g_fail;

/* Records key and msg, then writes out[i] = 0xA0 + i; returns !g_fail. */
static bool rec_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[UDSOTA_KEYS_HMAC_LEN])
{
    if (g_ncalls < REC_MAX) {
        rec_call_t *c = &g_calls[g_ncalls];
        c->key_len = key_len < sizeof c->key ? key_len : sizeof c->key;
        memcpy(c->key, key, c->key_len);
        c->msg_len = msg_len < sizeof c->msg ? msg_len : sizeof c->msg;
        memcpy(c->msg, msg, c->msg_len);
    }
    g_ncalls++;
    for (size_t i = 0; i < UDSOTA_KEYS_HMAC_LEN; i++) {
        out[i] = (uint8_t)(0xA0 + i);
    }
    return !g_fail;
}

/* ---- canned fake: real HMAC-SHA256 outputs for exactly the self-test's four inputs ----
 * T_TC2 is RFC 4231 test case 2. The others come from Python, e.g. T_KDEV and T_L1_FULL:
 *   python3 -c 'import hmac,hashlib as h; i=bytes([2,0,0,0,0,1]); k=hmac.new(bytes(range(32)),b"udsota-kat"+i,h.sha256).digest();
 *               print(k.hex(), hmac.new(k,bytes(range(16,32))+b"\x01"+i,h.sha256).hexdigest())' */

static const uint8_t T_ID[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t T_TC2[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
};
static const uint8_t T_KDEV[32] = {   /* HMAC(00..1F, "udsota-kat" || T_ID) */
    0x7b, 0xac, 0x00, 0xce, 0x78, 0x93, 0x69, 0xa8, 0xfb, 0x6f, 0x3c, 0xe1, 0xd1, 0xfb, 0xe7, 0xfe,
    0xa0, 0x2c, 0xd3, 0xcd, 0xbe, 0xd0, 0x2a, 0x23, 0xa0, 0xa4, 0x8a, 0x9d, 0x1a, 0x26, 0x87, 0x57,
};
static const uint8_t T_L1_FULL[32] = {   /* HMAC(T_KDEV, 10..1F || 01 || T_ID) */
    0x15, 0x32, 0xad, 0x02, 0x43, 0xf9, 0xaa, 0x10, 0x04, 0x24, 0xaa, 0x24, 0xa0, 0xd2, 0x83, 0x19,
    0xf9, 0x4f, 0x46, 0x7b, 0x03, 0x4b, 0xa9, 0x9d, 0x58, 0x12, 0x6d, 0x15, 0xc7, 0x16, 0x2f, 0xde,
};
static const uint8_t T_L3_FULL[32] = {   /* HMAC(T_KDEV, 10..1F || 03 || T_ID) */
    0x27, 0xe8, 0x91, 0xcd, 0x8c, 0x86, 0xac, 0x41, 0xa7, 0x88, 0x2a, 0x4f, 0x81, 0xd6, 0x66, 0xf3,
    0xfe, 0xa1, 0xfb, 0x38, 0x91, 0x80, 0x4d, 0xd8, 0x4a, 0x7e, 0xe8, 0xf8, 0x7e, 0x05, 0xd6, 0x42,
};

static int g_corrupt = -1;   /* 0 TC2, 1 K_dev, 2 level-1 key, 3 level-3 key: flip bit 0 of that answer */

/* What the fake ECDSA verifiers saw: their calls and the last message. */
static int     g_vcalls;
static uint8_t g_vmsg[UDSOTA_KEYS_SIG_MSG_MAX];
static size_t  g_vmsg_len;
static int     g_vanswer;   /* what always_verify answers */

/* Fills the test master (0..31) and test seed (0x10..0x1F). */
static void test_inputs(uint8_t master[32], uint8_t seed[16])
{
    for (int i = 0; i < 32; i++) {
        master[i] = (uint8_t)i;
    }
    for (int i = 0; i < 16; i++) {
        seed[i] = (uint8_t)(0x10 + i);
    }
}

/* Answers the four known (key, msg) pairs with their true HMAC; any other input fails. */
static bool canned_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                        uint8_t out[UDSOTA_KEYS_HMAC_LEN])
{
    uint8_t master[32], seed[16], kdev_msg[16], key_msg[23];
    test_inputs(master, seed);
    memcpy(kdev_msg, "udsota-kat", 10);
    memcpy(&kdev_msg[10], T_ID, 6);
    memcpy(key_msg, seed, 16);
    memcpy(&key_msg[17], T_ID, 6);

    int which = -1;
    const uint8_t *answer = NULL;
    if (key_len == 4 && memcmp(key, "Jefe", 4) == 0 && msg_len == 28
        && memcmp(msg, "what do ya want for nothing?", 28) == 0) {
        which = 0; answer = T_TC2;
    } else if (key_len == 32 && memcmp(key, master, 32) == 0 && msg_len == 16
               && memcmp(msg, kdev_msg, 16) == 0) {
        which = 1; answer = T_KDEV;
    } else if (key_len == 32 && memcmp(key, T_KDEV, 32) == 0 && msg_len == 23) {
        key_msg[16] = 0x01;
        if (memcmp(msg, key_msg, 23) == 0) {
            which = 2; answer = T_L1_FULL;
        }
        key_msg[16] = 0x03;
        if (memcmp(msg, key_msg, 23) == 0) {
            which = 3; answer = T_L3_FULL;
        }
    }
    if (answer == NULL) {
        return false;
    }
    memcpy(out, answer, UDSOTA_KEYS_HMAC_LEN);
    if (which == g_corrupt) {
        out[0] ^= 0x01;
    }
    return true;
}

/* Unity per-test hook: clears both fakes. */
void setUp(void)
{
    memset(g_calls, 0, sizeof g_calls);
    g_ncalls = 0;
    g_fail = false;
    g_corrupt = -1;
    g_vcalls = 0;
    g_vmsg_len = 0;
    g_vanswer = 0;
}

/* Unity per-test hook; nothing to release. */
void tearDown(void) {}

/* K_dev = HMAC(master, "udsota-example" || MAC): a 32-byte key and a 20-byte message, whole output. */
static void test_kdev_hashes_label_then_id_under_master(void)
{
    uint8_t master[32], seed[16], kdev[32];
    test_inputs(master, seed);
    TEST_ASSERT_TRUE(udsota_keys_derive_kdev(rec_hmac, master, 32, "udsota-example", T_ID, 6, kdev));
    TEST_ASSERT_EQUAL_INT(1, g_ncalls);
    TEST_ASSERT_EQUAL_UINT(32, g_calls[0].key_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(master, g_calls[0].key, 32);
    const uint8_t want_msg[20] = {'u', 'd', 's', 'o', 't', 'a', '-', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                  0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    TEST_ASSERT_EQUAL_UINT(20, g_calls[0].msg_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_msg, g_calls[0].msg, 20);
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_HEX8(0xA0 + i, kdev[i]);
    }
}

/* The master and device-ID lengths are the caller's: a 16-byte master is the HMAC key as given, and an
 * 8-byte ID follows the label. */
static void test_kdev_takes_key_and_id_lengths_from_the_caller(void)
{
    uint8_t master[32], seed[16], kdev[32];
    const uint8_t id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    test_inputs(master, seed);
    TEST_ASSERT_TRUE(udsota_keys_derive_kdev(rec_hmac, master, 16, "udsota-example", id, sizeof id, kdev));
    TEST_ASSERT_EQUAL_UINT(16, g_calls[0].key_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(master, g_calls[0].key, 16);
    TEST_ASSERT_EQUAL_UINT(14 + 8, g_calls[0].msg_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(id, &g_calls[0].msg[14], 8);
}

/* The key is HMAC(K_dev, seed || level || ID) truncated to its first 16 bytes. */
static void test_key_hashes_seed_level_id_under_kdev_and_keeps_16_bytes(void)
{
    uint8_t master[32], seed[16], key[17];
    test_inputs(master, seed);
    memset(key, 0xEE, sizeof key);
    TEST_ASSERT_TRUE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x03, T_ID, 6, key));
    TEST_ASSERT_EQUAL_INT(1, g_ncalls);
    TEST_ASSERT_EQUAL_UINT(32, g_calls[0].key_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_KDEV, g_calls[0].key, 32);
    TEST_ASSERT_EQUAL_UINT(23, g_calls[0].msg_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(seed, g_calls[0].msg, 16);
    TEST_ASSERT_EQUAL_HEX8(0x03, g_calls[0].msg[16]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_ID, &g_calls[0].msg[17], 6);
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQUAL_HEX8(0xA0 + i, key[i]);
    }
    TEST_ASSERT_EQUAL_HEX8(0xEE, key[16]);   /* nothing past 16 bytes */
}

/* Level 0x01 puts 0x01 in the message: the requestSeed byte, not the sendKey byte. */
static void test_key_level_byte_is_the_request_seed_byte(void)
{
    uint8_t master[32], seed[16], key[16];
    test_inputs(master, seed);
    TEST_ASSERT_TRUE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x01, T_ID, 6, key));
    TEST_ASSERT_EQUAL_HEX8(0x01, g_calls[0].msg[16]);
}

/* Any requestSeed byte a server may be configured with (odd, up to 0x7D) is hashed as given. */
static void test_key_accepts_any_request_seed_level(void)
{
    uint8_t master[32], seed[16], key[16];
    test_inputs(master, seed);
    const uint8_t ok[] = {0x05, 0x41, 0x7D};
    for (size_t i = 0; i < sizeof ok; i++) {
        TEST_ASSERT_TRUE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, ok[i], T_ID, 6, key));
        TEST_ASSERT_EQUAL_HEX8(ok[i], g_calls[i].msg[16]);
    }
}

/* 0, the even sendKey bytes, 0x7F (its sendKey is 0x80) and anything with the suppress bit fail without hashing, key zeroed. */
static void test_key_refuses_other_levels_without_hashing(void)
{
    uint8_t master[32], seed[16], key[16];
    test_inputs(master, seed);
    const uint8_t bad[] = {0x00, 0x02, 0x04, 0x7F, 0x80, 0x81, 0xFF};
    for (size_t i = 0; i < sizeof bad; i++) {
        memset(key, 0xEE, sizeof key);
        TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, bad[i], T_ID, 6, key));
        TEST_ASSERT_EACH_EQUAL_HEX8(0x00, key, 16);
    }
    TEST_ASSERT_EQUAL_INT(0, g_ncalls);
}

/* Labels up to UDSOTA_KEYS_LABEL_MAX and IDs up to UDSOTA_KEYS_ID_MAX bytes are hashed; one byte more, or
 * an empty master, fails closed without hashing. An empty label hashes the ID alone. */
static void test_label_and_id_bounds(void)
{
    uint8_t master[32], seed[16], kdev[32], key[16], id[UDSOTA_KEYS_ID_MAX + 1];
    char label[UDSOTA_KEYS_LABEL_MAX + 2];
    test_inputs(master, seed);
    memset(id, 0x5A, sizeof id);
    memset(label, 'L', sizeof label - 1);
    label[sizeof label - 1] = '\0';                               /* UDSOTA_KEYS_LABEL_MAX + 1 characters */
    memset(kdev, 0xEE, sizeof kdev);
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, label, T_ID, 6, kdev));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, kdev, 32);
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, "L", id, UDSOTA_KEYS_ID_MAX + 1, kdev));
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 0, "L", T_ID, 6, kdev));
    memset(key, 0xEE, sizeof key);
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x01, id, UDSOTA_KEYS_ID_MAX + 1, key));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, key, 16);
    TEST_ASSERT_EQUAL_INT(0, g_ncalls);

    label[UDSOTA_KEYS_LABEL_MAX] = '\0';                          /* exactly UDSOTA_KEYS_LABEL_MAX */
    TEST_ASSERT_TRUE(udsota_keys_derive_kdev(rec_hmac, master, 32, label, id, UDSOTA_KEYS_ID_MAX, kdev));
    TEST_ASSERT_EQUAL_UINT(UDSOTA_KEYS_LABEL_MAX + UDSOTA_KEYS_ID_MAX, g_calls[0].msg_len);
    TEST_ASSERT_TRUE(udsota_keys_derive_kdev(rec_hmac, master, 32, "", T_ID, 6, kdev));
    TEST_ASSERT_EQUAL_UINT(6, g_calls[1].msg_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_ID, g_calls[1].msg, 6);
    TEST_ASSERT_TRUE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x01, id, UDSOTA_KEYS_ID_MAX, key));
    TEST_ASSERT_EQUAL_UINT(16 + 1 + UDSOTA_KEYS_ID_MAX, g_calls[2].msg_len);
}

/* An HMAC failure fails both derivations and leaves their outputs zeroed, never half-written. */
static void test_hmac_failure_zeroes_outputs(void)
{
    uint8_t master[32], seed[16], kdev[32], key[16];
    test_inputs(master, seed);
    g_fail = true;
    memset(kdev, 0xEE, sizeof kdev);
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, "udsota-example", T_ID, 6, kdev));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, kdev, 32);
    memset(key, 0xEE, sizeof key);
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x03, T_ID, 6, key));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, key, 16);
}

/* NULL inputs fail closed with the output zeroed, and a NULL output is refused without a crash. */
static void test_null_arguments_fail_closed(void)
{
    uint8_t master[32], seed[16], kdev[32], key[16];
    test_inputs(master, seed);
    memset(kdev, 0xEE, sizeof kdev);
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(NULL, master, 32, "udsota-example", T_ID, 6, kdev));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, kdev, 32);
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, NULL, 32, "udsota-example", T_ID, 6, kdev));
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, NULL, T_ID, 6, kdev));
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, "udsota-example", NULL, 6, kdev));
    TEST_ASSERT_FALSE(udsota_keys_derive_kdev(rec_hmac, master, 32, "udsota-example", T_ID, 6, NULL));
    memset(key, 0xEE, sizeof key);
    TEST_ASSERT_FALSE(udsota_keys_derive_key(NULL, T_KDEV, seed, 0x03, T_ID, 6, key));
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, key, 16);
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, NULL, seed, 0x03, T_ID, 6, key));
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, NULL, 0x03, T_ID, 6, key));
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x03, NULL, 6, key));
    TEST_ASSERT_FALSE(udsota_keys_derive_key(rec_hmac, T_KDEV, seed, 0x03, T_ID, 6, NULL));
    TEST_ASSERT_EQUAL_INT(0, g_ncalls);
}

/* With an HMAC that gives the true answers, the self-test passes: vectors, inputs and chaining agree. */
static void test_self_test_passes_with_correct_hmac(void)
{
    TEST_ASSERT_TRUE(udsota_keys_self_test(canned_hmac));
}

/* One wrong bit at any stage (TC2, K_dev, level-1 key, level-3 key) fails the self-test. */
static void test_self_test_fails_on_each_wrong_stage(void)
{
    for (int stage = 0; stage < 4; stage++) {
        g_corrupt = stage;
        TEST_ASSERT_FALSE_MESSAGE(udsota_keys_self_test(canned_hmac), "corrupted stage passed");
    }
}

/* A NULL HMAC or one that ignores its inputs fails the self-test. */
static void test_self_test_fails_on_null_or_wrong_hmac(void)
{
    TEST_ASSERT_FALSE(udsota_keys_self_test(NULL));
    TEST_ASSERT_FALSE(udsota_keys_self_test(rec_hmac));
}

/* ---- the ECDSA mode: the signed message and the verify self-test ---- */

/* The message for seed 0x10..0x1F, level 0x03 and T_ID, and its SHA-256 (what the tester signs and the device
 * verifies). client/tests/test_udsota.py pins the same bytes:
 *   python3 -c 'import hashlib; m=b"udsota-27-ecdsa-v1"+bytes(range(16,32))+bytes([3,6,2,0,0,0,0,1]); print(m.hex(), hashlib.sha256(m).hexdigest())' */
static const uint8_t T_SIG_MSG_L3[42] = {
    'u', 'd', 's', 'o', 't', 'a', '-', '2', '7', '-', 'e', 'c', 'd', 's', 'a', '-', 'v', '1',
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x03, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
};
static const uint8_t T_SIG_DIGEST_L3[32] = {
    0xaf, 0x91, 0x4b, 0xa6, 0xad, 0x03, 0x0d, 0x8a, 0xc1, 0x02, 0xfe, 0x70, 0xba, 0x98, 0x25, 0x5a,
    0x9e, 0x50, 0xad, 0x7c, 0x45, 0x37, 0x39, 0x41, 0xdb, 0x3d, 0x4a, 0xaa, 0xc2, 0x46, 0xb4, 0xce,
};

/* A verify that records its inputs and answers g_vanswer, whatever they are. */
static int always_verify(const uint8_t *pubkey, const uint8_t *msg, size_t msg_len,
                         const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    g_vcalls++;
    g_vmsg_len = msg_len < sizeof g_vmsg ? msg_len : sizeof g_vmsg;
    memcpy(g_vmsg, msg, g_vmsg_len);
    return g_vanswer;
}

/* A verify that is true for exactly the level-0x03 KAT message and 0 for any other: what a correct ECDSA gives. */
static int kat_verify(const uint8_t *pubkey, const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    g_vcalls++;
    TEST_ASSERT_EQUAL_HEX8(0x04, pubkey[0]);
    return (msg_len == sizeof T_SIG_MSG_L3 && memcmp(msg, T_SIG_MSG_L3, msg_len) == 0) ? 1 : 0;
}

/* The message is tag || seed || level || id_len || id: the known bytes, and their known SHA-256. */
static void test_sig_msg_known_answer(void)
{
    uint8_t master[32], seed[16], msg[UDSOTA_KEYS_SIG_MSG_MAX + 1], digest[32];
    test_inputs(master, seed);
    memset(msg, 0xEE, sizeof msg);
    TEST_ASSERT_EQUAL_UINT(sizeof T_SIG_MSG_L3, udsota_keys_sig_msg(seed, 0x03, T_ID, sizeof T_ID, msg));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_SIG_MSG_L3, msg, sizeof T_SIG_MSG_L3);
    TEST_ASSERT_EQUAL_HEX8(0xEE, msg[sizeof T_SIG_MSG_L3]);   /* nothing past the message */
    TEST_ASSERT_TRUE(sha256_host(msg, sizeof T_SIG_MSG_L3, digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_SIG_DIGEST_L3, digest, 32);
}

/* The level byte and the length-prefixed ID bind the message: level 0x01 differs in one byte, and the longest
 * ID fills UDSOTA_KEYS_SIG_MSG_MAX exactly. */
static void test_sig_msg_binds_level_and_id(void)
{
    uint8_t master[32], seed[16], msg[UDSOTA_KEYS_SIG_MSG_MAX], id[UDSOTA_KEYS_ID_MAX];
    test_inputs(master, seed);
    TEST_ASSERT_EQUAL_UINT(42, udsota_keys_sig_msg(seed, 0x01, T_ID, sizeof T_ID, msg));
    TEST_ASSERT_EQUAL_HEX8(0x01, msg[34]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(T_SIG_MSG_L3, msg, 34);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&T_SIG_MSG_L3[35], &msg[35], 7);
    memset(id, 0x5A, sizeof id);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_KEYS_SIG_MSG_MAX, udsota_keys_sig_msg(seed, 0x7D, id, sizeof id, msg));
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_KEYS_ID_MAX, msg[35]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x5A, &msg[36], UDSOTA_KEYS_ID_MAX);
    TEST_ASSERT_EQUAL_UINT(36, udsota_keys_sig_msg(seed, 0x03, id, 0, msg));   /* an empty ID is still length-prefixed */
    TEST_ASSERT_EQUAL_HEX8(0x00, msg[35]);
}

/* A bad level, an ID over UDSOTA_KEYS_ID_MAX or a NULL argument builds nothing and writes nothing. */
static void test_sig_msg_refuses_bad_input(void)
{
    uint8_t master[32], seed[16], msg[UDSOTA_KEYS_SIG_MSG_MAX], id[UDSOTA_KEYS_ID_MAX + 1] = {0};
    test_inputs(master, seed);
    memset(msg, 0xEE, sizeof msg);
    const uint8_t bad[] = {0x00, 0x02, 0x7F, 0x81};
    for (size_t i = 0; i < sizeof bad; i++) {
        TEST_ASSERT_EQUAL_UINT(0, udsota_keys_sig_msg(seed, bad[i], T_ID, sizeof T_ID, msg));
    }
    TEST_ASSERT_EQUAL_UINT(0, udsota_keys_sig_msg(seed, 0x03, id, sizeof id, msg));
    TEST_ASSERT_EQUAL_UINT(0, udsota_keys_sig_msg(NULL, 0x03, T_ID, sizeof T_ID, msg));
    TEST_ASSERT_EQUAL_UINT(0, udsota_keys_sig_msg(seed, 0x03, NULL, sizeof T_ID, msg));
    TEST_ASSERT_EQUAL_UINT(0, udsota_keys_sig_msg(seed, 0x03, T_ID, sizeof T_ID, NULL));
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, msg, sizeof msg);
}

/* The self-test passes with a verify that accepts only the level-0x03 message, and hands it that message. */
static void test_sig_self_test_passes_with_correct_verify(void)
{
    TEST_ASSERT_TRUE(udsota_keys_sig_self_test(kat_verify));
    TEST_ASSERT_EQUAL_INT(2, g_vcalls);
}

/* The self-test fails with no verify, one that accepts anything (it must refuse the level-0x01 message), one
 * that accepts nothing, and one that cannot check. */
static void test_sig_self_test_fails_on_wrong_verify(void)
{
    TEST_ASSERT_FALSE(udsota_keys_sig_self_test(NULL));
    const int answers[] = {1, 0, -1};
    for (size_t i = 0; i < 3; i++) {
        g_vanswer = answers[i];
        TEST_ASSERT_FALSE(udsota_keys_sig_self_test(always_verify));
    }
    g_vcalls = 0;
    g_vanswer = 1;
    (void)udsota_keys_sig_self_test(always_verify);
    TEST_ASSERT_EQUAL_INT(2, g_vcalls);
    TEST_ASSERT_EQUAL_UINT(42, g_vmsg_len);
    TEST_ASSERT_EQUAL_HEX8(0x01, g_vmsg[34]);                 /* the second call asks about level 0x01 */
}

/* Runs every key-derivation test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_kdev_hashes_label_then_id_under_master);
    RUN_TEST(test_kdev_takes_key_and_id_lengths_from_the_caller);
    RUN_TEST(test_key_hashes_seed_level_id_under_kdev_and_keeps_16_bytes);
    RUN_TEST(test_key_level_byte_is_the_request_seed_byte);
    RUN_TEST(test_key_accepts_any_request_seed_level);
    RUN_TEST(test_key_refuses_other_levels_without_hashing);
    RUN_TEST(test_label_and_id_bounds);
    RUN_TEST(test_hmac_failure_zeroes_outputs);
    RUN_TEST(test_null_arguments_fail_closed);
    RUN_TEST(test_self_test_passes_with_correct_hmac);
    RUN_TEST(test_self_test_fails_on_each_wrong_stage);
    RUN_TEST(test_self_test_fails_on_null_or_wrong_hmac);
    RUN_TEST(test_sig_msg_known_answer);
    RUN_TEST(test_sig_msg_binds_level_and_id);
    RUN_TEST(test_sig_msg_refuses_bad_input);
    RUN_TEST(test_sig_self_test_passes_with_correct_verify);
    RUN_TEST(test_sig_self_test_fails_on_wrong_verify);
    return UNITY_END();
}
