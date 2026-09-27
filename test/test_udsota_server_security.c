#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

#define T0 20000u     /* 20 s after boot: past the 10 s post-boot delay */

/* Mock platform: a deterministic RNG and a stand-in HMAC that record how they were called. */
typedef struct {
    bool    rng_ok;          /* rng16 result */
    bool    rng_zero;        /* rng16 hands out an all-zero seed */
    uint8_t seed_base;       /* next seed is base, base+1, ... base+15 */
    int     rng_calls;
    bool    hmac_ok;         /* hmac_key result */
    int     hmac_calls;
    uint8_t hmac_level;      /* level passed on the last hmac_key call */
    uint8_t hmac_seed[16];   /* seed passed on the last hmac_key call */
} mock_t;

static mock_t       M;
static udsota_server_t S;
static uint8_t      R[4095];
static size_t       RL;

/* The mock's stand-in for HMAC-SHA256: key[i] = seed[i] ^ level ^ 0xA5. */
static void fake_key(const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(seed[i] ^ level ^ 0xA5);
    }
}

/* Mock rng16: fills base..base+15 (or zeros), then moves base on by 0x20 so seeds never repeat. */
static bool mock_rng16(void *ctx, uint8_t out[16])
{
    mock_t *m = ctx;
    m->rng_calls++;
    if (!m->rng_ok) {
        return false;
    }
    for (int i = 0; i < 16; i++) {
        out[i] = m->rng_zero ? 0 : (uint8_t)(m->seed_base + i);
    }
    m->seed_base = (uint8_t)(m->seed_base + 0x20);
    return true;
}

/* Mock security.key: records its arguments and returns fake_key(seed, level) when hmac_ok. */
static bool mock_key(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16])
{
    mock_t *m = ctx;
    m->hmac_calls++;
    m->hmac_level = level;
    memcpy(m->hmac_seed, seed, 16);
    if (!m->hmac_ok) {
        return false;
    }
    fake_key(seed, level, out);
    return true;
}

static udsota_mock_t g_mock;

/* Engine op that completes at once with success; no test here reaches the engine. */
static int noop(void *ctx) { return 0; }
/* Engine erase stub. */
static int noop_begin(void *ctx, uint32_t size) { return 0; }
/* Engine write stub. */
static int noop_write(void *ctx, uint32_t off, const uint8_t *d, size_t n) { return 0; }
/* Engine abort stub. */
static void noop_abort(void *ctx) {}
/* Engine first-block stub. */
static int noop_check(void *ctx, const uint8_t *f, size_t n, udsota_reason_t *r) { *r = UDSOTA_DL_OK; return 0; }

static const udsota_engine_t ENGINE = {
    .check_first = noop_check, .begin = noop_begin, .write = noop_write, .verify = noop, .activate = noop,
    .confirm = noop, .abort = noop_abort, .poll = noop, .status = udsota_mock_status, .ctx = &g_mock,
};
static const udsota_security_t SECURITY = {.rng16 = mock_rng16, .key = mock_key, .ctx = &M};

/* Rebuilds the server as a chip restart does, with the mock's config and hooks (the gate allows 10 02). */
static void fresh_server(void)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&S, &cfg, &ENGINE, &SECURITY, &hooks);
}

/* Unity hook: a healthy mock and a freshly booted server for every test. */
void setUp(void)
{
    memset(&M, 0, sizeof M);
    M.rng_ok = true;
    M.hmac_ok = true;
    M.seed_base = 0x10;
    memset(&S, 0, sizeof S);
    udsota_mock_clear(&g_mock);
    fresh_server();
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* Sends one request at now; the response is left in R/RL. */
static void txreq(const uint8_t *req, size_t n, uint32_t now)
{
    RL = udsota_on_request(&S, req, n, R, sizeof R, now);
}

/* Asserts the last response is 7F 27 <nrc>. */
static void assert_nrc(uint8_t nrc)
{
    TEST_ASSERT_EQUAL_UINT(3, RL);
    TEST_ASSERT_EQUAL_HEX8(0x7F, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x27, R[1]);
    TEST_ASSERT_EQUAL_HEX8(nrc, R[2]);
}

/* Sends 10 <session> and asserts the positive 50 <session>. */
static void enter(uint8_t session, uint32_t now)
{
    const uint8_t r[2] = {0x10, session};
    txreq(r, sizeof r, now);
    TEST_ASSERT_TRUE(RL >= 2);
    TEST_ASSERT_EQUAL_HEX8(0x50, R[0]);
    TEST_ASSERT_EQUAL_HEX8(session, R[1]);
}

/* Sends 27 <sub> (a requestSeed), asserts 67 <sub> + 16 bytes and copies the seed out. */
static void request_seed(uint8_t sub, uint32_t now, uint8_t out[16])
{
    const uint8_t r[2] = {0x27, sub};
    txreq(r, sizeof r, now);
    TEST_ASSERT_EQUAL_UINT(18, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
    TEST_ASSERT_EQUAL_HEX8(sub, R[1]);
    memcpy(out, &R[2], 16);
}

/* Sends 27 <sub> <key[16]> (a sendKey). */
static void send_key(uint8_t sub, const uint8_t key[16], uint32_t now)
{
    uint8_t r[18] = {0x27, sub};
    memcpy(&r[2], key, 16);
    txreq(r, sizeof r, now);
}

/* Requests a seed at now and sends its correct key at now+1; asserts 67 <level+1>. */
static void unlock(uint8_t level, uint32_t now)
{
    uint8_t seed[16], key[16];
    request_seed(level, now, seed);
    fake_key(seed, level, key);
    send_key((uint8_t)(level + 1), key, now + 1);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
    TEST_ASSERT_EQUAL_HEX8(level + 1, R[1]);
}

/* Requests a seed at now and sends its key with the last byte flipped at now+1; the NRC is left in R. */
static void wrong_key(uint8_t level, uint32_t now)
{
    uint8_t seed[16], key[16];
    request_seed(level, now, seed);
    fake_key(seed, level, key);
    key[15] ^= 0x01;
    send_key((uint8_t)(level + 1), key, now + 1);
}

/* Sends 3E 00 every 4 s strictly between from and to, so S3 (5 s) never expires. */
static void keep_alive(uint32_t from, uint32_t to)
{
    const uint8_t tp[2] = {0x3E, 0x00};
    for (uint32_t t = from + 4000u; t < to; t += 4000u) {
        txreq(tp, sizeof tp, t);
        TEST_ASSERT_EQUAL_HEX8(0x7E, R[0]);
    }
}

static const uint8_t SEED01[2] = {0x27, 0x01};
static const uint8_t ZERO16[16] = {0};

/* 10 02, 27 03 returns the RNG's seed; 27 04 with the right key answers 67 04 and unlocks level 03. */
static void test_programming_seed_and_key_unlock_level_03(void)
{
    static const uint8_t want_seed[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_PROGRAMMING, T0);
    request_seed(0x03, T0 + 1, seed);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_seed, seed, 16);
    TEST_ASSERT_EQUAL_INT(1, M.rng_calls);
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);                       /* a seed alone unlocks nothing */
    fake_key(seed, 0x03, key);
    send_key(0x04, key, T0 + 2);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x04, R[1]);
    TEST_ASSERT_EQUAL_HEX8(0x03, M.hmac_level);                     /* level = the requestSeed byte */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want_seed, M.hmac_seed, 16);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_SA_SEED_PROGRAMMING, S.security);
}

/* 10 03, 27 01 / 27 02 unlocks level 01, and hmac_key sees level 0x01. */
static void test_extended_seed_and_key_unlock_level_01(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    unlock(0x01, T0 + 1);
    TEST_ASSERT_EQUAL_HEX8(0x01, M.hmac_level);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_SA_SEED_EXTENDED, S.security);
}

/* Wrong keys answer 35, 35, then 36; 37 follows for 10 s (seed and key alike); then a fresh count of three. */
static void test_three_wrong_keys_lock_out_for_10s(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    wrong_key(0x01, T0 + 10);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 20);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 30);  assert_nrc(0x36);                   /* the key at T0+31 starts the delay */
    const uint32_t d = T0 + 31;
    const int calls = M.rng_calls;
    txreq(SEED01, 2, d + 1);          assert_nrc(0x37);
    send_key(0x02, ZERO16, d + 2);    assert_nrc(0x37);
    enter(UDSOTA_SESSION_EXTENDED, d + 4000);                          /* keep a non-default session */
    enter(UDSOTA_SESSION_EXTENDED, d + 8000);
    txreq(SEED01, 2, d + 9999);       assert_nrc(0x37);
    TEST_ASSERT_EQUAL_INT(calls, M.rng_calls);                      /* no seed drawn during the delay */
    wrong_key(0x01, d + 10000);       assert_nrc(0x35);             /* delay over: fresh count */
    wrong_key(0x01, d + 10010);       assert_nrc(0x35);
    wrong_key(0x01, d + 10020);       assert_nrc(0x36);
}

/* The attempt count is global and survives a session change: 2 wrong in extended + 1 in programming = 36. */
static void test_attempts_count_across_levels_and_sessions(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    wrong_key(0x01, T0 + 10);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 20);  assert_nrc(0x35);
    enter(UDSOTA_SESSION_PROGRAMMING, T0 + 30);                        /* relocks, keeps the count */
    wrong_key(0x03, T0 + 40);  assert_nrc(0x36);
    const uint8_t seed03[2] = {0x27, 0x03};
    txreq(seed03, 2, T0 + 50); assert_nrc(0x37);
}

/* A correct key clears the count: after 2 wrong + 1 right, two more wrong keys still answer 35. */
static void test_correct_key_clears_attempt_count(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    wrong_key(0x01, T0 + 10);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 20);  assert_nrc(0x35);
    unlock(0x01, T0 + 30);
    enter(UDSOTA_SESSION_EXTENDED, T0 + 40);                           /* relock */
    wrong_key(0x01, T0 + 50);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 60);  assert_nrc(0x35);
    wrong_key(0x01, T0 + 70);  assert_nrc(0x36);
}

/* After boot (clock 0) 0x27 answers 37 until 10 000 ms, without drawing a seed; at 10 000 ms a seed is issued. */
static void test_delay_after_boot(void)
{
    uint8_t seed[16];
    enter(UDSOTA_SESSION_EXTENDED, 100);
    txreq(SEED01, 2, 101);            assert_nrc(0x37);
    send_key(0x02, ZERO16, 102);      assert_nrc(0x37);
    enter(UDSOTA_SESSION_EXTENDED, 4000);
    enter(UDSOTA_SESSION_EXTENDED, 8000);
    txreq(SEED01, 2, 9999);           assert_nrc(0x37);
    TEST_ASSERT_EQUAL_INT(0, M.rng_calls);
    request_seed(0x01, 10000, seed);
    TEST_ASSERT_EQUAL_INT(1, M.rng_calls);
}

/* A requestSeed for an unlocked level answers 16 zero bytes, draws nothing, and leaves no seed outstanding. */
static void test_zero_seed_when_level_already_unlocked(void)
{
    uint8_t seed[16];
    enter(UDSOTA_SESSION_PROGRAMMING, T0);
    unlock(0x03, T0 + 1);
    const int calls = M.rng_calls;
    request_seed(0x03, T0 + 10, seed);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, seed, 16);
    TEST_ASSERT_EQUAL_INT(calls, M.rng_calls);
    send_key(0x04, ZERO16, T0 + 11);  assert_nrc(0x24);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_SA_SEED_PROGRAMMING, S.security);   /* a 0x24 does not relock */
}

/* A key with no outstanding seed answers 24, calls no HMAC, and is not counted as an attempt. */
static void test_key_without_seed_is_sequence_error(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    for (uint32_t i = 0; i < 3; i++) {
        send_key(0x02, ZERO16, T0 + 1 + i);
        assert_nrc(0x24);
    }
    TEST_ASSERT_EQUAL_INT(0, M.hmac_calls);
    wrong_key(0x01, T0 + 10);  assert_nrc(0x35);                    /* not 36: the 24s were not attempts */
}

/* A seed is single-use: after one wrong key, even the right key for that seed answers 24. */
static void test_seed_is_single_use(void)
{
    uint8_t seed[16], key[16], bad[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    request_seed(0x01, T0 + 1, seed);
    fake_key(seed, 0x01, key);
    memcpy(bad, key, 16);
    bad[0] ^= 0xFF;
    send_key(0x02, bad, T0 + 2);  assert_nrc(0x35);
    send_key(0x02, key, T0 + 3);  assert_nrc(0x24);
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
}

/* A seed is valid for 29 999 ms after issue and expired (24, not counted) at 30 000 ms. */
static void test_seed_expires_after_30s(void)
{
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    const uint32_t t1 = T0 + 1;
    request_seed(0x01, t1, seed);
    fake_key(seed, 0x01, key);
    keep_alive(t1, t1 + 29999u);
    send_key(0x02, key, t1 + 29999u);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);

    const uint32_t t2 = t1 + 30010u;
    enter(UDSOTA_SESSION_EXTENDED, t2);                                /* relock */
    request_seed(0x01, t2 + 1, seed);
    fake_key(seed, 0x01, key);
    keep_alive(t2 + 1, t2 + 1 + 30000u);
    send_key(0x02, key, t2 + 1 + 30000u);  assert_nrc(0x24);
    TEST_ASSERT_EQUAL_INT(1, M.hmac_calls);                         /* the expired seed reached no HMAC */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
}

/* A second requestSeed replaces the outstanding seed: the first seed's key is then wrong (35). */
static void test_new_seed_replaces_outstanding_one(void)
{
    uint8_t a[16], b[16], ka[16], kb[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    request_seed(0x01, T0 + 1, a);
    request_seed(0x01, T0 + 2, b);
    TEST_ASSERT_EQUAL_INT(2, M.rng_calls);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(a, b, 16));
    fake_key(a, 0x01, ka);
    send_key(0x02, ka, T0 + 3);  assert_nrc(0x35);
    request_seed(0x01, T0 + 4, b);
    fake_key(b, 0x01, kb);
    send_key(0x02, kb, T0 + 5);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
}

/* An RNG failure or an all-zero draw answers 22 and leaves no seed outstanding. */
static void test_rng_failure_or_zero_seed_refused(void)
{
    enter(UDSOTA_SESSION_EXTENDED, T0);
    M.rng_ok = false;
    txreq(SEED01, 2, T0 + 1);          assert_nrc(0x22);
    M.rng_ok = true;
    M.rng_zero = true;
    txreq(SEED01, 2, T0 + 2);          assert_nrc(0x22);           /* never send a zero seed while locked */
    M.rng_zero = false;
    send_key(0x02, ZERO16, T0 + 3);    assert_nrc(0x24);
}

/* An HMAC failure answers 22, consumes the seed and is not counted as an attempt. */
static void test_hmac_failure_refused_and_not_counted(void)
{
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    M.hmac_ok = false;
    request_seed(0x01, T0 + 1, seed);
    fake_key(seed, 0x01, key);
    send_key(0x02, key, T0 + 2);  assert_nrc(0x22);
    M.hmac_ok = true;
    send_key(0x02, key, T0 + 3);  assert_nrc(0x24);                 /* seed consumed */
    wrong_key(0x01, T0 + 10);     assert_nrc(0x35);
    wrong_key(0x01, T0 + 20);     assert_nrc(0x35);                 /* not 36: the 22 was not an attempt */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
}

/* In the default session every 0x27, even a 1-byte one, answers 7F 27 7F without drawing a seed. */
static void test_default_session_answers_7f(void)
{
    const uint8_t seed03[2] = {0x27, 0x03};
    const uint8_t bare[1] = {0x27};
    txreq(SEED01, 2, T0);          assert_nrc(0x7F);
    txreq(seed03, 2, T0 + 1);      assert_nrc(0x7F);
    txreq(bare, 1, T0 + 2);        assert_nrc(0x7F);
    send_key(0x02, ZERO16, T0 + 3); assert_nrc(0x7F);
    TEST_ASSERT_EQUAL_INT(0, M.rng_calls);
}

/* Level 01/02 is refused (7E) in programming and level 03/04 in extended. */
static void test_level_gated_by_session(void)
{
    const uint8_t seed03[2] = {0x27, 0x03};
    enter(UDSOTA_SESSION_EXTENDED, T0);
    txreq(seed03, 2, T0 + 1);         assert_nrc(0x7E);
    send_key(0x04, ZERO16, T0 + 2);   assert_nrc(0x7E);
    enter(UDSOTA_SESSION_PROGRAMMING, T0 + 10);
    txreq(SEED01, 2, T0 + 11);        assert_nrc(0x7E);
    send_key(0x02, ZERO16, T0 + 12);  assert_nrc(0x7E);
    TEST_ASSERT_EQUAL_INT(0, M.rng_calls);
}

/* Unknown sub-functions answer 12; a missing sub-function or a wrong total length answers 13. */
static void test_bad_subfunction_and_length(void)
{
    const uint8_t bare[1] = {0x27};
    const uint8_t sub00[2] = {0x27, 0x00}, sub05[2] = {0x27, 0x05};
    const uint8_t sub7f[2] = {0x27, 0x7F}, sub85[2] = {0x27, 0x85};
    const uint8_t seed_long[3] = {0x27, 0x01, 0x00};
    uint8_t key_req[19] = {0x27, 0x02};
    enter(UDSOTA_SESSION_EXTENDED, T0);
    txreq(bare, 1, T0 + 1);         assert_nrc(0x13);
    txreq(sub00, 2, T0 + 2);        assert_nrc(0x12);
    txreq(sub05, 2, T0 + 3);        assert_nrc(0x12);
    txreq(sub7f, 2, T0 + 4);        assert_nrc(0x12);
    txreq(sub85, 2, T0 + 5);        assert_nrc(0x12);
    txreq(seed_long, 3, T0 + 6);    assert_nrc(0x13);
    txreq(key_req, 17, T0 + 7);     assert_nrc(0x13);               /* 15 key bytes */
    txreq(key_req, 19, T0 + 8);     assert_nrc(0x13);               /* 17 key bytes */
    txreq(key_req, 2, T0 + 9);      assert_nrc(0x13);               /* no key bytes */
    TEST_ASSERT_EQUAL_INT(0, M.rng_calls);
    TEST_ASSERT_EQUAL_INT(0, M.hmac_calls);
}

/* A key wrong in any single byte position is rejected (the compare covers all 16 bytes). */
static void test_every_key_byte_compared(void)
{
    for (int pos = 0; pos < 16; pos++) {
        uint8_t seed[16], key[16];
        fresh_server();                                             /* no lockout carried between positions */
        enter(UDSOTA_SESSION_EXTENDED, T0);
        request_seed(0x01, T0 + 1, seed);
        fake_key(seed, 0x01, key);
        key[pos] ^= 0x80;
        send_key(0x02, key, T0 + 2);
        assert_nrc(0x35);
        TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    }
}

/* With SPRMIB (27 82) a wrong key still answers 35, and a right key unlocks with no response. */
static void test_suppress_bit_on_send_key(void)
{
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    request_seed(0x01, T0 + 1, seed);
    fake_key(seed, 0x01, key);
    key[3] ^= 0x10;
    send_key(0x82, key, T0 + 2);  assert_nrc(0x35);
    request_seed(0x01, T0 + 3, seed);
    fake_key(seed, 0x01, key);
    send_key(0x82, key, T0 + 4);
    TEST_ASSERT_EQUAL_UINT(0, RL);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_SA_SEED_EXTENDED, S.security);
}

/* Every accepted 10 xx relocks (same session, the other one, or default) and drops an outstanding seed. */
static void test_relock_on_session_change(void)
{
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_EXTENDED, T0);
    unlock(0x01, T0 + 1);
    enter(UDSOTA_SESSION_EXTENDED, T0 + 10);                           /* same session again */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    request_seed(0x01, T0 + 11, seed);                              /* locked: a real seed, not zeros */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(seed, ZERO16, 16));
    fake_key(seed, 0x01, key);
    enter(UDSOTA_SESSION_EXTENDED, T0 + 12);                           /* drops that outstanding seed */
    send_key(0x02, key, T0 + 13);  assert_nrc(0x24);

    unlock(0x01, T0 + 20);
    enter(UDSOTA_SESSION_PROGRAMMING, T0 + 30);                        /* extended -> programming */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    unlock(0x03, T0 + 31);
    enter(UDSOTA_SESSION_EXTENDED, T0 + 40);                           /* programming -> extended */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    unlock(0x01, T0 + 41);
    enter(UDSOTA_SESSION_DEFAULT, T0 + 50);                            /* 10 01 */
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, S.session);
}

/* The S3 fallback to default relocks and drops an outstanding seed. */
static void test_relock_on_s3_timeout(void)
{
    uint8_t seed[16], key[16];
    enter(UDSOTA_SESSION_PROGRAMMING, T0);
    unlock(0x03, T0 + 1);                                           /* last response at T0+2 */
    udsota_poll(&S, R, sizeof R, T0 + 2 + 6000u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, S.session);
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);

    const uint32_t t = T0 + 9000u;
    enter(UDSOTA_SESSION_EXTENDED, t);
    request_seed(0x01, t + 1, seed);                                /* outstanding across the fallback */
    fake_key(seed, 0x01, key);
    udsota_poll(&S, R, sizeof R, t + 1 + 6000u);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, S.session);
    enter(UDSOTA_SESSION_EXTENDED, t + 8000u);
    send_key(0x02, key, t + 8001u);  assert_nrc(0x24);
}

/* A reset (udsota_init on the restarted chip) relocks, returns to default and re-arms the boot delay. */
static void test_relock_on_reset(void)
{
    enter(UDSOTA_SESSION_PROGRAMMING, T0);
    unlock(0x03, T0 + 1);
    fresh_server();
    TEST_ASSERT_EQUAL_HEX8(0x00, S.security);
    TEST_ASSERT_EQUAL_INT(UDSOTA_SESSION_DEFAULT, S.session);
    enter(UDSOTA_SESSION_EXTENDED, 500);                               /* the clock restarts from 0 */
    txreq(SEED01, 2, 501);  assert_nrc(0x37);
}

/* Runs every SecurityAccess test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_programming_seed_and_key_unlock_level_03);
    RUN_TEST(test_extended_seed_and_key_unlock_level_01);
    RUN_TEST(test_three_wrong_keys_lock_out_for_10s);
    RUN_TEST(test_attempts_count_across_levels_and_sessions);
    RUN_TEST(test_correct_key_clears_attempt_count);
    RUN_TEST(test_delay_after_boot);
    RUN_TEST(test_zero_seed_when_level_already_unlocked);
    RUN_TEST(test_key_without_seed_is_sequence_error);
    RUN_TEST(test_seed_is_single_use);
    RUN_TEST(test_seed_expires_after_30s);
    RUN_TEST(test_new_seed_replaces_outstanding_one);
    RUN_TEST(test_rng_failure_or_zero_seed_refused);
    RUN_TEST(test_hmac_failure_refused_and_not_counted);
    RUN_TEST(test_default_session_answers_7f);
    RUN_TEST(test_level_gated_by_session);
    RUN_TEST(test_bad_subfunction_and_length);
    RUN_TEST(test_every_key_byte_compared);
    RUN_TEST(test_suppress_bit_on_send_key);
    RUN_TEST(test_relock_on_session_change);
    RUN_TEST(test_relock_on_s3_timeout);
    RUN_TEST(test_relock_on_reset);
    return UNITY_END();
}
