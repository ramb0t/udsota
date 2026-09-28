/* Host tests for the ESP32 port's device ID (components/udsota_esp32/udsota_esp32_devid.c) with the real
 * server and key derivation: F18C serves the stored ID, and a key a client derives from F18C's bytes is the
 * key the port's security callback expects, for a custom ID and for the base MAC. The HMAC is a stand-in
 * that mixes every key and message byte, so a key over the wrong ID cannot match by accident. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_keys.h"
#include "udsota_esp32_devid.h"
#include "udsota_mock.h"

#define T0 20000u     /* 20 s after boot: past the 10 s post-boot delay */

static const uint8_t MAC[UDSOTA_ESP32_DEVICE_ID_LEN] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC3};
static const uint8_t CUSTOM[10] = {'S', 'N', '-', '0', '0', '4', '2', 0x00, 0x7F, 0xFF};
static const char    LABEL[] = "udsota-test";

static uint8_t              s_master[32];
static udsota_esp32_devid_t s_dev;
static udsota_mock_t        s_mock;
static udsota_server_t      s_srv;
static uint8_t              R[4095];
static size_t               RL;

/* Stand-in HMAC-SHA256: 32 FNV-1a hashes, one per output byte, each over every key and message byte. */
static bool mix_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[UDSOTA_KEYS_HMAC_LEN])
{
    for (size_t j = 0; j < UDSOTA_KEYS_HMAC_LEN; j++) {
        uint32_t h = 2166136261u ^ (uint32_t)j;
        for (size_t i = 0; i < key_len; i++) {
            h = (h ^ key[i]) * 16777619u;
        }
        h = (h ^ (uint32_t)key_len ^ 0x5A00u) * 16777619u;
        for (size_t i = 0; i < msg_len; i++) {
            h = (h ^ msg[i]) * 16777619u;
        }
        h = (h ^ (uint32_t)msg_len) * 16777619u;
        out[j] = (uint8_t)(h >> 24);
    }
    return true;
}

/* security.rng16: a fixed non-zero seed; the server takes each seed once. */
static bool test_rng16(void *ctx, uint8_t out[UDSOTA_KEYS_SEED_LEN])
{
    for (int i = 0; i < UDSOTA_KEYS_SEED_LEN; i++) {
        out[i] = (uint8_t)(0x10 + i);
    }
    return true;
}

/* security.key: udsota_esp32_keys.c's sec_key without the PSA lock, over the struct in ctx. */
static bool test_key(void *ctx, const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                     uint8_t out[UDSOTA_KEYS_KEY_LEN])
{
    return udsota_esp32_devid_key(ctx, mix_hmac, seed, level, out);
}

/* Unity hook: master 00..1F, an empty device ID and a cleared mock. */
void setUp(void)
{
    for (int i = 0; i < 32; i++) {
        s_master[i] = (uint8_t)i;
    }
    memset(&s_dev, 0, sizeof s_dev);
    memset(&s_srv, 0, sizeof s_srv);
    udsota_mock_clear(&s_mock);
}

/* Unity hook: nothing to undo. */
void tearDown(void) {}

/* As udsota_esp32_security() does: fixes the ID (no change when already fixed) and derives K_dev over the
 * fixed ID. The MAC read succeeded. */
static udsota_esp32_devid_fix_t port_security(const uint8_t *id, size_t id_len)
{
    const udsota_esp32_devid_fix_t r = udsota_esp32_devid_fix(&s_dev, id, id_len, MAC, true);
    TEST_ASSERT_TRUE(udsota_esp32_devid_derive_kdev(&s_dev, mix_hmac, s_master, sizeof s_master, LABEL));
    return r;
}

/* As udsota_esp32_start() does with cfg.device_id = id: fixes the ID, runs security, points the config's
 * device_id at the stored ID and boots the server with the port's key callback. Returns start's fix result. */
static udsota_esp32_devid_fix_t port_start(const uint8_t *id, size_t id_len)
{
    const udsota_esp32_devid_fix_t r = udsota_esp32_devid_fix(&s_dev, id, id_len, MAC, true);
    (void)port_security(id, id_len);
    udsota_config_t cfg = udsota_mock_cfg();
    cfg.device_id = id;
    cfg.device_id_len = id_len;
    udsota_esp32_devid_serve(&s_dev, &cfg);
    const udsota_hooks_t hooks = udsota_mock_hooks(&s_mock);
    static udsota_security_t sec;
    sec = (udsota_security_t){.rng16 = test_rng16, .key = test_key, .ctx = &s_dev};
    const udsota_engine_t eng = udsota_mock_engine(&s_mock);   /* no test here reaches the engine */
    udsota_init(&s_srv, &cfg, &eng, &sec, &hooks);
    return r;
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

/* Enters the extended session, requests a level-01 seed and sends the key a client derives from id; the
 * sendKey answer is left in R/RL. */
static void unlock_with(const uint8_t *id, size_t id_len)
{
    const uint8_t ext[2] = {0x10, 0x03}, seed_req[2] = {0x27, 0x01};
    txreq(ext, sizeof ext, T0 + 1);
    TEST_ASSERT_EQUAL_HEX8(0x50, R[0]);
    txreq(seed_req, sizeof seed_req, T0 + 2);
    TEST_ASSERT_EQUAL_UINT(18, RL);
    uint8_t kdev[UDSOTA_KEYS_KDEV_LEN], key_req[18] = {0x27, 0x02};
    TEST_ASSERT_TRUE(udsota_keys_derive_kdev(mix_hmac, s_master, sizeof s_master, LABEL, id, id_len, kdev));
    TEST_ASSERT_TRUE(udsota_keys_derive_key(mix_hmac, kdev, &R[2], 0x01, id, id_len, &key_req[2]));
    txreq(key_req, sizeof key_req, T0 + 3);
}

/* A NULL ID is the 6-byte base MAC whatever id_len says, as before the port took cfg.device_id. */
static void test_null_id_is_the_base_mac(void)
{
    TEST_ASSERT_TRUE(udsota_esp32_devid_len_ok(NULL, 0));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_BAD, udsota_esp32_devid_fix(&s_dev, NULL, 0, NULL, true));
    TEST_ASSERT_FALSE(atomic_load(&s_dev.fixed));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, NULL, 99, MAC, true));
    TEST_ASSERT_TRUE(atomic_load(&s_dev.fixed));
    TEST_ASSERT_TRUE(s_dev.is_mac);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_ESP32_DEVICE_ID_LEN, s_dev.id_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(MAC, s_dev.id, UDSOTA_ESP32_DEVICE_ID_LEN);
}

/* A set ID of 1 to UDSOTA_KEYS_ID_MAX bytes is fixed as given; 0 or one byte more is refused and fixes nothing. */
static void test_id_lengths(void)
{
    uint8_t id[UDSOTA_KEYS_ID_MAX + 1];
    for (size_t i = 0; i < sizeof id; i++) {
        id[i] = (uint8_t)(0xC0 + i);
    }
    const size_t ok[] = {1, UDSOTA_KEYS_ID_MAX};
    for (size_t i = 0; i < 2; i++) {
        memset(&s_dev, 0, sizeof s_dev);
        TEST_ASSERT_TRUE(udsota_esp32_devid_len_ok(id, ok[i]));
        TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, id, ok[i], MAC, true));
        TEST_ASSERT_FALSE(s_dev.is_mac);
        TEST_ASSERT_EQUAL_UINT(ok[i], s_dev.id_len);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(id, s_dev.id, ok[i]);
    }
    const size_t bad[] = {0, UDSOTA_KEYS_ID_MAX + 1};
    for (size_t i = 0; i < 2; i++) {
        memset(&s_dev, 0, sizeof s_dev);
        TEST_ASSERT_FALSE(udsota_esp32_devid_len_ok(id, bad[i]));
        TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_BAD, udsota_esp32_devid_fix(&s_dev, id, bad[i], MAC, true));
        TEST_ASSERT_FALSE(atomic_load(&s_dev.fixed));
        TEST_ASSERT_FALSE(udsota_esp32_devid_derive_kdev(&s_dev, mix_hmac, s_master, sizeof s_master, LABEL));
    }
}

/* The ID is fixed once: the same bytes again are KEPT, other bytes are OTHER, and neither changes it. */
static void test_fixed_once(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, CUSTOM, sizeof CUSTOM, MAC, true));
    uint8_t copy[sizeof CUSTOM];
    memcpy(copy, CUSTOM, sizeof copy);
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_KEPT, udsota_esp32_devid_fix(&s_dev, copy, sizeof copy, MAC, true));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_OTHER, udsota_esp32_devid_fix(&s_dev, NULL, 0, MAC, true));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_OTHER, udsota_esp32_devid_fix(&s_dev, copy, 3, MAC, true));
    TEST_ASSERT_EQUAL_UINT(sizeof CUSTOM, s_dev.id_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(CUSTOM, s_dev.id, sizeof CUSTOM);
}

/* A MAC whose read failed gives no K_dev, also when the app hands back the MAC pointer as its own ID. */
static void test_failed_mac_no_kdev(void)
{
    static const uint8_t zero_mac[UDSOTA_ESP32_DEVICE_ID_LEN] = {0};
    const uint8_t *handed_back[] = {NULL, zero_mac};
    for (size_t i = 0; i < 2; i++) {
        memset(&s_dev, 0, sizeof s_dev);
        TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED,
                              udsota_esp32_devid_fix(&s_dev, handed_back[i], UDSOTA_ESP32_DEVICE_ID_LEN, zero_mac, false));
        TEST_ASSERT_TRUE(s_dev.is_mac);
        TEST_ASSERT_FALSE(udsota_esp32_devid_derive_kdev(&s_dev, mix_hmac, s_master, sizeof s_master, LABEL));
    }
}

/* Without K_dev the key callback refuses, with the key zeroed. */
static void test_no_kdev_no_key(void)
{
    uint8_t seed[UDSOTA_KEYS_SEED_LEN] = {1}, key[UDSOTA_KEYS_KEY_LEN];
    memset(key, 0xEE, sizeof key);
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, udsota_esp32_devid_fix(&s_dev, CUSTOM, sizeof CUSTOM, MAC, true));
    TEST_ASSERT_FALSE(udsota_esp32_devid_key(&s_dev, mix_hmac, seed, 0x01, key));
    TEST_ASSERT_EACH_EQUAL_HEX8(0, key, sizeof key);
}

/* A custom ID: F18C serves a copy of it, and the key a client derives from F18C's bytes unlocks, even after
 * the app's own buffer changes. */
static void test_custom_id_f18c_key_unlocks(void)
{
    uint8_t app_id[sizeof CUSTOM], f18c[UDSOTA_KEYS_ID_MAX];
    memcpy(app_id, CUSTOM, sizeof app_id);
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, port_start(app_id, sizeof app_id));
    memset(app_id, 0, sizeof app_id);
    const size_t n = read_f18c(f18c);
    TEST_ASSERT_EQUAL_UINT(sizeof CUSTOM, n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(CUSTOM, f18c, n);
    unlock_with(f18c, n);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, R[1]);
}

/* The negative control: with a custom ID in use, a key derived from the base MAC is refused with 0x35. */
static void test_custom_id_mac_key_refused(void)
{
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, port_start(CUSTOM, sizeof CUSTOM));
    unlock_with(MAC, sizeof MAC);
    TEST_ASSERT_EQUAL_UINT(3, RL);
    TEST_ASSERT_EQUAL_HEX8(0x7F, R[0]);
    TEST_ASSERT_EQUAL_HEX8(0x27, R[1]);
    TEST_ASSERT_EQUAL_HEX8(0x35, R[2]);
}

/* No device_id (what existing apps pass): F18C serves the 6-byte base MAC and a MAC-derived key unlocks. */
static void test_null_id_serves_mac_and_unlocks(void)
{
    uint8_t f18c[UDSOTA_KEYS_ID_MAX];
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, port_start(NULL, 0));
    const size_t n = read_f18c(f18c);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_ESP32_DEVICE_ID_LEN, n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(MAC, f18c, n);
    unlock_with(MAC, sizeof MAC);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
}

/* security() before start, with another ID: start keeps the first ID (OTHER, which it logs), F18C serves
 * it, and the key derived from F18C's bytes unlocks. */
static void test_security_first_then_start_other_id(void)
{
    uint8_t f18c[UDSOTA_KEYS_ID_MAX];
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_FIXED, port_security(CUSTOM, sizeof CUSTOM));
    TEST_ASSERT_EQUAL_INT(UDSOTA_ESP32_DEVID_OTHER, port_start(NULL, 0));
    const size_t n = read_f18c(f18c);
    TEST_ASSERT_EQUAL_UINT(sizeof CUSTOM, n);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(CUSTOM, f18c, n);
    unlock_with(f18c, n);
    TEST_ASSERT_EQUAL_UINT(2, RL);
    TEST_ASSERT_EQUAL_HEX8(0x67, R[0]);
}

/* Runs every test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_null_id_is_the_base_mac);
    RUN_TEST(test_id_lengths);
    RUN_TEST(test_fixed_once);
    RUN_TEST(test_failed_mac_no_kdev);
    RUN_TEST(test_no_kdev_no_key);
    RUN_TEST(test_custom_id_f18c_key_unlocks);
    RUN_TEST(test_custom_id_mac_key_refused);
    RUN_TEST(test_null_id_serves_mac_and_unlocks);
    RUN_TEST(test_security_first_then_start_other_id);
    return UNITY_END();
}
