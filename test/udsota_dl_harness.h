/* The download suites' shared harness (download, compress, delta): the server, its clock and last response, boot on
 * the mock, and the 10 02 + 27, 34, 37 and poll-to-final helpers. Defines statics, so one include per executable,
 * ahead of the test's engine, which reads g_now and srv. */
#pragma once
#include <stdint.h>
#include "unity.h"
#include "udsota.h"
#include "udsota_mock.h"

static udsota_server_t srv;
static uint32_t        g_now;
static uint8_t         g_resp[64];
static size_t          g_resp_len;
static udsota_mock_t   g_mock;

/* Asserts the last response is exactly the bytes listed. */
#define EXPECT(...) do {                                                       \
        const uint8_t e_[] = {__VA_ARGS__};                                    \
        TEST_ASSERT_EQUAL_UINT(sizeof e_, g_resp_len);                         \
        TEST_ASSERT_EQUAL_HEX8_ARRAY(e_, g_resp, sizeof e_);                   \
    } while (0)

/* Boots the server on engine with the mock's config, hooks and security. */
static inline void boot(const udsota_engine_t *engine)
{
    const udsota_config_t cfg = udsota_mock_cfg();
    const udsota_hooks_t hooks = udsota_mock_hooks(&g_mock);
    udsota_init(&srv, &cfg, engine, udsota_mock_security(), &hooks);
}

/* Sends one request at g_now; returns the immediate response length (0 = none yet) and keeps it in g_resp. */
static inline size_t send(const uint8_t *req, size_t len)
{
    g_resp_len = udsota_on_request(&srv, req, len, g_resp, sizeof g_resp, g_now);
    return g_resp_len;
}

/* Polls every 10 ms until a final response, counting the 0x78s into *pending (if not NULL) and, when sid is not 0,
 * asserting each is for sid; fails after 100 s. */
static inline size_t finish_job(unsigned *pending, uint8_t sid)
{
    unsigned n78 = 0;
    for (uint32_t waited = 0; waited < 100000u; waited += 10u) {
        g_now += 10u;
        const size_t n = udsota_poll(&srv, g_resp, sizeof g_resp, g_now);
        if (n == 3u && g_resp[0] == UDSOTA_NEG_RESPONSE && g_resp[2] == UDSOTA_NRC_RESPONSE_PENDING) {
            if (sid != 0u) TEST_ASSERT_EQUAL_HEX8(sid, g_resp[1]);
            n78++;
            continue;
        }
        if (n > 0u) {
            g_resp_len = n;
            if (pending != NULL) *pending = n78;
            return n;
        }
    }
    TEST_FAIL_MESSAGE("the job never finished");
    return 0;
}

/* 10 02, then 27 03 / 27 04 with the mock key: programming session, level 03 unlocked. */
static inline void enter_programming(void)
{
    const uint8_t sess[] = {UDSOTA_SID_SESSION, UDSOTA_SESSION_PROGRAMMING};
    send(sess, sizeof sess);
    TEST_ASSERT_EQUAL_HEX8(0x50, g_resp[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02, g_resp[1]);
    const uint8_t seed_req[] = {UDSOTA_SID_SECURITY, UDSOTA_SA_SEED_PROGRAMMING};
    send(seed_req, sizeof seed_req);
    TEST_ASSERT_EQUAL_UINT(2u + UDSOTA_SEED_LEN, g_resp_len);
    TEST_ASSERT_EQUAL_HEX8(0x67, g_resp[0]);
    uint8_t key[2u + UDSOTA_KEY_LEN] = {UDSOTA_SID_SECURITY, UDSOTA_SA_KEY_PROGRAMMING};
    udsota_mock_key_for(&g_resp[2], UDSOTA_SA_SEED_PROGRAMMING, &key[2]);
    send(key, sizeof key);
    EXPECT(0x67, 0x04);
}

/* Sends 34 <dfi> 44 <address 0> <size>. */
static inline size_t send_34(uint8_t dfi, uint32_t size)
{
    const uint8_t r[UDSOTA_DL_REQ_LEN] = {
        UDSOTA_SID_REQUEST_DOWNLOAD, dfi, UDSOTA_DL_ALFID, 0, 0, 0, 0,
        (uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size,
    };
    return send(r, sizeof r);
}

/* Sends 37 and returns the immediate response length. */
static inline size_t send_37(void)
{
    const uint8_t r[] = {UDSOTA_SID_TRANSFER_EXIT};
    return send(r, sizeof r);
}
