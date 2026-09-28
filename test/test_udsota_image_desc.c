/* Host tests for the image descriptor: the 32 bytes image_check reads at offset 288 from an instance made with
 * the ESP32 port's UDSOTA_ESP32_IMAGE_DESC for the example device (IDs 0x710/0x718). The layout itself is
 * _Static_asserted in udsota_image_desc.h. The top-level CMakeLists.txt builds it three times: board 1 and board 3
 * as dev images, and board 1 as a release. */
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota_esp32.h"

#ifndef UDSOTA_TEST_HW_ID
#error "the top-level CMakeLists.txt sets UDSOTA_TEST_HW_ID and UDSOTA_ESP32_IMG_RELEASE for each variant"
#endif
#ifndef UDSOTA_TEST_RELEASE
#define UDSOTA_TEST_RELEASE 0   /* 1 in the _release target, built with UDSOTA_ESP32_IMG_RELEASE=1 */
#endif

#define REQ_ID  0x710u
#define RESP_ID 0x718u

UDSOTA_ESP32_IMAGE_DESC(UDSOTA_TEST_HW_ID, 1, REQ_ID, RESP_ID);   /* hw_id, layout_id, request ID, response ID */

/* Unity hook: no per-test setup. */
void setUp(void) {}
/* Unity hook: no per-test teardown. */
void tearDown(void) {}

/* The instance carries the magic, version 1, this build's board, layout 1, the diag IDs
 * and flags 00 (01 only in the _release target). */
static void test_values(void)
{
    TEST_ASSERT_EQUAL_HEX32(0x5544534Fu, udsota_image_desc.magic);
    TEST_ASSERT_EQUAL_UINT16(1, udsota_image_desc.desc_version);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_TEST_HW_ID, udsota_image_desc.hw_id);
    TEST_ASSERT_EQUAL_UINT8(1, udsota_image_desc.partition_layout_id);
    TEST_ASSERT_EQUAL_HEX16(0x710, udsota_image_desc.diag_request_id);
    TEST_ASSERT_EQUAL_HEX16(0x718, udsota_image_desc.diag_response_id);
    TEST_ASSERT_EQUAL_HEX8(UDSOTA_TEST_RELEASE ? 0x01u : 0x00u, udsota_image_desc.flags);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, udsota_image_desc.reserved, sizeof udsota_image_desc.reserved);
}

/* The in-memory bytes (little-endian on host and ESP32-S3 alike) are the flash bytes at offset 288. */
static void test_flash_bytes(void)
{
    uint8_t want[32] = {0x4F, 0x53, 0x44, 0x55, 0x01, 0x00, UDSOTA_TEST_HW_ID, 0x01,
                        0x10, 0x07, 0x18, 0x07, UDSOTA_TEST_RELEASE ? 0x01 : 0x00};   /* flags, then bytes 13..31 zero */
    uint8_t got[32];
    memcpy(got, &udsota_image_desc, sizeof got);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, got, 32);
}

/* Runs every image descriptor test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_values);
    RUN_TEST(test_flash_bytes);
    return UNITY_END();
}
