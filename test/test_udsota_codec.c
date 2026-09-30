#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "unity.h"
#include "udsota_wire.h"

/* Unity per-test hook; each test builds its own buffers. */
void setUp(void) {}
/* Unity per-test hook; nothing to clean up. */
void tearDown(void) {}

/* F1F0 fixture: slot 1 PENDING_VERIFY and boot slot 1; other slot VERIFIED holding v0.2.7; flags bit0|bit1. */
static const uint8_t STATUS_BYTES[UDSOTA_STATUS_LEN] = {
    0x01, 0x02, 0x01, 0x03, 0x00, 0x02, 0x07,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0x03,
};

/* Returns the struct that STATUS_BYTES encodes. */
static udsota_status_t status_fixture(void)
{
    udsota_status_t s = {
        .running_slot = UDSOTA_SLOT_OTA1,
        .running_state = UDSOTA_IMG_PENDING_VERIFY,
        .boot_slot = UDSOTA_SLOT_OTA1,
        .other_slot_state = UDSOTA_OTHER_VERIFIED,
        .other_version = {0, 2, 7},
        .other_elf_sha_prefix = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8},
        .flags = UDSOTA_STATUS_SIG_CHECKED | UDSOTA_STATUS_BOOT_IGNORED_CONFIG,
    };
    return s;
}

/* F1F0 packs field by field into 16 bytes, in declaration order. */
static void test_status_packs_to_fixed_bytes(void)
{
    const udsota_status_t s = status_fixture();
    uint8_t out[UDSOTA_STATUS_LEN + 1];
    memset(out, 0xEE, sizeof out);
    TEST_ASSERT_EQUAL_UINT(UDSOTA_STATUS_LEN, udsota_pack_status(out, sizeof out, &s));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(STATUS_BYTES, out, UDSOTA_STATUS_LEN);
    TEST_ASSERT_EQUAL_HEX8(0xEE, out[UDSOTA_STATUS_LEN]);   /* nothing past the layout */
}

/* The fixed F1F0 bytes unpack to the fixture, and packing that again gives the same bytes. */
static void test_status_unpack_round_trips(void)
{
    const udsota_status_t want = status_fixture();
    udsota_status_t got;
    memset(&got, 0, sizeof got);
    TEST_ASSERT_TRUE(udsota_unpack_status(STATUS_BYTES, sizeof STATUS_BYTES, &got));
    TEST_ASSERT_EQUAL_UINT8(want.running_slot, got.running_slot);
    TEST_ASSERT_EQUAL_UINT8(want.running_state, got.running_state);
    TEST_ASSERT_EQUAL_UINT8(want.boot_slot, got.boot_slot);
    TEST_ASSERT_EQUAL_UINT8(want.other_slot_state, got.other_slot_state);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want.other_version, got.other_version, 3);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want.other_elf_sha_prefix, got.other_elf_sha_prefix, 8);
    TEST_ASSERT_EQUAL_HEX8(want.flags, got.flags);
    uint8_t again[UDSOTA_STATUS_LEN];
    TEST_ASSERT_EQUAL_UINT(UDSOTA_STATUS_LEN, udsota_pack_status(again, sizeof again, &got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(STATUS_BYTES, again, UDSOTA_STATUS_LEN);
}

/* A short buffer or a NULL pointer returns 0/false and leaves the destination untouched. */
static void test_status_short_or_null_refused(void)
{
    const udsota_status_t s = status_fixture();
    uint8_t out[UDSOTA_STATUS_LEN];
    memset(out, 0xEE, sizeof out);
    TEST_ASSERT_EQUAL_UINT(0, udsota_pack_status(out, UDSOTA_STATUS_LEN - 1, &s));
    TEST_ASSERT_EQUAL_UINT(0, udsota_pack_status(NULL, sizeof out, &s));
    TEST_ASSERT_EQUAL_UINT(0, udsota_pack_status(out, sizeof out, NULL));
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, out, sizeof out);
    udsota_status_t got;
    memset(&got, 0x5A, sizeof got);
    TEST_ASSERT_FALSE(udsota_unpack_status(STATUS_BYTES, UDSOTA_STATUS_LEN - 1, &got));
    TEST_ASSERT_FALSE(udsota_unpack_status(NULL, UDSOTA_STATUS_LEN, &got));
    TEST_ASSERT_EQUAL_HEX8(0x5A, got.running_slot);
    TEST_ASSERT_EQUAL_HEX8(0x5A, got.flags);
}

/* F1F1 is the reason byte then bytes_received as a big-endian u32; the bytes unpack back to the struct. */
static void test_result_round_trip(void)
{
    const udsota_result_t s = {.reason_code = UDSOTA_DL_VERIFY_FAILED, .bytes_received = 0x0014F2A0u};
    const uint8_t want[UDSOTA_RESULT_LEN] = {0x08, 0x00, 0x14, 0xF2, 0xA0};
    uint8_t out[UDSOTA_RESULT_LEN];
    TEST_ASSERT_EQUAL_UINT(UDSOTA_RESULT_LEN, udsota_pack_result(out, sizeof out, &s));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, out, UDSOTA_RESULT_LEN);
    udsota_result_t got = {0};
    TEST_ASSERT_TRUE(udsota_unpack_result(want, sizeof want, &got));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_DL_VERIFY_FAILED, got.reason_code);
    TEST_ASSERT_EQUAL_HEX32(0x0014F2A0u, got.bytes_received);
}

/* F1F1 with a 4-byte buffer packs nothing, and 4 input bytes do not unpack. */
static void test_result_short_refused(void)
{
    const udsota_result_t s = {.reason_code = UDSOTA_DL_OK, .bytes_received = 1};
    uint8_t out[UDSOTA_RESULT_LEN];
    memset(out, 0xEE, sizeof out);
    TEST_ASSERT_EQUAL_UINT(0, udsota_pack_result(out, UDSOTA_RESULT_LEN - 1, &s));
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, out, sizeof out);
    udsota_result_t got = {.reason_code = 0x5A, .bytes_received = 0x5A5A5A5Au};
    TEST_ASSERT_FALSE(udsota_unpack_result(out, UDSOTA_RESULT_LEN - 1, &got));
    TEST_ASSERT_EQUAL_HEX8(0x5A, got.reason_code);
    TEST_ASSERT_EQUAL_HEX32(0x5A5A5A5Au, got.bytes_received);
}

/* F1F2 is eight big-endian u16 counters in declaration order; distinct values catch a swap or reorder. */
static void test_counters_round_trip(void)
{
    const udsota_counters_t s = {
        .seq_errors = 0x0102, .ncr_timeouts = 0x0304, .repeated_blocks = 0x0506, .aborts = 0x0708,
        .withheld_fcs = 0x090A, .stmin_violations = 0x0B0C, .resp_pending_caps = 0x0D0E,
        .resp_frames_dropped = 0x0F10,
    };
    const uint8_t want[UDSOTA_COUNTERS_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };
    uint8_t out[UDSOTA_COUNTERS_LEN];
    TEST_ASSERT_EQUAL_UINT(UDSOTA_COUNTERS_LEN, udsota_pack_counters(out, sizeof out, &s));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, out, UDSOTA_COUNTERS_LEN);
    udsota_counters_t got;
    memset(&got, 0, sizeof got);
    TEST_ASSERT_TRUE(udsota_unpack_counters(want, sizeof want, &got));
    TEST_ASSERT_EQUAL_HEX16(0x0102, got.seq_errors);
    TEST_ASSERT_EQUAL_HEX16(0x0304, got.ncr_timeouts);
    TEST_ASSERT_EQUAL_HEX16(0x0506, got.repeated_blocks);
    TEST_ASSERT_EQUAL_HEX16(0x0708, got.aborts);
    TEST_ASSERT_EQUAL_HEX16(0x090A, got.withheld_fcs);
    TEST_ASSERT_EQUAL_HEX16(0x0B0C, got.stmin_violations);
    TEST_ASSERT_EQUAL_HEX16(0x0D0E, got.resp_pending_caps);
    TEST_ASSERT_EQUAL_HEX16(0x0F10, got.resp_frames_dropped);
}

/* F1F2 with a 15-byte buffer packs nothing, and 15 input bytes do not unpack. */
static void test_counters_short_refused(void)
{
    const udsota_counters_t s = {.seq_errors = 1};
    uint8_t out[UDSOTA_COUNTERS_LEN];
    memset(out, 0xEE, sizeof out);
    TEST_ASSERT_EQUAL_UINT(0, udsota_pack_counters(out, UDSOTA_COUNTERS_LEN - 1, &s));
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEE, out, sizeof out);
    udsota_counters_t got = {.seq_errors = 0x5A5A};
    TEST_ASSERT_FALSE(udsota_unpack_counters(out, UDSOTA_COUNTERS_LEN - 1, &got));
    TEST_ASSERT_EQUAL_HEX16(0x5A5A, got.seq_errors);
}

/* The F1F2 counter increment counts up to 0xFFFF and then holds there. */
static void test_sat_inc16_saturates(void)
{
    uint16_t c = 0xFFFE;
    udsota_sat_inc16(&c);
    TEST_ASSERT_EQUAL_HEX16(0xFFFF, c);
    udsota_sat_inc16(&c);
    TEST_ASSERT_EQUAL_HEX16(0xFFFF, c);
    c = 0;
    udsota_sat_inc16(&c);
    TEST_ASSERT_EQUAL_HEX16(1, c);
}

/* The big-endian helpers put the most significant byte first and read back what they wrote. */
static void test_be_helpers(void)
{
    uint8_t b[4];
    udsota_put_u16be(b, 0xF1F0);
    TEST_ASSERT_EQUAL_HEX8(0xF1, b[0]);
    TEST_ASSERT_EQUAL_HEX8(0xF0, b[1]);
    TEST_ASSERT_EQUAL_HEX16(0xF1F0, udsota_get_u16be(b));
    udsota_put_u32be(b, 0x01020304u);
    const uint8_t w[4] = {0x01, 0x02, 0x03, 0x04};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(w, b, 4);
    TEST_ASSERT_EQUAL_HEX32(0x01020304u, udsota_get_u32be(b));
}

/* SIDs and response framing are the ISO 14229-1 values. */
static void test_sid_values_pinned(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x10, UDSOTA_SID_SESSION);
    TEST_ASSERT_EQUAL_HEX8(0x11, UDSOTA_SID_RESET);
    TEST_ASSERT_EQUAL_HEX8(0x22, UDSOTA_SID_READ_DID);
    TEST_ASSERT_EQUAL_HEX8(0x27, UDSOTA_SID_SECURITY);
    TEST_ASSERT_EQUAL_HEX8(0x2E, UDSOTA_SID_WRITE_DID);
    TEST_ASSERT_EQUAL_HEX8(0x31, UDSOTA_SID_ROUTINE);
    TEST_ASSERT_EQUAL_HEX8(0x34, UDSOTA_SID_REQUEST_DOWNLOAD);
    TEST_ASSERT_EQUAL_HEX8(0x36, UDSOTA_SID_TRANSFER_DATA);
    TEST_ASSERT_EQUAL_HEX8(0x37, UDSOTA_SID_TRANSFER_EXIT);
    TEST_ASSERT_EQUAL_HEX8(0x3E, UDSOTA_SID_TESTER_PRESENT);
    TEST_ASSERT_EQUAL_HEX8(0x40, UDSOTA_POS_BIT);
    TEST_ASSERT_EQUAL_HEX8(0x7F, UDSOTA_NEG_RESPONSE);
    TEST_ASSERT_EQUAL_HEX8(0x80, UDSOTA_SPRMIB);
    TEST_ASSERT_EQUAL_HEX8(0x74, UDSOTA_POS(UDSOTA_SID_REQUEST_DOWNLOAD));
    TEST_ASSERT_EQUAL_HEX8(0x01, UDSOTA_RESET_HARD);
    TEST_ASSERT_EQUAL_HEX8(0x01, UDSOTA_RC_START);
    TEST_ASSERT_EQUAL_HEX8(0x00, UDSOTA_TP_ZERO_SUBFUNC);
}

/* All 19 NRCs match ISO 14229-1 (cross-checked against iso14229 src/uds.h). */
static void test_nrc_values_pinned(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x10, UDSOTA_NRC_GENERAL_REJECT);
    TEST_ASSERT_EQUAL_HEX8(0x11, UDSOTA_NRC_SERVICE_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_HEX8(0x12, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED);
    TEST_ASSERT_EQUAL_HEX8(0x13, UDSOTA_NRC_INCORRECT_LENGTH);
    TEST_ASSERT_EQUAL_HEX8(0x21, UDSOTA_NRC_BUSY_REPEAT);
    TEST_ASSERT_EQUAL_HEX8(0x22, UDSOTA_NRC_CONDITIONS_NOT_CORRECT);
    TEST_ASSERT_EQUAL_HEX8(0x24, UDSOTA_NRC_REQUEST_SEQUENCE_ERROR);
    TEST_ASSERT_EQUAL_HEX8(0x31, UDSOTA_NRC_REQUEST_OUT_OF_RANGE);
    TEST_ASSERT_EQUAL_HEX8(0x33, UDSOTA_NRC_SECURITY_ACCESS_DENIED);
    TEST_ASSERT_EQUAL_HEX8(0x35, UDSOTA_NRC_INVALID_KEY);
    TEST_ASSERT_EQUAL_HEX8(0x36, UDSOTA_NRC_EXCEEDED_ATTEMPTS);
    TEST_ASSERT_EQUAL_HEX8(0x37, UDSOTA_NRC_TIME_DELAY_NOT_EXPIRED);
    TEST_ASSERT_EQUAL_HEX8(0x70, UDSOTA_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED);
    TEST_ASSERT_EQUAL_HEX8(0x71, UDSOTA_NRC_TRANSFER_DATA_SUSPENDED);
    TEST_ASSERT_EQUAL_HEX8(0x72, UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE);
    TEST_ASSERT_EQUAL_HEX8(0x73, UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER);
    TEST_ASSERT_EQUAL_HEX8(0x78, UDSOTA_NRC_RESPONSE_PENDING);
    TEST_ASSERT_EQUAL_HEX8(0x7E, UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION);
    TEST_ASSERT_EQUAL_HEX8(0x7F, UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION);
}

/* Session numbers, seed/key sub-functions, lengths and timing wire values. */
static void test_session_and_security_values_pinned(void)
{
    TEST_ASSERT_EQUAL_INT(1, UDSOTA_SESSION_DEFAULT);
    TEST_ASSERT_EQUAL_INT(2, UDSOTA_SESSION_PROGRAMMING);
    TEST_ASSERT_EQUAL_INT(3, UDSOTA_SESSION_EXTENDED);
    TEST_ASSERT_EQUAL_HEX8(0x01, UDSOTA_SA_SEED_EXTENDED);
    TEST_ASSERT_EQUAL_HEX8(0x02, UDSOTA_SA_KEY_EXTENDED);
    TEST_ASSERT_EQUAL_HEX8(0x03, UDSOTA_SA_SEED_PROGRAMMING);
    TEST_ASSERT_EQUAL_HEX8(0x04, UDSOTA_SA_KEY_PROGRAMMING);
    TEST_ASSERT_EQUAL_UINT(16, UDSOTA_SEED_LEN);
    TEST_ASSERT_EQUAL_UINT(16, UDSOTA_KEY_LEN);
    TEST_ASSERT_EQUAL_UINT(50, UDSOTA_P2_MS);
    TEST_ASSERT_EQUAL_HEX16(0x01F4, UDSOTA_P2STAR_MS / 10u);   /* 10 xx positive: 50 xx 00 32 01 F4 */
    TEST_ASSERT_EQUAL_UINT(5000, UDSOTA_S3_MS);
}

/* DID and RID numbers and the fixed DID lengths. */
static void test_did_rid_values_pinned(void)
{
    TEST_ASSERT_EQUAL_HEX16(0xF186, UDSOTA_DID_ACTIVE_SESSION);
    TEST_ASSERT_EQUAL_HEX16(0xF189, UDSOTA_DID_SW_VERSION);
    TEST_ASSERT_EQUAL_HEX16(0xF18C, UDSOTA_DID_SERIAL);
    TEST_ASSERT_EQUAL_HEX16(0xF1F0, UDSOTA_DID_STATUS);
    TEST_ASSERT_EQUAL_HEX16(0xF1F3, UDSOTA_DID_RUNNING_SHA);
    TEST_ASSERT_EQUAL_HEX16(0xF1F1, UDSOTA_DID_RESULT);
    TEST_ASSERT_EQUAL_HEX16(0xF1F2, UDSOTA_DID_COUNTERS);
    TEST_ASSERT_EQUAL_UINT(6, UDSOTA_SERIAL_LEN);
    TEST_ASSERT_EQUAL_UINT(32, UDSOTA_SHA256_LEN);
    TEST_ASSERT_EQUAL_UINT(16, UDSOTA_STATUS_LEN);
    TEST_ASSERT_EQUAL_UINT(5, UDSOTA_RESULT_LEN);
    TEST_ASSERT_EQUAL_UINT(16, UDSOTA_COUNTERS_LEN);
    TEST_ASSERT_EQUAL_HEX16(0xFF01, UDSOTA_RID_CHECK_PROG_DEPS);
    TEST_ASSERT_EQUAL_HEX16(0xF000, UDSOTA_RID_GET_RESUME_POINT);
    TEST_ASSERT_EQUAL_HEX16(0xF001, UDSOTA_RID_ACTIVATE_IMAGE);
    TEST_ASSERT_EQUAL_HEX16(0xF002, UDSOTA_RID_CONFIRM_IMAGE);
    TEST_ASSERT_EQUAL_HEX8(0xFF, UDSOTA_RESUME_NOT_AVAILABLE);
}

/* The dataFormatIdentifiers and ALFID the client sends, the 34 field widths the server takes, and the RequestDownload
 * constants that give the positive response 74 20 0F FF and 4093 data bytes per 0x36. */
static void test_download_values_pinned(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00, UDSOTA_DL_DFI);
    TEST_ASSERT_EQUAL_HEX8(0x10, UDSOTA_DL_DFI_DEFLATE);
    TEST_ASSERT_EQUAL_HEX8(0x20, UDSOTA_DL_DFI_DELTA);
    TEST_ASSERT_EQUAL_HEX8(0x30, UDSOTA_DL_DFI_DELTA_DEFLATE);
    TEST_ASSERT_EQUAL_HEX8(0x44, UDSOTA_DL_ALFID);
    TEST_ASSERT_EQUAL_UINT(4, UDSOTA_DL_FIELD_MAX);
    TEST_ASSERT_EQUAL_UINT(3, UDSOTA_DL_REQ_MIN);
    TEST_ASSERT_EQUAL_UINT(11, UDSOTA_DL_REQ_LEN);
    TEST_ASSERT_EQUAL_UINT(4095, UDSOTA_DL_MAX_BLOCK_LEN);
    TEST_ASSERT_EQUAL_UINT(4093, UDSOTA_DL_MAX_DATA);
    uint8_t resp[4] = {UDSOTA_POS(UDSOTA_SID_REQUEST_DOWNLOAD), UDSOTA_DL_LFID, 0, 0};
    udsota_put_u16be(&resp[2], UDSOTA_DL_MAX_BLOCK_LEN);
    const uint8_t want[4] = {0x74, 0x20, 0x0F, 0xFF};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, resp, 4);
}

/* Reason codes go on the wire (F1F1, FF01 status), so every value is pinned. */
static void test_reason_codes_pinned(void)
{
    TEST_ASSERT_EQUAL_INT(0, UDSOTA_DL_OK);
    TEST_ASSERT_EQUAL_INT(1, UDSOTA_DL_BAD_HEADER);
    TEST_ASSERT_EQUAL_INT(2, UDSOTA_DL_BAD_PROJECT);
    TEST_ASSERT_EQUAL_INT(3, UDSOTA_DL_BAD_BOARD);
    TEST_ASSERT_EQUAL_INT(4, UDSOTA_DL_BAD_LAYOUT);
    TEST_ASSERT_EQUAL_INT(5, UDSOTA_DL_BAD_DIAG_IDS);
    TEST_ASSERT_EQUAL_INT(6, UDSOTA_DL_NOT_NEWER);
    TEST_ASSERT_EQUAL_INT(7, UDSOTA_DL_TOO_BIG);
    TEST_ASSERT_EQUAL_INT(8, UDSOTA_DL_VERIFY_FAILED);
    TEST_ASSERT_EQUAL_INT(9, UDSOTA_DL_SIG_FAILED);
    TEST_ASSERT_EQUAL_INT(10, UDSOTA_DL_WORKER_TIMEOUT);
    TEST_ASSERT_EQUAL_INT(11, UDSOTA_DL_ABORTED);
    TEST_ASSERT_EQUAL_INT(12, UDSOTA_DL_FLASH_ERROR);
    TEST_ASSERT_EQUAL_INT(13, UDSOTA_DL_BAD_STREAM);
    TEST_ASSERT_EQUAL_INT(14, UDSOTA_DL_NO_MEMORY);
    TEST_ASSERT_EQUAL_INT(15, UDSOTA_DL_BAD_BASE);
}

/* F1F0 slot numbers, state encodings and flag bits are wire values the PC tool decodes. */
static void test_status_encodings_pinned(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00, UDSOTA_SLOT_OTA0);
    TEST_ASSERT_EQUAL_HEX8(0x01, UDSOTA_SLOT_OTA1);
    TEST_ASSERT_EQUAL_HEX8(0xFF, UDSOTA_SLOT_NONE);
    TEST_ASSERT_EQUAL_INT(0, UDSOTA_IMG_UNDEFINED);
    TEST_ASSERT_EQUAL_INT(1, UDSOTA_IMG_NEW);
    TEST_ASSERT_EQUAL_INT(2, UDSOTA_IMG_PENDING_VERIFY);
    TEST_ASSERT_EQUAL_INT(3, UDSOTA_IMG_VALID);
    TEST_ASSERT_EQUAL_INT(4, UDSOTA_IMG_INVALID);
    TEST_ASSERT_EQUAL_INT(5, UDSOTA_IMG_ABORTED);
    TEST_ASSERT_EQUAL_INT(0, UDSOTA_OTHER_EMPTY);
    TEST_ASSERT_EQUAL_INT(1, UDSOTA_OTHER_UNVERIFIED);
    TEST_ASSERT_EQUAL_INT(2, UDSOTA_OTHER_WRITING);
    TEST_ASSERT_EQUAL_INT(3, UDSOTA_OTHER_VERIFIED);
    TEST_ASSERT_EQUAL_INT(4, UDSOTA_OTHER_INVALID);
    TEST_ASSERT_EQUAL_HEX8(0x01, UDSOTA_STATUS_SIG_CHECKED);
    TEST_ASSERT_EQUAL_HEX8(0x02, UDSOTA_STATUS_BOOT_IGNORED_CONFIG);
}

/* Runs every UDS codec and contract-value test. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_status_packs_to_fixed_bytes);
    RUN_TEST(test_status_unpack_round_trips);
    RUN_TEST(test_status_short_or_null_refused);
    RUN_TEST(test_result_round_trip);
    RUN_TEST(test_result_short_refused);
    RUN_TEST(test_counters_round_trip);
    RUN_TEST(test_counters_short_refused);
    RUN_TEST(test_sat_inc16_saturates);
    RUN_TEST(test_be_helpers);
    RUN_TEST(test_sid_values_pinned);
    RUN_TEST(test_nrc_values_pinned);
    RUN_TEST(test_session_and_security_values_pinned);
    RUN_TEST(test_did_rid_values_pinned);
    RUN_TEST(test_download_values_pinned);
    RUN_TEST(test_reason_codes_pinned);
    RUN_TEST(test_status_encodings_pinned);
    return UNITY_END();
}
