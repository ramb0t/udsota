/* Host tests for the file-backed fake OTA engine (fake_engine.c): its SHA-256, erase extent, the
 * esp_ota_end image check, the release flag, activation, rollback of an unconfirmed image, persistence
 * across a "power cut" and the stateless resume scan. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "unity.h"
#include "fake_engine.h"
#include "sha256_host.h"
#include "udsota_image.h"
#include "udsota_image_desc.h"

#define SLOT   0x10000u          /* 64 KB slots keep the test fast */
#define PAYLOAD 12000u           /* three 0x36 blocks' worth */
#define FLAGS_OFS (UDSOTA_IMG_DESC_OFFSET + 12u)   /* udsota_image_desc_t.flags in the image */

static fake_ota_t f;
static uint8_t    img[16384];
static size_t     img_len;

/* Unity hook: fresh slot files and a freshly built v0.3.0 image for every test. */
void setUp(void)
{
    TEST_ASSERT_TRUE(fake_ota_open(&f, FAKE_OTA_TEST_DIR, SLOT, true));
    img_len = fake_ota_build_image(img, sizeof img, "v0.3.0", NULL, PAYLOAD);
    TEST_ASSERT_NOT_EQUAL(0, img_len);
}

/* Unity hook: closes the slot files. */
void tearDown(void)
{
    fake_ota_close(&f);
}

/* Writes img to the inactive slot in 4093-byte chunks, as the server's 0x36 blocks would. */
static void download(const uint8_t *data, size_t len)
{
    TEST_ASSERT_EQUAL_INT(0, fake_ota_begin(&f, (uint32_t)len));
    for (size_t off = 0; off < len; off += 4093u) {
        size_t n = len - off < 4093u ? len - off : 4093u;
        TEST_ASSERT_EQUAL_INT(0, fake_ota_write(&f, &data[off], n));
    }
}

/* Reads one byte of a slot file. */
static uint8_t slot_byte(uint8_t slot, uint32_t off)
{
    uint8_t b = 0;
    TEST_ASSERT_EQUAL_INT(1, (int)pread(f.fd[slot], &b, 1, (off_t)off));
    return b;
}

/* Asserts sha256_host(msg) equals the hex digest want. */
static void assert_sha256(const char *msg, const char *want)
{
    uint8_t d[32];
    char hex[65];
    TEST_ASSERT_TRUE(sha256_host((const uint8_t *)msg, strlen(msg), d));
    for (int i = 0; i < 32; i++) {
        static const char digits[] = "0123456789abcdef";
        hex[2 * i] = digits[d[i] >> 4];
        hex[2 * i + 1] = digits[d[i] & 0x0Fu];
    }
    hex[64] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want, hex, msg);
}

/* The fake's SHA-256 against the FIPS 180-2 vectors: fake_ota_verify_image checks with the same function,
 * so a wrong hash would otherwise pass unnoticed. The 56-byte message pads into a second block. */
static void test_sha256_known_answers(void)
{
    assert_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_sha256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_sha256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    uint8_t d[32];
    TEST_ASSERT_FALSE(sha256_host(NULL, 1, d));
    TEST_ASSERT_TRUE(sha256_host(NULL, 0, d));
}

/* A fresh open runs slot 0 as VALID and boot target, with slot 1 erased and reported EMPTY. */
static void test_fresh_open_runs_slot0(void)
{
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SLOT_OTA0, s.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_VALID, s.running_state);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SLOT_OTA0, s.boot_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_OTHER_EMPTY, s.other_slot_state);
    TEST_ASSERT_EQUAL_UINT8(0, s.flags);
    TEST_ASSERT_EQUAL_HEX8(0xFF, slot_byte(1, 0));
    TEST_ASSERT_EQUAL_HEX8(0xFF, slot_byte(1, SLOT - 1u));
    TEST_ASSERT_EQUAL_UINT8(1, fake_ota_other(&f));
}

/* The built image passes the real first-block check and the fake's esp_ota_end check. */
static void test_built_image_passes_both_checks(void)
{
    const udsota_image_ctx_t ic = {
        .product = FAKE_OTA_PROJECT, .hw_id = 1, .partition_layout_id = FAKE_OTA_LAYOUT_ID,
        .diag_request_id = FAKE_OTA_REQ_ID, .diag_response_id = FAKE_OTA_RESP_ID,
        .running_version = {0, 2, 9}, .running_is_release = false, .slot_size = SLOT,
    };
    bool release = false;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, udsota_image_check(img, UDSOTA_IMAGE_MIN_LEN, (uint32_t)img_len, &ic, &release));
    TEST_ASSERT_TRUE(release);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_verify_image(img, img_len));
    TEST_ASSERT_EQUAL_UINT(0, fake_ota_build_image(img, 100, "v0.3.0", NULL, PAYLOAD));   /* cap too small */
    TEST_ASSERT_EQUAL_UINT(0, fake_ota_build_image(img, sizeof img, "v0.3.0", NULL, 287)); /* no room for descriptors */
}

/* The descriptor's release flag is set exactly for a clean [v]M.m.p, so both kinds pass image_check,
 * and fake_ota_slot_release reads it back from a slot. */
static void test_release_flag_follows_version(void)
{
    static const struct {
        const char *v;
        bool        release;
    } cases[] = {
        {"v0.3.0", true}, {"0.3.0", true}, {"v0.3.0-rc1", false}, {"v0.3.0-4-gabc1234-dirty", false},
        {"v0.3.0+meta", false},
    };
    const udsota_image_ctx_t ic = {
        .product = FAKE_OTA_PROJECT, .hw_id = 1, .partition_layout_id = FAKE_OTA_LAYOUT_ID,
        .diag_request_id = FAKE_OTA_REQ_ID, .diag_response_id = FAKE_OTA_RESP_ID,
        .running_version = {0, 2, 9}, .running_is_release = false, .slot_size = SLOT,
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        img_len = fake_ota_build_image(img, sizeof img, cases[i].v, NULL, PAYLOAD);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, img_len, cases[i].v);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(cases[i].release ? UDSOTA_IMG_FLAG_RELEASE : 0u, img[FLAGS_OFS], cases[i].v);
        bool release = !cases[i].release;
        TEST_ASSERT_EQUAL_INT_MESSAGE(UDSOTA_DL_OK, udsota_image_check(img, UDSOTA_IMAGE_MIN_LEN, (uint32_t)img_len,
                                                                     &ic, &release), cases[i].v);
        TEST_ASSERT_EQUAL_MESSAGE(cases[i].release, release, cases[i].v);
        TEST_ASSERT_EQUAL_INT(0, fake_ota_load_slot(&f, 1, img, img_len));
        TEST_ASSERT_EQUAL_MESSAGE(cases[i].release, fake_ota_slot_release(&f, 1), cases[i].v);
    }
    TEST_ASSERT_FALSE(fake_ota_slot_release(&f, 0));   /* erased slot: no descriptor */
}

/* One flipped payload byte, a missing last byte, or hash_appended 0 each fail the end check. */
static void test_verify_rejects_corruption(void)
{
    img[5000] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_VERIFY_FAILED, fake_ota_verify_image(img, img_len));
    img[5000] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_VERIFY_FAILED, fake_ota_verify_image(img, img_len - 1u));
    img[23] = 0;
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_VERIFY_FAILED, fake_ota_verify_image(img, img_len));
}

/* esp_ota_begin erases exactly ALIGN_UP(size, 4096) and leaves the rest of the slot alone. */
static void test_begin_erases_extent_only(void)
{
    static uint8_t zeros[3u * FAKE_OTA_SECTOR];
    TEST_ASSERT_EQUAL_INT(0, fake_ota_load_slot(&f, 1, zeros, sizeof zeros));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_begin(&f, 5000));
    TEST_ASSERT_EQUAL_HEX8(0xFF, slot_byte(1, 0));
    TEST_ASSERT_EQUAL_HEX8(0xFF, slot_byte(1, 2u * FAKE_OTA_SECTOR - 1u));
    TEST_ASSERT_EQUAL_HEX8(0x00, slot_byte(1, 2u * FAKE_OTA_SECTOR));
}

/* begin refuses size 0 and oversize; write refuses before begin, a first byte other than 0xE9, and overrun. */
static void test_begin_and_write_refusals(void)
{
    const uint8_t bad[4] = {0x00, 1, 2, 3};
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_begin(&f, 0));
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_begin(&f, SLOT + 1u));
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_write(&f, img, 16));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_begin(&f, SLOT));
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_write(&f, bad, sizeof bad));
    static uint8_t big[SLOT + 1u];
    big[0] = 0xE9;
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_write(&f, big, sizeof big));
}

/* The full install: verify, activate, boot into PENDING_VERIFY, confirm, and stay on the new slot. */
static void test_install_confirm_stays(void)
{
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_OTHER_VERIFIED, s.other_slot_state);
    const uint8_t v030[3] = {0, 3, 0};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(v030, s.other_version, 3);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&img[FAKE_OTA_ELF_SHA_OFS], s.other_elf_sha_prefix, 8);

    TEST_ASSERT_EQUAL_INT(0, fake_ota_activate(&f));
    TEST_ASSERT_EQUAL_UINT8(1, f.boot_slot);
    TEST_ASSERT_EQUAL_UINT8(0, f.running_slot);        /* still the old image until the reset */
    fake_ota_boot(&f);
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_PENDING_VERIFY, f.state[1]);
    char ver[33];
    uint8_t sha[32];
    TEST_ASSERT_TRUE(fake_ota_slot_desc(&f, f.running_slot, ver, sha));
    TEST_ASSERT_EQUAL_STRING("v0.3.0", ver);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&img[FAKE_OTA_ELF_SHA_OFS], sha, 32);

    TEST_ASSERT_EQUAL_INT(0, fake_ota_confirm(&f));
    fake_ota_boot(&f);
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_VALID, f.state[1]);
}

/* ota_unverify drops a pass: F1F0 stops reporting VERIFIED and activation is refused. */
static void test_unverify_clears_verified(void)
{
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    fake_ota_unverify(&f);
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_OTHER_UNVERIFIED, s.other_slot_state);
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_activate(&f));
}

/* An activated image that resets before ConfirmImage rolls back: old slot runs, new one reads INVALID. */
static void test_unconfirmed_image_rolls_back(void)
{
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_activate(&f));
    fake_ota_boot(&f);                                  /* first boot of the new image */
    fake_ota_boot(&f);                                  /* panic / power cut before ConfirmImage */
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SLOT_OTA0, s.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_VALID, s.running_state);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_SLOT_OTA0, s.boot_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_OTHER_INVALID, s.other_slot_state);
}

/* Activation needs a pass since the last boot: refused after a failed check, an abort, or a reboot. */
static void test_activate_needs_fresh_verify(void)
{
    img[5000] ^= 0x01;
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_VERIFY_FAILED, fake_ota_end(&f));
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_activate(&f));
    img[5000] ^= 0x01;
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(0, fake_ota_abort(&f));
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_activate(&f));
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    fake_ota_boot(&f);                                  /* a reboot clears "verified" */
    TEST_ASSERT_NOT_EQUAL(0, fake_ota_activate(&f));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_abort(&f));       /* nothing open: still a no-op success */
}

/* An aborted download keeps its bytes; the resume scan returns the sector before the first blank one. */
static void test_abort_keeps_partial_and_resume_point(void)
{
    TEST_ASSERT_EQUAL_UINT32(0, fake_ota_resume_point(&f));   /* erased slot */
    TEST_ASSERT_EQUAL_INT(0, fake_ota_begin(&f, (uint32_t)img_len));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_write(&f, img, 3u * FAKE_OTA_SECTOR + 100u));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_abort(&f));
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_OTHER_UNVERIFIED, s.other_slot_state);
    TEST_ASSERT_EQUAL_HEX8(img[100], slot_byte(1, 100));
    TEST_ASSERT_EQUAL_UINT32(3u * FAKE_OTA_SECTOR, fake_ota_resume_point(&f));
}

/* otadata survives a close/reopen (a power cut): the activated image boots, and a second cut rolls it back. */
static void test_state_survives_power_cut(void)
{
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_activate(&f));
    fake_ota_close(&f);
    TEST_ASSERT_TRUE(fake_ota_open(&f, FAKE_OTA_TEST_DIR, SLOT, false));
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_PENDING_VERIFY, f.state[1]);
    fake_ota_close(&f);
    TEST_ASSERT_TRUE(fake_ota_open(&f, FAKE_OTA_TEST_DIR, SLOT, false));
    TEST_ASSERT_EQUAL_UINT8(0, f.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_ABORTED, f.state[1]);
}

/* Rollback off (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE unset): activate writes UNDEFINED, as IDF's
 * set_new_state_otadata() does, the image runs from the next boot and stays over further boots and a
 * power cut without a confirm, and confirm is a no-op that returns 0. */
static void test_rollback_off_activate_is_permanent(void)
{
    f.no_rollback = true;
    download(img, img_len);
    TEST_ASSERT_EQUAL_INT(UDSOTA_DL_OK, fake_ota_end(&f));
    TEST_ASSERT_EQUAL_INT(0, fake_ota_activate(&f));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_UNDEFINED, f.state[1]);
    TEST_ASSERT_EQUAL_UINT8(1, f.boot_slot);
    fake_ota_boot(&f);
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_UNDEFINED, f.state[1]);
    udsota_status_t s;
    fake_ota_fill_status(&f, &s);                         /* never PENDING_VERIFY: the core's confirm is then a no-op */
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_UNDEFINED, s.running_state);
    TEST_ASSERT_EQUAL_UINT8(1, s.boot_slot);
    fake_ota_boot(&f);                                  /* with rollback on, this boot would roll back */
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
    TEST_ASSERT_EQUAL_INT(0, fake_ota_confirm(&f));
    TEST_ASSERT_EQUAL_UINT8(UDSOTA_IMG_UNDEFINED, f.state[1]);   /* confirm changed nothing */
    fake_ota_close(&f);                                 /* power cut: only otadata survives */
    TEST_ASSERT_TRUE(fake_ota_open(&f, FAKE_OTA_TEST_DIR, SLOT, false));
    TEST_ASSERT_EQUAL_UINT8(1, f.boot_slot);
    TEST_ASSERT_EQUAL_UINT8(1, f.running_slot);
}

/* Runs every fake OTA test. */
/* A slot's bytes read back as loaded, a read past the slot refused; the slot's hash is the SHA-256 its image stores,
 * not recomputed, and an erased slot has none (a delta download's base, as the demo server reads it). */
static void test_slot_read_and_hash(void)
{
    TEST_ASSERT_EQUAL_INT(0, fake_ota_load_slot(&f, 1, img, img_len));
    uint8_t back[64];
    TEST_ASSERT_EQUAL_INT(0, fake_ota_slot_read(&f, 1, 100, back, sizeof back));
    TEST_ASSERT_EQUAL_MEMORY(&img[100], back, sizeof back);
    TEST_ASSERT_EQUAL_INT(0, fake_ota_slot_read(&f, 1, SLOT - 1u, back, 1));
    TEST_ASSERT_EQUAL_INT(-1, fake_ota_slot_read(&f, 1, SLOT - 1u, back, 2));
    TEST_ASSERT_EQUAL_INT(-1, fake_ota_slot_read(&f, 2, 0, back, 1));
    uint8_t h[32];
    TEST_ASSERT_TRUE(fake_ota_slot_hash(&f, 1, h));
    TEST_ASSERT_EQUAL_MEMORY(&img[img_len - 32u], h, sizeof h);
    img[img_len - 1u] ^= 0x01;                                  /* a stored hash that no longer matches */
    TEST_ASSERT_EQUAL_INT(0, fake_ota_load_slot(&f, 1, img, img_len));
    TEST_ASSERT_TRUE(fake_ota_slot_hash(&f, 1, h));
    TEST_ASSERT_EQUAL_MEMORY(&img[img_len - 32u], h, sizeof h);
    TEST_ASSERT_FALSE(fake_ota_slot_hash(&f, 0, h));            /* slot 0 is erased */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_known_answers);
    RUN_TEST(test_fresh_open_runs_slot0);
    RUN_TEST(test_built_image_passes_both_checks);
    RUN_TEST(test_release_flag_follows_version);
    RUN_TEST(test_verify_rejects_corruption);
    RUN_TEST(test_begin_erases_extent_only);
    RUN_TEST(test_begin_and_write_refusals);
    RUN_TEST(test_install_confirm_stays);
    RUN_TEST(test_unverify_clears_verified);
    RUN_TEST(test_unconfirmed_image_rolls_back);
    RUN_TEST(test_rollback_off_activate_is_permanent);
    RUN_TEST(test_slot_read_and_hash);
    RUN_TEST(test_activate_needs_fresh_verify);
    RUN_TEST(test_abort_keeps_partial_and_resume_point);
    RUN_TEST(test_state_survives_power_cut);
    return UNITY_END();
}
