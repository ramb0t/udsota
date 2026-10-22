/* image_check: udsota's own image rules (check_first in udsota.c) run on a built image, on the host, so CI proves a
 * real ESP-IDF build carries a header and descriptor that a unit of that board accepts.
 *
 *   image_check <image.bin> <product>
 *
 * One executable per chip and board (CMakeLists.txt's udsota_image_check): CHIP_ID is ESP-IDF's esp_chip_id_t
 * (esp32 0, esp32s3 9), IMAGE_CHECK_HW, _LAYOUT, _REQ and _RESP make the descriptor a unit's running image carries,
 * and IMAGE_CHECK_SLOT is its slot size. The product goes through udsota_init's cfg, and the running version is
 * 0.0.0, a dev build, so any parseable version is newer. esp_ota_check_image_validity's chip revision and flash mode
 * rules are the device's and are not run. Exits 0 when the image is accepted, else the udsota_reason_t it was refused
 * with, or 100 on a usage error, an unreadable image or a failed udsota_init. */
#include <stdio.h>
#include <string.h>
#include "udsota.h"

UDSOTA_IMAGE_DESC(IMAGE_CHECK_HW, IMAGE_CHECK_LAYOUT, IMAGE_CHECK_REQ, IMAGE_CHECK_RESP);
udsota_reason_t udsota_test_check_first(const uint8_t *b, size_t len, uint32_t size);

#define FIRST 320u                 /* the bytes check_first reads */

uint32_t UDSMillis(void)
{
    return 0;
}

/* A unit that runs a dev build at 0.0.0 with an empty inactive slot whose writes fail. Only init and the image rules
 * call into it: nothing downloads. */
int udsota_plat_start(void) { return 0; }
int udsota_plat_run(int (*job)(void)) { (void)job; return -1; }
int udsota_plat_poll(void) { return -1; }
void udsota_plat_abort(void) {}
bool udsota_plat_compatible(const uint8_t *first, size_t len) { (void)first; (void)len; return true; }
int udsota_plat_begin(uint32_t size) { (void)size; return UDSOTA_DL_FLASH_ERROR; }
int udsota_plat_write(const uint8_t *d, size_t n) { (void)d; (void)n; return UDSOTA_DL_FLASH_ERROR; }
int udsota_plat_end(void) { return UDSOTA_DL_ABORTED; }
int udsota_plat_activate(void) { return UDSOTA_DL_ABORTED; }
int udsota_plat_confirm(void) { return 0; }
void udsota_plat_unverify(void) {}
void udsota_plat_status(udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->other_slot_state = UDSOTA_OTHER_EMPTY;
}
uint32_t udsota_plat_slot_size(void) { return IMAGE_CHECK_SLOT; }
const char *udsota_plat_version(void) { return "0.0.0-image-check"; }
const char *udsota_plat_project(void) { return "image-check"; }
const uint8_t *udsota_plat_sha(void)
{
    static const uint8_t sha[32];
    return sha;
}
size_t udsota_plat_mac(uint8_t out[16])
{
    memset(out, 0, 6);
    return 6;
}
bool udsota_plat_rng16(uint8_t out[16])
{
    memset(out, 0, 16);
    return false;
}
bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    (void)key;
    (void)key_len;
    (void)msg;
    (void)msg_len;
    memset(out, 0, 32);
    return false;
}
int udsota_plat_ecdsa_key(const uint8_t *pubkey) { (void)pubkey; return -1; }
int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[64])
{
    (void)msg;
    (void)n;
    (void)sig;
    return -1;
}

/* Reads the image's first bytes and size, starts udsota as that unit and runs the image rules on them. */
int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <image.bin> <product>\n", argv[0]);
        return 100;
    }
    FILE *f = fopen(argv[1], "rb");
    uint8_t first[FIRST];
    long size = -1;
    if (f != NULL && fread(first, 1, sizeof first, f) == sizeof first && fseek(f, 0, SEEK_END) == 0) {
        size = ftell(f);
    }
    if (f != NULL) {
        fclose(f);
    }
    if (size < (long)sizeof first || (unsigned long)size > UINT32_MAX) {
        fprintf(stderr, "image_check: cannot read the first %u bytes of %s\n", FIRST, argv[1]);
        return 100;
    }
    if (udsota_init(&(udsota_cfg_t){.product = argv[2]}) != 0) {
        fprintf(stderr, "image_check: udsota_init failed\n");
        return 100;
    }
    const udsota_reason_t r = udsota_test_check_first(first, sizeof first, (uint32_t)size);
    printf("%s: %ld bytes, project %.32s, version %.32s, for chip %u hw %u layout %u 0x%03X/0x%03X: reason %d (%s)\n",
           argv[1], size, (const char *)&first[32 + 48], (const char *)&first[32 + 16], (unsigned)CHIP_ID,
           (unsigned)IMAGE_CHECK_HW, (unsigned)IMAGE_CHECK_LAYOUT, (unsigned)IMAGE_CHECK_REQ,
           (unsigned)IMAGE_CHECK_RESP, (int)r, r == UDSOTA_DL_OK ? "accepted" : "refused");
    return (int)r;
}
