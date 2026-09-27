/* image_check: runs the ESP32 port's first-block check on a built image, on the host, so CI can prove a
 * real ESP-IDF build still carries a header and descriptor that udsota accepts.
 *
 *   image_check <image.bin> <chip_id> [product hw_id layout req_id resp_id slot_size]
 *
 * chip_id is ESP-IDF's esp_chip_id_t (esp32 0x0000, esp32s3 0x0009). The optional arguments default to
 * examples/esp32's values: example 1 1 0x710 0x718 0x1E0000. Exits 0 when the image is accepted, else the
 * udsota_reason_t it was refused with (2 when the file cannot be read). */
#include <stdio.h>
#include <stdlib.h>

#include "udsota_esp32_image.h"

/* Parses argv[i] as a number (decimal or 0x hex), or returns def when the argument is absent. */
static unsigned long arg_num(int argc, char **argv, int i, unsigned long def)
{
    return i < argc ? strtoul(argv[i], NULL, 0) : def;
}

/* Reads the image's first block and size, runs the check against the given context and reports it. */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <image.bin> <chip_id> [product hw_id layout req_id resp_id slot_size]\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    uint8_t block[UDSOTA_IMAGE_MIN_LEN];
    if (f == NULL || fread(block, 1, sizeof block, f) != sizeof block || fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "image_check: cannot read the first %u bytes of %s\n", (unsigned)sizeof block, argv[1]);
        return 2;
    }
    long size = ftell(f);
    fclose(f);

    udsota_image_ctx_t ctx = {
        .product = argc > 3 ? argv[3] : "example",
        .hw_id = (uint8_t)arg_num(argc, argv, 4, 1),
        .partition_layout_id = (uint8_t)arg_num(argc, argv, 5, 1),
        .diag_request_id = (uint16_t)arg_num(argc, argv, 6, 0x710),
        .diag_response_id = (uint16_t)arg_num(argc, argv, 7, 0x718),
        .slot_size = (uint32_t)arg_num(argc, argv, 8, 0x1E0000),
    };
    bool release = false;
    udsota_reason_t r = udsota_esp32_image_check(block, sizeof block, (uint32_t)size,
                                                 (uint16_t)strtoul(argv[2], NULL, 0), &ctx, &release);
    printf("%s: %ld bytes, reason %d (%s), %s image\n", argv[1], size, (int)r, r == 0 ? "accepted" : "refused",
           release ? "release" : "dev");
    return (int)r;
}
