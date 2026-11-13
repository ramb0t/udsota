/* Unit test of the bootloader core's pure parts (boot/udsota_boot.c): udsota_boot_crc32 against known answers, a
 * bit-by-bit CRC and chained pieces; the image rules case by case, one per reason and in their order; the boot rules
 * as a table over the reset cause, the handover words, the start count and the app's validity; the keep words'
 * encodings; and the image tools/make_boot_fixtures.py stamped with the client's own stamp(), which the CRC and the
 * image rules must accept as it is and the CRC refuse with any byte changed, and whose fixed header fields
 * UDSOTA_IMAGE_HEADER must lay out byte for byte. Every image-rules case reads its header from a heap block of
 * exactly hdr_len bytes, so ASan stops a read past it. */
#define UDSOTA_IMG_RELEASE 1   /* the fixture's version is a release: its descriptor carries flag 0x01 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "udsota_boot_internal.h"
#include "udsota_image.h"
#include "fixtures/boot_fixtures.h"

static int g_failures;
#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                   \
            g_failures++;                                                                                \
        }                                                                                                \
    } while (0)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* udsota's example identity, the fixture's, with a 0x20000 slot and the header at 0x100. */
static const udsota_boot_cfg_t k_cfg = {
    .request_id = BOOT_IMAGE_REQ_ID, .response_id = BOOT_IMAGE_RESP_ID, .product = BOOT_IMAGE_PRODUCT,
    .hw_id = BOOT_IMAGE_HW_ID, .layout_id = BOOT_IMAGE_LAYOUT_ID, .boot_version = "1.0.0", .buses = 2,
    .slot_size = 0x20000u, .slot_write_unit = 2u, .image_header_offset = BOOT_IMAGE_HEADER_OFFSET,
    .window_ms = 100u, .hold_after_starts = 5u, .watchdog_ms = 1000u,
};

/* ---- CRC-32 ---- */

/* zlib's CRC-32 a bit at a time, the reference for the table. */
static uint32_t crc_bitwise(uint32_t crc, const uint8_t *p, size_t n)
{
    crc = ~crc;
    while (n-- > 0u) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return ~crc;
}

static void crc_cases(void)
{
    static const char check[] = "123456789", fox[] = "The quick brown fox jumps over the lazy dog";
    uint8_t zeros[32] = {0}, ones[32];
    memset(ones, 0xFF, sizeof ones);
    CHECK(udsota_boot_crc32(0u, "", 0u) == 0u);
    CHECK(udsota_boot_crc32(0u, "a", 1u) == 0xE8B7BE43u);
    CHECK(udsota_boot_crc32(0u, check, 9u) == 0xCBF43926u);   /* the standard check value */
    CHECK(udsota_boot_crc32(0u, fox, (uint32_t)strlen(fox)) == 0x414FA339u);
    CHECK(udsota_boot_crc32(0u, zeros, sizeof zeros) == 0x190A55ADu);
    CHECK(udsota_boot_crc32(0u, ones, sizeof ones) == 0xFF6CAB0Bu);

    /* Chained from 0 over consecutive pieces, split at every point, and a piece of 0 bytes changes nothing. */
    for (uint32_t at = 0; at <= 9u; at++) {
        CHECK(udsota_boot_crc32(udsota_boot_crc32(0u, check, at), check + at, 9u - at) == 0xCBF43926u);
    }
    CHECK(udsota_boot_crc32(0xCBF43926u, check, 0u) == 0xCBF43926u);
    const uint32_t three = udsota_boot_crc32(udsota_boot_crc32(udsota_boot_crc32(0u, fox, 10u), fox + 10, 1u),
                                             fox + 11, (uint32_t)strlen(fox) - 11u);
    CHECK(three == 0x414FA339u);

    /* The table against the bitwise reference, every length to 1024 and chained from a nonzero start. */
    static uint8_t buf[1024];
    for (size_t i = 0; i < sizeof buf; i++) {
        buf[i] = (uint8_t)(i * 131u + (i >> 3));
    }
    int mismatches = 0;
    for (uint32_t n = 0; n <= sizeof buf; n++) {
        mismatches += udsota_boot_crc32(0u, buf, n) != crc_bitwise(0u, buf, n);
        mismatches += udsota_boot_crc32(0x12345678u, buf, n) != crc_bitwise(0x12345678u, buf, n);
    }
    CHECK(mismatches == 0);
}

/* ---- The image rules, case by case ----
 * Each case runs the rules on the fixture's header with the case's changes, against k_cfg (or another product), with
 * memorySize the fixture's size unless the case sets it. */
#define POKE(...) .poke = {__VA_ARGS__}, .pokes = (int)(sizeof((struct poke_s[]){__VA_ARGS__}) / sizeof(struct poke_s))
#define PROJECT   (UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_PROJECT_OFFSET)   /* the project field in the header */
#define VERSION   (UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_VERSION_OFFSET)
#define DESC      UDSOTA_BARE_HDR_DESC_OFFSET
#define FULL32    "abcdefghijklmnopqrstuvwxyz012345"   /* a project name that fills its 32-byte field */
struct poke_s {
    uint16_t at;
    uint8_t  val;
};
typedef struct {
    const char     *name;
    struct poke_s   poke[3];        /* header bytes set first */
    int             pokes;
    bool            set_length;     /* image_length = length, then */
    uint32_t        length;
    const char     *project;        /* the header's project field, NUL-padded; NULL = the fixture's */
    const char     *product;        /* cfg.product; NULL = the fixture's */
    uint32_t        hdr_len;        /* bytes the rules get; 0 = UDSOTA_BARE_HDR_LEN */
    uint32_t        mem;            /* the 34's memorySize; 0 = the fixture's size, or length when set_length */
    udsota_reason_t want;
} rule_case_t;

static const rule_case_t k_rules[] = {
    {"accepted", .want = UDSOTA_DL_OK},
    {"accepted: a first 36 that carries more than the header", .hdr_len = 300u, .want = UDSOTA_DL_OK},
    {"BAD_HEADER: no header bytes", .hdr_len = 1u, .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: a byte short of the header", .hdr_len = UDSOTA_BARE_HDR_LEN - 1u, .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: magic", POKE({0, 0x43}), .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: magic's top byte", POKE({3, 0x56}), .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: the descriptor's magic in its place", POKE({0, 0x4F}), .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: header_version 0", POKE({4, 0}), .want = UDSOTA_DL_BAD_HEADER},
    {"accepted: header_version 2", POKE({4, 2}), .want = UDSOTA_DL_OK},
    {"accepted: header_version 0x0100", POKE({4, 0}, {5, 1}), .want = UDSOTA_DL_OK},
    {"accepted: a low-byte flag", POKE({6, 0x01}), .want = UDSOTA_DL_OK},
    {"accepted: every low-byte flag", POKE({6, 0xFF}), .want = UDSOTA_DL_OK},
    {"BAD_HEADER: a high-byte flag", POKE({7, 0x01}), .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: the top flag", POKE({7, 0x80}), .want = UDSOTA_DL_BAD_HEADER},
    {"TOO_BIG: image_length past the slot", .set_length = true, .length = 0x20004u, .want = UDSOTA_DL_TOO_BIG},
    {"TOO_BIG: before memorySize", .set_length = true, .length = 0x20004u, .mem = 0x1000u,
     .want = UDSOTA_DL_TOO_BIG},
    {"accepted: image_length the slot", .set_length = true, .length = 0x20000u, .want = UDSOTA_DL_OK},
    {"BAD_HEADER: image_length other than memorySize", .mem = BOOT_IMAGE_SIZE + 4u, .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: image_length not a multiple of 4", .set_length = true, .length = 2050u,
     .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: image_length ends before the header", .set_length = true,
     .length = BOOT_IMAGE_HEADER_OFFSET + UDSOTA_BARE_HDR_LEN - 4u, .want = UDSOTA_DL_BAD_HEADER},
    {"BAD_HEADER: image_length 0", .set_length = true, .length = 0u, .want = UDSOTA_DL_BAD_HEADER},
    {"accepted: image_length ends with the header", .set_length = true,
     .length = BOOT_IMAGE_HEADER_OFFSET + UDSOTA_BARE_HDR_LEN, .want = UDSOTA_DL_OK},
    {"BAD_PROJECT: one letter", .project = "exampld", .want = UDSOTA_DL_BAD_PROJECT},
    {"BAD_PROJECT: longer", .project = "example2", .want = UDSOTA_DL_BAD_PROJECT},
    {"BAD_PROJECT: shorter", .project = "exampl", .want = UDSOTA_DL_BAD_PROJECT},
    {"BAD_PROJECT: another cfg.product", .product = "widget", .want = UDSOTA_DL_BAD_PROJECT},
    {"accepted: another cfg.product and project", .product = "widget", .project = "widget", .want = UDSOTA_DL_OK},
    {"accepted: a project that fills its field", .product = FULL32, .project = FULL32, .want = UDSOTA_DL_OK},
    {"BAD_PROJECT: a product longer than the field", .product = FULL32 "6", .project = FULL32,
     .want = UDSOTA_DL_BAD_PROJECT},
    {"BAD_BOARD: descriptor magic", POKE({DESC + 0, 0x4E}), .want = UDSOTA_DL_BAD_BOARD},
    {"BAD_BOARD: descriptor magic's top byte", POKE({DESC + 3, 0x56}), .want = UDSOTA_DL_BAD_BOARD},
    {"BAD_BOARD: desc_version 0", POKE({DESC + 4, 0}), .want = UDSOTA_DL_BAD_BOARD},
    {"accepted: desc_version 2", POKE({DESC + 4, 2}), .want = UDSOTA_DL_OK},
    {"accepted: desc_version 0x0100", POKE({DESC + 4, 0}, {DESC + 5, 1}), .want = UDSOTA_DL_OK},
    {"BAD_BOARD: hw_id", POKE({DESC + 6, 2}), .want = UDSOTA_DL_BAD_BOARD},
    {"BAD_LAYOUT: partition_layout_id", POKE({DESC + 7, 2}), .want = UDSOTA_DL_BAD_LAYOUT},
    {"BAD_DIAG_IDS: request", POKE({DESC + 8, 0x11}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"BAD_DIAG_IDS: request's high byte", POKE({DESC + 9, 0x06}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"BAD_DIAG_IDS: response", POKE({DESC + 10, 0x19}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"BAD_DIAG_IDS: response's high byte", POKE({DESC + 11, 0x08}), .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"BAD_DIAG_IDS: request and response swapped", POKE({DESC + 8, 0x18}, {DESC + 10, 0x10}),
     .want = UDSOTA_DL_BAD_DIAG_IDS},
    {"accepted: no release flag (no release rule)", POKE({DESC + 12, 0x00}), .want = UDSOTA_DL_OK},
    {"accepted: any descriptor flag", POKE({DESC + 12, 0xFF}), .want = UDSOTA_DL_OK},
    {"accepted: a version that does not parse (no version rule)", POKE({VERSION, 'x'}, {VERSION + 1, 0}),
     .want = UDSOTA_DL_OK},
    {"accepted: reserved bytes and the signature unread", POKE({16, 0x00}, {31, 0x12}, {223, 0x00}),
     .want = UDSOTA_DL_OK},
    {"accepted: the descriptor's reserved bytes unread", POKE({DESC + 13, 0x55}, {DESC + 31, 0xAA}),
     .want = UDSOTA_DL_OK},
    {"accepted: the stamped fields but image_length unread", POKE({12, 0x00}, {128, 0x00}, {159, 0x00}),
     .want = UDSOTA_DL_OK},
    {"first failure wins: header before project", POKE({0, 0x43}), .project = "other", .want = UDSOTA_DL_BAD_HEADER},
    {"first failure wins: size before project", .set_length = true, .length = 0x20004u, .project = "other",
     .want = UDSOTA_DL_TOO_BIG},
    {"first failure wins: length before project", .mem = 0x1000u, .project = "other", .want = UDSOTA_DL_BAD_HEADER},
    {"first failure wins: project before board", POKE({DESC + 6, 2}), .project = "other",
     .want = UDSOTA_DL_BAD_PROJECT},
    {"first failure wins: board before layout", POKE({DESC + 6, 2}, {DESC + 7, 2}), .want = UDSOTA_DL_BAD_BOARD},
    {"first failure wins: layout before IDs", POKE({DESC + 7, 2}, {DESC + 8, 0x11}), .want = UDSOTA_DL_BAD_LAYOUT},
};

static void image_rules_cases(void)
{
    const uint8_t *fixture = BOOT_IMAGE + BOOT_IMAGE_HEADER_OFFSET;
    for (size_t i = 0; i < sizeof k_rules / sizeof k_rules[0]; i++) {
        const rule_case_t *c = &k_rules[i];
        uint8_t h[300];
        memcpy(h, fixture, sizeof h);
        for (int k = 0; k < c->pokes; k++) {
            h[c->poke[k].at] = c->poke[k].val;
        }
        if (c->set_length) {
            put32(h + UDSOTA_BARE_HDR_LENGTH_OFFSET, c->length);
        }
        if (c->project != NULL) {
            memset(h + PROJECT, 0, 32);
            memcpy(h + PROJECT, c->project, strlen(c->project) < 32u ? strlen(c->project) : 32u);
        }
        udsota_boot_cfg_t cfg = k_cfg;
        if (c->product != NULL) {
            cfg.product = c->product;
        }
        const uint32_t n = (c->hdr_len != 0u) ? c->hdr_len : UDSOTA_BARE_HDR_LEN;
        uint8_t *exact = malloc(n);
        memcpy(exact, h, n);
        const uint32_t mem = (c->mem != 0u) ? c->mem : c->set_length ? c->length : BOOT_IMAGE_SIZE;
        const udsota_reason_t got = udsota_boot_image_rules(&cfg, exact, n, mem);
        free(exact);
        if (got != c->want) {
            fprintf(stderr, "%s:%d: image rules, %s: reason %d, want %d\n", __FILE__, __LINE__, c->name, (int)got,
                    (int)c->want);
            g_failures++;
        }
    }
    CHECK(udsota_boot_image_rules(&k_cfg, NULL, 0u, BOOT_IMAGE_SIZE) == UDSOTA_DL_BAD_HEADER);
}

/* ---- The keep words' encodings ---- */

static void encoding_cases(void)
{
    CHECK(UDSOTA_HANDOVER_MARK == 0xB007u && UDSOTA_BARE_HDR_FLAGS_MUST == 0xFF00u);
    CHECK(UDSOTA_START_COUNT_WORD(0) == 0xA500u && UDSOTA_START_COUNT_WORD(3) == 0xA503u);
    CHECK(UDSOTA_START_COUNT_WORD(255) == 0xA5FFu && UDSOTA_START_COUNT_WORD(256) == 0xA500u);
    CHECK(UDSOTA_START_COUNT_CLEAR == 0xA500u);
    CHECK(UDSOTA_KEEP_WORD_MARK == 0u && UDSOTA_KEEP_WORD_HANDOVER == 1u && UDSOTA_KEEP_WORD_COUNT == 2u &&
          UDSOTA_KEEP_WORDS == 3u);
}

/* ---- The boot rules, as a table ----
 * k_cfg's rules (two buses, hold after 5 starts, a 100 ms window) unless a case changes hold or window. */
#define HO(word)      .handover_ok = true, .handover = (word)
#define COUNT(n)      UDSOTA_START_COUNT_WORD(n)
#define POWER_ON      UDSOTA_BOOT_RESET_POWER_ON
#define PIN           UDSOTA_BOOT_RESET_PIN
#define OTHER         UDSOTA_BOOT_RESET_OTHER
typedef struct {
    const char            *name;
    bool                   handover_ok;
    uint16_t               handover;
    uint16_t               count_word;
    udsota_boot_reset_t    cause;
    bool                   invalid;      /* no valid app */
    bool                   set_hold;     /* cfg.hold_after_starts = hold */
    uint8_t                hold;
    bool                   no_window;    /* cfg.window_ms = 0 */
    udsota_boot_decision_t want;
    uint8_t                want_count;
} decide_case_t;

static const decide_case_t k_decide[] = {
    /* Reset causes, with a valid app and no handover. */
    {"power-on opens the window", .count_word = COUNT(0), .cause = POWER_ON, .want = UDSOTA_BOOT_DECIDE_WINDOW},
    {"power-on clears the count", .count_word = COUNT(7), .cause = POWER_ON, .want = UDSOTA_BOOT_DECIDE_WINDOW},
    {"power-on, window off", .count_word = COUNT(2), .cause = POWER_ON, .no_window = true,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"pin reset clears the count, opens no window", .count_word = COUNT(7), .cause = PIN,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"other reset keeps the count", .count_word = COUNT(2), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP,
     .want_count = 2},
    /* The start count against the threshold. */
    {"count below the threshold", .count_word = COUNT(4), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP,
     .want_count = 4},
    {"count at the threshold holds", .count_word = COUNT(5), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HELD,
     .want_count = 5},
    {"count past the threshold holds", .count_word = COUNT(6), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HELD,
     .want_count = 6},
    {"power-on clears a count past the threshold", .count_word = COUNT(9), .cause = POWER_ON,
     .want = UDSOTA_BOOT_DECIDE_WINDOW},
    {"pin reset clears a count past the threshold", .count_word = COUNT(9), .cause = PIN,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"marker missing: count 0", .count_word = 0x0009u, .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"marker wrong: count 0", .count_word = 0xA409u, .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"marker missing: an erased store", .count_word = 0xFFFFu, .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"saturated count holds", .count_word = COUNT(255), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HELD,
     .want_count = 255},
    {"threshold 255: one below", .count_word = COUNT(254), .cause = OTHER, .set_hold = true, .hold = 255,
     .want = UDSOTA_BOOT_DECIDE_START_APP, .want_count = 254},
    {"threshold 255: saturated", .count_word = COUNT(255), .cause = OTHER, .set_hold = true, .hold = 255,
     .want = UDSOTA_BOOT_DECIDE_HELD, .want_count = 255},
    {"threshold 1: the first restart holds", .count_word = COUNT(1), .cause = OTHER, .set_hold = true, .hold = 1,
     .want = UDSOTA_BOOT_DECIDE_HELD, .want_count = 1},
    {"threshold 1: a cleared count starts", .count_word = COUNT(0), .cause = OTHER, .set_hold = true, .hold = 1,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    /* App validity. */
    {"no app", .count_word = COUNT(0), .cause = OTHER, .invalid = true, .want = UDSOTA_BOOT_DECIDE_NO_APP},
    {"no app before held", .count_word = COUNT(5), .cause = OTHER, .invalid = true,
     .want = UDSOTA_BOOT_DECIDE_NO_APP, .want_count = 5},
    {"no app before the window", .count_word = COUNT(0), .cause = POWER_ON, .invalid = true,
     .want = UDSOTA_BOOT_DECIDE_NO_APP},
    /* The handover: word 1 is the bus, 1 to cfg.buses (2 here). */
    {"handover", HO(1), .count_word = COUNT(1), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HANDOVER, .want_count = 1},
    {"handover on the last bus", HO(2), .count_word = COUNT(0), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HANDOVER},
    {"handover before no app", HO(1), .count_word = COUNT(0), .cause = OTHER, .invalid = true,
     .want = UDSOTA_BOOT_DECIDE_HANDOVER},
    {"handover before held", HO(1), .count_word = COUNT(5), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HANDOVER,
     .want_count = 5},
    {"handover whatever the cause", HO(1), .count_word = COUNT(3), .cause = POWER_ON,
     .want = UDSOTA_BOOT_DECIDE_HANDOVER},
    {"a mark that did not clear: no handover", .handover = 1u, .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"a mark that did not clear: the next rule holds", .handover = 1u, .count_word = COUNT(5), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_HELD, .want_count = 5},
    {"word 1 does not decode: bus 0", HO(0), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: a bus past cfg.buses", HO(3), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: bus 15 past cfg.buses", HO(15), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: a bit past the bus", HO(0x0011u), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: a bus with a rate's bits", HO(0x0021u), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: the top bit", HO(0x8001u), .count_word = COUNT(0), .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: an erased store", HO(0xFFFFu), .count_word = 0xFFFFu, .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
    {"word 1 does not decode: then no app", HO(0), .count_word = COUNT(0), .cause = OTHER, .invalid = true,
     .want = UDSOTA_BOOT_DECIDE_NO_APP},
    {"word 1 does not decode: then the window", HO(3), .count_word = COUNT(0), .cause = POWER_ON,
     .want = UDSOTA_BOOT_DECIDE_WINDOW},
    /* A session exit's inputs: no handover, cause OTHER, the core's flag and the count read again. */
    {"session exit starts the app", .count_word = COUNT(3), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_START_APP,
     .want_count = 3},
    {"session exit while held stays", .count_word = COUNT(5), .cause = OTHER, .want = UDSOTA_BOOT_DECIDE_HELD,
     .want_count = 5},
    {"session exit with no app stays", .count_word = COUNT(0), .cause = OTHER, .invalid = true,
     .want = UDSOTA_BOOT_DECIDE_NO_APP},
    {"session exit after a clear", .count_word = UDSOTA_START_COUNT_CLEAR, .cause = OTHER,
     .want = UDSOTA_BOOT_DECIDE_START_APP},
};

static void decide_cases(void)
{
    for (size_t i = 0; i < sizeof k_decide / sizeof k_decide[0]; i++) {
        const decide_case_t *c = &k_decide[i];
        udsota_boot_cfg_t cfg = k_cfg;
        if (c->set_hold) {
            cfg.hold_after_starts = c->hold;
        }
        if (c->no_window) {
            cfg.window_ms = 0u;
        }
        const udsota_boot_inputs_t in = {.handover_ok = c->handover_ok, .handover = c->handover,
                                         .count_word = c->count_word, .cause = c->cause, .app_valid = !c->invalid};
        uint8_t count = 0xEEu;
        const udsota_boot_decision_t got = udsota_boot_decide(&cfg, &in, &count);
        if (got != c->want || count != c->want_count) {
            fprintf(stderr, "%s:%d: boot rules, %s: decision %d count %u, want %d count %u\n", __FILE__, __LINE__,
                    c->name, (int)got, count, (int)c->want, c->want_count);
            g_failures++;
        }
    }
}

/* ---- The image the client stamped (test/fixtures/boot_fixtures.h) ---- */

UDSOTA_IMAGE_HEADER(BOOT_IMAGE_HW_ID, BOOT_IMAGE_LAYOUT_ID, BOOT_IMAGE_REQ_ID, BOOT_IMAGE_RESP_ID, BOOT_IMAGE_VERSION,
                    BOOT_IMAGE_PRODUCT);

/* The image's CRC as the core computes it: the bytes before the header's crc32, then those after it. */
static uint32_t image_crc(const uint8_t *img, uint32_t len)
{
    const uint32_t at = BOOT_IMAGE_HEADER_OFFSET + UDSOTA_BARE_HDR_CRC_OFFSET;
    return udsota_boot_crc32(udsota_boot_crc32(0u, img, at), img + at + 4u, len - at - 4u);
}

static void fixture_cases(void)
{
    const uint8_t *hdr = BOOT_IMAGE + BOOT_IMAGE_HEADER_OFFSET;
    const uint32_t stamped = le32(hdr + UDSOTA_BARE_HDR_CRC_OFFSET);

    /* Accepted as it is: its length, its CRC, the image rules with its own size as memorySize. */
    CHECK(BOOT_IMAGE_SIZE % 4u == 0u && le32(hdr + UDSOTA_BARE_HDR_LENGTH_OFFSET) == BOOT_IMAGE_SIZE);
    CHECK(image_crc(BOOT_IMAGE, BOOT_IMAGE_SIZE) == stamped);
    CHECK(udsota_boot_image_rules(&k_cfg, hdr, UDSOTA_BARE_HDR_LEN, BOOT_IMAGE_SIZE) == UDSOTA_DL_OK);
    CHECK(udsota_boot_image_rules(&k_cfg, hdr, UDSOTA_BARE_HDR_LEN, BOOT_IMAGE_SIZE - 4u) == UDSOTA_DL_BAD_HEADER);
    CHECK(udsota_boot_image_rules(&k_cfg, hdr, UDSOTA_BARE_HDR_LEN, BOOT_IMAGE_SIZE + 4u) == UDSOTA_DL_BAD_HEADER);

    /* And only as it is: any one byte changed fails the CRC, the header's included, but not the crc32 field. */
    static uint8_t img[BOOT_IMAGE_SIZE];
    int missed = 0;
    for (uint32_t i = 0; i < BOOT_IMAGE_SIZE; i++) {
        if (i >= BOOT_IMAGE_HEADER_OFFSET + UDSOTA_BARE_HDR_CRC_OFFSET &&
            i < BOOT_IMAGE_HEADER_OFFSET + UDSOTA_BARE_HDR_CRC_OFFSET + 4u) {
            continue;
        }
        memcpy(img, BOOT_IMAGE, sizeof img);
        img[i] ^= 0x01u;
        missed += image_crc(img, BOOT_IMAGE_SIZE) == stamped;
    }
    CHECK(missed == 0);

    /* UDSOTA_IMAGE_HEADER with the same identity lays out every field the build fills as stamping left it, and
     * leaves the stamped ones (image_length, crc32, image_id) 0xFF. */
    const volatile uint8_t *placed = (const volatile uint8_t *)&udsota_image_header;
    int differ = 0, unstamped = 0;
    uint32_t fixed = 0;
    for (uint32_t i = 0; i < UDSOTA_BARE_HDR_LEN; i++) {
        const bool stamped_field = (i >= UDSOTA_BARE_HDR_LENGTH_OFFSET && i < UDSOTA_BARE_HDR_CRC_OFFSET + 4u) ||
                                   (i >= UDSOTA_BARE_HDR_DESC_OFFSET + UDSOTA_BARE_IMAGE_ID_OFFSET &&
                                    i < UDSOTA_BARE_HDR_SIG_OFFSET);
        if (stamped_field) {
            unstamped += placed[i] != 0xFFu;
        } else {
            differ += placed[i] != hdr[i];
            fixed++;
        }
    }
    CHECK(differ == 0 && unstamped == 0 && fixed == UDSOTA_BARE_HDR_LEN - 8u - 32u);
    CHECK(udsota_image_header.desc.flags == 0x01u && udsota_image_header.header_version == UDSOTA_BARE_HDR_VERSION);
}

int main(void)
{
    crc_cases();
    image_rules_cases();
    encoding_cases();
    decide_cases();
    fixture_cases();
    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_udsota_boot_pure: all checks passed\n");
    return 0;
}
