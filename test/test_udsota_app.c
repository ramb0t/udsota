/* Unit test of the app's side of a udsota bootloader (udsota_app.h), built as an app builds it, with the repository
 * root its one include path and no iso14229 or core: udsota_app_classify's four results whatever the padding, both
 * answers byte for byte, and the keep words udsota_app_write_handover and udsota_app_clear_start_count write, in
 * order, through a port that records them; and the buses that take updates under the app's own header
 * (udsota_app_bus_open, and the rule it shares with the bootloader, udsota_image_bus_open). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "udsota_app.h"

static int g_failures;
#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (!(cond)) {                                                                                   \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                   \
            g_failures++;                                                                                \
        }                                                                                                \
    } while (0)

#define REQ 0x710u

/* The app's own header, taking updates on buses 1 and 3. */
UDSOTA_IMAGE_HEADER_BUSES(UDSOTA_BUS(1) | UDSOTA_BUS(3), 1, 1, REQ, 0x718, "1.0.0", "example");

/* ---- The port: every keep-word write, in order ---- */

static struct {
    uint8_t  word;
    uint16_t value;
} s_writes[8];
static size_t s_nwrites;

void udsota_app_port_keep_write(uint8_t word, uint16_t value)
{
    if (s_nwrites < sizeof s_writes / sizeof s_writes[0]) {
        s_writes[s_nwrites].word = word;
        s_writes[s_nwrites].value = value;
    }
    s_nwrites++;
}

static bool wrote(size_t i, uint8_t word, uint16_t value)
{
    return i < s_nwrites && s_writes[i].word == word && s_writes[i].value == value;
}

/* ---- udsota_app_classify ---- */

#define F(...) (const uint8_t[]){__VA_ARGS__}, (uint8_t)sizeof((const uint8_t[]){__VA_ARGS__})
typedef struct {
    const char     *name;
    uint32_t        id;
    bool            ext;            /* a 29-bit frame */
    const uint8_t  *data;
    uint8_t         len;
    udsota_app_rx_t want;
} rx_case_t;

static const rx_case_t k_rx[] = {
    {"handover, padded 0xAA", REQ, false, F(0x02, 0x10, 0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_HANDOVER},
    {"handover, padded 0x00", REQ, false, F(0x02, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00), UDSOTA_APP_RX_HANDOVER},
    {"handover, padded 0x55", REQ, false, F(0x02, 0x10, 0x02, 0x55, 0x55, 0x55, 0x55, 0x55), UDSOTA_APP_RX_HANDOVER},
    {"handover, unpadded", REQ, false, F(0x02, 0x10, 0x02), UDSOTA_APP_RX_HANDOVER},
    {"read prefix, padded 0xAA", REQ, false, F(0x03, 0x22, 0xF1, 0xF4, 0xAA, 0xAA, 0xAA, 0xAA),
     UDSOTA_APP_RX_READ_PREFIX},
    {"read prefix, padded 0xCC", REQ, false, F(0x03, 0x22, 0xF1, 0xF4, 0xCC, 0xCC, 0xCC, 0xCC),
     UDSOTA_APP_RX_READ_PREFIX},
    {"read prefix, unpadded", REQ, false, F(0x03, 0x22, 0xF1, 0xF4), UDSOTA_APP_RX_READ_PREFIX},
    {"another ID", 0x711u, false, F(0x02, 0x10, 0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_NONE},
    {"the response ID", 0x718u, false, F(0x03, 0x22, 0xF1, 0xF4, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_NONE},
    {"a 29-bit frame on the same number", REQ, true, F(0x02, 0x10, 0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA),
     UDSOTA_APP_RX_NONE},
    {"10 01", REQ, false, F(0x02, 0x10, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"10 03", REQ, false, F(0x02, 0x10, 0x03, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"10 02 with a longer length byte", REQ, false, F(0x03, 0x10, 0x02, 0x00, 0xAA, 0xAA, 0xAA, 0xAA),
     UDSOTA_APP_RX_OTHER},
    {"10 82 (no answer wanted)", REQ, false, F(0x02, 0x10, 0x82, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"22 F1F3", REQ, false, F(0x03, 0x22, 0xF1, 0xF3, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"22 F1F4 F1F0, two DIDs", REQ, false, F(0x05, 0x22, 0xF1, 0xF4, 0xF1, 0xF0, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"22 F1F4 as a first frame", REQ, false, F(0x10, 0x08, 0x22, 0xF1, 0xF4, 0xF1, 0xF0, 0xF1),
     UDSOTA_APP_RX_OTHER},
    {"3E 00", REQ, false, F(0x02, 0x3E, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA), UDSOTA_APP_RX_OTHER},
    {"handover cut short", REQ, false, F(0x02, 0x10), UDSOTA_APP_RX_OTHER},
    {"read prefix cut short", REQ, false, F(0x03, 0x22, 0xF1), UDSOTA_APP_RX_OTHER},
    {"an empty frame", REQ, false, F(0x00), UDSOTA_APP_RX_OTHER},
};

static void classify_cases(void)
{
    for (size_t i = 0; i < sizeof k_rx / sizeof k_rx[0]; i++) {
        const rx_case_t *c = &k_rx[i];
        const udsota_app_rx_t got = udsota_app_classify(REQ, c->id, !c->ext, c->data, c->len);
        if (got != c->want) {
            fprintf(stderr, "%s:%d: classify, %s: %d, want %d\n", __FILE__, __LINE__, c->name, (int)got,
                    (int)c->want);
            g_failures++;
        }
    }
    const uint8_t none[1] = {0x02};
    CHECK(udsota_app_classify(REQ, REQ, true, none, 0u) == UDSOTA_APP_RX_OTHER);   /* len 0 reads nothing */
}

/* ---- Answers and keep words ---- */

static void answer_cases(void)
{
    uint8_t out[8];
    memset(out, 0x11, sizeof out);
    udsota_app_answer_pending(out);
    CHECK(memcmp(out, (const uint8_t[]){0x03, 0x7F, 0x10, 0x78, 0xAA, 0xAA, 0xAA, 0xAA}, 8) == 0);
    CHECK(UDSOTA_APP_PAD_BYTE == 0xAAu);
    memset(out, 0x11, sizeof out);
    udsota_app_answer_prefix((const uint8_t[]){0xDE, 0xAD, 0xBE, 0xEF}, out);
    CHECK(memcmp(out, (const uint8_t[]){0x07, 0x62, 0xF1, 0xF4, 0xDE, 0xAD, 0xBE, 0xEF}, 8) == 0);
}

static void keep_word_cases(void)
{
    /* Word 1, the bus, then the mark in word 0, as the bootloader reads them. */
    for (uint8_t bus = 1; bus <= 15u; bus++) {
        s_nwrites = 0;
        udsota_app_write_handover(bus);
        CHECK(s_nwrites == 2u && wrote(0, UDSOTA_KEEP_WORD_HANDOVER, bus) &&
              wrote(1, UDSOTA_KEEP_WORD_MARK, UDSOTA_HANDOVER_MARK));
    }
    CHECK(UDSOTA_HANDOVER_MARK == 0xB007u);

    s_nwrites = 0;
    udsota_app_clear_start_count();
    CHECK(s_nwrites == 1u && wrote(0, UDSOTA_KEEP_WORD_COUNT, 0xA500u));
}

/* ---- The buses that take updates ---- */

static void bus_cases(void)
{
    CHECK(UDSOTA_BUS(1) == 0x0001u && UDSOTA_BUS(2) == 0x0002u && UDSOTA_BUS(15) == 0x4000u);
    CHECK(udsota_image_header.update_buses == 0x0005u && UDSOTA_BARE_HDR_UPDATE_BUSES_OFFSET == 16u);
    CHECK(sizeof(udsota_image_header_t) == UDSOTA_BARE_HDR_LEN);
    /* The app's helper, on a board of 4 buses: its header's mask. */
    CHECK(udsota_app_bus_open(1u, 4u) && !udsota_app_bus_open(2u, 4u) && udsota_app_bus_open(3u, 4u) &&
          !udsota_app_bus_open(4u, 4u));
    CHECK(!udsota_app_bus_open(0u, 4u) && !udsota_app_bus_open(5u, 4u));
    /* Cut to 2 buses the mask names bus 1 only; cut to 1 bus, bus 1; cut to 3, buses 1 and 3. */
    CHECK(udsota_app_bus_open(1u, 2u) && !udsota_app_bus_open(2u, 2u) && !udsota_app_bus_open(3u, 2u));
    CHECK(udsota_app_bus_open(1u, 1u));
    CHECK(udsota_app_bus_open(3u, 3u) && !udsota_app_bus_open(2u, 3u));

    /* The shared rule, edge cases by name. */
    CHECK(udsota_image_bus_open(0xFFFFu, 2u, 1u) && udsota_image_bus_open(0xFFFFu, 2u, 2u));   /* every bus */
    CHECK(udsota_image_bus_open(0x0000u, 2u, 1u) && udsota_image_bus_open(0x0000u, 2u, 2u));   /* names none */
    CHECK(udsota_image_bus_open(UDSOTA_BUS(3), 2u, 1u) && udsota_image_bus_open(UDSOTA_BUS(3), 2u, 2u));
    CHECK(udsota_image_bus_open(0xFFFCu, 2u, 1u) && udsota_image_bus_open(0xFFFCu, 2u, 2u));   /* only buses past 2 */
    CHECK(!udsota_image_bus_open(UDSOTA_BUS(2) | UDSOTA_BUS(3), 2u, 1u) &&
          udsota_image_bus_open(UDSOTA_BUS(2) | UDSOTA_BUS(3), 2u, 2u));                       /* cut to the board */
    CHECK(udsota_image_bus_open(UDSOTA_BUS(15), 15u, 15u) && !udsota_image_bus_open(UDSOTA_BUS(15), 15u, 14u));
    CHECK(udsota_image_bus_open(0x0000u, 15u, 15u));
    CHECK(!udsota_image_bus_open(0xFFFFu, 2u, 0u) && !udsota_image_bus_open(0xFFFFu, 2u, 3u));   /* never outside */
    /* Against a plain statement of the rule, for every mask on boards of 1 to 15 buses. */
    int bad = 0;
    for (uint32_t mask = 0; mask <= 0xFFFFu; mask++) {
        for (uint8_t buses = 1; buses <= 15u; buses++) {
            const uint32_t all = (1u << buses) - 1u;
            const uint32_t eff = ((mask & all) != 0u) ? (mask & all) : all;
            for (uint8_t bus = 0; bus <= 16u; bus++) {
                const bool want = bus >= 1u && bus <= buses && ((eff >> (bus - 1u)) & 1u) != 0u;
                bad += udsota_image_bus_open((uint16_t)mask, buses, bus) != want;
            }
        }
    }
    CHECK(bad == 0);
}

int main(void)
{
    classify_cases();
    answer_cases();
    keep_word_cases();
    bus_cases();
    if (g_failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("test_udsota_app: all checks passed\n");
    return 0;
}
