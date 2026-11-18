/* The STM32F1 port's slot pointer, page erase and half-word programming, against test/boot/stm32f1/fake_cmsis. */
#include "stm32f1xx.h"
#include "f1_internal.h"
#include "check.h"
#include <string.h>

#define B 0x08004000u   /* the slot: 240 KB (0x3C000) after a 16 KB bootloader */
static void test_range_in_slot(void) {
    CHECK(f1_range_in_slot(0, 0x3C000u));       CHECK(f1_range_in_slot(0x3BFFEu, 2));
    CHECK(!f1_range_in_slot(0x3BFFEu, 4));      CHECK(!f1_range_in_slot(0x3C000u, 2));
    CHECK(!f1_range_in_slot(0, 0));             CHECK(!f1_range_in_slot(0xFFFFFFFEu, 4));
    CHECK(!f1_range_in_slot(2, 0xFFFFFFFFu));
}
static void test_pages_starting_in(void) {
    static const uint32_t t[][4] = {   /* off, len, count, first_off (0xDEAD: left as it was) */
        {0, 1026, 1, 0}, {0, 2048, 1, 0}, {0, 2049, 2, 0}, {1024, 1024, 0, 0xDEAD}, {1024, 1026, 1, 2048},
        {2048, 4096, 2, 2048}, {1, 2047, 0, 0xDEAD}, {0x3B800u, 0x800, 1, 0x3B800u}, {0x3BC00u, 0x400, 0, 0xDEAD}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        uint32_t first = 0xDEAD;
        CHECK_EQ_U32(f1_pages_starting_in(t[i][0], t[i][1], &first), t[i][2]); CHECK_EQ_U32(first, t[i][3]);
    }
}
static void test_slot_pointer(void) { CHECK(udsota_boot_port_slot() == fake_slot); }
static void test_erase_one_page(void) {
    fake_cmsis_reset(); memset(fake_slot, 0x00, sizeof fake_slot);
    CHECK(udsota_boot_port_flash_erase(1024, 1026));
    CHECK_EQ_U32(fake_flash_erased_len, 1); CHECK_EQ_U32(fake_flash_erased[0], B + 0x800);
    CHECK_EQ_U32(fake_slot[0x800], 0xFF); CHECK_EQ_U32(fake_slot[0xFFF], 0xFF);
    CHECK_EQ_U32(fake_slot[0x7FF], 0x00); CHECK_EQ_U32(fake_slot[0x1000], 0x00);
    CHECK_EQ_U32(fake_flash_keys_len, 2); CHECK_EQ_U32(fake_flash_keys[0], FLASH_KEY1); CHECK_EQ_U32(fake_flash_keys[1], FLASH_KEY2);
    CHECK(fake_flash_regs.CR & FLASH_CR_LOCK);
    CHECK_EQ_U32(fake_flash_regs.CR & (FLASH_CR_PER | FLASH_CR_STRT | FLASH_CR_PG), 0);
}
static void test_erase_two_pages_and_the_last(void) {
    fake_cmsis_reset();
    CHECK(udsota_boot_port_flash_erase(2048, 4096));
    CHECK_EQ_U32(fake_flash_erased_len, 2); CHECK_EQ_U32(fake_flash_erased[0], B + 0x800); CHECK_EQ_U32(fake_flash_erased[1], B + 0x1000);
    fake_cmsis_reset();
    CHECK(udsota_boot_port_flash_erase(0x3B800u, 0x800)); CHECK_EQ_U32(fake_flash_erased[0], 0x0803F800u);
}
static void test_erase_without_a_new_page_touches_nothing(void) {
    fake_cmsis_reset(); CHECK(udsota_boot_port_flash_erase(1024, 1024)); CHECK_EQ_U32(fake_flash_accesses, 0);
}
static void test_erase_refuses_outside_the_slot(void) {
    fake_cmsis_reset();
    CHECK(!udsota_boot_port_flash_erase(0x3B800u, 0x802)); CHECK(!udsota_boot_port_flash_erase(0xFFFFFFFEu, 4));
    CHECK(!udsota_boot_port_flash_erase(0, 0));            CHECK_EQ_U32(fake_flash_accesses, 0);
}
static void test_erase_reports_write_protection(void) {
    fake_cmsis_reset(); fake_flash_error = FLASH_SR_WRPRTERR;
    CHECK(!udsota_boot_port_flash_erase(0, 2));
    CHECK(fake_flash_regs.CR & FLASH_CR_LOCK); CHECK_EQ_U32(fake_flash_regs.CR & FLASH_CR_PER, 0);
}
static void test_erase_fails_when_unlock_is_refused(void) {
    fake_cmsis_reset(); fake_flash_keys_ignored = 1;
    CHECK(!udsota_boot_port_flash_erase(0, 2)); CHECK_EQ_U32(fake_flash_erased_len, 0);
}
static void test_erase_busy_times_out(void) {
    fake_cmsis_reset(); fake_flash_bsy_stuck = 1;
    uint32_t t0 = udsota_boot_port_us();
    CHECK(!udsota_boot_port_flash_erase(0, 2));
    uint32_t dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 200000u && dt <= 200010u); CHECK(fake_flash_regs.CR & FLASH_CR_LOCK);
}
static void test_program_from_an_unaligned_source(void) {
    fake_cmsis_reset(); static const uint8_t src[5] = {0x00, 0x11, 0x22, 0x33, 0x44};
    CHECK(udsota_boot_port_flash_program(0x200, src + 1, 4));
    CHECK_EQ_U32(fake_slot[0x200], 0x11); CHECK_EQ_U32(fake_slot[0x201], 0x22);
    CHECK_EQ_U32(fake_slot[0x202], 0x33); CHECK_EQ_U32(fake_slot[0x203], 0x44); CHECK_EQ_U32(fake_slot[0x204], 0xFF);
    CHECK(fake_flash_regs.CR & FLASH_CR_LOCK); CHECK_EQ_U32(fake_flash_regs.CR & FLASH_CR_PG, 0);
}
static void test_program_a_full_block(void) {
    fake_cmsis_reset(); static uint8_t buf[1025];
    for (int i = 0; i < 1025; i++) buf[i] = (uint8_t)(i * 7);
    CHECK(udsota_boot_port_flash_program(0x800, buf + 1, 1024));
    CHECK(memcmp(udsota_boot_port_slot() + 0x800, buf + 1, 1024) == 0);
}
static void test_program_refuses_bad_ranges(void) {
    fake_cmsis_reset(); static const uint8_t d[4] = {1, 2, 3, 4};
    CHECK(!udsota_boot_port_flash_program(1, d, 2));        CHECK(!udsota_boot_port_flash_program(0, d, 3));
    CHECK(!udsota_boot_port_flash_program(0x3BFFEu, d, 4)); CHECK(!udsota_boot_port_flash_program(0, d, 0));
    CHECK_EQ_U32(fake_flash_accesses, 0);
    CHECK(udsota_boot_port_flash_program(0x3BFFEu, d, 2));
}
static void test_program_reports_pgerr(void) {
    fake_cmsis_reset(); fake_flash_error = FLASH_SR_PGERR; static const uint8_t d[2] = {1, 2};
    CHECK(!udsota_boot_port_flash_program(0, d, 2));
    CHECK(fake_flash_regs.CR & FLASH_CR_LOCK); CHECK_EQ_U32(fake_flash_regs.CR & FLASH_CR_PG, 0);
}
static void test_program_busy_times_out(void) {
    fake_cmsis_reset(); fake_flash_bsy_stuck = 1; static const uint8_t d[2] = {1, 2};
    uint32_t t0 = udsota_boot_port_us();
    CHECK(!udsota_boot_port_flash_program(0, d, 2));
    uint32_t dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 1000u && dt <= 1010u);
}

int main(void)
{
    test_range_in_slot();
    test_pages_starting_in();
    test_slot_pointer();
    test_erase_one_page();
    test_erase_two_pages_and_the_last();
    test_erase_without_a_new_page_touches_nothing();
    test_erase_refuses_outside_the_slot();
    test_erase_reports_write_protection();
    test_erase_fails_when_unlock_is_refused();
    test_erase_busy_times_out();
    test_program_from_an_unaligned_source();
    test_program_a_full_block();
    test_program_refuses_bad_ranges();
    test_program_reports_pgerr();
    test_program_busy_times_out();
    CHECK_DONE();
}
