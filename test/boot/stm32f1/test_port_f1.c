/* The STM32F1 port's clock, reset cause, keep words, watchdog, device ID and reset, against test/boot/stm32f1/fake_cmsis. */
#include "stm32f1xx.h"
#include "f1_internal.h"
#include "check.h"
#include <string.h>

static void test_port_us_counts_dwt_at_system_core_clock(void) {
    fake_cmsis_reset(); fake_cycles_per_read = 0;
    uint32_t a = udsota_boot_port_us();                         /* CYCCNT 0, nothing elapsed */
    fake_dwt_regs.CYCCNT = 72u * 1000u + 36u;
    uint32_t b = udsota_boot_port_us();
    CHECK_EQ_U32(b - a, 1000);
    fake_dwt_regs.CYCCNT += 36u;                               /* the carried 36 makes one more */
    CHECK_EQ_U32(udsota_boot_port_us() - b, 1);
    SystemCoreClock = 8000000u;                                /* the board's HSI phase */
    uint32_t c = udsota_boot_port_us();
    fake_dwt_regs.CYCCNT += 8u * 250u;
    CHECK_EQ_U32(udsota_boot_port_us() - c, 250);
}
static void test_us_advance(void) {
    uint32_t last = 0, rem = 0;
    CHECK_EQ_U32(f1_us_advance(&last, &rem, 72u * 5u + 10u, 72000000u), 5);
    CHECK_EQ_U32(rem, 10); CHECK_EQ_U32(last, 370);
    CHECK_EQ_U32(f1_us_advance(&last, &rem, 432u, 72000000u), 1); CHECK_EQ_U32(rem, 0);
    last = 0xFFFFFF00u; rem = 0;                               /* CYCCNT wrapped */
    CHECK_EQ_U32(f1_us_advance(&last, &rem, 0x100u, 8000000u), 64);
    last = 0; rem = 71;                                        /* delta + rem passes 2^32 */
    CHECK_EQ_U32(f1_us_advance(&last, &rem, 0xFFFFFFFFu, 72000000u), 59652324u); CHECK_EQ_U32(rem, 38);
    last = 0; rem = 0;                                         /* under 1 MHz counts one cycle a microsecond */
    CHECK_EQ_U32(f1_us_advance(&last, &rem, 1000u, 500000u), 1000);
}
static void test_reset_cause_table(void) {
    static const struct { uint32_t csr; udsota_boot_reset_t want; } t[] = {
        {0x0C000000u, UDSOTA_BOOT_RESET_POWER_ON}, {0x08000000u, UDSOTA_BOOT_RESET_POWER_ON},
        {0x3C000000u, UDSOTA_BOOT_RESET_POWER_ON}, {0x04000000u, UDSOTA_BOOT_RESET_PIN},
        {0x04000003u, UDSOTA_BOOT_RESET_PIN},      {0x14000000u, UDSOTA_BOOT_RESET_OTHER},
        {0x24000000u, UDSOTA_BOOT_RESET_OTHER},    {0x44000000u, UDSOTA_BOOT_RESET_OTHER},
        {0x84000000u, UDSOTA_BOOT_RESET_OTHER},    {0x10000000u, UDSOTA_BOOT_RESET_OTHER},
        {0x00000000u, UDSOTA_BOOT_RESET_OTHER}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) CHECK(f1_reset_cause(t[i].csr) == t[i].want);
}
static void test_reset_cause_reads_and_clears_csr(void) {
    fake_cmsis_reset(); fake_rcc.CSR = 0x0C000000u;
    CHECK(udsota_boot_port_reset_cause() == UDSOTA_BOOT_RESET_POWER_ON);
    CHECK(fake_rcc.CSR & RCC_CSR_RMVF);
}
static void test_keep_words_are_dr1_to_dr3(void) {
    fake_cmsis_reset();
    udsota_boot_port_keep_write(0, 0xB007u); udsota_boot_port_keep_write(1, 0x0003u); udsota_boot_port_keep_write(2, 0xA502u);
    CHECK_EQ_U32(fake_bkp.DR1, 0xB007); CHECK_EQ_U32(fake_bkp.DR2, 0x0003); CHECK_EQ_U32(fake_bkp.DR3, 0xA502);
    fake_bkp.DR2 = 0x0002u; CHECK_EQ_U32(udsota_boot_port_keep_read(1), 2);
    udsota_boot_port_keep_write(3, 0x1234u);                   /* outside 0..2: ignored */
    CHECK_EQ_U32(fake_bkp.DR4, 0); CHECK_EQ_U32(udsota_boot_port_keep_read(3), 0);
}
static void test_iwdg_settings_table(void) {
    static const uint32_t t[][3] = {{0,0,0}, {1,0,9}, {100,0,999}, {409,0,4089}, {410,1,2049}, {1000,2,2499},
        {2000,3,2499}, {26214,6,4094}, {30000,6,4095}, {65535,6,4095}, {0xFFFFFFFFu,6,4095}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        uint32_t pr = 99, rlr = 99; f1_iwdg_settings(t[i][0], &pr, &rlr);
        CHECK_EQ_U32(pr, t[i][1]); CHECK_EQ_U32(rlr, t[i][2]);
    }
}
static void test_watchdog_start_order(void) {
    fake_cmsis_reset(); fake_iwdg_regs.RLR = 0xFFFu; fake_dbgmcu.CR = 0x7u;
    udsota_boot_port_watchdog_start(2000);
    (void)IWDG->KR;                                            /* lets the fake log the last key */
    CHECK_EQ_U32(fake_iwdg_log_len, 3);
    CHECK_EQ_U32(fake_iwdg_log[0].kr, 0xCCCC);
    CHECK_EQ_U32(fake_iwdg_log[1].kr, 0x5555); CHECK_EQ_U32(fake_iwdg_log[1].pr, 0); CHECK_EQ_U32(fake_iwdg_log[1].rlr, 0xFFF);
    CHECK_EQ_U32(fake_iwdg_log[2].kr, 0xAAAA); CHECK_EQ_U32(fake_iwdg_log[2].pr, 3); CHECK_EQ_U32(fake_iwdg_log[2].rlr, 2499);
    CHECK_EQ_U32(fake_dbgmcu.CR, 0x107);
}
static void test_watchdog_start_reloads_after_a_timed_out_wait(void) {
    fake_cmsis_reset(); fake_iwdg_regs.SR = IWDG_SR_PVU | IWDG_SR_RVU;   /* never clear */
    uint32_t t0 = udsota_boot_port_us();
    udsota_boot_port_watchdog_start(2000);
    uint32_t dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 1000 && dt <= 1010);
    CHECK_EQ_U32(fake_iwdg_regs.KR, 0xAAAA); CHECK_EQ_U32(fake_iwdg_regs.PR, 3); CHECK_EQ_U32(fake_iwdg_regs.RLR, 2499);
}
static void test_watchdog_reload(void) {
    fake_cmsis_reset(); udsota_boot_port_watchdog_reload(); CHECK_EQ_U32(fake_iwdg_regs.KR, 0xAAAA);
}
static void test_device_id_is_the_uid_bytes(void) {
    fake_cmsis_reset(); uint8_t out[16]; memset(out, 0x5A, sizeof out);
    for (int i = 0; i < 12; i++) fake_uid[i] = (uint8_t)(0xE8 + i);
    CHECK_EQ_U32(udsota_boot_port_device_id(out), 12);
    CHECK(memcmp(out, fake_uid, 12) == 0); CHECK_EQ_U32(out[12], 0x5A); CHECK_EQ_U32(out[15], 0x5A);
}
static void test_reset_is_a_system_reset(void) {
    fake_cmsis_reset(); udsota_boot_port_reset(); CHECK_EQ_U32(fake_system_resets, 1);
}

int main(void)
{
    test_port_us_counts_dwt_at_system_core_clock();   /* first, while the port's clock state is zero */
    test_us_advance();
    test_reset_cause_table();
    test_reset_cause_reads_and_clears_csr();
    test_keep_words_are_dr1_to_dr3();
    test_iwdg_settings_table();
    test_watchdog_start_order();
    test_watchdog_start_reloads_after_a_timed_out_wait();
    test_watchdog_reload();
    test_device_id_is_the_uid_bytes();
    test_reset_is_a_system_reset();
    CHECK_DONE();
}
