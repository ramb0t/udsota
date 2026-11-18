/* The STM32F1 port's polled bxCAN helper, against test/boot/stm32f1/fake_cmsis with a model of INAK and SLAK. */
#include "stm32f1xx.h"
#include "f1_bxcan.h"
#include "udsota_boot.h"
#include "check.h"
#include <string.h>

static int stuck_in_init, never_init;   /* a bus held dominant: INAK stays set; a controller that never enters init */
static int slow_enter, enter_reads;     /* CAN1's INAK follows INRQ only after slow_enter clock reads (1 us each) */
static void bxcan_model(void) {
    CAN_TypeDef *c[2] = {&fake_can1, &fake_can2};
    for (int i = 0; i < 2; i++) {
        bool inak = (c[i]->MCR & CAN_MCR_INRQ) != 0;
        if (never_init) inak = false;
        if (inak && i == 0 && enter_reads < slow_enter) { enter_reads++; inak = false; }
        if (stuck_in_init && (c[i]->MSR & CAN_MSR_INAK)) inak = true;
        c[i]->MSR = (c[i]->MSR & ~(CAN_MSR_INAK | CAN_MSR_SLAK)) | (inak ? CAN_MSR_INAK : 0)
                  | ((c[i]->MCR & CAN_MCR_SLEEP) ? CAN_MSR_SLAK : 0);
    }
}
static void setup(void) {
    fake_cmsis_reset(); stuck_in_init = never_init = slow_enter = enter_reads = 0; fake_on_clock_read = bxcan_model;
    fake_can1.MCR = fake_can2.MCR = 0x00010002u; fake_can1.MSR = fake_can2.MSR = 0x00000C02u; fake_can1.FMR = 0x2A1C0E01u;
}
static void test_start_can1_filters_0x710_data_frames(void) {
    setup();
    CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    CHECK_EQ_U32(fake_can1.BTR, 0x001E0007);
    CHECK_EQ_U32(fake_can1.MCR & (CAN_MCR_INRQ | CAN_MCR_SLEEP | CAN_MCR_NART | CAN_MCR_AWUM
                                  | CAN_MCR_RFLM | CAN_MCR_TTCM | CAN_MCR_RESET), 0);
    CHECK(fake_can1.MCR & CAN_MCR_ABOM);                /* bus-off ends by itself: nothing else restarts the bus */
    CHECK(fake_can1.MCR & CAN_MCR_TXFP); CHECK(fake_can1.MCR & CAN_MCR_DBF); CHECK_EQ_U32(fake_can1.IER, 0);
    CHECK_EQ_U32(fake_can1.sFilterRegister[0].FR1, 0xE2000000); CHECK_EQ_U32(fake_can1.sFilterRegister[0].FR2, 0xFFE00006);
    CHECK(fake_can1.FS1R & 1u); CHECK(!(fake_can1.FM1R & 1u)); CHECK(!(fake_can1.FFA1R & 1u)); CHECK(fake_can1.FA1R & 1u);
    CHECK_EQ_U32(fake_can1.FMR & CAN_FMR_FINIT, 0); CHECK_EQ_U32((fake_can1.FMR & CAN_FMR_CAN2SB) >> CAN_FMR_CAN2SB_Pos, 14);
}
static void test_start_can2_uses_can1_bank_14(void) {
    setup();
    CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    CHECK(f1_bxcan_start(CAN2, 0x001E0003u, 14, 1, 0x710, 10000));
    CHECK_EQ_U32(fake_can2.BTR, 0x001E0003); CHECK_EQ_U32(fake_can1.BTR, 0x001E0007);
    CHECK_EQ_U32(fake_can1.sFilterRegister[14].FR1, 0xE2000000); CHECK_EQ_U32(fake_can1.sFilterRegister[14].FR2, 0xFFE00006);
    CHECK(fake_can1.FFA1R & (1u << 14)); CHECK(fake_can1.FS1R & (1u << 14));
    CHECK_EQ_U32(fake_can1.FA1R & ((1u << 14) | 1u), (1u << 14) | 1u);
    CHECK_EQ_U32(fake_can1.FMR & CAN_FMR_FINIT, 0); CHECK_EQ_U32(fake_can2.sFilterRegister[14].FR1, 0);
}
/* A bus held dominant: the start does not wait for it. It leaves the request to join standing and returns, the
   controller joins by itself when the bus goes idle, and until then a send fails at once. */
static void test_start_on_a_bus_that_is_not_idle_leaves_the_controller_to_join(void) {
    static const uint8_t d[8] = {0};
    setup(); stuck_in_init = 1;
    uint32_t t0 = udsota_boot_port_us();
    CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    CHECK(udsota_boot_port_us() - t0 <= 10u);           /* no wait on the bus */
    CHECK_EQ_U32(fake_can1.MCR & CAN_MCR_INRQ, 0);      /* the request to join stands */
    (void)udsota_boot_port_us();
    CHECK(fake_can1.MSR & CAN_MSR_INAK);                /* not joined */
    fake_can1.TSR = CAN_TSR_TME;
    CHECK(!f1_bxcan_send(CAN1, 0x718, d, 8, 10000)); CHECK_EQ_U32(fake_can1.sTxMailBox[0].TIR, 0);
    stuck_in_init = 0; (void)udsota_boot_port_us();     /* the bus goes idle: the controller joins */
    CHECK_EQ_U32(fake_can1.MSR & CAN_MSR_INAK, 0);
    CHECK(f1_bxcan_send(CAN1, 0x718, d, 8, 10000));
}
/* The registers here are plain memory, so INRQ set and cleared again leaves no trace: this shows when rejoin acts
   and that it leaves the request standing and the filters alone, not the write itself. */
static void test_rejoin_asks_again_only_while_the_controller_has_not_joined(void) {
    setup(); stuck_in_init = 1;
    CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000)); (void)udsota_boot_port_us();
    uint32_t fmr = fake_can1.FMR, fa1r = fake_can1.FA1R;
    CHECK(f1_bxcan_rejoin(CAN1));                       /* still waiting for the bus: asked again */
    CHECK_EQ_U32(fake_can1.MCR & CAN_MCR_INRQ, 0); CHECK(fake_can1.MCR & CAN_MCR_ABOM);
    CHECK_EQ_U32(fake_can1.FMR, fmr); CHECK_EQ_U32(fake_can1.FA1R, fa1r);     /* no filter touched */
    stuck_in_init = 0; (void)udsota_boot_port_us();     /* the bus goes idle: the controller joins */
    uint32_t mcr = fake_can1.MCR;
    CHECK(!f1_bxcan_rejoin(CAN1)); CHECK_EQ_U32(fake_can1.MCR, mcr);
}
static void test_start_that_never_enters_init_fails(void) {
    setup(); never_init = 1;
    CHECK(!f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000)); CHECK(fake_can1.MCR & CAN_MCR_INRQ);
}
static void test_start_waits_only_to_enter_init(void) {
    setup(); slow_enter = 7000;                         /* entering init takes 7 ms of the 10 allowed */
    uint32_t t0 = udsota_boot_port_us();
    CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    uint32_t dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 7000u && dt <= 7010u); CHECK(enter_reads == 7000);
    setup(); slow_enter = 12000;                        /* and fails when that takes longer than allowed */
    t0 = udsota_boot_port_us();
    CHECK(!f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 10000u && dt <= 10010u); CHECK(fake_can1.MCR & CAN_MCR_INRQ);
}
static void test_start_refuses_bad_arguments(void) {
    setup(); CAN_TypeDef before = fake_can1;
    CHECK(!f1_bxcan_start(CAN1, 0x001E0007u, 28, 0, 0x710, 10000));
    CHECK(!f1_bxcan_start(CAN1, 0x001E0007u, 0, 2, 0x710, 10000));
    CHECK(!f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x800, 10000));
    CHECK(memcmp(&before, &fake_can1, sizeof before) == 0);
}
static void test_stop_requests_init_aborts_mailboxes_and_touches_no_clock(void) {
    setup(); CHECK(f1_bxcan_start(CAN1, 0x001E0007u, 0, 0, 0x710, 10000));
    RCC_TypeDef rcc = fake_rcc;
    f1_bxcan_stop(CAN1);
    CHECK(fake_can1.MCR & CAN_MCR_INRQ); CHECK_EQ_U32(fake_can1.MCR & CAN_MCR_RESET, 0);
    CHECK_EQ_U32(fake_can1.TSR, CAN_TSR_ABRQ0 | CAN_TSR_ABRQ1 | CAN_TSR_ABRQ2);
    CHECK_EQ_U32(fake_can1.BTR, 0x001E0007); CHECK(fake_can1.FA1R & 1u);
    CHECK(memcmp(&rcc, &fake_rcc, sizeof rcc) == 0);
}
static void test_send_fills_the_mailbox_code_names(void) {
    setup(); fake_can1.TSR = CAN_TSR_TME2 | (2u << CAN_TSR_CODE_Pos);
    static const uint8_t d[8] = {0x02, 0x50, 0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    CHECK(f1_bxcan_send(CAN1, 0x718, d, 8, 10000));
    CHECK_EQ_U32(fake_can1.sTxMailBox[2].TIR, 0xE3000001);
    CHECK_EQ_U32(fake_can1.sTxMailBox[2].TDTR & CAN_TDT0R_DLC, 8);
    CHECK_EQ_U32(fake_can1.sTxMailBox[2].TDLR, 0xAA025002); CHECK_EQ_U32(fake_can1.sTxMailBox[2].TDHR, 0xAAAAAAAA);
    CHECK_EQ_U32(fake_can1.sTxMailBox[0].TIR, 0); CHECK_EQ_U32(fake_can1.sTxMailBox[1].TIR, 0);
}
static void test_send_short_frame_reads_only_len_bytes(void) {
    setup(); fake_can1.TSR = CAN_TSR_TME0;
    static const uint8_t d[3] = {0x11, 0x22, 0x33};
    CHECK(f1_bxcan_send(CAN1, 0x718, d, 3, 10000));
    CHECK_EQ_U32(fake_can1.sTxMailBox[0].TDLR, 0x00332211); CHECK_EQ_U32(fake_can1.sTxMailBox[0].TDHR, 0);
    CHECK_EQ_U32(fake_can1.sTxMailBox[0].TDTR & CAN_TDT0R_DLC, 3);
}
static void test_send_with_no_empty_mailbox_times_out(void) {
    setup(); fake_can1.TSR = 0; static const uint8_t d[8] = {0};
    uint32_t t0 = udsota_boot_port_us();
    CHECK(!f1_bxcan_send(CAN1, 0x718, d, 8, 10000));
    uint32_t dt = udsota_boot_port_us() - t0;
    CHECK(dt >= 10000u && dt <= 10010u);
    CHECK_EQ_U32(fake_can1.sTxMailBox[0].TIR | fake_can1.sTxMailBox[1].TIR | fake_can1.sTxMailBox[2].TIR, 0);
}
static void test_send_refuses_a_stopped_bus_and_long_frames(void) {
    setup(); fake_can1.TSR = CAN_TSR_TME; fake_can1.MSR = CAN_MSR_INAK; fake_on_clock_read = 0;
    static const uint8_t d[9] = {0};
    uint32_t t0 = udsota_boot_port_us();
    CHECK(!f1_bxcan_send(CAN1, 0x718, d, 8, 10000)); CHECK(udsota_boot_port_us() - t0 <= 5u);
    fake_can1.MSR = 0; CHECK(!f1_bxcan_send(CAN1, 0x718, d, 9, 10000));
    CHECK_EQ_U32(fake_can1.sTxMailBox[0].TIR, 0);
}
static void test_recv_clamps_dlc_and_releases(void) {
    setup(); f1_can_frame_t f;
    fake_can1.RF0R = 1; fake_can1.sFIFOMailBox[0].RIR = 0xE2000000u; fake_can1.sFIFOMailBox[0].RDTR = 0xFu;
    fake_can1.sFIFOMailBox[0].RDLR = 0x44332211u; fake_can1.sFIFOMailBox[0].RDHR = 0x88776655u;
    CHECK(f1_bxcan_recv(CAN1, 0, &f));
    CHECK_EQ_U32(f.id, 0x710); CHECK_EQ_U32(f.len, 8); CHECK_EQ_U32(f.data[0], 0x11); CHECK_EQ_U32(f.data[7], 0x88);
    CHECK_EQ_U32(fake_can1.RF0R, CAN_RF0R_RFOM0);
}
static void test_recv_fifo1(void) {
    setup(); f1_can_frame_t f;
    fake_can2.RF1R = 2; fake_can2.sFIFOMailBox[1].RIR = 0xE2000000u; fake_can2.sFIFOMailBox[1].RDTR = 3u;
    CHECK(f1_bxcan_recv(CAN2, 1, &f)); CHECK_EQ_U32(f.len, 3); CHECK_EQ_U32(fake_can2.RF1R, CAN_RF1R_RFOM1);
}
static void test_recv_empty(void) {
    setup(); f1_can_frame_t f; CHECK(!f1_bxcan_recv(CAN1, 0, &f)); CHECK_EQ_U32(fake_can1.RF0R, 0);
}
static void test_recv_drops_remote_and_extended_frames(void) {
    setup(); f1_can_frame_t f;
    fake_can1.RF0R = 1; fake_can1.sFIFOMailBox[0].RIR = 0xE2000000u | CAN_RI0R_RTR;
    CHECK(!f1_bxcan_recv(CAN1, 0, &f)); CHECK_EQ_U32(fake_can1.RF0R, CAN_RF0R_RFOM0);
    fake_can1.RF0R = 1; fake_can1.sFIFOMailBox[0].RIR = 0xE2000000u | CAN_RI0R_IDE;
    CHECK(!f1_bxcan_recv(CAN1, 0, &f)); CHECK_EQ_U32(fake_can1.RF0R, CAN_RF0R_RFOM0);
}

int main(void)
{
    test_start_can1_filters_0x710_data_frames();
    test_start_can2_uses_can1_bank_14();
    test_start_on_a_bus_that_is_not_idle_leaves_the_controller_to_join();
    test_rejoin_asks_again_only_while_the_controller_has_not_joined();
    test_start_that_never_enters_init_fails();
    test_start_waits_only_to_enter_init();
    test_start_refuses_bad_arguments();
    test_stop_requests_init_aborts_mailboxes_and_touches_no_clock();
    test_send_fills_the_mailbox_code_names();
    test_send_short_frame_reads_only_len_bytes();
    test_send_with_no_empty_mailbox_times_out();
    test_send_refuses_a_stopped_bus_and_long_frames();
    test_recv_clamps_dlc_and_releases();
    test_recv_fifo1();
    test_recv_empty();
    test_recv_drops_remote_and_extended_frames();
    CHECK_DONE();
}
