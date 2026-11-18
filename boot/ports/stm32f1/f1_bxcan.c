/* A polled bxCAN helper for a bootloader on the STM32F1 (f1_bxcan.h). CMSIS register access only, no ST HAL and no
   interrupts. Each function takes one deadline, wait_us after its entry, before its first register access, and every
   wait in that call ends at it [registers and bits: stm32f105xc.h:286-310, :5368-5911]. */
#include "f1_bxcan.h"
#include "udsota_boot.h"

#define F1_BXCAN_BANKS 28u   /* filter banks 0 to 27, shared by CAN1 and CAN2 [RM0008 p654] */
#define F1_BXCAN_CAN2SB 14u  /* CAN2's first bank */
#define F1_BXCAN_ABORT_ALL (CAN_TSR_ABRQ0 | CAN_TSR_ABRQ1 | CAN_TSR_ABRQ2)

/* Polls until (*reg & mask) == want; false once wait_us have passed since t0. */
static bool f1_bxcan_wait(const volatile uint32_t *reg, uint32_t mask, uint32_t want, uint32_t t0, uint32_t wait_us)
{
    while ((*reg & mask) != want) {
        if (udsota_boot_port_us() - t0 >= wait_us) {
            return false;
        }
    }
    return true;
}

/* Configures the controller and asks it to join the bus, without waiting for it to: leaving initialisation mode
   needs 11 recessive bits, so a bus held dominant keeps INAK set [RM0008 p656-657]. The manual gives that wait no
   timeout, so the request is left standing for the controller to join once the bus goes idle; that reading has not
   been tried on a board, which is why the board calls f1_bxcan_rejoin while INAK stays set. Until the controller
   joins, f1_bxcan_send refuses. */
bool f1_bxcan_start(CAN_TypeDef *can, uint32_t btr, uint8_t filter_bank, uint8_t fifo, uint16_t std_id,
                    uint32_t wait_us)
{
    if (filter_bank >= F1_BXCAN_BANKS || fifo > 1u || std_id > 0x7FFu) {
        return false;
    }
    uint32_t t0 = udsota_boot_port_us();
    uint32_t bank = 1u << filter_bank;

    /* Out of sleep and into initialisation [RM0008 p656-657, p674-677]. */
    can->MCR = (can->MCR & ~CAN_MCR_SLEEP) | CAN_MCR_INRQ;
    if (!f1_bxcan_wait(&can->MSR, CAN_MSR_INAK | CAN_MSR_SLAK, CAN_MSR_INAK, t0, wait_us)) {
        can->MCR |= CAN_MCR_INRQ;
        return false;
    }

    /* TXFP sends mailboxes in request order, which ISO-TP consecutive frames need. ABOM lets the controller leave
       bus-off by itself: nothing in a bootloader restarts a bus that went bus-off, and a unit that sits in it would
       stay deaf there until reset. NART, AWUM, RFLM and TTCM stay clear [RM0008 p675]. */
    can->MCR = (can->MCR & CAN_MCR_DBF) | CAN_MCR_INRQ | CAN_MCR_TXFP | CAN_MCR_ABOM;
    can->IER = 0u;
    can->BTR = btr;
    can->TSR = F1_BXCAN_ABORT_ALL;

    /* The filters live in CAN1's registers whatever can is [RM0008 p654, p691-694]. One 32-bit mask-mode bank whose
       mask covers STID, IDE and RTR, so only standard data frames on std_id pass, as the RIR layout fixes
       [RM0008 p665; stm32f105xc.h:5800-5810]. */
    CAN1->FMR |= CAN_FMR_FINIT;
#ifdef CAN_FMR_CAN2SB
    CAN1->FMR = (CAN1->FMR & ~CAN_FMR_CAN2SB) | (F1_BXCAN_CAN2SB << CAN_FMR_CAN2SB_Pos);
#endif
    CAN1->FA1R &= ~bank;
    CAN1->FS1R |= bank;
    CAN1->FM1R &= ~bank;
    if (fifo != 0u) {
        CAN1->FFA1R |= bank;
    } else {
        CAN1->FFA1R &= ~bank;
    }
    CAN1->sFilterRegister[filter_bank].FR1 = (uint32_t)std_id << CAN_RI0R_STID_Pos;
    CAN1->sFilterRegister[filter_bank].FR2 = CAN_RI0R_STID | CAN_RI0R_IDE | CAN_RI0R_RTR;
    CAN1->FA1R |= bank;
    CAN1->FMR &= ~CAN_FMR_FINIT;

    can->MCR &= ~CAN_MCR_INRQ;
    return true;
}

/* INAK still set on a started controller means it is still waiting for the bus to go idle [RM0008 p657, p677].
   The manual states no timeout on that wait and does not say the request stands for ever, so it is made again: INRQ
   set and cleared, the sequence it gives for leaving bus-off by hand [p670]. It does not describe doing so during
   the wait; the configuration registers are kept [p657]. */
bool f1_bxcan_rejoin(CAN_TypeDef *can)
{
    if ((can->MSR & CAN_MSR_INAK) == 0u) {
        return false;
    }
    can->MCR |= CAN_MCR_INRQ;
    can->MCR &= ~CAN_MCR_INRQ;
    return true;
}

/* Aborting the mailboxes means no pending frame is sent after a later restart [RM0008 p677-679]. */
void f1_bxcan_stop(CAN_TypeDef *can)
{
    can->MCR |= CAN_MCR_INRQ;
    can->TSR = F1_BXCAN_ABORT_ALL;
}

/* CODE names the next empty mailbox while any TME is set [RM0008 p678]; TDTR, the data, then TIR with TXRQ last
   [stm32f105xc.h:5632-5650; RM0008 p685-686]. */
bool f1_bxcan_send(CAN_TypeDef *can, uint16_t std_id, const uint8_t *data, uint8_t len, uint32_t wait_us)
{
    if (len > 8u) {
        return false;
    }
    uint32_t t0 = udsota_boot_port_us();
    if ((can->MSR & CAN_MSR_INAK) != 0u) {
        return false;
    }
    while ((can->TSR & CAN_TSR_TME) == 0u) {
        if (udsota_boot_port_us() - t0 >= wait_us) {
            return false;
        }
    }
    uint32_t box = (can->TSR & CAN_TSR_CODE) >> CAN_TSR_CODE_Pos;
    if (box > 2u) {
        return false;                                  /* not a mailbox: CODE has four values for three */
    }

    uint32_t lo = 0u, hi = 0u;
    for (uint32_t i = 0u; i < len; i++) {
        if (i < 4u) {
            lo |= (uint32_t)data[i] << (8u * i);
        } else {
            hi |= (uint32_t)data[i] << (8u * (i - 4u));
        }
    }
    can->sTxMailBox[box].TDTR = len;
    can->sTxMailBox[box].TDLR = lo;
    can->sTxMailBox[box].TDHR = hi;
    can->sTxMailBox[box].TIR = ((uint32_t)std_id << CAN_TI0R_STID_Pos) | CAN_TI0R_TXRQ;
    return true;
}

/* At most the FIFO's three frames. The release is a plain store of RFOM: FMP is read-only, and FULL and FOVR clear only
   on a 1 [RM0008 p679-680]. The output mailbox's ID, DLC and data [RM0008 p688-689]. */
bool f1_bxcan_recv(CAN_TypeDef *can, uint8_t fifo, f1_can_frame_t *out)
{
    if (fifo > 1u) {
        return false;
    }
    volatile uint32_t *rfr = (fifo != 0u) ? &can->RF1R : &can->RF0R;
    uint32_t fmp = (fifo != 0u) ? CAN_RF1R_FMP1 : CAN_RF0R_FMP0;
    uint32_t rfom = (fifo != 0u) ? CAN_RF1R_RFOM1 : CAN_RF0R_RFOM0;

    for (int n = 0; n < 3; n++) {
        if ((*rfr & fmp) == 0u) {
            return false;
        }
        uint32_t rir = can->sFIFOMailBox[fifo].RIR;
        uint32_t dlc = can->sFIFOMailBox[fifo].RDTR & CAN_RDT0R_DLC;
        uint32_t lo = can->sFIFOMailBox[fifo].RDLR;
        uint32_t hi = can->sFIFOMailBox[fifo].RDHR;
        *rfr = rfom;
        if ((rir & (CAN_RI0R_IDE | CAN_RI0R_RTR)) != 0u) {
            continue;
        }
        out->id = (uint16_t)(rir >> CAN_RI0R_STID_Pos);
        out->len = (uint8_t)((dlc > 8u) ? 8u : dlc);
        for (uint32_t i = 0u; i < 4u; i++) {
            out->data[i] = (uint8_t)(lo >> (8u * i));
            out->data[i + 4u] = (uint8_t)(hi >> (8u * i));
        }
        return true;
    }
    return false;
}
