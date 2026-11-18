/* A polled bxCAN helper for a bootloader on the STM32F1: start, stop, send and receive standard data frames on CMSIS
   registers, with no interrupts and no ST HAL. Every wait is bounded by udsota_boot_port_us(). The board enables the
   controller's clock (CAN2 needs CAN1's too) and its pins before f1_bxcan_start. */
#ifndef F1_BXCAN_H
#define F1_BXCAN_H
#include "stm32f1xx.h"
#include <stdbool.h>
#include <stdint.h>

/* A standard data frame: an 11-bit ID and up to 8 bytes. */
typedef struct {
    uint16_t id;
    uint8_t len;
    uint8_t data[8];
} f1_can_frame_t;

/* Enters initialisation mode, sets btr and normal operation with transmit mailboxes sent in request order, points
   filter bank filter_bank (CAN1's banks, whatever can is) at fifo so that only standard data frames on std_id pass,
   then asks to leave initialisation mode and returns without waiting for the bus: the controller joins once it has
   seen the bus idle, with bus-off recovery automatic from then on. wait_us bounds the wait to enter initialisation
   mode, the only one. False, with initialisation still requested, when that wait runs out; false without touching a
   register when filter_bank > 27, fifo > 1 or std_id > 0x7FF. */
bool f1_bxcan_start(CAN_TypeDef *can, uint32_t btr, uint8_t filter_bank, uint8_t fifo, uint16_t std_id,
                    uint32_t wait_us);

/* Asks a started controller once more to join the bus when it has not yet: true when it asked, false and nothing
   written when the controller has joined. It touches no filter, so it cannot disturb the other controller. */
bool f1_bxcan_rejoin(CAN_TypeDef *can);

/* Requests initialisation mode and aborts every pending mailbox, without waiting. Leaves clocks and filters alone. */
void f1_bxcan_stop(CAN_TypeDef *can);

/* Queues one frame of len bytes from data in the next empty mailbox, waiting up to wait_us for one. False when
   len > 8, when the controller is in initialisation mode, or when no mailbox empties in time. */
bool f1_bxcan_send(CAN_TypeDef *can, uint16_t std_id, const uint8_t *data, uint8_t len, uint32_t wait_us);

/* Takes the next standard data frame from fifo (0 or 1) into *out, releasing every frame it reads and dropping remote
   and extended ones. False when the FIFO holds no such frame. Never waits. */
bool f1_bxcan_recv(CAN_TypeDef *can, uint8_t fifo, f1_can_frame_t *out);

#endif /* F1_BXCAN_H */
