/* The STM32F1 port's pure helpers, defined in udsota_port_stm32f1.c and declared here for its host tests.
   Nothing here touches a register. */
#ifndef F1_INTERNAL_H
#define F1_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>
#include "udsota_boot.h"

/* Microseconds in CYCCNT's advance from *last_cycles to now_cycles at core_hz, wrap included, the remainder carried in
   *rem_cycles; stores now_cycles in *last_cycles. Below 1 MHz it counts one cycle a microsecond. No 64-bit division. */
uint32_t f1_us_advance(uint32_t *last_cycles, uint32_t *rem_cycles, uint32_t now_cycles, uint32_t core_hz);

/* The cause in an RCC_CSR value: POWER_ON when PORRSTF is set, PIN when PINRSTF is the only other flag, else OTHER. */
udsota_boot_reset_t f1_reset_cause(uint32_t rcc_csr);

/* IWDG PR and RLR for period_ms at the nominal 40 kHz LSI: the smallest prescaler that fits, clamped to the longest. */
void f1_iwdg_settings(uint32_t period_ms, uint32_t *pr, uint32_t *rlr);

/* True when [off, off + len) is not empty, does not wrap past 2^32 and ends within UDSOTA_F1_SLOT_SIZE: the port's own
   guard on every flash write, whatever the core asks. */
bool f1_range_in_slot(uint32_t off, uint32_t len);

/* The number of pages that start in [off, off + len), offsets from the slot's start; the first one's offset goes to
   *first_off only when there is one. Only for a range f1_range_in_slot accepts. */
uint32_t f1_pages_starting_in(uint32_t off, uint32_t len, uint32_t *first_off);

#endif /* F1_INTERNAL_H */
