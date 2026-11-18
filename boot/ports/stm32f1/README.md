# udsota port for STM32F1

udsota's boot port for STM32F1 parts with memory-mapped flash and bxCAN, on CMSIS registers with no ST HAL. It is
udsota's `boot/ports/stm32f1/`, so nothing in it names a product, a board, its pins or its buses.

## Building it

A product compiles `udsota_port_stm32f1.c`, `udsota_port_stm32f1_start.c` and `f1_bxcan.c` with this directory on
the include path, and defines `UDSOTA_F1_SLOT_BASE`, `UDSOTA_F1_SLOT_SIZE` and `UDSOTA_F1_PAGE_SIZE`. The slot must
start and end on a page boundary, or the build fails. Its bounds are the port's own: the port refuses any erase or
program outside them whatever the core asks, independently of the core's configuration. The build also defines the
device macro that `stm32f1xx.h` needs (`STM32F105xC`, for example) and puts on the include path the CMSIS device and
core headers, udsota's root (for `udsota_wire.h`, which `udsota_boot.h` includes) and udsota's `boot/`.
`udsota_port_stm32f1_start.c` uses Cortex-M3 instructions and builds for the target only.

## Before `udsota_boot_init`

The port's clock is DWT's cycle counter at `SystemCoreClock`. The board therefore enables the counter (TRCENA in
DEMCR, then CYCCNTENA in DWT_CTRL), and sets `SystemCoreClock` to the real core clock before the first
`udsota_boot_port_us()` call: `system_stm32f1xx.c` starts it at 16 MHz while HSI runs at 8 MHz. It keeps the value
true through every clock switch. The keep words are BKP_DR1 to DR3, so the board enables the PWR and BKP clocks and
sets `DBP`. It sets the flash latency for its clock, and leaves HSI on, which the port assumes during flash erase and
program. It also resets every CAN controller it owns that a system reset does not reach, such as one on SPI.

## Bounds

Every wait reads `udsota_boot_port_us()` and has a bound: 1 ms for the watchdog's register update, 200 ms for each
page erase, 1 ms for each half-word program and 2 ms for each clock wait in `start_app`. A watchdog started by the
option bytes (hardware mode) allows about 273 ms from reset, so each of these fits inside one reload, and so must every
wait the board adds.

## `f1_bxcan`

`f1_bxcan.h` starts, stops, sends and receives on a bxCAN controller by polling, with no interrupts. The board enables
the controller's clock and pins before `f1_bxcan_start`; CAN2 needs CAN1's clock as well, since the filters live in
CAN1's registers. CAN1 takes banks 0 to 13 and CAN2 banks from 14, and `f1_bxcan_start` sets that split. Each start
points one bank at one FIFO and passes only standard data frames on one ID; its `wait_us` bounds the whole call, and
when it runs out the controller is left requesting initialisation. `f1_bxcan_stop` requests initialisation mode and
aborts the pending mailboxes, without waiting and without touching a clock or the filters. `f1_bxcan_send` sends
mailboxes in request order, as ISO-TP needs. `f1_bxcan_recv` never waits, and it releases and drops remote and
extended frames.

## What `start_app` leaves

`udsota_boot_port_start_app` disables interrupts, stops SysTick, disables and unpends every NVIC line and clears the
SysTick and PendSV pending bits. It clears EXTI, which has no reset bit. It puts the system clock on HSI (and
`SystemCoreClock` at 8 MHz), stops HSE, CSS and the PLLs, and returns CFGR, CIR and CFGR2 to their reset values. It
pulses every APB peripheral through reset except BKP and PWR, so the keep words survive, and returns the clock enables
to their reset values. It then sets VTOR to the slot, clears BASEPRI, FAULTMASK and CONTROL, loads MSP from the app's
vector table and jumps to its reset handler with interrupts enabled. The watchdog, DBGMCU_CR, the BKP data registers,
PWR_CR and FLASH_ACR are left as they are; a flash latency of 2 on HSI is only slower.

The reset masks are built from the device header's `RCC_APB1RSTR_*` and `RCC_APB2RSTR_*` names, a missing name
counting as 0, and a static assertion pins them for `STM32F105xC`. A port to an F1 part with other peripherals checks
those names against its device header.

## Tests

The host tests build the port against `test/boot/stm32f1/fake_cmsis/`, a stand-in for `stm32f1xx.h` with the real
types and bit names but the peripherals in RAM, and run with `ctest --test-dir build -R 'port_f1|f1_bxcan'` after
`cmake -S . -B build` and `cmake --build build`. `start_app` is target only, so no host test covers it.
