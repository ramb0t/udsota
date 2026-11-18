/* Host stand-in for the CMSIS device header: the real types and bit names, peripheral instances in RAM.
   test/boot/stm32f1/fake_cmsis/fake_cmsis.c is the one file that defines every object declared here, and SystemCoreClock. */
#ifndef FAKE_CMSIS_STM32F1XX_H
#define FAKE_CMSIS_STM32F1XX_H
#include_next <stm32f1xx.h>

/* One IWDG key as fake_iwdg() saw it, with the PR and RLR that held at the next access. */
typedef struct { uint32_t kr, pr, rlr; } fake_iwdg_entry_t;

extern RCC_TypeDef fake_rcc;
extern BKP_TypeDef fake_bkp;
extern DBGMCU_TypeDef fake_dbgmcu;
extern IWDG_TypeDef fake_iwdg_regs;
extern fake_iwdg_entry_t fake_iwdg_log[16];
extern unsigned fake_iwdg_log_len;
extern DWT_Type fake_dwt_regs;
extern uint32_t fake_cycles_per_read;   /* added to CYCCNT on every DWT access */
extern uint8_t fake_uid[12];
extern unsigned fake_system_resets;
extern FLASH_TypeDef fake_flash_regs;
extern uint8_t fake_slot[UDSOTA_F1_SLOT_SIZE] __attribute__((aligned(4)));  /* the slot, in RAM */
extern unsigned fake_flash_accesses;    /* every FLASH access, so a refusal can show it touched nothing */
extern uint32_t fake_flash_erased[8];   /* AR of each page erase started */
extern unsigned fake_flash_erased_len;
extern uint32_t fake_flash_keys[8];     /* each new KEYR value */
extern unsigned fake_flash_keys_len;
extern uint32_t fake_flash_error;       /* ORed into SR with EOP when an erase or a program ends */
extern int fake_flash_bsy_stuck;        /* BSY never clears and nothing completes */
extern int fake_flash_keys_ignored;     /* the right keys leave LOCK set */
extern CAN_TypeDef fake_can1, fake_can2;
extern void (*fake_on_clock_read)(void);  /* when set, fake_dwt() calls it after advancing CYCCNT: hardware that changes */
extern GPIO_TypeDef fake_gpioa, fake_gpiob, fake_gpioc, fake_gpiod;
extern AFIO_TypeDef fake_afio;
extern SPI_TypeDef fake_spi1;
extern PWR_TypeDef fake_pwr;
extern CoreDebug_Type fake_coredebug;

RCC_TypeDef *fake_rcc_access(void);   /* applies RMVF, then returns &fake_rcc */
IWDG_TypeDef *fake_iwdg(void);        /* logs a new key, then returns &fake_iwdg_regs */
DWT_Type *fake_dwt(void);             /* advances CYCCNT, calls fake_on_clock_read, then returns &fake_dwt_regs */
FLASH_TypeDef *fake_flash(void);      /* acts on the keys and on CR as the controller would, then returns &fake_flash_regs */
void fake_nvic_system_reset(void);    /* counts the reset and returns */
void fake_cmsis_reset(void);          /* zeroes every fake, locks the flash, erases fake_slot, clears the clock hook;
                                         72 cycles a read at 72 MHz */

#undef RCC
#define RCC (fake_rcc_access())
#undef BKP
#define BKP (&fake_bkp)
#undef DBGMCU
#define DBGMCU (&fake_dbgmcu)
#undef IWDG
#define IWDG (fake_iwdg())
#undef DWT
#define DWT (fake_dwt())
#undef UID_BASE
#define UID_BASE ((uintptr_t)fake_uid)
#undef NVIC_SystemReset
#define NVIC_SystemReset fake_nvic_system_reset
#undef FLASH
#define FLASH (fake_flash())
#undef CAN1
#define CAN1 (&fake_can1)
#undef CAN2
#define CAN2 (&fake_can2)
#undef GPIOA
#define GPIOA (&fake_gpioa)
#undef GPIOB
#define GPIOB (&fake_gpiob)
#undef GPIOC
#define GPIOC (&fake_gpioc)
#undef GPIOD
#define GPIOD (&fake_gpiod)
#undef AFIO
#define AFIO (&fake_afio)
#undef SPI1
#define SPI1 (&fake_spi1)
#undef PWR
#define PWR (&fake_pwr)
#undef CoreDebug
#define CoreDebug (&fake_coredebug)
#define F1_SLOT_ADDR ((uintptr_t)fake_slot)   /* the port's slot pointer and programming address */
#endif
