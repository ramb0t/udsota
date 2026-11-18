/* The one definition of each fake register object in test/boot/stm32f1/fake_cmsis/stm32f1xx.h, and of SystemCoreClock */
#include <string.h>
#include <stm32f1xx.h>   /* angle form, so that the header's include_next moves past test/boot/stm32f1/fake_cmsis */

RCC_TypeDef fake_rcc;
BKP_TypeDef fake_bkp;
DBGMCU_TypeDef fake_dbgmcu;
IWDG_TypeDef fake_iwdg_regs;
fake_iwdg_entry_t fake_iwdg_log[16];
unsigned fake_iwdg_log_len;
DWT_Type fake_dwt_regs;
uint32_t fake_cycles_per_read;
uint8_t fake_uid[12];
unsigned fake_system_resets;
FLASH_TypeDef fake_flash_regs;
uint8_t fake_slot[UDSOTA_F1_SLOT_SIZE] __attribute__((aligned(4)));
unsigned fake_flash_accesses;
uint32_t fake_flash_erased[8];
unsigned fake_flash_erased_len;
uint32_t fake_flash_keys[8];
unsigned fake_flash_keys_len;
uint32_t fake_flash_error;
int fake_flash_bsy_stuck;
int fake_flash_keys_ignored;
CAN_TypeDef fake_can1, fake_can2;
void (*fake_on_clock_read)(void);
GPIO_TypeDef fake_gpioa, fake_gpiob, fake_gpioc, fake_gpiod;
AFIO_TypeDef fake_afio;
SPI_TypeDef fake_spi1;
PWR_TypeDef fake_pwr;
CoreDebug_Type fake_coredebug;
uint32_t SystemCoreClock;

/* RMVF clears itself and every reset flag, bits 24 to 31 [RM0008 p152], so a later read of CSR sees none. */
RCC_TypeDef *fake_rcc_access(void)
{
    if (fake_rcc.CSR & RCC_CSR_RMVF) {
        fake_rcc.CSR &= 0x00FFFFFFu;
    }
    return &fake_rcc;
}

/* Runs before each access, so an entry holds a key with the PR and RLR written after it. */
IWDG_TypeDef *fake_iwdg(void)
{
    unsigned n = fake_iwdg_log_len;
    uint32_t kr = fake_iwdg_regs.KR;
    int append = (n == 0) ? (kr != 0u) : (kr != fake_iwdg_log[n - 1u].kr);

    if (append && n < sizeof fake_iwdg_log / sizeof fake_iwdg_log[0]) {
        fake_iwdg_log[n].kr = kr;
        fake_iwdg_log[n].pr = fake_iwdg_regs.PR;
        fake_iwdg_log[n].rlr = fake_iwdg_regs.RLR;
        fake_iwdg_log_len = n + 1u;
    }
    return &fake_iwdg_regs;
}

DWT_Type *fake_dwt(void)
{
    fake_dwt_regs.CYCCNT += fake_cycles_per_read;
    if (fake_on_clock_read != NULL) {
        fake_on_clock_read();
    }
    return &fake_dwt_regs;
}

/* Runs before each access, so it acts on what the previous access wrote: a new key is logged and KEY1 then KEY2 unlock;
   a started page erase fills the page with 0xFF and ends; a program ends at once. SR gets EOP with fake_flash_error,
   and while fake_flash_bsy_stuck gets BSY and nothing ends. */
FLASH_TypeDef *fake_flash(void)
{
    unsigned n = fake_flash_keys_len;
    uint32_t key = fake_flash_regs.KEYR;
    int append = (n == 0) ? (key != 0u) : (key != fake_flash_keys[n - 1u]);

    fake_flash_accesses++;
    if (append && n < sizeof fake_flash_keys / sizeof fake_flash_keys[0]) {
        fake_flash_keys[n++] = key;
        fake_flash_keys_len = n;
        if (n >= 2u && fake_flash_keys[n - 2u] == FLASH_KEY1 && fake_flash_keys[n - 1u] == FLASH_KEY2
            && !fake_flash_keys_ignored) {
            fake_flash_regs.CR &= ~FLASH_CR_LOCK;
        }
    }
    if (fake_flash_bsy_stuck) {
        fake_flash_regs.SR |= FLASH_SR_BSY;
        return &fake_flash_regs;
    }
    if ((fake_flash_regs.CR & FLASH_CR_STRT) && (fake_flash_regs.CR & FLASH_CR_PER)) {
        uint32_t off = fake_flash_regs.AR - UDSOTA_F1_SLOT_BASE;
        if (fake_flash_erased_len < sizeof fake_flash_erased / sizeof fake_flash_erased[0]) {
            fake_flash_erased[fake_flash_erased_len++] = fake_flash_regs.AR;
        }
        if (off < UDSOTA_F1_SLOT_SIZE) {
            memset(fake_slot + (off - off % UDSOTA_F1_PAGE_SIZE), 0xFF, UDSOTA_F1_PAGE_SIZE);
        }
        fake_flash_regs.CR &= ~FLASH_CR_STRT;
        fake_flash_regs.SR = FLASH_SR_EOP | fake_flash_error;
    } else if (fake_flash_regs.CR & FLASH_CR_PG) {
        fake_flash_regs.SR = FLASH_SR_EOP | fake_flash_error;
    }
    return &fake_flash_regs;
}

void fake_nvic_system_reset(void)
{
    fake_system_resets++;
}

void fake_cmsis_reset(void)
{
    memset(&fake_rcc, 0, sizeof fake_rcc);
    memset(&fake_bkp, 0, sizeof fake_bkp);
    memset(&fake_dbgmcu, 0, sizeof fake_dbgmcu);
    memset(&fake_iwdg_regs, 0, sizeof fake_iwdg_regs);
    memset(fake_iwdg_log, 0, sizeof fake_iwdg_log);
    fake_iwdg_log_len = 0;
    memset(&fake_dwt_regs, 0, sizeof fake_dwt_regs);
    memset(fake_uid, 0, sizeof fake_uid);
    fake_system_resets = 0;
    memset(&fake_flash_regs, 0, sizeof fake_flash_regs);
    fake_flash_regs.CR = FLASH_CR_LOCK;
    memset(fake_slot, 0xFF, sizeof fake_slot);
    fake_flash_accesses = 0;
    memset(fake_flash_erased, 0, sizeof fake_flash_erased);
    fake_flash_erased_len = 0;
    memset(fake_flash_keys, 0, sizeof fake_flash_keys);
    fake_flash_keys_len = 0;
    fake_flash_error = 0;
    fake_flash_bsy_stuck = 0;
    fake_flash_keys_ignored = 0;
    memset(&fake_can1, 0, sizeof fake_can1);
    memset(&fake_can2, 0, sizeof fake_can2);
    memset(&fake_gpioa, 0, sizeof fake_gpioa);
    memset(&fake_gpiob, 0, sizeof fake_gpiob);
    memset(&fake_gpioc, 0, sizeof fake_gpioc);
    memset(&fake_gpiod, 0, sizeof fake_gpiod);
    memset(&fake_afio, 0, sizeof fake_afio);
    memset(&fake_spi1, 0, sizeof fake_spi1);
    memset(&fake_pwr, 0, sizeof fake_pwr);
    memset(&fake_coredebug, 0, sizeof fake_coredebug);
    fake_on_clock_read = NULL;
    fake_cycles_per_read = 72u;
    SystemCoreClock = 72000000u;
}
