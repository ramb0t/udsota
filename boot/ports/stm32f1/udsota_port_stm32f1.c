/* udsota's boot port for the STM32F1: the clock, the reset cause, the keep words, the watchdog, the reset, the
   device ID, and the slot with its page erase and half-word programming. CMSIS register access only, no ST HAL; the
   product supplies the slot macros below and keeps SystemCoreClock true. */
#include "stm32f1xx.h"
#include "f1_internal.h"
#include <string.h>

#if !defined(UDSOTA_F1_SLOT_BASE) || !defined(UDSOTA_F1_SLOT_SIZE) || !defined(UDSOTA_F1_PAGE_SIZE)
#error "the product's build defines UDSOTA_F1_SLOT_BASE, UDSOTA_F1_SLOT_SIZE and UDSOTA_F1_PAGE_SIZE (README.md)"
#endif
#if (UDSOTA_F1_SLOT_BASE % UDSOTA_F1_PAGE_SIZE) != 0 || (UDSOTA_F1_SLOT_SIZE % UDSOTA_F1_PAGE_SIZE) != 0
#error "the slot must start and end on a flash page boundary"
#endif
#ifndef F1_SLOT_ADDR
#define F1_SLOT_ADDR ((uintptr_t)UDSOTA_F1_SLOT_BASE)   /* host tests point it at RAM; FLASH->AR always gets the real address */
#endif

/* IWDG keys [RM0008 p496 IWDG_KR]; they have no CMSIS name. */
#define F1_IWDG_KEY_START  0xCCCCu
#define F1_IWDG_KEY_ACCESS 0x5555u
#define F1_IWDG_KEY_RELOAD 0xAAAAu

/* The bound on the wait for PVU and RVU. An update takes up to 5 cycles of the LSI, 167 us at 30 kHz [RM0008 p497]. */
#define F1_IWDG_WAIT_US 1000u

/* The LSI's nominal 40 kHz in cycles a millisecond, and the longest period that fits: PR 6 (/256) with a quotient of
   4096 [RM0008 p497: PR 3 is /32, RLR is 12 bits]. */
#define F1_LSI_PER_MS       40u
#define F1_IWDG_PR_MAX      6u
#define F1_IWDG_RLR_MAX     0xFFFu
#define F1_IWDG_MAX_MS      26220u

/* The bounds on the wait for BSY. An erase: five times the datasheet's 40 ms for a 1 KB page, under the 273 ms a
   hardware-mode watchdog allows [STM32F105xx/107xx datasheet p53 tERASE; boot/README.md "STM32F1 watchdog"]; the 2 KB
   time is measured on the bench. A half-word program: 40 to 70 us [datasheet p53 tprog]. */
#define F1_ERASE_WAIT_US   200000u
#define F1_PROGRAM_WAIT_US 1000u

/* ---- Pure helpers (f1_internal.h) ---- */

uint32_t f1_us_advance(uint32_t *last_cycles, uint32_t *rem_cycles, uint32_t now_cycles, uint32_t core_hz)
{
    uint32_t per_us = core_hz / 1000000u;
    if (per_us == 0u) {
        per_us = 1u;
    }
    uint32_t delta = now_cycles - *last_cycles;   /* unsigned: a CYCCNT wrap is a small difference */
    uint32_t us = delta / per_us;
    uint32_t carry = delta % per_us + *rem_cycles; /* both below per_us, so no overflow */
    us += carry / per_us;
    *rem_cycles = carry % per_us;
    *last_cycles = now_cycles;
    return us;
}

/* [RM0008 p152-153; stm32f105xc.h:1836-1852] */
udsota_boot_reset_t f1_reset_cause(uint32_t rcc_csr)
{
    const uint32_t others = RCC_CSR_SFTRSTF | RCC_CSR_IWDGRSTF | RCC_CSR_WWDGRSTF | RCC_CSR_LPWRRSTF;

    if (rcc_csr & RCC_CSR_PORRSTF) {
        return UDSOTA_BOOT_RESET_POWER_ON;
    }
    if ((rcc_csr & RCC_CSR_PINRSTF) && !(rcc_csr & others)) {
        return UDSOTA_BOOT_RESET_PIN;
    }
    return UDSOTA_BOOT_RESET_OTHER;
}

void f1_iwdg_settings(uint32_t period_ms, uint32_t *pr, uint32_t *rlr)
{
    if (period_ms <= F1_IWDG_MAX_MS) {                /* clamp first: period_ms * 40 stays in 32 bits */
        uint32_t count = period_ms * F1_LSI_PER_MS;
        for (uint32_t p = 0u; p <= F1_IWDG_PR_MAX; p++) {
            uint32_t q = count / (4u << p);
            if (q <= F1_IWDG_RLR_MAX + 1u) {
                *pr = p;
                *rlr = (q == 0u) ? 0u : q - 1u;
                return;
            }
        }
    }
    *pr = F1_IWDG_PR_MAX;
    *rlr = F1_IWDG_RLR_MAX;
}

bool f1_range_in_slot(uint32_t off, uint32_t len)
{
    /* off <= size first, so size - off cannot wrap; then len <= size - off means off + len neither wraps nor passes it */
    return len != 0u && off <= UDSOTA_F1_SLOT_SIZE && len <= UDSOTA_F1_SLOT_SIZE - off;
}

uint32_t f1_pages_starting_in(uint32_t off, uint32_t len, uint32_t *first_off)
{
    uint32_t end = off + len;                          /* no wrap: f1_range_in_slot accepted the range */
    uint32_t first = off - off % UDSOTA_F1_PAGE_SIZE;
    if (first < off) {
        first += UDSOTA_F1_PAGE_SIZE;                  /* the next page boundary at or after off */
    }
    if (first >= end) {
        return 0u;
    }
    *first_off = first;
    return (end - 1u - first) / UDSOTA_F1_PAGE_SIZE + 1u;
}

/* ---- Flash controller sequences, from ST's HAL since RM0008 p58-59 defers to PM0075 ---- */

/* KEY1 then KEY2 when LOCK is set; fails if LOCK still reads set [hal_flash.c:661-670; stm32f105xc.h:12457-12462,
   :12505-12507]. */
static bool f1_flash_unlock(void)
{
    if ((FLASH->CR & FLASH_CR_LOCK) != 0u) {
        FLASH->KEYR = FLASH_KEY1;
        FLASH->KEYR = FLASH_KEY2;
    }
    return (FLASH->CR & FLASH_CR_LOCK) == 0u;
}

/* Clears PER and PG, then sets LOCK [hal_flash.c:698]. */
static void f1_flash_lock(void)
{
    FLASH->CR &= ~(FLASH_CR_PER | FLASH_CR_PG);
    FLASH->CR |= FLASH_CR_LOCK;
}

/* Polls BSY until clear, bounded by bound_us; false when the bound passes first [hal_flash.c:826-843;
   stm32f105xc.h:12473-12475]. */
static bool f1_flash_wait(uint32_t bound_us)
{
    uint32_t t0 = udsota_boot_port_us();
    while ((FLASH->SR & FLASH_SR_BSY) != 0u) {
        if (udsota_boot_port_us() - t0 >= bound_us) {
            return false;
        }
    }
    return true;
}

/* Reads SR, writes back the EOP, PGERR and WRPRTERR bits it found set (write 1 to clear), and is false when PGERR or
   WRPRTERR was among them [hal_flash.c:846-858; Inc/stm32f1xx_hal_flash_ex.h:719-728; stm32f105xc.h:12476-12484]. */
static bool f1_flash_status_ok(void)
{
    uint32_t sr = FLASH->SR & (FLASH_SR_EOP | FLASH_SR_PGERR | FLASH_SR_WRPRTERR);
    FLASH->SR = sr;
    return (sr & (FLASH_SR_PGERR | FLASH_SR_WRPRTERR)) == 0u;
}

/* ---- Port functions (udsota_boot.h) ---- */

/* DWT's cycle counter at SystemCoreClock. The board enables the counter before udsota_boot_init. */
uint32_t udsota_boot_port_us(void)
{
    static uint32_t us, last, rem;
    us += f1_us_advance(&last, &rem, DWT->CYCCNT, SystemCoreClock);
    return us;
}

/* RMVF clears every reset flag [RM0008 p152]. */
udsota_boot_reset_t udsota_boot_port_reset_cause(void)
{
    uint32_t csr = RCC->CSR;
    RCC->CSR |= RCC_CSR_RMVF;
    return f1_reset_cause(csr);
}

/* Words 0 to 2 are BKP_DR1 to DR3, the low 16 bits [RM0008 p83, p85]. The board has enabled the PWR and BKP clocks
   and set DBP. */
uint16_t udsota_boot_port_keep_read(uint8_t word)
{
    switch (word) {
    case 0: return (uint16_t)BKP->DR1;
    case 1: return (uint16_t)BKP->DR2;
    case 2: return (uint16_t)BKP->DR3;
    default: return 0u;
    }
}

void udsota_boot_port_keep_write(uint8_t word, uint16_t value)
{
    switch (word) {
    case 0: BKP->DR1 = value; break;
    case 1: BKP->DR2 = value; break;
    case 2: BKP->DR3 = value; break;
    default: break;
    }
}

/* Stopped while a debugger halts the core [RM0008 p1102]. KR 0xCCCC, 0x5555, PR, RLR, a bounded wait for PVU and RVU,
   then the reload, whether or not the wait ended [RM0008 p494-498]. */
void udsota_boot_port_watchdog_start(uint32_t period_ms)
{
    uint32_t pr, rlr;
    f1_iwdg_settings(period_ms, &pr, &rlr);

    DBGMCU->CR |= DBGMCU_CR_DBG_IWDG_STOP;
    IWDG->KR = F1_IWDG_KEY_START;
    IWDG->KR = F1_IWDG_KEY_ACCESS;
    IWDG->PR = pr;
    IWDG->RLR = rlr;
    uint32_t t0 = udsota_boot_port_us();
    while ((IWDG->SR & (IWDG_SR_PVU | IWDG_SR_RVU)) != 0u && udsota_boot_port_us() - t0 < F1_IWDG_WAIT_US) {
    }
    IWDG->KR = F1_IWDG_KEY_RELOAD;
}

void udsota_boot_port_watchdog_reload(void)
{
    IWDG->KR = F1_IWDG_KEY_RELOAD;
}

void udsota_boot_port_reset(void)
{
    NVIC_SystemReset();
}

/* The 96-bit unique ID, in address order [RM0008 p1077]. */
size_t udsota_boot_port_device_id(uint8_t out[16])
{
    memcpy(out, (const uint8_t *)UID_BASE, 12u);
    return 12u;
}

/* The slot is mapped flash, so its address. */
const uint8_t *udsota_boot_port_slot(void)
{
    return (const uint8_t *)F1_SLOT_ADDR;
}

/* For each page that starts in the range: wait, PER, AR, STRT, wait, status, clear PER; stop at the first failure
   [hal_flash_ex.c:273-289, :1106-1108; stm32f105xc.h:12490-12504]. The watchdog is the core's to reload. */
bool udsota_boot_port_flash_erase(uint32_t off, uint32_t len)
{
    uint32_t page_off = 0u;

    if (!f1_range_in_slot(off, len)) {
        return false;
    }
    uint32_t pages = f1_pages_starting_in(off, len, &page_off);
    if (pages == 0u) {
        return true;
    }
    bool ok = f1_flash_unlock();
    if (ok) {
        (void)f1_flash_status_ok();                    /* drops stale flags */
    }
    for (uint32_t n = 0u; ok && n < pages; n++, page_off += UDSOTA_F1_PAGE_SIZE) {
        ok = f1_flash_wait(F1_ERASE_WAIT_US);
        if (ok) {
            FLASH->CR |= FLASH_CR_PER;
            FLASH->AR = (uint32_t)UDSOTA_F1_SLOT_BASE + page_off;
            FLASH->CR |= FLASH_CR_STRT;
            ok = f1_flash_wait(F1_ERASE_WAIT_US) && f1_flash_status_ok();
            FLASH->CR &= ~FLASH_CR_PER;
        }
    }
    f1_flash_lock();
    return ok;
}

/* For each half-word, as HAL does it: wait, PG, the write, wait, status, clear PG; stop at the first failure
   [hal_flash.c:214-226, :807]. The half-word is assembled from bytes, since data may be unaligned. */
bool udsota_boot_port_flash_program(uint32_t off, const void *data, uint32_t len)
{
    const uint8_t *d = data;

    if (!f1_range_in_slot(off, len) || (off % 2u) != 0u || (len % 2u) != 0u) {
        return false;
    }
    bool ok = f1_flash_unlock();
    if (ok) {
        (void)f1_flash_status_ok();                    /* drops stale flags */
    }
    for (uint32_t i = 0u; ok && i < len; i += 2u) {
        ok = f1_flash_wait(F1_PROGRAM_WAIT_US);
        if (ok) {
            FLASH->CR |= FLASH_CR_PG;
            *(volatile uint16_t *)(F1_SLOT_ADDR + off + i) = (uint16_t)(d[i] | (d[i + 1u] << 8));
            ok = f1_flash_wait(F1_PROGRAM_WAIT_US) && f1_flash_status_ok();
            FLASH->CR &= ~FLASH_CR_PG;
        }
    }
    f1_flash_lock();
    return ok;
}
