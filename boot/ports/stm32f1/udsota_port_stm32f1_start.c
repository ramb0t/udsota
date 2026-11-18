/* udsota's boot port for the STM32F1: start_app, which leaves the chip as near its reset state as it can and jumps to
   the app. Target only, since it uses Cortex-M3 instructions; no host test compiles it. CMSIS register access only, no
   ST HAL. The watchdog, DBGMCU->CR, the BKP data registers, PWR->CR and FLASH->ACR are left as they are; a latency of
   2 on HSI is only slower [RM0008 p60]. */
#include "stm32f1xx.h"
#include "udsota_boot.h"

#if !defined(UDSOTA_F1_SLOT_BASE)
#error "the product's build defines UDSOTA_F1_SLOT_BASE (README.md)"
#endif

/* The bound on each clock wait, a design bound: HAL's HSI_TIMEOUT_VALUE for HSIRDY, and far shorter than its
   CLOCKSWITCH_TIMEOUT_VALUE (5 s) for SWS [Drivers/STM32F1xx_HAL_Driver/Inc/stm32f1xx_hal_rcc.h:1205, :1207]. */
#define F1_CLOCK_WAIT_US 2000u

/* HSI is the 8 MHz RC [RM0008 p128]. */
#define F1_HSI_HZ 8000000u

/* EXTI: one bit for every line [stm32f105xc.h:3698-3699; RM0008 p211-214]. */
#ifdef EXTI_PR_PR19
#define F1_EXTI_LINES 0x000FFFFFu
#else
#define F1_EXTI_LINES 0x0007FFFFu
#endif

/* The clocks to stop, and their ready flags [stm32f105xc.h:1280-1311]. */
#ifdef RCC_CR_PLL2ON
#define F1_CR_PLL2ON RCC_CR_PLL2ON
#define F1_CR_PLL2RDY RCC_CR_PLL2RDY
#else
#define F1_CR_PLL2ON 0u
#define F1_CR_PLL2RDY 0u
#endif
#ifdef RCC_CR_PLL3ON
#define F1_CR_PLL3ON RCC_CR_PLL3ON
#define F1_CR_PLL3RDY RCC_CR_PLL3RDY
#else
#define F1_CR_PLL3ON 0u
#define F1_CR_PLL3RDY 0u
#endif
#define F1_CR_OFF (RCC_CR_HSEON | RCC_CR_CSSON | RCC_CR_PLLON | F1_CR_PLL2ON | F1_CR_PLL3ON)
#define F1_CR_RDY (RCC_CR_HSERDY | RCC_CR_PLLRDY | F1_CR_PLL2RDY | F1_CR_PLL3RDY)

/* RCC_CIR: every ready and CSS flag cleared, their interrupts off [RM0008 p137]. */
#define F1_CIR_CLEAR_ALL 0x00FF0000u

/* The enables' reset values: SRAM and FLITF clocked, nothing else [RM0008 p145, p146, p148]. */
#define F1_AHBENR_RESET 0x00000014u

/* Every reset bit the device header names except BKPRST and PWRRST, so the keep words survive [stm32f105xc.h:1548-1656;
   RM0008 p141-142]. A name the header lacks is 0, so another F1 part builds. */
#ifndef RCC_APB2RSTR_AFIORST
#define RCC_APB2RSTR_AFIORST 0u
#endif
#ifndef RCC_APB2RSTR_IOPARST
#define RCC_APB2RSTR_IOPARST 0u
#endif
#ifndef RCC_APB2RSTR_IOPBRST
#define RCC_APB2RSTR_IOPBRST 0u
#endif
#ifndef RCC_APB2RSTR_IOPCRST
#define RCC_APB2RSTR_IOPCRST 0u
#endif
#ifndef RCC_APB2RSTR_IOPDRST
#define RCC_APB2RSTR_IOPDRST 0u
#endif
#ifndef RCC_APB2RSTR_IOPERST
#define RCC_APB2RSTR_IOPERST 0u
#endif
#ifndef RCC_APB2RSTR_ADC1RST
#define RCC_APB2RSTR_ADC1RST 0u
#endif
#ifndef RCC_APB2RSTR_ADC2RST
#define RCC_APB2RSTR_ADC2RST 0u
#endif
#ifndef RCC_APB2RSTR_TIM1RST
#define RCC_APB2RSTR_TIM1RST 0u
#endif
#ifndef RCC_APB2RSTR_SPI1RST
#define RCC_APB2RSTR_SPI1RST 0u
#endif
#ifndef RCC_APB2RSTR_USART1RST
#define RCC_APB2RSTR_USART1RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM2RST
#define RCC_APB1RSTR_TIM2RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM3RST
#define RCC_APB1RSTR_TIM3RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM4RST
#define RCC_APB1RSTR_TIM4RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM5RST
#define RCC_APB1RSTR_TIM5RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM6RST
#define RCC_APB1RSTR_TIM6RST 0u
#endif
#ifndef RCC_APB1RSTR_TIM7RST
#define RCC_APB1RSTR_TIM7RST 0u
#endif
#ifndef RCC_APB1RSTR_WWDGRST
#define RCC_APB1RSTR_WWDGRST 0u
#endif
#ifndef RCC_APB1RSTR_SPI2RST
#define RCC_APB1RSTR_SPI2RST 0u
#endif
#ifndef RCC_APB1RSTR_SPI3RST
#define RCC_APB1RSTR_SPI3RST 0u
#endif
#ifndef RCC_APB1RSTR_USART2RST
#define RCC_APB1RSTR_USART2RST 0u
#endif
#ifndef RCC_APB1RSTR_USART3RST
#define RCC_APB1RSTR_USART3RST 0u
#endif
#ifndef RCC_APB1RSTR_UART4RST
#define RCC_APB1RSTR_UART4RST 0u
#endif
#ifndef RCC_APB1RSTR_UART5RST
#define RCC_APB1RSTR_UART5RST 0u
#endif
#ifndef RCC_APB1RSTR_I2C1RST
#define RCC_APB1RSTR_I2C1RST 0u
#endif
#ifndef RCC_APB1RSTR_I2C2RST
#define RCC_APB1RSTR_I2C2RST 0u
#endif
#ifndef RCC_APB1RSTR_CAN1RST
#define RCC_APB1RSTR_CAN1RST 0u
#endif
#ifndef RCC_APB1RSTR_CAN2RST
#define RCC_APB1RSTR_CAN2RST 0u
#endif
#ifndef RCC_APB1RSTR_DACRST
#define RCC_APB1RSTR_DACRST 0u
#endif

#define F1_APB2_RESET (RCC_APB2RSTR_AFIORST | RCC_APB2RSTR_IOPARST | RCC_APB2RSTR_IOPBRST | RCC_APB2RSTR_IOPCRST \
                       | RCC_APB2RSTR_IOPDRST | RCC_APB2RSTR_IOPERST | RCC_APB2RSTR_ADC1RST | RCC_APB2RSTR_ADC2RST \
                       | RCC_APB2RSTR_TIM1RST | RCC_APB2RSTR_SPI1RST | RCC_APB2RSTR_USART1RST)
#define F1_APB1_RESET (RCC_APB1RSTR_TIM2RST | RCC_APB1RSTR_TIM3RST | RCC_APB1RSTR_TIM4RST | RCC_APB1RSTR_TIM5RST \
                       | RCC_APB1RSTR_TIM6RST | RCC_APB1RSTR_TIM7RST | RCC_APB1RSTR_WWDGRST | RCC_APB1RSTR_SPI2RST \
                       | RCC_APB1RSTR_SPI3RST | RCC_APB1RSTR_USART2RST | RCC_APB1RSTR_USART3RST \
                       | RCC_APB1RSTR_UART4RST | RCC_APB1RSTR_UART5RST | RCC_APB1RSTR_I2C1RST | RCC_APB1RSTR_I2C2RST \
                       | RCC_APB1RSTR_CAN1RST | RCC_APB1RSTR_CAN2RST | RCC_APB1RSTR_DACRST)

#if defined(STM32F105xC)
_Static_assert(F1_APB2_RESET == 0x00005E7DUL && F1_APB1_RESET == 0x267EC83FUL, "connectivity-line reset masks");
#endif

/* Polls until (*reg & mask) == want, bounded by F1_CLOCK_WAIT_US; false when the bound passes first. */
static bool f1_clock_wait(volatile uint32_t *reg, uint32_t mask, uint32_t want)
{
    uint32_t t0 = udsota_boot_port_us();
    while ((*reg & mask) != want) {
        if (udsota_boot_port_us() - t0 >= F1_CLOCK_WAIT_US) {
            return false;
        }
    }
    return true;
}

/* A wait that runs out does not stop the sequence. */
void udsota_boot_port_start_app(void)
{
    __disable_irq();                                   /* [cmsis_gcc.h:140] */
    SysTick->CTRL = 0u;                                /* [core_cm3.h:713, :1394] */

    /* The implemented 32-line groups minus one, so 2 on this part's 68 lines [core_cm3.h:344, :348, :658, :667-668,
       :1392; stm32f105xc.h:141; PM0056]. The loop never writes a word the part does not implement. */
    uint32_t groups = SCnSCB->ICTR & SCnSCB_ICTR_INTLINESNUM_Msk;
    for (uint32_t i = 0u; i <= groups; i++) {
        NVIC->ICER[i] = 0xFFFFFFFFu;
        NVIC->ICPR[i] = 0xFFFFFFFFu;
    }
    SCB->ICSR = SCB_ICSR_PENDSTCLR_Msk | SCB_ICSR_PENDSVCLR_Msk;   /* [core_cm3.h:423, :429] */

    /* EXTI has no reset bit [stm32f105xc.h:380-388; RM0008 p211-214]. */
    EXTI->IMR = 0u;
    EXTI->EMR = 0u;
    EXTI->RTSR = 0u;
    EXTI->FTSR = 0u;
    EXTI->PR = F1_EXTI_LINES;

    /* HSI on, then the system clock on HSI, since PLLON and HSEON cannot be cleared while they feed it [stm32f105xc.h:
       1268-1273, :1315-1332; RM0008 p132, p133-134]. */
    RCC->CR |= RCC_CR_HSION;
    (void)f1_clock_wait(&RCC->CR, RCC_CR_HSIRDY, RCC_CR_HSIRDY);
    RCC->CFGR &= ~RCC_CFGR_SW;
    if (f1_clock_wait(&RCC->CFGR, RCC_CFGR_SWS, RCC_CFGR_SWS_HSI)) {
        SystemCoreClock = F1_HSI_HZ;
    }

    /* HSE, CSS and the PLLs off, then wait for them to stop: HSEBYP, CFGR's PLL fields and CFGR2 are writable only with
       their source stopped [RM0008 p135, p154-155; HAL_RCC_DeInit waits the same way, stm32f1xx_hal_rcc.c:252-320]. */
    RCC->CR &= ~F1_CR_OFF;
    (void)f1_clock_wait(&RCC->CR, F1_CR_RDY, 0u);
    RCC->CR &= ~RCC_CR_HSEBYP;

    /* [RM0008 p134, p137, p154; SystemInit in system_stm32f1xx.c writes the same values] */
    RCC->CFGR = 0u;
    RCC->CIR = F1_CIR_CLEAR_ALL;
#ifdef RCC_CFGR2_PREDIV1
    RCC->CFGR2 = 0u;
#endif

    RCC->APB2RSTR = F1_APB2_RESET;
    RCC->APB2RSTR = 0u;
    RCC->APB1RSTR = F1_APB1_RESET;
    RCC->APB1RSTR = 0u;

    /* This stops the BKP and PWR clocks but leaves their registers and DBP alone. */
    RCC->AHBENR = F1_AHBENR_RESET;
    RCC->APB2ENR = 0u;
    RCC->APB1ENR = 0u;

    /* [core_cm3.h:378; cmsis_gcc.h:181, :491, :557, :866, :877; VTOR's alignment for 84 vectors, and CONTROL then
       DSB/ISB being enough: PM0056] */
    SCB->VTOR = UDSOTA_F1_SLOT_BASE;
    const volatile uint32_t *vectors = (const volatile uint32_t *)UDSOTA_F1_SLOT_BASE;
    uint32_t app_sp = vectors[0];
    uint32_t app_reset = vectors[1];
    __set_BASEPRI(0u);
    __set_FAULTMASK(0u);
    __set_CONTROL(0u);                                 /* privileged, main stack */
    __DSB();
    __ISB();

    /* One statement, so nothing touches the stack between loading MSP and the branch; bx to the vector's odd address
       stays in Thumb state [PM0056]. */
    __asm volatile ("msr msp, %0\n\tcpsie i\n\tbx %1" :: "r"(app_sp), "r"(app_reset) : "memory");
    __builtin_unreachable();
}
