/* udsota ESP32 boot-loop counter storage: the state sits in RTC_NOINIT memory (8 B of RTC slow memory on
 * the S3), which startup never zeroes and which survives panic, watchdog and software resets.
 * UDSOTA_BOOTLOOP_MAGIC guards it against power-up garbage. No heap, no NVS. On the S3 a chip-level
 * brownout or a super-watchdog reset reads as POWERON and clears the count; only the ISR-mode brownout
 * (CONFIG_ESP_BROWNOUT_USE_INTR) reports BROWNOUT and counts. */
#include <inttypes.h>
#include <stdbool.h>
#include "udsota_bootloop.h"
#include "udsota_esp32.h"
#include "udsota_esp32_priv.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "udsota_boot";

static RTC_NOINIT_ATTR udsota_bootloop_state_t s_rtc;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_booted;          /* udsota_bootloop_on_boot has consumed this boot's reset reason */
static bool s_ignore_config;   /* latched for the whole boot, even after udsota_esp32_bootloop_mark_healthy() */

/* Maps ESP-IDF v6.1's reset reason onto the core's: EXT, DEEPSLEEP, SDIO, USB and JTAG are deliberate
 * outside resets, the three watchdogs are WDT, and UNKNOWN, EFUSE, PWR_GLITCH, CPU_LOCKUP and any later value are OTHER. */
static udsota_reset_reason_t reason_from_esp(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON:
        return UDSOTA_RST_POWERON;
    case ESP_RST_SW:
        return UDSOTA_RST_SW;
    case ESP_RST_EXT:
    case ESP_RST_DEEPSLEEP:
    case ESP_RST_SDIO:
    case ESP_RST_USB:
    case ESP_RST_JTAG:
        return UDSOTA_RST_EXT;
    case ESP_RST_PANIC:
        return UDSOTA_RST_PANIC;
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
        return UDSOTA_RST_WDT;
    case ESP_RST_BROWNOUT:
        return UDSOTA_RST_BROWNOUT;
    default:
        return UDSOTA_RST_OTHER;
    }
}

/* Runs the boot step once per boot (app_main calls it before anything reads NVS); later calls return at once. */
void udsota_esp32_bootloop_init(void)
{
    esp_reset_reason_t reason = esp_reset_reason();
    udsota_bootloop_action_t act = { .ignore_config = false, .cleared = false };
    bool first = false;
    uint32_t count = 0;
    taskENTER_CRITICAL(&s_lock);
    if (!s_booted) {
        act = udsota_bootloop_on_boot(&s_rtc, reason_from_esp(reason), udsota_bootloop_magic_valid(&s_rtc));
        s_ignore_config = act.ignore_config;
        s_booted = true;
        first = true;
        count = s_rtc.count;
    }
    taskEXIT_CRITICAL(&s_lock);
    if (!first) {
        return;
    }
    if (act.ignore_config) {
        ESP_LOGW(TAG, "%" PRIu32 " crash resets since the last power-on or healthy boot (reset reason %d): "
                 "this boot ignores config and runs on defaults", count, (int)reason);
    } else {
        ESP_LOGD(TAG, "reset reason %d, crash count %" PRIu32 "%s", (int)reason, count,
                 act.cleared ? " (cleared)" : "");
    }
}

/* True when this boot ignores config; runs the boot step first if nothing has yet. */
bool udsota_esp32_bootloop_config_ignored(void)
{
    udsota_esp32_bootloop_init();
    return s_ignore_config;
}

/* Clears the crash count after the boot step has run; this boot's ignore flag stays latched. */
void udsota_esp32_bootloop_mark_healthy(void)
{
    udsota_esp32_bootloop_init();
    taskENTER_CRITICAL(&s_lock);
    uint32_t before = s_rtc.count;
    udsota_bootloop_on_healthy(&s_rtc);
    taskEXIT_CRITICAL(&s_lock);
    if (before != 0) {
        ESP_LOGD(TAG, "healthy: crash count %" PRIu32 " cleared", before);
    }
}

/* True when the app ran the boot step this boot and it chose to ignore config; never runs the step. */
bool udsota_esp32_bootloop_reported(void)
{
    taskENTER_CRITICAL(&s_lock);
    const bool r = s_booted && s_ignore_config;
    taskEXIT_CRITICAL(&s_lock);
    return r;
}
