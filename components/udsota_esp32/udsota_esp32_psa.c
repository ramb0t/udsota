/* The mutex that serialises PSA crypto between the port and the app (udsota_esp32.h). A FreeRTOS mutex,
 * so the flash worker inherits a waiting task's priority while it holds it. */
#include "udsota_esp32.h"
#include "udsota_esp32_priv.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static StaticSemaphore_t s_storage;
static SemaphoreHandle_t s_mutex;   /* set once by udsota_esp32_psa_lock_init(), before the port's tasks exist */

/* Creates the mutex in static storage; later calls do nothing. */
void udsota_esp32_psa_lock_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutexStatic(&s_storage);
    }
}

/* Takes the mutex within wait_ms; true without locking before init (only one task runs port code then). */
bool udsota_esp32_psa_lock(uint32_t wait_ms)
{
    if (s_mutex == NULL) {
        return true;
    }
    const TickType_t ticks = (wait_ms == UDSOTA_ESP32_PSA_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(wait_ms);
    return xSemaphoreTake(s_mutex, ticks) == pdTRUE;
}

/* Releases the mutex; a no-op before init. */
void udsota_esp32_psa_unlock(void)
{
    if (s_mutex != NULL) {
        (void)xSemaphoreGive(s_mutex);
    }
}
