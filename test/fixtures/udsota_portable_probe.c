/* Known positive for the udsota portability target (the top-level CMakeLists.txt): compiled with exactly
 * udsota_core's include path, each variant must fail to find its header, proving that path can't reach
 * ESP-IDF or FreeRTOS. */
#if defined(PROBE_ESP)
#include "esp_system.h"          /* ESP-IDF; test/stubs holds a host copy that must stay out of reach */
#elif defined(PROBE_FREERTOS)
#include "freertos/FreeRTOS.h"   /* FreeRTOS, as ESP-IDF ships it */
#else
#error "define PROBE_ESP or PROBE_FREERTOS"
#endif
