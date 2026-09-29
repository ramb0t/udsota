/* Known positives for the udsota portability target and the core-only build (the top-level CMakeLists.txt). Compiled
 * with exactly udsota_core's include path, PROBE_ESP and PROBE_FREERTOS must fail to find their header, proving that
 * path can't reach ESP-IDF or FreeRTOS. With the core-only include path, PROBE_UPDATER must fail to find an updater
 * header, while PROBE_STATE, the one updater header the server may name, must compile alone. PROBE_LINK_UPDATER,
 * linked against server/'s objects, must fail on the updater function it calls. */
#if defined(PROBE_ESP)
#include "esp_system.h"          /* ESP-IDF; test/stubs holds a host copy that must stay out of reach */
#elif defined(PROBE_FREERTOS)
#include "freertos/FreeRTOS.h"   /* FreeRTOS, as ESP-IDF ships it */
#elif defined(PROBE_UPDATER)
#include "udsota_image.h"        /* an updater header, in update/include */
#elif defined(PROBE_STATE)
#include "udsota_update_state.h"
int probe_state(void);
int probe_state(void) { return (int)sizeof(udsota_update_t); }
#elif defined(PROBE_LINK_UPDATER)
#include <stddef.h>
#include <stdint.h>
size_t udsota_pack_result(uint8_t *out, size_t max, const void *s);   /* update/udsota_update_codec.c's, by hand */
int main(void) { return (int)udsota_pack_result(NULL, 0, NULL); }
#else
#error "define PROBE_ESP, PROBE_FREERTOS, PROBE_UPDATER, PROBE_STATE or PROBE_LINK_UPDATER"
#endif
