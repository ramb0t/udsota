/* The ESP32 port's control block: the phase copy any task reads, the end-session request any task
 * raises, and the hook wrappers the server and the ISO-TP adapter call. No lock anywhere, so an app
 * hook may call any udsota_esp32_* function. Pure C11 (stdatomic, no ESP-IDF, no FreeRTOS):
 * host-tested by test_udsota_esp32_ctl. */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include "udsota.h"

typedef struct {
    atomic_uint    phase;                    /* udsota_phase_t, stored before the app's phase hook runs */
    atomic_bool    end_req;                  /* raised by udsota_esp32_end_session(), taken by the diag task */
    udsota_hooks_t app;                      /* the app's hooks, its ctx included */
    bool         (*default_reset)(void *ctx);   /* runs when app.reset is NULL; gets app.ctx */
} udsota_esp32_ctl_t;

/* Before the server exists: copies *app (NULL = no hooks), stores IDLE, clears any request, and fills
 * *out with the hooks to give the server and the adapter. out->ctx is ctl. out's gate, did_read and
 * stmin_us stay NULL where the app's are, so the core's defaults hold; out's phase is always set, and
 * out's reset is set when the app or default_reset gives one. */
void udsota_esp32_ctl_init(udsota_esp32_ctl_t *ctl, const udsota_hooks_t *app,
                           bool (*default_reset)(void *ctx), udsota_hooks_t *out);
/* Any task: the phase as of the server's last change. */
udsota_phase_t udsota_esp32_ctl_phase(udsota_esp32_ctl_t *ctl);
/* Any task, an app hook included: asks the diag task to end the session; requests count once until it runs. */
void udsota_esp32_ctl_request_end(udsota_esp32_ctl_t *ctl);
/* Diag task, outside every server call: runs udsota_end_session() once if a request is pending (the core
 * latches it during a job and ignores it while a restart is armed); true when it ran. */
bool udsota_esp32_ctl_run_end(udsota_esp32_ctl_t *ctl, udsota_server_t *s, uint32_t now_ms);
/* The FreeRTOS ticks to block for a wait of ms milliseconds at tick_hz: rounded down, so a deadline is never
 * overslept by more than one tick, but at least 1 for any wait above 0, so a short wait never becomes a
 * non-blocking poll (pdMS_TO_TICKS(5) is 0 at 100 Hz, which spun the diag task). 0 stays 0. */
uint32_t udsota_esp32_ctl_ticks(uint32_t ms, uint32_t tick_hz);
