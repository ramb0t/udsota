/* The ESP32 port's control block: the phase copy, progress snapshot and incoming version any task reads, the
 * end-session request any task raises, and the hook wrappers the server and the ISO-TP adapter call. The only
 * lock is the snapshot's, which the port supplies (a portMUX) and which is never held while an app hook runs, so
 * an app hook may call any udsota_esp32_* function. Pure C11 (stdatomic, no ESP-IDF, no FreeRTOS):
 * host-tested by test_udsota_esp32_ctl. */
#pragma once
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota.h"

#define UDSOTA_ESP32_CTL_VERSION_MAX 32u   /* UDSOTA_ESP32_VERSION_MAX: up to 31 characters and a NUL */
#define UDSOTA_ESP32_CTL_VERSION_OFF 48u   /* esp_app_desc_t.version in a first block: 24 + 8 header bytes, then 16 */
#define UDSOTA_ESP32_CTL_ID_MAX      0x7FFu   /* the largest 11-bit CAN ID: the port serves no other */

typedef struct {
    atomic_uint    phase;                    /* udsota_phase_t, stored before the app's phase hook runs */
    atomic_bool    end_req;                  /* raised by udsota_esp32_end_session(), taken by the diag task */
    udsota_hooks_t app;                      /* the app's hooks, its ctx included */
    bool         (*default_reset)(void *ctx);   /* runs when app.reset is NULL; gets app.ctx */
    udsota_progress_t progress;              /* the last progress the server reported, under lock */
    char           version[UDSOTA_ESP32_CTL_VERSION_MAX];   /* the incoming image's, with its NUL, under lock */
    void         (*lock)(void *ctx);         /* guard progress and version; NULL = no lock (one task, the host) */
    void         (*unlock)(void *ctx);
    void          *lock_ctx;
} udsota_esp32_ctl_t;

/* Before the server exists: copies *app (NULL = no hooks), stores IDLE, an IDLE progress and an empty version,
 * clears any request and the lock, and fills *out with the hooks to give the server and the adapter. out->ctx is ctl.
 * out's gate, did_read, stmin_us, comm_control, dtc_setting, did_write, routine, routine_poll, dtc_get,
 * dtc_ext_data, dtc_clear, did_read_ex and routine_ex stay NULL where the app's are, so the core's defaults hold;
 * out's phase and progress are always set, and out's reset is set when the app or default_reset gives one. */
void udsota_esp32_ctl_init(udsota_esp32_ctl_t *ctl, const udsota_hooks_t *app,
                           bool (*default_reset)(void *ctx), udsota_hooks_t *out);
/* After udsota_esp32_ctl_init and before the server runs: the lock that guards the progress snapshot and the
 * version, taken with lock_ctx around each copy in or out of them and held for nothing else. The port passes a
 * portMUX critical section, since the reader may be any task on either core. */
void udsota_esp32_ctl_set_lock(udsota_esp32_ctl_t *ctl, void (*lock)(void *ctx), void (*unlock)(void *ctx),
                               void *lock_ctx);
/* Any task: the phase as of the server's last change. */
udsota_phase_t udsota_esp32_ctl_phase(udsota_esp32_ctl_t *ctl);
/* Any task: a copy of the progress the server last reported (IDLE, 0 of 0, after init), under the lock. */
void udsota_esp32_ctl_progress(udsota_esp32_ctl_t *ctl, udsota_progress_t *out);
/* The first-block check's task, when it accepts an image: stores its version under the lock, from the first max
 * bytes of v up to the first NUL, at most 31, with each byte outside 0x20-0x7E stored as '?'. The progress hook
 * clears it, in the same locked copy as the report, when the stage moves into ERASING from any other stage (an
 * accepted 34), so a reader that sees the new download's ERASING never sees the previous download's version. */
void udsota_esp32_ctl_set_version(udsota_esp32_ctl_t *ctl, const char *v, size_t max);
/* The first-block check's task, once it has judged a first block of len bytes: when r is UDSOTA_DL_OK, stores the
 * esp_app_desc_t.version the block holds at UDSOTA_ESP32_CTL_VERSION_OFF (udsota_esp32_ctl_set_version); a
 * refused block, or one too short to hold the field, stores nothing. */
void udsota_esp32_ctl_first_block(udsota_esp32_ctl_t *ctl, udsota_reason_t r, const uint8_t *first, size_t len);
/* The diag task, when the engine refuses a compressed 34 (zbegin fails, and the server records the refusal as
 * last_reason): empties the version under the lock, so the refusal never reads as the previous download's. */
void udsota_esp32_ctl_clear_version(udsota_esp32_ctl_t *ctl);
/* Any task: a copy of the version with its NUL, under the lock; returns its length ("" after init and from an
 * accepted 34 until that download's first block passes the check). */
size_t udsota_esp32_ctl_version(udsota_esp32_ctl_t *ctl, char out[UDSOTA_ESP32_CTL_VERSION_MAX]);
/* Any task, an app hook included: asks the diag task to end the session; requests count once until it runs. */
void udsota_esp32_ctl_request_end(udsota_esp32_ctl_t *ctl);
/* Diag task, outside every server call: runs udsota_end_session() once if a request is pending (the core
 * latches it during a job and ignores it while a restart is armed); true when it ran. */
bool udsota_esp32_ctl_run_end(udsota_esp32_ctl_t *ctl, udsota_server_t *s, uint32_t now_ms);
/* The FreeRTOS ticks to block for a wait of ms milliseconds at tick_hz: rounded down, so a deadline is never
 * overslept by more than one tick, but at least 1 for any wait above 0, so a short wait never becomes a
 * non-blocking poll (pdMS_TO_TICKS(5) is 0 at 100 Hz, which spun the diag task). 0 stays 0. */
uint32_t udsota_esp32_ctl_ticks(uint32_t ms, uint32_t tick_hz);
/* True when cfg's CAN IDs are ones the port can serve: req_id and resp_id 11-bit (at most UDSOTA_ESP32_CTL_ID_MAX)
 * and distinct, and func_id, when set (0 = no functional addressing), 11-bit and equal to neither.
 * udsota_esp32_start() refuses any other with ESP_ERR_INVALID_ARG. */
bool udsota_esp32_ctl_ids_ok(const udsota_config_t *cfg);
