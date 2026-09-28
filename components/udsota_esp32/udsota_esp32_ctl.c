/* The ESP32 port's control block (priv/udsota_esp32_ctl.h). Pure C11: host-tested. */
#include "udsota_esp32_ctl.h"
#include <stddef.h>
#include <string.h>

/* phase hook: stores p for every task first, so an app hook that reads the phase sees p, then runs
 * the app's hook with no lock held. */
static void w_phase(void *ctx, udsota_phase_t p)
{
    udsota_esp32_ctl_t *ctl = ctx;
    atomic_store_explicit(&ctl->phase, (unsigned)p, memory_order_release);
    if (ctl->app.phase != NULL) {
        ctl->app.phase(ctl->app.ctx, p);
    }
}

/* progress hook: stores *p for every task under the lock first, clearing the version in the same copy when
 * the stage moves into ERASING (an accepted 34), so an app hook that reads the snapshot sees p, then runs the
 * app's hook with no lock held. */
static void w_progress(void *ctx, const udsota_progress_t *p)
{
    udsota_esp32_ctl_t *ctl = ctx;
    if (ctl->lock != NULL) {
        ctl->lock(ctl->lock_ctx);
    }
    if (p->stage == UDSOTA_STAGE_ERASING && ctl->progress.stage != UDSOTA_STAGE_ERASING) {
        ctl->version[0] = '\0';
    }
    ctl->progress = *p;
    if (ctl->unlock != NULL) {
        ctl->unlock(ctl->lock_ctx);
    }
    if (ctl->app.progress != NULL) {
        ctl->app.progress(ctl->app.ctx, p);
    }
}

/* gate hook: the app's gate with the app's ctx (installed only when the app has one). */
static uint8_t w_gate(void *ctx, udsota_op_t op)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.gate(ctl->app.ctx, op);
}

/* did_read hook: the app's did_read with the app's ctx (installed only when the app has one). */
static size_t w_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.did_read(ctl->app.ctx, did, buf, max);
}

/* stmin_us hook: the app's stmin_us with the app's ctx (installed only when the app has one). */
static uint32_t w_stmin_us(void *ctx)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.stmin_us(ctl->app.ctx);
}

/* reset hook: the app's reset, else the port's default; both get the app's ctx and return only on failure. */
static bool w_reset(void *ctx)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    if (ctl->app.reset != NULL) {
        return ctl->app.reset(ctl->app.ctx);
    }
    return ctl->default_reset(ctl->app.ctx);
}

/* comm_control hook: the app's with the app's ctx (installed only when the app has one). */
static uint8_t w_comm_control(void *ctx, uint8_t control, uint8_t comm_type)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.comm_control(ctl->app.ctx, control, comm_type);
}

/* dtc_setting hook: the app's with the app's ctx (installed only when the app has one). */
static void w_dtc_setting(void *ctx, bool on)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    ctl->app.dtc_setting(ctl->app.ctx, on);
}

/* did_write hook: the app's did_write with the app's ctx (installed only when the app has one). */
static uint8_t w_did_write(void *ctx, uint16_t did, const uint8_t *data, size_t len, udsota_access_t access)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.did_write(ctl->app.ctx, did, data, len, access);
}

/* routine hook: the app's routine with the app's ctx (installed only when the app has one). */
static int w_routine(void *ctx, uint16_t rid, const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_max, size_t *out_len, udsota_access_t access)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.routine(ctl->app.ctx, rid, in, in_len, out, out_max, out_len, access);
}

/* routine_poll hook: the app's routine_poll with the app's ctx (installed only when the app has one). */
static int w_routine_poll(void *ctx, uint8_t *out, size_t out_max, size_t *out_len)
{
    const udsota_esp32_ctl_t *ctl = ctx;
    return ctl->app.routine_poll(ctl->app.ctx, out, out_max, out_len);
}

/* Copies the app's hooks and builds the wrapped set (see the header). */
void udsota_esp32_ctl_init(udsota_esp32_ctl_t *ctl, const udsota_hooks_t *app,
                           bool (*default_reset)(void *ctx), udsota_hooks_t *out)
{
    const udsota_hooks_t none = {0};
    ctl->app = (app != NULL) ? *app : none;
    ctl->default_reset = default_reset;
    ctl->progress = (udsota_progress_t){.stage = UDSOTA_STAGE_IDLE};
    ctl->version[0] = '\0';
    ctl->lock = NULL;
    ctl->unlock = NULL;
    ctl->lock_ctx = NULL;
    atomic_store_explicit(&ctl->phase, (unsigned)UDSOTA_PHASE_IDLE, memory_order_release);
    atomic_store_explicit(&ctl->end_req, false, memory_order_release);
    *out = (udsota_hooks_t){
        .gate         = (ctl->app.gate != NULL) ? w_gate : NULL,
        .phase        = w_phase,
        .did_read     = (ctl->app.did_read != NULL) ? w_did_read : NULL,
        .stmin_us     = (ctl->app.stmin_us != NULL) ? w_stmin_us : NULL,
        .reset        = (ctl->app.reset != NULL || default_reset != NULL) ? w_reset : NULL,
        .comm_control = (ctl->app.comm_control != NULL) ? w_comm_control : NULL,
        .dtc_setting  = (ctl->app.dtc_setting != NULL) ? w_dtc_setting : NULL,
        .ctx          = ctl,
        .did_write    = (ctl->app.did_write != NULL) ? w_did_write : NULL,
        .routine      = (ctl->app.routine != NULL) ? w_routine : NULL,
        .routine_poll = (ctl->app.routine_poll != NULL) ? w_routine_poll : NULL,
        .progress     = w_progress,
    };
}

/* Installs the snapshot's lock; see the header. */
void udsota_esp32_ctl_set_lock(udsota_esp32_ctl_t *ctl, void (*lock)(void *ctx), void (*unlock)(void *ctx),
                               void *lock_ctx)
{
    ctl->lock = lock;
    ctl->unlock = unlock;
    ctl->lock_ctx = lock_ctx;
}

/* One atomic load. */
udsota_phase_t udsota_esp32_ctl_phase(udsota_esp32_ctl_t *ctl)
{
    return (udsota_phase_t)atomic_load_explicit(&ctl->phase, memory_order_acquire);
}

/* One copy under the lock. */
void udsota_esp32_ctl_progress(udsota_esp32_ctl_t *ctl, udsota_progress_t *out)
{
    if (ctl->lock != NULL) {
        ctl->lock(ctl->lock_ctx);
    }
    *out = ctl->progress;
    if (ctl->unlock != NULL) {
        ctl->unlock(ctl->lock_ctx);
    }
}

/* Truncates and sanitises v into a local first, then one copy under the lock. */
void udsota_esp32_ctl_set_version(udsota_esp32_ctl_t *ctl, const char *v, size_t max)
{
    char tmp[UDSOTA_ESP32_CTL_VERSION_MAX];
    size_t n = 0u;
    while (n < max && n < sizeof tmp - 1u && v[n] != '\0') {
        const unsigned char c = (unsigned char)v[n];
        tmp[n] = (c >= 0x20u && c <= 0x7Eu) ? (char)c : '?';
        n++;
    }
    tmp[n] = '\0';
    if (ctl->lock != NULL) {
        ctl->lock(ctl->lock_ctx);
    }
    memcpy(ctl->version, tmp, n + 1u);
    if (ctl->unlock != NULL) {
        ctl->unlock(ctl->lock_ctx);
    }
}

/* One copy under the lock; the length is counted after the lock is released. */
size_t udsota_esp32_ctl_version(udsota_esp32_ctl_t *ctl, char out[UDSOTA_ESP32_CTL_VERSION_MAX])
{
    if (ctl->lock != NULL) {
        ctl->lock(ctl->lock_ctx);
    }
    memcpy(out, ctl->version, UDSOTA_ESP32_CTL_VERSION_MAX);
    if (ctl->unlock != NULL) {
        ctl->unlock(ctl->lock_ctx);
    }
    return strlen(out);
}

/* One atomic store: the request never runs on the caller. */
void udsota_esp32_ctl_request_end(udsota_esp32_ctl_t *ctl)
{
    atomic_store_explicit(&ctl->end_req, true, memory_order_release);
}

/* Takes the request with one exchange and hands it to the core on the caller (the diag task). */
bool udsota_esp32_ctl_run_end(udsota_esp32_ctl_t *ctl, udsota_server_t *s, uint32_t now_ms)
{
    if (!atomic_exchange_explicit(&ctl->end_req, false, memory_order_acq_rel)) {
        return false;
    }
    udsota_end_session(s, now_ms);
    return true;
}

/* Milliseconds to ticks, rounded down but never to 0 for a real wait; see udsota_esp32_ctl.h. */
uint32_t udsota_esp32_ctl_ticks(uint32_t ms, uint32_t tick_hz)
{
    if (ms == 0u) {
        return 0u;
    }
    const uint64_t t = (uint64_t)ms * tick_hz / 1000u;
    if (t == 0u) {
        return 1u;
    }
    return (t > UINT32_MAX) ? UINT32_MAX : (uint32_t)t;
}
