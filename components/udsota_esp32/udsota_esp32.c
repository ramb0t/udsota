/* udsota's ESP32 port: the task and the app API (udsota_esp32.h). One diag task owns the ISO-TP adapter
 * and the UDS server. The app hands it request frames from its CAN task and the port sends through the
 * app's can_send, so the port never touches TWAI. The task does ISO-TP and the 0x27 HMAC or ECDSA verify
 * only and never flash (the engine's worker makes every esp_ota_* call), which is why its stack may live in
 * PSRAM. Phase, progress, end-session and the hook wrappers are the pure udsota_esp32_ctl.c. */
#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "udsota.h"
#include "udsota_esp32.h"
#include "udsota_esp32_ctl.h"
#include "udsota_esp32_devid.h"
#include "udsota_esp32_priv.h"
#include "udsota_esp32_sa.h"
#include "udsota_isotp.h"

static const char *TAG = "udsota";

#define MAX_WAIT_MS   100u      /* longest sleep, so a queued end-session never waits longer */
#define LOG_EVERY_MS  5000u

#if defined(CONFIG_UDSOTA_ESP32_BUFS_PSRAM)
#define BUF_CAPS   (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#else
#define BUF_CAPS   (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#endif
#if defined(CONFIG_UDSOTA_ESP32_TASK_STACK_PSRAM)
#define STACK_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#else
#define STACK_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#endif

/* One received request frame and the microsecond the app received it, or a wake from the flash worker. */
typedef struct {
    uint8_t  data[8];
    uint8_t  dlc;                  /* RX_WAKE_DLC: no frame, the worker finished a job */
    bool     func;                 /* arrived on cfg.func_id: a functional request */
    uint32_t t_us;
} rx_item_t;

#define RX_WAKE_DLC  0xFFu

/* Set by udsota_esp32_start() before the task exists; read-only afterwards. */
static bool               s_started;
static udsota_config_t    s_cfg;             /* the app's config, device_id pointed at the port's stored ID */
static udsota_esp32_can_t s_can;
static udsota_hooks_t     s_hooks;           /* udsota_esp32_ctl_init()'s wrappers */
static udsota_can_t       s_tpcan;
/* Diag task only (and start() before the task exists). */
static udsota_server_t    s_srv;
static udsota_isotp_t     s_tp;
/* Cross-task. */
static udsota_esp32_ctl_t     s_ctl;         /* phase, end-session request and progress snapshot */
static _Atomic(QueueHandle_t) s_q;           /* published last by start(); NULL = frames are dropped */
static portMUX_TYPE           s_progress_mux = portMUX_INITIALIZER_UNLOCKED;   /* guards s_ctl's progress copy */
static atomic_uint            s_rx_q_dropped;   /* written by the app's CAN task */
static atomic_bool            s_wake_posted;    /* a wake item is queued and not yet taken: at most one at a time */

/* Milliseconds since boot: the server's clock (the 0x27 boot delay counts from 0). */
static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* udsota_can_t.now_us: microseconds since boot, wrapping every 71 minutes (isotp-c compares wrap-safe). */
static uint32_t tp_now_us(void *ctx)
{
    (void)ctx;
    return (uint32_t)esp_timer_get_time();
}

/* udsota_can_t.send: the app's can_send, ESP_OK -> 0, ESP_ERR_NO_MEM -> UDSOTA_TX_RETRY (the adapter
 * parks an answer, retries an FC for cfg.fc_retry_ms and lets isotp_poll resend a CF), else -1. */
static int tp_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    (void)ctx;
    const esp_err_t err = s_can.can_send(s_can.ctx, id, data, len);
    if (err == ESP_OK) {
        return 0;
    }
    return (err == ESP_ERR_NO_MEM) ? UDSOTA_TX_RETRY : -1;
}

/* udsota_can_t.tx_pending: the app's count (installed only when the app gave one). */
static uint32_t tp_tx_pending(void *ctx)
{
    (void)ctx;
    return s_can.tx_pending(s_can.ctx);
}

/* The progress snapshot's lock: a critical section on s_progress_mux, which any task on either core may take. */
static void progress_lock(void *ctx)
{
    portENTER_CRITICAL((portMUX_TYPE *)ctx);
}

/* Releases progress_lock's critical section. */
static void progress_unlock(void *ctx)
{
    portEXIT_CRITICAL((portMUX_TYPE *)ctx);
}

/* The default reset hook: esp_restart() moves SP off a PSRAM stack first (system_internal.c:106-113)
 * and never returns. */
static bool default_reset(void *ctx)
{
    (void)ctx;
    ESP_LOGI(TAG, "restart requested over UDS");
    esp_restart();
    return false;
}

/* Diag task, before each adapter call: the status counters' resp_frames_dropped follows the app's
 * tx_dropped, saturated to 16 bits, refreshed before every adapter call. */
static void mirror_resp_dropped(void)
{
    if (s_can.tx_dropped == NULL) {
        return;
    }
    const uint32_t n = s_can.tx_dropped(s_can.ctx);
    s_srv.counters.resp_frames_dropped = (n > 0xFFFFu) ? 0xFFFFu : (uint16_t)n;
}

/* The diag task's log state: when it last looked, the loss total it logged, and the smallest stack
 * headroom and internal-heap low-water mark it logged. */
typedef struct {
    uint32_t    last_ms;
    uint32_t    losses;
    UBaseType_t headroom;
    size_t      heap_min;
} log_state_t;

/* Every LOG_EVERY_MS: a warning when a loss counter moved (frames the queue dropped, FCs and answers the
 * adapter dropped), and with CONFIG_UDSOTA_ESP32_DEBUG_MEASURE the stack headroom and internal-heap
 * low-water mark when either shrank. */
static void log_status(uint32_t now, log_state_t *lg)
{
    if ((uint32_t)(now - lg->last_ms) < LOG_EVERY_MS) {
        return;
    }
    lg->last_ms = now;
#if defined(CONFIG_UDSOTA_ESP32_DEBUG_MEASURE)
    const UBaseType_t headroom = uxTaskGetStackHighWaterMark(NULL);   /* bytes never used */
    if (headroom < lg->headroom) {
        lg->headroom = headroom;
        ESP_LOGI(TAG, "stack headroom %u B of %d", (unsigned)headroom, CONFIG_UDSOTA_ESP32_TASK_STACK);
    }
    const size_t heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    if (heap_min < lg->heap_min) {
        lg->heap_min = heap_min;
        ESP_LOGI(TAG, "internal heap min free %u B", (unsigned)heap_min);
    }
#endif
    const uint32_t q = atomic_load_explicit(&s_rx_q_dropped, memory_order_relaxed);
    const uint32_t fc = udsota_isotp_fc_lost(&s_tp);
    const uint32_t resp = udsota_isotp_resp_lost(&s_tp);
    const uint32_t sum = q + fc + resp;
    if (sum != lg->losses) {
        lg->losses = sum;
        ESP_LOGW(TAG, "losses: rx queue %" PRIu32 ", FC %" PRIu32 ", responses %" PRIu32, q, fc, resp);
    }
}

/* Flash worker, after each finished job: queues one wake item so the diag task serves the job's answer at once.
 * A full queue needs none, since the diag task is about to wake anyway. */
static void worker_wake(void)
{
    QueueHandle_t q = atomic_load_explicit(&s_q, memory_order_acquire);
    if (q == NULL || atomic_exchange_explicit(&s_wake_posted, true, memory_order_acq_rel)) {
        return;
    }
    const rx_item_t it = { .dlc = RX_WAKE_DLC };
    if (xQueueSend(q, &it, 0) != pdTRUE) {
        atomic_store_explicit(&s_wake_posted, false, memory_order_release);
    }
}

/* One queued request frame into the adapter; warns when the gate, the STmin monitor or a latched end withheld an FC.
 * A wake item only re-arms the next wake. */
static void rx_frame(const rx_item_t *it, uint32_t now)
{
    if (it->dlc == RX_WAKE_DLC) {
        atomic_store_explicit(&s_wake_posted, false, memory_order_release);
        return;
    }
    if (it->func) {
        udsota_isotp_on_func_frame(&s_tp, it->data, it->dlc, now);
        return;
    }
    const uint16_t withheld = s_srv.counters.withheld_fcs;
    udsota_isotp_on_frame(&s_tp, it->data, it->dlc, it->t_us, now);
    if (s_srv.counters.withheld_fcs != withheld) {
        ESP_LOGW(TAG, "FC withheld: transfer stopped, session ended");
    }
}

/* The diag task: sleeps on the frame queue until the adapter's next deadline (at most MAX_WAIT_MS), runs
 * a pending end-session, feeds every queued frame and services the adapter. Then it runs an end-session
 * that a hook raised during that service, so the request that raised it finishes first. */
static void task_main(void *arg)
{
    QueueHandle_t q = (QueueHandle_t)arg;
    log_state_t lg = { .last_ms = now_ms(), .losses = 0, .headroom = (UBaseType_t)~(UBaseType_t)0,
                       .heap_min = SIZE_MAX };
    uint32_t wait = 0;
    for (;;) {
        rx_item_t it;
        bool got = xQueueReceive(q, &it, (TickType_t)udsota_esp32_ctl_ticks(wait, configTICK_RATE_HZ)) == pdTRUE;
        const uint32_t now = now_ms();
        mirror_resp_dropped();
        (void)udsota_esp32_ctl_run_end(&s_ctl, &s_srv, now);
        while (got) {
            rx_frame(&it, now);
            got = xQueueReceive(q, &it, 0) == pdTRUE;
        }
        mirror_resp_dropped();
        wait = udsota_isotp_service(&s_tp, now);
        if (udsota_esp32_ctl_run_end(&s_ctl, &s_srv, now)) {
            wait = udsota_isotp_service(&s_tp, now);   /* the session change is served at once */
        }
        if (wait > MAX_WAIT_MS) {
            wait = MAX_WAIT_MS;
        }
        log_status(now, &lg);
    }
}

/* See udsota_esp32.h. Allocates everything once, then starts the task and publishes the queue last. */
esp_err_t udsota_esp32_start(const udsota_config_t *cfg, const udsota_hooks_t *hooks, const udsota_esp32_can_t *can)
{
    if (cfg == NULL || can == NULL || can->can_send == NULL ||
        !udsota_esp32_devid_len_ok(cfg->device_id, cfg->device_id_len) ||
        (cfg->key_pubkey != NULL && !udsota_esp32_sa_pubkey_ok(cfg->key_pubkey, cfg->key_pubkey_len)) ||
        (cfg->func_id != 0u && (cfg->func_id == cfg->req_id || cfg->func_id == cfg->resp_id))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    s_started = true;
#if defined(CONFIG_UDSOTA_ESP32_DEBUG_MEASURE)
    const size_t int_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
#endif
    s_cfg = *cfg;
    /* Fixed before security, which then hashes it; an ID an earlier udsota_esp32_security() call fixed wins. */
    const udsota_esp32_devid_t *dev = NULL;
    if (udsota_esp32_id_fix(s_cfg.device_id, s_cfg.device_id_len, &dev) == UDSOTA_ESP32_DEVID_OTHER) {
        ESP_LOGW(TAG, "cfg.device_id ignored: udsota_esp32_security() already fixed another device ID");
    }
    s_can = *can;
    udsota_esp32_ctl_init(&s_ctl, hooks, default_reset, &s_hooks);
    udsota_esp32_ctl_set_lock(&s_ctl, progress_lock, progress_unlock, &s_progress_mux);
    udsota_isotp_bufs_t *bufs = heap_caps_calloc(1, sizeof *bufs, BUF_CAPS);
    QueueHandle_t q = xQueueCreate(CONFIG_UDSOTA_ESP32_RX_QUEUE_LEN, sizeof(rx_item_t));
    if (bufs == NULL || q == NULL) {
        ESP_LOGE(TAG, "no memory for %u B of buffers or the frame queue: off", (unsigned)sizeof *bufs);
        heap_caps_free(bufs);
        if (q != NULL) {
            vQueueDelete(q);
        }
        return ESP_ERR_NO_MEM;
    }
    udsota_esp32_psa_lock_init();                /* before the first PSA user, security on or off */
    bool master_ignored = false;
    const udsota_esp32_sa_mode_t mode = udsota_esp32_sa_mode(&s_cfg, &master_ignored);
    if (master_ignored) {
        ESP_LOGW(TAG, "cfg.key_master ignored: cfg.key_pubkey selects the ECDSA mode; leave the master out");
    }
    const udsota_security_t *sec =
        (mode == UDSOTA_ESP32_SA_ECDSA) ? udsota_esp32_security_ecdsa(s_cfg.key_pubkey, s_cfg.key_pubkey_len,
                                                                      s_cfg.device_id, s_cfg.device_id_len)
        : (mode == UDSOTA_ESP32_SA_HMAC) ? udsota_esp32_security(s_cfg.key_label, s_cfg.key_master,
                                                                 s_cfg.key_master_len, s_cfg.device_id,
                                                                 s_cfg.device_id_len)
        : NULL;
    udsota_esp32_devid_serve(dev, &s_cfg);       /* F18C serves the stored bytes the key hashes */
#if configTICK_RATE_HZ < 1000
    ESP_LOGW(TAG, "CONFIG_FREERTOS_HZ=%d: the diag task wakes in %d ms steps; 1000 keeps the first 0x78 well "
             "inside P2", configTICK_RATE_HZ, 1000 / configTICK_RATE_HZ);
#endif
    udsota_esp32_engine_set_wake(worker_wake);
    udsota_esp32_engine_start(&s_cfg);           /* logs its own failures; the engine then refuses downloads */
    udsota_init(&s_srv, &s_cfg, udsota_esp32_engine(), sec, &s_hooks);   /* once per boot */
    s_tpcan = (udsota_can_t){
        .send = tp_send, .tx_pending = (s_can.tx_pending != NULL) ? tp_tx_pending : NULL,
        .now_us = tp_now_us, .ctx = NULL,
    };
    udsota_isotp_init(&s_tp, &s_srv, &s_cfg, &s_hooks, &s_tpcan, bufs);   /* installs its own tx_pending */
    if (xTaskCreatePinnedToCoreWithCaps(task_main, "udsota", CONFIG_UDSOTA_ESP32_TASK_STACK, q,
                                        CONFIG_UDSOTA_ESP32_TASK_PRIO, NULL, CONFIG_UDSOTA_ESP32_TASK_CORE,
                                        STACK_CAPS) != pdPASS) {
        ESP_LOGE(TAG, "diag task not created: off");
        vQueueDelete(q);
        heap_caps_free(bufs);
        return ESP_ERR_NO_MEM;
    }
    atomic_store_explicit(&s_q, q, memory_order_release);   /* last: on_frame queues only from now */
#if defined(CONFIG_UDSOTA_ESP32_DEBUG_MEASURE)
    const size_t int_after = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    ESP_LOGI(TAG, "on 0x%03" PRIX32 "/0x%03" PRIX32 ": internal heap -%d B (worker and keys included), "
             "PSRAM %u B buffers + %d B stack, slot %" PRIu32 " B",
             (uint32_t)s_cfg.req_id, (uint32_t)s_cfg.resp_id, (int)int_before - (int)int_after,
             (unsigned)sizeof *bufs, CONFIG_UDSOTA_ESP32_TASK_STACK, udsota_esp32_engine()->slot_size);
#else
    ESP_LOGD(TAG, "on 0x%03" PRIX32 "/0x%03" PRIX32, (uint32_t)s_cfg.req_id, (uint32_t)s_cfg.resp_id);
#endif
    return ESP_OK;
}

/* Any task: copies the frame and its time into the queue without waiting; see udsota_esp32.h. */
void udsota_esp32_on_frame(uint16_t id, const uint8_t *data, uint8_t dlc, uint32_t rx_us)
{
    QueueHandle_t q = atomic_load_explicit(&s_q, memory_order_acquire);
    const bool func = (s_cfg.func_id != 0u && id == s_cfg.func_id);
    if (q == NULL || data == NULL || (id != s_cfg.req_id && !func)) {
        return;
    }
    rx_item_t it = { .dlc = (dlc > 8u) ? 8u : dlc, .func = func, .t_us = rx_us };   /* classic CAN: DLC 9-15 carry 8 bytes */
    memcpy(it.data, data, (dlc > 8u) ? 8u : dlc);
    if (xQueueSend(q, &it, 0) != pdTRUE) {
        atomic_fetch_add_explicit(&s_rx_q_dropped, 1u, memory_order_relaxed);
    }
}

/* Any task: raises the control block's flag once the port runs. */
void udsota_esp32_end_session(void)
{
    if (atomic_load_explicit(&s_q, memory_order_acquire) != NULL) {
        udsota_esp32_ctl_request_end(&s_ctl);
    }
}

/* Any task: the control block's phase copy. */
udsota_phase_t udsota_esp32_phase(void)
{
    return udsota_esp32_ctl_phase(&s_ctl);
}

/* Any task: the control block's progress snapshot once the port runs, else IDLE. */
void udsota_esp32_progress(udsota_progress_t *out)
{
    if (atomic_load_explicit(&s_q, memory_order_acquire) == NULL) {
        *out = (udsota_progress_t){.stage = UDSOTA_STAGE_IDLE};
        return;
    }
    udsota_esp32_ctl_progress(&s_ctl, out);
}
