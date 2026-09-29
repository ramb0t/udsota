/* udsota on ESP32 over TWAI, the smallest complete integration: the boot-loop counter first, a TWAI node
 * whose receive path feeds request frames to the port and whose transmit path is the port's can_send, the
 * image descriptor, and the port started with security off and one hook, which serves the board name. The
 * comments mark where a real app adds its gate, its settings and its 0x27 master. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_twai.h"
#include "esp_twai_onchip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "udsota.h"
#include "udsota_esp32.h"

static const char *TAG = "example";

/* This image's identity. The same values go into cfg and into the image descriptor, so an image built
 * from this project is accepted only by a unit running it with these values. */
#define EXAMPLE_REQ_ID      0x710u   /* the tester's request ID */
#define EXAMPLE_RESP_ID     0x718u   /* this unit's response ID */
#define EXAMPLE_FUNC_ID     0x7DFu   /* functional requests (OBD's broadcast ID): 3E, 10 01, 10 03 and 22 */
#define EXAMPLE_HW_ID       1u       /* the board this image is for: the product's to allocate */
#define EXAMPLE_LAYOUT_ID   1u       /* the partition layout: bump it whenever partitions.csv moves */
#define EXAMPLE_BOARD_NAME  "devkit" /* this board's name, served as DID F191 */
#define DID_BOARD_NAME      0xF191u

#define TX_SLOTS            4u       /* frames handed to the TWAI driver at once */
#define RX_QUEUE_LEN        32u      /* received frames between the TWAI ISR and the receive task */
#define RX_TASK_STACK       3072u
#define RX_TASK_PRIO        (CONFIG_UDSOTA_ESP32_TASK_PRIO + 1)   /* above the port's diag task (Kconfig help) */
#define HEALTHY_AFTER_MS    10000u   /* this example's health rule: ten seconds up without a crash */

_Static_assert(TX_SLOTS <= 32u, "one bit per slot in s_tx_busy");

/* Places udsota_image_desc at image offset 288; main/CMakeLists.txt calls udsota_esp32_image_desc(). */
UDSOTA_ESP32_IMAGE_DESC(EXAMPLE_HW_ID, EXAMPLE_LAYOUT_ID, EXAMPLE_REQ_ID, EXAMPLE_RESP_ID);

/* One received standard data frame and the microsecond the ISR took it. */
typedef struct {
    uint32_t id;
    uint32_t t_us;
    uint8_t  data[8];
    uint8_t  dlc;
} rx_frame_t;

static twai_node_handle_t s_node;
static QueueHandle_t      s_rxq;
/* The driver keeps a pointer to each frame until its tx-done event, so each queued frame owns a slot. */
static twai_frame_t       s_tx[TX_SLOTS];
static uint8_t            s_tx_data[TX_SLOTS][8];
static atomic_uint        s_tx_busy;      /* bit i set: s_tx[i] is with the driver */
static atomic_uint        s_tx_failed;    /* frames the driver gave up on after queueing them */

/* TWAI ISR: queues each standard data frame with its receive time for can_rx_task; true when a
 * higher-priority task woke. */
static IRAM_ATTR bool on_rx_done(twai_node_handle_t node, const twai_rx_done_event_data_t *e, void *ctx)
{
    (void)e;
    (void)ctx;
    rx_frame_t f = { .t_us = (uint32_t)esp_timer_get_time() };
    twai_frame_t rx = { .buffer = f.data, .buffer_len = sizeof f.data };
    if (twai_node_receive_from_isr(node, &rx) != ESP_OK || rx.header.ide || rx.header.rtr) {
        return false;   /* udsota uses 11-bit data frames only */
    }
    f.id = rx.header.id;
    f.dlc = (rx.header.dlc > 8u) ? 8u : (uint8_t)rx.header.dlc;
    BaseType_t woken = pdFALSE;
    (void)xQueueSendFromISR(s_rxq, &f, &woken);   /* a full queue drops the frame; ISO-TP times it out */
    return woken == pdTRUE;
}

/* TWAI ISR: frees the finished frame's slot, counting it when the driver gave up on it. */
static IRAM_ATTR bool on_tx_done(twai_node_handle_t node, const twai_tx_done_event_data_t *e, void *ctx)
{
    (void)node;
    (void)ctx;
    const ptrdiff_t i = e->done_tx_frame - s_tx;
    if (i >= 0 && i < (ptrdiff_t)TX_SLOTS) {
        if (!e->is_tx_success) {
            atomic_fetch_add_explicit(&s_tx_failed, 1u, memory_order_relaxed);
        }
        atomic_fetch_and_explicit(&s_tx_busy, ~(1u << i), memory_order_release);
    }
    return false;
}

/* The app's CAN receive task: request frames go to udsota before the app decodes anything. The port's
 * udsota_esp32_on_frame() uses a task-level queue call, so it runs here and never in the ISR. */
static void can_rx_task(void *arg)
{
    (void)arg;
    rx_frame_t f;
    for (;;) {
        if (xQueueReceive(s_rxq, &f, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (f.id == EXAMPLE_REQ_ID || f.id == EXAMPLE_FUNC_ID) {
            udsota_esp32_on_frame((uint16_t)f.id, f.data, f.dlc, f.t_us);
            continue;
        }
        /* ... the app's own frames ... */
    }
}

/* udsota_esp32_can_t.can_send (diag task): queues one frame in a free slot without waiting. ESP_ERR_NO_MEM
 * (every slot busy, or the driver's queue full) makes the port keep the frame and retry. */
static esp_err_t can_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    (void)ctx;
    const unsigned busy = atomic_load_explicit(&s_tx_busy, memory_order_acquire);
    unsigned i = 0;
    while (i < TX_SLOTS && (busy & (1u << i)) != 0u) {
        i++;
    }
    if (i == TX_SLOTS) {
        return ESP_ERR_NO_MEM;
    }
    const uint8_t n = (len > 8u) ? 8u : len;
    memcpy(s_tx_data[i], data, n);
    s_tx[i] = (twai_frame_t){ .header = { .id = id, .dlc = n }, .buffer = s_tx_data[i], .buffer_len = n };
    atomic_fetch_or_explicit(&s_tx_busy, 1u << i, memory_order_release);   /* before on_tx_done can run */
    const esp_err_t err = twai_node_transmit(s_node, &s_tx[i], 0);
    if (err != ESP_OK) {
        atomic_fetch_and_explicit(&s_tx_busy, ~(1u << i), memory_order_release);
        return (err == ESP_ERR_TIMEOUT) ? ESP_ERR_NO_MEM : err;
    }
    return ESP_OK;
}

/* udsota_esp32_can_t.tx_pending (diag task): frames still with the driver, so a restart waits for the
 * answer to leave. */
static uint32_t can_tx_pending(void *ctx)
{
    (void)ctx;
    return (uint32_t)__builtin_popcount(atomic_load_explicit(&s_tx_busy, memory_order_acquire));
}

/* udsota_esp32_can_t.tx_dropped (diag task): frames the driver gave up on, for F1F2's resp_frames_dropped.
 * Only udsota transmits in this example, so every one was a response frame. */
static uint32_t can_tx_dropped(void *ctx)
{
    (void)ctx;
    return atomic_load_explicit(&s_tx_failed, memory_order_relaxed);
}

/* Starts the TWAI node at CONFIG_EXAMPLE_CAN_BITRATE on the Kconfig GPIOs, and the receive task on the
 * port's diag-task core. A real app also recovers from bus-off (twai_node_recover()); this one does not. */
static esp_err_t can_start(void)
{
    s_rxq = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_frame_t));
    ESP_RETURN_ON_FALSE(s_rxq != NULL, ESP_ERR_NO_MEM, TAG, "rx queue");
    const twai_onchip_node_config_t cfg = {
        .io_cfg = {
            .tx = (gpio_num_t)CONFIG_EXAMPLE_CAN_TX_GPIO,
            .rx = (gpio_num_t)CONFIG_EXAMPLE_CAN_RX_GPIO,
            .quanta_clk_out = GPIO_NUM_NC,      /* explicit: 0 would claim GPIO0 */
            .bus_off_indicator = GPIO_NUM_NC,
        },
        .bit_timing = { .bitrate = CONFIG_EXAMPLE_CAN_BITRATE },
        .fail_retry_cnt = -1,                   /* retransmit until acknowledged, as classic CAN does */
        .tx_queue_depth = TX_SLOTS,
    };
    ESP_RETURN_ON_ERROR(twai_new_node_onchip(&cfg, &s_node), TAG, "twai_new_node_onchip");
    const twai_event_callbacks_t cbs = { .on_rx_done = on_rx_done, .on_tx_done = on_tx_done };
    ESP_RETURN_ON_ERROR(twai_node_register_event_callbacks(s_node, &cbs, NULL), TAG, "callbacks");
    ESP_RETURN_ON_FALSE(xTaskCreatePinnedToCore(can_rx_task, "can_rx", RX_TASK_STACK, NULL, RX_TASK_PRIO, NULL,
                                                CONFIG_UDSOTA_ESP32_TASK_CORE) == pdPASS,
                        ESP_ERR_NO_MEM, TAG, "rx task");
    return twai_node_enable(s_node);
}

/* udsota_hooks_t.did_read (diag task): F191 answers the board name, and 0 for every other DID means "no
 * such DID" (NRC 0x31); the core serves its own DIDs without asking. The client profile's [board] and
 * [dids] sections read F191, and flash refuses to start without it. */
static size_t did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    (void)ctx;
    const size_t n = sizeof EXAMPLE_BOARD_NAME - 1u;   /* ASCII, no NUL */
    if (did != DID_BOARD_NAME || n > max) {
        return 0;
    }
    memcpy(buf, EXAMPLE_BOARD_NAME, n);
    return n;
}

/* Starts udsota with the neutral example identity, security off and only the did_read hook. */
static esp_err_t updater_start(void)
{
    /* The port copies cfg; what it points to (here the product string) must outlive it. Zero fields take
     * the core's defaults (P2 50 ms, P2* 5 s, S3 5 s, 4,095-byte blocks, BS 64, STmin 2 ms). */
    static const udsota_config_t cfg = {
        .req_id = EXAMPLE_REQ_ID,
        .resp_id = EXAMPLE_RESP_ID,
        .func_id = EXAMPLE_FUNC_ID,
        .product = "example",           /* must equal project() in CMakeLists.txt: esp_app_desc_t's project name */
        .hw_id = EXAMPLE_HW_ID,
        .layout_id = EXAMPLE_LAYOUT_ID,
        .device_id = NULL,              /* the port serves the base MAC as F18C */
        /* Security is off: key_pubkey and key_label are NULL, so 0x27 answers 0x11 and any tester on the bus
         * may program the unit. To turn it on, prefer the ECDSA mode: run `udsota keygen --out keys` (keys/ is
         * git-ignored), move keys/udsota_private.pem into the signing service (never into the repository or
         * the image), copy the public keys/udsota_pubkey.h next to this file, include it and set
         * .key_pubkey = udsota_pubkey and .key_pubkey_len = sizeof udsota_pubkey. The image then holds only
         * the public key, which unlocks nothing, and the client's profile sets [security] mode = "ecdsa".
         * The HMAC mode instead sets .key_label (for example "udsota-example") and points .key_master and
         * .key_master_len at a master key the app embeds from a git-ignored file at build time; every image
         * then carries the fleet's secret. Never commit either secret. Also turn on signed updates
         * (CONFIG_SECURE_SIGNED_ON_UPDATE), so FF01 checks a signature and not only a SHA-256. */
        .key_pubkey = NULL,
        .key_label = NULL,
    };
    const udsota_esp32_can_t can = {
        .can_send = can_send, .tx_pending = can_tx_pending, .tx_dropped = can_tx_dropped, .ctx = NULL,
    };
    /* Only did_read is set. With no gate every step is allowed at any time; a real app adds .gate here, which
     * refuses each step (UDSOTA_NRC_CONDITIONS_NOT_CORRECT) while updating is unsafe and holds
     * UDSOTA_OP_CONFIRM until the app's own self-test has passed. With no reset, a restart over UDS is
     * the port's esp_restart(). A product whose app sends its own frames adds .comm_control, which stops them
     * for 28 01/03 (a tester sends it to the whole bus before programming) until 28 00 or the default
     * session, and one that records DTCs adds .dtc_setting for 85; without them, 28 and 85 answer 0x11
     * (nothing, functionally). The port copies the struct. */
    const udsota_hooks_t hooks = { .did_read = did_read, .ctx = NULL };
    return udsota_esp32_start(&cfg, &hooks, &can);
}

/* Boot order: the boot-loop counter, settings, CAN, the updater, then the health decision. */
void app_main(void)
{
    /* First, before anything reads stored settings: counts this boot, and after three crash resets in a
     * row makes this boot skip them, since rollback cannot help a valid image that crashes on its config. */
    udsota_esp32_bootloop_init();
    if (udsota_esp32_bootloop_config_ignored()) {
        ESP_LOGW(TAG, "repeated crash resets: running on defaults this boot");
    } else {
        /* ... load the app's stored settings (NVS) here ... */
    }

    esp_err_t err = can_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "CAN start: %s; no updates this boot", esp_err_to_name(err));
        return;
    }
    err = updater_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "udsota_esp32_start: %s; the app runs on without updates", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "udsota on 0x%03X/0x%03X", (unsigned)EXAMPLE_REQ_ID, (unsigned)EXAMPLE_RESP_ID);
    }

    /* Rollback (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE): an image the client has just activated boots pending
     * verify, and the client's ConfirmImage (31 01 F002) keeps it. The app never calls
     * esp_ota_mark_app_valid_cancel_rollback() itself; it holds the confirm with its gate if it wants a say.
     * A reset before the confirm boots the previous image again. Being healthy, below, is a separate matter:
     * it clears the boot-loop count and confirms nothing. Built without the updater there is no F002, and
     * sdkconfig.noupdater turns rollback off: a device that takes its images some other way with rollback on
     * confirms them there, since udsota_esp32_image_unconfirmed() then reads false without looking. */

    /* The app decides when it is healthy; here, after HEALTHY_AFTER_MS up. */
    vTaskDelay(pdMS_TO_TICKS(HEALTHY_AFTER_MS));
    udsota_esp32_bootloop_mark_healthy();
    ESP_LOGI(TAG, "healthy%s", udsota_esp32_image_unconfirmed() ? "; image not yet confirmed, a reset rolls it back" : "");

    /* The local status snapshot, for a UI or a log: what F1F0 reports with the updater. Built without it
     * (sdkconfig.noupdater), nothing serves F1F0 unless did_read does (udsota_pack_status() over this), both
     * slots read UDSOTA_SLOT_NONE and the updater is never busy; only the flags remain. */
    udsota_status_t st;
    udsota_esp32_status(&st);
    ESP_LOGI(TAG, "slots: running %u, boot %u, flags 0x%02X%s", (unsigned)st.running_slot, (unsigned)st.boot_slot,
             (unsigned)st.flags, udsota_esp32_engine_busy() ? "; an update job is running" : "");
}
