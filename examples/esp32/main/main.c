/* udsota on ESP32 over TWAI, the smallest complete integration. The app owns everything iso14229 needs: a TWAI node
 * whose receive ISR queues request frames, isotp-c's send hook on the same node, the server task that feeds isotp-c
 * and calls UDSServerPoll (then udsota_poll), and the event callback, which hands each event to udsota_event() first
 * and serves the rest: here only the board name, DID F191. The image descriptor and udsota_init() with security off
 * complete it. The comments mark where a real app adds its gate, its own services and a 0x27 key. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_twai.h"
#include "esp_twai_onchip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "iso14229.h"
#include "udsota.h"

static const char *TAG = "example";

/* This image's identity. The same IDs go to the transport and into the image descriptor, so an image built from this
 * project is accepted only by a unit running it with these values; nothing checks that the two agree, so keep them
 * from one set of defines. */
#define EXAMPLE_REQ_ID      0x710u   /* the tester's request ID */
#define EXAMPLE_RESP_ID     0x718u   /* this unit's response ID */
#define EXAMPLE_HW_ID       1u       /* the board this image is for: the product's to allocate */
#define EXAMPLE_LAYOUT_ID   1u       /* the partition layout: bump it whenever partitions.csv moves */
#define EXAMPLE_BOARD_NAME  "devkit" /* this board's name, served as DID F191 */
#define DID_BOARD_NAME      0xF191u

#define TX_SLOTS            4u       /* frames handed to the TWAI driver at once */
#define RX_QUEUE_LEN        32u      /* received frames between the TWAI ISR and the server task */
#define SERVER_STACK        8192u    /* 0x27's key check runs here once keys are set */
#define SERVER_PRIO         5
#define STATE_LOG_AFTER_MS  10000u   /* how long app_main waits before logging the slot state */

_Static_assert(TX_SLOTS <= 32u, "one bit per slot in s_tx_busy");
_Static_assert(EXAMPLE_REQ_ID <= 0x7FFu && EXAMPLE_RESP_ID <= 0x7FFu, "udsota uses 11-bit IDs");

/* Places udsota_image_desc at image offset 288; udsota's CMakeLists sets its release flag and keeps it in the link. */
UDSOTA_IMAGE_DESC(EXAMPLE_HW_ID, EXAMPLE_LAYOUT_ID, EXAMPLE_REQ_ID, EXAMPLE_RESP_ID);

/* One received request frame. */
typedef struct {
    uint8_t data[8];
    uint8_t dlc;
} rx_frame_t;

static twai_node_handle_t s_node;
static QueueHandle_t      s_rxq;
/* The driver keeps a pointer to each frame until its tx-done event, so each queued frame owns a slot. */
static twai_frame_t       s_tx[TX_SLOTS];
static uint8_t            s_tx_data[TX_SLOTS][8];
static atomic_uint        s_tx_busy;      /* bit i set: s_tx[i] is with the driver */
static atomic_bool        s_bus_off;      /* set by the ISR; the server task starts the recovery */

static UDSServer_t        s_srv;
static UDSTpISOTpC_t      s_tp;

/* ---- TWAI ---- */

/* TWAI ISR: queues each standard data frame on the request ID for the server task; true when a higher-priority task
 * woke. An app with frames of its own routes them to its own queue here. */
static IRAM_ATTR bool on_rx_done(twai_node_handle_t node, const twai_rx_done_event_data_t *e, void *ctx)
{
    (void)e;
    (void)ctx;
    rx_frame_t f = {0};
    twai_frame_t rx = { .buffer = f.data, .buffer_len = sizeof f.data };
    if (twai_node_receive_from_isr(node, &rx) != ESP_OK || rx.header.ide || rx.header.rtr ||
        rx.header.id != EXAMPLE_REQ_ID) {
        return false;
    }
    f.dlc = (rx.header.dlc > 8u) ? 8u : (uint8_t)rx.header.dlc;
    BaseType_t woken = pdFALSE;
    (void)xQueueSendFromISR(s_rxq, &f, &woken);   /* a full queue drops the frame; ISO-TP times it out */
    return woken == pdTRUE;
}

/* TWAI ISR: frees the finished frame's slot. */
static IRAM_ATTR bool on_tx_done(twai_node_handle_t node, const twai_tx_done_event_data_t *e, void *ctx)
{
    (void)node;
    (void)ctx;
    const ptrdiff_t i = e->done_tx_frame - s_tx;
    if (i >= 0 && i < (ptrdiff_t)TX_SLOTS) {
        atomic_fetch_and_explicit(&s_tx_busy, ~(1u << i), memory_order_release);
    }
    return false;
}

/* TWAI ISR: flags bus-off, which the driver stays in until twai_node_recover(). */
static IRAM_ATTR bool on_state_change(twai_node_handle_t node, const twai_state_change_event_data_t *e, void *ctx)
{
    (void)node;
    (void)ctx;
    if (e->new_sta == TWAI_ERROR_BUS_OFF) {
        atomic_store(&s_bus_off, true);
    }
    return false;
}

/* Starts the TWAI node at CONFIG_EXAMPLE_CAN_BITRATE on the Kconfig GPIOs. */
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
    const twai_event_callbacks_t cbs = { .on_rx_done = on_rx_done, .on_tx_done = on_tx_done,
                                         .on_state_change = on_state_change };
    ESP_RETURN_ON_ERROR(twai_node_register_event_callbacks(s_node, &cbs, NULL), TAG, "callbacks");
    return twai_node_enable(s_node);
}

/* ---- isotp-c's platform hooks (iso14229 compiles isotp-c with ISO_TP_USER_SEND_CAN_ARG) ---- */

/* Queues one frame in a free slot, waiting up to about 10 ms for one; ISOTP_RET_NOSPACE makes isotp-c try again on
 * its next poll. */
int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    (void)arg;
    for (int tries = 0; tries < 10; tries++) {
        const unsigned busy = atomic_load_explicit(&s_tx_busy, memory_order_acquire);
        unsigned i = 0;
        while (i < TX_SLOTS && (busy & (1u << i)) != 0u) {
            i++;
        }
        if (i < TX_SLOTS) {
            const uint8_t n = (size > 8u) ? 8u : size;
            memcpy(s_tx_data[i], data, n);
            s_tx[i] = (twai_frame_t){ .header = { .id = arbitration_id, .dlc = n }, .buffer = s_tx_data[i],
                                      .buffer_len = n };
            atomic_fetch_or_explicit(&s_tx_busy, 1u << i, memory_order_release);   /* before on_tx_done can run */
            if (twai_node_transmit(s_node, &s_tx[i], 0) == ESP_OK) {
                return ISOTP_RET_OK;
            }
            atomic_fetch_and_explicit(&s_tx_busy, ~(1u << i), memory_order_release);
        }
        vTaskDelay(1);
    }
    return ISOTP_RET_NOSPACE;
}

uint32_t isotp_user_get_us(void)
{
    return (uint32_t)esp_timer_get_time();
}

void isotp_user_debug(const char *message, ...)
{
    (void)message;
}

/* ---- The iso14229 server and its event callback ---- */

/* iso14229's fn: the updater first, then the app's own services. F191 answers the board name, which the client
 * profile's [board] and [dids] read and without which flash refuses to start. Everything udsota passes back that the
 * app doesn't serve gets an NRC: 0x27 answers 0x11 while security is off, and 28 and 85 answer 0x11 too. A product
 * whose app sends its own frames serves 28 (UDS_EVT_CommCtrl), stopping them for 28 01/03, which a tester sends to
 * the whole bus before programming, and one that records DTCs serves 85 (UDS_EVT_ControlDTCSetting). Both undo it
 * themselves at UDS_EVT_SessionTimeout and on a 10 01, a UDS_EVT_DiagSessCtrl that udsota answers, so they check for
 * it when udsota_event returns true. */
static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent: {
        UDSRDBIArgs_t *a = arg;
        if (a->dataId == DID_BOARD_NAME) {
            return (UDSErr_t)a->copy(srv, EXAMPLE_BOARD_NAME, sizeof EXAMPLE_BOARD_NAME - 1u);   /* ASCII, no NUL */
        }
        return UDS_NRC_RequestOutOfRange;
    }
    case UDS_EVT_DiagSessCtrl:
        return UDS_NRC_SubFunctionNotSupported;          /* a session the updater doesn't know */
    case UDS_EVT_SessionTimeout:
    case UDS_EVT_Err:
        return UDS_OK;
    default:
        return UDS_NRC_ServiceNotSupported;
    }
}

/* udsota_cfg_t.reset: iso14229 has queued the answer (11 01, or ActivateImage's); let its frames leave first, since
 * esp_restart() would cut them off. */
static void do_reset(void *ctx)
{
    (void)ctx;
    for (int i = 0; i < 100 && atomic_load(&s_tx_busy) != 0u; i++) {
        vTaskDelay(1);
    }
    ESP_LOGI(TAG, "restarting");
    esp_restart();
}

/* The server task: request frames into isotp-c, then UDSServerPoll and udsota_poll, at least every millisecond, so a
 * finished flash job is answered within one. Bus-off is recovered here, since the driver refuses to send until then. */
static void server_task(void *arg)
{
    (void)arg;
    for (;;) {
        rx_frame_t f;
        if (xQueueReceive(s_rxq, &f, pdMS_TO_TICKS(1)) == pdTRUE) {
            do {
                isotp_on_can_message(&s_tp.phys_link, f.data, f.dlc);
            } while (xQueueReceive(s_rxq, &f, 0) == pdTRUE);
        }
        if (atomic_exchange(&s_bus_off, false)) {
            ESP_LOGW(TAG, "bus-off: recovering");
            (void)twai_node_recover(s_node);
        }
        UDSServerPoll(&s_srv);
        udsota_poll(&s_srv);
    }
}

/* Starts udsota with security off and no gate, then iso14229's server on the example's IDs and its task. */
static esp_err_t server_start(void)
{
    /* udsota copies cfg; what it points to must outlive it. product is NULL, so an image must carry this one's project
     * name, "example" from project() in CMakeLists.txt.
     *
     * Security is off: with no key_pubkey and no key_master, 0x27 is the app's and any tester on the bus may program
     * the unit. To turn it on, prefer the ECDSA mode: run `udsota keygen --out keys` (keys/ is git-ignored), move
     * keys/udsota_private.pem into the signing service (never into the repository or the image), copy the public
     * keys/udsota_pubkey.h next to this file, include it and set .key_pubkey = udsota_pubkey and
     * .key_pubkey_len = sizeof udsota_pubkey. The image then holds only the public key, which unlocks nothing, and
     * the client's profile sets [security] mode = "ecdsa". The HMAC mode instead sets .key_label (for example
     * "udsota-example") and points .key_master and .key_master_len at a master key the app embeds from a git-ignored
     * file at build time; every image then carries the fleet's secret. Never commit either secret. Also turn on
     * signed updates, so FF01 checks a signature and not only a SHA-256: CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y
     * and CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y with a signing scheme and key, as in
     * examples/candash_ws43/sdkconfig.defaults, or secure boot. Either sets CONFIG_SECURE_SIGNED_ON_UPDATE, which has
     * no prompt of its own.
     *
     * With no gate every step is allowed at any time; a real app adds .gate, which refuses each step
     * (UDS_NRC_ConditionsNotCorrect) while updating is unsafe and holds UDSOTA_OP_CONFIRM until its own self-test has
     * passed. .progress would feed a display. */
    const udsota_cfg_t cfg = { .reset = do_reset };
    if (udsota_init(&cfg) != 0) {
        ESP_LOGW(TAG, "udsota: no inactive slot or worker; downloads refused");
    }
    ESP_RETURN_ON_FALSE(UDSServerInit(&s_srv) == UDS_OK, ESP_FAIL, TAG, "UDSServerInit");
    s_srv.p2_ms = 5;  /* iso14229's 50 ms default spaces back-to-back answers enough to clip the client's P2 under a
                         CAN rate cap; 5 ms keeps a token rate limit. See README "Known limits". */
    ESP_RETURN_ON_FALSE(UDSServerTpISOTpCInit(&s_tp, EXAMPLE_REQ_ID, EXAMPLE_RESP_ID, UDS_TP_NOOP_ADDR) == UDS_OK,
                        ESP_FAIL, TAG, "isotp");
    s_srv.tp = &s_tp.hdl;
    s_srv.fn = on_event;
    ESP_RETURN_ON_FALSE(xTaskCreate(server_task, "uds", SERVER_STACK, NULL, SERVER_PRIO, NULL) == pdPASS,
                        ESP_ERR_NO_MEM, TAG, "server task");
    ESP_LOGI(TAG, "udsota %s on iso14229 %s, 0x%03X/0x%03X", UDSOTA_VERSION, UDS_LIB_VERSION,
             (unsigned)EXAMPLE_REQ_ID, (unsigned)EXAMPLE_RESP_ID);
    return ESP_OK;
}

/* Boot order: settings, CAN, the updater, then a log of the slot state. */
void app_main(void)
{
    /* ... load the app's stored settings (NVS) here ... */

    esp_err_t err = can_start();
    if (err == ESP_OK) {
        err = server_start();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "start: %s; no updates this boot", esp_err_to_name(err));
        return;
    }

    /* Rollback (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE): an image the client has just activated boots pending verify,
     * and the client's ConfirmImage (31 01 F002) keeps it. The app never calls
     * esp_ota_mark_app_valid_cancel_rollback() itself; it holds the confirm with its gate if it wants a say. A reset
     * before the confirm boots the previous image again. */
    vTaskDelay(pdMS_TO_TICKS(STATE_LOG_AFTER_MS));
    ESP_LOGI(TAG, "running%s", udsota_unconfirmed() ? "; image not yet confirmed, a reset rolls it back" : "");

    /* The local status snapshot, for a UI or a log: what F1F0 reports. Any task may read it. */
    udsota_status_t st;
    udsota_plat_status(&st);
    ESP_LOGI(TAG, "slots: running %u, boot %u, flags 0x%02X%s", (unsigned)st.running_slot, (unsigned)st.boot_slot,
             (unsigned)st.flags, udsota_busy() ? "; an update is running" : "");
}
