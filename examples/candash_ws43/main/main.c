/* udsota on iso14229, on the CANDash ws43 (Waveshare ESP32-S3-Touch-LCD-4.3). The app owns everything iso14229
 * needs, as an iso14229 user already does: the TWAI node, the server task that feeds isotp-c and calls UDSServerPoll,
 * and the event callback. The callback hands each event to udsota_event() first and serves the rest (here, F191). */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "driver/i2c_master.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_twai.h"
#include "esp_twai_onchip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "iso14229.h"
#include "udsota.h"

static const char *TAG = "poc";

/* CANDash's identity (CAN-Protocol-SPEC 1.20: Display_Diag_Request/Response), so images move both ways. */
#define REQ_ID        0x7E6u
#define RESP_ID       0x7EEu
#define HW_ID         1u          /* BOARD_WS43 */
#define LAYOUT_ID     1u          /* CANDASH_PARTITION_LAYOUT_ID: partitions.csv is CANDash's */
#define BOARD_NAME    "ws43"      /* F191, which CANDash's client profile checks */
#define DID_BOARD     0xF191u
#define KEY_LABEL     "CANDash-SA-v1"

/* The ws43's CAN: TWAI on GPIO20/19, 250 kbit/s at CANDash's timing (80 MHz / 16, 1 + 15 + 4 quanta, SJW 2). The
 * transceiver shares its pins with USB: CH422G EXIO5 high selects CAN. */
#define CAN_TX_GPIO   20
#define CAN_RX_GPIO   19
#define I2C_SDA       8
#define I2C_SCL       9
#define CH422G_MODE   0x24u       /* the CH422G's registers are I2C addresses */
#define CH422G_IO_OUT 0x38u
#define EXIO_BOOT     ((1u << 5) | (1u << 4) | (1u << 3))   /* USB_SEL = CAN, SD_CS off, LCD out of reset */

#define TX_SLOTS      16u
#define RX_QUEUE_LEN  64u
#define SERVER_STACK  8192u       /* the 0x27 HMAC runs here */
#define SERVER_PRIO   6
#define HEALTHY_MS    10000u

UDSOTA_IMAGE_DESC(HW_ID, LAYOUT_ID, REQ_ID, RESP_ID);

#if defined(POC_HAVE_MASTER)
extern const uint8_t _binary_poc_master_start[];
extern const uint8_t _binary_poc_master_end[];
#endif

typedef struct {
    uint32_t id;
    uint8_t  data[8];
    uint8_t  dlc;
} rx_frame_t;

static twai_node_handle_t s_node;
static QueueHandle_t      s_rxq;
static twai_frame_t       s_tx[TX_SLOTS];       /* the driver keeps each frame until its tx-done event */
static uint8_t            s_tx_data[TX_SLOTS][8];
static atomic_uint        s_tx_busy;            /* bit i: s_tx[i] is with the driver */
static atomic_bool        s_bus_off;            /* set by the ISR; the server task starts the recovery */

static UDSServer_t        s_srv;
static UDSTpISOTpC_t      s_tp;

/* ---- TWAI ---- */

static IRAM_ATTR bool on_rx_done(twai_node_handle_t node, const twai_rx_done_event_data_t *e, void *ctx)
{
    (void)e;
    (void)ctx;
    rx_frame_t f = {0};
    twai_frame_t rx = { .buffer = f.data, .buffer_len = sizeof f.data };
    if (twai_node_receive_from_isr(node, &rx) != ESP_OK || rx.header.ide || rx.header.rtr ||
        rx.header.id != REQ_ID) {
        return false;
    }
    f.id = rx.header.id;
    f.dlc = (rx.header.dlc > 8u) ? 8u : (uint8_t)rx.header.dlc;
    BaseType_t woken = pdFALSE;
    (void)xQueueSendFromISR(s_rxq, &f, &woken);
    return woken == pdTRUE;
}

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

static IRAM_ATTR bool on_state_change(twai_node_handle_t node, const twai_state_change_event_data_t *e, void *ctx)
{
    (void)node;
    (void)ctx;
    if (e->new_sta == TWAI_ERROR_BUS_OFF) {
        atomic_store(&s_bus_off, true);
    }
    return false;
}

static esp_err_t can_start(void)
{
    s_rxq = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_frame_t));
    ESP_RETURN_ON_FALSE(s_rxq != NULL, ESP_ERR_NO_MEM, TAG, "rx queue");
    const twai_onchip_node_config_t cfg = {
        .io_cfg = { .tx = CAN_TX_GPIO, .rx = CAN_RX_GPIO, .quanta_clk_out = GPIO_NUM_NC,
                    .bus_off_indicator = GPIO_NUM_NC },
        .clk_src = TWAI_CLK_SRC_DEFAULT,
        .bit_timing = { .bitrate = 250000 },
        .fail_retry_cnt = -1,                   /* retransmit until acknowledged */
        .tx_queue_depth = TX_SLOTS,
    };
    ESP_RETURN_ON_ERROR(twai_new_node_onchip(&cfg, &s_node), TAG, "twai_new_node_onchip");
    const twai_event_callbacks_t cbs = { .on_rx_done = on_rx_done, .on_tx_done = on_tx_done,
                                         .on_state_change = on_state_change };
    ESP_RETURN_ON_ERROR(twai_node_register_event_callbacks(s_node, &cbs, NULL), TAG, "callbacks");
    const twai_timing_advanced_config_t timing = { .brp = 16, .tseg_1 = 15, .tseg_2 = 4, .sjw = 2 };
    ESP_RETURN_ON_ERROR(twai_node_reconfig_timing(s_node, &timing, NULL), TAG, "bit timing");
    return twai_node_enable(s_node);
}

/* The ws43's CH422G: CAN selected on the shared pins, backlight off. Write, enable outputs, write again. */
static esp_err_t select_can(void)
{
    i2c_master_bus_handle_t bus;
    const i2c_master_bus_config_t bus_cfg = {
        .i2c_port = 0, .sda_io_num = I2C_SDA, .scl_io_num = I2C_SCL, .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7, .flags = { .enable_internal_pullup = 1 },
    };
    ESP_RETURN_ON_ERROR(i2c_new_master_bus(&bus_cfg, &bus), TAG, "i2c");
    i2c_master_dev_handle_t mode, out;
    i2c_device_config_t dev = { .dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = CH422G_MODE,
                                .scl_speed_hz = 100000 };
    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev, &mode), TAG, "ch422g mode");
    dev.device_address = CH422G_IO_OUT;
    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &dev, &out), TAG, "ch422g out");
    const uint8_t io = EXIO_BOOT, oe = 0x01u;
    ESP_RETURN_ON_ERROR(i2c_master_transmit(out, &io, 1, 50), TAG, "io");
    ESP_RETURN_ON_ERROR(i2c_master_transmit(mode, &oe, 1, 50), TAG, "mode");
    return i2c_master_transmit(out, &io, 1, 50);
}

/* ---- isotp-c's platform hooks (iso14229 compiles isotp-c with ISO_TP_USER_SEND_CAN_ARG) ---- */

int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size, void *arg)
{
    (void)arg;
    for (int tries = 0; tries < 10; tries++) {             /* up to ~10 ms for a free slot */
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
            atomic_fetch_or_explicit(&s_tx_busy, 1u << i, memory_order_release);
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

/* iso14229's fn: the updater first, then the app's own services (F191). */
static UDSErr_t on_event(UDSServer_t *srv, UDSEvent_t ev, void *arg)
{
    UDSErr_t rc;
    if (udsota_event(srv, ev, arg, &rc)) {
        return rc;
    }
    switch (ev) {
    case UDS_EVT_ReadDataByIdent: {
        UDSRDBIArgs_t *a = arg;
        if (a->dataId == DID_BOARD) {
            return (UDSErr_t)a->copy(srv, BOARD_NAME, sizeof BOARD_NAME - 1u);
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

/* udsota_cfg_t.reset: iso14229 has sent the answer (11 01 or ActivateImage); let its frames leave. */
static void do_reset(void *ctx)
{
    (void)ctx;
    for (int i = 0; i < 100 && atomic_load(&s_tx_busy) != 0u; i++) {
        vTaskDelay(1);
    }
    ESP_LOGI(TAG, "restarting");
    esp_restart();
}

/* udsota_cfg_t.progress: a log line per stage and per tenth of the image. */
static void on_progress(void *ctx, const udsota_progress_t *p)
{
    (void)ctx;
    static const char *const stages[] = {"idle", "erasing", "writing", "verifying", "activating"};
    static int last_stage = -1;
    static unsigned last_tenth;
    const unsigned tenth = (p->total != 0u) ? (unsigned)((uint64_t)p->done * 10u / p->total) : 0u;
    if ((int)p->stage != last_stage || tenth != last_tenth) {
        ESP_LOGI(TAG, "update: %s %u/%u (last reason %u)", stages[p->stage % 5u], (unsigned)p->done,
                 (unsigned)p->total, (unsigned)p->last_reason);
        last_stage = (int)p->stage;
        last_tenth = tenth;
    }
}

/* The server task: request frames into isotp-c, then UDSServerPoll, at least every millisecond, so a finished
 * flash job is answered within one; bus-off is recovered here, since the driver refuses to send until then. */
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
    }
}

static esp_err_t server_start(void)
{
    const udsota_cfg_t cfg = {
#if defined(POC_HAVE_MASTER)
        .key_label = KEY_LABEL, .key_master = _binary_poc_master_start,
        .key_master_len = (size_t)(_binary_poc_master_end - _binary_poc_master_start),
#endif
        .progress = on_progress, .reset = do_reset,
    };
    if (udsota_init(&cfg) != 0) {
        ESP_LOGW(TAG, "udsota: no inactive slot or worker; downloads refused");
    }
    ESP_RETURN_ON_FALSE(UDSServerInit(&s_srv) == UDS_OK, ESP_FAIL, TAG, "UDSServerInit");
    ESP_RETURN_ON_FALSE(UDSServerTpISOTpCInit(&s_tp, REQ_ID, RESP_ID, UDS_TP_NOOP_ADDR) == UDS_OK, ESP_FAIL, TAG,
                        "isotp");
    s_srv.tp = &s_tp.hdl;
    s_srv.fn = on_event;
    ESP_RETURN_ON_FALSE(xTaskCreatePinnedToCore(server_task, "uds", SERVER_STACK, NULL, SERVER_PRIO, NULL, 0) == pdPASS,
                        ESP_ERR_NO_MEM, TAG, "task");
    ESP_LOGI(TAG, "iso14229 %s serving udsota on 0x%03X/0x%03X, 0x27 %s", UDS_LIB_VERSION, (unsigned)REQ_ID,
             (unsigned)RESP_ID, (cfg.key_master != NULL) ? "on (HMAC)" : "OFF");
    return ESP_OK;
}

void app_main(void)
{
    ESP_LOGI(TAG, "udsota on iso14229 (%s)", esp_app_get_description()->version);
    esp_err_t err = select_can();
    if (err == ESP_OK) {
        err = can_start();
    }
    if (err == ESP_OK) {
        err = server_start();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "start: %s; no updates this boot", esp_err_to_name(err));
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(HEALTHY_MS));
    ESP_LOGI(TAG, "running%s", udsota_unconfirmed() ? "; image not yet confirmed: a reset rolls it back" : "");
}
