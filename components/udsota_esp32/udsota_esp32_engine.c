/* udsota ESP32 engine (udsota_esp32.h): udsota_engine_t on esp_ota_*. Every flash-touching esp_ota_* call
 * runs on one worker task; the server's task queues jobs through s_q and polls s_pending. Only the worker
 * writes s_cache (eng_unverify only demotes VERIFIED), and every other task reads it under s_mux, so status
 * readers never wait behind an erase. With CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE an activated image boots
 * PENDING_VERIFY and needs confirm; without it the image is permanent and confirm does nothing. IDF v6.1
 * line numbers below are components/app_update/esp_ota_ops.c unless another file is named. */
#include "udsota_esp32.h"

#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
#include "esp_private/flash_mmap.h"   /* flash_mmap_remain(): the cache-off check, logged only */
#endif

#include "udsota_esp32_image.h"
#include "udsota_esp32_priv.h"

static const char *TAG = "udsota_eng";

/* udsota_esp32_image.c and the core's udsota_image.c copy these IDF layouts so they build on the host, and
 * the host tests check them against synthesised blocks; these pin the copies to IDF's own headers. */
_Static_assert(sizeof(esp_image_header_t) == 24u && sizeof(esp_image_segment_header_t) == 8u &&
               sizeof(esp_app_desc_t) == 256u, "image header, segment header and app desc sizes");
_Static_assert(offsetof(esp_image_header_t, segment_count) == 1u && offsetof(esp_image_header_t, spi_mode) == 2u &&
               offsetof(esp_image_header_t, chip_id) == 12u, "esp_image_header_t fields the check reads");
_Static_assert(offsetof(esp_image_segment_header_t, data_len) == 4u, "segment 0 data_len at image offset 28");
_Static_assert(offsetof(esp_app_desc_t, version) == 16u && offsetof(esp_app_desc_t, project_name) == 48u,
               "esp_app_desc_t version and project_name");
_Static_assert(ESP_IMAGE_HEADER_MAGIC == 0xE9 && ESP_IMAGE_MAX_SEGMENTS == 16 &&
               ESP_IMAGE_SPI_MODE_SLOW_READ == 5 && ESP_APP_DESC_MAGIC_WORD == 0xABCD5432u,
               "the constants udsota_esp32_image.c copies");
_Static_assert(UDSOTA_ESP32_CHIP_ID_S3 == ESP_CHIP_ID_ESP32S3, "the host tests' chip ID");

#define WORKER_STACK    CONFIG_UDSOTA_ESP32_WORKER_STACK   /* bytes, internal: RSA-3072 verify inside esp_ota_end */
#define WORKER_PRIO     CONFIG_UDSOTA_ESP32_WORKER_PRIO    /* below the app's own tasks, so they run during an erase */
#define WORKER_CORE     CONFIG_UDSOTA_ESP32_WORKER_CORE
#define QUEUE_LEN       4       /* BEGIN + WRITE of the first block, plus slack */
#define SHA_PREFIX      8u      /* status other_elf_sha_prefix */
#define BLOCK_BUF       4096u   /* the worker's internal-RAM block buffer: one whole 0x36 payload */
#define ERR_NOT_STARTED (-1)    /* engine not started, its allocation failed, or no inactive slot */
#define ERR_BUSY        (-2)    /* job queue full, or the block buffer still holds an unwritten block */
#define ERR_ARG         (-3)    /* NULL data, or a block longer than BLOCK_BUF */

_Static_assert(BLOCK_BUF >= UDSOTA_DL_MAX_DATA, "a whole 0x36 payload fits the worker buffer");
_Static_assert(sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t) ==
               UDSOTA_IMG_DESC_OFFSET, "udsota_image_desc_t sits right after esp_app_desc_t");

typedef enum { JOB_REFRESH, JOB_BEGIN, JOB_WRITE, JOB_END, JOB_ABORT, JOB_ACTIVATE, JOB_CONFIRM } job_kind_t;

typedef struct {
    uint8_t  kind;              /* job_kind_t */
    uint32_t arg;               /* BEGIN: announced image size; WRITE: bytes in s_buf */
} job_t;

typedef struct {
    bool    ready;              /* the boot read has finished */
    uint8_t running_slot;       /* UDSOTA_SLOT_* */
    uint8_t running_state;      /* udsota_img_state_t */
    uint8_t boot_slot;          /* UDSOTA_SLOT_*: the otadata boot target */
    uint8_t other_slot_state;   /* udsota_other_state_t */
    uint8_t other_version[3];   /* when INVALID: the rolled-back image's version */
    uint8_t other_sha_prefix[SHA_PREFIX];
} ota_cache_t;

/* Shared: read and written under s_mux. */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ota_cache_t s_cache = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE};
static uint32_t s_pending;          /* ops jobs queued and not finished */
static uint32_t s_refreshing;       /* refresh jobs queued and not finished */
static int s_batch_result;          /* first failure since s_pending was last 0 */
static bool s_buf_busy;             /* s_buf holds a block the worker has not written yet */
static bool s_verified;             /* FF01 passed on s_target since the last BEGIN, eng_unverify or boot */
static uint32_t s_unverify_gen;     /* bumped by every eng_unverify: a verify that spans one never marks the slot */

/* Set once by udsota_esp32_engine_start() before the worker runs; read-only afterwards. */
static QueueHandle_t s_q;
static uint8_t *s_buf;                      /* BLOCK_BUF bytes, internal RAM */
static const esp_partition_t *s_target;     /* the inactive slot; NULL refuses every download */
static udsota_image_ctx_t s_ctx;

/* Worker only. */
static esp_ota_handle_t s_handle;
static bool s_handle_open;
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
static uint32_t s_writes;           /* blocks written since the last BEGIN */
static uint32_t s_mmap_writes;      /* of those, blocks written while a flash mmap was held (cache off) */
#endif

/* Status slot number of an app partition: ota_0 -> 0, ota_1 -> 1, anything else (or NULL) -> NONE. */
static uint8_t slot_of(const esp_partition_t *p)
{
    if (p == NULL || p->type != ESP_PARTITION_TYPE_APP) {
        return UDSOTA_SLOT_NONE;
    }
    if (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0) {
        return UDSOTA_SLOT_OTA0;
    }
    if (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
        return UDSOTA_SLOT_OTA1;
    }
    return UDSOTA_SLOT_NONE;
}

/* Compacts IDF's otadata state (NEW 0 .. ABORTED 4, UNDEFINED 0xFFFFFFFF) to the status byte. */
static uint8_t map_state(esp_ota_img_states_t st)
{
    switch (st) {
    case ESP_OTA_IMG_NEW:            return UDSOTA_IMG_NEW;
    case ESP_OTA_IMG_PENDING_VERIFY: return UDSOTA_IMG_PENDING_VERIFY;
    case ESP_OTA_IMG_VALID:          return UDSOTA_IMG_VALID;
    case ESP_OTA_IMG_INVALID:        return UDSOTA_IMG_INVALID;
    case ESP_OTA_IMG_ABORTED:        return UDSOTA_IMG_ABORTED;
    default:                         return UDSOTA_IMG_UNDEFINED;
    }
}

/* Copy of the cache taken under the lock. */
static ota_cache_t cache_get(void)
{
    taskENTER_CRITICAL(&s_mux);
    ota_cache_t c = s_cache;
    taskEXIT_CRITICAL(&s_mux);
    return c;
}

/* Worker: replaces the cache under the lock (the worker is its only writer besides eng_unverify's
 * demotion). A VERIFIED other slot is stored only while s_verified holds, so a copy taken before an
 * eng_unverify can't bring VERIFIED back into the status. */
static void cache_put(const ota_cache_t *c)
{
    taskENTER_CRITICAL(&s_mux);
    s_cache = *c;
    if (s_cache.other_slot_state == UDSOTA_OTHER_VERIFIED && !s_verified) {
        s_cache.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
    }
    taskEXIT_CRITICAL(&s_mux);
}

/* s_verified read under the lock. */
static bool verified_get(void)
{
    taskENTER_CRITICAL(&s_mux);
    bool v = s_verified;
    taskEXIT_CRITICAL(&s_mux);
    return v;
}

/* Worker: fills c's other-slot fields with state and, unless a download is writing the slot, the
 * version and SHA prefix from its app descriptor (the rolled-back image's when state is INVALID);
 * a slot with no descriptor reads EMPTY. */
static void fill_other(ota_cache_t *c, uint8_t state)
{
    esp_app_desc_t d;
    memset(c->other_version, 0, sizeof c->other_version);
    memset(c->other_sha_prefix, 0, sizeof c->other_sha_prefix);
    c->other_slot_state = state;
    if (state == UDSOTA_OTHER_WRITING) {
        return;
    }
    if (s_target == NULL || esp_ota_get_partition_description(s_target, &d) != ESP_OK) {
        c->other_slot_state = UDSOTA_OTHER_EMPTY;
        return;
    }
    (void)udsota_parse_version(d.version, sizeof d.version, c->other_version, NULL);
    memcpy(c->other_sha_prefix, d.app_elf_sha256, SHA_PREFIX);
}

/* Worker: sets the other slot's state in the cache and re-reads its descriptor. */
static void set_other(uint8_t state)
{
    ota_cache_t c = cache_get();
    fill_other(&c, state);
    cache_put(&c);
}

/* Worker: reads every cached field from otadata and the partitions, at boot. The only caller of
 * esp_ota_get_last_invalid_partition(), which verifies a whole image (:1272). A download in progress or
 * a verified slot keeps its in-RAM state. */
static void refresh_all(void)
{
    ota_cache_t c = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE};
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    c.running_slot = slot_of(run);
    c.boot_slot = slot_of(esp_ota_get_boot_partition());
    c.running_state = (esp_ota_get_state_partition(run, &st) == ESP_OK) ? map_state(st) : UDSOTA_IMG_UNDEFINED;
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    /* Without rollback nothing waits for a confirm: an image the otadata of a rollback build left pending
     * is as permanent as any other, and the core then answers ConfirmImage without calling confirm. */
    if (c.running_state == UDSOTA_IMG_PENDING_VERIFY) {
        c.running_state = UDSOTA_IMG_VALID;
    }
#endif
    uint8_t other = UDSOTA_OTHER_UNVERIFIED;
    if (s_handle_open) {
        other = UDSOTA_OTHER_WRITING;
    } else if (verified_get()) {
        other = UDSOTA_OTHER_VERIFIED;
    } else if (s_target != NULL) {
        (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);   /* verifies the invalid image (:1272): PSA hash */
        const esp_partition_t *inv = esp_ota_get_last_invalid_partition();
        udsota_esp32_psa_unlock();
        esp_ota_img_states_t ost;
        bool marked = esp_ota_get_state_partition(s_target, &ost) == ESP_OK &&
                      (ost == ESP_OTA_IMG_INVALID || ost == ESP_OTA_IMG_ABORTED);
        if (marked || (inv != NULL && inv->address == s_target->address)) {
            other = UDSOTA_OTHER_INVALID;
        }
    }
    fill_other(&c, other);
    c.ready = true;
    cache_put(&c);
    ESP_LOGD(TAG, "OTA state: running slot %u state %u, boot slot %u, other slot state %u (v%u.%u.%u)",
             c.running_slot, c.running_state, c.boot_slot, c.other_slot_state,
             c.other_version[0], c.other_version[1], c.other_version[2]);
}

/* Chip revision and flash mode against the running app (IDF, :1131), then the header and core rules with
 * the size rule left to BEGIN. Copies into aligned locals because first may sit at any alignment. */
static udsota_reason_t check_first_block(const uint8_t *first, size_t len)
{
    if (first == NULL || len < UDSOTA_IMAGE_MIN_LEN) {
        return UDSOTA_DL_BAD_HEADER;
    }
    esp_image_header_t hdr;
    esp_app_desc_t app;
    memcpy(&hdr, first, sizeof hdr);
    memcpy(&app, first + sizeof hdr + sizeof(esp_image_segment_header_t), sizeof app);
    esp_err_t err = esp_ota_check_image_validity(ESP_PARTITION_TYPE_APP, &hdr, &app);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "image refused by esp_ota_check_image_validity: %s", esp_err_to_name(err));
        return UDSOTA_DL_BAD_HEADER;
    }
    bool release = false;
    udsota_reason_t r = udsota_esp32_image_check(first, len, s_ctx.slot_size, (uint16_t)CONFIG_IDF_FIRMWARE_CHIP_ID,
                                                 &s_ctx, &release);
    if (r != UDSOTA_DL_OK) {
        ESP_LOGW(TAG, "image refused: reason %d", (int)r);
    } else {
        ESP_LOGD(TAG, "image accepted: %.32s (%s build)", app.version, release ? "release" : "dev");
    }
    return r;
}

/* Worker: reads the slot's first UDSOTA_IMAGE_MIN_LEN bytes back from flash and re-runs the
 * first-block checks on the bytes esp_ota_end verified (FF01 after the verify, ActivateImage before
 * set_boot). */
static udsota_reason_t recheck_slot(void)
{
    uint8_t first[UDSOTA_IMAGE_MIN_LEN];
    if (esp_partition_read(s_target, 0, first, sizeof first) != ESP_OK) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    return check_first_block(first, sizeof first);
}

/* Worker: closes an open download handle with esp_ota_abort; the partial image stays in the slot. */
static void close_handle(void)
{
    if (s_handle_open) {
        (void)esp_ota_abort(s_handle);
        s_handle_open = false;
    }
}

/* Worker: erases the slot for size bytes and opens the handle. Refused before any erase when the
 * size is out of range, or when otadata already names the slot as the boot target (an activated,
 * not yet reset image): erasing it would leave otadata booting a half-written slot. A failed
 * esp_ota_begin is always followed by esp_ota_abort, because its handle is registered before the
 * erase that can fail (:195 then :217); IDF handles start at 1 (:149), so abort(0) is a harmless
 * NOT_FOUND when begin failed before registering one. */
static int job_begin(uint32_t size)
{
    close_handle();
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    taskEXIT_CRITICAL(&s_mux);
    if (size < UDSOTA_IMAGE_MIN_LEN || size > s_target->size) {
        udsota_reason_t r = (size < UDSOTA_IMAGE_MIN_LEN) ? UDSOTA_DL_BAD_HEADER : UDSOTA_DL_TOO_BIG;
        ESP_LOGW(TAG, "download of %" PRIu32 " B refused before any erase (slot %" PRIu32 " B)", size, s_target->size);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return r;
    }
    const ota_cache_t now = cache_get();
    if (now.boot_slot == slot_of(s_target)) {
        ESP_LOGE(TAG, "download refused before any erase: %s is the boot slot until the reset", s_target->label);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return UDSOTA_DL_FLASH_ERROR;
    }
    set_other(UDSOTA_OTHER_WRITING);
    s_handle = 0;
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    s_writes = 0;
    s_mmap_writes = 0;
    /* An unlocked read, for the log only: true means a flash mmap is held, so IDF turns the cache off for
     * every erase and write command and both cores stall (spi_flash_os_func_app.c:242). */
    const bool mmap_before = flash_mmap_remain();
    int64_t t0 = esp_timer_get_time();
#endif
    esp_err_t err = esp_ota_begin(s_target, size, &s_handle);
    if (err != ESP_OK) {
        (void)esp_ota_abort(s_handle);
        ESP_LOGE(TAG, "esp_ota_begin(%s, %" PRIu32 ") failed: %s", s_target->label, size, esp_err_to_name(err));
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return UDSOTA_DL_FLASH_ERROR;
    }
    s_handle_open = true;
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    ESP_LOGI(TAG, "esp_ota_begin(%s, %" PRIu32 " B): %" PRId64 " ms, flash_mmap_remain %d before, %d after",
             s_target->label, size, (esp_timer_get_time() - t0) / 1000, (int)mmap_before, (int)flash_mmap_remain());
#endif
    return UDSOTA_DL_OK;
}

/* Worker: writes the len bytes waiting in s_buf, then frees s_buf for the next block. A write
 * failure closes the handle; a write after a failed BEGIN fails without touching flash. */
static int job_write(uint32_t len)
{
    int r = UDSOTA_DL_FLASH_ERROR;
    if (s_handle_open) {
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
        s_writes++;
        if (flash_mmap_remain() && s_mmap_writes++ == 0) {   /* unlocked read, for the log only */
            ESP_LOGW(TAG, "flash_mmap_remain() is true at block %" PRIu32 ": flash writes run with the cache off",
                     s_writes);
        }
#endif
        int64_t t0 = esp_timer_get_time();
        esp_err_t err = esp_ota_write(s_handle, s_buf, len);
        if (err == ESP_OK) {
            r = UDSOTA_DL_OK;
            ESP_LOGD(TAG, "esp_ota_write %" PRIu32 " B: %" PRId64 " us", len, esp_timer_get_time() - t0);
        } else {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            close_handle();
            set_other(UDSOTA_OTHER_UNVERIFIED);
        }
    }
    taskENTER_CRITICAL(&s_mux);
    s_buf_busy = false;
    taskEXIT_CRITICAL(&s_mux);
    return r;
}

/* Worker: FF01. esp_ota_end (SHA-256, and the signature under CONFIG_SECURE_SIGNED_ON_UPDATE), then
 * the first-block checks re-run on the verified bytes read back from flash. A pass marks the slot
 * verified until the next BEGIN, unverify or reboot. Idempotent: a repeat after a pass (the client
 * lost the answer) passes again. */
static int job_end(void)
{
    if (!s_handle_open) {
        return verified_get() ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    taskENTER_CRITICAL(&s_mux);
    const uint32_t gen = s_unverify_gen;
    taskEXIT_CRITICAL(&s_mux);
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    int64_t t0 = esp_timer_get_time();
    const size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
#endif
    (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);   /* PSA hash + signature: serialised with 0x27 */
    esp_err_t err = esp_ota_end(s_handle);
    udsota_esp32_psa_unlock();
    s_handle_open = false;                      /* esp_ota_end frees the handle on every path (:660-661) */
    udsota_reason_t r = UDSOTA_DL_OK;
    if (err != ESP_OK) {
        /* esp_ota_end reports every verify failure as ESP_ERR_OTA_VALIDATE_FAILED (:587-588), one for
         * lack of internal heap included (mbedTLS allocates internal-only here), so the heap is logged
         * with it. IDF's own "err: -141" line (PSA_ERROR_INSUFFICIENT_MEMORY) marks that case. */
        ESP_LOGE(TAG, "esp_ota_end failed: %s (internal heap free %u B, largest block %u B)", esp_err_to_name(err),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
        r = UDSOTA_DL_VERIFY_FAILED;
    } else {
        r = recheck_slot();
    }
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    ESP_LOGI(TAG, "FF01 verify: reason %d, %" PRId64 " ms, worker stack %u B unused; flash mmap held on %" PRIu32
             " of %" PRIu32 " writes; internal heap free %u B, min %u -> %u B", (int)r,
             (esp_timer_get_time() - t0) / 1000, (unsigned)uxTaskGetStackHighWaterMark(NULL), s_mmap_writes,
             s_writes, (unsigned)heap_free, (unsigned)heap_min,
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
#endif
    taskENTER_CRITICAL(&s_mux);
    s_verified = (r == UDSOTA_DL_OK) && s_unverify_gen == gen;
    const bool verified = s_verified;
    taskEXIT_CRITICAL(&s_mux);
    set_other(verified ? UDSOTA_OTHER_VERIFIED : UDSOTA_OTHER_UNVERIFIED);
    return r;
}

/* Worker: 10 01 or S3 fallback mid-download. Closes an open handle and keeps the partial slot; a
 * verified slot is left alone, so a client can still activate it in a later session. */
static int job_abort(void)
{
    if (s_handle_open) {
        close_handle();
        set_other(UDSOTA_OTHER_UNVERIFIED);
        ESP_LOGW(TAG, "download aborted; partial slot kept");
    }
    return UDSOTA_DL_OK;
}

/* Worker: ActivateImage. Re-checks the verified slot from flash, then esp_ota_set_boot_partition,
 * which re-runs the SHA-256 and signature check (:855) before it writes otadata (NEW with rollback,
 * UNDEFINED without, :129-133). The cache's boot slot is written here even if the server never takes
 * the result (a capped ActivateImage that lands late), so the status DID and the boot-slot guard see it
 * and refuse 10 02 and 0x34 until the reset. The reset itself is the server's, after the answer has left. */
static int job_activate(void)
{
    if (!verified_get()) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    int64_t t0 = esp_timer_get_time();
    const size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
#endif
    udsota_reason_t r = recheck_slot();
    if (r == UDSOTA_DL_OK) {
        (void)udsota_esp32_psa_lock(UDSOTA_ESP32_PSA_WAIT_FOREVER);   /* re-verifies the image: same PSA rule */
        esp_err_t err = esp_ota_set_boot_partition(s_target);
        udsota_esp32_psa_unlock();
        if (err != ESP_OK) {
            /* Like esp_ota_end, a verify that ran out of internal heap reads as a failed verify. */
            ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s (internal heap free %u B, largest block %u B)",
                     esp_err_to_name(err), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
            r = UDSOTA_DL_VERIFY_FAILED;
        }
    }
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    ESP_LOGI(TAG, "activate: reason %d, %" PRId64 " ms, worker stack %u B unused; internal heap free %u B, "
             "min %u -> %u B", (int)r, (esp_timer_get_time() - t0) / 1000,
             (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)heap_free, (unsigned)heap_min,
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
#endif
    if (r != UDSOTA_DL_OK) {
        taskENTER_CRITICAL(&s_mux);
        s_verified = false;
        taskEXIT_CRITICAL(&s_mux);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return r;
    }
    ota_cache_t c = cache_get();
    c.boot_slot = slot_of(s_target);
    cache_put(&c);
    return UDSOTA_DL_OK;
}

/* Worker: ConfirmImage. Marks the running image valid only when the cache shows it PENDING_VERIFY
 * and the boot slot, because esp_ota_mark_app_valid_cancel_rollback() marks the active (newest valid)
 * otadata entry, not necessarily the running one (:1179-1222). */
static int job_confirm(void)
{
    ota_cache_t c = cache_get();
    if (!c.ready || c.running_slot == UDSOTA_SLOT_NONE || c.boot_slot != c.running_slot ||
        c.running_state != UDSOTA_IMG_PENDING_VERIFY) {
        ESP_LOGW(TAG, "confirm refused: running slot %u state %u, boot slot %u",
                 c.running_slot, c.running_state, c.boot_slot);
        return UDSOTA_DL_ABORTED;
    }
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_mark_app_valid_cancel_rollback failed: %s", esp_err_to_name(err));
        return UDSOTA_DL_ABORTED;
    }
    c = cache_get();                            /* only the worker writes these fields; re-read keeps other_* current */
    c.running_state = UDSOTA_IMG_VALID;
    cache_put(&c);
    ESP_LOGD(TAG, "running image confirmed");
    return UDSOTA_DL_OK;
}

/* Worker: records a finished job. */
static void finish(job_kind_t kind, int result)
{
    taskENTER_CRITICAL(&s_mux);
    if (kind == JOB_REFRESH) {
        if (s_refreshing > 0) {
            s_refreshing--;
        }
    } else {
        if (result != UDSOTA_DL_OK && s_batch_result == UDSOTA_DL_OK) {
            s_batch_result = result;
        }
        if (s_pending > 0) {
            s_pending--;
        }
    }
    taskEXIT_CRITICAL(&s_mux);
}

/* The flash worker: runs queued jobs one at a time, forever. Not on the task watchdog: an erase
 * busy-waits for up to ~43 s, yielding only between flash commands. */
static void worker_task(void *arg)
{
    (void)arg;
    for (;;) {
        job_t j;
        if (xQueueReceive(s_q, &j, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        int r;
        switch ((job_kind_t)j.kind) {
        case JOB_REFRESH:  refresh_all(); r = UDSOTA_DL_OK; break;
        case JOB_BEGIN:    r = job_begin(j.arg); break;
        case JOB_WRITE:    r = job_write(j.arg); break;
        case JOB_END:      r = job_end(); break;
        case JOB_ABORT:    r = job_abort(); break;
        case JOB_ACTIVATE: r = job_activate(); break;
        case JOB_CONFIRM:  r = job_confirm(); break;
        default:           r = UDSOTA_DL_ABORTED; break;
        }
        finish((job_kind_t)j.kind, r);
    }
}

/* Queues one job without blocking: UDSOTA_PENDING when queued, ERR_* when refused. Ops jobs join the
 * batch that eng_poll() reports; only the server's task queues them. */
static int submit(job_kind_t kind, uint32_t arg)
{
    if (s_q == NULL || (kind != JOB_REFRESH && s_target == NULL)) {
        return ERR_NOT_STARTED;
    }
    taskENTER_CRITICAL(&s_mux);
    if (kind == JOB_REFRESH) {
        s_refreshing++;
    } else {
        if (s_pending == 0) {
            s_batch_result = UDSOTA_DL_OK;
        }
        s_pending++;
    }
    taskEXIT_CRITICAL(&s_mux);
    const job_t j = {.kind = (uint8_t)kind, .arg = arg};
    if (xQueueSend(s_q, &j, 0) != pdTRUE) {
        taskENTER_CRITICAL(&s_mux);
        if (kind == JOB_REFRESH) {
            s_refreshing--;
        } else {
            s_pending--;
        }
        taskEXIT_CRITICAL(&s_mux);
        return ERR_BUSY;
    }
    return UDSOTA_PENDING;
}

/* ---- Public API (udsota_esp32.h) and the udsota_engine_t members ---- */

/* Status flag bits the port owns: 0x01 while IDF checks update signatures, 0x02 while the app's boot-loop
 * counter made this boot ignore config. */
static uint8_t status_flags(void)
{
    uint8_t flags = 0;
#if CONFIG_SECURE_SIGNED_ON_UPDATE
    flags |= UDSOTA_STATUS_SIG_CHECKED;
#endif
    if (udsota_esp32_bootloop_reported()) {
        flags |= UDSOTA_STATUS_BOOT_IGNORED_CONFIG;
    }
    return flags;
}

/* Fills out from the RAM cache plus status_flags(); see udsota_esp32.h. */
void udsota_esp32_status(udsota_status_t *out)
{
    if (out == NULL) {
        return;
    }
    const ota_cache_t c = cache_get();
    memset(out, 0, sizeof *out);
    out->running_slot = c.running_slot;
    out->running_state = c.running_state;
    out->boot_slot = c.boot_slot;
    out->other_slot_state = c.other_slot_state;
    memcpy(out->other_version, c.other_version, sizeof out->other_version);
    memcpy(out->other_elf_sha_prefix, c.other_sha_prefix, sizeof out->other_elf_sha_prefix);
    out->flags = status_flags();
}

/* PENDING_VERIFY and the boot slot, from the cache only. */
bool udsota_esp32_image_unconfirmed(void)
{
    const ota_cache_t c = cache_get();
    return c.ready && c.running_slot != UDSOTA_SLOT_NONE && c.boot_slot == c.running_slot &&
           c.running_state == UDSOTA_IMG_PENDING_VERIFY;
}

/* True while an ops job or the boot-time refresh is queued or running. */
bool udsota_esp32_engine_busy(void)
{
    taskENTER_CRITICAL(&s_mux);
    const bool busy = s_pending != 0 || s_refreshing != 0;
    taskEXIT_CRITICAL(&s_mux);
    return busy;
}

/* engine.check_first: the first-block check on the caller's task, no flash access. UDSOTA_DL_FLASH_ERROR
 * when the worker never started or there is no inactive slot. 0 = pass, else 1 with *why set. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    (void)ctx;
    const udsota_reason_t r = (s_q == NULL || s_target == NULL) ? UDSOTA_DL_FLASH_ERROR : check_first_block(first, len);
    if (why != NULL) {
        *why = r;
    }
    return (r == UDSOTA_DL_OK) ? 0 : 1;
}

/* engine.begin: queues the erase for size bytes. */
static int eng_begin(void *ctx, uint32_t size)
{
    (void)ctx;
    return submit(JOB_BEGIN, size);
}

/* engine.write: copies the block into the worker buffer now (a 3E arriving mid-job may reuse the ISO-TP
 * receive buffer), then queues its write; refused while the previous block is unwritten. esp_ota_write is
 * sequential and the server writes in order, so off is not used. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    (void)off;
    if (d == NULL || n > BLOCK_BUF) {
        return ERR_ARG;
    }
    if (s_buf == NULL) {
        return ERR_NOT_STARTED;
    }
    taskENTER_CRITICAL(&s_mux);
    const bool busy = s_buf_busy;
    s_buf_busy = true;
    taskEXIT_CRITICAL(&s_mux);
    if (busy) {
        return ERR_BUSY;
    }
    memcpy(s_buf, d, n);
    const int r = submit(JOB_WRITE, (uint32_t)n);
    if (r != UDSOTA_PENDING) {
        taskENTER_CRITICAL(&s_mux);
        s_buf_busy = false;
        taskEXIT_CRITICAL(&s_mux);
    }
    return r;
}

/* engine.verify: queues FF01's esp_ota_end and flash re-check. */
static int eng_verify(void *ctx)
{
    (void)ctx;
    return submit(JOB_END, 0);
}

/* engine.activate: queues the flash re-check and esp_ota_set_boot_partition. */
static int eng_activate(void *ctx)
{
    (void)ctx;
    return submit(JOB_ACTIVATE, 0);
}

/* engine.confirm: queues esp_ota_mark_app_valid_cancel_rollback. Without rollback an activated image is
 * already permanent, so there is nothing to confirm: 0 at once, no job. */
static int eng_confirm(void *ctx)
{
    (void)ctx;
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    return submit(JOB_CONFIRM, 0);
#else
    return UDSOTA_DL_OK;
#endif
}

/* engine.abort: queues the close of an open download; never blocks (a full queue drops it). */
static void eng_abort(void *ctx)
{
    (void)ctx;
    (void)submit(JOB_ABORT, 0);
}

/* engine.unverify: clears s_verified and demotes a VERIFIED other slot in the cache to UNVERIFIED (its
 * descriptor fields stay: the image is still there), in one critical section. */
static void eng_unverify(void *ctx)
{
    (void)ctx;
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    s_unverify_gen++;
    if (s_cache.other_slot_state == UDSOTA_OTHER_VERIFIED) {
        s_cache.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
    }
    taskEXIT_CRITICAL(&s_mux);
}

/* engine.poll: UDSOTA_PENDING while an ops job is unfinished, else the batch result (0 or the first failure). */
static int eng_poll(void *ctx)
{
    (void)ctx;
    taskENTER_CRITICAL(&s_mux);
    const bool done = (s_pending == 0);
    const int r = s_batch_result;
    taskEXIT_CRITICAL(&s_mux);
    return done ? r : UDSOTA_PENDING;
}

/* engine.status: the cached status DID. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    (void)ctx;
    udsota_esp32_status(out);
}

/* engine.running_sha: the running image's app_elf_sha256 (0xF1F3); 0 when max is short. */
static size_t eng_running_sha(void *ctx, uint8_t *out, size_t max)
{
    (void)ctx;
    const esp_app_desc_t *app = esp_app_get_description();
    if (out == NULL || max < sizeof app->app_elf_sha256) {
        return 0;
    }
    memcpy(out, app->app_elf_sha256, sizeof app->app_elf_sha256);
    return sizeof app->app_elf_sha256;
}

/* engine.version: the running esp_app_desc version string (F189), unterminated; 0 when max is short. */
static size_t eng_version(void *ctx, char *out, size_t max)
{
    (void)ctx;
    const esp_app_desc_t *app = esp_app_get_description();
    const size_t n = strnlen(app->version, sizeof app->version);
    if (out == NULL || n > max) {
        return 0;
    }
    memcpy(out, app->version, n);
    return n;
}

static udsota_engine_t s_engine = {
    .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_verify,
    .activate = eng_activate, .confirm = eng_confirm, .abort = eng_abort, .unverify = eng_unverify,
    .poll = eng_poll, .status = eng_status, .running_sha = eng_running_sha, .version = eng_version,
    .slot_size = 0u,                    /* set by udsota_esp32_engine_start(); 0 = UDSOTA_SLOT_SIZE_DEFAULT */
    .ctx = NULL,
};

/* The engine; see udsota_esp32.h. */
const udsota_engine_t *udsota_esp32_engine(void)
{
    return &s_engine;
}

/* Creates the worker, its buffer and queue in internal RAM, fills the image rules from cfg and the running
 * image, and queues the boot-time cache read; see udsota_esp32_priv.h. */
void udsota_esp32_engine_start(const udsota_config_t *cfg)
{
    if (s_q != NULL || cfg == NULL) {
        return;
    }
    udsota_esp32_psa_lock_init();
    const esp_partition_t *run = esp_ota_get_running_partition();
    s_target = esp_ota_get_next_update_partition(NULL);
    if (s_target == NULL || s_target == run) {
        ESP_LOGE(TAG, "no inactive OTA slot: every download will be refused");
        s_target = NULL;
    }
    s_ctx = (udsota_image_ctx_t){
        .hw_id = cfg->hw_id,
        .partition_layout_id = cfg->layout_id,
        .diag_request_id = cfg->req_id,
        .diag_response_id = cfg->resp_id,
        .running_version = {0, 0, 0},
        .running_is_release = false,
        .slot_size = (s_target != NULL) ? s_target->size : 0u,
        .product = cfg->product,
    };
    s_engine.slot_size = s_ctx.slot_size;
    /* An unparseable running version stays {0,0,0} and counts as a dev build: fail-open, and on dev units
     * only, since the build sets the release flag only on a clean tag. */
    const esp_app_desc_t *app = esp_app_get_description();
    if (udsota_parse_version(app->version, sizeof app->version, s_ctx.running_version, NULL)) {
        s_ctx.running_is_release = (udsota_image_desc.flags & UDSOTA_IMG_FLAG_RELEASE) != 0u;
    }

    s_buf = heap_caps_malloc(BLOCK_BUF, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    QueueHandle_t q = xQueueCreate(QUEUE_LEN, sizeof(job_t));
    if (s_buf == NULL || q == NULL) {
        ESP_LOGE(TAG, "no internal RAM for the flash worker: downloads refused");
        heap_caps_free(s_buf);
        s_buf = NULL;
        if (q != NULL) {
            vQueueDelete(q);
        }
        return;
    }
    s_q = q;                                    /* before the task: worker_task reads it */
    if (xTaskCreatePinnedToCoreWithCaps(worker_task, "udsota_worker", WORKER_STACK, NULL, WORKER_PRIO, NULL,
                                        WORKER_CORE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) != pdPASS) {
        ESP_LOGE(TAG, "flash worker task not created: downloads refused");
        s_q = NULL;
        vQueueDelete(q);
        heap_caps_free(s_buf);
        s_buf = NULL;
        return;
    }
    (void)submit(JOB_REFRESH, 0);
    ESP_LOGD(TAG, "flash worker up: target %s (%" PRIu32 " B), running v%u.%u.%u (%s), hw_id %u",
             (s_target != NULL) ? s_target->label : "none", s_ctx.slot_size, s_ctx.running_version[0],
             s_ctx.running_version[1], s_ctx.running_version[2], s_ctx.running_is_release ? "release" : "dev",
             s_ctx.hw_id);
}
