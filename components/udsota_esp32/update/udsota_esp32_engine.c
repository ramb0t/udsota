/* udsota ESP32 engine (udsota_esp32.h): udsota_engine_t on esp_ota_*. Every flash-touching esp_ota_* call
 * runs on one worker task; the server's task queues jobs through s_q and polls s_pending. Only the worker
 * writes s_cache (eng_unverify only demotes VERIFIED), and every other task reads it under s_mux, so status
 * readers never wait behind an erase. With CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE an activated image boots
 * PENDING_VERIFY and needs confirm; without it the image is permanent and confirm does nothing. With
 * CONFIG_UDSOTA_ESP32_COMPRESSION the engine also serves coded downloads: compressed ones (DFI 0x10), and with
 * CONFIG_UDSOTA_ESP32_DELTA delta ones (0x20, 0x30) rebuilt from the running partition. The diag task only copies
 * each coded block into the worker's buffer, and the worker decodes it (udsota_coded over tinfl and detools), runs
 * the first-block check once the image's first 320 bytes are out, erases and writes. It never writes the running
 * partition. IDF v6.1 line numbers below are components/app_update/esp_ota_ops.c unless another file is named. */
#include "udsota_esp32.h"

#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_image_format.h"
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
#include "esp_private/flash_mmap.h"   /* MMAP_EXECUTABLES_FROM_FLASH, flash_mmap_remain(): logged only */
#endif

#include "udsota_esp32_ctl.h"
#include "udsota_esp32_image.h"
#include "udsota_esp32_priv.h"
#if CONFIG_UDSOTA_ESP32_COMPRESSION
#include "esp_memory_utils.h"   /* esp_ptr_external_ram(), logged only */
#include "udsota_coded.h"
#include "udsota_tinfl.h"
#endif
#if CONFIG_UDSOTA_ESP32_DELTA
#include "udsota_detools.h"
#endif

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
_Static_assert(sizeof(((esp_app_desc_t *)0)->version) == UDSOTA_ESP32_VERSION_MAX, "the incoming version's size");
_Static_assert(sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + offsetof(esp_app_desc_t, version) ==
               UDSOTA_ESP32_CTL_VERSION_OFF, "where the control block reads the incoming version");
_Static_assert(ESP_IMAGE_HEADER_MAGIC == 0xE9 && ESP_IMAGE_MAX_SEGMENTS == 16 &&
               ESP_IMAGE_SPI_MODE_SLOW_READ == 5 && ESP_APP_DESC_MAGIC_WORD == 0xABCD5432u,
               "the constants udsota_esp32_image.c copies");
_Static_assert(UDSOTA_ESP32_CHIP_ID_S3 == ESP_CHIP_ID_ESP32S3, "the host tests' chip ID");

#define WORKER_STACK    CONFIG_UDSOTA_ESP32_WORKER_STACK   /* bytes, internal: RSA-3072 verify inside esp_ota_end */
#define WORKER_PRIO     CONFIG_UDSOTA_ESP32_WORKER_PRIO    /* below the app's own tasks, so they run during an erase */
#define WORKER_CORE     CONFIG_UDSOTA_ESP32_WORKER_CORE
#define QUEUE_LEN       4       /* BEGIN + WRITE of the first block, plus slack */
#define BLOCK_BUF       4096u   /* the worker's internal-RAM block buffer: one whole 0x36 payload */
#define PATCH_BUF       1024u   /* DFI 0x30: inflated patch bytes on their way to detools */
#define ERR_NOT_STARTED (-1)    /* engine not started, its allocation failed, or no inactive slot */
#define ERR_BUSY        (-2)    /* job queue full, or the block buffer still holds an unwritten block */
#define ERR_ARG         (-3)    /* NULL data, or a block longer than BLOCK_BUF */

_Static_assert(BLOCK_BUF >= UDSOTA_DL_MAX_DATA, "a whole 0x36 payload fits the worker buffer");
_Static_assert(sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t) ==
               UDSOTA_IMG_DESC_OFFSET, "udsota_image_desc_t sits right after esp_app_desc_t");

typedef enum {
    JOB_BEGIN, JOB_WRITE, JOB_END, JOB_ABORT, JOB_ACTIVATE, JOB_CONFIRM, JOB_ZWRITE, JOB_ZEND
} job_kind_t;

typedef struct {
    uint8_t  kind;              /* job_kind_t */
    uint32_t arg;               /* BEGIN: announced image size; WRITE, ZWRITE: bytes in s_buf; ABORT: the coded
                                   download generation it may free */
} job_t;

typedef struct {
    bool            ready;      /* the boot read has finished */
    udsota_status_t st;         /* flags stays 0: udsota_esp32_status() fills it */
} ota_cache_t;

/* Shared: read and written under s_mux. */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ota_cache_t s_cache = {.st = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE}};
static uint32_t s_pending;          /* ops jobs queued and not finished */
static int s_batch_result;          /* first failure since s_pending was last 0 */
static bool s_buf_busy;             /* s_buf holds a block the worker has not written yet */
static bool s_verified;             /* FF01 passed on s_target since the last BEGIN, eng_unverify or boot */
static uint32_t s_unverify_gen;     /* bumped by every eng_unverify: a verify that spans one never marks the slot */

/* Set once by engine_start() before the worker runs; read-only afterwards. */
static QueueHandle_t s_q;
static uint8_t *s_buf;                      /* BLOCK_BUF bytes, internal RAM */
static const esp_partition_t *s_target;     /* the inactive slot; NULL refuses every download */
static const esp_partition_t *s_running;    /* the running slot: a delta download's base, only ever read */
static udsota_image_ctx_t s_ctx;

/* Worker only. */
static esp_ota_handle_t s_handle;
static bool s_handle_open;
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
static uint32_t s_writes;           /* blocks written since the last BEGIN */
static uint32_t s_cache_off_writes; /* of those, blocks written with the cache off */

/* For the log only: whether IDF turns the cache off, stalling the CPUs, for an erase or write issued now. On the
 * ESP32 it always does (spi1_start(), spi_flash_os_func_app.c:122-151). On the other targets spi1_start()
 * (:204-257) keeps it on under CONFIG_SPI_FLASH_AUTO_SUSPEND, turns it off for every erase and write unless code
 * and read-only data are both in PSRAM or it is a RAM app (MMAP_EXECUTABLES_FROM_FLASH), and otherwise only while a
 * flash mmap is held. flash_mmap_remain() exists on those targets only; the read is unlocked. */
#ifndef MMAP_EXECUTABLES_FROM_FLASH
#error "esp_private/flash_mmap.h no longer defines MMAP_EXECUTABLES_FROM_FLASH: recheck cache_off_for_writes()"
#endif
static bool cache_off_for_writes(void)
{
#if CONFIG_SPI_FLASH_AUTO_SUSPEND
    return false;
#elif MMAP_EXECUTABLES_FROM_FLASH || CONFIG_IDF_TARGET_ESP32
    return true;
#else
    return flash_mmap_remain();
#endif
}
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
    if (s_cache.st.other_slot_state == UDSOTA_OTHER_VERIFIED && !s_verified) {
        s_cache.st.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
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
    memset(c->st.other_version, 0, sizeof c->st.other_version);
    memset(c->st.other_elf_sha_prefix, 0, sizeof c->st.other_elf_sha_prefix);
    c->st.other_slot_state = state;
    if (state == UDSOTA_OTHER_WRITING) {
        return;
    }
    if (s_target == NULL || esp_ota_get_partition_description(s_target, &d) != ESP_OK) {
        c->st.other_slot_state = UDSOTA_OTHER_EMPTY;
        return;
    }
    (void)udsota_parse_version(d.version, sizeof d.version, c->st.other_version, NULL);
    memcpy(c->st.other_elf_sha_prefix, d.app_elf_sha256, sizeof c->st.other_elf_sha_prefix);
}

/* Worker: sets the other slot's state in the cache and re-reads its descriptor. */
static void set_other(uint8_t state)
{
    ota_cache_t c = cache_get();
    fill_other(&c, state);
    cache_put(&c);
}

/* Worker: reads every cached field from otadata and the partitions, once at boot before any job, so no download
 * is open and no slot verified yet. The only caller of esp_ota_get_last_invalid_partition(), which verifies a whole
 * image (:1272). */
static void refresh_all(void)
{
    ota_cache_t c = {.st = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE}};
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    c.st.running_slot = slot_of(run);
    c.st.boot_slot = slot_of(esp_ota_get_boot_partition());
    c.st.running_state = (esp_ota_get_state_partition(run, &st) == ESP_OK) ? map_state(st) : UDSOTA_IMG_UNDEFINED;
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    /* Without rollback nothing waits for a confirm: an image the otadata of a rollback build left pending
     * is as permanent as any other, and the core then answers ConfirmImage without calling confirm. */
    if (c.st.running_state == UDSOTA_IMG_PENDING_VERIFY) {
        c.st.running_state = UDSOTA_IMG_VALID;
    }
#endif
    uint8_t other = UDSOTA_OTHER_UNVERIFIED;
    if (s_target != NULL) {
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
             c.st.running_slot, c.st.running_state, c.st.boot_slot, c.st.other_slot_state,
             c.st.other_version[0], c.st.other_version[1], c.st.other_version[2]);
}

/* Chip revision and flash mode against the running app (IDF, :1131), then the header and core rules with
 * the size rule left to BEGIN. Copies into aligned locals because first may sit at any alignment. With store,
 * an accepted image's version becomes the incoming version; a refused one leaves it as the 34 cleared it. */
static udsota_reason_t check_first_block(const uint8_t *first, size_t len, bool store)
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
    if (store) {
        udsota_esp32_first_block_checked(r, first, len);   /* keeps the version only when r is UDSOTA_DL_OK */
    }
    return r;
}

/* Worker: reads the slot's first UDSOTA_IMAGE_MIN_LEN bytes back from flash and re-runs the
 * first-block checks on the bytes esp_ota_end verified (FF01 after the verify, ActivateImage before
 * set_boot). The first block already stored the version, so this leaves it alone. */
static udsota_reason_t recheck_slot(void)
{
    uint8_t first[UDSOTA_IMAGE_MIN_LEN];
    if (esp_partition_read(s_target, 0, first, sizeof first) != ESP_OK) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    return check_first_block(first, sizeof first, false);
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
    if (now.st.boot_slot == slot_of(s_target)) {
        ESP_LOGE(TAG, "download refused before any erase: %s is the boot slot until the reset", s_target->label);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return UDSOTA_DL_FLASH_ERROR;
    }
    set_other(UDSOTA_OTHER_WRITING);
    s_handle = 0;
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    s_writes = 0;
    s_cache_off_writes = 0;
    const bool cache_off_before = cache_off_for_writes();
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
    ESP_LOGI(TAG, "esp_ota_begin(%s, %" PRIu32 " B): %" PRId64 " ms, cache off for writes %d before, %d after",
             s_target->label, size, (esp_timer_get_time() - t0) / 1000, (int)cache_off_before,
             (int)cache_off_for_writes());
#endif
    return UDSOTA_DL_OK;
}

/* Worker: writes len bytes of d through the open handle. A write failure closes the handle; a write after a
 * failed BEGIN fails without touching flash. */
static int ota_write(const uint8_t *d, size_t len)
{
    int r = UDSOTA_DL_FLASH_ERROR;
    if (s_handle_open) {
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
        s_writes++;
        if (cache_off_for_writes() && s_cache_off_writes++ == 0) {
            ESP_LOGW(TAG, "flash writes run with the cache off, first at block %" PRIu32, s_writes);
        }
#endif
        int64_t t0 = esp_timer_get_time();
        esp_err_t err = esp_ota_write(s_handle, d, len);
        if (err == ESP_OK) {
            r = UDSOTA_DL_OK;
            ESP_LOGD(TAG, "esp_ota_write %u B: %" PRId64 " us", (unsigned)len, esp_timer_get_time() - t0);
        } else {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            close_handle();
            set_other(UDSOTA_OTHER_UNVERIFIED);
        }
    }
    return r;
}

/* Worker: frees s_buf for the next block. */
static void buf_release(void)
{
    taskENTER_CRITICAL(&s_mux);
    s_buf_busy = false;
    taskEXIT_CRITICAL(&s_mux);
}

/* Worker: writes the len bytes waiting in s_buf, then frees s_buf for the next block. */
static int job_write(uint32_t len)
{
    const int r = ota_write(s_buf, len);
    buf_release();
    return r;
}

#if CONFIG_UDSOTA_ESP32_COMPRESSION
/* The coded download. The diag task opens it at zbegin and closes it at zend, and the worker feeds it in between
 * and frees it at an abort. At zend the worker is idle (the server waits on every job). At zbegin it may still run
 * the abort of a finished image the same 34 released, whose download zend already freed; s_z_gen keeps that abort,
 * or any older one, off the new download. s_z_live and s_z_gen are read and written under s_mux. */
static udsota_coded_t   s_cd;
static udsota_tinfl_t   s_tinfl;
static uint8_t         *s_zout;         /* BLOCK_BUF bytes, internal RAM: image bytes on their way to flash */
static bool             s_z_live;       /* s_cd is open and its memory held */
static uint32_t         s_z_gen;        /* bumped by every zbegin, so an abort queued before it frees nothing new */
#if CONFIG_UDSOTA_ESP32_DELTA
static udsota_detools_t s_detools;
static uint8_t         *s_pbuf;         /* PATCH_BUF bytes, internal RAM: DFI 0x30's inflated patch bytes */
static uint8_t          s_base_hash[UDSOTA_PATCH_HASH_LEN];   /* worker only: the running image's appended SHA-256 */
static bool             s_base_hash_ok; /* worker only: s_base_hash is computed; the running image never changes */
#endif

/* The inflater's state and dictionary: PSRAM first with UDSOTA_ESP32_INFLATE_PSRAM, else internal RAM. The
 * decoders free through free(), which on IDF is heap_caps_free (esp_libc/src/heap.c), so no free hook. */
static void *z_alloc(void *ctx, size_t n)
{
    (void)ctx;
#if CONFIG_UDSOTA_ESP32_INFLATE_PSRAM
    return heap_caps_malloc_prefer(n, 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
#else
    return heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
#endif
}

/* Closes the download and frees its decoders and buffers; the caller has cleared s_z_live. */
static void z_release(void)
{
    udsota_coded_close(&s_cd);
    heap_caps_free(s_zout);
    s_zout = NULL;
#if CONFIG_UDSOTA_ESP32_DELTA
    heap_caps_free(s_pbuf);
    s_pbuf = NULL;
#endif
}

/* Worker, the image's sink: the first-block check on the first image bytes, before any erase; a pass stores the
 * version. */
static int z_check(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    (void)ctx;
    *why = check_first_block(first, len, true);
    return (*why == UDSOTA_DL_OK) ? 0 : 1;
}

/* Worker, the image's sink: the erase, as JOB_BEGIN. */
static int z_begin(void *ctx, uint32_t size)
{
    (void)ctx;
    return (job_begin(size) == UDSOTA_DL_OK) ? 0 : 1;
}

/* Worker, the image's sink: one buffer of image bytes; esp_ota_write is sequential, so off is not used. */
static int z_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    (void)off;
    return (ota_write(d, n) == UDSOTA_DL_OK) ? 0 : 1;
}

#if CONFIG_UDSOTA_ESP32_DELTA
/* The patch decoder's state: internal RAM, as it is small. */
static void *internal_alloc(void *ctx, size_t n)
{
    (void)ctx;
    return heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/* Worker, the delta base: n bytes of the running partition at off, through esp_partition_read (which decrypts under
 * flash encryption). detools seeks with no check, so a read that leaves the partition is refused here. */
static int base_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    (void)ctx;
    if (s_running == NULL || (uint64_t)off + n > s_running->size) {
        ESP_LOGW(TAG, "delta patch read %u B at %" PRIu32 ", outside the running partition", (unsigned)n, off);
        return -1;
    }
    return esp_partition_read(s_running, off, buf, n) == ESP_OK ? 0 : -1;
}

/* Worker, the delta base's identity: the SHA-256 the running image appends, as esp_image_get_metadata reads it, not
 * recomputed (esp_partition_get_sha256 would hash the whole image). The bootloader usually checked it at boot, but
 * need not have (CONFIG_BOOTLOADER_SKIP_VALIDATE_ON_POWER_ON without secure boot): FF01 is the backstop, since a base
 * that differs from its stored hash only rebuilds an image FF01 refuses. The first delta download reads it and later
 * ones reuse it: the running image never changes. */
static int base_hash(void *ctx, uint8_t out[UDSOTA_PATCH_HASH_LEN])
{
    (void)ctx;
    if (!s_base_hash_ok && s_running != NULL) {
        const esp_partition_pos_t pos = {.offset = s_running->address, .size = s_running->size};
        esp_image_metadata_t md;
        const esp_err_t err = esp_image_get_metadata(&pos, &md);
        s_base_hash_ok = (err == ESP_OK && md.image.hash_appended == 1u);
        if (s_base_hash_ok) {
            memcpy(s_base_hash, md.image_digest, sizeof s_base_hash);
        } else {
            ESP_LOGE(TAG, "running image %s has no appended SHA-256 to match a patch against: %s", s_running->label,
                     esp_err_to_name(err));
        }
    }
    if (!s_base_hash_ok) {
        return -1;
    }
    memcpy(out, s_base_hash, UDSOTA_PATCH_HASH_LEN);
    return 0;
}
#endif

/* Worker: the coded download's 37 check, then its memory freed. A delta patch's decoder may still hold the image's
 * last bytes, whose base reads and writes are flash work, so this runs here and not on the diag task. eng_zend has
 * already cleared s_z_live, so no abort frees the download meanwhile. */
static int job_zend(void)
{
    const int r = (int)udsota_coded_end(&s_cd);
    z_release();
    return r;
}

/* Worker: decodes the len coded bytes waiting in s_buf into the check, the erase and the writes, then frees s_buf.
 * Returns the download's reason. */
static int job_zwrite(uint32_t len)
{
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    const int64_t t0 = esp_timer_get_time();
    const uint32_t before = udsota_coded_written(&s_cd);
#endif
    const int r = udsota_coded_feed(&s_cd, s_buf, len);
    buf_release();
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    ESP_LOGI(TAG, "zwrite %" PRIu32 " B -> %" PRIu32 " image B: %" PRId64 " us, reason %d, worker stack %u B unused",
             len, udsota_coded_written(&s_cd) - before, esp_timer_get_time() - t0, r,
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
#endif
    return r;
}
#endif

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
    ESP_LOGI(TAG, "FF01 verify: reason %d, %" PRId64 " ms, worker stack %u B unused; cache off on %" PRIu32
             " of %" PRIu32 " writes; internal heap free %u B, min %u -> %u B", (int)r,
             (esp_timer_get_time() - t0) / 1000, (unsigned)uxTaskGetStackHighWaterMark(NULL), s_cache_off_writes,
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
 * verified slot is left alone, so a client can still activate it in a later session. Frees the coded download
 * of generation gen, if it is still open. */
static int job_abort(uint32_t gen)
{
#if CONFIG_UDSOTA_ESP32_COMPRESSION
    taskENTER_CRITICAL(&s_mux);
    const bool mine = s_z_live && s_z_gen == gen;
    if (mine) {
        s_z_live = false;
    }
    taskEXIT_CRITICAL(&s_mux);
    if (mine) {
        z_release();
    }
#else
    (void)gen;
#endif
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
    c.st.boot_slot = slot_of(s_target);
    cache_put(&c);
    return UDSOTA_DL_OK;
}

/* The running image is PENDING_VERIFY and the boot slot: when job_confirm acts, and what
 * udsota_esp32_image_unconfirmed() reports, so the two can't drift apart. */
static bool pending_confirm(const ota_cache_t *c)
{
    return c->ready && c->st.running_slot != UDSOTA_SLOT_NONE && c->st.boot_slot == c->st.running_slot &&
           c->st.running_state == UDSOTA_IMG_PENDING_VERIFY;
}

/* Worker: ConfirmImage. Marks the running image valid only when pending_confirm(), because
 * esp_ota_mark_app_valid_cancel_rollback() marks the active (newest valid) otadata entry, not
 * necessarily the running one (:1179-1222). */
static int job_confirm(void)
{
    ota_cache_t c = cache_get();
    if (!pending_confirm(&c)) {
        ESP_LOGW(TAG, "confirm refused: running slot %u state %u, boot slot %u",
                 c.st.running_slot, c.st.running_state, c.st.boot_slot);
        return UDSOTA_DL_ABORTED;
    }
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_mark_app_valid_cancel_rollback failed: %s", esp_err_to_name(err));
        return UDSOTA_DL_ABORTED;
    }
    c = cache_get();                            /* only the worker writes these fields; re-read keeps other_* current */
    c.st.running_state = UDSOTA_IMG_VALID;
    cache_put(&c);
    ESP_LOGD(TAG, "running image confirmed");
    return UDSOTA_DL_OK;
}

/* Worker: records a finished job. */
static void finish(int result)
{
    taskENTER_CRITICAL(&s_mux);
    if (result != UDSOTA_DL_OK && s_batch_result == UDSOTA_DL_OK) {
        s_batch_result = result;
    }
    if (s_pending > 0) {
        s_pending--;
    }
    taskEXIT_CRITICAL(&s_mux);
}

/* Set once by engine_set_wake() before the worker exists: called after every finished job. */
static void (*s_wake)(void);

/* Installs the function the flash worker calls after each finished job, from the worker's task, so the diag task
 * answers at once instead of at its next poll. Called before engine_start(); NULL = none. */
static void engine_set_wake(void (*wake)(void))
{
    s_wake = wake;
}

/* The flash worker: reads the OTA state, then runs queued jobs one at a time, forever. Not on the task
 * watchdog: an erase busy-waits for up to ~43 s, yielding only between flash commands. */
static void worker_task(void *arg)
{
    (void)arg;
    refresh_all();                              /* before any job: jobs queued meanwhile wait for it */
    for (;;) {
        job_t j;
        if (xQueueReceive(s_q, &j, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        int r;
        switch ((job_kind_t)j.kind) {
        case JOB_BEGIN:    r = job_begin(j.arg); break;
        case JOB_WRITE:    r = job_write(j.arg); break;
        case JOB_END:      r = job_end(); break;
        case JOB_ABORT:    r = job_abort(j.arg); break;
#if CONFIG_UDSOTA_ESP32_COMPRESSION
        case JOB_ZWRITE:   r = job_zwrite(j.arg); break;
        case JOB_ZEND:     r = job_zend(); break;
#endif
        case JOB_ACTIVATE: r = job_activate(); break;
        case JOB_CONFIRM:  r = job_confirm(); break;
        default:           r = UDSOTA_DL_ABORTED; break;
        }
        finish(r);
        if (s_wake != NULL) {
            s_wake();
        }
    }
}

/* Queues one job without blocking: UDSOTA_PENDING when queued, ERR_* when refused. Every job joins the
 * batch that eng_poll() reports; only the server's task queues them. */
static int submit(job_kind_t kind, uint32_t arg)
{
    if (s_q == NULL || s_target == NULL) {
        return ERR_NOT_STARTED;
    }
    taskENTER_CRITICAL(&s_mux);
    if (s_pending++ == 0) {
        s_batch_result = UDSOTA_DL_OK;
    }
    taskEXIT_CRITICAL(&s_mux);
    const job_t j = {.kind = (uint8_t)kind, .arg = arg};
    if (xQueueSend(s_q, &j, 0) != pdTRUE) {
        taskENTER_CRITICAL(&s_mux);
        s_pending--;
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
    *out = cache_get().st;
    out->flags = status_flags();
}

/* pending_confirm() on the cache. */
bool udsota_esp32_image_unconfirmed(void)
{
    const ota_cache_t c = cache_get();
    return pending_confirm(&c);
}

/* True while an ops job is queued or running, or the started worker's boot read has not finished. */
bool udsota_esp32_engine_busy(void)
{
    taskENTER_CRITICAL(&s_mux);
    const bool busy = s_pending != 0 || (s_q != NULL && !s_cache.ready);
    taskEXIT_CRITICAL(&s_mux);
    return busy;
}

/* engine.check_first: the first-block check on the caller's task, no flash access; a pass stores the version.
 * UDSOTA_DL_FLASH_ERROR when the worker never started or there is no inactive slot. 0 = pass, else 1 with *why
 * set. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    (void)ctx;
    const udsota_reason_t r = (s_q == NULL || s_target == NULL) ? UDSOTA_DL_FLASH_ERROR
                              : check_first_block(first, len, true);
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

/* Copies a block into the worker buffer now (a 3E arriving mid-job may reuse the ISO-TP receive buffer), then
 * queues kind (JOB_WRITE or JOB_ZWRITE) on it; refused while the previous block is unwritten. */
static int queue_block(job_kind_t kind, const uint8_t *d, size_t n)
{
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
    const int r = submit(kind, (uint32_t)n);
    if (r != UDSOTA_PENDING) {
        taskENTER_CRITICAL(&s_mux);
        s_buf_busy = false;
        taskEXIT_CRITICAL(&s_mux);
    }
    return r;
}

/* engine.write: queue_block's JOB_WRITE. esp_ota_write is sequential and the server writes in order, so off is not
 * used. */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    (void)off;
    return queue_block(JOB_WRITE, d, n);
}

#if CONFIG_UDSOTA_ESP32_COMPRESSION
/* engine.zbegin, on the diag task: allocates s_zout (internal), the inflater (z_alloc) for 0x10 and 0x30, the patch
 * decoder (internal) for 0x20 and 0x30 and s_pbuf (internal) for 0x30, and opens the download, then publishes it
 * under a new generation. UDSOTA_DL_FLASH_ERROR without a worker or an inactive slot, UDSOTA_DL_NO_MEMORY when an
 * allocation fails. */
static int eng_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    (void)ctx;
    if (s_q == NULL || s_target == NULL) {
        udsota_esp32_zbegin_refused();
        return UDSOTA_DL_FLASH_ERROR;
    }
    taskENTER_CRITICAL(&s_mux);
    const bool stale = s_z_live;               /* an abort the full queue dropped */
    s_z_live = false;
    taskEXIT_CRITICAL(&s_mux);
    if (stale) {
        z_release();
    }
    s_zout = heap_caps_malloc(BLOCK_BUF, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    s_tinfl = (udsota_tinfl_t){.alloc = z_alloc};
    const udsota_inflate_t inf = udsota_tinfl_inflate(&s_tinfl);
    udsota_coded_cfg_t cfg = {
        .sink = {.check_first = z_check, .begin = z_begin, .write = z_write},
        .out = s_zout, .out_max = BLOCK_BUF, .inflate = &inf,
    };
    bool bufs = (s_zout != NULL);
#if CONFIG_UDSOTA_ESP32_DELTA
    s_detools = (udsota_detools_t){.alloc = internal_alloc};
    const udsota_patch_t patch = udsota_detools_patch(&s_detools);
    static const udsota_pbase_t base = {.read = base_read, .hash = base_hash};
    cfg.patch = &patch;
    cfg.base = &base;
    if (dfi == UDSOTA_DL_DFI_DELTA_DEFLATE) {
        s_pbuf = heap_caps_malloc(PATCH_BUF, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        cfg.zbuf = s_pbuf;
        cfg.zbuf_max = PATCH_BUF;
        bufs = bufs && s_pbuf != NULL;
    }
#endif
    const udsota_reason_t r = bufs ? udsota_coded_open(&s_cd, dfi, size, &cfg) : UDSOTA_DL_NO_MEMORY;
    if (r != UDSOTA_DL_OK) {
        ESP_LOGW(TAG, "no memory for DFI 0x%02X's decoder: 34 refused; internal heap largest block %u B", dfi,
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
        z_release();
        udsota_esp32_zbegin_refused();
        return UDSOTA_DL_NO_MEMORY;
    }
    taskENTER_CRITICAL(&s_mux);
    s_z_gen++;
    s_z_live = true;
    taskEXIT_CRITICAL(&s_mux);
#if CONFIG_UDSOTA_ESP32_DEBUG_MEASURE
    const bool inflates = dfi == UDSOTA_DL_DFI_DEFLATE || dfi == UDSOTA_DL_DFI_DELTA_DEFLATE;   /* 0x30's outer layer */
    ESP_LOGI(TAG, "DFI 0x%02X download open for %" PRIu32 " B: inflater %u B state + %u B dictionary (%s), %u B image "
             "buffer; internal heap free %u B", dfi, size, (unsigned)(inflates ? udsota_tinfl_state_len() : 0u),
             (unsigned)(inflates ? UDSOTA_TINFL_DICT_LEN : 0u),
             (inflates && esp_ptr_external_ram(s_tinfl.dict)) ? "PSRAM" : "internal", (unsigned)BLOCK_BUF,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
#if CONFIG_UDSOTA_ESP32_DELTA
    if (dfi != UDSOTA_DL_DFI_DEFLATE) {
        ESP_LOGI(TAG, "patch decoder %u B, patch buffer %u B", (unsigned)udsota_detools_state_len(),
                 (unsigned)(s_pbuf != NULL ? PATCH_BUF : 0u));
    }
#endif
#endif
    return UDSOTA_DL_OK;
}

/* engine.zwrite: queue_block's JOB_ZWRITE; the worker decodes. */
static int eng_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    (void)ctx;
    return queue_block(JOB_ZWRITE, d, n);
}

/* engine.zwritten, on the diag task once the worker has finished the block's job (engine.poll's lock orders the
 * two): the image bytes the download has written. */
static uint32_t eng_zwritten(void *ctx)
{
    (void)ctx;
    return udsota_coded_written(&s_cd);
}

/* engine.zend, on the diag task with the worker idle: queues JOB_ZEND, the download's 37 check and its free, on the
 * worker. A queue that refuses it frees the download here, which touches no flash, and fails the 37. */
static int eng_zend(void *ctx)
{
    (void)ctx;
    taskENTER_CRITICAL(&s_mux);
    const bool live = s_z_live;
    s_z_live = false;
    taskEXIT_CRITICAL(&s_mux);
    if (!live) {
        z_release();
        return UDSOTA_DL_BAD_STREAM;
    }
    const int r = submit(JOB_ZEND, 0);
    if (r != UDSOTA_PENDING) {
        z_release();
        return UDSOTA_DL_FLASH_ERROR;
    }
    return r;
}
#endif

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

/* engine.abort: queues the close of an open download, and the free of the coded download open now; never
 * blocks (a full queue drops it, and the next zbegin frees the download). */
static void eng_abort(void *ctx)
{
    (void)ctx;
    uint32_t gen = 0;
#if CONFIG_UDSOTA_ESP32_COMPRESSION
    taskENTER_CRITICAL(&s_mux);
    gen = s_z_gen;
    taskEXIT_CRITICAL(&s_mux);
#endif
    (void)submit(JOB_ABORT, gen);
}

/* engine.unverify: clears s_verified and demotes a VERIFIED other slot in the cache to UNVERIFIED (its
 * descriptor fields stay: the image is still there), in one critical section. */
static void eng_unverify(void *ctx)
{
    (void)ctx;
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    s_unverify_gen++;
    if (s_cache.st.other_slot_state == UDSOTA_OTHER_VERIFIED) {
        s_cache.st.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
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
    .slot_size = 0u,                    /* set by engine_start(); 0 = UDSOTA_SLOT_SIZE_DEFAULT */
    .ctx = NULL,
#if CONFIG_UDSOTA_ESP32_COMPRESSION
    .zbegin = eng_zbegin, .zwrite = eng_zwrite, .zend = eng_zend, .zwritten = eng_zwritten,
#if CONFIG_UDSOTA_ESP32_DELTA
    .zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE) | UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA) |
                UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA_DEFLATE),
#else
    .zformats = UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE),
#endif
#endif
};

/* The engine; see udsota_esp32.h. */
const udsota_engine_t *udsota_esp32_engine(void)
{
    return &s_engine;
}

/* Starts the engine once, before anything uses it. Creates the flash worker (Kconfig core, priority and stack;
 * internal RAM; off the task watchdog), its 4 KB block buffer and job queue. Takes the image identity from cfg
 * (product, hw_id, layout_id, req_id, resp_id; the product string must stay valid), the running version from
 * esp_app_desc and the release flag from udsota_image_desc, and puts the inactive slot's size in
 * udsota_esp32_engine()->slot_size. The worker reads the OTA state before its first job. Idempotent. A failed
 * allocation or a missing inactive slot is logged, and every download is then refused. Links against
 * udsota_image_desc, so the app places one with UDSOTA_ESP32_IMAGE_DESC. */
static void engine_start(const udsota_config_t *cfg)
{
    if (s_q != NULL || cfg == NULL) {
        return;
    }
    const esp_partition_t *run = esp_ota_get_running_partition();
    s_running = run;
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
    s_q = q;                                    /* before the task: worker_task reads it */
    /* The task is created only when both allocations succeeded. */
    if (s_buf == NULL || q == NULL ||
        xTaskCreatePinnedToCoreWithCaps(worker_task, "udsota_worker", WORKER_STACK, NULL, WORKER_PRIO, NULL,
                                        WORKER_CORE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) != pdPASS) {
        ESP_LOGE(TAG, "no internal RAM for the flash worker or its task: downloads refused");
        s_q = NULL;
        if (q != NULL) {
            vQueueDelete(q);
        }
        heap_caps_free(s_buf);
        s_buf = NULL;
        return;
    }
    ESP_LOGD(TAG, "flash worker up: target %s (%" PRIu32 " B), running v%u.%u.%u (%s), hw_id %u",
             (s_target != NULL) ? s_target->label : "none", s_ctx.slot_size, s_ctx.running_version[0],
             s_ctx.running_version[1], s_ctx.running_version[2], s_ctx.running_is_release ? "release" : "dev",
             s_ctx.hw_id);
}

/* See udsota_esp32_priv.h: the one call the diag task's start makes into the updater. */
bool udsota_esp32_server_init(udsota_server_t *srv, const udsota_config_t *cfg, const udsota_security_t *sec,
                              const udsota_hooks_t *hooks, void (*wake)(void))
{
    engine_set_wake(wake);
    engine_start(cfg);                          /* logs its own failures; the engine then refuses downloads */
    return udsota_init(srv, cfg, udsota_esp32_engine(), sec, hooks);
}
