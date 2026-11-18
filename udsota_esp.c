/* udsota_esp.c: udsota's ESP-IDF platform, the udsota_plat_* functions of udsota.h and the PSA lock. The flash worker on
 * esp_ota_*, the slot status, identity, crypto and a delta's base. A host build does not compile it: each host target
 * brings a platform of its own (test/e2e/lite_platform.c is one). It calls back into udsota.c only through
 * udsota_priv.h. */
#include <string.h>
#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#if UDSOTA_DELTA
#include "esp_image_format.h"
#endif
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include "udsota_priv.h"
#define LOGW(...) ESP_LOGW("udsota", __VA_ARGS__)

/* The PSA lock (udsota.h): a FreeRTOS mutex in static storage, created by udsota_init before its key setup, so the
 * worker inherits a waiting task's priority while it holds it. */
static StaticSemaphore_t s_psa_storage;
static SemaphoreHandle_t s_psa;

void udsota_psa_lock_init(void)
{
    if (s_psa == NULL) {
        s_psa = xSemaphoreCreateMutexStatic(&s_psa_storage);
    }
}

bool udsota_psa_lock(uint32_t wait_ms)
{
    if (s_psa == NULL) {
        return true;                                     /* before udsota_init: only start code runs */
    }
    const TickType_t ticks = (wait_ms == UDSOTA_PSA_WAIT_FOREVER) ? portMAX_DELAY : pdMS_TO_TICKS(wait_ms);
    return xSemaphoreTake(s_psa, ticks) == pdTRUE;
}

void udsota_psa_unlock(void)
{
    if (s_psa != NULL) {
        (void)xSemaphoreGive(s_psa);
    }
}

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static udsota_status_t s_st = {.running_slot = UDSOTA_SLOT_NONE, .boot_slot = UDSOTA_SLOT_NONE};
static const esp_partition_t *s_target;          /* the inactive slot; NULL refuses every download */
static esp_ota_handle_t s_handle;
static bool s_open, s_verified;
static TaskHandle_t s_worker;
static int (*s_job)(void);
static int s_result;
static bool s_busy;
static psa_key_id_t s_pub;

static uint8_t slot_of(const esp_partition_t *p)
{
    return (p == NULL || p->type != ESP_PARTITION_TYPE_APP)        ? UDSOTA_SLOT_NONE
         : (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0)          ? UDSOTA_SLOT_OTA0
         : (p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1)          ? UDSOTA_SLOT_OTA1
                                                                    : UDSOTA_SLOT_NONE;
}

static uint8_t map_state(esp_ota_img_states_t s)
{
    switch (s) {
    case ESP_OTA_IMG_NEW:            return UDSOTA_IMG_NEW;
    case ESP_OTA_IMG_PENDING_VERIFY: return UDSOTA_IMG_PENDING_VERIFY;
    case ESP_OTA_IMG_VALID:          return UDSOTA_IMG_VALID;
    case ESP_OTA_IMG_INVALID:        return UDSOTA_IMG_INVALID;
    case ESP_OTA_IMG_ABORTED:        return UDSOTA_IMG_ABORTED;
    default:                         return UDSOTA_IMG_UNDEFINED;
    }
}

/* The other slot's state, with its version and SHA prefix read from its descriptor unless it is being written. */
static void set_other(uint8_t state)
{
    esp_app_desc_t d;
    uint8_t ver[3] = {0, 0, 0}, sha[8] = {0};
    bool clean;
    if (state != UDSOTA_OTHER_WRITING) {
        if (s_target == NULL || esp_ota_get_partition_description(s_target, &d) != ESP_OK) {
            state = UDSOTA_OTHER_EMPTY;
        } else {
            (void)udsota_parse_version(d.version, sizeof d.version, ver, &clean);
            memcpy(sha, d.app_elf_sha256, sizeof sha);
        }
    }
    taskENTER_CRITICAL(&s_mux);
    s_st.other_slot_state = (state == UDSOTA_OTHER_VERIFIED && !s_verified) ? UDSOTA_OTHER_UNVERIFIED : state;
    memcpy(s_st.other_version, ver, 3);
    memcpy(s_st.other_elf_sha_prefix, sha, 8);
    taskEXIT_CRITICAL(&s_mux);
}

/* The slots as they are at start, read on udsota_init's task, so udsota_unconfirmed() and F1F0 are right from then. */
static void read_slots(const esp_partition_t *run)
{
    esp_ota_img_states_t st;
    udsota_status_t s = {.running_slot = slot_of(run), .boot_slot = slot_of(esp_ota_get_boot_partition())};
    s.running_state = (esp_ota_get_state_partition(run, &st) == ESP_OK) ? map_state(st) : UDSOTA_IMG_UNDEFINED;
#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    if (s.running_state == UDSOTA_IMG_PENDING_VERIFY) {
        s.running_state = UDSOTA_IMG_VALID;              /* without rollback nothing waits for a confirm */
    }
#endif
#if CONFIG_SECURE_SIGNED_ON_UPDATE
    s.flags = UDSOTA_STATUS_SIG_CHECKED;
#endif
    taskENTER_CRITICAL(&s_mux);
    s_st = s;
    taskEXIT_CRITICAL(&s_mux);
    const bool rolled_back = s_target != NULL && esp_ota_get_state_partition(s_target, &st) == ESP_OK &&
                             (st == ESP_OTA_IMG_INVALID || st == ESP_OTA_IMG_ABORTED);
    set_other(rolled_back ? UDSOTA_OTHER_INVALID : UDSOTA_OTHER_UNVERIFIED);
}

/* The worker: runs one job at a time. Off the task watchdog: an erase busy-waits. */
static void worker(void *arg)
{
    (void)arg;
    for (;;) {
        taskENTER_CRITICAL(&s_mux);
        int (*job)(void) = s_job;
        s_job = NULL;
        s_busy = (job != NULL);
        taskEXIT_CRITICAL(&s_mux);
        if (job == NULL) {
            (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            continue;
        }
        const int r = job();
        taskENTER_CRITICAL(&s_mux);
        s_result = r;
        taskEXIT_CRITICAL(&s_mux);
    }
}

#if UDSOTA_DELTA
static const esp_partition_t *s_running;         /* a delta download's base */
static uint8_t s_base_hash[32];
static bool s_base_hash_ok;                      /* s_base_hash is read, and kept for the boot */

/* The worker, a delta download's base: n bytes of the running slot at off, bounded by the slot and not the image, so a
 * signature block past the image reads too. esp_partition_read is esp_flash_read, or under flash encryption a map made
 * and dropped for each read. Never hold a map of the slot: with XIP from PSRAM a held map turns the cache off for every
 * erase and write. */
bool udsota_plat_base_read(uint32_t off, void *buf, size_t n)
{
    return s_running != NULL && (uint64_t)off + n <= s_running->size &&
           esp_partition_read(s_running, off, buf, n) == ESP_OK;
}

/* The worker, the base's identity: the SHA-256 the running image appends, as esp_image_get_metadata reads it, which
 * hashes nothing and takes no PSA lock. The first call reads it and later ones reuse it, as the running image never
 * changes. A base that no longer matches its stored hash only rebuilds an image FF01 refuses. */
bool udsota_plat_base_hash(uint8_t out[32])
{
    if (!s_base_hash_ok && s_running != NULL) {
        const esp_partition_pos_t pos = {.offset = s_running->address, .size = s_running->size};
        esp_image_metadata_t md;
        const esp_err_t err = esp_image_get_metadata(&pos, &md);
        s_base_hash_ok = (err == ESP_OK && md.image.hash_appended == 1u);
        if (s_base_hash_ok) {
            memcpy(s_base_hash, md.image_digest, sizeof s_base_hash);
        } else if (err != ESP_OK) {
            LOGW("can't read the running image to match a delta's base against: %s", esp_err_to_name(err));
        } else {
            LOGW("the running image has no appended SHA-256 to match a delta's base against");
        }
    }
    if (s_base_hash_ok) {
        memcpy(out, s_base_hash, sizeof s_base_hash);
    }
    return s_base_hash_ok;
}
#endif

int udsota_plat_start(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
#if UDSOTA_DELTA
    s_running = run;
#endif
    s_target = esp_ota_get_next_update_partition(NULL);
    if (s_target == NULL || s_target == run) {
        s_target = NULL;
        LOGW("no inactive OTA slot: every download is refused");
    } else if (slot_of(run) == UDSOTA_SLOT_NONE) {
        LOGW("running the factory app: every download is refused until an OTA slot boots");
    }
    read_slots(run);
    if (xTaskCreatePinnedToCore(worker, "udsota", 8192, NULL, 2, &s_worker, tskNO_AFFINITY) != pdPASS) {
        LOGW("no memory for the flash worker: every download is refused");
        s_worker = NULL;
        return -1;
    }
    return (s_target != NULL) ? 0 : -1;
}

int udsota_plat_run(int (*job)(void))
{
    taskENTER_CRITICAL(&s_mux);
    const bool ok = s_worker != NULL && !s_busy && s_job == NULL;
    if (ok) {
        s_job = job;
        s_busy = true;
    }
    taskEXIT_CRITICAL(&s_mux);
    if (ok) {
        xTaskNotifyGive(s_worker);
    }
    return ok ? UDSOTA_PENDING : -1;
}

int udsota_plat_poll(void)
{
    taskENTER_CRITICAL(&s_mux);
    const int r = s_busy ? UDSOTA_PENDING : s_result;
    taskEXIT_CRITICAL(&s_mux);
    return r;
}

void udsota_plat_abort(void)
{
    if (s_open) {
        (void)esp_ota_abort(s_handle);
        s_open = false;
        set_other(UDSOTA_OTHER_UNVERIFIED);
    }
}

bool udsota_plat_compatible(const uint8_t *first, size_t len)
{
    esp_image_header_t hdr;
    esp_app_desc_t app;
    if (len < sizeof hdr + sizeof(esp_image_segment_header_t) + sizeof app) {
        return false;
    }
    memcpy(&hdr, first, sizeof hdr);
    memcpy(&app, first + sizeof hdr + sizeof(esp_image_segment_header_t), sizeof app);
    return esp_ota_check_image_validity(ESP_PARTITION_TYPE_APP, &hdr, &app) == ESP_OK;   /* chip revision, flash mode */
}

/* Opens the slot with sequential writes, so each write erases only the sectors it writes and the erase is spread over
 * the download.
 * Refused while otadata already boots the slot (an activated image waiting for its reset). */
int udsota_plat_begin(uint32_t size)
{
    udsota_plat_abort();
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    const bool booting = s_st.boot_slot == slot_of(s_target);
    taskEXIT_CRITICAL(&s_mux);
    if (s_target == NULL || size > s_target->size || booting) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    set_other(UDSOTA_OTHER_WRITING);
    s_handle = 0;
    if (esp_ota_begin(s_target, OTA_WITH_SEQUENTIAL_WRITES, &s_handle) != ESP_OK) {
        (void)esp_ota_abort(s_handle);
        set_other(UDSOTA_OTHER_UNVERIFIED);
        return UDSOTA_DL_FLASH_ERROR;
    }
    s_open = true;
    return UDSOTA_DL_OK;
}

int udsota_plat_write(const uint8_t *d, size_t n)
{
    if (!s_open || esp_ota_write(s_handle, d, n) != ESP_OK) {
        udsota_plat_abort();
        return UDSOTA_DL_FLASH_ERROR;
    }
    return UDSOTA_DL_OK;
}

/* The first bytes of the slot, read back after the verify, pass the image rules again. */
static int recheck(void)
{
    uint8_t first[IMAGE_MIN];
    if (esp_partition_read(s_target, 0, first, sizeof first) != ESP_OK) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    return udsota_check_first(first, sizeof first, IMAGE_MIN);
}

/* FF01: esp_ota_end checks the SHA-256, and the signature with CONFIG_SECURE_SIGNED_ON_UPDATE. */
int udsota_plat_end(void)
{
    if (!s_open) {
        return s_verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    s_open = false;                                      /* esp_ota_end frees the handle either way */
    int r = (esp_ota_end(s_handle) == ESP_OK) ? recheck() : UDSOTA_DL_VERIFY_FAILED;
    taskENTER_CRITICAL(&s_mux);
    s_verified = (r == UDSOTA_DL_OK);
    taskEXIT_CRITICAL(&s_mux);
    set_other(r == UDSOTA_DL_OK ? UDSOTA_OTHER_VERIFIED : UDSOTA_OTHER_UNVERIFIED);
    return r;
}

/* F001: esp_ota_set_boot_partition checks the image again before it writes otadata. */
int udsota_plat_activate(void)
{
    int r = s_verified ? recheck() : UDSOTA_DL_VERIFY_FAILED;
    if (r == UDSOTA_DL_OK && esp_ota_set_boot_partition(s_target) != ESP_OK) {
        r = UDSOTA_DL_VERIFY_FAILED;
    }
    taskENTER_CRITICAL(&s_mux);
    if (r == UDSOTA_DL_OK) {
        s_st.boot_slot = slot_of(s_target);
    } else {
        s_verified = false;
    }
    taskEXIT_CRITICAL(&s_mux);
    if (r != UDSOTA_DL_OK) {
        set_other(UDSOTA_OTHER_UNVERIFIED);
    }
    return r;
}

/* F002: marks the running image valid; the updater checked it is the pending boot image. */
int udsota_plat_confirm(void)
{
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) {
        return UDSOTA_DL_ABORTED;
    }
#endif
    taskENTER_CRITICAL(&s_mux);
    s_st.running_state = UDSOTA_IMG_VALID;
    taskEXIT_CRITICAL(&s_mux);
    return UDSOTA_DL_OK;
}

void udsota_plat_unverify(void)
{
    taskENTER_CRITICAL(&s_mux);
    s_verified = false;
    if (s_st.other_slot_state == UDSOTA_OTHER_VERIFIED) {
        s_st.other_slot_state = UDSOTA_OTHER_UNVERIFIED;
    }
    taskEXIT_CRITICAL(&s_mux);
}

void udsota_plat_status(udsota_status_t *out)
{
    taskENTER_CRITICAL(&s_mux);
    *out = s_st;
    taskEXIT_CRITICAL(&s_mux);
}

uint32_t udsota_plat_slot_size(void) { return (s_target != NULL) ? s_target->size : 0u; }
const char *udsota_plat_version(void) { return esp_app_get_description()->version; }
const char *udsota_plat_project(void) { return esp_app_get_description()->project_name; }
const uint8_t *udsota_plat_sha(void) { return esp_app_get_description()->app_elf_sha256; }

size_t udsota_plat_mac(uint8_t out[16])
{
    return (esp_read_mac(out, ESP_MAC_BASE) == ESP_OK) ? 6u : 0u;
}

/* A seed from the hardware RNG. udsota never switches an entropy source on or off, since that would reconfigure the
 * app's ADC (and I2S0 on an ESP32): the RNG is true random while Wi-Fi or Bluetooth runs or the app has called
 * bootloader_random_enable(), and otherwise draws on the chip's secondary entropy source (not on an ESP32). */
bool udsota_plat_rng16(uint8_t out[16])
{
    esp_fill_random(out, 16);
    return true;
}

bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    size_t n = 0;
    bool ok = psa_import_key(&attr, key, key_len, &id) == PSA_SUCCESS &&
              psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len, out, 32, &n) == PSA_SUCCESS &&
              n == 32u;
    ok = (psa_destroy_key(id) == PSA_SUCCESS) && ok;
    if (!ok) {
        udsota_wipe(out, 32);
    }
    return ok;
}

int udsota_plat_ecdsa_key(const uint8_t *pubkey)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    return (psa_import_key(&attr, pubkey, UDSOTA_KEYS_PUBKEY_LEN, &s_pub) == PSA_SUCCESS) ? 0 : -1;
}

int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[UDSOTA_KEYS_SIG_LEN])
{
    uint8_t hash[32];
    size_t hn = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, msg, n, hash, sizeof hash, &hn) != PSA_SUCCESS) {
        return -1;
    }
    const psa_status_t st =
        psa_verify_hash(s_pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hn, sig, UDSOTA_KEYS_SIG_LEN);
    return (st == PSA_SUCCESS) ? 1 : (st == PSA_ERROR_INSUFFICIENT_MEMORY || st == PSA_ERROR_HARDWARE_FAILURE) ? -1 : 0;
}
