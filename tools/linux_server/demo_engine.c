/* The Linux demo server's update engine over fake_engine; see demo_engine.h. */
#define _GNU_SOURCE
#include "demo_engine.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "sha256_host.h"
#include "udsota_esp32_image.h"
#include "udsota_image_desc.h"

#define SEG0_OFS     32u    /* segment 0 data: esp_image_header_t 24 + esp_image_segment_header_t 8 */
#define PROJECT_OFS  80u    /* esp_app_desc_t.project_name (32 B) */
#define HASH_LEN     32u
#define SEED_CAP     (SEG0_OFS + DEMO_SEED_PAYLOAD + 16u + HASH_LEN)

/* Monotonic milliseconds, for the emulated worker jobs. */
static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Writes a little-endian u16. */
static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* Re-reads the version rule's inputs from the running slot: its version and whether it is a clean release. */
static void rules_refresh(demo_engine_t *e)
{
    char v[33];
    uint8_t sha[32];
    const uint8_t run = e->ota.running_slot;
    e->rules.running_is_release = false;
    if (fake_ota_slot_desc(&e->ota, run, v, sha) &&
        udsota_parse_version(v, sizeof v, e->rules.running_version, NULL)) {
        e->rules.running_is_release = fake_ota_slot_release(&e->ota, run);
    } else {
        memset(e->rules.running_version, 0, sizeof e->rules.running_version);   /* no image: a dev build 0.0.0 */
    }
}

/* Reports rc as a worker would: at once with no job delay, else as part of the running (or a new) job. */
static int job(demo_engine_t *e, int rc)
{
    if (e->job_ms == 0u) {
        e->last_result = rc;
        return rc;
    }
    if (!e->job_open) {
        e->job_open = true;
        e->job_end_ms = mono_ms() + e->job_ms;
        e->job_result = rc;
    } else if (e->job_result == 0) {
        e->job_result = rc;                  /* the batch reports its first failure */
    }
    return UDSOTA_PENDING;
}

/* The first-block rules: the port's image header check at chip_id, then udsota_image_check. The size rule gets
 * the slot size, as in the port: the server checks the announced size itself. */
static udsota_reason_t first_block_rules(const demo_engine_t *e, const uint8_t *first, size_t len)
{
    return udsota_esp32_image_check(first, len, e->rules.slot_size, e->chip_id, &e->rules, NULL);
}

/* engine.check_first: the first-block rules on the block in hand; 0 = pass, else 1 with *why set. */
static int eng_check_first(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why)
{
    const udsota_reason_t r = first_block_rules((const demo_engine_t *)ctx, first, len);
    if (why != NULL) {
        *why = r;
    }
    return r == UDSOTA_DL_OK ? 0 : 1;
}

/* engine.begin: erases the inactive slot's image extent. */
static int eng_begin(void *ctx, uint32_t size)
{
    demo_engine_t *e = ctx;
    return job(e, fake_ota_begin(&e->ota, size));
}

/* engine.write: appends at off, which must be where the last write ended; joins a running job (the erase). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    demo_engine_t *e = ctx;
    const int rc = (off == e->ota.written) ? fake_ota_write(&e->ota, d, n) : -1;
    if (e->job_open) {
        return job(e, rc);
    }
    e->last_result = rc;
    return rc;
}

/* engine.verify (FF01): fake_ota_end's image check, then the first-block rules on the bytes in the slot. */
static int eng_verify(void *ctx)
{
    demo_engine_t *e = ctx;
    int r = fake_ota_end(&e->ota);
    if (r == UDSOTA_DL_OK) {
        uint8_t first[UDSOTA_IMAGE_MIN_LEN];
        const int fd = e->ota.fd[fake_ota_other(&e->ota)];
        const bool got = pread(fd, first, sizeof first, 0) == (ssize_t)sizeof first;
        r = got ? (int)first_block_rules(e, first, sizeof first) : (int)UDSOTA_DL_VERIFY_FAILED;
        e->ota.verified = (r == UDSOTA_DL_OK);
    }
    return job(e, r);
}

/* engine.activate: makes the verified slot the boot slot. */
static int eng_activate(void *ctx)
{
    demo_engine_t *e = ctx;
    return job(e, fake_ota_activate(&e->ota));
}

/* engine.confirm: marks a PENDING_VERIFY running image valid. */
static int eng_confirm(void *ctx)
{
    demo_engine_t *e = ctx;
    return job(e, fake_ota_confirm(&e->ota));
}

/* engine.abort: drops the open write; the partial image stays in the slot. */
static void eng_abort(void *ctx)
{
    demo_engine_t *e = ctx;
    (void)fake_ota_abort(&e->ota);
}

/* engine.unverify: an accepted 34 means the inactive slot no longer counts as verified. */
static void eng_unverify(void *ctx)
{
    demo_engine_t *e = ctx;
    fake_ota_unverify(&e->ota);
}

/* engine.poll: UDSOTA_PENDING until the running job's time is up, then its result (and that result after). */
static int eng_poll(void *ctx)
{
    demo_engine_t *e = ctx;
    if (e->job_open) {
        if (mono_ms() < e->job_end_ms) {
            return UDSOTA_PENDING;
        }
        e->job_open = false;
        e->last_result = e->job_result;
    }
    return e->last_result;
}

/* engine.status (F1F0): the slots' state as fake_engine models it; no flags. */
static void eng_status(void *ctx, udsota_status_t *out)
{
    fake_ota_fill_status(&((const demo_engine_t *)ctx)->ota, out);
}

/* engine.running_sha (F1F3): the running image's app_elf_sha256; 0 when the slot holds no image. */
static size_t eng_running_sha(void *ctx, uint8_t *out, size_t max)
{
    const demo_engine_t *e = ctx;
    char v[33];
    uint8_t sha[32];
    if (max < sizeof sha || !fake_ota_slot_desc(&e->ota, e->ota.running_slot, v, sha)) {
        return 0;
    }
    memcpy(out, sha, sizeof sha);
    return sizeof sha;
}

/* engine.version (F189): the running image's version string, unterminated; 0 when there is none or max is short. */
static size_t eng_version(void *ctx, char *out, size_t max)
{
    char v[33];
    demo_engine_version((const demo_engine_t *)ctx, v);
    const size_t n = strlen(v);
    if (n == 0u || n > max) {
        return 0;
    }
    memcpy(out, v, n);
    return n;
}

/* The running image's version, "" without one. */
void demo_engine_version(const demo_engine_t *e, char out[33])
{
    uint8_t sha[32];
    if (!fake_ota_slot_desc(&e->ota, e->ota.running_slot, out, sha)) {
        out[0] = '\0';
    }
}

/* Opens the slots, boots, seeds a running image if there is none, and fills the rules from cfg. */
bool demo_engine_open(demo_engine_t *e, const char *dir, uint32_t slot_size, bool fresh, const udsota_config_t *cfg,
                      const char *seed_version, uint16_t chip_id, uint32_t job_ms)
{
    memset(e, 0, sizeof *e);
    if (!fake_ota_open(&e->ota, dir, slot_size, fresh)) {
        return false;
    }
    e->chip_id = chip_id;
    e->job_ms = job_ms;
    e->rules = (udsota_image_ctx_t){
        .hw_id = cfg->hw_id,
        .partition_layout_id = cfg->layout_id,
        .diag_request_id = cfg->req_id,
        .diag_response_id = cfg->resp_id,
        .slot_size = slot_size,
        .product = cfg->product,
    };
    char v[33];
    uint8_t sha[32];
    if (!fake_ota_slot_desc(&e->ota, e->ota.running_slot, v, sha)) {
        uint8_t img[SEED_CAP];
        const size_t n = demo_image_build(img, sizeof img, seed_version, cfg, DEMO_SEED_PAYLOAD);
        if (n == 0u || fake_ota_load_slot(&e->ota, e->ota.running_slot, img, n) != 0) {
            fake_ota_close(&e->ota);
            return false;
        }
    }
    rules_refresh(e);
    return true;
}

/* Simulated reset; see demo_engine.h. */
void demo_engine_boot(demo_engine_t *e)
{
    fake_ota_boot(&e->ota);
    e->job_open = false;
    e->last_result = 0;
    rules_refresh(e);
}

/* Closes the slot files. */
void demo_engine_close(demo_engine_t *e)
{
    fake_ota_close(&e->ota);
}

/* The op table; see demo_engine.h. */
udsota_engine_t demo_engine_ops(demo_engine_t *e)
{
    return (udsota_engine_t){
        .check_first = eng_check_first, .begin = eng_begin, .write = eng_write, .verify = eng_verify,
        .activate = eng_activate, .confirm = eng_confirm, .abort = eng_abort, .unverify = eng_unverify,
        .poll = eng_poll, .status = eng_status, .running_sha = eng_running_sha, .version = eng_version,
        .slot_size = e->rules.slot_size, .ctx = e,
    };
}

/* fake_ota_build_image's image, restamped for cfg and resealed; see demo_engine.h. */
size_t demo_image_build(uint8_t *out, size_t cap, const char *version, const udsota_config_t *cfg,
                        uint32_t payload_len)
{
    const char *product = (cfg->product != NULL) ? cfg->product : FAKE_OTA_PROJECT;
    if (strlen(product) > 31u) {
        return 0;
    }
    const size_t total = fake_ota_build_image(out, cap, version, cfg->hw_id, payload_len);
    if (total == 0u) {
        return 0;
    }
    memset(&out[PROJECT_OFS], 0, 32);
    memcpy(&out[PROJECT_OFS], product, strlen(product));
    uint8_t *d = &out[UDSOTA_IMG_DESC_OFFSET];
    d[offsetof(udsota_image_desc_t, partition_layout_id)] = cfg->layout_id;
    put_le16(&d[offsetof(udsota_image_desc_t, diag_request_id)], cfg->req_id);
    put_le16(&d[offsetof(udsota_image_desc_t, diag_response_id)], cfg->resp_id);
    const size_t padded = total - HASH_LEN;         /* segment 0, then the checksum byte ending a 16-byte block */
    uint8_t x = 0xEF;                               /* ESP_ROM_CHECKSUM_INITIAL */
    for (size_t i = SEG0_OFS; i < SEG0_OFS + payload_len; i++) {
        x ^= out[i];
    }
    out[padded - 1u] = x;
    return sha256_host(out, padded, &out[padded]) ? total : 0u;
}
