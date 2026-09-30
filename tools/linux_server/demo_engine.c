/* The Linux demo server's update engine over fake_engine; see demo_engine.h. */
#define _GNU_SOURCE
#include "demo_engine.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "udsota_esp32_image.h"

#define SEED_CAP (32u + DEMO_SEED_PAYLOAD + 16u + 32u)   /* headers, segment 0, checksum padding, SHA-256 */

/* Monotonic milliseconds, for the emulated worker jobs. */
static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
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

/* The coded download's erase: fake_ota_begin, synchronous (the job wraps the whole zwrite). */
static int z_begin(void *ctx, uint32_t size)
{
    demo_engine_t *e = ctx;
    return fake_ota_begin(&e->ota, size);
}

/* The coded download's write, at the image offset where the last one ended. */
static int z_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    demo_engine_t *e = ctx;
    return (off == e->ota.written) ? fake_ota_write(&e->ota, d, n) : -1;
}

/* engine.begin: erases the inactive slot's image extent. */
static int eng_begin(void *ctx, uint32_t size)
{
    return job(ctx, z_begin(ctx, size));
}

/* engine.write: appends at off, which must be where the last write ended; joins a running job (the erase). */
static int eng_write(void *ctx, uint32_t off, const uint8_t *d, size_t n)
{
    demo_engine_t *e = ctx;
    const int rc = z_write(ctx, off, d, n);
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
        const bool got = fake_ota_slot_read(&e->ota, fake_ota_other(&e->ota), 0, first, sizeof first) == 0;
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

/* engine.abort: drops the open write, and any coded download; the partial image stays in the slot. */
static void eng_abort(void *ctx)
{
    demo_engine_t *e = ctx;
    udsota_coded_close(&e->cd);
    (void)fake_ota_abort(&e->ota);
}

/* A delta download's base: n bytes of the running slot at off; a read past the slot is refused. */
static int base_read(void *ctx, uint32_t off, uint8_t *buf, size_t n)
{
    const demo_engine_t *e = ctx;
    return fake_ota_slot_read(&e->ota, e->ota.running_slot, off, buf, n);
}

/* A delta download's base identity: the SHA-256 the running image stores, as the ESP32 port reads it; read once
 * per boot. */
static int base_hash(void *ctx, uint8_t out[UDSOTA_PATCH_HASH_LEN])
{
    demo_engine_t *e = ctx;
    if (!e->base_hash_ok) {
        e->base_hash_ok = fake_ota_slot_hash(&e->ota, e->ota.running_slot, e->base_hash);
    }
    if (!e->base_hash_ok) {
        return -1;
    }
    memcpy(out, e->base_hash, UDSOTA_PATCH_HASH_LEN);
    return 0;
}

/* engine.zbegin: opens the coded download for dfi and size bytes over the vendored tinfl and detools;
 * UDSOTA_DL_NO_MEMORY when malloc fails. */
static int eng_zbegin(void *ctx, uint32_t size, uint8_t dfi)
{
    demo_engine_t *e = ctx;
    udsota_coded_close(&e->cd);
    const udsota_inflate_t inf = udsota_tinfl_inflate(&e->tinfl);
    const udsota_patch_t patch = udsota_detools_patch(&e->detools);
    const udsota_pbase_t base = {.read = base_read, .hash = base_hash, .ctx = e};
    const udsota_coded_cfg_t cfg = {
        .sink = {.check_first = eng_check_first, .begin = z_begin, .write = z_write, .ctx = e},
        .out = e->zout, .out_max = sizeof e->zout, .inflate = &inf, .patch = &patch, .base = &base,
        .zbuf = e->pbuf, .zbuf_max = sizeof e->pbuf,
    };
    return (int)udsota_coded_open(&e->cd, dfi, size, &cfg);
}

/* engine.zwrite: decodes one payload into the rules, erase and writes; a job like any other when job_ms is set. */
static int eng_zwrite(void *ctx, const uint8_t *d, size_t n)
{
    demo_engine_t *e = ctx;
    return job(e, (int)udsota_coded_feed(&e->cd, d, n));
}

/* engine.zwritten: the image bytes the download has written, for progress. */
static uint32_t eng_zwritten(void *ctx)
{
    return udsota_coded_written(&((const demo_engine_t *)ctx)->cd);
}

/* engine.zend: the 37 check; frees the decoders. A job like any other when job_ms is set, as the ESP32 port runs it
 * on its worker. */
static int eng_zend(void *ctx)
{
    demo_engine_t *e = ctx;
    return job(e, (int)udsota_coded_end(&e->cd));
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

/* engine.running_sha (F1F3): the running image's app_elf_sha256; 0 when the slot holds no image, its length,
 * unwritten, when max is short. */
static size_t eng_running_sha(void *ctx, uint8_t *out, size_t max)
{
    const demo_engine_t *e = ctx;
    char v[33];
    uint8_t sha[32];
    if (!fake_ota_slot_desc(&e->ota, e->ota.running_slot, v, sha)) {
        return 0;
    }
    if (max >= sizeof sha) {
        memcpy(out, sha, sizeof sha);
    }
    return sizeof sha;
}

/* engine.version (F189): the running image's version string, unterminated; 0 when there is none, its length,
 * unwritten, when max is short. */
static size_t eng_version(void *ctx, char *out, size_t max)
{
    char v[33];
    demo_engine_version((const demo_engine_t *)ctx, v);
    const size_t n = strlen(v);
    if (n <= max) {
        memcpy(out, v, n);
    }
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
        const size_t n = fake_ota_build_image(img, sizeof img, seed_version, &e->rules, DEMO_SEED_PAYLOAD);
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
    udsota_coded_close(&e->cd);
    fake_ota_boot(&e->ota);
    e->base_hash_ok = false;                    /* the running slot may be the other one now */
    e->job_open = false;
    e->last_result = 0;
    rules_refresh(e);
}

/* Closes the slot files. */
void demo_engine_close(demo_engine_t *e)
{
    udsota_coded_close(&e->cd);
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
        .zbegin = e->compress ? eng_zbegin : NULL, .zwrite = e->compress ? eng_zwrite : NULL,
        .zend = e->compress ? eng_zend : NULL, .zwritten = e->compress ? eng_zwritten : NULL,
        .zformats = !e->compress ? 0u
                    : !e->delta  ? UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE)
                                 : (uint16_t)(UDSOTA_DL_FMT(UDSOTA_DL_DFI_DEFLATE) | UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA) |
                                              UDSOTA_DL_FMT(UDSOTA_DL_DFI_DELTA_DEFLATE)),
    };
}

/* fake_ota_build_image's image with cfg's identity; see demo_engine.h. */
size_t demo_image_build(uint8_t *out, size_t cap, const char *version, const udsota_config_t *cfg,
                        uint32_t payload_len)
{
    const udsota_image_ctx_t id = {.hw_id = cfg->hw_id, .partition_layout_id = cfg->layout_id,
                                   .diag_request_id = cfg->req_id, .diag_response_id = cfg->resp_id,
                                   .product = cfg->product};
    return fake_ota_build_image(out, cap, version, &id, payload_len);
}
