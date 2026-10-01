/* udsota_lite_server's platform; see lite_platform.h. The ESP-IDF platform at the end of udsota.c is its model: the
 * same slot states, F1F0 fields and refusals, with RAM in place of flash and otadata. */
#include "lite_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hmac_sha256_host.h"
#include "sha256_host.h"
#include "udsota.h"

#define APP_DESC  32u              /* esp_app_desc_t: version at +16, project at +48, app_elf_sha256 at +144 */
#define IMAGE_MIN 320u
#define JOB_MS    100u             /* a job's result comes this long after it is queued, past iso14229's P2 (50 ms) */

static struct {
    uint8_t *slot[2];
    bool     aborted[2];           /* the bootloader rolled this slot's image back */
    uint8_t  running, boot, state; /* the running and boot slots, and the running image's UDSOTA_IMG_* */
    bool     open, verified;       /* the other slot is being written; it passed FF01 */
    uint32_t pos;                  /* bytes written to it */
    int      result;               /* the last job's */
    uint64_t done_ms;              /* when it is reported */
    char     version[33], project[33];
} P;

static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* The slot udsota downloads into. */
static unsigned other(void)
{
    return 1u - P.running;
}

/* True when slot s holds an esp_app_desc_t. */
static bool has_desc(unsigned s)
{
    return le32(&P.slot[s][APP_DESC]) == 0xABCD5432u;
}

/* One of slot s's esp_app_desc_t strings (32 bytes at off), NUL-terminated. */
static void desc_str(unsigned s, size_t off, char out[33])
{
    memcpy(out, &P.slot[s][APP_DESC + off], 32);
    out[32] = '\0';
}

/* The length of the ESP-IDF app image in img[0..len), up to its appended SHA-256 when it has one, if its segments,
 * checksum byte and SHA-256 hold (what esp_ota_end checks, short of a signature); 0 otherwise. */
static size_t image_len(const uint8_t *img, size_t len)
{
    if (len < IMAGE_MIN || img[0] != 0xE9u || img[1] == 0u || img[1] > 16u) {
        return 0;
    }
    size_t off = 24u;
    uint8_t x = 0xEFu;
    for (unsigned s = 0; s < img[1]; s++) {
        if (len - off < 8u || le32(&img[off + 4u]) > len - off - 8u) {
            return 0;
        }
        const size_t n = le32(&img[off + 4u]);
        off += 8u;
        for (size_t i = 0; i < n; i++) {
            x ^= img[off + i];
        }
        off += n;
    }
    const size_t end = (off + 1u + 15u) & ~(size_t)15u;   /* the checksum byte closes a 16-byte-aligned run */
    if (end > len || img[end - 1u] != x) {
        return 0;
    }
    uint8_t sha[32];
    if (img[23] != 1u) {
        return end;
    }
    return (len - end >= 32u && sha256_host(img, end, sha) && memcmp(sha, &img[end], 32) == 0) ? end + 32u : 0u;
}

/* "[v]M.m.p" and anything after it as three bytes, as F1F0 gives the other slot's version; zeros when it doesn't
 * parse. */
static void version3(const char *s, uint8_t out[3])
{
    s += (*s == 'v');
    for (int i = 0; i < 3; i++) {
        char *end;
        const unsigned long v = strtoul(s, &end, 10);
        if (end == s || v > 255u || (i < 2 && *end != '.')) {
            memset(out, 0, 3);
            return;
        }
        out[i] = (uint8_t)v;
        s = end + 1;
    }
}

bool lite_plat_load(const uint8_t *image, size_t len)
{
    P.slot[0] = malloc(LITE_SLOT_SIZE);
    P.slot[1] = malloc(LITE_SLOT_SIZE);
    if (P.slot[0] == NULL || P.slot[1] == NULL || len > LITE_SLOT_SIZE || image_len(image, len) == 0u) {
        return false;
    }
    memset(P.slot[0], 0xFF, LITE_SLOT_SIZE);
    memset(P.slot[1], 0xFF, LITE_SLOT_SIZE);
    memcpy(P.slot[0], image, len);
    P.running = P.boot = 0;
    P.state = UDSOTA_IMG_VALID;
    return has_desc(0);
}

void lite_plat_boot(unsigned boot_no)
{
    static const char *const states[] = {"undefined", "new", "pending verify", "valid", "invalid", "aborted"};
    P.open = P.verified = false;
    P.done_ms = 0u;                                      /* a reset ends the worker's job */
    if (P.boot != P.running) {                           /* activated: the new image's first boot */
        P.running = P.boot;
        P.state = UDSOTA_IMG_PENDING_VERIFY;
    } else if (P.state == UDSOTA_IMG_PENDING_VERIFY) {   /* never confirmed: back to the other slot */
        P.aborted[P.running] = true;
        P.running = P.boot = (uint8_t)other();
        P.state = UDSOTA_IMG_VALID;
    }
    desc_str(P.running, 16u, P.version);
    desc_str(P.running, 48u, P.project);
    fprintf(stderr, "udsota_lite_server: boot %u: slot %u runs %s (%s)%s\n", boot_no, P.running, P.version,
            states[P.state], P.aborted[other()] ? "; the other slot's image was rolled back" : "");
}

void lite_plat_close(void)
{
    free(P.slot[0]);
    free(P.slot[1]);
    memset(&P, 0, sizeof P);
}

/* ---- udsota.h's platform ---- */

int udsota_plat_start(void)
{
    return 0;
}

/* The job runs now, and its result is reported JOB_MS later, as an ESP32's worker takes a while to erase and write:
 * meanwhile the worker is busy and iso14229 answers the request 0x78. */
int udsota_plat_run(int (*job)(void))
{
    if (mono_ms() < P.done_ms) {
        return -1;
    }
    P.result = job();
    P.done_ms = mono_ms() + JOB_MS;
    return UDSOTA_PENDING;
}

int udsota_plat_poll(void)
{
    return (mono_ms() < P.done_ms) ? UDSOTA_PENDING : P.result;
}

void udsota_plat_abort(void)
{
    P.open = false;
}

bool udsota_plat_compatible(const uint8_t *first, size_t len)
{
    (void)first;
    (void)len;
    return true;
}

/* Erases the other slot and opens it; refused while otadata already boots it (an activated image waiting for its
 * reset). */
int udsota_plat_begin(uint32_t size)
{
    udsota_plat_abort();
    P.verified = false;
    if (size > LITE_SLOT_SIZE || P.boot != P.running) {
        return UDSOTA_DL_FLASH_ERROR;
    }
    memset(P.slot[other()], 0xFF, LITE_SLOT_SIZE);
    P.aborted[other()] = false;
    P.pos = 0u;
    P.open = true;
    return UDSOTA_DL_OK;
}

int udsota_plat_write(const uint8_t *d, size_t n)
{
    if (!P.open || n > LITE_SLOT_SIZE - P.pos) {
        udsota_plat_abort();
        return UDSOTA_DL_FLASH_ERROR;
    }
    memcpy(&P.slot[other()][P.pos], d, n);
    P.pos += (uint32_t)n;
    return UDSOTA_DL_OK;
}

int udsota_plat_end(void)
{
    if (!P.open) {
        return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_ABORTED;
    }
    P.open = false;
    P.verified = image_len(P.slot[other()], P.pos) != 0u;
    return P.verified ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}

int udsota_plat_activate(void)
{
    if (!P.verified) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    P.boot = (uint8_t)other();
    return UDSOTA_DL_OK;
}

int udsota_plat_confirm(void)
{
    P.state = UDSOTA_IMG_VALID;
    return UDSOTA_DL_OK;
}

void udsota_plat_unverify(void)
{
    P.verified = false;
}

void udsota_plat_status(udsota_status_t *out)
{
    const unsigned o = other();
    memset(out, 0, sizeof *out);
    out->running_slot = P.running;
    out->running_state = P.state;
    out->boot_slot = P.boot;
    if (P.open || !has_desc(o)) {
        out->other_slot_state = P.open ? UDSOTA_OTHER_WRITING : UDSOTA_OTHER_EMPTY;
        return;
    }
    out->other_slot_state = P.aborted[o] ? UDSOTA_OTHER_INVALID
                          : P.verified   ? UDSOTA_OTHER_VERIFIED
                                         : UDSOTA_OTHER_UNVERIFIED;
    char v[33];
    desc_str(o, 16u, v);
    version3(v, out->other_version);
    memcpy(out->other_elf_sha_prefix, &P.slot[o][APP_DESC + 144u], 8);
}

uint32_t udsota_plat_slot_size(void)
{
    return LITE_SLOT_SIZE;
}

const char *udsota_plat_version(void)
{
    return P.version;
}

const char *udsota_plat_project(void)
{
    return P.project;
}

const uint8_t *udsota_plat_sha(void)
{
    return &P.slot[P.running][APP_DESC + 144u];
}

/* A locally administered MAC, the device ID the client's tests use. */
size_t udsota_plat_mac(uint8_t out[16])
{
    static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(out, mac, sizeof mac);
    return sizeof mac;
}

bool udsota_plat_rng16(uint8_t out[16])
{
    FILE *f = fopen("/dev/urandom", "rb");
    const bool ok = f != NULL && fread(out, 1, 16, f) == 16u;
    if (f != NULL) {
        fclose(f);
    }
    return ok;
}

bool udsota_plat_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    return hmac_sha256_host(key, key_len, msg, msg_len, out);
}

int udsota_plat_ecdsa_key(const uint8_t *pubkey)
{
    (void)pubkey;
    return -1;
}

int udsota_plat_ecdsa(const uint8_t *msg, size_t n, const uint8_t sig[64])
{
    (void)msg;
    (void)n;
    (void)sig;
    return -1;
}
