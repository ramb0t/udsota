/* File-backed fake OTA engine for host tools: two slot files plus a one-line otadata file. See fake_engine.h. */
#define _GNU_SOURCE
#include "fake_engine.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "udsota_image.h"        /* udsota_parse_version */
#include "udsota_image_desc.h"
#include "sha256_host.h"

#define HDR_LEN        24u           /* esp_image_header_t */
#define SEG_HDR_LEN    8u            /* esp_image_segment_header_t */
#define APP_DESC_OFS   32u           /* esp_app_desc_t, first thing in segment 0 */
#define PROJECT_OFS    80u           /* esp_app_desc_t.project_name */
#define IDF_VER_OFS    144u          /* esp_app_desc_t.idf_ver */
#define HASH_LEN       32u
#define APP_DESC_MAGIC 0xABCD5432u   /* ESP_APP_DESC_MAGIC_WORD */

/* Builds "<dir>/<name>" into out; false if it does not fit. */
static bool path_of(const fake_ota_t *f, const char *name, char *out, size_t max)
{
    int n = snprintf(out, max, "%s/%s", f->dir, name);
    return n > 0 && (size_t)n < max;
}

/* Writes all of buf at off; 0, or -1 on a short write or error. */
static int pwrite_all(int fd, const uint8_t *buf, size_t len, off_t off)
{
    while (len > 0) {
        ssize_t w = pwrite(fd, buf, len, off);
        if (w <= 0) {
            return -1;
        }
        buf += w;
        len -= (size_t)w;
        off += w;
    }
    return 0;
}

/* Reads all of len bytes at off; 0, or -1 on a short read or error. */
static int pread_all(int fd, uint8_t *buf, size_t len, off_t off)
{
    while (len > 0) {
        ssize_t r = pread(fd, buf, len, off);
        if (r <= 0) {
            return -1;
        }
        buf += r;
        len -= (size_t)r;
        off += r;
    }
    return 0;
}

/* Fills [off, off + len) with 0xFF, as a flash erase leaves it. */
static int erase_range(int fd, uint32_t off, uint32_t len)
{
    static uint8_t ff[65536];
    if (ff[0] != 0xFF) {
        memset(ff, 0xFF, sizeof ff);
    }
    while (len > 0) {
        uint32_t n = len < sizeof ff ? len : (uint32_t)sizeof ff;
        if (pwrite_all(fd, ff, n, off) != 0) {
            return -1;
        }
        off += n;
        len -= n;
    }
    return 0;
}

/* Reads a little-endian u32 (image fields are little-endian, like the S3). */
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Writes a little-endian u32. */
static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* True for a clean tag: the ESP32 port's release regex ^v?[0-9]+\.[0-9]+\.[0-9]+$. */
static bool is_clean_tag(const char *v)
{
    if (*v == 'v') {
        v++;
    }
    for (int part = 0; part < 3; part++) {
        if (*v < '0' || *v > '9') {
            return false;
        }
        while (*v >= '0' && *v <= '9') {
            v++;
        }
        if (part < 2 && *v++ != '.') {
            return false;
        }
    }
    return *v == '\0';
}

/* Saves boot target and slot states to otadata.txt through a rename, so a SIGKILL never tears it. */
static void persist(const fake_ota_t *f)
{
    char tmp[300], dst[300];
    if (!path_of(f, "otadata.tmp", tmp, sizeof tmp) || !path_of(f, "otadata.txt", dst, sizeof dst)) {
        return;
    }
    FILE *fp = fopen(tmp, "w");
    if (fp == NULL) {
        return;
    }
    fprintf(fp, "boot=%u state0=%u state1=%u\n", f->boot_slot, f->state[0], f->state[1]);
    if (fclose(fp) == 0) {
        (void)rename(tmp, dst);
    }
}

/* Loads otadata.txt; false (caller uses defaults) if it is missing or malformed. */
static bool load_otadata(fake_ota_t *f)
{
    char p[300];
    unsigned b, s0, s1;
    if (!path_of(f, "otadata.txt", p, sizeof p)) {
        return false;
    }
    FILE *fp = fopen(p, "r");
    if (fp == NULL) {
        return false;
    }
    int n = fscanf(fp, "boot=%u state0=%u state1=%u", &b, &s0, &s1);
    fclose(fp);
    if (n != 3 || b > 1 || s0 > UDSOTA_IMG_ABORTED || s1 > UDSOTA_IMG_ABORTED) {
        return false;
    }
    f->boot_slot = (uint8_t)b;
    f->state[0] = (uint8_t)s0;
    f->state[1] = (uint8_t)s1;
    return true;
}

/* Opens (or with fresh, recreates) the slot files and otadata under dir, then simulates a boot. */
bool fake_ota_open(fake_ota_t *f, const char *dir, uint32_t slot_size, bool fresh)
{
    memset(f, 0, sizeof *f);
    f->fd[0] = f->fd[1] = -1;
    if (dir == NULL || strlen(dir) >= sizeof f->dir || slot_size < FAKE_OTA_SECTOR ||
        slot_size % FAKE_OTA_SECTOR != 0) {
        return false;
    }
    strcpy(f->dir, dir);
    f->slot_size = slot_size;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        return false;
    }
    static const char *const names[] = {"ota_0.bin", "ota_1.bin", "otadata.txt"};
    char p[300];
    if (fresh) {
        for (size_t i = 0; i < 3; i++) {
            if (path_of(f, names[i], p, sizeof p)) {
                (void)unlink(p);
            }
        }
    }
    for (uint8_t s = 0; s < 2; s++) {
        struct stat st;
        if (!path_of(f, names[s], p, sizeof p)) {
            fake_ota_close(f);
            return false;
        }
        f->fd[s] = open(p, O_RDWR | O_CREAT, 0644);
        if (f->fd[s] < 0 || fstat(f->fd[s], &st) != 0) {
            fake_ota_close(f);
            return false;
        }
        if ((uint64_t)st.st_size != slot_size &&
            (ftruncate(f->fd[s], (off_t)slot_size) != 0 || erase_range(f->fd[s], 0, slot_size) != 0)) {
            fake_ota_close(f);
            return false;
        }
    }
    if (!load_otadata(f)) {
        f->boot_slot = 0;
        f->state[0] = UDSOTA_IMG_VALID;   /* a serial-flashed, already confirmed image */
        f->state[1] = UDSOTA_IMG_UNDEFINED;
    }
    fake_ota_boot(f);
    return true;
}

/* Closes the slot files; otadata is already on disk after every state change. */
void fake_ota_close(fake_ota_t *f)
{
    for (uint8_t s = 0; s < 2; s++) {
        if (f->fd[s] >= 0) {
            close(f->fd[s]);
            f->fd[s] = -1;
        }
    }
}

/* Simulated reset: runs the boot target, promoting NEW and rolling back an unconfirmed PENDING_VERIFY. */
void fake_ota_boot(fake_ota_t *f)
{
    uint8_t s = f->boot_slot;
    if (f->state[s] == UDSOTA_IMG_NEW) {
        f->state[s] = UDSOTA_IMG_PENDING_VERIFY;   /* first boot of an activated image */
        f->running_slot = s;
    } else if (f->state[s] == UDSOTA_IMG_PENDING_VERIFY) {
        f->state[s] = UDSOTA_IMG_ABORTED;          /* rebooted before ConfirmImage: roll back */
        f->boot_slot = (uint8_t)(1u - s);
        f->running_slot = f->boot_slot;
    } else {
        f->running_slot = s;
    }
    f->writing = false;
    f->verified = false;                            /* a reboot clears "verified" */
    f->written = 0;
    persist(f);
}

/* The inactive slot: the one a download writes. */
uint8_t fake_ota_other(const fake_ota_t *f)
{
    return (uint8_t)(1u - f->running_slot);
}

/* Writes a whole image into slot (to seed a running image); erases the slot first. */
int fake_ota_load_slot(fake_ota_t *f, uint8_t slot, const uint8_t *data, size_t len)
{
    if (slot > 1 || data == NULL || len > f->slot_size) {
        return -1;
    }
    if (erase_range(f->fd[slot], 0, f->slot_size) != 0 || pwrite_all(f->fd[slot], data, len, 0) != 0) {
        return -1;
    }
    return 0;
}

/* esp_ota_begin(other, size): erases the image extent, rounded up to whole sectors. */
int fake_ota_begin(fake_ota_t *f, uint32_t size)
{
    if (size == 0 || size > f->slot_size) {
        return -1;
    }
    uint8_t t = fake_ota_other(f);
    uint32_t extent = (size + FAKE_OTA_SECTOR - 1u) / FAKE_OTA_SECTOR * FAKE_OTA_SECTOR;
    if (erase_range(f->fd[t], 0, extent) != 0) {
        return -1;
    }
    f->state[t] = UDSOTA_IMG_UNDEFINED;   /* IDF invalidates the otadata entry naming the target */
    f->writing = true;
    f->verified = false;
    f->written = 0;
    persist(f);
    return 0;
}

/* esp_ota_write: sequential append; the first byte must be the image magic 0xE9, as IDF checks. */
int fake_ota_write(fake_ota_t *f, const uint8_t *data, size_t len)
{
    if (!f->writing || (data == NULL && len > 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if ((f->written == 0 && data[0] != 0xE9) || len > (size_t)(f->slot_size - f->written)) {
        return -1;
    }
    if (pwrite_all(f->fd[fake_ota_other(f)], data, len, (off_t)f->written) != 0) {
        return -1;
    }
    f->written += (uint32_t)len;
    f->writes++;
    return 0;
}

/* esp_ota_end: closes the write and checks the whole image; UDSOTA_DL_OK or UDSOTA_DL_VERIFY_FAILED. */
int fake_ota_end(fake_ota_t *f)
{
    if (!f->writing) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    f->writing = false;
    uint8_t *buf = malloc(f->written ? f->written : 1u);
    udsota_reason_t r = UDSOTA_DL_VERIFY_FAILED;
    if (buf != NULL && pread_all(f->fd[fake_ota_other(f)], buf, f->written, 0) == 0) {
        r = fake_ota_verify_image(buf, f->written);
    }
    free(buf);
    f->verified = (r == UDSOTA_DL_OK);
    return (int)r;
}

/* esp_ota_abort: drops the open write and keeps the partial slot; a no-op when nothing is open. */
int fake_ota_abort(fake_ota_t *f)
{
    f->writing = false;
    f->verified = false;
    return 0;
}

/* ota_unverify: an accepted 0x34 means the other slot no longer counts as verified. */
void fake_ota_unverify(fake_ota_t *f)
{
    f->verified = false;
}

/* esp_ota_set_boot_partition(other): needs a slot that passed fake_ota_end since the last boot. NEW, or
 * UNDEFINED without rollback (esp_ota_ops.c:129-133), which fake_ota_boot runs as is on every boot. */
int fake_ota_activate(fake_ota_t *f)
{
    if (!f->verified || f->writing) {
        return -1;
    }
    uint8_t t = fake_ota_other(f);
    f->state[t] = f->no_rollback ? UDSOTA_IMG_UNDEFINED : UDSOTA_IMG_NEW;
    f->boot_slot = t;
    persist(f);
    return 0;
}

/* esp_ota_mark_app_valid_cancel_rollback: PENDING_VERIFY -> VALID; OK in any other state, like IDF.
 * Without rollback there is nothing to confirm: 0 and no change. */
int fake_ota_confirm(fake_ota_t *f)
{
    if (f->no_rollback) {
        return 0;
    }
    if (f->state[f->running_slot] == UDSOTA_IMG_PENDING_VERIFY) {
        f->state[f->running_slot] = UDSOTA_IMG_VALID;
        persist(f);
    }
    return 0;
}

/* Reads a slot's app descriptor version and app_elf_sha256; false if the descriptor magic is absent. */
bool fake_ota_slot_desc(const fake_ota_t *f, uint8_t slot, char version[33], uint8_t elf_sha[32])
{
    uint8_t m[4];
    if (slot > 1 || f->fd[slot] < 0 || pread_all(f->fd[slot], m, 4, APP_DESC_OFS) != 0 ||
        le32(m) != APP_DESC_MAGIC) {
        return false;
    }
    if (pread_all(f->fd[slot], (uint8_t *)version, 32, FAKE_OTA_VERSION_OFS) != 0 ||
        pread_all(f->fd[slot], elf_sha, 32, FAKE_OTA_ELF_SHA_OFS) != 0) {
        return false;
    }
    version[32] = '\0';
    return true;
}

/* Reads a slot's udsota descriptor; true only for a valid magic/desc_version with the release bit set. */
bool fake_ota_slot_release(const fake_ota_t *f, uint8_t slot)
{
    uint8_t d[sizeof(udsota_image_desc_t)];
    if (slot > 1 || f->fd[slot] < 0 || pread_all(f->fd[slot], d, sizeof d, UDSOTA_IMG_DESC_OFFSET) != 0) {
        return false;
    }
    const uint16_t desc_version = (uint16_t)(d[4] | (d[5] << 8));
    return le32(d) == UDSOTA_IMG_DESC_MAGIC && desc_version >= UDSOTA_IMG_DESC_VERSION &&
           (d[offsetof(udsota_image_desc_t, flags)] & UDSOTA_IMG_FLAG_RELEASE) != 0u;
}

/* F1F0 from the fake's state; flags stay 0. */
void fake_ota_fill_status(const fake_ota_t *f, udsota_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->running_slot = f->running_slot;
    out->running_state = f->state[f->running_slot];
    out->boot_slot = f->boot_slot;
    uint8_t o = fake_ota_other(f);
    char v[33];
    uint8_t sha[32];
    bool has = fake_ota_slot_desc(f, o, v, sha);
    if (f->writing) {
        out->other_slot_state = UDSOTA_OTHER_WRITING;
    } else if (f->verified) {
        out->other_slot_state = UDSOTA_OTHER_VERIFIED;
    } else if (f->state[o] == UDSOTA_IMG_ABORTED || f->state[o] == UDSOTA_IMG_INVALID) {
        out->other_slot_state = UDSOTA_OTHER_INVALID;
    } else {
        out->other_slot_state = has ? UDSOTA_OTHER_UNVERIFIED : UDSOTA_OTHER_EMPTY;
    }
    if (has) {
        (void)udsota_parse_version(v, sizeof v, out->other_version, NULL);   /* zeroes it when unparseable */
        memcpy(out->other_elf_sha_prefix, sha, sizeof out->other_elf_sha_prefix);
    }
}

/* Stateless resume point of the inactive slot: the sector before the first blank one (it may hold a torn page). */
uint32_t fake_ota_resume_point(const fake_ota_t *f)
{
    static uint8_t sec[FAKE_OTA_SECTOR];
    int fd = f->fd[fake_ota_other(f)];
    for (uint32_t off = 0; off < f->slot_size; off += FAKE_OTA_SECTOR) {
        if (pread_all(fd, sec, sizeof sec, (off_t)off) != 0) {
            return 0;
        }
        size_t i = 0;
        while (i < sizeof sec && sec[i] == 0xFF) {
            i++;
        }
        if (i == sizeof sec) {
            return off >= FAKE_OTA_SECTOR ? off - FAKE_OTA_SECTOR : 0;
        }
    }
    return f->slot_size - FAKE_OTA_SECTOR;
}

/* Where an image's appended SHA-256 starts: past the header, the segment walk and the checksum byte, which must
 * match. 0 for a malformed image, one without hash_appended or a wrong checksum. */
static size_t hash_offset(const uint8_t *img, size_t len)
{
    if (img == NULL || len < HDR_LEN + SEG_HDR_LEN || img[0] != 0xE9 || img[1] == 0 || img[1] > 16 ||
        img[23] != 1) {
        return 0;
    }
    size_t off = HDR_LEN;
    uint8_t x = 0xEF;                                   /* ESP_ROM_CHECKSUM_INITIAL */
    for (uint8_t i = 0; i < img[1]; i++) {
        if (len - off < SEG_HDR_LEN) {
            return 0;
        }
        uint32_t dl = le32(&img[off + 4]);
        off += SEG_HDR_LEN;
        if (dl > len - off) {
            return 0;
        }
        for (uint32_t k = 0; k < dl; k++) {
            x ^= img[off + k];
        }
        off += dl;
    }
    size_t padded = (off + 1u + 15u) & ~(size_t)15u;    /* checksum byte ends a 16-byte block */
    if (padded + HASH_LEN > len || img[padded - 1] != x) {
        return 0;
    }
    return padded;
}

/* The fake's esp_ota_end check over a whole image; see fake_engine.h. */
udsota_reason_t fake_ota_verify_image(const uint8_t *img, size_t len)
{
    const size_t padded = hash_offset(img, len);
    uint8_t d[HASH_LEN];
    if (padded == 0u || !sha256_host(img, padded, d)) {
        return UDSOTA_DL_VERIFY_FAILED;
    }
    return memcmp(d, &img[padded], HASH_LEN) == 0 ? UDSOTA_DL_OK : UDSOTA_DL_VERIFY_FAILED;
}

/* Reads n bytes of a slot at off; see fake_engine.h. */
int fake_ota_slot_read(const fake_ota_t *f, uint8_t slot, uint32_t off, uint8_t *buf, size_t n)
{
    if (slot > 1 || f->fd[slot] < 0 || (uint64_t)off + n > f->slot_size) {
        return -1;
    }
    return pread_all(f->fd[slot], buf, n, (off_t)off);
}

/* esp_partition_get_sha256 of a slot; see fake_engine.h. */
bool fake_ota_slot_hash(const fake_ota_t *f, uint8_t slot, uint8_t out[32])
{
    uint8_t *img = malloc(f->slot_size);
    bool ok = img != NULL && fake_ota_slot_read(f, slot, 0, img, f->slot_size) == 0 &&
              fake_ota_verify_image(img, f->slot_size) == UDSOTA_DL_OK;
    if (ok) {
        memcpy(out, &img[hash_offset(img, f->slot_size)], HASH_LEN);
    }
    free(img);
    return ok;
}

/* Builds a one-segment image that passes udsota_image_check and fake_ota_verify_image. */
size_t fake_ota_build_image(uint8_t *out, size_t cap, const char *version, uint8_t hw_id, uint32_t payload_len)
{
    if (out == NULL || version == NULL || strlen(version) > 31 || payload_len < FAKE_OTA_MIN_PAYLOAD ||
        payload_len % 4u != 0) {
        return 0;
    }
    size_t unpadded = HDR_LEN + SEG_HDR_LEN + payload_len;
    size_t padded = (unpadded + 1u + 15u) & ~(size_t)15u;
    size_t total = padded + HASH_LEN;
    if (cap < total) {
        return 0;
    }
    memset(out, 0, total);
    out[0] = 0xE9;                                   /* ESP_IMAGE_HEADER_MAGIC */
    out[1] = 1;                                      /* segment_count */
    out[2] = 2;                                      /* spi_mode DIO */
    put_le32(&out[4], 0x40378000u);                  /* entry_addr */
    out[8] = 0xEE;                                   /* wp_pin disabled */
    out[12] = 0x09;                                  /* chip_id ESP32-S3 (0x0009, little-endian) */
    out[23] = 1;                                     /* hash_appended */
    put_le32(&out[24], 0x3C000020u);                 /* segment 0 load_addr (DROM) */
    put_le32(&out[28], payload_len);                 /* segment 0 data_len */
    put_le32(&out[APP_DESC_OFS], APP_DESC_MAGIC);
    memcpy(&out[FAKE_OTA_VERSION_OFS], version, strlen(version));
    memcpy(&out[PROJECT_OFS], FAKE_OTA_PROJECT, strlen(FAKE_OTA_PROJECT));
    memcpy(&out[IDF_VER_OFS], "v6.1", 4);
    if (!sha256_host((const uint8_t *)version, strlen(version), &out[FAKE_OTA_ELF_SHA_OFS])) {   /* distinct per version */
        return 0;
    }
    const udsota_image_desc_t d = {
        .magic = UDSOTA_IMG_DESC_MAGIC, .desc_version = UDSOTA_IMG_DESC_VERSION, .hw_id = hw_id,
        .partition_layout_id = FAKE_OTA_LAYOUT_ID,
        .diag_request_id = FAKE_OTA_REQ_ID, .diag_response_id = FAKE_OTA_RESP_ID,
        .flags = is_clean_tag(version) ? UDSOTA_IMG_FLAG_RELEASE : 0u,   /* as the ESP32 port's build sets it */
    };
    memcpy(&out[UDSOTA_IMG_DESC_OFFSET], &d, sizeof d);          /* little-endian host, as on the S3 */
    for (size_t i = UDSOTA_IMG_DESC_OFFSET + sizeof d; i < unpadded; i++) {
        out[i] = (uint8_t)(i * 7u + 13u);
    }
    uint8_t x = 0xEF;
    for (size_t i = HDR_LEN + SEG_HDR_LEN; i < unpadded; i++) {
        x ^= out[i];
    }
    out[padded - 1] = x;
    if (!sha256_host(out, padded, &out[padded])) {
        return 0;
    }
    return total;
}
