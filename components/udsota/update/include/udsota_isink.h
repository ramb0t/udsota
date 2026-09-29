/* The image sink every coded download (DFI 0x10, 0x20, 0x30) writes through: it holds the image's first bytes until
 * the engine's first-block check passes, only then erases, and batches the rest into full-buffer writes at image
 * offsets. The rule "nothing is erased before the first block passes" lives here and nowhere else. Pure C. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_wire.h"   /* udsota_reason_t */

/* Where an image's bytes go: the engine's own synchronous first-block check, erase and write. Each returns 0 on
 * success. */
typedef struct {
    int  (*check_first)(void *ctx, const uint8_t *first, size_t len, udsota_reason_t *why);   /* as engine.check_first */
    int  (*begin)(void *ctx, uint32_t size);                               /* erase for size bytes */
    int  (*write)(void *ctx, uint32_t off, const uint8_t *d, size_t n);    /* write at image offset off */
    void  *ctx;
} udsota_zsink_t;

/* One image on its way to flash. Fill it with udsota_isink_open; the fields are read-only to the caller. */
typedef struct {
    udsota_zsink_t   sink;
    uint8_t         *buf;          /* the caller's buffer: image bytes wait here until written */
    size_t           buf_max;      /* at least UDSOTA_IMAGE_MIN_LEN */
    uint32_t         size;         /* memorySize: the image the 34 announced */
    uint32_t         produced;     /* image bytes taken so far */
    uint32_t         written;      /* image bytes handed to sink.write so far: the download's progress */
    size_t           held;         /* bytes in buf not yet written (produced - written) */
    bool             begun;        /* the first-block check passed and sink.begin succeeded */
    bool             finished;     /* udsota_isink_finish ran: no more bytes come */
    udsota_reason_t  failed;       /* the first failure (UDSOTA_DL_OK while none); every later call returns it */
} udsota_isink_t;

/* Starts an image of size bytes into sink, with buf (buf_max >= UDSOTA_IMAGE_MIN_LEN) as its buffer. UDSOTA_DL_OK, or
 * UDSOTA_DL_BAD_HEADER for a NULL argument or a short buf. */
udsota_reason_t udsota_isink_open(udsota_isink_t *k, const udsota_zsink_t *sink, uint8_t *buf, size_t buf_max,
                                  uint32_t size);
/* The free room in the buffer, for a producer that writes into it in place: *at points at it. 0 once failed. */
size_t udsota_isink_space(udsota_isink_t *k, uint8_t **at);
/* Takes n bytes the producer put at udsota_isink_space's pointer. The first min(UDSOTA_IMAGE_MIN_LEN, size) bytes go
 * to sink.check_first, then sink.begin, before anything is written; a full buffer is written, and so is the last of
 * the image once all size bytes are in. Returns UDSOTA_DL_OK, check_first's reason, UDSOTA_DL_BAD_STREAM for bytes
 * past size, or UDSOTA_DL_FLASH_ERROR when begin or write fails. */
udsota_reason_t udsota_isink_commit(udsota_isink_t *k, size_t n);
/* Copies n bytes in, through udsota_isink_space and udsota_isink_commit; the same results. */
udsota_reason_t udsota_isink_push(udsota_isink_t *k, const uint8_t *d, size_t n);
/* No more bytes come: UDSOTA_DL_BAD_HEADER when the check never had its bytes, else writes what is held. Returns the
 * first failure or UDSOTA_DL_OK. */
udsota_reason_t udsota_isink_finish(udsota_isink_t *k);
/* True once finished with exactly size bytes, all written, and no failure. */
bool udsota_isink_complete(const udsota_isink_t *k);
