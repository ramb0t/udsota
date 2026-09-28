/* The image sink (udsota_isink.h): hold the first bytes for the image check, then erase and write full buffers at
 * image offsets. Pure C over the caller's sink. */
#include "udsota_isink.h"
#include <string.h>
#include "udsota_image.h"   /* UDSOTA_IMAGE_MIN_LEN */

/* Records the sink's first failure and returns it. */
static udsota_reason_t fail(udsota_isink_t *k, udsota_reason_t r)
{
    if (k->failed == UDSOTA_DL_OK) {
        k->failed = r;
    }
    return k->failed;
}

/* Bytes the first-block check needs before the erase: UDSOTA_IMAGE_MIN_LEN, or the whole image when it is shorter. */
static size_t first_len(const udsota_isink_t *k)
{
    return k->size < UDSOTA_IMAGE_MIN_LEN ? (size_t)k->size : (size_t)UDSOTA_IMAGE_MIN_LEN;
}

/* Runs the first-block check on the held bytes, then the erase. */
static udsota_reason_t start(udsota_isink_t *k)
{
    udsota_reason_t why = UDSOTA_DL_OK;
    if (k->sink.check_first(k->sink.ctx, k->buf, k->held, &why) != 0) {
        return fail(k, why != UDSOTA_DL_OK ? why : UDSOTA_DL_BAD_HEADER);
    }
    if (k->sink.begin(k->sink.ctx, k->size) != 0) {
        return fail(k, UDSOTA_DL_FLASH_ERROR);
    }
    k->begun = true;
    return UDSOTA_DL_OK;
}

/* Writes the held bytes at their image offset and empties the buffer. */
static udsota_reason_t flush(udsota_isink_t *k)
{
    if (k->held == 0u) {
        return UDSOTA_DL_OK;
    }
    if (k->sink.write(k->sink.ctx, k->written, k->buf, k->held) != 0) {
        return fail(k, UDSOTA_DL_FLASH_ERROR);
    }
    k->written += (uint32_t)k->held;
    k->held = 0;
    return UDSOTA_DL_OK;
}

/* Starts an image; see udsota_isink.h. */
udsota_reason_t udsota_isink_open(udsota_isink_t *k, const udsota_zsink_t *sink, uint8_t *buf, size_t buf_max,
                                  uint32_t size)
{
    if (k == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(k, 0, sizeof *k);
    if (sink == NULL || buf == NULL || buf_max < UDSOTA_IMAGE_MIN_LEN) {
        k->failed = UDSOTA_DL_BAD_HEADER;
        return UDSOTA_DL_BAD_HEADER;
    }
    k->sink = *sink;
    k->buf = buf;
    k->buf_max = buf_max;
    k->size = size;
    return UDSOTA_DL_OK;
}

/* The buffer's free room; see udsota_isink.h. */
size_t udsota_isink_space(udsota_isink_t *k, uint8_t **at)
{
    *at = k->buf + k->held;
    return (k->failed != UDSOTA_DL_OK || k->finished) ? 0u : k->buf_max - k->held;
}

/* Takes bytes placed in the buffer, checking, erasing and writing as it fills; see udsota_isink.h. */
udsota_reason_t udsota_isink_commit(udsota_isink_t *k, size_t n)
{
    if (k->failed != UDSOTA_DL_OK) {
        return k->failed;
    }
    if (k->finished || n > k->buf_max - k->held || n > (size_t)(k->size - k->produced)) {
        return fail(k, UDSOTA_DL_BAD_STREAM);                  /* past memorySize */
    }
    k->produced += (uint32_t)n;
    k->held += n;
    if (!k->begun && k->held >= first_len(k) && start(k) != UDSOTA_DL_OK) {
        return k->failed;
    }
    if (k->begun && (k->held == k->buf_max || k->produced == k->size) && flush(k) != UDSOTA_DL_OK) {
        return k->failed;
    }
    return UDSOTA_DL_OK;
}

/* Copies bytes in; see udsota_isink.h. */
udsota_reason_t udsota_isink_push(udsota_isink_t *k, const uint8_t *d, size_t n)
{
    while (n > 0u) {
        uint8_t *at = NULL;
        size_t room = udsota_isink_space(k, &at);
        if (room == 0u) {
            return k->failed != UDSOTA_DL_OK ? k->failed : fail(k, UDSOTA_DL_BAD_STREAM);
        }
        const size_t take = n < room ? n : room;
        if (take > (size_t)(k->size - k->produced)) {
            return fail(k, UDSOTA_DL_BAD_STREAM);              /* past memorySize */
        }
        memcpy(at, d, take);
        const udsota_reason_t r = udsota_isink_commit(k, take);
        if (r != UDSOTA_DL_OK) {
            return r;
        }
        d += take;
        n -= take;
    }
    return k->failed;
}

/* The end of the input; see udsota_isink.h. */
udsota_reason_t udsota_isink_finish(udsota_isink_t *k)
{
    if (k->failed != UDSOTA_DL_OK || k->finished) {
        return k->failed;
    }
    k->finished = true;
    if (!k->begun) {
        if (k->held < first_len(k)) {
            return fail(k, UDSOTA_DL_BAD_HEADER);              /* the input ended before the check had its bytes */
        }
        if (start(k) != UDSOTA_DL_OK) {
            return k->failed;
        }
    }
    return flush(k);
}

/* True for a finished, whole, written image; see udsota_isink.h. */
bool udsota_isink_complete(const udsota_isink_t *k)
{
    return k->failed == UDSOTA_DL_OK && k->finished && k->begun && k->produced == k->size && k->held == 0u;
}
