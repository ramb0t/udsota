/* One coded download (udsota_coded.h): the stages for its DFI, chained. Pure C. */
#include "udsota_coded.h"
#include <string.h>

/* Opens the stages for dfi; see udsota_coded.h. */
udsota_reason_t udsota_coded_open(udsota_coded_t *c, uint8_t dfi, uint32_t size, const udsota_coded_cfg_t *cfg)
{
    if (c == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    memset(c, 0, sizeof *c);
    if (cfg == NULL) {
        return UDSOTA_DL_BAD_HEADER;
    }
    udsota_reason_t r = UDSOTA_DL_BAD_HEADER;
    if (dfi == UDSOTA_DL_DFI_DEFLATE) {
        r = udsota_zstream_open(&c->zs, cfg->inflate, &cfg->sink, cfg->out, cfg->out_max, size);
    } else if (dfi == UDSOTA_DL_DFI_DELTA || dfi == UDSOTA_DL_DFI_DELTA_DEFLATE) {
        r = udsota_isink_open(&c->image, &cfg->sink, cfg->out, cfg->out_max, size);
        if (r == UDSOTA_DL_OK) {
            r = udsota_pstream_open(&c->ps, cfg->patch, cfg->base, &c->image);
        }
        if (r == UDSOTA_DL_OK && dfi == UDSOTA_DL_DFI_DELTA_DEFLATE) {
            const udsota_push_t next = {.push = udsota_pstream_push_cb, .ctx = &c->ps};
            r = udsota_zstream_open_push(&c->zs, cfg->inflate, &next, cfg->zbuf, cfg->zbuf_max);
        }
    }
    if (r != UDSOTA_DL_OK) {
        udsota_zstream_close(&c->zs);
        udsota_pstream_close(&c->ps);
        return r;
    }
    c->dfi = dfi;
    return UDSOTA_DL_OK;
}

/* One payload into the outermost stage; see udsota_coded.h. */
udsota_reason_t udsota_coded_feed(udsota_coded_t *c, const uint8_t *d, size_t n)
{
    switch (c->dfi) {
    case UDSOTA_DL_DFI_DEFLATE:
    case UDSOTA_DL_DFI_DELTA_DEFLATE:
        return udsota_zstream_feed(&c->zs, d, n);
    case UDSOTA_DL_DFI_DELTA:
        return udsota_pstream_push(&c->ps, d, n);
    default:
        return UDSOTA_DL_BAD_STREAM;
    }
}

/* Every stage's 37 check; see udsota_coded.h. */
udsota_reason_t udsota_coded_end(udsota_coded_t *c)
{
    udsota_reason_t r = UDSOTA_DL_BAD_STREAM;
    switch (c->dfi) {
    case UDSOTA_DL_DFI_DEFLATE:
        r = udsota_zstream_end(&c->zs);
        break;
    case UDSOTA_DL_DFI_DELTA:
        r = udsota_pstream_end(&c->ps);
        break;
    case UDSOTA_DL_DFI_DELTA_DEFLATE:
        r = udsota_zstream_end(&c->zs);             /* the DEFLATE stream ended, with nothing after it */
        if (r == UDSOTA_DL_OK) {
            r = udsota_pstream_end(&c->ps);         /* then the patch, and the image */
        }
        break;
    default:
        break;
    }
    udsota_coded_close(c);
    return r;
}

/* Frees the decoders once; see udsota_coded.h. */
void udsota_coded_close(udsota_coded_t *c)
{
    udsota_zstream_close(&c->zs);
    udsota_pstream_close(&c->ps);
    c->dfi = 0u;
}

/* The image's written count; see udsota_coded.h. */
uint32_t udsota_coded_written(const udsota_coded_t *c)
{
    return c->dfi == UDSOTA_DL_DFI_DEFLATE ? c->zs.image.written : c->image.written;
}
