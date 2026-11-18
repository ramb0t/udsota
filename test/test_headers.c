/* udsota.h and udsota_app.h, the headers an app includes, compile cleanly as C11 here and as C++20 through
 * test_headers.cpp, which includes this file: an ESP-IDF app may be written in either. Both place a header with
 * UDSOTA_IMAGE_HEADER_BUSES, the C++ one also with UDSOTA_IMAGE_HEADER; both place UDSOTA_IMAGE_DESC, and main checks the fields they set. */
#include <string.h>
#include "udsota.h"
#include "udsota_app.h"

UDSOTA_IMAGE_HEADER_BUSES(UDSOTA_BUS(2), 1, 2, 0x710, 0x718, "1.0.0", "example");
UDSOTA_IMAGE_DESC(3, 4, 0x720, 0x728);   /* the ESP-IDF app's descriptor, from udsota.h */

static bool header_is(const volatile udsota_image_header_t *h, uint16_t buses)
{
    return h->magic == UDSOTA_BARE_HDR_MAGIC && h->header_version == UDSOTA_BARE_HDR_VERSION && h->flags == 0u &&
           h->image_length == 0xFFFFFFFFu && h->crc32 == 0xFFFFFFFFu && h->update_buses == buses &&
           h->reserved[0] == 0xFFu && h->reserved[13] == 0xFFu && h->desc.magic == UDSOTA_IMG_DESC_MAGIC &&
           h->desc.desc_version == 1u && h->desc.hw_id == 1u && h->desc.partition_layout_id == 2u &&
           h->desc.diag_request_id == 0x710u && h->desc.diag_response_id == 0x718u && h->desc.reserved[0] == 0u &&
           h->desc.reserved[18] == 0u && strcmp((const char *)h->version, "1.0.0") == 0 &&
           strcmp((const char *)h->project, "example") == 0 && h->image_id[31] == 0xFFu && h->signature[0] == 0xFFu;
}

#ifndef UDSOTA_TEST_EVERY_BUS_HEADER_IS
#define UDSOTA_TEST_EVERY_BUS_HEADER_IS() true
#endif

static bool desc_is(const udsota_image_desc_t *d)
{
    return d->magic == UDSOTA_IMG_DESC_MAGIC && d->desc_version == 1u && d->hw_id == 3u &&
           d->partition_layout_id == 4u && d->diag_request_id == 0x720u && d->diag_response_id == 0x728u &&
           d->reserved[0] == 0u && d->reserved[18] == 0u;
}

int main(void)
{
    return header_is(&udsota_image_header, UDSOTA_BUS(2)) && UDSOTA_TEST_EVERY_BUS_HEADER_IS() &&
                   desc_is(&udsota_image_desc)
               ? 0
               : 1;
}
