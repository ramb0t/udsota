// test_headers.c compiled as C++20 (see there), with the other header macro placed here.
#include "udsota_image.h"

namespace every_bus {
UDSOTA_IMAGE_HEADER(1, 2, 0x710, 0x718, "1.0.0", "example");
}
#define UDSOTA_TEST_EVERY_BUS_HEADER_IS() header_is(&every_bus::udsota_image_header, 0xFFFFu)

#include "test_headers.c"
