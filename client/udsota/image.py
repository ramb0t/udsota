"""The image file checks the client makes before it transmits: an ESP-IDF app image carrying the udsota
descriptor, with the identity the profile expects."""
import struct
from collections import namedtuple

from .errors import Refused
from .wire import cstr

IMG_MAGIC = 0xE9
APP_DESC_OFFSET, APP_DESC_MAGIC = 32, 0xABCD5432
DESC_OFFSET, DESC_MAGIC = 288, 0x5544534F   # udsota_image_desc_t, "UDSO"
IMAGE_MIN_LEN = 320

# Fields of an image file that the precheck and the transfer use.
ImageInfo = namedtuple("ImageInfo", "version project elf_sha hw_id layout_id size")


# Parse and check an app image against profile; raises Refused before anything is sent.
def parse_image(profile, data):
    if len(data) < IMAGE_MIN_LEN or data[0] != IMG_MAGIC:
        raise Refused("not an ESP-IDF app image (no 0xE9 header)")
    if struct.unpack_from("<I", data, APP_DESC_OFFSET)[0] != APP_DESC_MAGIC:
        raise Refused("no esp_app_desc_t at offset %d" % APP_DESC_OFFSET)
    version, project = cstr(data[48:80]), cstr(data[80:112])
    if profile.product is not None and project != profile.product:
        raise Refused("image project is %r, not %r" % (project, profile.product))
    magic, _ver, hw_id, layout, req, resp = struct.unpack_from("<IHBBHH", data, DESC_OFFSET)
    if magic != DESC_MAGIC:
        raise Refused("no udsota image descriptor (magic UDSO) at offset %d" % DESC_OFFSET)
    if (req, resp) != (profile.req_id, profile.resp_id):
        raise Refused("image answers on 0x%03X/0x%03X, not 0x%03X/0x%03X"
                      % (req, resp, profile.req_id, profile.resp_id))
    if profile.hw_ids and hw_id not in profile.hw_ids:
        raise Refused("image hw_id %d is not one of the profile's %s" % (hw_id, list(profile.hw_ids)))
    if profile.layout_id is not None and layout != profile.layout_id:
        raise Refused("image layout %d is not the profile's %d" % (layout, profile.layout_id))
    if len(data) > profile.slot_size:
        raise Refused("image is %d bytes; the slot holds %d" % (len(data), profile.slot_size))
    return ImageInfo(version, project, bytes(data[176:208]), hw_id, layout, len(data))
