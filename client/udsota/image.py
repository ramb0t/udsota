"""The image file checks the client makes before it transmits: an ESP-IDF app image carrying the udsota
descriptor, or with [image] format = "bare" any image carrying the bare descriptor block, with the identity the
profile expects."""
import struct
from collections import namedtuple

from .errors import Refused
from .wire import cstr

IMG_MAGIC = 0xE9
APP_DESC_OFFSET, APP_DESC_MAGIC = 32, 0xABCD5432
DESC_OFFSET, DESC_MAGIC = 288, 0x5544534F   # udsota_image_desc_t, "UDSO"
IMAGE_MIN_LEN = 320
# The bare descriptor block (UDSOTA_BARE_*): udsota_image_desc_t, then the version, project and image ID fields of
# 32 bytes each, at the profile's desc_offset.
BARE_DESC_LEN, BARE_VERSION_OFFSET, BARE_PROJECT_OFFSET, BARE_IMAGE_ID_OFFSET = 128, 32, 64, 96

# Fields of an image file that the precheck and the transfer use. elf_sha is app_elf_sha256, or a bare image's
# image_id: what F1F3 answers once the image runs.
ImageInfo = namedtuple("ImageInfo", "version project elf_sha hw_id layout_id size")


# Parse and check an image against profile, by its [image] format; raises Refused before anything is sent.
def parse_image(profile, data):
    if profile.image_format == "bare":
        return _parse_bare(profile, data)
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
    _check_identity(profile, req, resp, hw_id, layout, len(data))
    return ImageInfo(version, project, bytes(data[176:208]), hw_id, layout, len(data))


# A bare image: the descriptor block at profile.desc_offset, checked as parse_image checks an ESP-IDF image's.
def _parse_bare(profile, data):
    off = profile.desc_offset
    if len(data) < off + BARE_DESC_LEN:
        raise Refused("image is %d bytes, too short for the %d-byte descriptor block at desc_offset %d"
                      % (len(data), BARE_DESC_LEN, off))
    magic, ver, hw_id, layout, req, resp = struct.unpack_from("<IHBBHH", data, off)
    if magic != DESC_MAGIC:
        raise Refused("no udsota image descriptor (magic UDSO) at desc_offset %d" % off)
    if ver < 1:
        raise Refused("the image descriptor at desc_offset %d has desc_version %d, not 1 or later" % (off, ver))
    version = cstr(data[off + BARE_VERSION_OFFSET:off + BARE_PROJECT_OFFSET])
    project = cstr(data[off + BARE_PROJECT_OFFSET:off + BARE_IMAGE_ID_OFFSET])
    if profile.product is not None and project != profile.product:
        raise Refused("image project is %r, not %r" % (project, profile.product))
    _check_identity(profile, req, resp, hw_id, layout, len(data))
    image_id = bytes(data[off + BARE_IMAGE_ID_OFFSET:off + BARE_DESC_LEN])
    return ImageInfo(version, project, image_id, hw_id, layout, len(data))


# The descriptor's CAN IDs, hw_id and layout, and the image's size, against the profile.
def _check_identity(profile, req, resp, hw_id, layout, size):
    if (req, resp) != (profile.req_id, profile.resp_id):
        raise Refused("image answers on 0x%03X/0x%03X, not 0x%03X/0x%03X"
                      % (req, resp, profile.req_id, profile.resp_id))
    if profile.hw_ids and hw_id not in profile.hw_ids:
        raise Refused("image hw_id %d is not one of the profile's %s" % (hw_id, list(profile.hw_ids)))
    if profile.layout_id is not None and layout != profile.layout_id:
        raise Refused("image layout %d is not the profile's %d" % (layout, profile.layout_id))
    if size > profile.slot_size:
        raise Refused("image is %d bytes; the slot holds %d" % (size, profile.slot_size))
