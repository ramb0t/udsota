"""The image file checks the client makes before it transmits: an ESP-IDF app image carrying the udsota
descriptor, or with [image] format = "bare" any image carrying udsota's bare header, stamped, with the identity the
profile expects; and stamp(), which fills a bare header's length, image ID and CRC after a build."""
import hashlib
import struct
import zlib
from collections import namedtuple

from .errors import Refused
from .wire import cstr

IMG_MAGIC = 0xE9
APP_DESC_OFFSET, APP_DESC_MAGIC = 32, 0xABCD5432
DESC_OFFSET, DESC_MAGIC = 288, 0x5544534F   # udsota_image_desc_t, "UDSO"
IMAGE_MIN_LEN = 320
# The bare header (UDSOTA_BARE_HDR_*), at the profile's header_offset: magic "UDSB", header_version, flags,
# image_length, crc32, 16 reserved bytes, the descriptor block, then the signature.
BARE_HDR_MAGIC, BARE_HDR_VERSION, BARE_HDR_LEN = 0x55445342, 1, 224
BARE_HDR_LENGTH_OFFSET, BARE_HDR_CRC_OFFSET, BARE_HDR_DESC_OFFSET = 8, 12, 32
BARE_HDR_SIG_OFFSET, BARE_HDR_SIG_LEN = 160, 64
BARE_HDR_FLAGS_MUST = 0xFF00   # flags a reader must understand to take the image; the low byte is ignorable
# The descriptor block (UDSOTA_BARE_*), in the header: udsota_image_desc_t, then the version, project and image ID
# fields of 32 bytes each.
BARE_DESC_LEN, BARE_VERSION_OFFSET, BARE_PROJECT_OFFSET, BARE_IMAGE_ID_OFFSET = 128, 32, 64, 96
BARE_ID_OFFSET = BARE_HDR_DESC_OFFSET + BARE_IMAGE_ID_OFFSET   # the image ID's offset in the header
BARE_ID_LEN = 32
NOT_STAMPED = "the image is not stamped or was changed after stamping (`udsota stamp` stamps it)"

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


# The CRC-32 a bare header carries, as zlib computes it: over data's bytes before the crc32 field, then those after
# it, to the end of data (the image, image_length bytes).
def bare_crc(data, header_offset):
    at = header_offset + BARE_HDR_CRC_OFFSET
    return zlib.crc32(memoryview(data)[at + 4:], zlib.crc32(memoryview(data)[:at]))


# The image ID a bare header carries: the SHA-256 of data (the image) with its image_id, crc32 and signature fields
# taken as 0xFF.
def bare_image_id(data, header_offset):
    img = bytearray(data)
    for at, n in ((BARE_HDR_CRC_OFFSET, 4), (BARE_ID_OFFSET, BARE_ID_LEN), (BARE_HDR_SIG_OFFSET, BARE_HDR_SIG_LEN)):
        img[header_offset + at:header_offset + at + n] = b"\xff" * n
    return hashlib.sha256(img).digest()


# Refuse data unless it holds a bare header of this version at header_offset.
def _check_header(data, header_offset):
    if header_offset < 0:
        raise Refused("header_offset %d is negative" % header_offset)
    if len(data) < header_offset + BARE_HDR_LEN:
        raise Refused("image is %d bytes, too short for the %d-byte bare header at header_offset %d"
                      % (len(data), BARE_HDR_LEN, header_offset))
    if len(data) + (-len(data) % 4) > 0xFFFFFFFF:
        raise Refused("image is %d bytes, more than a bare header's image_length can hold" % len(data))
    magic, version, flags = struct.unpack_from("<IHH", data, header_offset)
    if magic != BARE_HDR_MAGIC:
        raise Refused("no bare image header (magic UDSB) at header_offset %d" % header_offset)
    if version != BARE_HDR_VERSION:
        raise Refused("the bare header at header_offset %d has header_version %d, not %d"
                      % (header_offset, version, BARE_HDR_VERSION))
    if flags & BARE_HDR_FLAGS_MUST:
        raise Refused("the bare header at header_offset %d has flags 0x%04X: a bit in the high byte is one a reader "
                      "must understand, and this client knows none" % (header_offset, flags))


# A bare image as a post-build step stamps it, needing no profile: data padded with 0xFF to a multiple of 4 bytes,
# then its header's image_length, image_id and crc32 written in that order. The signature is never touched, and
# stamping a stamped image returns the same bytes. Refused unless data holds a version 1 header at header_offset.
def stamp(data, header_offset):
    _check_header(data, header_offset)
    img = bytearray(data)
    img += b"\xff" * (-len(img) % 4)
    struct.pack_into("<I", img, header_offset + BARE_HDR_LENGTH_OFFSET, len(img))
    img[header_offset + BARE_ID_OFFSET:header_offset + BARE_ID_OFFSET + BARE_ID_LEN] = bare_image_id(img, header_offset)
    struct.pack_into("<I", img, header_offset + BARE_HDR_CRC_OFFSET, bare_crc(img, header_offset))
    return bytes(img)


# A bare image: the header at profile.header_offset, stamped, then its descriptor block checked as parse_image
# checks an ESP-IDF image's descriptor.
def _parse_bare(profile, data):
    off = profile.header_offset
    _check_header(data, off)
    length, crc = struct.unpack_from("<II", data, off + BARE_HDR_LENGTH_OFFSET)
    if length != len(data):
        raise Refused("the bare header's image_length is %d and the file %d bytes: %s" % (length, len(data),
                                                                                         NOT_STAMPED))
    if len(data) % 4:
        raise Refused("image is %d bytes, not a multiple of 4: %s" % (len(data), NOT_STAMPED))
    want = bare_crc(data, off)
    if crc != want:
        raise Refused("the bare header's crc32 is 0x%08X and the image's 0x%08X: %s" % (crc, want, NOT_STAMPED))
    image_id, want = bytes(data[off + BARE_ID_OFFSET:off + BARE_ID_OFFSET + BARE_ID_LEN]), bare_image_id(data, off)
    if image_id != want:
        raise Refused("the bare header's image_id %s... is not the image's %s...: %s"
                      % (image_id[:4].hex(), want[:4].hex(), NOT_STAMPED))
    blk = off + BARE_HDR_DESC_OFFSET
    magic, ver, hw_id, layout, req, resp = struct.unpack_from("<IHBBHH", data, blk)
    if magic != DESC_MAGIC:
        raise Refused("no udsota image descriptor (magic UDSO) in the bare header at header_offset %d" % off)
    if ver < 1:
        raise Refused("the image descriptor in the bare header at header_offset %d has desc_version %d, not 1 or "
                      "later" % (off, ver))
    version = cstr(data[blk + BARE_VERSION_OFFSET:blk + BARE_PROJECT_OFFSET])
    project = cstr(data[blk + BARE_PROJECT_OFFSET:blk + BARE_IMAGE_ID_OFFSET])
    if profile.product is not None and project != profile.product:
        raise Refused("image project is %r, not %r" % (project, profile.product))
    _check_identity(profile, req, resp, hw_id, layout, len(data))
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
