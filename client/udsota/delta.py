"""Delta downloads (DFI 0x20 and 0x30): the patch the device rebuilds the new image from, in Espressif's
esp_delta_ota format, and the base image's identity. The patch is built with detools, the optional extra
`diff` (pip install "./client[diff]" from the repository); everything else here is plain Python."""
import hashlib
import io
import struct
import zlib

from .wire import DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE

MAGIC = 0xFCCDDE10                   # the header's first 4 bytes, little-endian (esp_delta_ota's magic)
HEADER_LEN, HASH_LEN = 64, 32        # magic, the base's validation hash, 28 reserved bytes
IMG_MAGIC, SEG_MAX = 0xE9, 16        # esp_image_header_t magic; ESP_IMAGE_MAX_SEGMENTS
DETOOLS_HINT = ('delta downloads need detools: pip install "./client[diff]" from the udsota repository (it builds '
                "from source, so it needs a C and C++ compiler)")


# The validation hash of an ESP-IDF app image: the SHA-256 appended after its checksum byte, which
# esp_partition_get_sha256() returns for the partition running it. None when the image has no appended hash, is
# malformed, or its hash does not match its bytes (the device would not be running it).
def validation_hash(image):
    if len(image) < 24 or image[0] != IMG_MAGIC or image[1] > SEG_MAX or image[23] != 1:
        return None
    off = 24
    for _ in range(image[1]):
        if off + 8 > len(image):
            return None
        off += 8 + struct.unpack_from("<I", image, off + 4)[0]
    end = (off + 1 + 15) & ~15       # the checksum byte closes a 16-byte-aligned run
    if end + HASH_LEN > len(image):
        return None
    stored = bytes(image[end:end + HASH_LEN])
    return stored if hashlib.sha256(image[:end]).digest() == stored else None


# The 64-byte header naming base_hash as the image the patch applies to.
def header(base_hash):
    return struct.pack("<I", MAGIC) + bytes(base_hash) + bytes(HEADER_LEN - 4 - HASH_LEN)


# The detools sequential patch from base to new, compressed with compression ("heatshrink" or "none"), behind the
# header. Raises ImportError without detools and ValueError for a base with no validation hash.
def make_patch(base, new, compression):
    import detools   # the optional extra: only a delta download needs it
    base_hash = validation_hash(base)
    if base_hash is None:
        raise ValueError("the base image has no valid appended SHA-256, so a device cannot be matched to it")
    out = io.BytesIO()
    # The window and lookahead esp_delta_ota's decoder is built for, named so a detools bump cannot move them.
    detools.create_patch(io.BytesIO(bytes(base)), io.BytesIO(bytes(new)), out, compression=compression,
                         heatshrink_window_sz2=8, heatshrink_lookahead_sz2=7)
    return header(base_hash) + out.getvalue()


# Raw DEFLATE (RFC 1951, no zlib header) at level 9, as the 0x10 and 0x30 downloads carry.
def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


# What a delta download with dfi carries for base -> new: 0x20 the header and a heatshrink patch, 0x30 the header
# and an uncompressed patch, all of it raw DEFLATE.
def build(base, new, dfi):
    if dfi == DL_DFI_DELTA:
        return make_patch(base, new, "heatshrink")
    if dfi == DL_DFI_DELTA_DEFLATE:
        return deflate(make_patch(base, new, "none"))
    raise ValueError("DFI 0x%02X is no delta download" % dfi)
