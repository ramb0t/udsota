"""`pack`: the payloads `flash` would send, written to files with a JSON manifest, for a flasher that is not this
client (an edge device that runs the UDS sequence itself). encode() is what flash sends too, so the two cannot
drift; the sequence a flasher runs with them is in the core README's "Flashing without the client"."""
import hashlib
import json

from . import __version__
from .delta import DETOOLS_HINT, build as build_delta, deflate, validation_hash
from .errors import Refused, UpdateFailed
from .image import parse_image
from .wire import DL_DFI, DL_DFI_DEFLATE, DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE

DELTA_DFIS = (DL_DFI_DELTA, DL_DFI_DELTA_DEFLATE)
DFIS = (DL_DFI, DL_DFI_DEFLATE) + DELTA_DFIS


# What the 0x36 blocks carry for image under dfi: the image (0x00), it as raw DEFLATE (0x10), or a patch from base
# (0x20, 0x30; delta.build, which needs detools). RequestDownload's memorySize is len(image) in every mode.
def encode(image, dfi, base=None):
    if dfi == DL_DFI:
        return bytes(image)
    if dfi == DL_DFI_DEFLATE:
        return deflate(image)
    return build_delta(base, image, dfi)


# `pack`: checks image against profile, writes one payload per DFI in dfis (all that the arguments allow when None)
# to out as <stem>.dfi<XX>.bin, and <stem>.manifest.json listing them in the order flash tries them: deltas smallest
# first, then 0x10, then 0x00. A delta no smaller than the 0x10 payload is still written, with smaller_than_dfi_10
# false. Returns the manifest.
def pack(profile, image, stem, out, dfis=None, base=None, log=print):
    img = parse_image(profile, image)
    if dfis is None:
        dfis = DFIS if base is not None else (DL_DFI, DL_DFI_DEFLATE)
    if base is not None:
        if not any(d in DELTA_DFIS for d in dfis):
            raise Refused("--diff-from is for DFI 0x20 and 0x30")
        if bytes(base) == bytes(image):
            raise Refused("the base is the new image itself")
        base_hash = validation_hash(base)
        if base_hash is None:
            raise Refused("the base image has no valid appended SHA-256, so a device cannot be matched to it")
    elif any(d in DELTA_DFIS for d in dfis):
        raise Refused("DFI 0x20 and 0x30 need --diff-from, the image the device runs")
    common = {"memory_size": img.size, "image_elf_sha256": img.elf_sha.hex(), "image_version": img.version,
              "hw_id": img.hw_id, "board_did": profile.board_did, "board": profile.board_names.get(img.hw_id)}
    if base is not None:
        common.update(base_elf_sha256=bytes(base[176:208]).hex(), base_validation_sha256=base_hash.hex())
    try:
        payloads = {dfi: encode(image, dfi, base) for dfi in dfis}
    except ImportError:
        raise Refused(DETOOLS_HINT) from None
    except Exception as e:                      # detools' own errors, as plan_deltas wraps them
        raise UpdateFailed("building the patch failed: %s" % e) from e
    z_len = len(payloads[DL_DFI_DEFLATE]) if DL_DFI_DEFLATE in payloads else len(deflate(image))
    order = sorted((d for d in dfis if d in DELTA_DFIS), key=lambda d: len(payloads[d]))
    order += [d for d in (DL_DFI_DEFLATE, DL_DFI) if d in dfis]
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for dfi in order:
        data, name = payloads[dfi], "%s.dfi%02x.bin" % (stem, dfi)
        (out / name).write_bytes(data)
        entry = {"dfi": dfi, "file": name, "payload_size": len(data),
                 "payload_sha256": hashlib.sha256(data).hexdigest(), **common}
        if dfi in DELTA_DFIS:
            entry["smaller_than_dfi_10"] = len(data) < z_len
        else:
            entry.pop("base_elf_sha256", None)
            entry.pop("base_validation_sha256", None)
        entries.append(entry)
        log("DFI 0x%02X: %s, %d -> %d bytes (%.0f%%)%s" % (dfi, name, img.size, len(data), 100.0 * len(data) / img.size,
            "" if entry.get("smaller_than_dfi_10", True) else ", no smaller than DFI 0x10's %d" % z_len))
    manifest = {"udsota_version": __version__, "profile": profile.name, "payloads": entries}
    name = "%s.manifest.json" % stem
    (out / name).write_text(json.dumps(manifest, indent=2) + "\n")
    log("wrote %s" % (out / name))
    return manifest
