"""`pack`: the payloads `flash` would send, written to files with a JSON manifest, for a flasher that is not this
client (an edge device that runs the UDS sequence itself). encode() is what flash sends too, so the two cannot
drift; the sequence a flasher runs with them is in the core README's "Flashing without the client"."""
import dataclasses
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
# to out as <stem>.dfi<XX>.bin, and <stem>.manifest.json listing them in the order `flash --compress-auto
# --diff-from` tries them: deltas smallest first, 0x10, then 0x00. A delta no smaller than the 0x10 payload, which
# flash would not send, is still written, flagged smaller_than_dfi_10 false and listed after 0x10: it needs less
# device memory than 0x10, so a flasher may still try it before 0x00. Never overwrites: a <stem> file already in out
# is refused. Returns the manifest.
def pack(profile, image, stem, out, dfis=None, base=None, log=print):
    img = parse_image(profile, image)
    if dfis is None:
        dfis = DFIS if base is not None else (DL_DFI, DL_DFI_DEFLATE)
    if base is not None:
        if not any(d in DELTA_DFIS for d in dfis):
            raise Refused("--diff-from is for DFI 0x20 and 0x30")
        if bytes(base) == bytes(image):
            raise Refused("the base is the new image itself")
        # Not the profile's full check: a base may predate a layout or slot-size change.
        try:
            was = parse_image(dataclasses.replace(profile, layout_id=None, slot_size=len(base)), base)
        except Refused as e:
            raise Refused("the base: %s" % e) from None
        if was.hw_id != img.hw_id:
            raise Refused("the base is for hw_id %d, the image for %d" % (was.hw_id, img.hw_id))
        base_hash = validation_hash(base)
        if base_hash is None:
            raise Refused("the base image has no valid appended SHA-256, so a device cannot be matched to it")
    elif any(d in DELTA_DFIS for d in dfis):
        raise Refused("DFI 0x20 and 0x30 need --diff-from, the image the device runs")
    try:
        taken = sorted(f.name for f in out.glob(stem + ".*") if f.name.startswith(stem + ".dfi")
                       or f.name == stem + ".manifest.json")
    except OSError:
        taken = []
    if taken:
        raise Refused("%s already holds %s: pack never overwrites, so give each image and base its own --out"
                      % (out, ", ".join(taken)))
    common = {"memory_size": img.size, "image_elf_sha256": img.elf_sha.hex(), "image_version": img.version,
              "hw_id": img.hw_id, "req_id": profile.req_id, "resp_id": profile.resp_id,
              "board_did": profile.board_did, "board": profile.board_names.get(img.hw_id)}
    payloads = {}
    for dfi in dfis:
        try:
            payloads[dfi] = encode(image, dfi, base)
        except ImportError:
            raise Refused(DETOOLS_HINT) from None
        except Exception as e:                  # detools' own errors, as plan_deltas wraps them
            raise UpdateFailed("building the DFI 0x%02X patch failed: %s" % (dfi, e)) from e
    z_len = len(payloads[DL_DFI_DEFLATE]) if DL_DFI_DEFLATE in payloads else len(deflate(image))
    deltas = sorted((d for d in dfis if d in DELTA_DFIS), key=lambda d: len(payloads[d]))
    order = [d for d in deltas if len(payloads[d]) < z_len] + [d for d in (DL_DFI_DEFLATE,) if d in dfis]
    order += [d for d in deltas if len(payloads[d]) >= z_len] + [d for d in (DL_DFI,) if d in dfis]
    entries = []
    for dfi in order:
        data = payloads[dfi]
        entry = {"dfi": dfi, "file": "%s.dfi%02x.bin" % (stem, dfi), "payload_size": len(data),
                 "payload_sha256": hashlib.sha256(data).hexdigest(), **common}
        if dfi in DELTA_DFIS:
            entry.update(base_elf_sha256=bytes(base[176:208]).hex(), base_validation_sha256=base_hash.hex(),
                         smaller_than_dfi_10=len(data) < z_len)
        entries.append(entry)
    manifest = {"udsota_version": __version__, "profile": profile.name, "payloads": entries}
    name = "%s.manifest.json" % stem
    try:
        out.mkdir(parents=True, exist_ok=True)
        for e in entries:
            (out / e["file"]).write_bytes(payloads[e["dfi"]])
        (out / name).write_text(json.dumps(manifest, indent=2) + "\n")   # last: a manifest names only whole files
    except OSError as e:
        raise Refused("cannot write in %s: %s" % (out, e.strerror)) from None
    for e in entries:
        log("DFI 0x%02X: %s, %d -> %d bytes (%.0f%%)%s" % (e["dfi"], e["file"], img.size, e["payload_size"],
            100.0 * e["payload_size"] / img.size,
            "" if e.get("smaller_than_dfi_10", True) else ", no smaller than DFI 0x10's %d" % z_len))
    log("wrote %s" % (out / name))
    return manifest
