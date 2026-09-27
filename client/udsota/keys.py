"""SecurityAccess keys (udsota_keys.c). The hmac mode: K_dev = HMAC-SHA256(master, label || device ID), and the
0x27 key is the first 16 bytes of HMAC-SHA256(K_dev, seed || level || device ID). The ecdsa mode: the key is a
P-256 ECDSA signature, raw r || s, over SHA-256 of "udsota-27-ecdsa-v1" || seed || level || len(ID) || ID, made
with a private key the device never holds; `keygen` makes that key pair."""
import hashlib
import hmac
import os
import pathlib

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .errors import Refused, UpdateFailed

MASTER_LEN, SEED_LEN, KEY_LEN = 32, 16, 16
SIG_TAG = b"udsota-27-ecdsa-v1"          # UDSOTA_KEYS_SIG_TAG
SIG_LEN, PUBKEY_LEN, ID_MAX = 64, 65, 16   # UDSOTA_KEYS_SIG_LEN, UDSOTA_KEYS_PUBKEY_LEN, UDSOTA_KEYS_ID_MAX
PRIVATE_NAME, HEADER_NAME = "udsota_private.pem", "udsota_pubkey.h"


# HMAC-SHA256(key, msg), 32 bytes.
def hmac_sha256(key, msg):
    return hmac.new(bytes(key), bytes(msg), hashlib.sha256).digest()


# K_dev = HMAC-SHA256(master, label || device_id), the per-device key.
def derive_k_dev(master, label, device_id):
    if len(master) != MASTER_LEN or not device_id:
        raise UpdateFailed("the master must be %d bytes and the device ID not empty" % MASTER_LEN)
    return hmac_sha256(master, bytes(label) + bytes(device_id))


# 0x27 key: first 16 bytes of HMAC-SHA256(k_dev, seed || level || device_id); level = requestSeed byte.
def seed_key(k_dev, seed, level, device_id):
    return hmac_sha256(k_dev, bytes(seed) + bytes([level]) + bytes(device_id))[:KEY_LEN]


# The master key at path (the profile's master_file, or --master): exactly 32 raw bytes. Never printed.
def load_master(path):
    try:
        raw = pathlib.Path(path).read_bytes()
    except OSError as e:
        raise Refused("cannot read the master key %s: %s" % (path, e.strerror))
    if len(raw) != MASTER_LEN:
        raise Refused("%s is %d bytes; the master key is %d raw bytes" % (path, len(raw), MASTER_LEN))
    return raw


# One device's 0x27 keys in the hmac mode: K_dev and the device ID it was derived with.
class DeviceKeys:
    # Derive K_dev from master, the profile's label and the device ID the server reported.
    def __init__(self, master, label, device_id):
        self.k_dev, self.device_id = derive_k_dev(master, label, device_id), bytes(device_id)

    # The key answering seed at requestSeed level.
    def key(self, seed, level):
        return seed_key(self.k_dev, seed, level, self.device_id)


# The ecdsa mode's signed message (udsota_keys_sig_msg): tag || seed || level || len(device_id) || device_id.
def sig_message(seed, level, device_id):
    if len(seed) != SEED_LEN or len(device_id) > ID_MAX:
        raise UpdateFailed("the seed must be %d bytes and the device ID at most %d" % (SEED_LEN, ID_MAX))
    return SIG_TAG + bytes(seed) + bytes([level, len(device_id)]) + bytes(device_id)


# The 0x27 key in the ecdsa mode: private_key's ECDSA P-256 signature over SHA-256(sig_message), as r || s.
def sign_seed(private_key, seed, level, device_id):
    r, s = decode_dss_signature(private_key.sign(sig_message(seed, level, device_id), ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# The public key as the device takes it: an uncompressed SEC1 point, 04 || X || Y (65 bytes).
def public_point(private_key):
    return private_key.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)


# The P-256 private key at path (the profile's private_key_file, or --private-key): an unencrypted PEM. Never printed.
def load_private_key(path):
    try:
        raw = pathlib.Path(path).read_bytes()
    except OSError as e:
        raise Refused("cannot read the private key %s: %s" % (path, e.strerror))
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except TypeError:
        raise Refused("%s is encrypted; the client reads an unencrypted PEM (sign in a signing service to "
                      "keep the key off this PC)" % path)
    except (ValueError, UnsupportedAlgorithm):
        raise Refused("%s is not a PEM private key" % path)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise Refused("%s is not a P-256 (secp256r1) EC key" % path)
    return key


# One device's 0x27 keys in the ecdsa mode: the private key and the device ID each signature binds.
class SigningKeys:
    # Keep the private key and the device ID the server reported.
    def __init__(self, private_key, device_id):
        if not device_id or len(device_id) > ID_MAX:
            raise UpdateFailed("the device ID must be 1 to %d bytes, not %d" % (ID_MAX, len(device_id)))
        self.private_key, self.device_id = private_key, bytes(device_id)

    # The key answering seed at requestSeed level: a fresh signature.
    def key(self, seed, level):
        return sign_seed(self.private_key, seed, level, self.device_id)


# The C header keygen writes: the public key as cfg.key_pubkey takes it.
def pubkey_header(point):
    rows = ["    " + ", ".join("0x%02x" % b for b in point[i:i + 16]) + "," for i in range(1, PUBKEY_LEN, 16)]
    return ("/* udsota 0x27 public key (ECDSA mode): P-256, uncompressed SEC1 (04 || X || Y), made by\n"
            " * `udsota keygen`. It is public and unlocks nothing, so commit it with the app. Set\n"
            " * cfg.key_pubkey = udsota_pubkey and cfg.key_pubkey_len = sizeof udsota_pubkey. Its private key,\n"
            " * %s, belongs in the signing service or HSM that answers the seeds: never in a\n"
            " * repository or a firmware image. */\n"
            "#pragma once\n#include <stdint.h>\n\n"
            "static const uint8_t udsota_pubkey[%d] = {\n    0x%02x,\n%s\n};\n"
            % (PRIVATE_NAME, PUBKEY_LEN, point[0], "\n".join(rows)))


# `keygen`: a new P-256 key pair in out_dir, as udsota_private.pem (0600) and udsota_pubkey.h. Refuses to
# overwrite either. Returns (private path, header path).
def keygen(out_dir):
    out = pathlib.Path(out_dir)
    private, header = out / PRIVATE_NAME, out / HEADER_NAME
    for p in (private, header):
        if p.exists():
            raise Refused("%s exists; keygen never overwrites a key" % p)
    try:
        out.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        with open(header, "x") as f:
            f.write(pubkey_header(public_point(key)))
    except OSError as e:
        raise Refused("cannot write the key pair in %s: %s" % (out, e.strerror))
    return private, header
