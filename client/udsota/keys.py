"""SecurityAccess keys (udsota_keys.c's derivation): K_dev = HMAC-SHA256(master, label || device ID), and the
0x27 key is the first 16 bytes of HMAC-SHA256(K_dev, seed || level || device ID)."""
import hashlib
import hmac
import pathlib

from .errors import Refused, UpdateFailed

MASTER_LEN, SEED_LEN, KEY_LEN = 32, 16, 16


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


# One device's 0x27 keys: K_dev and the device ID it was derived with.
class DeviceKeys:
    # Derive K_dev from master, the profile's label and the device ID the server reported.
    def __init__(self, master, label, device_id):
        self.k_dev, self.device_id = derive_k_dev(master, label, device_id), bytes(device_id)

    # The key answering seed at requestSeed level.
    def key(self, seed, level):
        return seed_key(self.k_dev, seed, level, self.device_id)
