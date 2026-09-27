# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.2.0] - unreleased

The ESP32 port now derives the 0x27 keys from `cfg.device_id` when it is set (1 to 16 bytes), otherwise from the base MAC, so an app with its own device ID can unlock. Before, it always hashed the base MAC while F18C served the app's ID, and every key was refused (0x35, then 0x36 and 0x37). With `cfg.device_id` NULL, F18C and the keys are unchanged.

An ECDSA mode for SecurityAccess, after SAE paper 2022-01-0132, recommended for production. The device holds only the tester's P-256 public key, and the key in 27 02 or 27 04 is a 64-byte signature (r ‖ s) over SHA-256("udsota-27-ecdsa-v1" ‖ seed ‖ level ‖ id_len ‖ device ID). No image or flash dump then unlocks any device, where the HMAC mode's fleet master key, built into every image, unlocks all of them. The HMAC mode stays the default, and its keys and wire are unchanged.
- Core: `udsota_security_t` gains `verify` and `key_len`, appended after `ctx`. With `verify` set, the server asks it instead of computing the key, and a sendKey must be exactly 2 + `key_len` bytes. Counting, lockout, single use, expiry and NRC order are as before. `udsota_keys_sig_msg()` builds the signed message, and `udsota_keys_sig_self_test()` checks a verify against a published test key.
- ESP32 port: `cfg.key_pubkey` and `cfg.key_pubkey_len` (appended to `udsota_config_t`) turn security on in the ECDSA mode through the new `udsota_esp32_security_ecdsa()`. It verifies with PSA ECDSA under a public key imported once, after a start-up self-test. `key_pubkey` wins over `key_label`, and a `key_master` given with it is ignored with a warning.
- Client: `[security] mode = "ecdsa"` with `private_key_file` (or `--private-key`) signs each seed, and `udsota keygen --out DIR` writes `udsota_private.pem` and `udsota_pubkey.h`. The client now depends on cryptography (42 or newer).

Breaking, in the ESP32 port only:
- `udsota_esp32_security()` takes the device ID: `(label, master, master_len, id, id_len)`, where `id` NULL means the base MAC.
- `udsota_esp32_device_id()` takes a `size_t *len` and returns the ID in use, not always the base MAC.
- `udsota_esp32_start()` returns `ESP_ERR_INVALID_ARG` for a set `cfg.device_id` whose length is not 1 to 16, and serves a copy of the ID as F18C rather than the app's buffer.

## [0.1.0] - unreleased

First standalone release. udsota was developed and bench-tested inside a CAN-connected product before it was extracted here.

- The portable C11 core: UDS server (sessions, SecurityAccess, RequestDownload/TransferData/TransferExit, routines, DIDs), the ISO-TP adapter over isotp-c, image rules, key derivation and boot-loop logic.
- The ESP-IDF port: an update engine on `esp_ota_*` with A/B slots and rollback, PSA-based keys, the diag task and flash worker, and the image-descriptor macro and CMake helper.
- The Python client `udsota`, driven by TOML profiles, with an example profile.
- A minimal ESP-IDF example project, host unit tests with a request-parser fuzz harness, and CI.
