# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.2.0] - unreleased

The ESP32 port now derives the 0x27 keys from `cfg.device_id` when it is set (1 to 16 bytes), otherwise from the base MAC, so an app with its own device ID can unlock. Before, it always hashed the base MAC while F18C served the app's ID, and every key was refused (0x35, then 0x36 and 0x37). With `cfg.device_id` NULL, F18C and the keys are unchanged.

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
