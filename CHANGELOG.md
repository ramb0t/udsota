# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.2.0] - unreleased

The ESP32 port now derives the 0x27 keys from `cfg.device_id` when it is set (1 to 16 bytes), otherwise from the base MAC, so an app with its own device ID can unlock. Before, it always hashed the base MAC while F18C served the app's ID, and every key was refused (0x35, then 0x36 and 0x37). With `cfg.device_id` NULL, F18C and the keys are unchanged.

Breaking, in the ESP32 port only:
- `udsota_esp32_security()` takes the device ID: `(label, master, master_len, id, id_len)`, where `id` NULL means the base MAC.
- `udsota_esp32_device_id()` takes a `size_t *len` and returns the ID in use, not always the base MAC.
- `udsota_esp32_start()` returns `ESP_ERR_INVALID_ARG` for a set `cfg.device_id` whose length is not 1 to 16, and serves a copy of the ID as F18C rather than the app's buffer.

`tools/linux_server` is a Linux demo server for testing the client end to end. It runs the core's UDS server and ISO-TP adapter over SocketCAN or a stdin/stdout frame pipe. Its engine keeps two file-backed A/B slots, runs the real first-block rules and checks a real SHA-256 in FF01. It emulates rollback with an in-process restart after ActivateImage or 11 01, and security with `udsota_keys.c` over a host HMAC-SHA256. New client tests drive it: `client/tests/test_e2e_pipe.py` runs `cli.main` and `update` over the pipe with can-isotp's Python ISO-TP stack, and `client/tests/test_e2e_vcan.py` runs the `udsota` command on vcan0. A new CI job builds it and runs both. Three client weaknesses the pipe tests found are marked xfail:
- A lost ActivateImage answer ends `flash` with exit 1, though the server activated. `confirm` finishes the update.
- If the first 0x78 of a flash job longer than about 3 s is lost, every resend answers 0x21 until the client gives up.
- A 76 that arrives after P2 answers the resent block, and the server's answer to the repeat is then read as the next block's answer ("block 2 answered with counter 01"). A lost 0x78 on a short job can end the same way.

## [0.1.0] - unreleased

First standalone release. udsota was developed and bench-tested inside a CAN-connected product before it was extracted here.

- The portable C11 core: UDS server (sessions, SecurityAccess, RequestDownload/TransferData/TransferExit, routines, DIDs), the ISO-TP adapter over isotp-c, image rules, key derivation and boot-loop logic.
- The ESP-IDF port: an update engine on `esp_ota_*` with A/B slots and rollback, PSA-based keys, the diag task and flash worker, and the image-descriptor macro and CMake helper.
- The Python client `udsota`, driven by TOML profiles, with an example profile.
- A minimal ESP-IDF example project, host unit tests with a request-parser fuzz harness, and CI.
