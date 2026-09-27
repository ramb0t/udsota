# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.1.0] - unreleased

First standalone release. udsota was developed and bench-tested inside a CAN-connected product before it was extracted here.

- The portable C11 core: UDS server (sessions, SecurityAccess, RequestDownload/TransferData/TransferExit, routines, DIDs), the ISO-TP adapter over isotp-c, image rules, key derivation and boot-loop logic.
- The ESP-IDF port: an update engine on `esp_ota_*` with A/B slots and rollback, PSA-based keys, the diag task and flash worker, and the image-descriptor macro and CMake helper.
- The Python client `udsota`, driven by TOML profiles, with an example profile.
- A minimal ESP-IDF example project, host unit tests with a request-parser fuzz harness, and CI.
