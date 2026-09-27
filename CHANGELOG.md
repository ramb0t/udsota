# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.2.0] - unreleased

The ESP32 port now derives the 0x27 keys from `cfg.device_id` when it is set (1 to 16 bytes), otherwise from the base MAC, so an app with its own device ID can unlock. Before, it always hashed the base MAC while F18C served the app's ID, and every key was refused (0x35, then 0x36 and 0x37). With `cfg.device_id` NULL, F18C and the keys are unchanged.

Added:
- Functional addressing: `cfg.func_id` and `udsota_isotp_on_func_frame()`. A single frame on that ID is served when it is 10 01, 10 03, 3E, 22, 28 or 85, with NRCs 0x11, 0x12, 0x31, 0x7E and 0x7F suppressed; anything else, and anything during a flash job but 3E, gets no answer. The ESP32 port routes the ID, and the example listens on 0x7DF.
- 28 CommunicationControl through the new `hooks.comm_control` (without it, 28 still answers 0x11), and 85 ControlDTCSetting with the optional `hooks.dtc_setting`. A return to the default session undoes both.
- `cfg.p2_prog_ms` and `cfg.p2star_prog_ms`: P2 and P2* for the programming session, carried by its 10 02 answer and followed by its 0x78 cadence.
- The client's optional `[functional]` table: the functional ID, and `quiet_bus`, which quiets every node on the bus (10 83, 85 82, 28 83 03, then 3E 80 every 2 s) while `flash` runs and releases them afterwards.
- The ESP32 port's flash worker wakes the diag task as each job finishes, so a block's 76 leaves as soon as its write is done.

Fixed:
- ISO-TP: the STmin sent in the flow control is rounded up to a value the FC can carry (100–900 µs in 100 µs steps, else whole ms up to 127 ms), and the STmin monitor judges that value. Before, isotp-c rounded down (950 µs went out as 0) while the monitor used the raw value, so an unencodable STmin could stop a client that honoured the FC exactly.
- ISO-TP: an answer the bus keeps refusing is dropped after 1 s (`UDSOTA_ISOTP_PARK_MAX_MS`, counted as lost). Before, it stayed parked and the server's poll, S3 included, never ran, so a bus with no acknowledging node could hold an unlocked session open.
- ISO-TP: with no `can.tx_pending`, a restart waits the full 100 ms for its answer to leave, as documented. Before, it fired at the next poll and the answer to ActivateImage or 11 01 could be lost in the driver's queue.
- ESP32 port: a wait under one FreeRTOS tick no longer becomes a non-blocking poll. At `CONFIG_FREERTOS_HZ=100` the diag task spun while a flash job ran and starved the flash worker on its core, so the first erase never finished. The port warns when the tick rate is under 1000 Hz, and the example sets 1000.
- ESP32 port: `udsota_esp32_on_frame()` clamps a DLC over 8 to 8.

Breaking, for code that fills `udsota_hooks_t` or `udsota_config_t` positionally: both gained fields (`comm_control`, `dtc_setting`; `func_id`, `p2_prog_ms`, `p2star_prog_ms`). Designated initializers are unaffected.

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
