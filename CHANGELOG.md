# Changelog

All notable changes to udsota. Versions follow semantic versioning; the wire protocol is part of the public API.

## [0.2.0] - unreleased

The ESP32 port now derives the 0x27 keys from `cfg.device_id` when it is set (1 to 16 bytes), otherwise from the base MAC, so an app with its own device ID can unlock. Before, it always hashed the base MAC while F18C served the app's ID, and every key was refused (0x35, then 0x36 and 0x37). With `cfg.device_id` NULL, F18C and the keys are unchanged.

An ECDSA mode for SecurityAccess, after SAE paper 2022-01-0132, recommended for production. The device holds only the tester's P-256 public key, and the key in 27 02 or 27 04 is a 64-byte signature (r ‖ s) over SHA-256("udsota-27-ecdsa-v1" ‖ seed ‖ level ‖ id_len ‖ device ID). No image or flash dump then unlocks any device, where the HMAC mode's fleet master key, built into every image, unlocks all of them. The HMAC mode stays the default, and its keys and wire are unchanged.
- Core: `udsota_security_t` gains `verify` and `key_len`, appended after `ctx`. With `verify` set, the server asks it instead of computing the key, and a sendKey must be exactly 2 + `key_len` bytes. Counting, lockout, single use, expiry and NRC order are as before. `udsota_keys_sig_msg()` builds the signed message, and `udsota_keys_sig_self_test()` checks a verify against a published test key.
- ESP32 port: `cfg.key_pubkey` and `cfg.key_pubkey_len` (appended to `udsota_config_t`) turn security on in the ECDSA mode through the new `udsota_esp32_security_ecdsa()`. It verifies with PSA ECDSA under a public key imported once, after a start-up self-test. `key_pubkey` wins over `key_label`, and a `key_master` given with it is ignored with a warning.
- Client: `[security] mode = "ecdsa"` with `private_key_file` (or `--private-key`) signs each seed, and `udsota keygen --out DIR` writes `udsota_private.pem` and `udsota_pubkey.h`. The client now depends on cryptography (42 or newer).

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
- Client: no answer to ActivateImage no longer fails `flash`. The client reads F1F0: a server that answers nothing is restarting and one whose boot slot switched restarts next, so it waits for the new image and confirms it; one that has not switched never got the request, which is sent once more.
- Client: after NRC 0x21 the client listens out its backoff instead of sleeping through it, so when an earlier send's 0x78 was lost it takes the next 0x78 and waits for that request's answer. Before, a lost 0x78 on a job over about 3 s (an erase) ended the update with 0x21.
- Client: a 76 carrying the previous block's counter (a late answer to a resend) is passed over and the block's own answer awaited. Before, it ended the update with "block N answered with counter N-1".

Breaking, for code that fills `udsota_hooks_t` or `udsota_config_t` positionally: both gained fields (`comm_control`, `dtc_setting`; `func_id`, `p2_prog_ms`, `p2star_prog_ms`). Designated initializers are unaffected.

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
