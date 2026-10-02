# Third-party code

udsota-lite vendors two libraries, both unmodified and each under its own MIT licence, which applies to its files only.

**iso14229** by driftregion and contributors: the single-file amalgamation `iso14229.c` and `iso14229.h`, with the isotp-c it embeds, and its licence, in `iso14229/`. They are upstream's committed files at `d018adc7015a88d7a4f164418fcb7e7927e5aa77`, upstream main of 2026-09-29, untagged. `iso14229/SHA256SUMS` holds their hashes, and CI fails if they change. The header's `UDS_LIB_VERSION` says 0.11.0, but the tag 0.11.0 is an earlier commit (8a7eb23d, whose header says 0.10.2); this one is 31 commits past it. Upstream CI passed at this commit: GitHub Actions unit tests (run 36615027352: linux, windows, arduino, esp32 on ESP-IDF 5.2), static analysis (run 36615027250, whose lint job checks the amalgamation against `src/`), and CircleCI.

**miniz** by Rich Geldreich, RAD Game Tools and Valve Software: release 3.0.2's amalgamated `miniz.c` and `miniz.h`, with its licence, in `test/miniz/`. Only the host builds use it. On the ESP32, udsota calls the ROM's copy of miniz's inflater, tinfl.

**The client** fetches its dependencies at install time: python-can (LGPL-3.0), can-isotp (MIT) and udsoncan (MIT), pinned in `client/pyproject.toml`, cryptography 42 or newer (Apache-2.0 or BSD-3-Clause), and detools (BSD-2-Clause) for its optional `diff` extra. It imports python-can as an unmodified library, which LGPL-3.0 permits under udsota's MIT licence. Its `RxResilientIsoTPConnection` (`client/udsota/transport.py`) adapts udsoncan's MIT-licensed ISO-TP receive loop.
