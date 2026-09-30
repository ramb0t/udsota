# Third-party code

udsota vendors two libraries. Each licence travels with its library and applies to those files only.

**iso14229** by driftregion and contributors, MIT licence, upstream commit `d018adc7` (0.11.0 and 31 commits): the single-file amalgamation `iso14229.c` and `iso14229.h`, unmodified, with the isotp-c it embeds. The files and their licence are in `iso14229/`.

**miniz** by Rich Geldreich, RAD Game Tools and Valve Software, MIT licence, release 3.0.2 (the amalgamated `miniz.c` and `miniz.h`), unpatched, in `test/miniz/` with its licence. Only the host test builds it: on the ESP32, udsota calls the ROM's copy of miniz's inflater, tinfl.

The client fetches python-can (LGPL-3.0), can-isotp (MIT) and udsoncan (MIT) at install time, pinned in `client/pyproject.toml`, with detools (BSD-2-Clause) for its optional `diff` extra. It imports python-can as an unmodified library, which LGPL-3.0 permits under udsota's MIT licence. The client's `RxResilientIsoTPConnection` (`client/udsota/transport.py`) adapts udsoncan's MIT-licensed ISO-TP receive loop.
