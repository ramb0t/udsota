# Third-party code

udsota vendors two libraries. Each licence travels with its library and applies to those files only.

**isotp-c** by Simon Cahill and contributors (originally Li Shen), MIT licence, pinned at v1.9.3, commit `1fc19e2`, unpatched. The files are in `components/isotp/isotp-c/`, and its licence is `components/isotp/isotp-c/LICENSE`. The port shim around it (`components/isotp/isotp_port.c`, `isotp_force.h`, `include/isotp_port.h`) is udsota's own code under udsota's licence.

**miniz** by Rich Geldreich, RAD Game Tools and Valve Software, MIT licence, release 3.0.2 (the amalgamated `miniz.c` and `miniz.h`), unpatched. The files are in `components/udsota_inflate/miniz/`, and its licence is `components/udsota_inflate/miniz/LICENSE`. udsota builds only its inflater, tinfl, for compressed downloads, and only off target: under ESP-IDF every v6.1 target's ROM holds tinfl, so the ROM's copy is used and miniz is not compiled. The wrapper (`components/udsota_inflate/udsota_tinfl.c` and its header) is udsota's own code.

Two more libraries are fetched at build or install time and are not vendored: Unity (MIT) for the host tests, pinned in `CMakeLists.txt`; and, for the client, python-can (LGPL-3.0), can-isotp (MIT) and udsoncan (MIT), pinned in `client/pyproject.toml`. The client imports python-can as an unmodified library, which LGPL-3.0 permits under udsota's MIT licence. The client's `RxResilientIsoTPConnection` (`client/udsota/transport.py`) adapts udsoncan's MIT-licensed ISO-TP receive loop.
