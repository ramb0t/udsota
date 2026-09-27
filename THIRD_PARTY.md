# Third-party code

udsota vendors one library. Its licence travels with it and applies to those files only.

**isotp-c** by Simon Cahill and contributors (originally Li Shen), MIT licence, pinned at v1.9.3, commit `1fc19e2`, unpatched. The files are in `components/isotp/isotp-c/`, and its licence is `components/isotp/isotp-c/LICENSE`. The port shim around it (`components/isotp/isotp_port.c`, `isotp_force.h`, `include/isotp_port.h`) is udsota's own code under udsota's licence.

Two more libraries are fetched at build or install time and are not vendored: Unity (MIT) for the host tests, pinned in `CMakeLists.txt`; and, for the client, python-can (LGPL-3.0), can-isotp (MIT) and udsoncan (MIT), pinned in `client/pyproject.toml`. The client imports python-can as an unmodified library, which LGPL-3.0 permits under udsota's MIT licence. The client's `RxResilientIsoTPConnection` (`client/udsota/transport.py`) adapts udsoncan's MIT-licensed ISO-TP receive loop.
