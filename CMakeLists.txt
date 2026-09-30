# Host build for the iso14229 proof of concept: udsota's portable updater (udsota_core), iso14229's amalgamation and
# the binding between them (udsota_iso14229), compiled for the host as a portability check. The firmware builds
# through examples/candash_ws43. This branch's unit tests went with udsota's server.
#   cmake -S . -B build && cmake --build build -j
cmake_minimum_required(VERSION 3.20)
project(udsota C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_subdirectory(components/iso14229)
add_subdirectory(components/udsota)
add_subdirectory(components/udsota_iso14229)
add_subdirectory(components/udsota_inflate)
add_subdirectory(components/udsota_delta)
# iso14229 picks its system from the compiler; on a host that is UNIX, whose transport is the kernel's ISO-TP.
target_compile_definitions(iso14229 PUBLIC UDS_SYS=UDS_SYS_UNIX PRIVATE _DEFAULT_SOURCE)
target_compile_options(udsota_core PRIVATE -Wall -Wextra -Werror)
target_compile_options(udsota_iso14229 PRIVATE -Wall -Wextra -Werror)
