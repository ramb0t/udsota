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

# End-to-end host test: iso14229 on its mock transport and a clock the test sets, with the binding and a RAM engine.
enable_testing()
add_library(iso14229_mock STATIC components/iso14229/iso14229/iso14229.c)
target_include_directories(iso14229_mock PUBLIC components/iso14229/iso14229)
target_compile_definitions(iso14229_mock PUBLIC UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_MOCK
                                                UDS_CUSTOM_MILLIS PRIVATE _DEFAULT_SOURCE)
add_library(udsota_iso14229_mock STATIC components/udsota_iso14229/udsota_iso14229.c)
target_include_directories(udsota_iso14229_mock PUBLIC components/udsota_iso14229/include)
target_link_libraries(udsota_iso14229_mock PUBLIC udsota_core iso14229_mock)
target_compile_options(udsota_iso14229_mock PRIVATE -Wall -Wextra -Werror)
add_executable(test_poc_e2e test/test_poc_e2e.c)
target_link_libraries(test_poc_e2e PRIVATE udsota_iso14229_mock)
target_compile_options(test_poc_e2e PRIVATE -Wall -Wextra -Werror -fsanitize=address,undefined)
target_link_options(test_poc_e2e PRIVATE -fsanitize=address,undefined)
add_test(NAME test_poc_e2e COMMAND test_poc_e2e)
