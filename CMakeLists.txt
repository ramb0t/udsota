# Host build for udsota: the Unity unit tests, the UDS request-parser fuzz harness, the core portability
# probe and, on Linux, the demo server. ESP-IDF builds the components through examples/esp32, not through
# this file.
#   cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
cmake_minimum_required(VERSION 3.20)
project(udsota C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

enable_testing()

include(FetchContent)
FetchContent_Declare(unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        cbcd08fa7de711053a3deec6339ee89cad5d2697  # v2.6.1
)
FetchContent_MakeAvailable(unity)
target_compile_definitions(unity PUBLIC UNITY_INCLUDE_DOUBLE)

set(ROOT       ${CMAKE_CURRENT_LIST_DIR})
set(TEST_DIR   ${ROOT}/test)
set(STUBS      ${TEST_DIR}/stubs)
set(CORE_DIR   ${ROOT}/components/udsota)
set(CORE_INC   ${CORE_DIR}/include)
set(CORE_PRIV  ${CORE_DIR}/priv)
set(ESP32_DIR  ${ROOT}/components/udsota_esp32)
set(INFLATE_DIR ${ROOT}/components/udsota_inflate)
set(DELTA_DIR  ${ROOT}/components/udsota_delta)

# ---- Libraries: isotp (vendored isotp-c v1.9.3, unpatched, plus the per-link BS/STmin port) and
# udsota_core, the portability target. udsota_core is every core .c, compiled with nothing on its
# include path but the core's own headers and isotp, at -std=c11 -Wall -Wextra -Werror: an ESP-IDF or
# FreeRTOS include fails this build. isotp-c is upstream code, so it also gets -Wno-unused-parameter.
add_subdirectory(components/isotp)
add_subdirectory(components/udsota)
add_subdirectory(components/udsota_inflate)
add_subdirectory(components/udsota_delta)
target_compile_options(isotp PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_compile_options(udsota_core PRIVATE -Wall -Wextra -Werror)

# udsota_test(<name> SOURCES <files...> [INCLUDES <dirs...>] [LIBS <libs...>])
# One Unity test executable and its CTest entry, with the ESP-IDF stubs and the core's headers on the include path.
# -Wno-unused-parameter: the mocks take a ctx they don't need.
function(udsota_test name)
    cmake_parse_arguments(T "" "" "SOURCES;INCLUDES;LIBS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_include_directories(${name} PRIVATE ${STUBS} ${CORE_INC} ${T_INCLUDES})
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
    target_link_libraries(${name} PRIVATE unity ${T_LIBS} m)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

set(SERVER_SRCS ${CORE_DIR}/udsota_server.c ${CORE_DIR}/udsota_codec.c)

# ---- ISO-TP ----
udsota_test(test_isotp_loopback
    SOURCES test/test_isotp_loopback.c
    LIBS    isotp)

# The transport test links udsota_core itself, so it tests the objects the portability build compiled.
udsota_test(test_udsota_isotp
    SOURCES test/test_udsota_isotp.c
    LIBS    udsota_core)

# ---- Core, pure parts ----
udsota_test(test_udsota_codec
    SOURCES  test/test_udsota_codec.c ${CORE_DIR}/udsota_codec.c)

udsota_test(test_udsota_image
    SOURCES  test/test_udsota_image.c ${CORE_DIR}/udsota_image.c
    INCLUDES ${TEST_DIR})

# With the host SHA-256, for the digest of the ECDSA mode's known-answer message.
udsota_test(test_udsota_keys
    SOURCES  test/test_udsota_keys.c ${CORE_DIR}/udsota_keys.c ${CORE_DIR}/test/sha256_host.c
    INCLUDES ${CORE_DIR}/test)

udsota_test(test_udsota_rxwatch
    SOURCES  test/test_udsota_rxwatch.c ${CORE_DIR}/udsota_rxwatch.c)

udsota_test(test_udsota_bootloop
    SOURCES  test/test_udsota_bootloop.c ${CORE_DIR}/udsota_bootloop.c)

# ---- Server, over SERVER_SRCS alone. _write: 0x2E through hooks.did_write, and the access state and session epoch
# every app hook gets. _progress: udsota_progress() and hooks.progress after each step of a download.
foreach(t IN ITEMS server server_security server_routines server_matrix server_hooks server_write
                   server_functional server_progress)
    udsota_test(test_udsota_${t} SOURCES test/test_udsota_${t}.c ${SERVER_SRCS} INCLUDES ${CORE_PRIV})
endforeach()

# The download test also runs the real first-block rules behind engine.check_first.
udsota_test(test_udsota_server_download
    SOURCES  test/test_udsota_server_download.c ${SERVER_SRCS} ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_PRIV} ${TEST_DIR})

# Compressed downloads: the stream and the real tinfl behind an engine's z ops, with the core image rules. The test
# compiles its own miniz with deflate on, to make the streams it sends.
set(ZSTREAM_SRCS ${CORE_DIR}/udsota_isink.c ${CORE_DIR}/udsota_zstream.c ${INFLATE_DIR}/udsota_tinfl.c
                 ${INFLATE_DIR}/miniz/miniz.c)
set(ZSTREAM_INC ${INFLATE_DIR}/include ${INFLATE_DIR})
set(MINIZ_TEST_DEFS MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS)   # deflate on, for tdefl
udsota_test(test_udsota_server_compress
    SOURCES  test/test_udsota_server_compress.c ${SERVER_SRCS} ${ZSTREAM_SRCS} ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_PRIV} ${TEST_DIR} ${ZSTREAM_INC})
target_compile_definitions(test_udsota_server_compress PRIVATE ${MINIZ_TEST_DEFS})

# Delta downloads (DFI 0x20 and 0x30): udsota_coded over the real detools and tinfl, with the core image rules, on the
# fixtures tools/make_delta_fixtures.py generates; and the image sink on its own. miniz is built with deflate on, to
# wrap a patch in DEFLATE.
udsota_test(test_udsota_server_delta
    SOURCES  test/test_udsota_server_delta.c ${SERVER_SRCS} ${ZSTREAM_SRCS} ${CORE_DIR}/udsota_patch.c
             ${CORE_DIR}/udsota_coded.c ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_PRIV} ${TEST_DIR} ${ZSTREAM_INC} ${DELTA_DIR}/include
    LIBS     udsota_delta)
target_compile_definitions(test_udsota_server_delta PRIVATE ${MINIZ_TEST_DEFS})

# The server with compressed downloads compiled out (UDSOTA_COMPRESSION=0): its own test, and the download and progress
# tests again, which must pass unchanged.
udsota_test(test_udsota_server_nocompress
    SOURCES  test/test_udsota_server_nocompress.c ${SERVER_SRCS}
    INCLUDES ${CORE_PRIV})
udsota_test(test_udsota_server_download_nocompress
    SOURCES  test/test_udsota_server_download.c ${SERVER_SRCS} ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_PRIV} ${TEST_DIR})
udsota_test(test_udsota_server_progress_nocompress
    SOURCES  test/test_udsota_server_progress.c ${SERVER_SRCS}
    INCLUDES ${CORE_PRIV})
foreach(t IN ITEMS test_udsota_server_nocompress test_udsota_server_download_nocompress
                   test_udsota_server_progress_nocompress)
    target_compile_definitions(${t} PRIVATE UDSOTA_COMPRESSION=0)
endforeach()

# ---- Image descriptor: one UDSOTA_ESP32_IMAGE_DESC instance per variant, as a dev image for two
# boards and as a release image. On target, udsota_esp32_image_desc() sets UDSOTA_ESP32_IMG_RELEASE
# from PROJECT_VER.
foreach(name IN ITEMS test_udsota_image_desc test_udsota_image_desc_board3 test_udsota_image_desc_release)
    udsota_test(${name}
        SOURCES  test/test_udsota_image_desc.c
        INCLUDES ${ESP32_DIR}/include)
endforeach()
target_compile_definitions(test_udsota_image_desc         PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_board3  PRIVATE UDSOTA_TEST_HW_ID=3 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_release PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=1
                                                                  UDSOTA_TEST_RELEASE=1)

# ---- ESP32 port, pure parts ----
# The ESP-IDF first-block header check in front of the core rules.
udsota_test(test_udsota_esp32_image
    SOURCES  test/test_udsota_esp32_image.c ${ESP32_DIR}/udsota_esp32_image.c ${CORE_DIR}/udsota_image.c
    INCLUDES ${ESP32_DIR}/include ${TEST_DIR})

# The port's control block (phase, end-session, hook wrappers, incoming version) with the real server, and the
# real stream and tinfl for a compressed download.
udsota_test(test_udsota_esp32_ctl
    SOURCES  test/test_udsota_esp32_ctl.c ${ESP32_DIR}/udsota_esp32_ctl.c ${SERVER_SRCS} ${ZSTREAM_SRCS}
    INCLUDES ${CORE_PRIV} ${ESP32_DIR}/priv ${TEST_DIR} ${ZSTREAM_INC})
target_compile_definitions(test_udsota_esp32_ctl PRIVATE ${MINIZ_TEST_DEFS})

# The device ID the port serves as F18C and the K_dev and keys over it, with the real server and key derivation.
udsota_test(test_udsota_esp32_devid
    SOURCES  test/test_udsota_esp32_devid.c ${ESP32_DIR}/udsota_esp32_devid.c ${CORE_DIR}/udsota_keys.c ${SERVER_SRCS}
    INCLUDES ${CORE_PRIV} ${ESP32_DIR}/include ${ESP32_DIR}/priv)

# The 0x27 mode the port's config selects and the ECDSA key check over the device ID, with the real server, key
# messages and device ID, and a stand-in verify on the host SHA-256.
udsota_test(test_udsota_esp32_sa
    SOURCES  test/test_udsota_esp32_sa.c ${ESP32_DIR}/udsota_esp32_sa.c ${ESP32_DIR}/udsota_esp32_devid.c
             ${CORE_DIR}/udsota_keys.c ${CORE_DIR}/test/sha256_host.c ${SERVER_SRCS}
    INCLUDES ${CORE_PRIV} ${CORE_DIR}/test ${ESP32_DIR}/include ${ESP32_DIR}/priv)

# ---- Host fake of a two-slot OTA engine (file-backed, POSIX), the engine behind tools/linux_server's demo
# server. Its test checks the fake and its SHA-256 against known answers.
if(UNIX)
    udsota_test(test_fake_engine
        SOURCES  test/test_fake_engine.c ${CORE_DIR}/test/fake_engine.c ${CORE_DIR}/test/sha256_host.c
                 ${CORE_DIR}/udsota_image.c
        INCLUDES ${CORE_DIR}/test)
    target_compile_definitions(test_fake_engine PRIVATE FAKE_OTA_TEST_DIR="${CMAKE_CURRENT_BINARY_DIR}/fake_ota_test")
endif()

# ---- Portability probes. udsota_core's include path must not reach ESP-IDF or FreeRTOS. Each probe
# compiles one platform include with exactly that path and passes only when the compiler names the
# probe's own header as missing (gcc "x.h: No such file", clang "'x.h' file not found"), so a found
# header failing on something else does not pass.
get_target_property(UDSOTA_CORE_INC udsota_core INCLUDE_DIRECTORIES)
get_target_property(ISOTP_INC isotp INTERFACE_INCLUDE_DIRECTORIES)
set(UDSOTA_PROBE_INC ${UDSOTA_CORE_INC} ${ISOTP_INC})   # absolute: target_include_directories resolves them
list(TRANSFORM UDSOTA_PROBE_INC PREPEND -I)
set(UDSOTA_PROBE_CC ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only ${UDSOTA_PROBE_INC})
add_test(NAME udsota_core_probe_esp
         COMMAND ${UDSOTA_PROBE_CC} -DPROBE_ESP ${TEST_DIR}/fixtures/udsota_portable_probe.c)
set_tests_properties(udsota_core_probe_esp PROPERTIES
    PASS_REGULAR_EXPRESSION "error: (esp_system\\.h: No such file|'esp_system\\.h' file not found)")
add_test(NAME udsota_core_probe_freertos
         COMMAND ${UDSOTA_PROBE_CC} -DPROBE_FREERTOS ${TEST_DIR}/fixtures/udsota_portable_probe.c)
set_tests_properties(udsota_core_probe_freertos PROPERTIES
    PASS_REGULAR_EXPRESSION "error: (freertos/FreeRTOS\\.h: No such file|'freertos/FreeRTOS\\.h' file not found)")

# ---- UDS request-parser fuzz harness (on by default; -DUDSOTA_FUZZ=OFF skips it) ----
# Replays built-in seeds and their mutants (and any corpus in UDSOTA_FUZZ_CORPUS) through the pure
# server, with guard pages in place of ASan and UBSan in trap mode (no runtime library needed).
option(UDSOTA_FUZZ "Build and run the UDS request-parser fuzz harness (fuzz_udsota)" ON)
set(UDSOTA_FUZZ_CORPUS "" CACHE PATH "Extra corpus directory for the fuzz_udsota_corpus test (off when empty)")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(FUZZ_SAN -fsanitize=undefined,bounds-strict -fsanitize-trap=all)
else()
    set(FUZZ_SAN -fsanitize=undefined -fsanitize-trap=undefined)
endif()
if(UDSOTA_FUZZ)
    # A compiler without trap-mode UBSan (gcc before 12) skips the harness rather than failing the suite.
    include(CheckCSourceCompiles)
    string(REPLACE ";" " " FUZZ_SAN_FLAGS "${FUZZ_SAN}")
    set(CMAKE_REQUIRED_FLAGS "${FUZZ_SAN_FLAGS}")
    check_c_source_compiles("int main(void) { return 0; }" UDSOTA_FUZZ_SAN_OK)
    unset(CMAKE_REQUIRED_FLAGS)
    if(NOT UDSOTA_FUZZ_SAN_OK)
        message(WARNING "fuzz_udsota skipped: ${CMAKE_C_COMPILER} rejects ${FUZZ_SAN_FLAGS}")
    endif()
endif()
if(UDSOTA_FUZZ AND UDSOTA_FUZZ_SAN_OK)
    # udsota_fuzz(<name> <timeout> [SOURCES..] [INCLUDES..] [DEFS..]): fuzz_udsota.c over the server, with FUZZ_SAN
    # on the link line too, or gcc wants libubsan.
    function(udsota_fuzz name timeout)
        cmake_parse_arguments(F "" "" "SOURCES;INCLUDES;DEFS" ${ARGN})
        udsota_test(${name} SOURCES ${CORE_DIR}/test/fuzz_udsota.c ${SERVER_SRCS} ${F_SOURCES}
                            INCLUDES ${CORE_PRIV} ${F_INCLUDES})
        target_compile_options(${name} PRIVATE ${FUZZ_SAN})
        target_link_options(${name} PRIVATE ${FUZZ_SAN})
        target_compile_definitions(${name} PRIVATE UDSOTA_FUZZ_UBSAN_TRAP=1 ${F_DEFS})
        set_tests_properties(${name} PROPERTIES TIMEOUT ${timeout})
    endfunction()
    udsota_fuzz(fuzz_udsota 300)
    if(UDSOTA_FUZZ_CORPUS)
        add_test(NAME fuzz_udsota_corpus COMMAND fuzz_udsota ${UDSOTA_FUZZ_CORPUS})
        set_tests_properties(fuzz_udsota_corpus PROPERTIES TIMEOUT 1800)
    endif()
    # The same harness with did_write, routine and routine_poll set: 0x2E served, app routines answered at once,
    # after 0x78s and orphaned at the 90 s cap, each with exactly one owner.
    udsota_fuzz(fuzz_udsota_app_hooks 300 DEFS UDSOTA_FUZZ_APP_HOOKS=1)
    # The same harness with the progress hook set: done never passes total nor shrinks within a download, and the
    # hook runs at most once per call and reports every change of stage. Its PASS line matches fuzz_udsota's.
    udsota_fuzz(fuzz_udsota_progress 300 DEFS UDSOTA_FUZZ_PROGRESS=1)
    # The same harness with compressed downloads served: the z ops over udsota_zstream and the real tinfl, a
    # compressed preamble, and generated DEFLATE streams (miniz built with deflate on, to make them), with the progress
    # hook set so that its checks hold on the compressed path too.
    udsota_fuzz(fuzz_udsota_z 600 SOURCES ${ZSTREAM_SRCS} INCLUDES ${ZSTREAM_INC}
                DEFS UDSOTA_FUZZ_Z=1 UDSOTA_FUZZ_PROGRESS=1 ${MINIZ_TEST_DEFS})
    # The delta patch path on mutated patches (test/fuzz_udsota_patch.c): udsota_coded over the real detools and
    # tinfl, with AddressSanitizer where the toolchain has it, since the device parses these patches from the bus.
    set(FUZZ_PATCH_SAN ${FUZZ_SAN})
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    check_c_source_compiles("int main(void) { return 0; }" UDSOTA_FUZZ_ASAN_OK)
    unset(CMAKE_REQUIRED_FLAGS)
    if(UDSOTA_FUZZ_ASAN_OK)
        list(APPEND FUZZ_PATCH_SAN -fsanitize=address)
    else()
        message(WARNING "no AddressSanitizer runtime: fuzz_udsota_patch runs with UBSan only")
    endif()
    add_executable(fuzz_udsota_patch test/fuzz_udsota_patch.c ${CORE_DIR}/udsota_coded.c ${CORE_DIR}/udsota_patch.c
                   ${ZSTREAM_SRCS} ${DELTA_DIR}/udsota_detools.c ${DELTA_DIR}/detools/detools.c
                   ${DELTA_DIR}/detools/heatshrink/heatshrink_decoder.c)
    target_include_directories(fuzz_udsota_patch PRIVATE ${CORE_INC} ${TEST_DIR} ${ZSTREAM_INC}
                               ${DELTA_DIR}/include ${DELTA_DIR}/detools ${DELTA_DIR}/detools/heatshrink)
    target_compile_definitions(fuzz_udsota_patch PRIVATE ${MINIZ_TEST_DEFS} ${UDSOTA_DETOOLS_DEFS})
    target_compile_options(fuzz_udsota_patch PRIVATE -Wall -Wextra -Werror ${FUZZ_PATCH_SAN})
    target_link_options(fuzz_udsota_patch PRIVATE ${FUZZ_PATCH_SAN})
    add_test(NAME fuzz_udsota_patch COMMAND fuzz_udsota_patch)   # its exit code: 1 for a broken invariant, and a
    set_tests_properties(fuzz_udsota_patch PROPERTIES TIMEOUT 600)   # sanitizer's (a leak report too) fails it
endif()

# ---- tools/image_check: the ESP32 port's first-block check as a host program, for checking a real
# ESP-IDF build (CI runs it on examples/esp32's image). Built here so it always compiles.
add_executable(udsota_image_check tools/image_check.c ${ESP32_DIR}/udsota_esp32_image.c ${CORE_DIR}/udsota_image.c)
target_include_directories(udsota_image_check PRIVATE ${CORE_INC} ${ESP32_DIR}/include)
target_compile_options(udsota_image_check PRIVATE -Wall -Wextra -Werror)

# ---- tools/linux_server: the core on Linux (SocketCAN or a stdin/stdout frame pipe) with a file-backed A/B
# engine, for the client's end-to-end tests (client/tests/test_e2e_*.py). Linux only: it opens CAN_RAW sockets.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(tools/linux_server)
endif()
