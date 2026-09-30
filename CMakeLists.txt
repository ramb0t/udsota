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

# -DUDSOTA_SANITIZE=ON builds every host target, Unity and the fuzz harnesses included, with AddressSanitizer and
# UBSan, and the first report ends the program. CI's sanitize job runs the whole suite so, with clang.
option(UDSOTA_SANITIZE "Build every host target with ASan and UBSan, stopping at the first report" OFF)
if(UDSOTA_SANITIZE)
    set(UDSOTA_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_compile_options(${UDSOTA_SAN_FLAGS})
    add_link_options(${UDSOTA_SAN_FLAGS})
endif()

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
include(${ROOT}/components/udsota/sources.cmake)         # UDSOTA_*: the core's files and include dirs
include(${ROOT}/components/udsota_esp32/sources.cmake)   # UDSOTA_ESP32_*: the port's
set(CORE_INC   ${UDSOTA_INCLUDE_DIRS})
set(CORE_TEST  ${ROOT}/components/udsota/test)
set(INFLATE_DIR ${ROOT}/components/udsota_inflate)
set(DELTA_DIR  ${ROOT}/components/udsota_delta)

# sources.cmake is what each component compiles, so a .c file it doesn't list would go unbuilt without a word, and
# one listed under another directory's list would reach the wrong build (a server/ file under the update list escapes
# the core-only build below): stop unless the component's .c files are exactly its whole list, and each directory's
# exactly that directory's list.
function(udsota_check_srcs dir listed)
    file(GLOB found CONFIGURE_DEPENDS ${dir}/*.c ${dir}/server/*.c ${dir}/update/*.c ${dir}/bootloop/*.c)
    list(SORT found)
    list(SORT listed)
    if(NOT found STREQUAL listed)
        message(FATAL_ERROR "${dir}/sources.cmake does not list exactly the .c files there:\n"
                            "  on disk: ${found}\n  listed:  ${listed}")
    endif()
    foreach(pair IN LISTS ARGN)                      # <subdir>=<list variable>
        string(REPLACE "=" ";" pair "${pair}")
        list(GET pair 0 sub)
        list(GET pair 1 var)
        file(GLOB found CONFIGURE_DEPENDS ${dir}/${sub}/*.c)
        set(own ${${var}})
        list(SORT found)
        list(SORT own)
        if(NOT found STREQUAL own)
            message(FATAL_ERROR "${dir}/sources.cmake's ${var} is not exactly the .c files in ${sub}/:\n"
                                "  on disk: ${found}\n  listed:  ${own}")
        endif()
    endforeach()
endfunction()
udsota_check_srcs(${ROOT}/components/udsota "${UDSOTA_SRCS}"
    server=UDSOTA_SERVER_SRCS update=UDSOTA_UPDATE_SRCS bootloop=UDSOTA_BOOTLOOP_SRCS)
# The port's update/ holds both halves of CONFIG_UDSOTA_ESP32_UPDATER: the updater and its no-updater stub.
set(UDSOTA_ESP32_UPDATE_DIR_SRCS ${UDSOTA_ESP32_UPDATE_SRCS} ${UDSOTA_ESP32_NOUPDATER_SRCS})
udsota_check_srcs(${ROOT}/components/udsota_esp32 "${UDSOTA_ESP32_SRCS};${UDSOTA_ESP32_NOUPDATER_SRCS}"
    server=UDSOTA_ESP32_SERVER_SRCS update=UDSOTA_ESP32_UPDATE_DIR_SRCS bootloop=UDSOTA_ESP32_BOOTLOOP_SRCS)
# ESP-IDF stops on an include dir that doesn't exist and a plain CMake build doesn't notice one: stop here too.
foreach(d IN LISTS UDSOTA_INCLUDE_DIRS UDSOTA_PRIV_INCLUDE_DIRS UDSOTA_ESP32_INCLUDE_DIRS UDSOTA_ESP32_PRIV_INCLUDE_DIRS)
    if(NOT IS_DIRECTORY "${d}")
        message(FATAL_ERROR "sources.cmake names an include dir that doesn't exist: ${d}")
    endif()
endforeach()

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

set(SERVER_SRCS ${UDSOTA_SERVICES_SRCS})

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
    SOURCES  test/test_udsota_codec.c ${UDSOTA_CODEC_SRCS})

udsota_test(test_udsota_image
    SOURCES  test/test_udsota_image.c ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${TEST_DIR})

# With the host SHA-256, for the digest of the ECDSA mode's known-answer message.
udsota_test(test_udsota_keys
    SOURCES  test/test_udsota_keys.c ${UDSOTA_KEYS_SRCS} ${CORE_TEST}/sha256_host.c
    INCLUDES ${CORE_TEST})

udsota_test(test_udsota_rxwatch
    SOURCES  test/test_udsota_rxwatch.c ${UDSOTA_RXWATCH_SRCS})

udsota_test(test_udsota_bootloop
    SOURCES  test/test_udsota_bootloop.c ${UDSOTA_BOOTLOOP_SRCS})

# ---- Server, over SERVER_SRCS alone. _write: 0x2E through hooks.did_write, and the access state and session epoch
# every app hook gets. _progress: udsota_progress() and hooks.progress after each step of a download. _no_engine: the
# server with no updater registered (udsota_init with a NULL engine). _dtc: 0x19 and 0x14 through the DTC hooks.
foreach(t IN ITEMS server server_security server_routines server_matrix server_hooks server_write
                   server_functional server_progress server_no_engine server_dtc)
    udsota_test(test_udsota_${t} SOURCES test/test_udsota_${t}.c ${SERVER_SRCS})
endforeach()
target_include_directories(test_udsota_server_no_engine PRIVATE ${TEST_DIR}/core_only)   # the rows it shares

# The download test also runs the real first-block rules behind engine.check_first.
udsota_test(test_udsota_server_download
    SOURCES  test/test_udsota_server_download.c ${SERVER_SRCS} ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${TEST_DIR})

# Compressed downloads: the stream and the real tinfl behind an engine's z ops, with the core image rules. The test
# compiles its own miniz with deflate on, to make the streams it sends.
set(ZSTREAM_SRCS ${UDSOTA_ZSTREAM_SRCS} ${INFLATE_DIR}/udsota_tinfl.c ${INFLATE_DIR}/miniz/miniz.c)
set(ZSTREAM_INC ${INFLATE_DIR}/include ${INFLATE_DIR})
set(MINIZ_TEST_DEFS MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS)   # deflate on, for tdefl
udsota_test(test_udsota_server_compress
    SOURCES  test/test_udsota_server_compress.c ${SERVER_SRCS} ${ZSTREAM_SRCS} ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${TEST_DIR} ${ZSTREAM_INC})
target_compile_definitions(test_udsota_server_compress PRIVATE ${MINIZ_TEST_DEFS})

# Delta downloads (DFI 0x20 and 0x30): udsota_coded over the real detools and tinfl, with the core image rules, on the
# fixtures tools/make_delta_fixtures.py generates; and the image sink on its own. miniz is built with deflate on, to
# wrap a patch in DEFLATE.
udsota_test(test_udsota_server_delta
    SOURCES  test/test_udsota_server_delta.c ${SERVER_SRCS} ${ZSTREAM_SRCS} ${UDSOTA_CODED_SRCS}
             ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${TEST_DIR} ${ZSTREAM_INC} ${DELTA_DIR}/include
    LIBS     udsota_delta)
target_compile_definitions(test_udsota_server_delta PRIVATE ${MINIZ_TEST_DEFS})

# The server with compressed downloads compiled out (UDSOTA_COMPRESSION=0): its own test, and the download and progress
# tests again, which must pass unchanged.
udsota_test(test_udsota_server_nocompress
    SOURCES  test/test_udsota_server_nocompress.c ${SERVER_SRCS})
udsota_test(test_udsota_server_download_nocompress
    SOURCES  test/test_udsota_server_download.c ${SERVER_SRCS} ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${TEST_DIR})
udsota_test(test_udsota_server_progress_nocompress
    SOURCES  test/test_udsota_server_progress.c ${SERVER_SRCS})
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
        INCLUDES ${UDSOTA_ESP32_INCLUDE_DIRS})
endforeach()
target_compile_definitions(test_udsota_image_desc         PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_board3  PRIVATE UDSOTA_TEST_HW_ID=3 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_release PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=1
                                                                  UDSOTA_TEST_RELEASE=1)

# ---- ESP32 port, pure parts ----
# The ESP-IDF first-block header check in front of the core rules.
udsota_test(test_udsota_esp32_image
    SOURCES  test/test_udsota_esp32_image.c ${UDSOTA_ESP32_IMAGE_SRCS} ${UDSOTA_IMAGE_SRCS}
    INCLUDES ${UDSOTA_ESP32_INCLUDE_DIRS} ${TEST_DIR})

# The port's control block (phase, end-session, hook wrappers, incoming version) with the real server, and the
# real stream and tinfl for a compressed download.
udsota_test(test_udsota_esp32_ctl
    SOURCES  test/test_udsota_esp32_ctl.c ${UDSOTA_ESP32_CTL_SRCS} ${SERVER_SRCS} ${ZSTREAM_SRCS}
    INCLUDES ${UDSOTA_ESP32_PRIV_INCLUDE_DIRS} ${TEST_DIR} ${ZSTREAM_INC})
target_compile_definitions(test_udsota_esp32_ctl PRIVATE ${MINIZ_TEST_DEFS})

# The device ID the port serves as F18C and the K_dev and keys over it, with the real server and key derivation.
udsota_test(test_udsota_esp32_devid
    SOURCES  test/test_udsota_esp32_devid.c ${UDSOTA_ESP32_DEVID_SRCS} ${UDSOTA_KEYS_SRCS} ${SERVER_SRCS}
    INCLUDES ${UDSOTA_ESP32_INCLUDE_DIRS} ${UDSOTA_ESP32_PRIV_INCLUDE_DIRS})

# The 0x27 mode the port's config selects and the ECDSA key check over the device ID, with the real server, key
# messages and device ID, and a stand-in verify on the host SHA-256.
udsota_test(test_udsota_esp32_sa
    SOURCES  test/test_udsota_esp32_sa.c ${UDSOTA_ESP32_SA_SRCS} ${UDSOTA_ESP32_DEVID_SRCS}
             ${UDSOTA_KEYS_SRCS} ${CORE_TEST}/sha256_host.c ${SERVER_SRCS}
    INCLUDES ${CORE_TEST} ${UDSOTA_ESP32_INCLUDE_DIRS} ${UDSOTA_ESP32_PRIV_INCLUDE_DIRS})

# ---- Host fake of a two-slot OTA engine (file-backed, POSIX), the engine behind tools/linux_server's demo
# server. Its test checks the fake and its SHA-256 against known answers.
if(UNIX)
    udsota_test(test_fake_engine
        SOURCES  test/test_fake_engine.c ${CORE_TEST}/fake_engine.c ${CORE_TEST}/sha256_host.c
                 ${UDSOTA_IMAGE_SRCS}
        INCLUDES ${CORE_TEST})
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

# ---- The server without the updater. udsota_server_only is server/ alone (UDSOTA_SERVER_SRCS), compiled with
# server/include, isotp and a build-dir copy of udsota_update_state.h (the one updater header the server context may
# name) on its include path: a core file that includes any other updater header through the include path fails to
# compile, and tools/check_seam.sh catches one included by a relative path. An OBJECT library,
# not an archive, so every object reaches the link: test_udsota_core_only links it alone, and a core call into the
# updater fails that link. It runs the no-updater rows through udsota_core_init, a test-local service and the
# ISO-TP adapter.
set(UDSOTA_UPDATE_STATE_H ${ROOT}/components/udsota/update/include/udsota_update_state.h)
set(CORE_ONLY_INC ${CMAKE_CURRENT_BINARY_DIR}/core_only_include)
file(REMOVE_RECURSE ${CORE_ONLY_INC})
configure_file(${UDSOTA_UPDATE_STATE_H} ${CORE_ONLY_INC}/udsota_update_state.h COPYONLY)   # the one updater header allowed
add_library(udsota_server_only OBJECT ${UDSOTA_SERVER_SRCS})
target_include_directories(udsota_server_only PUBLIC ${UDSOTA_SERVER_INCLUDE_DIRS} ${CORE_ONLY_INC})
target_link_libraries(udsota_server_only PUBLIC isotp)
target_compile_options(udsota_server_only PRIVATE -Wall -Wextra -Werror)
add_executable(test_udsota_core_only test/core_only/test_udsota_core_only.c)
target_include_directories(test_udsota_core_only PRIVATE ${TEST_DIR}/core_only)
target_compile_options(test_udsota_core_only PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(test_udsota_core_only PRIVATE udsota_server_only unity m)
add_test(NAME test_udsota_core_only COMMAND test_udsota_core_only)

# Its probes, each a known positive: the core-only include path can't reach an updater header, yet the state header
# compiles alone on it; and server/'s objects don't define an updater function (udsota_pack_result), so a program
# that calls one fails to link against them.
set(CORE_ONLY_PROBE_INC ${UDSOTA_SERVER_INCLUDE_DIRS} ${CORE_ONLY_INC} ${ISOTP_INC})
list(TRANSFORM CORE_ONLY_PROBE_INC PREPEND -I)
add_test(NAME udsota_core_only_probe_updater
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only ${CORE_ONLY_PROBE_INC} -DPROBE_UPDATER
                 ${TEST_DIR}/fixtures/udsota_portable_probe.c)
set_tests_properties(udsota_core_only_probe_updater PROPERTIES
    PASS_REGULAR_EXPRESSION "error: (udsota_image\\.h: No such file|'udsota_image\\.h' file not found)")
add_test(NAME udsota_core_only_probe_state
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only -Wall -Wextra -Werror -I${CORE_ONLY_INC} -DPROBE_STATE
                 ${TEST_DIR}/fixtures/udsota_portable_probe.c)
add_test(NAME udsota_core_only_link_updater
         COMMAND ${CMAKE_C_COMPILER} ${UDSOTA_SAN_FLAGS} -DPROBE_LINK_UPDATER
                 ${TEST_DIR}/fixtures/udsota_portable_probe.c
                 $<TARGET_OBJECTS:udsota_server_only> $<TARGET_FILE:isotp>
                 -o ${CMAKE_CURRENT_BINARY_DIR}/udsota_core_only_link_updater
         COMMAND_EXPAND_LISTS)
set_tests_properties(udsota_core_only_link_updater PROPERTIES
    PASS_REGULAR_EXPRESSION   # GNU ld and gold; lld and mold; ld64, which names the symbol on the next line
    "undefined reference to .?udsota_pack_result;undefined symbol: .?udsota_pack_result;Undefined symbols[^\n]*\n[^\n]*\"_udsota_pack_result\"")

# The seam's other direction: no server/ source, the port's included, touches the updater's member of the context or
# names an update/include header but udsota_update_state.h, by any path. The port's server/ still takes the updater
# through the umbrella udsota.h; the core's can't, since the core-only build has no include/ on its path.
add_test(NAME udsota_seam_grep COMMAND sh ${ROOT}/tools/check_seam.sh)
set_tests_properties(udsota_seam_grep PROPERTIES PASS_REGULAR_EXPRESSION "check_seam: PASS")

# ---- UDS request-parser fuzz harness (on by default; -DUDSOTA_FUZZ=OFF skips it) ----
# Replays built-in seeds and their mutants (and any corpus in UDSOTA_FUZZ_CORPUS) through the pure
# server, with guard pages in place of ASan and UBSan in trap mode (no runtime library needed). -DUDSOTA_SANITIZE=ON
# adds ASan on top; the harness keeps SIGSEGV from it (handle_segv=0), so the guard pages still fault as before.
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
    # udsota_fuzz(<name> <timeout> [SERVER..] [SOURCES..] [INCLUDES..] [DEFS..]): fuzz_udsota.c over the server
    # (SERVER_SRCS unless SERVER names another list), with FUZZ_SAN on the link line too, or gcc wants libubsan.
    function(udsota_fuzz name timeout)
        cmake_parse_arguments(F "" "DIGEST" "SERVER;SOURCES;INCLUDES;DEFS" ${ARGN})
        if(NOT F_SERVER)
            set(F_SERVER ${SERVER_SRCS})
        endif()
        udsota_test(${name} SOURCES ${CORE_TEST}/fuzz_udsota.c ${F_SERVER} ${F_SOURCES}
                            INCLUDES ${F_INCLUDES})
        target_compile_options(${name} PRIVATE ${FUZZ_SAN})
        target_link_options(${name} PRIVATE ${FUZZ_SAN})
        target_compile_definitions(${name} PRIVATE UDSOTA_FUZZ_UBSAN_TRAP=1 ${F_DEFS})
        set_tests_properties(${name} PROPERTIES TIMEOUT ${timeout})
        # DIGEST pins the answers while the server/updater seam lands (docs/plans): a changed answer fails the
        # test even where every count on the PASS line is the same. Update the pin only for an intended change.
        if(F_DIGEST)
            set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "fuzz_udsota: PASS .* digest=${F_DIGEST}")
        endif()
    endfunction()
    udsota_fuzz(fuzz_udsota 300 DIGEST 167b0bb1e30d7960)
    if(UDSOTA_FUZZ_CORPUS)
        add_test(NAME fuzz_udsota_corpus COMMAND fuzz_udsota ${UDSOTA_FUZZ_CORPUS})
        set_tests_properties(fuzz_udsota_corpus PROPERTIES TIMEOUT 1800)
    endif()
    # The same harness with did_write, routine and routine_poll set: 0x2E served, app routines answered at once,
    # after 0x78s and orphaned at the 90 s cap, each with exactly one owner.
    udsota_fuzz(fuzz_udsota_app_hooks 300 DIGEST f89754fc3ef5118b DEFS UDSOTA_FUZZ_APP_HOOKS=1)
    # The same harness with the progress hook set: done never passes total nor shrinks within a download, and the
    # hook runs at most once per call and reports every change of stage. Its PASS line matches fuzz_udsota's.
    udsota_fuzz(fuzz_udsota_progress 300 DIGEST 167b0bb1e30d7960 DEFS UDSOTA_FUZZ_PROGRESS=1)
    # The same harness with compressed downloads served: the z ops over udsota_zstream and the real tinfl, a
    # compressed preamble, and generated DEFLATE streams (miniz built with deflate on, to make them), with the progress
    # hook set so that its checks hold on the compressed path too.
    udsota_fuzz(fuzz_udsota_z 600 DIGEST 744cebe8b3e84bd0 SOURCES ${ZSTREAM_SRCS} INCLUDES ${ZSTREAM_INC}
                DEFS UDSOTA_FUZZ_Z=1 UDSOTA_FUZZ_PROGRESS=1 ${MINIZ_TEST_DEFS})
    # The same harness with no update service (udsota_core_init, which is udsota_init given a NULL engine), from the
    # five states a download isn't needed for: 34, 36 and 37 get only 0x11 (0x21 while an app routine runs), and the
    # app hooks give 0x31 its positive answers. Built from the core list, so the updater isn't even linked.
    udsota_fuzz(fuzz_udsota_no_update 300 DIGEST 9f7c2932c2332507 SERVER ${UDSOTA_SERVER_CORE_SRCS}
                DEFS UDSOTA_FUZZ_NO_UPDATE=1 UDSOTA_FUZZ_APP_HOOKS=1)
    # The same harness with the DTC hooks set over a 90-DTC table: 19 01, 02, 06 and 0A and 14 served, lists past the
    # response buffer (0x14), and every status sent a subset of the availability mask.
    udsota_fuzz(fuzz_udsota_dtc 300 DIGEST e05a7138b28a2a22 DEFS UDSOTA_FUZZ_DTC=1)
    # The ISO-TP frame path (components/udsota/test/fuzz_udsota_frames.c): raw CAN frames through udsota_isotp.c, the
    # receive mirror and isotp-c into the server and updater, with fake_engine's file-backed slots behind them. isotp-c
    # is compiled in, force-including isotp_force.h as components/isotp does, so FUZZ_SAN covers the whole path.
    set(ISOTP_C ${ROOT}/components/isotp/isotp-c/isotp.c)
    set(FRAMES_SRCS ${UDSOTA_SERVER_SRCS} ${SERVER_SRCS} ${UDSOTA_IMAGE_SRCS} ${CORE_TEST}/fake_engine.c
                    ${CORE_TEST}/sha256_host.c ${ISOTP_C} ${ROOT}/components/isotp/isotp_port.c)
    list(REMOVE_DUPLICATES FRAMES_SRCS)
    set_source_files_properties(${ISOTP_C} PROPERTIES
                                COMPILE_OPTIONS "-include;${ROOT}/components/isotp/isotp_force.h")
    udsota_test(fuzz_udsota_frames SOURCES ${CORE_TEST}/fuzz_udsota_frames.c ${FRAMES_SRCS}
                INCLUDES ${CORE_TEST} $<TARGET_PROPERTY:isotp,INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(fuzz_udsota_frames PRIVATE UDSOTA_FUZZ_UBSAN_TRAP=1
                               $<TARGET_PROPERTY:isotp,INTERFACE_COMPILE_DEFINITIONS>
                               FUZZ_FRAMES_OTA_DIR="${CMAKE_CURRENT_BINARY_DIR}/fuzz_frames_ota")
    target_compile_options(fuzz_udsota_frames PRIVATE ${FUZZ_SAN})
    target_link_options(fuzz_udsota_frames PRIVATE ${FUZZ_SAN})
    set_tests_properties(fuzz_udsota_frames PROPERTIES TIMEOUT 120
                         PASS_REGULAR_EXPRESSION "fuzz_udsota_frames: PASS .* digest=bae692df8eb90a5c")
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
    add_executable(fuzz_udsota_patch test/fuzz_udsota_patch.c ${UDSOTA_CODED_SRCS}
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
add_executable(udsota_image_check tools/image_check.c ${UDSOTA_ESP32_IMAGE_SRCS} ${UDSOTA_IMAGE_SRCS})
target_include_directories(udsota_image_check PRIVATE ${CORE_INC} ${UDSOTA_ESP32_INCLUDE_DIRS})
target_compile_options(udsota_image_check PRIVATE -Wall -Wextra -Werror)

# ---- tools/linux_server: the core on Linux (SocketCAN or a stdin/stdout frame pipe) with a file-backed A/B
# engine, for the client's end-to-end tests (client/tests/test_e2e_*.py). Linux only: it opens CAN_RAW sockets.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(tools/linux_server)
endif()
