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
set(ISOTP_DIR  ${ROOT}/components/isotp)
set(ESP32_DIR  ${ROOT}/components/udsota_esp32)

# ---- Libraries: isotp (vendored isotp-c v1.9.3, unpatched, plus the per-link BS/STmin port) and
# udsota_core, the portability target. udsota_core is every core .c, compiled with nothing on its
# include path but the core's own headers and isotp, at -std=c11 -Wall -Wextra -Werror: an ESP-IDF or
# FreeRTOS include fails this build. isotp-c is upstream code, so it also gets -Wno-unused-parameter.
add_subdirectory(components/isotp)
add_subdirectory(components/udsota)
target_compile_options(isotp PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_compile_options(udsota_core PRIVATE -Wall -Wextra -Werror)

# udsota_test(<name> SOURCES <files...> [INCLUDES <dirs...>] [LIBS <libs...>])
# One Unity test executable and its CTest entry, with the ESP-IDF stubs on the include path.
# -Wno-unused-parameter: the mocks take a ctx they don't need.
function(udsota_test name)
    cmake_parse_arguments(T "" "" "SOURCES;INCLUDES;LIBS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_include_directories(${name} PRIVATE ${STUBS} ${T_INCLUDES})
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
    SOURCES  test/test_udsota_codec.c ${CORE_DIR}/udsota_codec.c
    INCLUDES ${CORE_INC})

udsota_test(test_udsota_image
    SOURCES  test/test_udsota_image.c ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_INC} ${TEST_DIR})

udsota_test(test_udsota_keys
    SOURCES  test/test_udsota_keys.c ${CORE_DIR}/udsota_keys.c
    INCLUDES ${CORE_INC})

udsota_test(test_udsota_rxwatch
    SOURCES  test/test_udsota_rxwatch.c ${CORE_DIR}/udsota_rxwatch.c
    INCLUDES ${CORE_INC})

udsota_test(test_udsota_bootloop
    SOURCES  test/test_udsota_bootloop.c ${CORE_DIR}/udsota_bootloop.c
    INCLUDES ${CORE_INC})

# ---- Server ----
udsota_test(test_udsota_server
    SOURCES  test/test_udsota_server.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV})

udsota_test(test_udsota_server_security
    SOURCES  test/test_udsota_server_security.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV})

# The download test also runs the real first-block rules behind engine.check_first.
udsota_test(test_udsota_server_download
    SOURCES  test/test_udsota_server_download.c ${SERVER_SRCS} ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_INC} ${CORE_PRIV} ${TEST_DIR})

udsota_test(test_udsota_server_routines
    SOURCES  test/test_udsota_server_routines.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV})

udsota_test(test_udsota_server_matrix
    SOURCES  test/test_udsota_server_matrix.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV})

udsota_test(test_udsota_server_hooks
    SOURCES  test/test_udsota_server_hooks.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV})

# ---- Image descriptor: one UDSOTA_ESP32_IMAGE_DESC instance per variant, as a dev image for two
# boards and as a release image. On target, udsota_esp32_image_desc() sets UDSOTA_ESP32_IMG_RELEASE
# from PROJECT_VER.
foreach(name IN ITEMS test_udsota_image_desc test_udsota_image_desc_board3 test_udsota_image_desc_release)
    udsota_test(${name}
        SOURCES  test/test_udsota_image_desc.c
        INCLUDES ${CORE_INC} ${ESP32_DIR}/include)
endforeach()
target_compile_definitions(test_udsota_image_desc         PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_board3  PRIVATE UDSOTA_TEST_HW_ID=3 UDSOTA_ESP32_IMG_RELEASE=0)
target_compile_definitions(test_udsota_image_desc_release PRIVATE UDSOTA_TEST_HW_ID=1 UDSOTA_ESP32_IMG_RELEASE=1
                                                                  UDSOTA_TEST_RELEASE=1)

# ---- ESP32 port, pure parts ----
# The ESP-IDF first-block header check in front of the core rules.
udsota_test(test_udsota_esp32_image
    SOURCES  test/test_udsota_esp32_image.c ${ESP32_DIR}/udsota_esp32_image.c ${CORE_DIR}/udsota_image.c
    INCLUDES ${CORE_INC} ${ESP32_DIR}/include ${TEST_DIR})

# The port's control block (phase, end-session, hook wrappers) with the real server.
udsota_test(test_udsota_esp32_ctl
    SOURCES  test/test_udsota_esp32_ctl.c ${ESP32_DIR}/udsota_esp32_ctl.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV} ${ESP32_DIR}/priv)

# The device ID the port serves as F18C and the K_dev and keys over it, with the real server and key derivation.
udsota_test(test_udsota_esp32_devid
    SOURCES  test/test_udsota_esp32_devid.c ${ESP32_DIR}/udsota_esp32_devid.c ${CORE_DIR}/udsota_keys.c ${SERVER_SRCS}
    INCLUDES ${CORE_INC} ${CORE_PRIV} ${ESP32_DIR}/include ${ESP32_DIR}/priv)

# ---- Host fake of a two-slot OTA engine (file-backed, POSIX), the engine behind tools/linux_server's demo
# server. Its test checks the fake and its SHA-256 against known answers.
if(UNIX)
    set(FAKE_DIR ${CORE_DIR}/test)
    udsota_test(test_fake_engine
        SOURCES  test/test_fake_engine.c ${FAKE_DIR}/fake_engine.c ${FAKE_DIR}/sha256_host.c
                 ${CORE_DIR}/udsota_image.c
        INCLUDES ${FAKE_DIR} ${CORE_INC})
    target_compile_definitions(test_fake_engine PRIVATE FAKE_OTA_TEST_DIR="${CMAKE_CURRENT_BINARY_DIR}/fake_ota_test")
endif()

# ---- Portability probes. udsota_core's include path must not reach ESP-IDF or FreeRTOS. Each probe
# compiles one platform include with exactly that path and passes only when the compiler names the
# probe's own header as missing (gcc "x.h: No such file", clang "'x.h' file not found"), so a found
# header failing on something else does not pass.
get_target_property(UDSOTA_CORE_INC udsota_core INCLUDE_DIRECTORIES)
get_target_property(ISOTP_INC isotp INTERFACE_INCLUDE_DIRECTORIES)
set(UDSOTA_PROBE_CC ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only)
foreach(dir IN LISTS UDSOTA_CORE_INC ISOTP_INC)
    if(IS_ABSOLUTE "${dir}")
        list(APPEND UDSOTA_PROBE_CC -I${dir})
    else()
        list(APPEND UDSOTA_PROBE_CC -I${CORE_DIR}/${dir})
    endif()
endforeach()
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
    udsota_test(fuzz_udsota
        SOURCES  ${CORE_DIR}/test/fuzz_udsota.c ${SERVER_SRCS}
        INCLUDES ${CORE_INC} ${CORE_PRIV})
    target_compile_options(fuzz_udsota PRIVATE ${FUZZ_SAN})
    target_link_options(fuzz_udsota PRIVATE ${FUZZ_SAN})   # trap mode must reach the link line too, or gcc wants libubsan
    target_compile_definitions(fuzz_udsota PRIVATE UDSOTA_FUZZ_UBSAN_TRAP=1)
    set_tests_properties(fuzz_udsota PROPERTIES TIMEOUT 300)
    if(UDSOTA_FUZZ_CORPUS)
        add_test(NAME fuzz_udsota_corpus COMMAND fuzz_udsota ${UDSOTA_FUZZ_CORPUS})
        set_tests_properties(fuzz_udsota_corpus PROPERTIES TIMEOUT 1800)
    endif()
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
