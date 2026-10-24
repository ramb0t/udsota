# udsota. Under ESP-IDF this directory is the component: udsota.c and the vendored iso14229, and detools when the build
# defines UDSOTA_DELTA=1. On a host it builds the host test and udsota_lite_server:
# cmake -S . -B build && cmake --build build && ctest --test-dir build

# Delta downloads: detools as they use it, uncompressed sequential patches only and no file I/O. udsota.c reads detools.h
# under the same defines.
set(UDSOTA_DELTA_DEFS UDSOTA_DELTA=1 DETOOLS_CONFIG_FILE_IO=0 DETOOLS_CONFIG_COMPRESSION_NONE=1
                      DETOOLS_CONFIG_COMPRESSION_LZMA=0 DETOOLS_CONFIG_COMPRESSION_CRLE=0
                      DETOOLS_CONFIG_COMPRESSION_HEATSHRINK=0)

if(ESP_PLATFORM)
    # A clean [v]X.Y.Z PROJECT_VER is a release; UDSOTA_IMAGE_DESC stamps the flag into the image.
    idf_build_get_property(udsota_ver PROJECT_VER)
    if(udsota_ver MATCHES "^v?[0-9]+\\.[0-9]+\\.[0-9]+$")
        set(udsota_release 1)
    else()
        set(udsota_release 0)
    endif()
    # Delta downloads come only with UDSOTA_DELTA=1 in the build's COMPILE_DEFINITIONS, where udsota.c and the app
    # both read it; detools.c is compiled only then. The app sets it before project(), with
    # idf_build_set_property(COMPILE_DEFINITIONS UDSOTA_DELTA=1 APPEND), as this reads the list only here.
    idf_build_get_property(udsota_build_defs COMPILE_DEFINITIONS)
    set(udsota_srcs "udsota.c" "iso14229/iso14229.c")
    set(udsota_priv_inc "")
    if("UDSOTA_DELTA=1" IN_LIST udsota_build_defs)
        list(APPEND udsota_srcs "detools/detools.c")
        set(udsota_priv_inc "detools")
    endif()
    idf_component_register(SRCS ${udsota_srcs}
                           INCLUDE_DIRS "." "iso14229"
                           PRIV_INCLUDE_DIRS ${udsota_priv_inc}
                           PRIV_REQUIRES app_update bootloader_support esp_app_format esp_partition esp_timer
                                         esp_hw_support esp_system mbedtls)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC UDSOTA_IMG_RELEASE=${udsota_release})
    if("UDSOTA_DELTA=1" IN_LIST udsota_build_defs)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE ${UDSOTA_DELTA_DEFS})
    endif()
    # Keep the app's UDSOTA_IMAGE_DESC in every image: ESP-IDF places .rodata_custom_desc without KEEP, so under
    # --gc-sections it would go from a build that never reaches udsota_init (diagnostics compiled out, say), and units
    # would then refuse that image as BAD_BOARD.
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u udsota_image_desc")
    # iso14229's isotp-c trips GCC's stringop-overflow (upstream's own ESP32 example allows it too). -fwrapv: its
    # IsoTpTimeAfter subtracts as int32_t, and without it GCC folds that to a compare that ends a transfer with a
    # false N_Bs or N_Cr timeout whenever the 32-bit us clock passes 2^31, every 71.6 minutes (test_isotp_wrap).
    set_source_files_properties(iso14229/iso14229.c PROPERTIES COMPILE_OPTIONS
                                "-Wno-error=stringop-overflow;-Wno-stringop-overflow;-fwrapv")
    return()
endif()

cmake_minimum_required(VERSION 3.20)
project(udsota C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
enable_testing()
set_source_files_properties(iso14229/iso14229.c PROPERTIES COMPILE_OPTIONS "-fwrapv")   # as the component does

# iso14229 on its mock transport with a clock the test sets, udsota over the test's platform, and miniz's tinfl
# (tdefl too, to make a raw-DEFLATE image), under ASan and UBSan, the first report ending the test. malloc, calloc and
# free go through the test, which can fail any one of the 34's allocations and counts the blocks udsota holds.
# test_udsota_no_rollback is the same test on a platform that reports what ESP-IDF does without
# CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE, and test_udsota_delta (below) the same with delta downloads.
function(udsota_test name)
    add_executable(${name} test/test_udsota.c udsota.c iso14229/iso14229.c test/miniz/miniz.c)
    target_include_directories(${name} PRIVATE . iso14229 test/miniz)
    target_compile_definitions(${name} PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_MOCK
                                               UDS_CUSTOM_MILLIS _DEFAULT_SOURCE UDSOTA_TEST MINIZ_NO_STDIO
                                               MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS ${ARGN})
    target_compile_options(${name} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all
                                           -fno-omit-frame-pointer)
    target_link_options(${name} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all -Wl,--wrap=malloc
                                        -Wl,--wrap=calloc -Wl,--wrap=free)
    add_test(NAME ${name} COMMAND ${name})
endfunction()
set_source_files_properties(udsota.c test/test_udsota.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
udsota_test(test_udsota)
udsota_test(test_udsota_no_rollback TEST_ROLLBACK=0)

# Delta downloads in a host target: UDSOTA_DELTA=1, detools and its defines. The target's platform supplies the two
# udsota_plat_base_* functions. -DUDSOTA_DELTA=ON builds udsota_lite_server so.
option(UDSOTA_DELTA "Build udsota_lite_server with delta downloads (UDSOTA_DELTA=1 and detools)" OFF)
function(udsota_with_delta name)
    target_sources(${name} PRIVATE detools/detools.c)
    target_include_directories(${name} PRIVATE detools)
    target_compile_definitions(${name} PRIVATE ${UDSOTA_DELTA_DEFS})
endfunction()
udsota_test(test_udsota_delta)
udsota_with_delta(test_udsota_delta)

# The app on a host for the client's end-to-end tests (client/tests/test_e2e_lite.py, test_e2e_lite_vcan.py): udsota
# on iso14229 over isotp-c, CAN frames on stdin and stdout or, where linux/can/raw.h is, on a vcan with --can, two RAM
# slots, every timer on CLOCK_MONOTONIC, ASan and UBSan.
include(CheckIncludeFile)
check_include_file(linux/can/raw.h UDSOTA_HAVE_SOCKETCAN)
add_executable(udsota_lite_server test/e2e/lite_server.c test/e2e/lite_platform.c test/e2e/sha256_host.c
               test/e2e/hmac_sha256_host.c udsota.c iso14229/iso14229.c test/miniz/miniz.c)
target_include_directories(udsota_lite_server PRIVATE . iso14229 test/miniz test/e2e)
target_compile_definitions(udsota_lite_server PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_C
                                                      UDS_CUSTOM_MILLIS _DEFAULT_SOURCE UDSOTA_TEST MINIZ_NO_STDIO
                                                      MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS)
if(UDSOTA_HAVE_SOCKETCAN)
    target_compile_definitions(udsota_lite_server PRIVATE LITE_SOCKETCAN)
endif()
if(UDSOTA_DELTA)
    udsota_with_delta(udsota_lite_server)
endif()
target_compile_options(udsota_lite_server PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all
                                                  -fno-omit-frame-pointer)
target_link_options(udsota_lite_server PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
set_source_files_properties(test/e2e/lite_server.c test/e2e/lite_platform.c PROPERTIES COMPILE_OPTIONS
                            "-Wall;-Wextra;-Werror")

# The fuzzer (test/fuzz_udsota.c): CAN frames through iso14229's isotp-c into UDSServerPoll and udsota, with delta
# downloads, under ASan and UBSan. Each run replays its seeds, their mutants, random programs and mutants of a delta's
# patch, the same every time, and fails unless the seeds reach a whole update over DFI 00, 10 and 30, a refused first
# block and a delta refused at its base. -DUDSOTA_FUZZ_CORPUS=<dir> replays that corpus too (fuzz_udsota_corpus).
# fuzz_udsota_nodelta is the same harness on udsota built without UDSOTA_DELTA, as every app is by default, with 50
# mutants a seed. -DUDSOTA_FUZZ_LIBFUZZER=ON (clang) also builds fuzz_udsota_libfuzzer, the same harness as a
# libFuzzer target, and runs it once over the seeds: fuzz_udsota --write-seeds <dir> starts a corpus.
set(UDSOTA_FUZZ_CORPUS "" CACHE PATH "A corpus directory for fuzz_udsota_corpus to replay (none when empty)")
option(UDSOTA_FUZZ_LIBFUZZER "Build fuzz_udsota_libfuzzer, the fuzzer as a libFuzzer target (clang only)" OFF)
function(udsota_fuzz name sanitizers)
    add_executable(${name} test/fuzz_udsota.c udsota.c iso14229/iso14229.c test/miniz/miniz.c)
    target_include_directories(${name} PRIVATE . iso14229 test/miniz)
    target_compile_definitions(${name} PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_C
                                               UDS_CUSTOM_MILLIS _DEFAULT_SOURCE UDSOTA_TEST MINIZ_NO_STDIO
                                               MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS ${ARGN})
    target_compile_options(${name} PRIVATE -fsanitize=${sanitizers} -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_link_options(${name} PRIVATE -fsanitize=${sanitizers} -fno-sanitize-recover=all)
endfunction()
set_source_files_properties(test/fuzz_udsota.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
udsota_fuzz(fuzz_udsota address,undefined)
udsota_with_delta(fuzz_udsota)
add_test(NAME fuzz_udsota COMMAND fuzz_udsota)
set_tests_properties(fuzz_udsota PROPERTIES TIMEOUT 600)
udsota_fuzz(fuzz_udsota_nodelta address,undefined)
add_test(NAME fuzz_udsota_nodelta COMMAND fuzz_udsota_nodelta --mutations 50)
if(UDSOTA_FUZZ_CORPUS)
    add_test(NAME fuzz_udsota_corpus COMMAND fuzz_udsota ${UDSOTA_FUZZ_CORPUS})
    set_tests_properties(fuzz_udsota_corpus PROPERTIES TIMEOUT 1800)
endif()
if(UDSOTA_FUZZ_LIBFUZZER)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "UDSOTA_FUZZ_LIBFUZZER needs clang: ${CMAKE_C_COMPILER_ID} has no -fsanitize=fuzzer")
    endif()
    udsota_fuzz(fuzz_udsota_libfuzzer fuzzer,address,undefined UDSOTA_FUZZ_LIBFUZZER)
    udsota_with_delta(fuzz_udsota_libfuzzer)
    add_test(NAME fuzz_udsota_seeds COMMAND fuzz_udsota --write-seeds ${CMAKE_CURRENT_BINARY_DIR}/fuzz_seeds)
    add_test(NAME fuzz_udsota_libfuzzer COMMAND fuzz_udsota_libfuzzer -runs=0 ${CMAKE_CURRENT_BINARY_DIR}/fuzz_seeds)
    set_tests_properties(fuzz_udsota_seeds PROPERTIES FIXTURES_SETUP fuzz_seeds)
    set_tests_properties(fuzz_udsota_libfuzzer PROPERTIES FIXTURES_REQUIRED fuzz_seeds)
endif()

# isotp-c's timers across the 2^31 us point, at -O2, where the -fwrapv above matters.
add_executable(test_isotp_wrap test/test_isotp_wrap.c iso14229/iso14229.c)
target_include_directories(test_isotp_wrap PRIVATE iso14229)
target_compile_definitions(test_isotp_wrap PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_C
                                                   UDS_CUSTOM_MILLIS _DEFAULT_SOURCE)
target_compile_options(test_isotp_wrap PRIVATE -O2)
add_test(NAME test_isotp_wrap COMMAND test_isotp_wrap)

# tools/image_check, once per chip and board: udsota's image rules run on a built image, as a unit with that chip,
# descriptor and slot size would (CI runs each on its board's image). Not a test: it needs the image.
function(udsota_image_check name chip hw layout req resp slot)
    add_executable(${name} tools/image_check.c udsota.c test/miniz/miniz.c)
    target_include_directories(${name} PRIVATE . iso14229 test/miniz)
    target_compile_definitions(${name} PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_CUSTOM_MILLIS
                                               _DEFAULT_SOURCE UDSOTA_TEST MINIZ_NO_STDIO MINIZ_NO_TIME
                                               MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS CHIP_ID=${chip}u
                                               IMAGE_CHECK_HW=${hw} IMAGE_CHECK_LAYOUT=${layout}
                                               IMAGE_CHECK_REQ=${req} IMAGE_CHECK_RESP=${resp}
                                               IMAGE_CHECK_SLOT=${slot}u)
endfunction()
set_source_files_properties(tools/image_check.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
udsota_image_check(image_check_example_esp32   0 1 1 0x710 0x718 0x1E0000)   # examples/esp32 and its partitions.csv
udsota_image_check(image_check_example_esp32s3 9 1 1 0x710 0x718 0x1E0000)
udsota_image_check(image_check_ws43            9 1 1 0x7E6 0x7EE 0x400000)   # examples/candash_ws43
udsota_image_check(image_check_ws43b           9 2 1 0x7E6 0x7EE 0x400000)
