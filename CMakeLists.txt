# udsota. Under ESP-IDF this directory is the component: udsota.c and the vendored iso14229. On a host it builds the
# end-to-end test: cmake -S . -B build && cmake --build build && ctest --test-dir build
if(ESP_PLATFORM)
    # A clean [v]X.Y.Z PROJECT_VER is a release; UDSOTA_IMAGE_DESC stamps the flag into the image.
    idf_build_get_property(udsota_ver PROJECT_VER)
    if(udsota_ver MATCHES "^v?[0-9]+\\.[0-9]+\\.[0-9]+$")
        set(udsota_release 1)
    else()
        set(udsota_release 0)
    endif()
    idf_component_register(SRCS "udsota.c" "iso14229/iso14229.c"
                           INCLUDE_DIRS "." "iso14229"
                           PRIV_REQUIRES app_update bootloader_support esp_app_format esp_partition esp_timer
                                         esp_hw_support esp_system mbedtls)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC UDSOTA_IMG_RELEASE=${udsota_release})
    # Keep the app's UDSOTA_IMAGE_DESC in every image: ESP-IDF places .rodata_custom_desc without KEEP, so under
    # --gc-sections it would go from a build that never reaches udsota_init (diagnostics compiled out, say), and units
    # would then refuse that image as BAD_BOARD.
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u udsota_image_desc")
    # iso14229's isotp-c trips GCC's stringop-overflow (upstream's own ESP32 example allows it too).
    set_source_files_properties(iso14229/iso14229.c PROPERTIES COMPILE_OPTIONS
                                "-Wno-error=stringop-overflow;-Wno-stringop-overflow")
    return()
endif()

cmake_minimum_required(VERSION 3.20)
project(udsota C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
enable_testing()

# iso14229 on its mock transport with a clock the test sets, udsota over the test's platform, and miniz's tinfl
# (tdefl too, to make a raw-DEFLATE image).
add_executable(test_udsota test/test_udsota.c udsota.c iso14229/iso14229.c test/miniz/miniz.c)
target_include_directories(test_udsota PRIVATE . iso14229 test/miniz)
target_compile_definitions(test_udsota PRIVATE UDS_SYS=UDS_SYS_UNIX UDS_AUTOSELECT_TP=0 UDS_TP_ISOTP_MOCK
                                               UDS_CUSTOM_MILLIS _DEFAULT_SOURCE UDSOTA_TEST MINIZ_NO_STDIO MINIZ_NO_TIME
                                               MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS)
# ASan and UBSan, the first report ending the test.
target_compile_options(test_udsota PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
target_link_options(test_udsota PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
set_source_files_properties(udsota.c test/test_udsota.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
add_test(NAME test_udsota COMMAND test_udsota)
