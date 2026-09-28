# udsota_delta: a udsota_patch_t (udsota_patch.h) on detools, for delta downloads (DFI 0x20 and 0x30). detools 0.53.0's
# C side is vendored unpatched in detools/, with the heatshrink decoder it bundles, and built for sequential patches
# only: heatshrink-compressed or uncompressed, no LZMA, no CRLE, no file I/O. Under ESP-IDF it is the component
# udsota_delta; in a plain CMake build it is the static library udsota_delta, which needs udsota_core first.
set(UDSOTA_DETOOLS_DEFS DETOOLS_CONFIG_FILE_IO=0 DETOOLS_CONFIG_COMPRESSION_NONE=1 DETOOLS_CONFIG_COMPRESSION_LZMA=0
                        DETOOLS_CONFIG_COMPRESSION_CRLE=0 DETOOLS_CONFIG_COMPRESSION_HEATSHRINK=1)
set(UDSOTA_DETOOLS_SRCS "detools/detools.c" "detools/heatshrink/heatshrink_decoder.c")

if(ESP_PLATFORM)
    idf_component_register(SRCS "udsota_detools.c" ${UDSOTA_DETOOLS_SRCS}
                           INCLUDE_DIRS "include"
                           PRIV_INCLUDE_DIRS "detools" "detools/heatshrink"
                           REQUIRES udsota)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ${UDSOTA_DETOOLS_DEFS})
else()
    add_library(udsota_delta STATIC udsota_detools.c ${UDSOTA_DETOOLS_SRCS})
    target_include_directories(udsota_delta PUBLIC include PRIVATE detools detools/heatshrink)
    target_compile_definitions(udsota_delta PRIVATE ${UDSOTA_DETOOLS_DEFS})
    target_compile_options(udsota_delta PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(udsota_delta PUBLIC udsota_core)
endif()
