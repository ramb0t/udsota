# udsota_inflate: a udsota_inflate_t (udsota_zstream.h) on miniz's tinfl, for compressed downloads (DFI 0x10).
# Under ESP-IDF it calls the ROM's tinfl when the target's ROM linker script provides tinfl_decompress (every v6.1
# target's does), and compiles the vendored miniz 3.0.2 (miniz/, unpatched) only where it does not. In a
# plain CMake build it is the static library udsota_inflate over the vendored copy, which needs udsota_core first.
# miniz is built for inflate only: no deflate, zlib, archive, stdio, time or malloc.
set(UDSOTA_MINIZ_DEFS MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS MINIZ_NO_DEFLATE_APIS
                      MINIZ_NO_MALLOC)

if(ESP_PLATFORM)
    set(rom_ld "${IDF_PATH}/components/esp_rom/${IDF_TARGET}/ld/${IDF_TARGET}.rom.ld")
    set(rom_tinfl "")
    if(EXISTS "${rom_ld}")
        file(STRINGS "${rom_ld}" rom_tinfl REGEX "tinfl_decompress[ \t]*=")
    endif()
    if(rom_tinfl)
        idf_component_register(SRCS "udsota_tinfl.c"
                               INCLUDE_DIRS "include"
                               REQUIRES udsota
                               PRIV_REQUIRES esp_rom)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE UDSOTA_TINFL_ROM=1)
    else()
        idf_component_register(SRCS "udsota_tinfl.c" "miniz/miniz.c"
                               INCLUDE_DIRS "include"
                               REQUIRES udsota)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE ${UDSOTA_MINIZ_DEFS})
    endif()
else()
    add_library(udsota_inflate STATIC udsota_tinfl.c miniz/miniz.c)
    target_include_directories(udsota_inflate PUBLIC include)
    target_compile_definitions(udsota_inflate PRIVATE ${UDSOTA_MINIZ_DEFS})
    target_compile_options(udsota_inflate PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(udsota_inflate PUBLIC udsota_core)
endif()
