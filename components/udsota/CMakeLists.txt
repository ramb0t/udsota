# udsota core: the portable UDS updater. Pure C11: the server, codecs, first-block image checks,
# receive mirror, key derivation, boot-loop counter logic and the ISO-TP transport (udsota_isotp.c,
# which defines isotp-c's platform hooks), all host-tested from test/. isotp is a public requirement:
# udsota_isotp.h embeds IsoTpLink, whose layout depends on isotp's PUBLIC ABI defines. The
# integrator's rules reach the server through the hooks passed to udsota_init.
# Under ESP-IDF this is the component `udsota`. In a plain CMake build it is the static library
# udsota_core (alias udsota), which needs the isotp target from components/isotp to exist first.
set(UDSOTA_SRCS "udsota_server.c" "udsota_codec.c" "udsota_image.c" "udsota_rxwatch.c"
                "udsota_keys.c" "udsota_bootloop.c" "udsota_isotp.c")

if(ESP_PLATFORM)
    idf_component_register(SRCS ${UDSOTA_SRCS}
                           INCLUDE_DIRS "include"
                           PRIV_INCLUDE_DIRS "priv"
                           REQUIRES isotp)
else()
    # Only the core's own headers and isotp are on the include path, so a platform include fails the build.
    add_library(udsota_core STATIC ${UDSOTA_SRCS})
    target_include_directories(udsota_core PUBLIC include PRIVATE priv)
    target_link_libraries(udsota_core PUBLIC isotp)
    add_library(udsota ALIAS udsota_core)
endif()
