# udsota core: the portable UDS updater. Pure C11: the server, codecs, first-block image checks, the
# coded-download stages (the image sink, the compressed stream and the delta patch stage), receive mirror, key
# derivation, boot-loop counter logic and the ISO-TP transport (udsota_isotp.c, which defines isotp-c's platform
# hooks), all host-tested from test/. isotp is a public requirement:
# udsota_isotp.h embeds IsoTpLink, whose layout depends on isotp's PUBLIC ABI defines. The
# integrator's rules reach the server through the hooks passed to udsota_init.
# Under ESP-IDF this is the component `udsota`. In a plain CMake build it is the static library
# udsota_core (alias udsota), which needs the isotp target from components/isotp to exist first. The file lists
# are in sources.cmake.
include(${CMAKE_CURRENT_LIST_DIR}/sources.cmake)

if(ESP_PLATFORM)
    idf_component_register(SRCS ${UDSOTA_SRCS}
                           INCLUDE_DIRS ${UDSOTA_INCLUDE_DIRS}
                           PRIV_INCLUDE_DIRS ${UDSOTA_PRIV_INCLUDE_DIRS}
                           REQUIRES isotp)
else()
    # Only the core's own headers and isotp are on the include path, so a platform include fails the build.
    add_library(udsota_core STATIC ${UDSOTA_SRCS})
    target_include_directories(udsota_core PUBLIC ${UDSOTA_INCLUDE_DIRS} PRIVATE ${UDSOTA_PRIV_INCLUDE_DIRS})
    target_link_libraries(udsota_core PUBLIC isotp)
    add_library(udsota ALIAS udsota_core)
endif()
