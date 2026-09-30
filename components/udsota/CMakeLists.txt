# udsota core: the portable firmware updater, with no UDS server. Pure C11: the updater, codecs, first-block image
# checks, the coded-download stages, 0x27 key derivation and the boot-loop counter logic. A host UDS server calls
# the updater; components/udsota_iso14229 binds it to iso14229. Under ESP-IDF this is the component `udsota`; in a
# plain CMake build the static library udsota_core (alias udsota). The file lists are in sources.cmake.
include(${CMAKE_CURRENT_LIST_DIR}/sources.cmake)

if(ESP_PLATFORM)
    idf_component_register(SRCS ${UDSOTA_SRCS}
                           INCLUDE_DIRS ${UDSOTA_INCLUDE_DIRS})
else()
    add_library(udsota_core STATIC ${UDSOTA_SRCS})
    target_include_directories(udsota_core PUBLIC ${UDSOTA_INCLUDE_DIRS})
    add_library(udsota ALIAS udsota_core)
endif()
