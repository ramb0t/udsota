# udsota's updater on iso14229's server (udsota_iso14229.h). Pure C over udsota and iso14229. Under ESP-IDF the
# component `udsota_iso14229`; in a plain CMake build the static library udsota_iso14229, which needs the iso14229
# and udsota_core targets to exist first.
if(ESP_PLATFORM)
    idf_component_register(SRCS udsota_iso14229.c
                           INCLUDE_DIRS include
                           REQUIRES udsota iso14229)
else()
    add_library(udsota_iso14229 STATIC ${CMAKE_CURRENT_LIST_DIR}/udsota_iso14229.c)
    target_include_directories(udsota_iso14229 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
    target_link_libraries(udsota_iso14229 PUBLIC udsota_core iso14229)
endif()
