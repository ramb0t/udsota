# iso14229 (github.com/driftregion/iso14229, the submodule in iso14229/): its single-file amalgamation, the UDS
# server and its isotp-c transport (UDS_TP_ISOTP_C on ESP32). The app provides isotp_user_send_can,
# isotp_user_get_us and isotp_user_debug. Upstream code, built with its own warnings allowed.
set(_iso ${CMAKE_CURRENT_LIST_DIR}/iso14229)
if(NOT EXISTS ${_iso}/iso14229.c)
    message(FATAL_ERROR "iso14229 submodule missing: run 'git submodule update --init'")
endif()
if(ESP_PLATFORM)
    idf_component_register(SRCS ${_iso}/iso14229.c
                           INCLUDE_DIRS ${_iso}
                           PRIV_REQUIRES esp_timer)
    # isotp-c trips GCC's stringop-overflow (upstream's ESP32 example sets the same; isotp-c issue 83).
    target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=stringop-overflow -Wno-stringop-overflow)
else()
    add_library(iso14229 STATIC ${_iso}/iso14229.c)
    target_include_directories(iso14229 PUBLIC ${_iso})
endif()
unset(_iso)
