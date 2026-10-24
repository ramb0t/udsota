# udsota on iso14229, on the CANDash ws43 or ws43b (ESP32-S3). It carries CANDash's image identity (project "candash",
# hw_id 1 or 2, layout 1, diag pair 0x7E6/0x7EE), so CANDash's own updater takes it and it takes CANDash back.
# components/udsota is a link to the repository root, the udsota component. See README.md.
cmake_minimum_required(VERSION 3.22)

# A dev build (a suffix after the core) needs a core at least the running one's: 0.5.0 goes both ways with CANDash
# v0.5.0. Override with -DPOC_VER=... to build a second image to update to.
if(NOT DEFINED POC_VER)
    set(POC_VER "0.5.0-lite.1")
endif()
set(PROJECT_VER "${POC_VER}")

# The board: ws43, or -DPOC_BOARD=ws43b for the 4.3B (hw_id 2, CAN on GPIO15/16, console on native USB). A ws43b
# build keeps its sdkconfig in its build directory: the project's, a ws43's, would keep the ws43's UART console, and
# defaults never override an option an sdkconfig already sets.
if(NOT DEFINED POC_BOARD)
    set(POC_BOARD "ws43")
endif()
if(POC_BOARD STREQUAL "ws43b")
    if(NOT DEFINED SDKCONFIG)
        set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
    endif()
    if(NOT DEFINED SDKCONFIG_DEFAULTS)
        set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
    endif()
    list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults.ws43b")
elseif(NOT POC_BOARD STREQUAL "ws43")
    message(FATAL_ERROR "POC_BOARD is ws43 or ws43b, not ${POC_BOARD}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
if(POC_BOARD STREQUAL "ws43b")
    idf_build_set_property(COMPILE_DEFINITIONS POC_BOARD_WS43B=1 APPEND)
endif()
# -DPOC_DELTA=1: udsota with delta downloads, which the app then turns on (cfg.allow_delta).
if(POC_DELTA)
    idf_build_set_property(COMPILE_DEFINITIONS UDSOTA_DELTA=1 APPEND)
endif()
project(candash)
