# udsota on iso14229, on the CANDash ws43 (ESP32-S3). It carries CANDash's image identity (project "candash", hw_id 1,
# layout 1, diag pair 0x7E6/0x7EE), so CANDash's own updater takes it and it takes CANDash back. components/udsota
# is a link to the repository root, the udsota component. See README.md.
cmake_minimum_required(VERSION 3.22)

# A dev build (a suffix after the core) needs a core at least the running one's: 0.5.0 goes both ways with CANDash
# v0.5.0. Override with -DPOC_VER=... to build a second image to update to.
if(NOT DEFINED POC_VER)
    set(POC_VER "0.5.0-lite.1")
endif()
set(PROJECT_VER "${POC_VER}")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(candash)
