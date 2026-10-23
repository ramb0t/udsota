# udsota ESP32 example: udsota on iso14229 over TWAI, security off, rollback on, for any ESP32 with TWAI. See README.md.
# components/udsota is a link to the repository root, the udsota component.
cmake_minimum_required(VERSION 3.22)

# The version esp_app_desc_t carries, which the image rules compare. A clean [v]X.Y.Z marks a release build (udsota's
# CMakeLists sets the descriptor's flag); a suffix such as -dev marks a dev build. Remove the line to take it from
# `git describe` instead.
set(PROJECT_VER "0.1.0-dev")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(example)
