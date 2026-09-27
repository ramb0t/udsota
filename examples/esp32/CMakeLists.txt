# udsota ESP32 example: the port over TWAI, security off, rollback on. See README.md.
cmake_minimum_required(VERSION 3.22)

# udsota, udsota_esp32 and isotp live in the repository's components/ directory.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

# The version esp_app_desc_t carries, which the image rules compare. A clean [v]X.Y.Z marks a release build
# (udsota_esp32_image_desc() sets the descriptor's flag); a suffix such as -dev marks a dev build. Remove the
# line to take it from `git describe` instead.
set(PROJECT_VER "0.1.0-dev")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(example)
