# udsota_esp32's source files and include dirs, as absolute paths: the one list the component, the host build and an
# out-of-tree host build all take. include() it; it only set()s variables, so ESP-IDF's requirements pass can read it.
#
# By directory: UDSOTA_ESP32_SERVER_SRCS, UDSOTA_ESP32_UPDATE_SRCS, UDSOTA_ESP32_BOOTLOOP_SRCS (always built), and
# UDSOTA_ESP32_SRCS (all three); UDSOTA_ESP32_INCLUDE_DIRS and UDSOTA_ESP32_PRIV_INCLUDE_DIRS. By unit, for a host test
# of a pure part: UDSOTA_ESP32_IMAGE_SRCS, _CTL_SRCS, _DEVID_SRCS and _SA_SRCS. The rest is target-only.
set(_udsota_d ${CMAKE_CURRENT_LIST_DIR})

set(UDSOTA_ESP32_SERVER_SRCS   ${_udsota_d}/server/udsota_esp32.c ${_udsota_d}/server/udsota_esp32_keys.c
                               ${_udsota_d}/server/udsota_esp32_sa.c ${_udsota_d}/server/udsota_esp32_psa.c
                               ${_udsota_d}/server/udsota_esp32_devid.c ${_udsota_d}/server/udsota_esp32_ctl.c)
set(UDSOTA_ESP32_UPDATE_SRCS   ${_udsota_d}/update/udsota_esp32_engine.c ${_udsota_d}/update/udsota_esp32_image.c)
set(UDSOTA_ESP32_BOOTLOOP_SRCS ${_udsota_d}/bootloop/udsota_esp32_bootloop.c)
set(UDSOTA_ESP32_SRCS          ${UDSOTA_ESP32_SERVER_SRCS} ${UDSOTA_ESP32_UPDATE_SRCS} ${UDSOTA_ESP32_BOOTLOOP_SRCS})

set(UDSOTA_ESP32_INCLUDE_DIRS      ${_udsota_d}/include ${_udsota_d}/update/include)
set(UDSOTA_ESP32_PRIV_INCLUDE_DIRS ${_udsota_d}/priv ${_udsota_d}/server/priv)

set(UDSOTA_ESP32_IMAGE_SRCS ${_udsota_d}/update/udsota_esp32_image.c)
set(UDSOTA_ESP32_CTL_SRCS   ${_udsota_d}/server/udsota_esp32_ctl.c)
set(UDSOTA_ESP32_DEVID_SRCS ${_udsota_d}/server/udsota_esp32_devid.c)
set(UDSOTA_ESP32_SA_SRCS    ${_udsota_d}/server/udsota_esp32_sa.c)

unset(_udsota_d)
