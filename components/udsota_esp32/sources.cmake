# udsota_esp32's source files and include dirs, as absolute paths. include() it; it only set()s variables.
# UDSOTA_ESP32_PORT_SRCS (start, security, device ID, PSA lock), UDSOTA_ESP32_UPDATE_SRCS (the engine),
# UDSOTA_ESP32_BOOTLOOP_SRCS, and UDSOTA_ESP32_SRCS (all three).
set(_udsota_d ${CMAKE_CURRENT_LIST_DIR})

set(UDSOTA_ESP32_PORT_SRCS     ${_udsota_d}/port/udsota_esp32_updater.c ${_udsota_d}/port/udsota_esp32_keys.c
                               ${_udsota_d}/port/udsota_esp32_sa.c ${_udsota_d}/port/udsota_esp32_psa.c
                               ${_udsota_d}/port/udsota_esp32_devid.c)
set(UDSOTA_ESP32_UPDATE_SRCS   ${_udsota_d}/update/udsota_esp32_engine.c ${_udsota_d}/update/udsota_esp32_image.c)
set(UDSOTA_ESP32_BOOTLOOP_SRCS ${_udsota_d}/bootloop/udsota_esp32_bootloop.c)
set(UDSOTA_ESP32_SRCS          ${UDSOTA_ESP32_PORT_SRCS} ${UDSOTA_ESP32_UPDATE_SRCS} ${UDSOTA_ESP32_BOOTLOOP_SRCS})

set(UDSOTA_ESP32_INCLUDE_DIRS      ${_udsota_d}/include ${_udsota_d}/update/include)
set(UDSOTA_ESP32_PRIV_INCLUDE_DIRS ${_udsota_d}/priv ${_udsota_d}/port/priv)

unset(_udsota_d)
