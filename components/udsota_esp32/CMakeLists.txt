# udsota ESP32 port, without a UDS server: the update engine on esp_ota_* (flash worker and OTA state cache), 0x27
# security on PSA HMAC or PSA ECDSA and the hardware RNG, the PSA lock they share with the app, the boot-loop
# counter in RTC_NOINIT memory and the ESP image-header check. The app runs the server (iso14229) and binds the
# updater with udsota_iso14229. udsota_inflate and udsota_delta are linked only into what
# CONFIG_UDSOTA_ESP32_COMPRESSION and CONFIG_UDSOTA_ESP32_DELTA reference. project_include.cmake defines
# udsota_esp32_image_desc(). The file lists are in sources.cmake.
include(${CMAKE_CURRENT_LIST_DIR}/sources.cmake)
idf_component_register(SRCS ${UDSOTA_ESP32_SRCS}
                       INCLUDE_DIRS ${UDSOTA_ESP32_INCLUDE_DIRS}
                       PRIV_INCLUDE_DIRS ${UDSOTA_ESP32_PRIV_INCLUDE_DIRS}
                       REQUIRES udsota
                       PRIV_REQUIRES udsota_inflate udsota_delta app_update esp_partition esp_app_format esp_timer
                                     spi_flash bootloader_support mbedtls)

# Without compressed downloads the updater compiles none of the coded-download handling either (UDSOTA_COMPRESSION,
# udsota_update.h).
if(NOT CONFIG_UDSOTA_ESP32_COMPRESSION)
    idf_component_get_property(udsota_lib udsota COMPONENT_LIB)
    target_compile_definitions(${udsota_lib} PRIVATE UDSOTA_COMPRESSION=0)
endif()
