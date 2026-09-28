# udsota ESP32 port. The update engine on esp_ota_* (flash worker and OTA state cache), 0x27 security on
# PSA HMAC or PSA ECDSA and the hardware RNG, the PSA lock they share with the app, the boot-loop counter in
# RTC_NOINIT memory and the ESP image-header check. udsota_esp32_image.c, udsota_esp32_ctl.c (the diag
# task's control block), udsota_esp32_devid.c (the device ID and its K_dev) and udsota_esp32_sa.c (the 0x27
# mode and the ECDSA key check) are pure and host-tested; the rest is target-only. udsota_inflate and
# udsota_delta are linked only into what CONFIG_UDSOTA_ESP32_COMPRESSION and CONFIG_UDSOTA_ESP32_DELTA reference.
# project_include.cmake defines udsota_esp32_image_desc(). udsota_esp32.c is the diag task and the app API.
idf_component_register(SRCS "udsota_esp32_engine.c" "udsota_esp32_image.c" "udsota_esp32_keys.c"
                            "udsota_esp32_psa.c" "udsota_esp32_bootloop.c" "udsota_esp32.c" "udsota_esp32_ctl.c"
                            "udsota_esp32_devid.c" "udsota_esp32_sa.c"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "priv"
                       REQUIRES udsota
                       PRIV_REQUIRES isotp udsota_inflate udsota_delta app_update esp_partition esp_app_format esp_timer
                                     spi_flash bootloader_support mbedtls)

# Without compressed downloads the core compiles none of the coded-download handling either (UDSOTA_COMPRESSION,
# udsota.h).
if(NOT CONFIG_UDSOTA_ESP32_COMPRESSION)
    idf_component_get_property(udsota_lib udsota COMPONENT_LIB)
    target_compile_definitions(${udsota_lib} PRIVATE UDSOTA_COMPRESSION=0)
endif()
