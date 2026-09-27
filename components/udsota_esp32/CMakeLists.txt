# udsota ESP32 port. The update engine on esp_ota_* (flash worker and OTA state cache), 0x27 security on
# PSA HMAC and the hardware RNG, the PSA lock they share with the app, the boot-loop counter in
# RTC_NOINIT memory and the ESP image-header check. udsota_esp32_image.c is pure and host-tested; the
# rest is target-only. project_include.cmake defines udsota_esp32_image_desc(). udsota_esp32.c is the diag task
# and the app API; udsota_esp32_ctl.c its pure control block.
idf_component_register(SRCS "udsota_esp32_engine.c" "udsota_esp32_image.c" "udsota_esp32_keys.c"
                            "udsota_esp32_psa.c" "udsota_esp32_bootloop.c" "udsota_esp32.c" "udsota_esp32_ctl.c"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "priv"
                       REQUIRES udsota
                       PRIV_REQUIRES isotp app_update esp_partition esp_app_format esp_timer spi_flash
                                     bootloader_support mbedtls)
