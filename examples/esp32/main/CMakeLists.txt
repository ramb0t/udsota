idf_component_register(SRCS "main.c"
                       PRIV_REQUIRES udsota udsota_esp32 esp_driver_twai esp_timer)

# The image descriptor that main.c places with UDSOTA_ESP32_IMAGE_DESC: sets its release flag from
# PROJECT_VER and keeps it in the link.
udsota_esp32_image_desc(${COMPONENT_LIB})
