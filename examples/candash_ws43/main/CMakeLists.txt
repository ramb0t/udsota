idf_component_register(SRCS "main.c"
                       PRIV_REQUIRES udsota udsota_esp32 udsota_iso14229 iso14229 esp_driver_twai esp_driver_i2c
                                     esp_timer esp_app_format)

# The image descriptor main.c places with UDSOTA_ESP32_IMAGE_DESC.
udsota_esp32_image_desc(${COMPONENT_LIB})

# CANDash's 0x27 HMAC master (git-ignored secrets/, as in CANDash): embedded when present, else 0x27 stays off.
set(poc_master "${PROJECT_DIR}/secrets/dev_uds_unlock_master.bin")
if(EXISTS "${poc_master}")
    target_add_binary_data(${COMPONENT_LIB} "${poc_master}" BINARY RENAME_TO poc_master)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE POC_HAVE_MASTER=1)
endif()
