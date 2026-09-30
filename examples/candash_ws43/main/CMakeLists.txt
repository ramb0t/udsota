idf_component_register(SRCS "main.c"
                       PRIV_REQUIRES udsota esp_driver_twai esp_driver_i2c esp_timer esp_app_format)

# CANDash's 0x27 HMAC master (git-ignored secrets/, as in CANDash): embedded when present, else 0x27 stays off.
set(poc_master "${PROJECT_DIR}/secrets/dev_uds_unlock_master.bin")
if(EXISTS "${poc_master}")
    target_add_binary_data(${COMPONENT_LIB} "${poc_master}" BINARY RENAME_TO poc_master)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE POC_HAVE_MASTER=1)
endif()

# ECDSA 0x27 instead: -DPOC_PUBKEY_DIR=<a directory holding the udsota_pubkey.h that `udsota keygen` wrote>.
if(DEFINED POC_PUBKEY_DIR AND EXISTS "${POC_PUBKEY_DIR}/udsota_pubkey.h")
    target_include_directories(${COMPONENT_LIB} PRIVATE "${POC_PUBKEY_DIR}")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE POC_HAVE_PUBKEY=1)
endif()
