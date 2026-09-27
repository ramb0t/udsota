# udsota_esp32_image_desc(<target>): call it from the CMakeLists.txt of the component whose source uses
# UDSOTA_ESP32_IMAGE_DESC. It defines UDSOTA_ESP32_IMG_RELEASE as 1 when PROJECT_VER (the version
# esp_app_desc carries) is a clean tag [v]N.N.N and 0 otherwise (a describe suffix, -dirty or a bare
# hash is a dev build), and keeps the descriptor with "-u udsota_image_desc", since nothing references it.
function(udsota_esp32_image_desc target)
    idf_build_get_property(udsota_ver PROJECT_VER)
    if(udsota_ver MATCHES "^v?[0-9]+\\.[0-9]+\\.[0-9]+$")
        set(udsota_release 1)
    else()
        set(udsota_release 0)
    endif()
    target_compile_definitions(${target} PRIVATE "UDSOTA_ESP32_IMG_RELEASE=${udsota_release}")
    target_link_libraries(${target} INTERFACE "-u udsota_image_desc")
endfunction()
