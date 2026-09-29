# ISO-TP transport: the pinned SimonCahill isotp-c v1.9.3 (commit 1fc19e2, unpatched) plus a port
# that gives each link its own block size and STmin (include/isotp_port.h). The platform hooks
# isotp_user_send_can / isotp_user_get_us / isotp_user_debug are defined by components/udsota/server/udsota_isotp.c;
# test_isotp_loopback defines its own and never links it.
# Under ESP-IDF this is the component `isotp`; in a plain CMake build it is the static library `isotp`.
if(ESP_PLATFORM)
    idf_component_register(SRCS "isotp-c/isotp.c" "isotp_port.c"
                           INCLUDE_DIRS "include" "isotp-c")
    set(ISOTP_LIB ${COMPONENT_LIB})
else()
    add_library(isotp STATIC isotp-c/isotp.c isotp_port.c)
    target_include_directories(isotp PUBLIC include isotp-c)
    set(ISOTP_LIB isotp)
endif()

# ABI options: IsoTpLink's layout depends on them, so every includer must be built with the same
# set. PUBLIC puts them on each component or target that links isotp. N_Bs and N_Cr are 1 s.
target_compile_definitions(${ISOTP_LIB} PUBLIC
    ISO_TP_USER_SEND_CAN_ARG
    ISO_TP_FRAME_PADDING
    ISO_TP_FRAME_PADDING_VALUE=0xAA
    ISO_TP_NO_FORMATTED_ERRORS
    ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US=1000000)

# Per-link BS and STmin: isotp_force.h turns isotp-c's two receive-side macros into calls that take
# `link`. It goes on isotp.c only; nowhere else has `link` in scope. Source properties are
# directory-scoped, so this stays in the file that creates the target.
set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/isotp-c/isotp.c" PROPERTIES
                            COMPILE_OPTIONS "-include;${CMAKE_CURRENT_LIST_DIR}/isotp_force.h")
