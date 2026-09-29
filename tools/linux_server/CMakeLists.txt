# udsota_demo_server: the portable core (udsota_core, isotp) on Linux over SocketCAN or a stdin/stdout frame
# pipe, with fake_engine's file-backed A/B slots behind the ESP32 port's first-block check and the core's image
# rules, and compressed and delta downloads over udsota_inflate's vendored tinfl and udsota_delta's detools. Built
# from the root CMakeLists.txt on Linux only. client/tests/test_e2e_*.py drive it with the client.
add_executable(udsota_demo_server
    demo_server.c demo_engine.c demo_can.c hmac_sha256_host.c
    ${CORE_TEST}/fake_engine.c ${CORE_TEST}/sha256_host.c ${UDSOTA_ESP32_IMAGE_SRCS})
target_include_directories(udsota_demo_server PRIVATE ${CMAKE_CURRENT_LIST_DIR} ${CORE_TEST} ${UDSOTA_ESP32_INCLUDE_DIRS})
target_compile_options(udsota_demo_server PRIVATE -Wall -Wextra -Werror)
target_link_libraries(udsota_demo_server PRIVATE udsota_core udsota_inflate udsota_delta)

# The host HMAC under udsota_keys.c's known answers (RFC 4231 TC2 and both derivations).
add_test(NAME udsota_demo_server_self_test COMMAND udsota_demo_server --self-test)
# One request over the pipe: 22 F186 answers 62 F1 86 01 (default session), then stdin's EOF stops the server.
add_test(NAME udsota_demo_server_pipe
         COMMAND sh -c "printf '710#0322F186\\n' | '$<TARGET_FILE:udsota_demo_server>'")
set_tests_properties(udsota_demo_server_pipe PROPERTIES PASS_REGULAR_EXPRESSION "718#0462F18601AAAAAA")
# --socketcan refuses an interface that is not vcan, before it opens any socket: lo, and a name that does not exist.
add_test(NAME udsota_demo_server_refuses_real_bus
         COMMAND sh -c "! '$<TARGET_FILE:udsota_demo_server>' --socketcan lo && \
! '$<TARGET_FILE:udsota_demo_server>' --socketcan udsota_no_such_if")
set_tests_properties(udsota_demo_server_refuses_real_bus PROPERTIES
                     PASS_REGULAR_EXPRESSION "lo is not a vcan interface.*udsota_no_such_if is not a vcan interface")
# An image from --make-image passes the port's first-block check as tools/image_check runs it.
add_test(NAME udsota_demo_server_make_image
         COMMAND sh -c "'$<TARGET_FILE:udsota_demo_server>' --make-image '${CMAKE_CURRENT_BINARY_DIR}/demo.bin' \
--version v0.2.0 && '$<TARGET_FILE:udsota_image_check>' '${CMAKE_CURRENT_BINARY_DIR}/demo.bin' 0x0009")
