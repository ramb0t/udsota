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
# --no-updater runs the server alone: 10 02 answers 7F 10 12, and 31 03 A001 (the self-test's results) 71 03 A0 01 00.
add_test(NAME udsota_demo_server_no_updater
         COMMAND sh -c "printf '710#021002\\n710#043103A001\\n' | '$<TARGET_FILE:udsota_demo_server>' --no-updater")
set_tests_properties(udsota_demo_server_no_updater PROPERTIES
                     PASS_REGULAR_EXPRESSION "718#037F1012AAAAAAAA.*718#057103A00100AAAA")
# The echo service through hooks.request: BA 01 42 answers FA 01 42, BA 81 42 nothing, and BB, which it doesn't serve,
# 7F BB 11 right after; with --no-updater 34 reaches the hook too (7F 34 11, logged).
add_test(NAME udsota_demo_server_request
         COMMAND sh -c "printf '710#03BA0142\\n710#03BA8142\\n710#01BB\\n' | \
'$<TARGET_FILE:udsota_demo_server>' 2>/dev/null && printf '710#0134\\n' | \
'$<TARGET_FILE:udsota_demo_server>' --no-updater 2>&1")
set_tests_properties(udsota_demo_server_request PROPERTIES
                     PASS_REGULAR_EXPRESSION "718#03FA0142AAAAAAAA\n718#037FBB11AAAAAAAA.*SID 0x34 is not served")
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
