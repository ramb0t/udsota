# The udsota_boot_arm_size target's check: cmake -DSIZE=<arm-none-eabi-size> -DOBJECT=<udsota_boot_arm.o> -DGATE=<bytes>
# -P tools/boot_size_gate.cmake prints the object's sizes and fails when its text is over GATE bytes.
if(NOT GATE MATCHES "^[0-9]+$")
    message(FATAL_ERROR "GATE must be a byte count, not '${GATE}'")
endif()
execute_process(COMMAND ${SIZE} ${OBJECT} OUTPUT_VARIABLE report COMMAND_ERROR_IS_FATAL ANY)
message("${report}")
string(REGEX MATCH "\n[ \t]*([0-9]+)" row "${report}")   # the second line's first column is the text size
if(NOT row)
    message(FATAL_ERROR "no sizes in ${SIZE}'s report on ${OBJECT}")
endif()
if(CMAKE_MATCH_1 GREATER GATE)
    message(FATAL_ERROR "${OBJECT} has ${CMAKE_MATCH_1} bytes of text, over the gate of ${GATE}")
endif()
