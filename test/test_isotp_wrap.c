/* isotp-c's timer check across the 2^31 us point of its 32-bit us clock, which a device passes every 71.6 minutes.
 * IsoTpTimeAfter subtracts as int32_t, which overflows there, and at -O1 and above GCC and Clang fold it to a plain
 * signed compare that reads a deadline just past 0x80000000 as already gone. udsota's CMakeLists compiles iso14229.c
 * with -fwrapv, a build flag rather than a change to iso14229, and this test, built at -O2, fails without it: a
 * first frame 65 ms before the crossing must still be receiving 1 ms later, not ended by a false N_Cr timeout. */
#include <stdint.h>
#include <stdio.h>
#include "iso14229.h"

static uint32_t g_us;

uint32_t isotp_user_get_us(void)
{
    return g_us;
}

uint32_t UDSMillis(void)
{
    return g_us / 1000u;
}

int isotp_user_send_can(const uint32_t id, const uint8_t *data, const uint8_t len, void *arg)
{
    (void)id;
    (void)data;
    (void)len;
    (void)arg;
    return ISOTP_RET_OK;
}

void isotp_user_debug(const char *fmt, ...)
{
    (void)fmt;
}

int main(void)
{
    static uint8_t send_buf[256], recv_buf[256];
    static IsoTpLink link;
    isotp_init_link(&link, 0x7EE, send_buf, sizeof send_buf, recv_buf, sizeof recv_buf);
    g_us = 0x7FFF0000u;
    const uint8_t first_frame[8] = {0x10, 0x20, 0x36, 0x01, 1, 2, 3, 4};   /* a 32-byte 36 */
    isotp_on_can_message(&link, first_frame, sizeof first_frame);
    g_us += 1000u;
    isotp_poll(&link);
    if (link.receive_status != ISOTP_RECEIVE_STATUS_INPROGRESS) {
        fprintf(stderr, "test_isotp_wrap: the receive ended 1 ms after its first frame (result %d)\n",
                link.receive_protocol_result);
        return 1;
    }
    printf("test_isotp_wrap: N_Cr holds across the 2^31 us point\n");
    return 0;
}
