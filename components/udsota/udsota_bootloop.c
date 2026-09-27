/* Boot-loop breaker logic. Pure: the target keeps the state in RTC memory
 * (udsota_esp32_bootloop.c); host-tested by test_udsota_bootloop. */
#include <stddef.h>
#include "udsota_bootloop.h"

typedef enum { RR_CLEAR, RR_KEEP, RR_CRASH } rr_class_t;

/* Sorts a reset reason: power-on clears, deliberate resets keep, crashes and unknown values count. */
static rr_class_t classify(udsota_reset_reason_t reason)
{
    switch (reason) {
    case UDSOTA_RST_POWERON:
        return RR_CLEAR;
    case UDSOTA_RST_SW:
    case UDSOTA_RST_EXT:
        return RR_KEEP;
    default:   /* OTHER, PANIC, WDT, BROWNOUT, and any value outside the enum */
        return RR_CRASH;
    }
}

/* Applies this boot's reset reason to *s and writes the magic; returns whether to ignore config. */
udsota_bootloop_action_t udsota_bootloop_on_boot(udsota_bootloop_state_t *s, udsota_reset_reason_t reason, bool magic_valid)
{
    udsota_bootloop_action_t a = { .ignore_config = false, .cleared = false };
    if (!magic_valid) {
        s->count = 0;
        a.cleared = true;
    }
    s->magic = UDSOTA_BOOTLOOP_MAGIC;
    switch (classify(reason)) {
    case RR_CLEAR:
        s->count = 0;
        a.cleared = true;
        break;
    case RR_CRASH:
        if (s->count < UINT32_MAX) {
            s->count++;
        }
        break;
    case RR_KEEP:
        break;
    }
    a.ignore_config = s->count >= UDSOTA_BOOTLOOP_THRESHOLD;
    return a;
}

/* Reaching healthy: clears the count and writes the magic. */
void udsota_bootloop_on_healthy(udsota_bootloop_state_t *s)
{
    s->magic = UDSOTA_BOOTLOOP_MAGIC;
    s->count = 0;
}

/* True when s is non-NULL and holds UDSOTA_BOOTLOOP_MAGIC. */
bool udsota_bootloop_magic_valid(const udsota_bootloop_state_t *s)
{
    return s != NULL && s->magic == UDSOTA_BOOTLOOP_MAGIC;
}
