/* Boot-loop breaker logic (udsota_bootloop.c): every reset reason, the count-3 threshold, the healthy
 * clear, the magic guard and saturation. Pure; the RTC storage is target-only (udsota_esp32_bootloop.c). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "unity.h"
#include "udsota_bootloop.h"

/* Unity per-test hook; each test builds its own state. */
void setUp(void) {}
/* Unity per-test hook; nothing to clean up. */
void tearDown(void) {}

/* Returns a state with a valid magic holding this count. */
static udsota_bootloop_state_t at(uint32_t count)
{
    udsota_bootloop_state_t s = { .magic = UDSOTA_BOOTLOOP_MAGIC, .count = count };
    return s;
}

/* Runs one boot over a state whose magic is valid. */
static udsota_bootloop_action_t boot(udsota_bootloop_state_t *s, udsota_reset_reason_t r)
{
    return udsota_bootloop_on_boot(s, r, true);
}

/* Every core reason plus one past the enum: from count 1, power-on gives 0, a deliberate reset 1, a crash 2. */
static void test_every_reset_reason_classified(void)
{
    static const struct { udsota_reset_reason_t r; uint32_t want; bool cleared; } rows[] = {
        { UDSOTA_RST_OTHER,    2, false },
        { UDSOTA_RST_POWERON,  0, true  },
        { UDSOTA_RST_SW,       1, false },
        { UDSOTA_RST_EXT,      1, false },
        { UDSOTA_RST_PANIC,    2, false },
        { UDSOTA_RST_WDT,      2, false },
        { UDSOTA_RST_BROWNOUT, 2, false },
        { (udsota_reset_reason_t)0x7F, 2, false },   /* a value outside the enum counts as a crash */
    };
    const size_t n = sizeof rows / sizeof rows[0];
    TEST_ASSERT_EQUAL_INT((int)UDSOTA_RST_BROWNOUT + 2, (int)n);   /* the table covers the whole enum */
    for (size_t i = 0; i < n; i++) {
        char msg[24];
        snprintf(msg, sizeof msg, "reason %d", (int)rows[i].r);
        udsota_bootloop_state_t s = at(1);
        udsota_bootloop_action_t a = boot(&s, rows[i].r);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(rows[i].want, s.count, msg);
        TEST_ASSERT_EQUAL_MESSAGE(rows[i].cleared, a.cleared, msg);
        TEST_ASSERT_FALSE_MESSAGE(a.ignore_config, msg);
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(UDSOTA_BOOTLOOP_MAGIC, s.magic, msg);
    }
}

/* A power-on reset clears the count, even from above the threshold, and the boot uses config again. */
static void test_power_on_clears_count(void)
{
    udsota_bootloop_state_t s = at(5);
    udsota_bootloop_action_t a = boot(&s, UDSOTA_RST_POWERON);
    TEST_ASSERT_EQUAL_UINT32(0, s.count);
    TEST_ASSERT_TRUE(a.cleared);
    TEST_ASSERT_FALSE(a.ignore_config);
}

/* The device's own restart (esp_restart: 11 01, ActivateImage) leaves the count alone. */
static void test_sw_reset_leaves_count(void)
{
    udsota_bootloop_state_t s = at(2);
    udsota_bootloop_action_t a = boot(&s, UDSOTA_RST_SW);
    TEST_ASSERT_EQUAL_UINT32(2, s.count);
    TEST_ASSERT_FALSE(a.cleared);
    TEST_ASSERT_FALSE(a.ignore_config);
}

/* From a first power-up, the third crash reset in a row ignores config, and so does every one after it. */
static void test_third_crash_ignores_config(void)
{
    udsota_bootloop_state_t s = { .magic = 0x0BADF00Du, .count = 77 };   /* RTC garbage at first power-up */
    udsota_bootloop_action_t a = udsota_bootloop_on_boot(&s, UDSOTA_RST_POWERON, false);
    TEST_ASSERT_EQUAL_UINT32(0, s.count);
    TEST_ASSERT_FALSE(a.ignore_config);

    a = boot(&s, UDSOTA_RST_PANIC);
    TEST_ASSERT_EQUAL_UINT32(1, s.count);
    TEST_ASSERT_FALSE(a.ignore_config);
    a = boot(&s, UDSOTA_RST_WDT);
    TEST_ASSERT_EQUAL_UINT32(2, s.count);
    TEST_ASSERT_FALSE(a.ignore_config);
    a = boot(&s, UDSOTA_RST_BROWNOUT);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_BOOTLOOP_THRESHOLD, s.count);
    TEST_ASSERT_TRUE(a.ignore_config);
    a = boot(&s, UDSOTA_RST_OTHER);
    TEST_ASSERT_EQUAL_UINT32(4, s.count);
    TEST_ASSERT_TRUE(a.ignore_config);
}

/* A technician's reset while config is ignored keeps it ignored: only healthy or power-on clears. */
static void test_sw_reset_keeps_config_ignored(void)
{
    udsota_bootloop_state_t s = at(UDSOTA_BOOTLOOP_THRESHOLD);
    udsota_bootloop_action_t a = boot(&s, UDSOTA_RST_SW);
    TEST_ASSERT_EQUAL_UINT32(UDSOTA_BOOTLOOP_THRESHOLD, s.count);
    TEST_ASSERT_TRUE(a.ignore_config);
}

/* Crash, crash, healthy, crash: reaching healthy restarts the count, so it ends at 1, not 3. */
static void test_healthy_clears_and_restarts_count(void)
{
    udsota_bootloop_state_t s = at(0);
    (void)boot(&s, UDSOTA_RST_PANIC);
    (void)boot(&s, UDSOTA_RST_PANIC);
    TEST_ASSERT_EQUAL_UINT32(2, s.count);
    udsota_bootloop_on_healthy(&s);
    TEST_ASSERT_EQUAL_UINT32(0, s.count);
    udsota_bootloop_action_t a = boot(&s, UDSOTA_RST_PANIC);
    TEST_ASSERT_EQUAL_UINT32(1, s.count);
    TEST_ASSERT_FALSE(a.ignore_config);
}

/* An invalid magic resets the count to 0 and writes the magic, whatever the stored count said. */
static void test_invalid_magic_resets_to_zero(void)
{
    udsota_bootloop_state_t s = { .magic = 0x12345678u, .count = 0xDEADBEEFu };
    udsota_bootloop_action_t a = udsota_bootloop_on_boot(&s, UDSOTA_RST_SW, false);
    TEST_ASSERT_EQUAL_UINT32(0, s.count);
    TEST_ASSERT_EQUAL_HEX32(UDSOTA_BOOTLOOP_MAGIC, s.magic);
    TEST_ASSERT_TRUE(a.cleared);
    TEST_ASSERT_FALSE(a.ignore_config);
}

/* An invalid magic after a panic (RTC memory lost) starts from 0 and then counts that panic. */
static void test_invalid_magic_then_panic_counts_one(void)
{
    udsota_bootloop_state_t s = { .magic = 0, .count = UINT32_MAX };
    udsota_bootloop_action_t a = udsota_bootloop_on_boot(&s, UDSOTA_RST_PANIC, false);
    TEST_ASSERT_EQUAL_UINT32(1, s.count);
    TEST_ASSERT_TRUE(a.cleared);
    TEST_ASSERT_FALSE(a.ignore_config);
}

/* The count holds at UINT32_MAX rather than wrapping to 0 and re-reading config. */
static void test_count_saturates(void)
{
    udsota_bootloop_state_t s = at(UINT32_MAX);
    udsota_bootloop_action_t a = boot(&s, UDSOTA_RST_PANIC);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, s.count);
    TEST_ASSERT_TRUE(a.ignore_config);
}

/* Marking healthy also repairs a bad magic, so the next boot trusts the zero it wrote. */
static void test_on_healthy_repairs_magic(void)
{
    udsota_bootloop_state_t s = { .magic = 0, .count = 9 };
    udsota_bootloop_on_healthy(&s);
    TEST_ASSERT_EQUAL_UINT32(0, s.count);
    TEST_ASSERT_TRUE(udsota_bootloop_magic_valid(&s));
}

/* The magic check accepts only UDSOTA_BOOTLOOP_MAGIC and refuses NULL. */
static void test_magic_valid(void)
{
    udsota_bootloop_state_t good = at(0);
    udsota_bootloop_state_t bad = { .magic = UDSOTA_BOOTLOOP_MAGIC ^ 1u, .count = 0 };
    TEST_ASSERT_TRUE(udsota_bootloop_magic_valid(&good));
    TEST_ASSERT_FALSE(udsota_bootloop_magic_valid(&bad));
    TEST_ASSERT_FALSE(udsota_bootloop_magic_valid(NULL));
}

/* Runs the boot-loop breaker tests. */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_every_reset_reason_classified);
    RUN_TEST(test_power_on_clears_count);
    RUN_TEST(test_sw_reset_leaves_count);
    RUN_TEST(test_third_crash_ignores_config);
    RUN_TEST(test_sw_reset_keeps_config_ignored);
    RUN_TEST(test_healthy_clears_and_restarts_count);
    RUN_TEST(test_invalid_magic_resets_to_zero);
    RUN_TEST(test_invalid_magic_then_panic_counts_one);
    RUN_TEST(test_count_saturates);
    RUN_TEST(test_on_healthy_repairs_magic);
    RUN_TEST(test_magic_valid);
    return UNITY_END();
}
