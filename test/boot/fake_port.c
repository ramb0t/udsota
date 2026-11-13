/* fake_port: udsota_boot_port_* on a host (see fake_port.h). */
#include "fake_port.h"
#include <stdio.h>
#include <string.h>

fake_port_t fake;

#define BREACH(...)                                                                                       \
    do {                                                                                                 \
        fprintf(stderr, "fake_port: " __VA_ARGS__);                                                      \
        fputc('\n', stderr);                                                                             \
        fake.bad++;                                                                                      \
    } while (0)

static bool bus_ok(uint8_t bus, const char *what)
{
    if (bus == 0u || bus > FAKE_BUSES) {
        BREACH("%s on bus %u", what, bus);
        return false;
    }
    return true;
}

/* A call that may take time, which needs a clock read since the last one (udsota_boot_port_us). */
static void timed(const char *what)
{
    if (fake.timed++ != 0) {
        BREACH("%s with no clock read since the last call that may take time", what);
    }
}

static bool in_slot(uint32_t off, uint32_t len)
{
    return off <= fake.slot_size && len <= fake.slot_size - off;
}

void fake_geometry(uint32_t size, uint32_t write_unit, const uint32_t *sizes, size_t n)
{
    fake.slot_size = (size <= FAKE_SLOT_MAX) ? size : FAKE_SLOT_MAX;
    fake.write_unit = write_unit;
    fake.units = 0;
    for (uint32_t at = 0; at < fake.slot_size && fake.units < FAKE_UNITS_MAX; fake.units++) {
        fake.unit_at[fake.units] = at;
        at += sizes[(fake.units < n) ? fake.units : n - 1u];
    }
    fake.unit_at[fake.units] = fake.slot_size;
    memset(fake.slot, 0xFF, sizeof fake.slot);
    fake_erases_clear();
}

void fake_erases_clear(void)
{
    memset(fake.erased, 0, sizeof fake.erased);
}

void fake_reset(void)
{
    memset(&fake, 0, sizeof fake);
    fake.us = 0x00123456u;
    fake.erase_us = 20000u;
    fake.program_us = 2000u;
    fake.can_start_us = 10000u;
    fake_geometry(0x20000u, 2u, (const uint32_t[]){1024u}, 1u);
    fake.cause = UDSOTA_BOOT_RESET_POWER_ON;
    fake.devid_len = 12u;
    for (size_t i = 0; i < fake.devid_len; i++) {
        fake.devid[i] = (uint8_t)(0xD0u + i);
    }
}

/* ---- The port ---- */

uint32_t udsota_boot_port_us(void)
{
    fake.calls++;
    fake.timed = 0;
    return fake.us;
}

udsota_boot_reset_t udsota_boot_port_reset_cause(void)
{
    fake.calls++;
    fake.cause_calls++;
    return fake.cause;
}

uint16_t udsota_boot_port_keep_read(uint8_t word)
{
    fake.calls++;
    if (word >= UDSOTA_KEEP_WORDS) {
        BREACH("keep_read of word %u", word);
        return 0u;
    }
    return fake.keep[word];
}

void udsota_boot_port_keep_write(uint8_t word, uint16_t value)
{
    fake.calls++;
    if (word >= UDSOTA_KEEP_WORDS) {
        BREACH("keep_write of word %u", word);
        return;
    }
    if ((fake.keep_stuck & (1u << word)) == 0u) {
        fake.keep[word] = value;
    }
}

const uint8_t *udsota_boot_port_slot(void)
{
    fake.calls++;
    return fake.slot;
}

bool udsota_boot_port_flash_erase(uint32_t off, uint32_t len)
{
    fake.calls++;
    timed("flash_erase");
    fake.erase_calls++;
    fake.erase_off = off;
    fake.erase_len = len;
    if (!in_slot(off, len)) {
        BREACH("flash_erase of 0x%X bytes at 0x%X, outside the slot", len, off);
        return false;
    }
    if (fake.erase_fails) {
        return false;
    }
    for (size_t u = 0; u < fake.units; u++) {
        if (fake.unit_at[u] >= off && fake.unit_at[u] - off < len) {
            memset(fake.slot + fake.unit_at[u], 0xFF, fake.unit_at[u + 1u] - fake.unit_at[u]);
            fake.erased[u]++;
            fake.us += fake.erase_us;
        }
    }
    return true;
}

bool udsota_boot_port_flash_program(uint32_t off, const void *data, uint32_t len)
{
    fake.calls++;
    timed("flash_program");
    fake.program_calls++;
    fake.program_off = off;
    fake.program_len = len;
    if (!in_slot(off, len) || off % fake.write_unit != 0u || len % fake.write_unit != 0u) {
        BREACH("flash_program of 0x%X bytes at 0x%X: outside the slot or off the write unit", len, off);
        return false;
    }
    if (fake.program_fails) {
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (fake.slot[off + i] != 0xFFu) {
            BREACH("flash_program at 0x%X, not erased", off + i);
            return false;
        }
    }
    memcpy(fake.slot + off, data, len);
    if (fake.program_flips && len != 0u) {
        fake.slot[off + len - 1u] ^= 0x01u;
    }
    fake.us += fake.program_us;
    return true;
}

bool udsota_boot_port_can_start(uint8_t bus, uint16_t request_id)
{
    fake.calls++;
    timed("can_start");
    fake.start_calls++;
    (void)request_id;
    if (!bus_ok(bus, "can_start") || (fake.absent & (1u << bus)) != 0u) {
        return false;
    }
    fake.started |= (uint16_t)(1u << bus);
    fake.us += fake.can_start_us;
    return true;
}

void udsota_boot_port_can_stop(uint8_t bus)
{
    fake.calls++;
    timed("can_stop");
    if (bus_ok(bus, "can_stop")) {
        fake.started &= (uint16_t)~(1u << bus);
    }
}

bool udsota_boot_port_can_send(uint8_t bus, uint32_t id, const uint8_t *data, uint8_t len)
{
    fake.calls++;
    timed("can_send");
    fake.send_calls++;
    if (id > 0x7FFu || len > 8u) {
        BREACH("can_send of id 0x%X, %u bytes", id, len);
        return false;
    }
    if (!bus_ok(bus, "can_send") || fake.send_fails || (fake.started & (1u << bus)) == 0u) {
        return false;
    }
    if (fake.n_frames < FAKE_FRAMES_MAX) {
        fake_frame_t *f = &fake.frames[fake.n_frames++];
        f->bus = bus;
        f->id = id;
        f->len = len;
        memset(f->data, 0, sizeof f->data);
        memcpy(f->data, data, len);
        f->us = fake.us;
    }
    return true;
}

void udsota_boot_port_watchdog_start(uint32_t period_ms)
{
    fake.calls++;
    timed("watchdog_start");
    fake.wd_starts++;
    fake.wd_period = period_ms;
    if (period_ms == 0u) {
        BREACH("watchdog_start with period 0");
    }
}

void udsota_boot_port_watchdog_reload(void)
{
    fake.wd_reloads++;
}

void udsota_boot_port_reset(void)
{
    fake.calls++;
    fake.resets++;
    fake.reset_us = fake.us;
}

void udsota_boot_port_start_app(void)
{
    fake.calls++;
    fake.starts++;
    fake.start_us = fake.us;
    fake.started_at_start = fake.started;
    fake.wd_starts_at_start = fake.wd_starts;
}

size_t udsota_boot_port_device_id(uint8_t out[16])
{
    fake.calls++;
    memcpy(out, fake.devid, (fake.devid_len < 16u) ? fake.devid_len : 16u);
    return fake.devid_len;
}
