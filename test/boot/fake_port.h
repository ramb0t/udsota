/* fake_port: every udsota_boot_port_* function on a host, for the bootloader core's tests and its host process
 * (test/e2e/boot_server.c). A RAM slot with erase units the core does not know, keep words, a reset cause, CAN buses
 * whose sent frames are captured, and a clock the caller advances. It counts the port calls, and the flash, the keep
 * words, a bus and can_send can be made to fail. reset and start_app record the call and return, which stops the core
 * until udsota_boot_init is called again: that is a reboot.
 *
 * It also checks the core against the port's contract, counting each breach in fake.bad and naming it on stderr: a
 * flash range outside the slot or off the write unit, programming bytes that are not erased, a keep word past 2, a
 * frame that is not a classic 11-bit one, a bus outside 1..FAKE_BUSES, a watchdog period of 0, and two calls that may
 * take time (flash, CAN, watchdog_start) with no clock read between them. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_boot.h"

#define FAKE_SLOT_MAX   0x40000u
#define FAKE_UNITS_MAX  1024u
#define FAKE_FRAMES_MAX 8192u
#define FAKE_BUSES      15u

typedef struct {
    uint8_t  bus;
    uint32_t id;
    uint8_t  len;
    uint8_t  data[8];
    uint32_t us;                     /* the clock when it was sent */
} fake_frame_t;

typedef struct {
    uint32_t us;                     /* the clock udsota_boot_port_us returns; the caller advances it */
    uint32_t erase_us, program_us;   /* what each erase unit and each program call add to it */
    uint32_t can_start_us;           /* and what each can_start that starts a bus adds */
    int      calls;                  /* every port call but watchdog_reload */
    int      timed;                  /* calls that may take time since the last clock read */

    /* The slot. */
    uint32_t slot_size, write_unit;
    uint32_t unit_at[FAKE_UNITS_MAX + 1u];   /* each erase unit's first offset, ascending from 0, then slot_size */
    size_t   units;
    uint8_t  slot[FAKE_SLOT_MAX];
    uint16_t erased[FAKE_UNITS_MAX];         /* erases of each unit since fake_reset or fake_erases_clear */
    int      erase_calls, program_calls;
    uint32_t erase_off, erase_len, program_off, program_len;   /* the last erase's and program's range */
    bool     erase_fails, program_fails, program_flips;   /* while set: a call fails, or programs a bit flipped */

    /* Reset cause and keep words. */
    udsota_boot_reset_t cause;
    int      cause_calls;
    uint16_t keep[UDSOTA_KEEP_WORDS];
    uint16_t keep_stuck;                     /* bit w: a write to word w does not keep */

    /* CAN. */
    uint16_t started;                        /* bit b: bus b runs */
    uint16_t absent;                         /* bit b: bus b does not start */
    int      start_calls;
    bool     send_fails;
    int      send_calls;
    fake_frame_t frames[FAKE_FRAMES_MAX];    /* every frame can_send took, in order */
    size_t   n_frames;

    /* Watchdog, reset, start, identity. */
    int      wd_starts, wd_reloads;
    uint32_t wd_period;
    int      resets, starts;
    uint32_t reset_us, start_us;             /* the clock at the last reset and start_app */
    uint16_t started_at_start;               /* the buses running when start_app was called */
    int      wd_starts_at_start;
    uint8_t  devid[16];
    size_t   devid_len;                      /* device_id's return; it copies at most 16 bytes */

    int      bad;                            /* breaches of the port's contract */
} fake_port_t;

extern fake_port_t fake;

/* The power-on state: the slot erased (0xFF), 0x20000 bytes with a write unit of 2 and 1 KB erase units, the keep words
 * 0, cause POWER_ON, every bus fitted, a 12-byte device ID, 20 ms an erase unit, 2 ms a program call and 10 ms a bus
 * started, no faults, nothing counted. */
void fake_reset(void);

/* The slot's geometry: size bytes, a write unit, and erase units of sizes[0], sizes[1], ... from offset 0, the last
 * size repeating to the slot's end. The slot is erased. */
void fake_geometry(uint32_t size, uint32_t write_unit, const uint32_t *sizes, size_t n);

/* Clears fake.erased. */
void fake_erases_clear(void);
