/* udsota boot: a resident bootloader core for single-slot microcontroller units, so the udsota client can update them
 * over CAN in the bootloader flow (docs/wire.md, "Bootloader flow"). This header is what a product writes against:
 * the configuration, the port functions the core calls, and the core's API. Experimental: outside udsota's 1.0
 * promise until a product has run on it in the field.
 *
 * A product's bootloader main():
 *
 *     board_init();                                   // clocks, pins, the keep words' store, the clock's counter
 *     udsota_boot_decision_t d = udsota_boot_init(&board_boot_cfg);
 *     log_decision(d);                                // optional: the core acts on d by itself
 *     for (;;) {
 *         board_drain_rx();                           // udsota_boot_rx() for each frame the board received
 *         udsota_boot_poll();                         // does not return once it resets or starts the app
 *     }
 *
 * Timing. The core never answers 0x78, so no call into it, and no port call it makes, takes longer than about 100 ms,
 * inside a tester's 150 ms P2; udsota_boot_init alone may take longer, for the boot check and starting every bus.
 * The port keeps these:
 *
 *   one 36             the erase units it starts times the erase time, plus its bytes over the write unit times the
 *                      program time, plus a compare of the block: within about 100 ms (UDS_SERVER_RECV_BUF_SIZE sets
 *                      the bytes, and flash_erase says which units a 36 starts)
 *   the slot's CRC     slot_size times the CRC routine's cycles a byte at the CPU's clock: within about 100 ms, since
 *                      the boot check and FF01 each run it whole in one call
 *   a port function    about 10 ms unless its comment gives more; can_start about 10 ms a bus
 *
 * The core keeps these, each from the moment given:
 *
 *   power-up window    window_ms, from init's clock read after it starts the buses
 *   idle exit          5100 ms in the default session, from the udsota_boot_rx call that carried the last tester
 *                      frame, once no request is in flight
 *   S3                 5100 ms outside the default session, from the last 10 or 3E that iso14229 served
 *   reset              60 ms, from the first poll that served 11 01 or F001
 *   answers            5 ms apart (P2); the first after each init, the handover's 50 02 included, about 6 ms after
 *                      it; the 10's answer gives P2* 5000 ms, covering the handover's reboot
 *   clock reads        never more than one port call plus a few milliseconds apart */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_wire.h"

/* ==== Configuration ====
 * iso14229's build definitions (the API below) size the core's buffers: UDS_SERVER_RECV_BUF_SIZE, at most 4095, is
 * also the 34's maxNumberOfBlockLength, answered as 74 20 <len>, so a 36 carries up to UDS_SERVER_RECV_BUF_SIZE - 2
 * data bytes. Everything else is a const struct that the product defines and passes to udsota_boot_init, which keeps
 * the pointer. Examples use udsota's example identity. */

typedef struct {
    /* Identity: the image rules (udsota_boot_internal.h) hold every image to it before anything is erased. */
    uint16_t    request_id;          /* 11-bit: physical requests and tester frames; example 0x710 */
    uint16_t    response_id;         /* 11-bit: every answer; example 0x718 */
    const char *product;             /* the project an image must carry, at most 32 characters; example "example" */
    uint8_t     hw_id;               /* the image descriptor's hw_id; example 1 */
    uint8_t     layout_id;           /* its partition_layout_id; example 1 */
    const char *boot_version;        /* this bootloader's version, NUL-terminated; example "1.0.0". F180
                                        (UDSOTA_DID_BOOT_VERSION) answers it followed by a space and "udsota/" with
                                        the udsota release the core was built from: "1.0.0 udsota/0.17.0". That
                                        answer must fit UDS_SERVER_SEND_BUF_SIZE, or F180 answers 0x14 */
    uint8_t     buses;               /* the board's CAN buses, 1 to 15, numbered 1..buses in every call. A bus the
                                        board may lack is still counted: can_start fails for it. Example 1 */

    /* The update slot. Every address the core uses is an offset from the slot's start; only the port knows where it
     * is, and the core knows nothing of its erase units. */
    uint32_t    slot_size;           /* bytes, a multiple of slot_write_unit: the largest image; example 0x20000 */
    uint16_t    slot_write_unit;     /* the programming unit in bytes, a power of two; example 2. The 34's
                                        memorySize is the container's multiple of 4, from the header's end up to
                                        slot_size; a 34 with any other answers 0x31 and leaves F1F1 as it was. Every
                                        36 but the last carries a multiple of the unit, and one that does not answers
                                        0x13, which ends the transfer with F1F1 reason UDSOTA_DL_ABORTED. The core
                                        pads the last one's tail to the unit with 0xFF before flash_program; F1F1's
                                        byte count is the data bytes the 36s carried, without that padding */
    uint32_t    image_header_offset; /* the image header's offset in an image (udsota_image.h), past the vector
                                        table; example 0x100 */

    /* Policy. The app keeps its own healthy delay, and the profile the client's wait; the core needs neither. */
    uint16_t    window_ms;           /* the power-up window after a power-on reset; 0 = none; example 100 */
    uint8_t     hold_after_starts;   /* 1 to 255: hold in the bootloader once the start count reaches this;
                                        example 5 */
    uint16_t    watchdog_ms;         /* nominal watchdog period, started just before the app; 0 = no watchdog;
                                        example 1000 */
} udsota_boot_cfg_t;

/* ==== The port ====
 * Link-time functions that the product defines, as with udsota_plat_*: there is no pointer table, and the host's fake
 * port (test/boot/fake_port.c) links in their place. The core calls them from udsota_boot_init, udsota_boot_poll and
 * udsota_boot_rx, all on the main loop and never from an interrupt.
 *
 * The port never reads the configuration: everything a function needs arrives as its arguments. Its flash bounds are
 * its own constants, which is what makes them a guard independent of the core. Each keeps to the timing table above,
 * and need not reload the watchdog: the core does that between calls.
 *
 * The core defines the four hooks that iso14229 built with UDS_SYS=UDS_SYS_CUSTOM requires, so the product must not:
 * UDSMillis(), isotp_user_get_us(), isotp_user_debug() (a no-op) and isotp_user_send_can(), which sends through
 * udsota_boot_port_can_send on the bus of the request being served and ignores iso14229's forced arg. */

/* -- Clock -- */

/* Free-running microseconds that wrap at 2^32 and keep counting while a flash erase stalls the CPU; the board starts
 * the counter behind it before udsota_boot_init. This is the only clock. Its value at init is arbitrary: the core uses
 * differences only, adding them, the remainder carried, into UDSMillis()'s milliseconds, which wrap at 2^32 (us / 1000
 * would wrap after 71.6 minutes and break iso14229's timers). isotp_user_get_us() returns it as it is. The core reads
 * it in every call, and within one between any two port calls that may take time (flash, CAN and watchdog_start), and
 * never waits on it, so a port that extends a shorter counter may rely on the timing table's gap between reads. It
 * returns at once and cannot fail. */
uint32_t udsota_boot_port_us(void);

/* -- Reset cause and keep words -- */

/* Why this boot happened. */
typedef enum {
    UDSOTA_BOOT_RESET_POWER_ON = 0, /* power-on, or brown-out where the part tells it apart: clears the start count
                                       and opens the power-up window */
    UDSOTA_BOOT_RESET_PIN,          /* the reset pin and nothing else: clears the start count, opens no window */
    UDSOTA_BOOT_RESET_OTHER,        /* anything else, no flag at all included: the start count stands */
} udsota_boot_reset_t;

/* Reads the reset flags, clears them, and returns the cause: POWER_ON when its flag is set; PIN when the pin's flag is
 * the only one, since on many parts the pin is driven on every reset; else OTHER. The core calls it once in each
 * udsota_boot_init whose configuration is good. It returns at once and cannot fail. */
udsota_boot_reset_t udsota_boot_port_reset_cause(void);

/* The UDSOTA_KEEP_WORDS 16-bit words of udsota_wire.h, which hold the handover and the start count across a software,
 * pin and watchdog reset; a power-on may lose them, since it clears the start count anyway. word is 0 to 2, a
 * UDSOTA_KEEP_WORD_* index; the core never passes another. A write is read back exactly by the next read, before and
 * after a reset. The app writes the same words through udsota_app_port_keep_write (udsota_app.h).
 * The core reads them in udsota_boot_init, and writes them there (the handover's clear, and the start count as the
 * boot rules leave it), just before each start of the app (the start count plus one) and on 11 01 and F001 (the start
 * count's clear). Both return at once and have no failure return. A store that does not keep a write is safe: a
 * handover mark that does not read back cleared is not taken, so it cannot make every boot a handover; a start count
 * that does not keep its increment never holds the unit, and never stops the app starting; a clear that does not keep
 * leaves the count as it was. A part with no store that survives a reset can use a .noinit RAM area: after a power-on
 * random contents almost never pass the mark, its read-back and the start count's marker, and the count clears on a
 * power-on regardless. */
uint16_t udsota_boot_port_keep_read(uint8_t word);
void     udsota_boot_port_keep_write(uint8_t word, uint16_t value);

/* -- The update slot -- */

/* The slot's bytes, always readable for slot_size: a part with mapped flash returns the slot's address. The slot
 * starts on an erase-unit boundary. The core calls it each time it reads the slot: the boot check and FF01 read the
 * image header and run the CRC through it, a 36 compares what it programmed, and F189 and F1F3 read the installed
 * image's version and image_id. On a part whose read of an interrupted write faults (ECC flash), the port keeps every
 * read safe (boot/README.md). */
const uint8_t *udsota_boot_port_slot(void);

/* Erases every erase unit whose first byte lies in [off, off + len). The core calls it in a 36, with the range that 36
 * programs, just before programming it. A download writes from offset 0 upward, so each unit is erased once, before
 * its first byte is programmed, and units need not be of one size. It blocks until done, within the timing table's
 * 36. Returns true, or false for a range outside the slot or a failure the part reports; the core then answers that
 * 36 with 0x72, F1F1 reason UDSOTA_DL_FLASH_ERROR. */
bool udsota_boot_port_flash_erase(uint32_t off, uint32_t len);

/* Programs len bytes at off, both multiples of slot_write_unit, into units erased in this download. data may be
 * unaligned, since it points into iso14229's receive buffer. The core calls it in a 36, just after flash_erase for the
 * same range, and then compares the slot with data, so it need not verify. Returns true, or false for a range outside
 * the slot or a failure the part reports; the core then answers that 36 as for a failed erase, and so it does when the
 * comparison fails. Both flash functions refuse any range outside the slot, and that check stays in the port: it is
 * what stops a core bug writing the bootloader. */
bool udsota_boot_port_flash_program(uint32_t off, const void *data, uint32_t len);

/* -- CAN -- */

/* Starts bus (1..buses) at the port's own rate for it, accepting 11-bit frames on request_id, or every frame if the
 * hardware cannot filter. Received frames wait in the controller, or in a queue its interrupt fills, until the main
 * loop passes them to udsota_boot_rx. Starting a running bus restarts it. The core calls it in udsota_boot_init, for
 * the handed-over bus or for every bus, and for every bus each time it returns to listening. Returns true once the bus
 * runs, or false when the bus is not fitted or has not started within its time in the timing table, leaving it
 * stopped with its interrupt off. The core treats a bus that did not start as absent, and a handover to it as not
 * decoding. */
bool udsota_boot_port_can_start(uint8_t bus, uint16_t request_id);

/* Stops bus: no more frames are received from it or sent on it. It is idempotent, and harmless on a bus that never
 * started. The core calls it on every other bus when a tester frame locks one, and on every bus before it returns to
 * listening and before start_app, so the port undoes only what the board's own init did. */
void udsota_boot_port_can_stop(uint8_t bus);

/* Sends one classic 11-bit frame (id <= 0x7FF, len <= 8) on bus: an answer's, from inside udsota_boot_poll, or a flow
 * control, from inside udsota_boot_rx. When no transmit slot is free it waits for one, with a bound of its own, rather
 * than refusing: iso14229 drops an answer whose single or first frame fails to send. It does not wait for the frame to
 * leave. Returns true once the controller holds the frame, or false if the wait runs out or the bus is not running;
 * that answer is then lost, and the next request is still served. */
bool udsota_boot_port_can_send(uint8_t bus, uint32_t id, const uint8_t *data, uint8_t len);

/* -- Watchdog, reset, jump, identity -- */

/* Starts the watchdog with a nominal period_ms (cfg.watchdog_ms, never 0), from its first period on (boot/README.md
 * gives the order of writes on an STM32F1), stopped while a debugger halts the core if the part allows. The core calls
 * it once per start of the app, after writing the start count and stopping the buses, just before start_app, so an app
 * that hangs before its own watchdog setup is still reset. With watchdog_ms 0 it is not called. Nothing in the core
 * depends on the watchdog running. */
void udsota_boot_port_watchdog_start(uint32_t period_ms);

/* Reloads the watchdog. The core calls it in every poll and, within a call, beside each clock read between port
 * calls. On a part whose watchdog may run from reset, that keeps the bootloader alive; where it does not run, the
 * reload does nothing. It returns at once and cannot fail. */
void udsota_boot_port_watchdog_reload(void);

/* Resets the chip. The core calls it only from udsota_boot_poll, after iso14229's poll has returned: 60 ms after the
 * first poll that served 11 01 or F001, and when a session exit's decision is to start the app. The core has already
 * written the words it needs. On a target it does not return. If it returns, the core is stopped: udsota_boot_poll
 * only reloads the watchdog and udsota_boot_rx ignores frames, until udsota_boot_init is called again. A host fake
 * returns, which is how a test sees the reset. */
void udsota_boot_port_reset(void);

/* Starts the application. The core calls it only from udsota_boot_poll, after iso14229's poll has returned, once it has
 * checked the app, written the start count plus one, stopped every bus and started the watchdog. The port leaves the
 * chip as after a reset, as far as the port can, so that an app never depends on which bootloader started it, and
 * branches to the app's reset handler. At the least: every interrupt line disabled and its pending bit cleared;
 * SysTick stopped, and neither it nor PendSV pending; PRIMASK 0, and BASEPRI and FAULTMASK 0 where the part has them;
 * privileged thread mode on the main stack, with the stack pointer loaded from word 0 of the app's vector table; and
 * the vector table base, where the part has one, at that table. The watchdog keeps running. On a target it does not
 * return. If it returns, the core is stopped, as when udsota_boot_port_reset returns. */
void udsota_boot_port_start_app(void);

/* F18C: the device's ID, 1 to 16 bytes into out; returns the length. The core calls it when F18C is read. It returns at
 * once and has no failure return: the core answers F18C with the bytes it gives, so a length outside 1..16 is a port
 * bug. */
size_t udsota_boot_port_device_id(uint8_t out[16]);

/* ==== The API ====
 * Only what a product calls: init, poll and rx.
 *
 * iso14229 is compiled by the product, unmodified, with:
 *  - UDS_SYS=UDS_SYS_CUSTOM, which selects isotp-c and requires the core's UDSMillis;
 *  - ISO_TP_FRAME_PADDING (0xAA);
 *  - NDEBUG, which leaves out iso14229's asserts and their libc path;
 *  - -fwrapv on iso14229.c: isotp-c compares its microsecond timers by a signed subtraction, which GCC and Clang
 *    otherwise fold, ending a transfer in flight whenever the clock passes 2^31;
 *  - UDS_SERVER_RECV_BUF_SIZE, the request buffer and so the longest 36, 4095 at most (example 1026);
 *  - UDS_SERVER_SEND_BUF_SIZE, the answer buffer, at least 35 for F1F3's answer (example 64); it also sizes the answer
 *    buffer of the core's transport, and a 22 whose answer would not fit it gets iso14229's 0x14;
 *  - ISO_TP_DEFAULT_BLOCK_SIZE, _ST_MIN_US and _RESPONSE_TIMEOUT_US, which are the product's choice (example 8, 0,
 *    1000000).
 * Every definition that changes a struct layout must reach iso14229.c and udsota_boot.c identically, and udsota_boot.c
 * stops the build with #error when a definition it depends on is missing. The core owns the UDSServer_t and its own
 * transport, a UDSTp_t over one IsoTpLink in place of UDSTpISOTpC_t. It makes every write to their state, and the
 * product never touches iso14229. */

/* What udsota_boot_init decided, in the order the boot rules apply. */
typedef enum {
    UDSOTA_BOOT_DECIDE_HANDOVER = 0, /* serves on the handed-over bus only and answers the 10 02 the app took */
    UDSOTA_BOOT_DECIDE_NO_APP,       /* no valid app: listens on every bus and stays */
    UDSOTA_BOOT_DECIDE_HELD,         /* start count >= hold_after_starts: listens on every bus, stays until 11 01,
                                        F001, a power-on or a pin reset */
    UDSOTA_BOOT_DECIDE_WINDOW,       /* power-on with window_ms > 0: listens on every bus for window_ms, then starts
                                        the app unless a tester frame held it, a download has begun or the session is
                                        no longer the default; in those two it listens on */
    UDSOTA_BOOT_DECIDE_START_APP,    /* the first udsota_boot_poll() starts the app; no bus has been started */
    UDSOTA_BOOT_DECIDE_BAD_CFG,      /* cfg breaks an invariant; nothing is served, and udsota_boot_poll() only
                                        reloads the watchdog. A host test catches it at once */
} udsota_boot_decision_t;

/* A boot. Call it after the board's own setup and before udsota_boot_poll or udsota_boot_rx. It may be called again at
 * any time, and each call is a boot: it resets every piece of core state, relies on no zeroed .bss, and may be given
 * another configuration. It is the one call that may take longer than about 100 ms. It:
 *  - checks cfg, and decides BAD_CFG unless every one of these holds: cfg is not NULL; request_id and response_id are
 *    at most 0x7FF and differ; buses is 1 to 15; product is not NULL and at most 32 characters; boot_version is not
 *    NULL; hold_after_starts is not 0; slot_write_unit is a power of two; slot_size is a multiple of it and at least
 *    image_header_offset + UDSOTA_BARE_HDR_LEN; UDS_SERVER_RECV_BUF_SIZE - 2 is a multiple of it and at least
 *    image_header_offset + UDSOTA_BARE_HDR_LEN, so a full first 36 carries the whole header. On BAD_CFG it calls no
 *    port function but udsota_boot_port_watchdog_reload, so the reset flags and the keep words stay as they are;
 *  - reads the reset cause;
 *  - takes the handover words;
 *  - checks the app (the boot check): magic UDSOTA_BARE_HDR_MAGIC, header_version at least 1, no bit of
 *    UDSOTA_BARE_HDR_FLAGS_MUST set, an image_length that is a multiple of 4 from the header's end up to slot_size,
 *    and the CRC over it, reloading the watchdog. It applies no project, board, layout or ID rule;
 *  - reads and updates the start count;
 *  - decides.
 * For every decision but START_APP and BAD_CFG it then starts the buses it will listen on and sets up iso14229, so a
 * bus is running before the server is first polled, and reads the clock: window_ms runs from that read, so the boot
 * check's time is not part of it. On a handover the core's own transport hands iso14229 the 10 02 the app took, as the
 * first request it receives; that 10 02 counts as a tester frame received at that clock read. cfg must outlive the
 * core (a static const). */
udsota_boot_decision_t udsota_boot_init(const udsota_boot_cfg_t *cfg);

/* Call from the main loop as often as it can run. The product's own work between two calls stays under 5 ms
 * (iso14229's UDSServerPoll contract). One call reloads the watchdog, polls the server, ages iso14229's timers so a
 * unit that stays in its bootloader for weeks still answers at once, keeps the F1F1 bookkeeping, and applies the
 * session rules of the timing table: the window, the idle exit, S3 and the pending reset. Both session exits, the idle
 * exit and S3's expiry, apply the boot rules again with no handover and cause OTHER (udsota_boot_internal.h) and reset
 * exactly when they answer START_APP; otherwise the core returns to listening on every bus. On a target it does not
 * return once it resets or starts the app. */
void udsota_boot_poll(void);

/* One received frame, which the port passes only when it is an 11-bit one. The product calls it for each frame the
 * board received, whether the loop polled the controller for it or an interrupt queued it, in arrival order, from the
 * main loop only: never from an interrupt, and never from inside a port function. It feeds isotp-c, which may send a
 * flow control from inside this call. bus is 1..cfg.buses, id the identifier, len 0..8. The core reads the clock at
 * the call, and that is the frame's time for the window and the idle exit. The core ignores:
 *  - a bus outside 1..cfg.buses, a len over 8, and IDs other than request_id;
 *  - frames from any bus but the one a tester frame locked;
 *  - before a lock, frames from any other bus from the first frame of a request until its whole answer has been
 *    handed to can_send, so each request is answered on the bus it came from;
 *  - every frame while the core is stopped, before the first poll of a START_APP, and after BAD_CFG.
 * A tester frame is a frame whose first bytes are exactly 02 10 02, 02 3E 00 or 02 3E 80. It holds the window,
 * restarts the idle exit's time, and locks its bus, stopping the others until the core next returns to listening.
 * Only a tester frame locks a bus. */
void udsota_boot_rx(uint8_t bus, uint32_t id, const uint8_t *data, uint8_t len);
