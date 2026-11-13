# udsota boot

A resident bootloader core for a microcontroller unit with one app slot, so that the udsota client updates it over CAN in the bootloader flow ([docs/wire.md](../docs/wire.md#bootloader-flow)). It is one C11 file, `udsota_boot.c`, on unmodified iso14229, with no malloc and no RTOS; the app's side is the header-only `udsota_app.h` at the repository root.

It is experimental: outside udsota's 1.0 promise until a product has run on it in the field. So far it has run on one STM32F1 unit on a bench.

## What a product supplies

A product writes three things against `udsota_boot.h`, whose comments are the contract: a `const udsota_boot_cfg_t` with the unit's identity, slot and policy; the port, the `udsota_boot_port_*` functions the core calls, linked in at build time; and a main loop that calls `udsota_boot_init` once, then passes each received frame to `udsota_boot_rx` and calls `udsota_boot_poll`, as the header's example `main()` does. The board starts the port's clock before init; on a Cortex-M3 or M4 that is the DWT cycle counter (TRCENA, then CYCCNTENA), counted into microseconds with the remainder carried.

The board also resets every CAN controller it owns before `udsota_boot_init`. A controller that the chip's reset does not reach keeps running through a software reset, so after a handover it would still be in the app's mode with the app's filters, acknowledging frames; check which of yours survive a reset.

A port may poll its CAN controllers from the main loop instead of taking interrupts: each controller's hardware filter accepts only the request ID, the loop reads the controllers and calls `udsota_boot_rx`, and the controllers' own receive buffers are the queue. Nothing arrives during a flash erase, since a tester sends its next frame only after an answer or a flow control. Where the hardware filters, polling is the simpler choice: there is no interrupt to set up, and none for `start_app` to undo. Keep the loop's round shorter than a burst of consecutive frames takes to fill a controller's buffer, or ask for an STmin (`ISO_TP_DEFAULT_ST_MIN_US`) that spaces them.

F180 answers the product's `boot_version`, then `udsota/` and the udsota release the core was built from. That release changes only when udsota cuts one, so a core built from a commit between releases names the last release: only a release tag names a core, and a product that ships pins one.

## Building

Compile `udsota_boot.c` and `iso14229/iso14229.c` as they are, with `-I` for the repository root, `boot/` and `iso14229/`, and on both the same definitions, which `udsota_boot.h` lists under "The API"; `udsota_boot.c` stops the build with `#error` when one it depends on is missing. The image then needs `memcpy`, `memmove`, `memset`, `memcmp` and `strlen` from libc, `memcpy` and `memmove` for iso14229.

## Timing

The core never answers 0x78, so every call into it but `udsota_boot_init`, port calls included, must end within about 100 ms, inside a tester's 150 ms P2. Two budgets decide which parts that allows.

A `36` costs the erase units it starts times the erase time, plus its bytes over the write unit times the program time, plus a compare of the block. On an STM32F1 with 1 KB pages, a block of 1024 data bytes (`UDS_SERVER_RECV_BUF_SIZE` 1026) starts one page (20 to 40 ms to erase) and programs 512 half-words (40 to 70 µs each): under 80 ms. A smaller `UDS_SERVER_RECV_BUF_SIZE` shortens it. Measured on an STM32F1 with 2 KB pages, such a block took 32 to 54 ms from its last frame to its answer, 47 at the median, and a download ran at about 4.7 KB a second at any bit rate, since flash and STmin set the pace.

The boot check and FF01 cost the CRC's cycles a byte times `slot_size`, the largest image, at the port's clock. Measured on a Cortex-M3 at 72 MHz with two flash wait states, the core's loop takes 0.35 µs a byte, about 25 cycles, so a 128 KB slot takes about 45 ms and 100 ms covers about 280 KB; at an 8 MHz reset clock a 128 KB slot would take several hundred milliseconds. The bootloader must therefore run from its fast clock.

That admits parts that erase in pages of a few KB within tens of milliseconds and program a word in tens of microseconds: STM32F0, F1, F3, G0, G4 and L4, and their like from other vendors. It rules out parts that erase in sectors of 16 KB or more, which take hundreds of milliseconds to seconds, STM32F2, F4, F7 and H7 among them: a `36` that starts such a sector cannot answer in time, and the core has no start-and-poll erase.

## STM32F1 watchdog

Start the independent watchdog in this order: KR 0xCCCC, KR 0x5555, PR, RLR, a bounded wait for PVU and RVU, then KR 0xAAAA, written whether or not the wait succeeded. PR and RLR take writes only after the 0x5555, and a wait before the 0xCCCC can hang, since the LSI starts with the watchdog. With that order the first full period is already the nominal one, and the LSI's spread makes a nominal 2 s period 1.33 to 2.67 s, so the app reloads well inside 1.33 s. A watchdog started by the option bytes runs from reset at the full count and the reset prescaler, about 273 ms at worst, so every wait in a bootloader must reload inside that, the board's own start-up included.

## What `start_app` leaves behind

`udsota_boot_port_start_app` does at least what its comment in `udsota_boot.h` lists. So that an app never depends on which bootloader started it, the port also puts the clock tree back on its reset oscillator with the PLLs off and resets the peripherals the board used, except the store that holds the keep words.

## Flash with ECC

A part whose flash has ECC (STM32G0, G4 and L4 among them) faults when it reads a word whose programming a reset or power cut interrupted. Its port keeps the slot readable for `slot_size`, as `udsota_boot_port_slot` promises, by erasing the erase unit that faulted, in its fault handler or at the next boot before `udsota_boot_init`, so the read returns erased bytes. The boot check then fails, the unit has no valid app and stays in its bootloader, and the next download recovers it.

## Size

With arm-none-eabi-gcc 14.3.1 for Cortex-M3, `-Os -ffunction-sections -fdata-sections` and the tests' definitions, `udsota_boot.o` is 2,879 bytes of text, 64 of data (the CRC table, kept in RAM so its reads wait on no flash wait state) and 2,448 of bss (the server, the transport and their buffers). Linked with iso14229 under `--gc-sections` into a minimal image, the two add about 10.7 KB of flash and 2.5 KB of RAM to an empty one, the port aside. CI holds the core's text to that size plus about a fifth.

## The app

The app's one include path is the repository root, and it compiles no udsota source. It places its header once with `UDSOTA_IMAGE_HEADER(hw_id, layout_id, request_id, response_id, "version", "project")` from `udsota_image.h`. Its linker script puts the section `.udsota_image_header` at `image_header_offset` into the image, past the vector table, with `KEEP`, and ends the image on a 4-byte boundary. After the build, `udsota stamp app.bin`, or `udsota.image.stamp(data, header_offset)` from a post-build script, writes the image's length, ID and CRC. The stamped `.bin` is what a debugger loads and the client sends: an unstamped image fails the boot check, and the client refuses it.

The app then keeps the duties `udsota_app.h` lists, with its helpers for the two answers, the handover and the healthy mark. One of them is easy to break by accident: nothing before the healthy mark may wait without a limit, the print path included. A `printf` that mirrors to the debug trace port with CMSIS's `ITM_SendChar` waits for ever when a debugger has left the port enabled and nothing drains it; behind the watchdog that is a reset at every start, and the bootloader holds the unit. If its start-up code points VTOR at the start of flash, it points VTOR at its own vector table again; a part with no VTOR, such as a Cortex-M0, copies its vectors to RAM and remaps RAM to address 0 instead.

## Tests and the host process

```sh
cmake -S . -B build && cmake --build build -j && ctest --test-dir build -R 'udsota_(boot|app)|headers'
python -m pytest client/tests/test_e2e_boot.py     # runs build/udsota_boot_server, or $UDSOTA_BOOT_SERVER
```

`test/test_udsota_boot.c` drives the core frame by frame through the fake port in `test/boot/`; `test_udsota_boot_pure.c` covers the CRC, the image rules, the boot rules and an image the client stamped; `test_udsota_app.c` covers the app's side. `udsota_boot_server` (`test/e2e/boot_server.c`) runs the core and a stand-in app as a Linux process, with CAN frames as text lines on stdin and stdout, which is the pipe `test_e2e_boot.py` drives the client over. It takes a unit's identity and geometry as arguments, so another product's profile and stamped image run against it unchanged:

```sh
build/udsota_boot_server --req-id 0x7A0 --resp-id 0x7A8 --product widget --hw-id 7 --layout-id 3 \
    --slot-size 0x30000 --header-offset 0x180 --write-unit 8 --image widget.bin
```

`DemoServer` and `run_cli` in `client/tests/demo_server.py` put the client on that pipe, as `test_identity_passed_as_arguments` does. The comment at the top of `test/e2e/boot_server.c` lists every option, the injected faults among them.
