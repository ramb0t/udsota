/* The Linux demo server's CAN backends: a SocketCAN raw socket on an interface, or a frame pipe on
 * stdin/stdout for hosts with no kernel CAN support.
 *
 * Pipe format: one frame per line, in can-utils' compact form `<id>#<data>`: a 3-digit hex ID (an 8-digit
 * one is extended, and never a request), then 0 to 8 data bytes as hex pairs, optionally split by '.'
 * (`710#0322F18C`, `710#03.22.F1.8C`). Blank lines are skipped and malformed ones are reported on stderr
 * and dropped. Every frame the server sends is written as one line, with its 8 bytes in upper case
 * (`718#0562F18C020000AA`). stdin's EOF stops the server. Host only (Linux). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DEMO_CAN_LINE_MAX 64u   /* longest pipe line kept; a longer one is malformed */

typedef struct {
    uint16_t id;
    uint8_t  dlc;
    uint8_t  data[8];
    uint32_t rx_us;              /* arrival, on the caller's clock */
} demo_frame_t;

typedef struct {
    bool     socketcan;          /* false: the stdin/stdout pipe */
    int      fd_in, fd_out;      /* SocketCAN: the raw socket, twice */
    uint16_t req_id;             /* the only ID handed on */
    bool     verbose;            /* log every frame on stderr */
    char     line[DEMO_CAN_LINE_MAX + 1u];
    size_t   line_len;
    bool     line_long;          /* the pipe line being read is already too long */
    uint32_t (*now_us)(void);    /* the arrival stamp */
} demo_can_t;

/* Opens the pipe backend on stdin and stdout. */
bool demo_can_open_pipe(demo_can_t *c, uint16_t req_id, uint32_t (*now_us)(void));
/* Opens a non-blocking CAN_RAW socket on ifname that receives only standard frames on req_id. False (and a
 * message on stderr) when the interface or PF_CAN is missing. */
bool demo_can_open_socketcan(demo_can_t *c, const char *ifname, uint16_t req_id, uint32_t (*now_us)(void));
/* True only when ifname is a vcan interface (its rtnetlink link kind is "vcan"); false for a real CAN interface,
 * an unknown name or any netlink error. */
bool demo_can_is_vcan(const char *ifname);
/* The descriptor to poll for input. */
int  demo_can_fd(const demo_can_t *c);
/* Reads every frame available now and calls fn for each standard frame on req_id. Returns the frames read, or
 * -1 at EOF or on a read error (the server stops). */
int  demo_can_read(demo_can_t *c, void (*fn)(void *ctx, const demo_frame_t *f), void *ctx);
/* udsota_can_t.send with ctx a demo_can_t: 0 sent, UDSOTA_TX_RETRY when the socket's queue is full, -1 dropped. */
int  demo_can_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len);
/* Closes the socket; the pipe's descriptors stay open. */
void demo_can_close(demo_can_t *c);
