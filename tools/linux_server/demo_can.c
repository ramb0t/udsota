/* The Linux demo server's CAN backends; see demo_can.h. */
#define _GNU_SOURCE
#include "demo_can.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include "udsota_isotp.h"   /* UDSOTA_TX_RETRY */

/* Value of one hex digit, or -1. */
static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

/* Parses one pipe line `<id>#<data>` into *f; *extended is set for an 8-digit ID. False when malformed. */
static bool parse_line(const char *s, demo_frame_t *f, bool *extended)
{
    uint32_t id = 0;
    size_t digits = 0;
    while (hexval(*s) >= 0) {
        id = (id << 4) | (uint32_t)hexval(*s++);
        digits++;
    }
    if (*s++ != '#' || (digits != 3u && digits != 8u) || (digits == 3u && id > 0x7FFu) || id > 0x1FFFFFFFu) {
        return false;
    }
    *extended = (digits == 8u);
    f->id = (uint16_t)id;
    f->dlc = 0;
    while (*s != '\0' && *s != '\r' && *s != ' ') {
        if (*s == '.') {
            s++;
            continue;
        }
        const int hi = hexval(s[0]);
        const int lo = (hi >= 0) ? hexval(s[1]) : -1;
        if (lo < 0 || f->dlc == 8u) {
            return false;
        }
        f->data[f->dlc++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return true;
}

/* Logs one frame on stderr as `rx 710#...` or `tx 718#...`. */
static void log_frame(const char *dir, uint16_t id, const uint8_t *data, uint8_t len)
{
    char hex[17];
    for (uint8_t i = 0; i < len; i++) {
        snprintf(&hex[2 * i], 3, "%02X", data[i]);
    }
    hex[2 * len] = '\0';
    fprintf(stderr, "%s %03X#%s\n", dir, id, hex);
}

/* Hands one parsed frame on when it is a standard frame on req_id. */
static void deliver(demo_can_t *c, demo_frame_t *f, bool extended, void (*fn)(void *, const demo_frame_t *), void *ctx)
{
    if (extended || f->id != c->req_id) {
        return;
    }
    if (c->verbose) {
        log_frame("rx", f->id, f->data, f->dlc);
    }
    f->rx_us = c->now_us();
    fn(ctx, f);
}

/* Takes the pipe bytes in buf: complete lines are parsed and delivered, a partial one is kept for the next read. */
static int pipe_take(demo_can_t *c, const char *buf, size_t n, void (*fn)(void *, const demo_frame_t *), void *ctx)
{
    int frames = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] != '\n') {
            if (c->line_len < DEMO_CAN_LINE_MAX) {
                c->line[c->line_len++] = buf[i];
            } else {
                c->line_long = true;
            }
            continue;
        }
        c->line[c->line_len] = '\0';
        demo_frame_t f;
        bool ext = false;
        if (c->line_len == 0u || (c->line_len == 1u && c->line[0] == '\r')) {
            /* blank */
        } else if (c->line_long || !parse_line(c->line, &f, &ext)) {
            fprintf(stderr, "udsota_demo_server: dropped a malformed pipe line: %.*s\n", (int)c->line_len, c->line);
        } else {
            deliver(c, &f, ext, fn, ctx);
            frames++;
        }
        c->line_len = 0u;
        c->line_long = false;
    }
    return frames;
}

/* Opens the pipe backend; see demo_can.h. */
bool demo_can_open_pipe(demo_can_t *c, uint16_t req_id, uint32_t (*now_us)(void))
{
    memset(c, 0, sizeof *c);
    c->fd_in = STDIN_FILENO;
    c->fd_out = STDOUT_FILENO;
    c->req_id = req_id;
    c->now_us = now_us;
    return true;
}

/* Opens the SocketCAN backend; see demo_can.h. */
bool demo_can_open_socketcan(demo_can_t *c, const char *ifname, uint16_t req_id, uint32_t (*now_us)(void))
{
    memset(c, 0, sizeof *c);
    c->socketcan = true;
    c->req_id = req_id;
    c->now_us = now_us;
    const int fd = socket(PF_CAN, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, CAN_RAW);
    if (fd < 0) {
        fprintf(stderr, "udsota_demo_server: no CAN_RAW socket: %s\n", strerror(errno));
        return false;
    }
    const unsigned idx = if_nametoindex(ifname);
    if (idx == 0u) {
        fprintf(stderr, "udsota_demo_server: no CAN interface %s: %s\n", ifname, strerror(errno));
        close(fd);
        return false;
    }
    const struct can_filter flt = { .can_id = req_id, .can_mask = CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG };
    struct sockaddr_can addr = { .can_family = AF_CAN, .can_ifindex = (int)idx };
    if (setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, &flt, sizeof flt) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(stderr, "udsota_demo_server: cannot bind to %s: %s\n", ifname, strerror(errno));
        close(fd);
        return false;
    }
    c->fd_in = c->fd_out = fd;
    return true;
}

/* The descriptor to poll. */
int demo_can_fd(const demo_can_t *c)
{
    return c->fd_in;
}

/* Reads what is available; see demo_can.h. */
int demo_can_read(demo_can_t *c, void (*fn)(void *ctx, const demo_frame_t *f), void *ctx)
{
    if (!c->socketcan) {
        char buf[4096];
        const ssize_t n = read(c->fd_in, buf, sizeof buf);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
            return 0;
        }
        return (n <= 0) ? -1 : pipe_take(c, buf, (size_t)n, fn, ctx);
    }
    int frames = 0;
    for (;;) {
        struct can_frame cf;
        const ssize_t n = read(c->fd_in, &cf, sizeof cf);
        if (n < 0) {
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? frames : -1;
        }
        if ((size_t)n != sizeof cf || (cf.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) != 0u || cf.can_dlc > 8u) {
            continue;
        }
        demo_frame_t f = { .id = (uint16_t)(cf.can_id & CAN_SFF_MASK), .dlc = cf.can_dlc };
        memcpy(f.data, cf.data, cf.can_dlc);
        deliver(c, &f, (cf.can_id & CAN_EFF_FLAG) != 0u, fn, ctx);
        frames++;
    }
}

/* Sends one frame; see demo_can.h. */
int demo_can_send(void *ctx, uint16_t id, const uint8_t data[8], uint8_t len)
{
    demo_can_t *c = ctx;
    if (len > 8u) {
        return -1;
    }
    if (c->socketcan) {
        struct can_frame cf = { .can_id = id & CAN_SFF_MASK, .can_dlc = len };
        memcpy(cf.data, data, len);
        if (write(c->fd_out, &cf, sizeof cf) == (ssize_t)sizeof cf) {
            if (c->verbose) {
                log_frame("tx", id, data, len);
            }
            return 0;
        }
        return (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) ? UDSOTA_TX_RETRY : -1;
    }
    char line[32];
    int n = snprintf(line, sizeof line, "%03X#", id);
    for (uint8_t i = 0; i < len; i++) {
        n += snprintf(&line[n], sizeof line - (size_t)n, "%02X", data[i]);
    }
    line[n++] = '\n';
    for (int off = 0; off < n;) {
        const ssize_t w = write(c->fd_out, &line[off], (size_t)(n - off));
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return -1;                   /* the reader is gone: the frame is dropped */
        }
        off += (int)w;
    }
    if (c->verbose) {
        log_frame("tx", id, data, len);
    }
    return 0;
}

/* Closes the socket. */
void demo_can_close(demo_can_t *c)
{
    if (c->socketcan && c->fd_in >= 0) {
        close(c->fd_in);
        c->fd_in = c->fd_out = -1;
    }
}
