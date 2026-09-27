/* Shared host-test mock for the udsota server: a gate that answers per op and counts what it was
 * asked, a phase recorder, a reset hook, an app DID hook and the engine's status source. Header-only and all
 * static inline, so a test that uses part of it still builds under -Werror. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "udsota.h"

#define UDSOTA_MOCK_OPS      8u    /* udsota_op_t runs 1..7; index 0 is unused */
#define UDSOTA_MOCK_LOG_MAX  64u

typedef struct {
    uint8_t         gate_nrc[UDSOTA_MOCK_OPS];     /* what gate(op) answers: 0 allows */
    unsigned        gate_calls[UDSOTA_MOCK_OPS];   /* times gate(op) was asked */
    unsigned        gate_total;                    /* every gate call */
    int             phases[UDSOTA_MOCK_LOG_MAX];   /* every phase the hook reported, in order */
    size_t          phase_n;
    udsota_status_t status;                        /* engine.status answer (udsota_mock_status) */
    bool            reset_ok;                      /* hooks.reset result */
    unsigned        resets;                        /* hooks.reset calls */
    size_t        (*app_did)(uint16_t did, uint8_t *buf, size_t max);   /* the test's own DIDs; NULL = none */
    unsigned        did_reads;                     /* hooks.did_read calls */
    uint16_t        last_did;                      /* DID of the last hooks.did_read call */
    void           *last_ctx;                      /* ctx the last gate or did_read call got */
} udsota_mock_t;

/* Clears m: the gate allows everything, slot 0 runs VALID and is the boot slot, a reset succeeds. */
static inline void udsota_mock_clear(udsota_mock_t *m)
{
    memset(m, 0, sizeof *m);
    m->status.running_slot = UDSOTA_SLOT_OTA0;
    m->status.running_state = UDSOTA_IMG_VALID;
    m->status.boot_slot = UDSOTA_SLOT_OTA0;
    m->status.other_slot_state = UDSOTA_OTHER_EMPTY;
    m->reset_ok = true;
}

/* hooks.gate: counts the question and answers gate_nrc[op]; an op outside udsota_op_t gets 0x10 so the test fails. */
static inline uint8_t udsota_mock_gate(void *ctx, udsota_op_t op)
{
    udsota_mock_t *m = ctx;
    m->last_ctx = ctx;
    m->gate_total++;
    if ((unsigned)op == 0u || (unsigned)op >= UDSOTA_MOCK_OPS) {
        return UDSOTA_NRC_GENERAL_REJECT;
    }
    m->gate_calls[op]++;
    return m->gate_nrc[op];
}

/* hooks.phase: appends p to the log. */
static inline void udsota_mock_phase(void *ctx, udsota_phase_t p)
{
    udsota_mock_t *m = ctx;
    if (m->phase_n < UDSOTA_MOCK_LOG_MAX) {
        m->phases[m->phase_n++] = (int)p;
    }
}

/* hooks.reset: counts the restart and returns reset_ok (a real restart never returns). */
static inline bool udsota_mock_reset_hook(void *ctx)
{
    udsota_mock_t *m = ctx;
    m->resets++;
    return m->reset_ok;
}

/* hooks.did_read: counts the call and asks the test's app_did, if any; 0 = no such DID (NRC 0x31). */
static inline size_t udsota_mock_did_read(void *ctx, uint16_t did, uint8_t *buf, size_t max)
{
    udsota_mock_t *m = ctx;
    m->last_ctx = ctx;
    m->did_reads++;
    m->last_did = did;
    return m->app_did != NULL ? m->app_did(did, buf, max) : 0u;
}

/* engine.status: copies the status the test set; the engine's ctx must be the mock. */
static inline void udsota_mock_status(void *ctx, udsota_status_t *out)
{
    const udsota_mock_t *m = ctx;
    *out = m->status;
}

/* The mock's hooks, with m as ctx: gate, phase, did_read and reset; stmin_us is left NULL (the transport's). */
static inline udsota_hooks_t udsota_mock_hooks(udsota_mock_t *m)
{
    udsota_hooks_t h = {
        .gate = udsota_mock_gate, .phase = udsota_mock_phase, .did_read = udsota_mock_did_read,
        .stmin_us = NULL, .reset = udsota_mock_reset_hook, .ctx = m,
    };
    return h;
}

/* The tests' server config: every timing and level default, the STmin monitor on, device ID 02 00 00 00 00 01 (F18C). */
static inline udsota_config_t udsota_mock_cfg(void)
{
    static const uint8_t serial[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    udsota_config_t c;
    memset(&c, 0, sizeof c);
    c.stmin_monitor = true;
    c.device_id = serial;
    c.device_id_len = sizeof serial;
    return c;
}
