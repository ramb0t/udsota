/* The firmware updater's API: the udsota_init that registers it on the server, and the download progress it
 * reports. Its wire contract is udsota_update_wire.h; its types are in udsota_update_state.h. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "udsota_server.h"
#include "udsota_update_state.h"

#define UDSOTA_SLOT_SIZE_DEFAULT  0x400000u  /* bytes a 34 may announce while engine.slot_size is 0 */

/* 1: the server serves coded downloads (DFI 0x10, 0x20, 0x30) when the engine sets zbegin, zwrite and zend and names
 * the format in zformats. 0: none of that is compiled in, and a 34 with any DFI but 00 answers 0x31 whatever the engine
 * sets; the structs keep their layout either way. Only update/udsota_update.c reads it, so define it for that file
 * (the ESP32 port sets 0 while its compression is off). */
#ifndef UDSOTA_COMPRESSION
#define UDSOTA_COMPRESSION 1
#endif

/* Registers the updater on s, right after udsota_core_init and before any request: copies engine (required) and
 * registers the updater's service (udsota_service.h). */
void   udsota_update_init(udsota_server_t *s, const udsota_engine_t *engine);
/* Resets s to the default session, locked and idle, and copies cfg (NULL = every default), engine (NULL = no
 * updater: the server alone, see udsota_core_init), security (NULL = none: 0x27 answers 0x11 and nothing needs a key)
 * and hooks (NULL = none). Silent: no phase call. Returns as udsota_core_init does.
 * Every now_ms below is milliseconds since boot (wrapping at 2^32): the post-boot 0x27 delay is measured from
 * now_ms 0, so a clock that starts elsewhere shortens or skips it. */
bool   udsota_init(udsota_server_t *s, const udsota_config_t *cfg, const udsota_engine_t *engine,
                   const udsota_security_t *security, const udsota_hooks_t *hooks);
/* Server context only: the download's stage, bytes and last reason into *out (udsota_progress_t). A pure read of
 * the server's state: it calls no engine op or hook, and between server calls it equals what hooks.progress last
 * got, or would have. */
void   udsota_progress(const udsota_server_t *s, udsota_progress_t *out);
/* done / total in permille (0..1000), with 64-bit arithmetic; 0 when total is 0 (the stage is indeterminate). Pure:
 * any task may call it on a copy, such as the ESP32 port's snapshot. */
uint16_t udsota_progress_permille(const udsota_progress_t *p);
