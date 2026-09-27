/* udsota_server internals shared with its host tests and its service handlers: NRC framing and the
 * worker-job wait (0x78 cadence, 90 s cap). Not part of the public diag API. */
#pragma once
#include "udsota.h"

/* Writes 7F <sid> <nrc>; returns 3, or 0 without writing when resp_max < 3. */
size_t udsota_nrc(uint8_t *resp, size_t resp_max, uint8_t sid, uint8_t nrc);

/* Finishes a handler whose op may have queued worker work. rc == UDSOTA_PENDING starts the wait
 * (poll sends 0x78 from 40 ms, answers 0x72 at 90 s, calls done when job_poll reports) and returns
 * 0; any other rc calls done(rc) now and returns its answer. arg is stored in s->job_arg for done.
 * suppress_pos drops a positive final answer unless a 0x78 went out first. */
size_t udsota_job_start(udsota_server_t *s, uint8_t sid, bool suppress_pos, int rc, udsota_job_done_fn done,
                     uint32_t arg, uint8_t *resp, size_t resp_max, uint32_t now_ms);
