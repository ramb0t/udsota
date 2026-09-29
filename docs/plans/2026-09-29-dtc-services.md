# Plan: DTC services, 0x19 and 0x14

This plan adds ReadDTCInformation (0x19: 01, 02, 06, 0A) and ClearDiagnosticInformation (0x14) as core services, served through three app hooks, with `udsota dtc show` and `udsota dtc clear` in the client. It implements CANDash's request `docs/design/requests/2026-09-29-udsota-dtc-services.md` as its "Response from udsota" settled it, which CANDash accepted.

It ships as one PR and a minor release (0.10.0): the hooks go after `progress` in `udsota_hooks_t` and the config fields at the end of `udsota_config_t`, so nothing is breaking. The proof that nothing else changes on the wire is the five pinned fuzz digests, which must not move; a new DTC fuzz build gets its own pin. Line numbers below refer to v0.9.0 (`5a0103c`).

## Flagged

Three things the request and response don't say, found in the code:

- **The ESP32 port would drop the new hooks.** `udsota_esp32_ctl_init()` (`server/udsota_esp32_ctl.c:130-143`) builds the server's hooks field by field, each wrapped to pass the app's ctx, so a new hook stays NULL and CANDash's 19 and 14 would answer 0x11. The plan adds `w_dtc_get`, `w_dtc_ext_data` and `w_dtc_clear` on the existing pattern, installed only when the app sets them.
- **The RAM is about 44 B on the ESP32 port, not 16.** The response's 16 B is `udsota_server_t` alone (three pointers, two config bytes and two of padding), so `s_srv` goes from 372 to 388. The port holds three more copies: `s_cfg` (+4), `s_hooks` (+12) and the app's hooks in `s_ctl.app` (+12). On a 64-bit host `sizeof(udsota_server_t)` goes from 584 to 616. The CHANGELOG states the measured figures.
- **Four tests pin today's shape and must change without a wire change.** `fuzz_udsota.c:84` asserts `progress` is the last hook, so it moves to `dtc_clear`; the digests prove the move harmless. `test_functional_unserved_services_are_silent` (`test_udsota_server_functional.c:140`) uses `19 02 FF` as its unserved example, which after this is silent only because the hooks are NULL, so it takes `14 FF FF FF` instead. Two more still pass but describe 19 and 14 as unserved: `test_unknown_sid`'s comment (`test_udsota_server.c:311`) gains "19 and 14 included: not served with `dtc_get` and `dtc_clear` NULL", as it says for 2E, and the matrix row `E1 19 ReadDTC` (`test_udsota_server_matrix.c:235`) moves under the 28/85 "need hooks, which this suite leaves NULL" comment, which then names `dtc_get` too.

Nothing in the request is wrong against ISO 14229-1 beyond what the response already records (0x13 before CANDash's 0x7F for a malformed 14). The formats of 59 01, 02, 06 and 0A, the `status & mask & availability` match, record 00 being reserved, FF meaning every record, 54 as 14's answer, 0x14 responseTooLong, and 0x11, 0x12, 0x31, 0x7E and 0x7F as the NRCs suppressed for a functional request all match the standard, and DTCFormatIdentifier 0x00 (SAE J2012-DA format 00) fits CANDash's OBD codes.

## Decisions

- **Every NRC about room is still sent under SPRMIB.** A 19 is built exactly as without the bit, and only a positive answer is then dropped, so a list that doesn't fit answers `7F 19 14` either way. `sa_request_seed` (`udsota_server.c:77`) sets the precedent: its no-room 0x10 ignores the bit.
- **Room is judged on the `resp_max` the core is given**, never on `UDSOTA_ISOTP_RESP_MAX`. The fuzz harness runs `resp_max` down to 0. An NRC that doesn't fit is silence, because `udsota_nrc` writes nothing below 3 bytes. A 19 positive that doesn't fit is 0x14. A 14 with `resp_max` 0 calls no hook and answers nothing, as 11 01 won't restart without answering (`:695`).
- **`dtc_get` is asked only below `UDSOTA_DTC_INDEX_MAX` (0xFFFF)**, since 19 01 counts in a u16. A hook that never returns false then costs one bounded walk instead of a hung diag task. 19 02 and 0A stop walking at the first DTC that would overflow.
- **Record 0xFE goes to the hook** like any record but 00 and FF (the 2013 edition's "all OBD records"): the hook serves it or answers 0x31, as CANDash will.
- **The DTC's top byte is ignored.** The core masks `udsota_dtc_t.dtc` to 24 bits both when it writes a DTC and when it compares one for 19 06; the first match wins. `dtc_ext_data` gets the request's 24-bit DTC (top byte 0), never `dtc_get`'s raw value, so an app that stores a top byte compares `(entry & 0xFFFFFF) == dtc`.
- **No `0x59`/`0x54` defines.** Positive SIDs are `UDSOTA_POS(sid)` throughout the header, and these follow.
- **The handlers live in `server/udsota_server.c`**, beside 28, 85 and 2E, so no `.c` file is added and neither `sources.cmake` changes. `tools/check_seam.sh` and `udsota_server_only` pass unchanged, since nothing here touches `update/`.

## Header additions

`udsota_server_wire.h`: after `UDSOTA_SID_RESET`, and in value order:

```c
#define UDSOTA_SID_CLEAR_DTC         0x14   /* ClearDiagnosticInformation: served only with hooks.dtc_clear */
#define UDSOTA_SID_READ_DTC          0x19   /* ReadDTCInformation: served only with hooks.dtc_get */
```

after `UDSOTA_DTC_OFF`:

```c
#define UDSOTA_RDTC_COUNT_BY_MASK   0x01    /* 19 01 reportNumberOfDTCByStatusMask: 59 01 <avail> <format> <count u16> */
#define UDSOTA_RDTC_BY_MASK         0x02    /* 19 02 reportDTCByStatusMask: 59 02 <avail>, then <DTC 3 B> <status> each */
#define UDSOTA_RDTC_EXT_DATA        0x06    /* 19 06 reportDTCExtDataRecordByDTCNumber: 59 06 <DTC> <status> <records> */
#define UDSOTA_RDTC_SUPPORTED       0x0A    /* 19 0A reportSupportedDTC: 59 0A <avail>, then every DTC and its status */
#define UDSOTA_DTC_RECORD_ALL       0xFF    /* 19 06: every extended data record; record 00 is reserved (0x31) */
#define UDSOTA_DTC_GROUP_ALL        0xFFFFFFu   /* 14's groupOfDTC for every DTC */
#define UDSOTA_CLEAR_DTC_LEN        4u      /* 14 and the 3-byte group, exactly; any other length is 0x13 */
```

and among the NRCs:

```c
#define UDSOTA_NRC_RESPONSE_TOO_LONG               0x14   /* responseTooLong: a 19 answer past the response buffer */
```

`udsota_server.h`, among the server-internal limits:

```c
#define UDSOTA_DTC_INDEX_MAX      0xFFFFu   /* hooks.dtc_get is asked for i below this only: 19 01 counts in a u16 */
```

after `udsota_access_t`:

```c
/* One DTC as hooks.dtc_get reports it. */
typedef struct {
    uint32_t dtc;      /* the 3-byte DTC in the low 24 bits, the top byte ignored: for DTCFormatIdentifier 0x00 the
                          2-byte SAE J2012 code and the failure-type byte, so U0073 with FTB 00 is 0xC07300 */
    uint8_t  status;   /* its ISO 14229-1 statusOfDTC now; the core sends status & cfg.dtc_availability_mask */
} udsota_dtc_t;
```

at the end of `udsota_hooks_t`, after `progress`:

```c
    bool     (*dtc_get)(void *ctx, size_t i, udsota_dtc_t *out);
                                                   /* 0x19: the i-th supported DTC and its status now; false past the
                                                      last. i names the same DTC for as long as the server runs, and
                                                      only its status may change. Asked from 0 up for each 19 01, 02
                                                      and 0A, and for 19 06 until the DTC asked is found, never for i
                                                      at UDSOTA_DTC_INDEX_MAX or past it. NULL: 19 answers 0x11, as
                                                      before. It answers at once, may read udsota_phase() but must not
                                                      call other udsota functions */
    uint8_t  (*dtc_ext_data)(void *ctx, uint32_t dtc, uint8_t record, uint8_t *buf, size_t max, size_t *len);
                                                   /* 19 06, for a DTC dtc_get reports (the core answers 0x31 for any
                                                      other, and for record 00, without a call); dtc is the request's
                                                      24 bits, top byte 0, whatever top byte dtc_get gave it; record
                                                      01-FE, or FF for every one. Writes <record> <data>... into buf, at most max
                                                      bytes (the room after 59 06 <DTC> <status>, possibly 0; buf is
                                                      valid only during the call), sets *len and returns 0; *len 0 is
                                                      a record held with no data. Else returns the NRC: 0x31 no such
                                                      record, 0x14 the records don't fit max; never 0x78. A *len over
                                                      max is 0x10. NULL: 19 06 answers 0x12. Called as dtc_get */
    uint8_t  (*dtc_clear)(void *ctx, uint32_t group, udsota_access_t access);
                                                   /* 0x14 with exactly a 3-byte groupOfDTC (else 0x13 without a
                                                      call), physical only, in any session; group in the low 24 bits
                                                      (UDSOTA_DTC_GROUP_ALL is every DTC). Returns 0 to answer 54, or
                                                      the NRC, checked in ISO order: its session rule (0x7F), then its
                                                      key rule (0x33), then 0x31 for a group it doesn't clear; never
                                                      0x78. NULL: 14 answers 0x11, as before. Called as dtc_get */
```

at the end of `udsota_config_t`, after `key_pubkey_len`; the comment at `:143` becomes "...except device_id, device_id_len and the dtc_ fields":

```c
    /* Fields added after key_pubkey_len, so every earlier field keeps its offset. */
    uint8_t     dtc_availability_mask; /* 19's DTCStatusAvailabilityMask, the status bits the app supports: every
                                          status sent is ANDed with it, and a DTC matches a status mask when status &
                                          mask & this is non-zero; 0 = 0xFF (cfg_resolve) */
    uint8_t     dtc_format;            /* 59 01's DTCFormatIdentifier, sent as given: 0x00 SAE J2012-DA format 00
                                          (OBD codes such as U0073 with a failure-type byte), 0x01 ISO 14229-1 */
```

The functional comment at `udsota_server.h:240` becomes "Only 10 01, 10 03, 3E, 19, 22, 28 and 85 ...", and the one above `functional_served` (`udsota_server.c:940`) becomes "10 01, 10 03, 3E, 19 (every sub-function), 22, 28 and 85; 14 stays physical".

## Check order

Dispatch gains two cases on the 28/85/2E pattern: `UDSOTA_SID_READ_DTC` answers 0x11 without `dtc_get` and otherwise calls `handle_read_dtc`; `UDSOTA_SID_CLEAR_DTC` answers 0x11 without `dtc_clear` and otherwise calls `handle_clear_dtc`. Before dispatch, as now, an armed restart answers nothing and a running job answers 0x21. Neither service has a session or key rule in the core. Each check below answers its NRC without calling a hook further down:

| Request | Checks in order |
|---|---|
| any 19 | length < 2: 0x13. Sub-function (SPRMIB masked) not 01, 02, 06 or 0A, or 06 without `dtc_ext_data`: 0x12 |
| 19 01 | length ≠ 3: 0x13. `resp_max` < 6: 0x14. Walk `dtc_get`, count `status & mask & avail` ≠ 0; `59 01 <avail> <format> <count>` |
| 19 02 | length ≠ 3: 0x13. `resp_max` < 3: 0x14. Walk; each match writes `<DTC> <status & avail>`, and the first that would pass `resp_max` answers 0x14 and ends the walk; `59 02 <avail> ...` |
| 19 0A | length ≠ 2: 0x13. Then as 19 02 with every DTC matching; `59 0A <avail> ...` |
| 19 06 | length ≠ 6: 0x13. Record 00: 0x31. Walk to the DTC, none: 0x31. `resp_max` < 6: 0x14. Hook with `buf = resp + 6`, `max = resp_max - 6`: its NRC as given, `*len > max` 0x10, else `59 06 <DTC> <status & avail>` and `*len` bytes |
| 14 | length ≠ 4: 0x13 (a 2020-edition memorySelection byte too). `resp_max` 0: nothing, no call. Hook with the group and `access_of(s)`: its NRC as given, else `54` |

SPRMIB then drops a positive 19 answer (`spr && is_positive`). The header comments state this order as `handle_comm_control`'s and `handle_write_did`'s do. The list walk, `rdtc_list(s, sub, mask, resp, resp_max)`, serves 01, 02 and 0A; `rdtc_ext_data` serves 06. A static `put_u24be` writes the DTCs.

**Functional.** `functional_served` (`:942`) gains `case UDSOTA_SID_READ_DTC:`, for every sub-function; 14 stays out, so a functional 14 is dropped before the server sees it and calls no hook. The existing suppression then does the rest: a functional 19 06 for a DTC the node lacks (0x31), an unserved sub-function (0x12) or a node without `dtc_get` (0x11) is silent, while 0x13 and 0x14 are sent. A functional answer longer than a frame goes out multi-frame on `resp_id`, as any other.

**Busy.** Nothing new: while a job runs a physical 19 or 14 answers 0x21 and calls no hook, and a functional one is silent. Orphans, an open transfer and every session leave 19 served.

## ESP32 port

`udsota_esp32_ctl.c` gains the three wrappers, each "the app's X with the app's ctx (installed only when the app has one)", and `udsota_esp32_ctl_init` sets them after `progress`. The header comment at `udsota_esp32_ctl.h:30` names them among the hooks that stay NULL. `s_cfg` is a whole-struct copy, so the two config fields already reach the server.

## Tests

`test/test_udsota_server_dtc.c` joins the `server_*` foreach at `CMakeLists.txt:128`. A mock table of five DTCs, statuses with bits inside and outside 0x2F, and one `dtc` with a non-zero top byte; its ext hook records every call and answers per record; availability 0x2F and format 0x01, except where a test sets them.

| Test | Pins |
|---|---|
| `null_hooks` | without `dtc_get` every 19, malformed ones included, answers 0x11 in all three sessions; without `dtc_ext_data` 19 06 answers 0x12 while 01/02/0A are served; without `dtc_clear` 14 answers 0x11; 14 is served with `dtc_get` NULL |
| `count_by_mask` | 59 01 with availability, format and count; mask 0 and mask 0x40 (outside availability) count 0; availability 0 in cfg reads 0xFF |
| `by_mask` | table order, `status & avail` on the wire, `status & mask & avail` filter, top byte masked off, no match answers `59 02 2F` alone |
| `supported` | 19 0A lists every DTC, status 00 included, masked |
| `ext_data` | one record; FF; the DTC with a non-zero top byte reaches the hook as its 24 bits; `*len` 0 answers DTC and status alone; the hook's 0x31 and 0x14 verbatim; `*len > max` 0x10; `max` equals `resp_max - 6`; 0xFE reaches the hook; record 00 and an unknown DTC answer 0x31 with no hook call |
| `lengths_and_subfunctions` | `19`, `19 01`, `19 01 FF 00`, `19 0A 00`, `19 06` short and long: 0x13; `19 03`, `19 04`, `19 04 00 00 00 00`: 0x12 (the sub-function before the exact length) |
| `response_too_long` | 63 DTCs fit 256 B and 64 answer 0x14; `resp_max` 3 + 4k fits k and one less answers 0x14; 19 01 at 6 and 5; 19 06 at 6 (with `*len` 0) and 5, the latter without a call; `resp_max` 2 is silent; the walk stops at the overflow (`dtc_get` calls counted) |
| `index_cap` | a `dtc_get` that never returns false: 19 01 answers count 0xFFFF after 65,535 calls |
| `sprmib` | `19 82 FF` and `19 8A` silent after the walk, `19 86` with an unknown DTC still `7F 19 31`, `19 82 FF` too long still `7F 19 14` |
| `sessions` | 19 served in default, extended and programming, locked, with security on |
| `clear` | lengths 3 and 5 answer 0x13 with no call; the group and access (session, level, epoch) reach the hook; its NRC verbatim; `54`; `resp_max` 0 calls nothing; the default session reaches the hook |
| `busy` | during a pending 36, 19 and 14 answer 0x21 and call nothing; functionally both are silent |
| `functional` | 19 02 answered; 19 06 unknown, 19 04 and a NULL `dtc_get` silent; `19` alone answers `7F 19 13`; 19 0A too long answers `7F 19 14`; 14 silent with no call |

Elsewhere: `test_udsota_server_functional.c:140` takes `14 FF FF FF` (see Flagged); `test/core_only/udsota_core_rows.h` gains group I (group H is already the no-engine test's init comparison), `test_I1_...` rows for 19 02 and 14 through their hooks with no service registered, so the no-engine and core-only tests prove the core serves them alone. `boot()` sets the three DTC hooks over a small table of its own, `g_served()` gains `UDSOTA_SID_READ_DTC` and `UDSOTA_SID_CLEAR_DTC`, so group G's sweep keeps "every hook set" true and covers 19 and 14 in all five states on both init paths, the new rows join `CORE_ROWS`, and the header's "Groups A to G" becomes "Groups A to G and I"; `test_udsota_esp32_ctl.c` gains a test that 19 02, 19 06 and 14 reach the app's hooks through the port with the app's ctx, and that a NULL stays NULL.

**Fuzz.** A sixth build, `fuzz_udsota_dtc` (`UDSOTA_FUZZ_DTC=1`, nothing else), adds everything under `#if UDSOTA_FUZZ_DTC`, so the other five builds compile to what they are now. Its FUZZ_CFG sets availability 0x2F and format 0x00, and its table holds 90 DTCs with statuses cycling through 00, 01, 2F, 08, 40, 09, FF and 28 and a junk top byte. 19 0A and 19 02 FF then outgrow 256 B, while 19 02 01 and 02 08 fit. The mocks fail the run when they are handed an index at the cap, an unknown DTC (compared as `(entry & 0xFFFFFF) == dtc`), a `dtc` with a non-zero top byte, record 00, an access state that is not the server's, or a `buf` shorter than `max` (they `memset` all of `max` first, as `mock_did_read` does). The ext mock answers 01 (2 bytes), 02 (none held), FF (both, or 0x14), 7E (`*len = max + 1`, for the core's 0x10) and 0x31 for the rest; clear answers 0 for FFFFFF, 0x31 for other groups, and 0x22 in variant 1. `sid_served` gains 19 and 14, `nrc_known` gains 0x14 (its comment says 20), and `positive_shape_ok` checks 59 01's length, availability and format; 59 02 and 0A's `(n - 3) % 4 == 0`, echo, and every status `s` a subset of availability, `(s & ~avail) == 0`, and for 02 sharing a bit with the request's mask, `(s & req[2]) != 0` (the same test as `status & mask & avail != 0`, since `s` is `status & avail`; a status need not be a subset of the mask); 59 06's DTC echo and status; and `54` for exactly 4 request bytes. The seeds are 19 01/02/0A/06 in valid, short, long, SPRMIB and unknown forms, and 14 with the right and wrong groups and lengths; mutation also re-aims at 19 and 14. The coverage floor adds NRC 0x14 seen and a call to each of the three hooks. `RESP_MAXES` needs no change: 6 and 5 cut 59 01, 1 and 0 cut `54`, and 64 and 256 cut the lists. CMake pins it with `udsota_fuzz(fuzz_udsota_dtc 300 DIGEST <recorded> DEFS UDSOTA_FUZZ_DTC=1)`, the digest recorded from the first passing run and quoted in the commit message.

The five existing pins must pass untouched: `fuzz_udsota` c2a27ece321ea94d, `_app_hooks` 835eca2454905330, `_progress` c2a27ece321ea94d, `_z` 2488a2952adadc9e, `_no_update` 7e2cee56a31e126f. They leave the new hooks NULL, where 19 and 14 still answer `7F xx 11` from dispatch as they did from the default case, and the harness sends no functional request.

## Demo server

There is one demo server, `tools/linux_server/demo_server.c`, which `client/tests/demo_server.py` starts and both e2e modules use; the vcan tests only flash, so only `test_e2e_pipe.py` gains DTC tests. It gets availability 0x2F, format 0x00 and a three-entry table:

| DTC | Status | Ext records |
|---|---|---|
| U0073 (C07300) | 2F | 01 occurrence count (1 B), 10 first and last seen (two u32 seconds) |
| P0562 (056200) | 68, so 28 on the wire | 01; 10 held with no data |
| B1234 (923400) | 00: only 19 0A lists it | none |

`dtc_clear` checks in the header's ISO order: the extended session (else 0x7F), then unlocked at `level_extended` when security is on (else 0x33), then group FFFFFF only (else 0x31); it then zeroes every status and count. `--no-dtc` leaves the three hooks NULL. The demo README's intro paragraph gains the DTC table and its options table `--no-dtc`, its Tests paragraph gains the dtc commands, and `usage()` in `demo_server.c` gains a `dtc: --no-dtc` line.

## Client

`client/udsota/dtc.py` holds the commands and the code rendering. `uds.py` gains `read_dtc(sub, data)`, which checks the sub-function echo and returns what follows it, and `clear_dtc(group)`. `wire.py` gains the sub-functions, `DTC_RECORD_ALL`, `DTC_GROUP_ALL`, `NRC_RESPONSE_TOO_LONG` and `DTC_STATUS_BITS`, the eight ISO names from bit 0 (testFailed) to bit 7 (warningIndicatorRequested), and `test_wire_numbers_match_udsota_wire`'s `WIRE_DEFINES` checks the new numbers against the header.

`udsota dtc show` sends 19 01 FF for the format, then 19 02 FF, in the default session:

```
2 DTCs (availability 0x2F, format 0x00)
U0073  status 0x2F (testFailed, testFailedThisOperationCycle, pendingDTC, confirmedDTC, testFailedSinceLastClear)  Lost communication with ECM/PCM "A"
P0562  status 0x28 (confirmedDTC, testFailedSinceLastClear)
```

or `no DTCs match (availability 0x2F)`. Formats 0x00 and 0x04 print the SAE J2012 form, with `-XX` when the failure-type byte isn't 00; other formats print 6 hex digits. The description comes from the profile's `[dtcs]`, and is left off when it has none. `--ext CODE` sends 19 06 <DTC> FF and prints the DTC's line, then `extended data: 01 03 10 ...` as hex, or `no extended data stored`: record lengths are the product's, so the client doesn't split them. CODE is `U0073`, `U0073-1C` or `0xC07300`, in either case, and is checked before the bus opens (exit 2).

`udsota dtc clear` sends 10 03, unlocks at `level_extended` when the profile has `[security]` (as `config set`, through `device_keys` and `load_secret`), then `14 FF FF FF`, and prints `cleared every DTC`. It leaves the session to expire, as `config set` does. `cli.main` loads the secret only for flash, reset and config-set writes today (`cli.py:188`), so its condition gains `or (args.cmd == "dtc" and args.dtc_cmd == "clear")`.

Exit codes follow `config`. 19 or 14 answering 0x11, or 19 06 answering 0x12, means firmware without DTC services or extended data: Refused, exit 2. Any other NRC is UpdateFailed, exit 1, and names it: 0x31 to `--ext` as "not a DTC the device supports", 0x14 as "more DTCs than the device can send in one answer".

In the profile, `[dtcs]` maps codes to text, such as `"U0073" = "Lost communication with ECM/PCM \"A\""`. `KEYS` gains `"dtcs": None`, and `Profile` gains `dtcs: dict = field(default_factory=dict)` at its end, after the defaulted fields (`field` joins the `dataclasses` import), keyed by the 24-bit DTC with a flag for "any FTB". A key without an FTB matches every FTB of that code, and one with an FTB wins over it. Refused, exit 2: a key that isn't a code, a value that isn't a non-empty string, and two keys naming the same DTC. `example.toml` gains a commented `[dtcs]` table.

Client tests, in `test_udsota.py`: `FakeServer` gains `dtcs=None` (None: 19 and 14 answer 0x11) with the core's rules. The tests cover the show output (bits spelled out, descriptions, FTB suffix, format 0x01 as hex, the empty list), `--ext` with records, with none and with 0x31, a bad `--ext` code refused before the bus, the clear sequence with and without security, clear NRCs (exit 1) and 0x11 (exit 2), 0x14 on show, and `[dtcs]` validation. In `test_e2e_pipe.py`: show then `--ext U0073` then clear then an empty show; a keyed clear against `--label`/`--master`; the demo hook's order through `uds.clear_dtc(0x000001)` directly, 0x7F in the default session, 0x33 in the extended session locked with security on, and 0x31 once unlocked; and `--no-dtc`, where both commands exit 2.

## Docs

- `components/udsota/README.md`: rows for the three hooks in Hooks, `dtc_ext_data`'s saying it gets the request's 24-bit DTC; 19 and 14 in the Services table, with a sentence under 19's row on `cfg.dtc_availability_mask` (0 = 0xFF) and `cfg.dtc_format` (sent as given); 19 added to the functional list; 0x14 in the NRC table; 0x10's row gains "a `dtc_ext_data` `*len` over `max`", 0x11's "19 with no `dtc_get`, 14 with no `dtc_clear`", 0x12's "19 06 with no `dtc_ext_data`" and 0x31's "a 19 06 for a DTC `dtc_get` doesn't report or for record 00"; `dtc_ext_data` and `dtc_clear` join the "any NRC but 0x78" line; the "hooks run in the server's context" paragraph (`:164`) names `dtc_get`, `dtc_ext_data` and `dtc_clear` among the hooks that must not wait; and "Adding DIDs, routines and services" names the DTC hooks.
- Root `README.md:13`: "DIDs, writes, routines and fault codes (DTCs)".
- Client README: two lines in Commands, a paragraph on `dtc`, a `[dtcs]` row in Profiles, and "firmware without DTC services" in exit code 2.
- The port README's list of forwarded hooks (`:30`) gains the three DTC hooks; `udsota_esp32.h` needs nothing.
- CHANGELOG `[Unreleased]`, in the house style (the summary line comes at release): a **Core** entry (the services, the hooks and fields and where they sit, check order in brief, functional 19, NRC 0x14, not breaking, and the measured flash and RAM with `s_srv` and the host `sizeof`); an **ESP32 port** entry (the pass-through, and the port's three extra copies in the RAM figure); a **Client** entry (`dtc show`, `dtc clear`, `[dtcs]`); a **demo server** entry (the table and `--no-dtc`); and **Internal** (`fuzz_udsota_dtc` and its digest; the five digests unchanged).

## Commits

The plan is its own commit, then four. Each builds and passes `tools/run_tests.sh` (ctest, including `udsota_seam_grep`, `test_udsota_core_only` and the fuzz pins) and `python -m pytest -q client/tests` with the demo built, as CI's host job does.

1. `DTC: 0x19 and 0x14 as core services, through three app hooks`: both headers, the two handlers, dispatch, `functional_served`, `cfg_resolve`, the unit tests, core rows group I with `boot()` and `g_served()`, the four test fixes in Flagged, and the fuzz build with its pin (digest in the message).
2. `DTC: the ESP32 port passes the three hooks through`: the wrappers, the ctl header comment and the ctl test. Verified with the four ESP32 builds below, with no warnings.
3. `DTC: udsota dtc show and dtc clear, and a DTC table in the demo server`: `dtc.py`, `uds.py`, `wire.py`, `cli.py` (subcommand, docstring and the secret condition), `profile.py`, `example.toml`, the demo server and both kinds of test.
4. `DTC: docs, CHANGELOG and the measured size`: every doc above, with the numbers from the next section.

Every message ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Nothing is pushed.

## Size

Build the baseline before commit 1, while the tree's code is still v0.9.0's (the plan commit touches only `docs/`), in this worktree, so both builds share an absolute path (isotp-c's `assert` embeds `__FILE__`). For esp32 and esp32s3, each with `sdkconfig.defaults` and with `sdkconfig.noupdater` added, run CI's command into `examples/esp32/build/base-<target>-<config>`, then after commit 2 into `examples/esp32/build/<target>-<config>`:

```sh
bash -c 'source ~/.espressif/tools/activate_idf_v6.1.sh >/dev/null && cd /home/ben/Dev/Personal/udsota-dtc/examples/esp32 && \
  idf.py -B build/<dir> -D SDKCONFIG=build/<dir>/sdkconfig -D SDKCONFIG_DEFAULTS="sdkconfig.defaults[;sdkconfig.noupdater]" set-target <target> build'
```

Compare `idf.py size` totals and the `libudsota.a` and `libudsota_esp32.a` rows of `size-components`, and diff the maps with `python -m esp_idf_size --diff base/example.map new/example.map`. Read `s_srv`, `s_cfg`, `s_hooks` and `s_ctl` from `xtensa-<target>-elf-nm -S example.elf`. Expected: `s_srv` 372 to 388 and 44 B more `.bss` in all; flash around 1 KB, nearly all of it in `libudsota.a`; the noupdater build the same. On the host, `sizeof(udsota_server_t)` should read 616. Scratch output goes in `/tmp/claude-1000/-home-ben-Dev-Personal-udsota/357e4782-925d-4a3c-805f-e2d7fea137e7/scratchpad/dtc`.
