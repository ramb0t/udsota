/* udsota wire contract (ISO 14229-1 over ISO-TP): every SID, NRC, session, DID and RID the server
 * uses, the download framing, the reason codes, and the status, result and counter byte layouts with
 * their codecs (udsota_codec.c). Pure C. Every value here is on the wire: changing one needs a
 * matching client change and a CHANGELOG entry. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Service IDs and response framing ---- */
#define UDSOTA_SID_SESSION           0x10   /* DiagnosticSessionControl */
#define UDSOTA_SID_RESET             0x11   /* ECUReset (keyed) */
#define UDSOTA_SID_READ_DID          0x22   /* ReadDataByIdentifier */
#define UDSOTA_SID_SECURITY          0x27   /* SecurityAccess */
#define UDSOTA_SID_COMM_CONTROL      0x28   /* CommunicationControl: served only with hooks.comm_control */
#define UDSOTA_SID_WRITE_DID         0x2E   /* WriteDataByIdentifier: served through hooks.did_write, else 0x11 */
#define UDSOTA_SID_ROUTINE           0x31   /* RoutineControl */
#define UDSOTA_SID_REQUEST_DOWNLOAD  0x34
#define UDSOTA_SID_TRANSFER_DATA     0x36
#define UDSOTA_SID_TRANSFER_EXIT     0x37   /* RequestTransferExit */
#define UDSOTA_SID_TESTER_PRESENT    0x3E
#define UDSOTA_SID_DTC_SETTING       0x85   /* ControlDTCSetting */

#define UDSOTA_POS_BIT       0x40           /* positive response SID = request SID | 0x40 */
#define UDSOTA_NEG_RESPONSE  0x7F           /* negative response: 7F <sid> <nrc> */
#define UDSOTA_SPRMIB        0x80           /* suppressPosRspMsgIndicationBit in a sub-function byte */
#define UDSOTA_POS(sid)      ((uint8_t)((sid) | UDSOTA_POS_BIT))

#define UDSOTA_RESET_HARD       0x01        /* 11 01 hardReset, the only reset served */
#define UDSOTA_RC_START         0x01        /* 31 01 startRoutine, the only routine control served */
#define UDSOTA_TP_ZERO_SUBFUNC  0x00        /* 3E 00 (3E 80 with the suppress bit) */
#define UDSOTA_WRITE_DID_MIN_LEN 4u         /* 2E, the DID and at least one data byte; shorter is 0x13 */
#define UDSOTA_CC_ENABLE_RX_TX  0x00        /* 28 00 enableRxAndTx; 01 and 02 disable one direction */
#define UDSOTA_CC_DISABLE_RX_TX 0x03        /* 28 03 disableRxAndTx, the highest controlType served */
#define UDSOTA_CC_TYPE_ALL      0x03        /* communicationType: normal and network-management messages, all subnets */
#define UDSOTA_DTC_ON           0x01        /* 85 01 */
#define UDSOTA_DTC_OFF          0x02        /* 85 02 */

/* ---- Negative response codes (ISO 14229-1; values match iso14229 src/uds.h) ---- */
#define UDSOTA_NRC_GENERAL_REJECT                  0x10
#define UDSOTA_NRC_SERVICE_NOT_SUPPORTED           0x11
#define UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED           0x12
#define UDSOTA_NRC_INCORRECT_LENGTH                0x13   /* incorrectMessageLengthOrInvalidFormat */
#define UDSOTA_NRC_BUSY_REPEAT                     0x21   /* busyRepeatRequest: a request while a job runs */
#define UDSOTA_NRC_CONDITIONS_NOT_CORRECT          0x22   /* interlocks: the app's gate refused */
#define UDSOTA_NRC_REQUEST_SEQUENCE_ERROR          0x24
#define UDSOTA_NRC_REQUEST_OUT_OF_RANGE            0x31
#define UDSOTA_NRC_SECURITY_ACCESS_DENIED          0x33
#define UDSOTA_NRC_INVALID_KEY                     0x35
#define UDSOTA_NRC_EXCEEDED_ATTEMPTS               0x36   /* exceedNumberOfAttempts */
#define UDSOTA_NRC_TIME_DELAY_NOT_EXPIRED          0x37   /* requiredTimeDelayNotExpired */
#define UDSOTA_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED    0x70
#define UDSOTA_NRC_TRANSFER_DATA_SUSPENDED         0x71
#define UDSOTA_NRC_GENERAL_PROGRAMMING_FAILURE     0x72
#define UDSOTA_NRC_WRONG_BLOCK_SEQUENCE_COUNTER    0x73
#define UDSOTA_NRC_RESPONSE_PENDING                0x78   /* requestCorrectlyReceived-ResponsePending */
#define UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION  0x7E
#define UDSOTA_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION  0x7F

/* ---- Sessions (ISO 14229-1 numbers; the app maps udsota_phase_t to any state of its own) ---- */
typedef enum {
    UDSOTA_SESSION_DEFAULT     = 1,
    UDSOTA_SESSION_PROGRAMMING = 2,
    UDSOTA_SESSION_EXTENDED    = 3,
} udsota_session_t;

/* ---- SecurityAccess sub-functions: odd = requestSeed, even = sendKey ---- */
#define UDSOTA_SA_SEED_EXTENDED     0x01    /* extended session: unlocks ECUReset */
#define UDSOTA_SA_KEY_EXTENDED      0x02
#define UDSOTA_SA_SEED_PROGRAMMING  0x03    /* programming session: unlocks download and ECUReset */
#define UDSOTA_SA_KEY_PROGRAMMING   0x04
#define UDSOTA_SEED_LEN             16
#define UDSOTA_KEY_LEN              16      /* first 16 bytes of HMAC-SHA256(K_dev, seed || level || device ID), the F18C bytes */
#define UDSOTA_SA_SEED_VALID_MS     30000u  /* an outstanding seed is single-use and expires after this */
#define UDSOTA_SA_MAX_ATTEMPTS      3       /* the third wrong key answers 0x36 and starts the delay */
#define UDSOTA_SA_DELAY_MS          10000u  /* NRC 0x37 window after a lockout, and after every boot */

/* ---- Server timing on the wire: 10 xx positive = 50 xx 00 32 01 F4 (P2* in 10 ms units) ---- */
#define UDSOTA_P2_MS      50u
#define UDSOTA_P2STAR_MS  5000u
#define UDSOTA_S3_MS      5000u

/* ---- Data identifiers (all readable in any session; none is secret) ---- */
#define UDSOTA_DID_ACTIVE_SESSION  0xF186   /* 1 B: udsota_session_t */
#define UDSOTA_DID_SW_VERSION      0xF189   /* git describe string */
#define UDSOTA_DID_SERIAL          0xF18C   /* the device ID, cfg.device_id_len bytes */
#define UDSOTA_DID_STATUS          0xF1F0   /* UDSOTA_STATUS_LEN B: udsota_status_t */
#define UDSOTA_DID_RUNNING_SHA     0xF1F3   /* 32 B: the running image's app_elf_sha256 */
#define UDSOTA_DID_RESULT          0xF1F1   /* UDSOTA_RESULT_LEN B: udsota_result_t */
#define UDSOTA_DID_COUNTERS        0xF1F2   /* UDSOTA_COUNTERS_LEN B: udsota_counters_t */
#define UDSOTA_SERIAL_LEN          6        /* the ESP32 port's default device ID (base MAC), not an F18C limit */
#define UDSOTA_SHA256_LEN          32

/* ---- Routine identifiers (31 01 <rid>) ---- */
#define UDSOTA_RID_CHECK_PROG_DEPS   0xFF01 /* CheckProgrammingDependencies: engine.verify; status = udsota_reason_t */
#define UDSOTA_RID_GET_RESUME_POINT  0xF000 /* reserved for resume; answers status UDSOTA_RESUME_NOT_AVAILABLE */
#define UDSOTA_RID_ACTIVATE_IMAGE    0xF001
#define UDSOTA_RID_CONFIRM_IMAGE     0xF002
#define UDSOTA_RESUME_NOT_AVAILABLE  0xFF

/* ---- RequestDownload / TransferData ---- */
#define UDSOTA_DL_DFI            0x00       /* dataFormatIdentifier: no compression or encryption */
#define UDSOTA_DL_DFI_DEFLATE    0x10       /* dataFormatIdentifier: raw DEFLATE (RFC 1951, no zlib or gzip header), no
                                               encryption; served only when the engine has zbegin */
#define UDSOTA_DL_ALFID          0x44       /* addressAndLengthFormatIdentifier: 4-byte address, 4-byte size */
#define UDSOTA_DL_LFID           0x20       /* positive-response lengthFormatIdentifier: 2-byte block length */
#define UDSOTA_DL_MAX_BLOCK_LEN  4095u      /* maxNumberOfBlockLength (SID + BSC + data): 74 20 0F FF */
#define UDSOTA_DL_MAX_DATA       (UDSOTA_DL_MAX_BLOCK_LEN - 2u)   /* 4093 data bytes per 0x36 */
#define UDSOTA_DL_REQ_LEN        11u        /* 34 DFI ALFID address[4] size[4] */
#define UDSOTA_TD_MIN_LEN        3u         /* 36 BSC and at least one data byte */
/* The most compressed bytes a DFI 0x10 download of `size` bytes may carry: size + size/8 + 1024. zlib and miniz's
 * tdefl never exceed it (their worst case is stored blocks, 5 bytes per 64 KB); a legal stream padded with empty
 * blocks can, and a 36 that would carry it past the bound is refused as an overrun (0x71). */
#define UDSOTA_DL_Z_BOUND(size)  ((uint64_t)(size) + ((uint64_t)(size) >> 3) + 1024u)

/* ---- Download result: F1F1 reason and FF01 status byte. Wire values; append only. ---- */
typedef enum {
    UDSOTA_DL_OK = 0,
    UDSOTA_DL_BAD_HEADER,        /* 1: esp_image_header_t / esp_app_desc_t magic, chip or flash mode; an unparseable
                           *    version; or the release flag and the version string disagree */
    UDSOTA_DL_BAD_PROJECT,       /* 2: product name differs (esp_app_desc_t project_name) */
    UDSOTA_DL_BAD_BOARD,         /* 3: descriptor missing, bad magic or desc_version, or hw_id is not this board */
    UDSOTA_DL_BAD_LAYOUT,        /* 4: partition_layout_id differs */
    UDSOTA_DL_BAD_DIAG_IDS,      /* 5: the image would not answer on the configured request/response IDs */
    UDSOTA_DL_NOT_NEWER,         /* 6: release build not strictly newer than the running one, or dev build older */
    UDSOTA_DL_TOO_BIG,           /* 7: announced size exceeds the slot */
    UDSOTA_DL_VERIFY_FAILED,     /* 8: the engine's image check failed (on the ESP32 port, esp_ota_end's SHA-256 or signature) */
    UDSOTA_DL_SIG_FAILED,        /* 9: reserved; the ESP32 port never emits it: IDF v6.1's esp_ota_end returns one code for a
                           *    hash or a signature failure, so both report 8 */
    UDSOTA_DL_WORKER_TIMEOUT,    /* 10: a flash job passed the 90 s cap */
    UDSOTA_DL_ABORTED,           /* 11: ended early: S3 fallback, any accepted 10 xx, an interlock or end_session stop
                           *     at a 0x36 or FC point, or an overrun (0x71). Not a flash failure (12) or the
                           *     90 s cap (10) */
    UDSOTA_DL_FLASH_ERROR,       /* 12: the worker's ota_begin (erase) or ota_write failed or could not be queued (0x72),
                           *     or at the first-block check there is no worker or no inactive slot (0x31); for a
                           *     compressed download, no worker or slot at the 34 (0x22), and an erase or write
                           *     failure at a 36 (0x72) */
    UDSOTA_DL_BAD_STREAM,        /* 13: a compressed download (DFI 0x10) did not inflate to exactly memorySize bytes: a
                           *     corrupt stream or one inflating past memorySize (36: 0x31), or at 37 a stream that
                           *     had not ended, ended short or carried data after its end (0x72) */
    UDSOTA_DL_NO_MEMORY,         /* 14: a 34 with DFI 0x10 found no memory for the inflater (0x22) */
    UDSOTA_DL_REASON_COUNT       /* not a reason and never on the wire: the bound for range checks; append new reasons above it */
} udsota_reason_t;

/* ---- F1F0 device state (engine.status; the ESP32 port answers from a cache, never esp_ota_* at read time) ---- */
#define UDSOTA_SLOT_OTA0  0x00
#define UDSOTA_SLOT_OTA1  0x01
#define UDSOTA_SLOT_NONE  0xFF          /* factory app or not known */

/* Enum values not listed below are unused: never sent; readers treat unknown values as unknown. */
typedef enum {                           /* running_state: the ESP32 port maps esp_ota_img_states_t explicitly (values differ; never cast) */
    UDSOTA_IMG_UNDEFINED      = 0,
    UDSOTA_IMG_NEW            = 1,
    UDSOTA_IMG_PENDING_VERIFY = 2,
    UDSOTA_IMG_VALID          = 3,
    UDSOTA_IMG_INVALID        = 4,
    UDSOTA_IMG_ABORTED        = 5,
} udsota_img_state_t;

typedef enum {                           /* other_slot_state (F1F0) */
    UDSOTA_OTHER_EMPTY      = 0,        /* no valid app descriptor */
    UDSOTA_OTHER_UNVERIFIED = 1,        /* holds an image not verified since boot */
    UDSOTA_OTHER_WRITING    = 2,        /* a download is writing it */
    UDSOTA_OTHER_VERIFIED   = 3,        /* passed FF01 since boot; ActivateImage may use it */
    UDSOTA_OTHER_INVALID    = 4,        /* rolled back (otadata INVALID or ABORTED) */
} udsota_other_state_t;

#define UDSOTA_STATUS_SIG_CHECKED          0x01   /* CONFIG_SECURE_SIGNED_ON_UPDATE is set */
#define UDSOTA_STATUS_BOOT_IGNORED_CONFIG  0x02   /* the boot-loop breaker ran this boot on defaults */
/* Flag bits 0x04-0x80 are reserved: sent as 0; readers treat unknown values as unknown. */

typedef struct {
    uint8_t running_slot;                /* UDSOTA_SLOT_* */
    uint8_t running_state;               /* udsota_img_state_t */
    uint8_t boot_slot;                   /* UDSOTA_SLOT_*: the otadata boot target */
    uint8_t other_slot_state;            /* udsota_other_state_t */
    uint8_t other_version[3];            /* major, minor, patch; 0,0,0 when empty; the rolled-back image's when INVALID */
    uint8_t other_elf_sha_prefix[8];     /* first 8 bytes of the other slot's app_elf_sha256; the rolled-back image's when INVALID */
    uint8_t flags;                       /* UDSOTA_STATUS_* */
} udsota_status_t;
#define UDSOTA_STATUS_LEN  16                 /* single bytes in field order */

/* ---- F1F1 last download result ---- */
typedef struct {
    uint8_t  reason_code;                /* udsota_reason_t */
    uint32_t bytes_received;             /* data bytes accepted by 0x36 */
} udsota_result_t;
#define UDSOTA_RESULT_LEN  5                  /* reason, then bytes_received big-endian */

/* ---- F1F2 ISO-TP and UDS counters, each saturating at 0xFFFF (udsota_sat_inc16) ---- */
typedef struct {
    uint16_t seq_errors;                 /* wrong block sequence counters (NRC 0x73) */
    uint16_t ncr_timeouts;               /* N_Cr: a request's sender went silent mid-message */
    uint16_t repeated_blocks;            /* repeat of the last BSC, answered without a rewrite */
    uint16_t aborts;                     /* downloads ended early */
    uint16_t withheld_fcs;               /* FCs withheld by the mid-transfer interlock */
    uint16_t stmin_violations;           /* median CF interval < 0.8 x STmin, counted only when the gate allowed */
    uint16_t resp_pending_caps;          /* 0x78 sequences that hit the 90 s cap */
    uint16_t resp_frames_dropped;        /* response frames the app's CAN driver dropped (tx_dropped) */
} udsota_counters_t;
#define UDSOTA_COUNTERS_LEN  16                 /* eight u16 big-endian, field order */

/* Packs F1F0 into out; returns UDSOTA_STATUS_LEN, or 0 without writing when max is short or a pointer is NULL. */
size_t udsota_pack_status(uint8_t *out, size_t max, const udsota_status_t *s);
/* Unpacks F1F0; false without touching *s when len < UDSOTA_STATUS_LEN or a pointer is NULL. */
bool   udsota_unpack_status(const uint8_t *in, size_t len, udsota_status_t *s);
/* Packs F1F1 (reason, u32 BE); returns UDSOTA_RESULT_LEN, or 0 without writing when short or NULL. */
size_t udsota_pack_result(uint8_t *out, size_t max, const udsota_result_t *s);
/* Unpacks F1F1; false without touching *s when len < UDSOTA_RESULT_LEN or a pointer is NULL. */
bool   udsota_unpack_result(const uint8_t *in, size_t len, udsota_result_t *s);
/* Packs F1F2 (8 x u16 BE); returns UDSOTA_COUNTERS_LEN, or 0 without writing when short or NULL. */
size_t udsota_pack_counters(uint8_t *out, size_t max, const udsota_counters_t *s);
/* Unpacks F1F2; false without touching *s when len < UDSOTA_COUNTERS_LEN or a pointer is NULL. */
bool   udsota_unpack_counters(const uint8_t *in, size_t len, udsota_counters_t *s);
/* Adds one to an F1F2 counter, holding at 0xFFFF. */
void   udsota_sat_inc16(uint16_t *c);
/* Writes v big-endian into p[0..1]. */
void     udsota_put_u16be(uint8_t *p, uint16_t v);
/* Reads a big-endian u16 from p[0..1]. */
uint16_t udsota_get_u16be(const uint8_t *p);
/* Writes v big-endian into p[0..3]. */
void     udsota_put_u32be(uint8_t *p, uint32_t v);
/* Reads a big-endian u32 from p[0..3]. */
uint32_t udsota_get_u32be(const uint8_t *p);
