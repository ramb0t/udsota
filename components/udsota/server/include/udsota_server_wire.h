/* The UDS server's wire contract (ISO 14229-1 over ISO-TP): every SID, the framing, the sub-functions, NRCs,
 * sessions, SecurityAccess, timing, the server's own DIDs and the F1F2 counters with their codec
 * (server/udsota_codec.c). Pure C. The updater's part is udsota_update_wire.h; udsota_wire.h includes both. Every
 * value here is on the wire: changing one needs a matching client change and a CHANGELOG entry. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Service IDs and response framing ---- */
#define UDSOTA_SID_SESSION           0x10   /* DiagnosticSessionControl */
#define UDSOTA_SID_RESET             0x11   /* ECUReset (keyed) */
#define UDSOTA_SID_CLEAR_DTC         0x14   /* ClearDiagnosticInformation: served only with hooks.dtc_clear */
#define UDSOTA_SID_READ_DTC          0x19   /* ReadDTCInformation: served only with hooks.dtc_get */
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
#define UDSOTA_RDTC_COUNT_BY_MASK   0x01    /* 19 01 reportNumberOfDTCByStatusMask: 59 01 <avail> <format> <count u16> */
#define UDSOTA_RDTC_BY_MASK         0x02    /* 19 02 reportDTCByStatusMask: 59 02 <avail>, then <DTC 3 B> <status> each */
#define UDSOTA_RDTC_EXT_DATA        0x06    /* 19 06 reportDTCExtDataRecordByDTCNumber: 59 06 <DTC> <status> <records> */
#define UDSOTA_RDTC_SUPPORTED       0x0A    /* 19 0A reportSupportedDTC: 59 0A <avail>, then every DTC and its status */
#define UDSOTA_DTC_RECORD_ALL       0xFF    /* 19 06: every extended data record; record 00 is reserved (0x31) */
#define UDSOTA_DTC_GROUP_ALL        0xFFFFFFu   /* 14's groupOfDTC for every DTC */
#define UDSOTA_CLEAR_DTC_LEN        4u      /* 14 and the 3-byte group, exactly; any other length is 0x13 */

/* ---- Negative response codes (ISO 14229-1; values match iso14229 src/uds.h) ---- */
#define UDSOTA_NRC_GENERAL_REJECT                  0x10
#define UDSOTA_NRC_SERVICE_NOT_SUPPORTED           0x11
#define UDSOTA_NRC_SUBFUNC_NOT_SUPPORTED           0x12
#define UDSOTA_NRC_INCORRECT_LENGTH                0x13   /* incorrectMessageLengthOrInvalidFormat */
#define UDSOTA_NRC_RESPONSE_TOO_LONG               0x14   /* responseTooLong: a 22 or 19 answer past the response buffer */
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

/* ---- The server's own data identifiers (all readable in any session; none is secret) ---- */
#define UDSOTA_DID_ACTIVE_SESSION  0xF186   /* 1 B: udsota_session_t */
#define UDSOTA_DID_SERIAL          0xF18C   /* the device ID, cfg.device_id_len bytes */
#define UDSOTA_DID_COUNTERS        0xF1F2   /* UDSOTA_COUNTERS_LEN B: udsota_counters_t */
#define UDSOTA_SERIAL_LEN          6        /* the ESP32 port's default device ID (base MAC), not an F18C limit */

/* ---- The largest 0x36 the server and its transport take (the transport's receive buffer is sized to it) ---- */
#define UDSOTA_DL_MAX_BLOCK_LEN  4095u      /* maxNumberOfBlockLength (SID + BSC + data): 74 20 0F FF */

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
