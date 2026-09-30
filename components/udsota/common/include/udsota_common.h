/* What the updater and its ports share now that udsota carries no UDS server: the job sentinel, the gate's
 * operations, the 0x27 security vtable a port builds, and the port's config. Pure C. The host UDS server (iso14229
 * on this branch) owns sessions, timing and ISO-TP; udsota_iso14229.h binds the updater to it. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* An engine op or updater call whose work is still queued on the worker returns UDSOTA_PENDING; the host server
 * answers 0x78 and asks again (udsota_upd_resume). INT32_MAX: never an esp_err_t, never 0, never an NRC. */
#define UDSOTA_PENDING  0x7FFFFFFF

/* The steps the app's gate may refuse. */
typedef enum {
    UDSOTA_OP_ENTER_EXTENDED = 1,   /* 10 03 */
    UDSOTA_OP_ENTER_PROGRAMMING,    /* 10 02 */
    UDSOTA_OP_START_DOWNLOAD,       /* 34 */
    UDSOTA_OP_CONTINUE_TRANSFER,    /* every 36 */
    UDSOTA_OP_ACTIVATE,             /* 31 01 ActivateImage (0xF001) */
    UDSOTA_OP_RESET,                /* 11 01 */
    UDSOTA_OP_CONFIRM,              /* 31 01 ConfirmImage (0xF002) */
} udsota_op_t;

typedef struct {   /* NULL anywhere it is taken: 0x27 is not served and nothing needs a key */
    bool  (*rng16)(void *ctx, uint8_t out[16]);
    bool  (*key)(void *ctx, const uint8_t seed[16], uint8_t level, uint8_t out[16]);  /* false = no key now (0x22) */
    void  *ctx;
    /* Optional verifier, for a key the device cannot compute (the ECDSA mode, udsota_keys.h): 1 = right, -1 = no
     * verdict now (0x22), anything else = wrong. When set, key is unused. */
    int   (*verify)(void *ctx, const uint8_t seed[16], uint8_t level, const uint8_t *key, size_t key_len);
    uint16_t key_len;   /* with verify set, the exact key length a sendKey carries (0 = 16) */
} udsota_security_t;

typedef struct {
    uint16_t    req_id, resp_id;       /* the diag pair: the ESP32 engine's image check wants the image to answer on it */
    uint16_t    max_block_len;         /* 34's maxNumberOfBlockLength and the 36 length limit; 0 = 4095 */
    uint8_t     level_extended;        /* 27 requestSeed level in the extended session; 0 = 0x01 */
    uint8_t     level_programming;     /* 27 requestSeed level in the programming session; 0 = 0x03 */
    const char *key_label;             /* ESP32 port: HMAC-mode security on; K_dev = HMAC(master, label || device_id) */
    const uint8_t *key_master;
    size_t      key_master_len;
    const uint8_t *device_id;          /* served as F18C; the 0x27 key hashes the same bytes. ESP32: NULL = base MAC */
    size_t      device_id_len;
    const char *product;               /* ESP32 engine: esp_app_desc project name the image must carry; NULL = any */
    uint8_t     hw_id, layout_id;      /* ESP32 engine: descriptor values the image must carry */
    const uint8_t *key_pubkey;         /* ESP32 port: ECDSA-mode security (udsota_keys.h); wins over key_label */
    size_t      key_pubkey_len;
} udsota_config_t;
