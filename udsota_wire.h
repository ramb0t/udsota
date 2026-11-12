/* udsota's wire contract, with no #include, so a bootloader, a tester or a post-build tool can take it alone;
 * UDSOTA_DL_Z_BOUND needs <stdint.h> from the includer. udsota.h includes it. */
#pragma once

/* ---- Wire contract ----
 * The numbers a tester sees, under the names udsota v0.14.2 gave them; UDSOTA_BARE_*, UDSOTA_DID_IMAGE_PREFIX and
 * UDSOTA_STATUS_BOOT_HELD are newer, and udsota.c neither serves nor sets them. client/udsota/wire.py, keys.py and
 * image.py mirror them, and client/tests/test_udsota.py checks each against its client copy, or against v0.14.2's for
 * the few the client never uses: changing one needs a matching client change and a CHANGELOG entry. NRCs and sessions
 * are iso14229's (UDS_NRC_*, UDS_LEV_DS_*), and the download reasons are udsota_reason_t in udsota.h. */
#define UDSOTA_DID_ACTIVE_SESSION   0xF186u   /* 1 B: the active session */
#define UDSOTA_DID_SW_VERSION       0xF189u   /* the running image's version string */
#define UDSOTA_DID_SERIAL           0xF18Cu   /* the device ID the keys bind to */
#define UDSOTA_DID_STATUS           0xF1F0u   /* 16 B: the A/B slots (udsota_status_t) */
#define UDSOTA_DID_RESULT           0xF1F1u   /* 5 B: the last download's reason and bytes received */
#define UDSOTA_DID_RUNNING_SHA      0xF1F3u   /* 32 B: the running image's app_elf_sha256 */
#define UDSOTA_DID_IMAGE_PREFIX     0xF1F4u   /* 4 B: F1F3's first 4 bytes, from a single-slot bootloader unit's app
                                                 once healthy (docs/wire.md); udsota.c does not serve it */
#define UDSOTA_RID_CHECK_PROG_DEPS  0xFF01u   /* CheckProgrammingDependencies (verify): status udsota_reason_t */
#define UDSOTA_RID_GET_RESUME_POINT 0xF000u   /* reserved: status UDSOTA_RESUME_NOT_AVAILABLE */
#define UDSOTA_RID_ACTIVATE_IMAGE   0xF001u
#define UDSOTA_RID_CONFIRM_IMAGE    0xF002u
#define UDSOTA_RESUME_NOT_AVAILABLE 0xFFu
#define UDSOTA_DL_DFI               0x00u     /* 34's dataFormatIdentifier: the image as it is */
#define UDSOTA_DL_DFI_DEFLATE       0x10u     /* raw DEFLATE (RFC 1951); memorySize is still the image's size */
#define UDSOTA_DL_DFI_DELTA_DEFLATE 0x30u     /* a delta patch from the running image, as raw DEFLATE; memorySize the
                                                 image's size (UDSOTA_DELTA and cfg.allow_delta, else 0x31) */
#define UDSOTA_DL_MAX_BLOCK_LEN     4095u     /* 34's maxNumberOfBlockLength: SID, BSC and 4093 data bytes */
#define UDSOTA_DL_Z_BOUND(size)     ((uint64_t)(size) + ((uint64_t)(size) >> 3) + 1024u)   /* the most bytes a
                                                 DEFLATE download of a size-byte image may take; past it, 0x71 */
#define UDSOTA_SA_SEED_EXTENDED     0x01u     /* 27 01/02, extended session; iso14229's securityLevel once unlocked */
#define UDSOTA_SA_SEED_PROGRAMMING  0x03u     /* 27 03/04, programming session: unlocks downloads */
#define UDSOTA_SEED_LEN             16u
#define UDSOTA_SA_SEED_VALID_MS     30000u    /* a seed is single-use and expires after this */
#define UDSOTA_KEY_LEN              16u       /* HMAC mode: HMAC-SHA256(K_dev, seed || level || ID)[0..15] */
#define UDSOTA_KEYS_SIG_LEN         64u       /* ECDSA mode: r || s over SHA-256 of the message below */
#define UDSOTA_KEYS_SIG_TAG         "udsota-27-ecdsa-v1"   /* the message: tag || seed || level || ID length || ID */
#define UDSOTA_KEYS_PUBKEY_LEN      65u       /* cfg.key_pubkey: 04 || X || Y, P-256 */
#define UDSOTA_KEYS_ID_MAX          16u       /* the longest device ID (F18C) */
#define UDSOTA_IMG_DESC_OFFSET      288u      /* udsota_image_desc_t in the image, right after esp_app_desc_t */
#define UDSOTA_BARE_HDR_MAGIC         0x55445342u /* a bare image's header (docs/wire.md), at its profile's
                                                     header_offset: "UDSB", bytes 42 53 44 55 */
#define UDSOTA_BARE_HDR_VERSION       1u          /* header_version (16 bits at 4); flags (16 bits at 6) are 0 */
#define UDSOTA_BARE_HDR_LEN           224u        /* the whole header, its unnamed fields 0xFF */
#define UDSOTA_BARE_HDR_LENGTH_OFFSET 8u          /* in the header: 4 B, the image's length from its first byte,
                                                     the header included; a multiple of 4 */
#define UDSOTA_BARE_HDR_CRC_OFFSET    12u         /* in the header: 4 B, zlib's CRC-32 of the image's bytes before
                                                     this field and after it */
#define UDSOTA_BARE_HDR_DESC_OFFSET   32u         /* in the header: the descriptor block, UDSOTA_BARE_DESC_LEN */
#define UDSOTA_BARE_HDR_SIG_OFFSET    160u        /* in the header: the signature, 0xFF; reserved */
#define UDSOTA_BARE_HDR_SIG_LEN       64u
#define UDSOTA_BARE_DESC_LEN        128u      /* a non-ESP image's descriptor block: udsota_image_desc_t first */
#define UDSOTA_BARE_VERSION_OFFSET  32u       /* in the block: 32 B, the version string F189 returns, NUL-terminated */
#define UDSOTA_BARE_PROJECT_OFFSET  64u       /* in the block: 32 B, the project name, NUL-terminated */
#define UDSOTA_BARE_IMAGE_ID_OFFSET 96u       /* in the block: 32 B, the image ID F1F3 returns */
#define UDSOTA_STATUS_SIG_CHECKED   0x01u     /* F1F0's flags: images are signature-checked */
#define UDSOTA_STATUS_BOOT_HELD     0x04u     /* F1F0's flags: held in the bootloader, the app failed to start; a
                                                 bootloader unit's, never udsota.c's */
