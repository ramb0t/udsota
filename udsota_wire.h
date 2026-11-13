/* udsota's wire contract, with no #include, so a bootloader, a tester or a post-build tool can take it alone;
 * UDSOTA_DL_Z_BOUND and UDSOTA_START_COUNT_WORD need <stdint.h> from the includer. udsota.h includes it, and so do
 * the bootloader core (boot/udsota_boot.h) and the app's side of it (udsota_app.h). */
#pragma once

/* ---- Wire contract ----
 * The numbers a tester sees, under the names udsota v0.14.2 gave them; UDSOTA_BARE_*, UDSOTA_DID_IMAGE_PREFIX,
 * UDSOTA_DID_BOOT_VERSION and UDSOTA_STATUS_BOOT_HELD are not in v0.14.2, and udsota.c neither serves nor sets them;
 * UDSOTA_IMG_DESC_MAGIC is not in v0.14.2 either, though its value is.
 * client/udsota/wire.py, keys.py and image.py mirror them, and client/tests/test_udsota.py checks each against its
 * client copy, or against v0.14.2's for the few the client never uses: changing one needs a matching client change
 * and a CHANGELOG entry. NRCs and sessions are iso14229's (UDS_NRC_*, UDS_LEV_DS_*), and the download reasons are
 * udsota_reason_t below. */
#define UDSOTA_DID_BOOT_VERSION     0xF180u   /* a bootloader unit's: the bootloader's version and its core's udsota
                                                 release; udsota.c does not serve it */
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
#define UDSOTA_IMG_DESC_MAGIC       0x5544534Fu /* udsota_image_desc_t's magic, "UDSO": flash bytes 4F 53 44 55 */
#define UDSOTA_BARE_HDR_MAGIC         0x55445342u /* a bare image's header (docs/wire.md), at its profile's
                                                     header_offset: "UDSB", bytes 42 53 44 55 */
#define UDSOTA_BARE_HDR_VERSION       1u          /* header_version (16 bits at 4); flags (16 bits at 6) are 0 */
#define UDSOTA_BARE_HDR_FLAGS_MUST    0xFF00u     /* flags' high byte: a reader refuses an image with a bit set here
                                                     that it does not know; version 1 defines none */
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

/* Why the last download ended: F1F1's byte 0 and FF01's status, each meaning as docs/wire.md's Reasons table gives
 * it. Wire values, the same from udsota.c and from a bootloader unit. */
typedef enum {
    UDSOTA_DL_OK = 0,
    UDSOTA_DL_BAD_HEADER,           /* 1: not an image this unit takes (its header, its format or its version
                                       string), or a stream that ends before the image rules' bytes */
    UDSOTA_DL_BAD_PROJECT,          /* 2: another project name */
    UDSOTA_DL_BAD_BOARD,            /* 3: no udsota descriptor, descriptor version 0, or another hw_id */
    UDSOTA_DL_BAD_LAYOUT,           /* 4: another partition or slot layout */
    UDSOTA_DL_BAD_DIAG_IDS,         /* 5: the image would answer on other CAN IDs */
    UDSOTA_DL_NOT_NEWER,            /* 6: a release not newer than the running image, or a dev build older; never
                                       from a bootloader unit, which has no version rule */
    UDSOTA_DL_TOO_BIG,              /* 7: larger than the slot */
    UDSOTA_DL_VERIFY_FAILED,        /* 8: FF01's hash, CRC or signature check failed */
    UDSOTA_DL_SIG_FAILED,           /* 9: reserved */
    UDSOTA_DL_WORKER_TIMEOUT,       /* 10: a flash job passed 90 s, or its session ended while it ran */
    UDSOTA_DL_ABORTED,              /* 11: ended early: a session change, S3, the gate, an overrun, or iso14229 */
    UDSOTA_DL_FLASH_ERROR,          /* 12: an erase, write or read-back failed, or no inactive slot */
    UDSOTA_DL_BAD_STREAM,           /* 13: a coded download did not inflate (or patch) to exactly the image */
    UDSOTA_DL_NO_MEMORY,            /* 14: no memory for the inflater, or a delta's patch state */
    UDSOTA_DL_BAD_BASE,             /* 15: a delta patch for another base than the running image, or no hash to tell */
} udsota_reason_t;

/* ---- A bootloader unit's keep words ----
 * Three 16-bit words that survive a software, pin and watchdog reset, shared by a bootloader built on boot/ and its
 * app (udsota_boot_port_keep_* and udsota_app_port_keep_write). A bootloader and an app built from different udsota
 * releases must agree on them, so changing one is a contract change. */
#define UDSOTA_KEEP_WORD_MARK      0u    /* word 0: UDSOTA_HANDOVER_MARK while a handover is pending, else anything */
#define UDSOTA_KEEP_WORD_HANDOVER  1u    /* word 1: the handover's bus, below */
#define UDSOTA_KEEP_WORD_COUNT     2u    /* word 2: the start count with its marker, below */
#define UDSOTA_KEEP_WORDS          3u

/* The handover. The app writes word 1, the bus its 10 02 came in on (1 to 15), then word 0 = UDSOTA_HANDOVER_MARK, then
 * resets. The bootloader takes the handover only if word 0 is the mark, word 0 reads back other than the mark after
 * the bootloader writes 0 to both words, word 1 is a bus from 1 to its cfg.buses (any other value does not decode),
 * and that bus starts; otherwise the boot goes on to the next rule. */
#define UDSOTA_HANDOVER_MARK         0xB007u

/* The start count: how many times the bootloader started the app without the app reaching its healthy mark since.
 * It becomes 0 at boot on a POWER_ON or PIN reset, or when the marker is missing; nothing else clears it at boot. The
 * bootloader adds 1 just before each start of the app; if that write does not keep, the app still starts. The app
 * clears it at its healthy mark and before every deliberate reset (udsota_app_clear_start_count). The bootloader
 * clears it on 11 01 and on F001. A handover boot does not start the app, so it adds nothing. While the start count is
 * hold_after_starts or more, the bootloader holds and F1F0's flags carry UDSOTA_STATUS_BOOT_HELD (0x04). */
#define UDSOTA_START_COUNT_MARKER        0xA5u     /* bits 8-15: present means the low byte is a count */
#define UDSOTA_START_COUNT_MARKER_SHIFT  8u
#define UDSOTA_START_COUNT_MASK          0x00FFu   /* bits 0-7: the count, saturating at 255 */
#define UDSOTA_START_COUNT_WORD(n) \
    ((uint16_t)((UDSOTA_START_COUNT_MARKER << UDSOTA_START_COUNT_MARKER_SHIFT) | ((unsigned)(n) & 0xFFu)))
#define UDSOTA_START_COUNT_CLEAR         UDSOTA_START_COUNT_WORD(0)   /* 0xA500, what every clear writes */
