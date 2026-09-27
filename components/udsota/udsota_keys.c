/* Default 0x27 key derivation (see udsota_keys.h): K_dev, the expected key and a known-answer self-test.
 * Pure: the HMAC is injected. */
#include "udsota_keys.h"

#include <string.h>

/* RFC 4231 test case 2: HMAC-SHA256("Jefe", "what do ya want for nothing?"). */
static const uint8_t KAT_TC2[UDSOTA_KEYS_HMAC_LEN] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
    0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
    0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
};
/* The self-test's inputs: master bytes 0..31, this label and ID, seed bytes 0x10..0x1F. */
static const char    KAT_LABEL[] = "udsota-kat";
static const uint8_t KAT_ID[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t KAT_KDEV[UDSOTA_KEYS_KDEV_LEN] = {
    0x7b, 0xac, 0x00, 0xce, 0x78, 0x93, 0x69, 0xa8,
    0xfb, 0x6f, 0x3c, 0xe1, 0xd1, 0xfb, 0xe7, 0xfe,
    0xa0, 0x2c, 0xd3, 0xcd, 0xbe, 0xd0, 0x2a, 0x23,
    0xa0, 0xa4, 0x8a, 0x9d, 0x1a, 0x26, 0x87, 0x57,
};
static const uint8_t KAT_KEY_L1[UDSOTA_KEYS_KEY_LEN] = {
    0x15, 0x32, 0xad, 0x02, 0x43, 0xf9, 0xaa, 0x10,
    0x04, 0x24, 0xaa, 0x24, 0xa0, 0xd2, 0x83, 0x19,
};
static const uint8_t KAT_KEY_L3[UDSOTA_KEYS_KEY_LEN] = {
    0x27, 0xe8, 0x91, 0xcd, 0x8c, 0x86, 0xac, 0x41,
    0xa7, 0x88, 0x2a, 0x4f, 0x81, 0xd6, 0x66, 0xf3,
};

/* Zeroes n bytes through a volatile pointer so the compiler cannot drop the wipe of key material. */
static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- > 0) {
        *v++ = 0;
    }
}

/* Length of s, or max + 1 when s is longer than max, reading no further than s[max]. */
static size_t bounded_len(const char *s, size_t max)
{
    size_t n = 0;
    while (n <= max && s[n] != '\0') {
        n++;
    }
    return n;
}

/* True for a requestSeed sub-function byte: odd and 0x01..0x7D (the suppress bit already stripped; 0x7F's sendKey would be 0x80). */
static bool seed_level_ok(uint8_t level)
{
    return (level & 1u) != 0u && level <= 0x7Du;
}

/* Derives K_dev from master under label and id; see udsota_keys.h. */
bool udsota_keys_derive_kdev(udsota_hmac_fn hmac, const uint8_t *master, size_t master_len, const char *label,
                             const uint8_t *id, size_t id_len, uint8_t kdev[UDSOTA_KEYS_KDEV_LEN])
{
    if (kdev == NULL) {
        return false;
    }
    const size_t label_len = (label != NULL) ? bounded_len(label, UDSOTA_KEYS_LABEL_MAX) : 0u;
    if (hmac == NULL || master == NULL || master_len == 0u || label == NULL ||
        label_len > UDSOTA_KEYS_LABEL_MAX || id == NULL || id_len > UDSOTA_KEYS_ID_MAX) {
        wipe(kdev, UDSOTA_KEYS_KDEV_LEN);
        return false;
    }
    uint8_t msg[UDSOTA_KEYS_LABEL_MAX + UDSOTA_KEYS_ID_MAX];
    memcpy(msg, label, label_len);
    memcpy(&msg[label_len], id, id_len);
    if (!hmac(master, master_len, msg, label_len + id_len, kdev)) {
        wipe(kdev, UDSOTA_KEYS_KDEV_LEN);
        return false;
    }
    return true;
}

/* Derives the expected 16-byte key for one seed and requestSeed level; see udsota_keys.h. */
bool udsota_keys_derive_key(udsota_hmac_fn hmac, const uint8_t kdev[UDSOTA_KEYS_KDEV_LEN],
                            const uint8_t seed[UDSOTA_KEYS_SEED_LEN], uint8_t level,
                            const uint8_t *id, size_t id_len, uint8_t key[UDSOTA_KEYS_KEY_LEN])
{
    if (key == NULL) {
        return false;
    }
    if (hmac == NULL || kdev == NULL || seed == NULL || id == NULL || id_len > UDSOTA_KEYS_ID_MAX ||
        !seed_level_ok(level)) {
        wipe(key, UDSOTA_KEYS_KEY_LEN);
        return false;
    }
    uint8_t msg[UDSOTA_KEYS_SEED_LEN + 1u + UDSOTA_KEYS_ID_MAX];
    memcpy(msg, seed, UDSOTA_KEYS_SEED_LEN);
    msg[UDSOTA_KEYS_SEED_LEN] = level;
    memcpy(&msg[UDSOTA_KEYS_SEED_LEN + 1u], id, id_len);
    uint8_t full[UDSOTA_KEYS_HMAC_LEN];
    const bool ok = hmac(kdev, UDSOTA_KEYS_KDEV_LEN, msg, UDSOTA_KEYS_SEED_LEN + 1u + id_len, full);
    if (ok) {
        memcpy(key, full, UDSOTA_KEYS_KEY_LEN);
    } else {
        wipe(key, UDSOTA_KEYS_KEY_LEN);
    }
    wipe(full, sizeof full);   /* leave no copy of the derived key or its input on this stack */
    wipe(msg, sizeof msg);
    return ok;
}

/* Runs the known-answer vectors through hmac and both derivations; true only if every byte matches. */
bool udsota_keys_self_test(udsota_hmac_fn hmac)
{
    static const char TC2_KEY[] = "Jefe";
    static const char TC2_MSG[] = "what do ya want for nothing?";
    uint8_t out[UDSOTA_KEYS_HMAC_LEN];
    if (hmac == NULL
        || !hmac((const uint8_t *)TC2_KEY, sizeof TC2_KEY - 1,
                 (const uint8_t *)TC2_MSG, sizeof TC2_MSG - 1, out)
        || memcmp(out, KAT_TC2, sizeof out) != 0) {
        return false;
    }
    uint8_t master[32];
    uint8_t seed[UDSOTA_KEYS_SEED_LEN];
    for (size_t i = 0; i < sizeof master; i++) {
        master[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < sizeof seed; i++) {
        seed[i] = (uint8_t)(0x10 + i);
    }
    uint8_t kdev[UDSOTA_KEYS_KDEV_LEN];
    uint8_t key[UDSOTA_KEYS_KEY_LEN];
    bool ok = udsota_keys_derive_kdev(hmac, master, sizeof master, KAT_LABEL, KAT_ID, sizeof KAT_ID, kdev)
              && memcmp(kdev, KAT_KDEV, sizeof kdev) == 0
              && udsota_keys_derive_key(hmac, kdev, seed, 0x01u, KAT_ID, sizeof KAT_ID, key)
              && memcmp(key, KAT_KEY_L1, sizeof key) == 0
              && udsota_keys_derive_key(hmac, kdev, seed, 0x03u, KAT_ID, sizeof KAT_ID, key)
              && memcmp(key, KAT_KEY_L3, sizeof key) == 0;
    wipe(kdev, sizeof kdev);
    wipe(key, sizeof key);
    return ok;
}
