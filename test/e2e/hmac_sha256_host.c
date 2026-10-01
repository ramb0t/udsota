/* HMAC-SHA256 on sha256_host; see hmac_sha256_host.h. sha256_host is one-shot, so each pass hashes a
 * heap copy of the padded key followed by its input. From udsota main 0.13.0 (tools/linux_server/hmac_sha256_host.c),
 * MIT, the same project. */
#include "hmac_sha256_host.h"
#include <stdlib.h>
#include <string.h>
#include "sha256_host.h"

#define BLOCK 64u   /* SHA-256 block size, the HMAC key width */
#define HASH  32u

/* SHA-256((key XOR pad) || data), the inner (0x36) or outer (0x5C) pass; false on no memory. */
static bool pass(const uint8_t key[BLOCK], uint8_t pad, const uint8_t *data, size_t len, uint8_t out[HASH])
{
    uint8_t *buf = malloc(BLOCK + len);
    if (buf == NULL) {
        return false;
    }
    for (size_t i = 0; i < BLOCK; i++) {
        buf[i] = key[i] ^ pad;
    }
    if (len > 0u) {
        memcpy(&buf[BLOCK], data, len);
    }
    const bool ok = sha256_host(buf, BLOCK + len, out);
    memset(buf, 0, BLOCK);
    free(buf);
    return ok;
}

/* See hmac_sha256_host.h. A key longer than one block is hashed first; every key is zero-padded to 64 bytes. */
bool hmac_sha256_host(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    if (out == NULL || (key == NULL && key_len > 0u) || (msg == NULL && msg_len > 0u)) {
        return false;
    }
    uint8_t k[BLOCK] = {0};
    if (key_len > BLOCK) {
        if (!sha256_host(key, key_len, k)) {
            return false;
        }
    } else if (key_len > 0u) {
        memcpy(k, key, key_len);
    }
    uint8_t inner[HASH];
    const bool ok = pass(k, 0x36u, msg, msg_len, inner) && pass(k, 0x5Cu, inner, HASH, out);
    memset(k, 0, sizeof k);
    return ok;
}
