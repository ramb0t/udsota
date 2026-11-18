/* udsota_host.c: the host build's PSA lock, beside udsota.c. A host build is one task, so the lock is a depth that the
 * host test reads, and a wait on it held fails at once. ESP-IDF's is udsota_esp.c's. The rest of a host platform is
 * the build's to supply (udsota.h). */
#include "udsota.h"
#include "udsota_priv.h"

static int s_psa_depth;

void udsota_psa_lock_init(void) {}

bool udsota_psa_lock(uint32_t wait_ms)
{
    (void)wait_ms;
    if (s_psa_depth != 0) {
        return false;
    }
    s_psa_depth++;
    return true;
}

void udsota_psa_unlock(void)
{
    s_psa_depth--;
}

#if defined(UDSOTA_TEST)
int udsota_test_psa_depth(void)
{
    return s_psa_depth;
}
#endif
