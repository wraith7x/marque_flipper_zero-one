/* SPDX-License-Identifier: GPL-3.0-or-later */
/* crypto_backend_stub.c - HOST TEST ONLY. Always reports "valid".
 * Never ship this. Real builds link Monocypher (Zero) or libsodium (One). */
#include "crypto_backend.h"
int sl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg,
                      size_t len, const uint8_t pk[32]) {
    (void)sig; (void)msg; (void)len; (void)pk;
    return 0; /* pretend valid so we can test parsing + enforcement alone */
}
