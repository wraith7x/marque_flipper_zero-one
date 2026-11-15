/* SPDX-License-Identifier: GPL-3.0-or-later */
/* crypto_backend_libsodium.c - Flipper One (Linux) Ed25519 backend.
 * Build dep: libsodium (apt install libsodium-dev). */
#include "../core/crypto_backend.h"
#include <sodium.h>

int sl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg,
                      size_t len, const uint8_t pk[32]) {
    if (sodium_init() < 0) return -1;
    /* returns 0 on success */
    return crypto_sign_ed25519_verify_detached(sig, msg, len, pk);
}
