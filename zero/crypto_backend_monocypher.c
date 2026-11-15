/* SPDX-License-Identifier: GPL-3.0-or-later */
/* crypto_backend_monocypher.c - Flipper Zero Ed25519 backend.
 *
 * Vendor Monocypher (public domain / CC0 / BSD-2) into zero/lib/monocypher.
 * Monocypher's EdDSA uses SHA-512; enable the optional ed25519 module
 * (monocypher-ed25519.c/.h) which provides crypto_ed25519_check().
 *
 *   https://monocypher.org   (single-file, ~fits comfortably in a FAP)
 */
#include "../core/crypto_backend.h"
#include "lib/monocypher/monocypher-ed25519.h"

int sl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg,
                      size_t len, const uint8_t pk[32]) {
    /* crypto_ed25519_check returns 0 when the signature is valid. */
    return crypto_ed25519_check(sig, pk, msg, len);
}
