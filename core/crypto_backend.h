/* SPDX-License-Identifier: GPL-3.0-or-later */
/* crypto_backend.h - Ed25519 verification seam for the Marque core.
 *
 * The core never implements crypto itself. Each platform supplies one function:
 *   - Flipper Zero  (.fap)  : back it with Monocypher (vendored, ~public domain)
 *   - Flipper One   (Linux) : back it with libsodium  (crypto_sign_verify_detached)
 *   - Host test             : a stub that returns a fixed verdict
 *
 * Return 0 on a VALID signature, non-zero otherwise. Must be constant-time
 * w.r.t. the signature contents in the real backends.
 */
#ifndef MARQUE_CRYPTO_BACKEND_H
#define MARQUE_CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>

int sl_ed25519_verify(const uint8_t signature[64],
                      const uint8_t *message, size_t message_len,
                      const uint8_t public_key[32]);

#endif /* MARQUE_CRYPTO_BACKEND_H */
