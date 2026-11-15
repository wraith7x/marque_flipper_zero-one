/* SPDX-License-Identifier: GPL-3.0-or-later */
/* scope_token.h - Portable Marque token parser + policy checks.
 *
 * No dynamic allocation, no platform headers. Shared verbatim by the Flipper
 * Zero .fap and the Flipper One Linux daemon. See scope_token_format.md.
 */
#ifndef MARQUE_SCOPE_TOKEN_H
#define MARQUE_SCOPE_TOKEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Bounds — a token exceeding any of these is rejected (SL_ERR_TOOMANY). */
#define SL_MAX_FREQ_RANGES 8
#define SL_MAX_RFID_UIDS   16
#define SL_MAX_FACILITIES  8
#define SL_MAX_NFC_UIDS    16
#define SL_MAX_NOGO_FREQS  16
#define SL_MAX_NOGO_UIDS   16
#define SL_MAX_CIDRS       16
#define SL_MAX_PORTRANGES  16
#define SL_UID_MAXLEN      31
#define SL_ENGID_MAXLEN    31
#define SL_CIDR_MAXLEN     31

/* Capability flag bits (match the format spec). */
#define SL_SUBGHZ_RX  (1u << 0)
#define SL_SUBGHZ_TX  (1u << 1)
#define SL_RW_READ    (1u << 0)
#define SL_RW_EMULATE (1u << 1)
#define SL_RW_WRITE   (1u << 2)
#define SL_IR_TX      (1u << 1)
#define SL_RUN        (1u << 0)

typedef enum {
    SL_OK = 0,
    SL_ERR_MAGIC,
    SL_ERR_TRUNCATED,
    SL_ERR_TOOMANY,
    SL_ERR_BADLEN,
    SL_ERR_SIG,        /* signature invalid / wrong signer */
    SL_ERR_KEYID,      /* token signed by an unpinned key   */
} sl_err_t;

typedef struct { uint32_t lo, hi; } sl_range_u32_t;
typedef struct { uint16_t lo, hi; } sl_range_u16_t;
typedef struct { char s[SL_UID_MAXLEN + 1]; } sl_str_t;
typedef struct { char s[SL_CIDR_MAXLEN + 1]; } sl_cidr_t;

typedef struct {
    char     engagement_id[SL_ENGID_MAXLEN + 1];
    int64_t  not_before;      /* unix seconds; 0 = unset */
    int64_t  not_after;

    uint8_t  subghz_flags;
    sl_range_u32_t subghz_ranges[SL_MAX_FREQ_RANGES];
    uint8_t  subghz_range_n;

    uint8_t  rfid_flags;
    sl_str_t rfid_uids[SL_MAX_RFID_UIDS];
    uint8_t  rfid_uid_n;
    uint16_t facilities[SL_MAX_FACILITIES];
    uint8_t  facility_n;

    uint8_t  nfc_flags;
    sl_str_t nfc_uids[SL_MAX_NFC_UIDS];
    uint8_t  nfc_uid_n;

    uint8_t  ir_flags;
    uint8_t  badusb_flags;
    uint8_t  gpiowifi_flags;

    uint32_t nogo_freqs[SL_MAX_NOGO_FREQS];
    uint8_t  nogo_freq_n;
    sl_str_t nogo_uids[SL_MAX_NOGO_UIDS];
    uint8_t  nogo_uid_n;

    uint16_t max_tx_per_min;  /* 0 = unset */

    sl_cidr_t      net_cidrs[SL_MAX_CIDRS];
    uint8_t        net_cidr_n;
    sl_range_u16_t net_ports[SL_MAX_PORTRANGES];
    uint8_t        net_port_n;

    /* raw signature material (kept for an explicit verify step) */
    const uint8_t *signed_region;
    size_t         signed_len;
    const uint8_t *sig;        /* 64 bytes */
    uint8_t        key_id[8];
} sl_token_t;

/* Parse raw bytes into `out`. Does NOT verify the signature. */
sl_err_t sl_token_parse(const uint8_t *buf, size_t len, sl_token_t *out);

/* Verify the parsed token's signature against a pinned key + key_id.
 * Call sl_token_parse first. Returns SL_OK only if the pinned key_id matches
 * and sl_ed25519_verify accepts. */
sl_err_t sl_token_verify(const sl_token_t *t,
                         const uint8_t pinned_pubkey[32],
                         const uint8_t pinned_key_id[8]);

/* ---- enforcement predicates. `now` is unix seconds from the device clock. ---
 * Each returns true only if the action is fully in scope. */
bool sl_window_open(const sl_token_t *t, int64_t now);
bool sl_allow_subghz_tx(const sl_token_t *t, uint32_t freq_hz, int64_t now);
bool sl_allow_subghz_rx(const sl_token_t *t, uint32_t freq_hz, int64_t now);
bool sl_allow_rfid(const sl_token_t *t, uint8_t action_bit,
                   const char *uid, int64_t now);
bool sl_allow_nfc(const sl_token_t *t, uint8_t action_bit,
                  const char *uid, int64_t now);

const char *sl_strerror(sl_err_t e);

#endif /* MARQUE_SCOPE_TOKEN_H */
