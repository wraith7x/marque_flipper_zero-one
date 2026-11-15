/* SPDX-License-Identifier: GPL-3.0-or-later */
/* scope_token.c - Portable Marque token parser + policy checks. */
#include "scope_token.h"
#include "crypto_backend.h"
#include <string.h>

/* ---- little-endian readers (no unaligned access, endian-independent) ---- */
static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int64_t rd_i64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return (int64_t)v;
}

static void copy_str(char *dst, size_t cap, const uint8_t *v, uint16_t ln) {
    if (ln > cap) ln = (uint16_t)cap;      /* truncate over-long entries */
    memcpy(dst, v, ln);
    dst[ln] = '\0';
}

/* TLV tags (match tools/marque.py and scope_token_format.md). */
enum {
    TAG_ENGAGEMENT_ID = 0x01, TAG_NOT_BEFORE = 0x02, TAG_NOT_AFTER = 0x03,
    TAG_SUBGHZ_FLAGS = 0x10, TAG_SUBGHZ_RANGE = 0x11,
    TAG_RFID_FLAGS = 0x20, TAG_RFID_UID = 0x21, TAG_RFID_FACILITY = 0x22,
    TAG_NFC_FLAGS = 0x30, TAG_NFC_UID = 0x31,
    TAG_IR_FLAGS = 0x40, TAG_BADUSB_FLAGS = 0x50, TAG_GPIOWIFI_FLAGS = 0x60,
    TAG_NOGO_FREQ = 0x70, TAG_NOGO_UID = 0x71, TAG_MAX_TX_PER_MIN = 0x80,
    TAG_NET_CIDR = 0x0A, TAG_NET_PORT_RANGE = 0x0B,
};

sl_err_t sl_token_parse(const uint8_t *buf, size_t len, sl_token_t *out) {
    memset(out, 0, sizeof(*out));
    if (len < 12 + 2 + 64 + 8) return SL_ERR_TRUNCATED;
    if (memcmp(buf, "MARQ", 4) != 0) return SL_ERR_MAGIC;

    uint32_t body_len = rd_u32(buf + 8);
    size_t body_off = 12;
    size_t trailer_off = body_off + body_len;
    if (trailer_off + 2 + 64 + 8 > len) return SL_ERR_TRUNCATED;

    uint16_t sig_len = rd_u16(buf + trailer_off);
    if (sig_len != 64) return SL_ERR_BADLEN;
    out->signed_region = buf;
    out->signed_len = trailer_off;
    out->sig = buf + trailer_off + 2;
    memcpy(out->key_id, buf + trailer_off + 2 + 64, 8);

    size_t i = body_off;
    size_t end = body_off + body_len;
    while (i + 3 <= end) {
        uint8_t tag = buf[i];
        uint16_t ln = rd_u16(buf + i + 1);
        const uint8_t *v = buf + i + 3;
        if (i + 3 + ln > end) return SL_ERR_TRUNCATED;

        switch (tag) {
        case TAG_ENGAGEMENT_ID:
            copy_str(out->engagement_id, SL_ENGID_MAXLEN, v, ln); break;
        case TAG_NOT_BEFORE: if (ln == 8) out->not_before = rd_i64(v); break;
        case TAG_NOT_AFTER:  if (ln == 8) out->not_after  = rd_i64(v); break;
        case TAG_SUBGHZ_FLAGS: if (ln == 1) out->subghz_flags = v[0]; break;
        case TAG_SUBGHZ_RANGE:
            if (ln == 8) {
                if (out->subghz_range_n >= SL_MAX_FREQ_RANGES) return SL_ERR_TOOMANY;
                out->subghz_ranges[out->subghz_range_n].lo = rd_u32(v);
                out->subghz_ranges[out->subghz_range_n].hi = rd_u32(v + 4);
                out->subghz_range_n++;
            } break;
        case TAG_RFID_FLAGS: if (ln == 1) out->rfid_flags = v[0]; break;
        case TAG_RFID_UID:
            if (out->rfid_uid_n >= SL_MAX_RFID_UIDS) return SL_ERR_TOOMANY;
            copy_str(out->rfid_uids[out->rfid_uid_n++].s, SL_UID_MAXLEN, v, ln);
            break;
        case TAG_RFID_FACILITY:
            if (ln == 2) {
                if (out->facility_n >= SL_MAX_FACILITIES) return SL_ERR_TOOMANY;
                out->facilities[out->facility_n++] = rd_u16(v);
            } break;
        case TAG_NFC_FLAGS: if (ln == 1) out->nfc_flags = v[0]; break;
        case TAG_NFC_UID:
            if (out->nfc_uid_n >= SL_MAX_NFC_UIDS) return SL_ERR_TOOMANY;
            copy_str(out->nfc_uids[out->nfc_uid_n++].s, SL_UID_MAXLEN, v, ln);
            break;
        case TAG_IR_FLAGS:      if (ln == 1) out->ir_flags = v[0]; break;
        case TAG_BADUSB_FLAGS:  if (ln == 1) out->badusb_flags = v[0]; break;
        case TAG_GPIOWIFI_FLAGS:if (ln == 1) out->gpiowifi_flags = v[0]; break;
        case TAG_NOGO_FREQ:
            if (ln == 4) {
                if (out->nogo_freq_n >= SL_MAX_NOGO_FREQS) return SL_ERR_TOOMANY;
                out->nogo_freqs[out->nogo_freq_n++] = rd_u32(v);
            } break;
        case TAG_NOGO_UID:
            if (out->nogo_uid_n >= SL_MAX_NOGO_UIDS) return SL_ERR_TOOMANY;
            copy_str(out->nogo_uids[out->nogo_uid_n++].s, SL_UID_MAXLEN, v, ln);
            break;
        case TAG_MAX_TX_PER_MIN: if (ln == 2) out->max_tx_per_min = rd_u16(v); break;
        case TAG_NET_CIDR:
            if (out->net_cidr_n >= SL_MAX_CIDRS) return SL_ERR_TOOMANY;
            copy_str(out->net_cidrs[out->net_cidr_n++].s, SL_CIDR_MAXLEN, v, ln);
            break;
        case TAG_NET_PORT_RANGE:
            if (ln == 4) {
                if (out->net_port_n >= SL_MAX_PORTRANGES) return SL_ERR_TOOMANY;
                out->net_ports[out->net_port_n].lo = rd_u16(v);
                out->net_ports[out->net_port_n].hi = rd_u16(v + 2);
                out->net_port_n++;
            } break;
        default: /* unknown tag: skip, never grants permission */ break;
        }
        i += 3 + ln;
    }
    if (i != end) return SL_ERR_BADLEN;
    return SL_OK;
}

sl_err_t sl_token_verify(const sl_token_t *t,
                         const uint8_t pinned_pubkey[32],
                         const uint8_t pinned_key_id[8]) {
    if (memcmp(t->key_id, pinned_key_id, 8) != 0) return SL_ERR_KEYID;
    if (sl_ed25519_verify(t->sig, t->signed_region, t->signed_len,
                          pinned_pubkey) != 0)
        return SL_ERR_SIG;
    return SL_OK;
}

/* ---- enforcement ---- */
bool sl_window_open(const sl_token_t *t, int64_t now) {
    if (t->not_before && now < t->not_before) return false;
    if (t->not_after && now > t->not_after) return false;
    return (t->not_before != 0 && t->not_after != 0);  /* window is mandatory */
}

static bool freq_in_ranges(const sl_token_t *t, uint32_t f) {
    for (uint8_t i = 0; i < t->subghz_range_n; i++)
        if (f >= t->subghz_ranges[i].lo && f <= t->subghz_ranges[i].hi) return true;
    return false;
}
static bool freq_is_nogo(const sl_token_t *t, uint32_t f) {
    for (uint8_t i = 0; i < t->nogo_freq_n; i++)
        if (t->nogo_freqs[i] == f) return true;
    return false;
}
static bool uid_is_nogo(const sl_token_t *t, const char *uid) {
    for (uint8_t i = 0; i < t->nogo_uid_n; i++)
        if (strcmp(t->nogo_uids[i].s, uid) == 0) return true;
    return false;
}

bool sl_allow_subghz_tx(const sl_token_t *t, uint32_t f, int64_t now) {
    if (!sl_window_open(t, now)) return false;
    if (!(t->subghz_flags & SL_SUBGHZ_TX)) return false;
    if (freq_is_nogo(t, f)) return false;
    return freq_in_ranges(t, f);
}
bool sl_allow_subghz_rx(const sl_token_t *t, uint32_t f, int64_t now) {
    if (!sl_window_open(t, now)) return false;
    if (!(t->subghz_flags & SL_SUBGHZ_RX)) return false;
    if (freq_is_nogo(t, f)) return false;
    return freq_in_ranges(t, f);
}
bool sl_allow_rfid(const sl_token_t *t, uint8_t action_bit,
                   const char *uid, int64_t now) {
    if (!sl_window_open(t, now)) return false;
    if (!(t->rfid_flags & action_bit)) return false;
    if (uid_is_nogo(t, uid)) return false;
    for (uint8_t i = 0; i < t->rfid_uid_n; i++)
        if (strcmp(t->rfid_uids[i].s, uid) == 0) return true;
    return false;
}
bool sl_allow_nfc(const sl_token_t *t, uint8_t action_bit,
                  const char *uid, int64_t now) {
    if (!sl_window_open(t, now)) return false;
    if (!(t->nfc_flags & action_bit)) return false;
    if (uid_is_nogo(t, uid)) return false;
    for (uint8_t i = 0; i < t->nfc_uid_n; i++)
        if (strcmp(t->nfc_uids[i].s, uid) == 0) return true;
    return false;
}

const char *sl_strerror(sl_err_t e) {
    switch (e) {
    case SL_OK: return "ok";
    case SL_ERR_MAGIC: return "bad magic";
    case SL_ERR_TRUNCATED: return "truncated";
    case SL_ERR_TOOMANY: return "too many entries";
    case SL_ERR_BADLEN: return "bad length";
    case SL_ERR_SIG: return "bad signature";
    case SL_ERR_KEYID: return "unpinned signer";
    default: return "unknown";
    }
}
