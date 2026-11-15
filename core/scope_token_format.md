# Marque token v1 (.marque) — Marque binary token format

A **scope token** is the compiled, signed form of an engagement's Rules of
Engagement. The client's security authority authors the ROE as JSON, then
`tools/marque.py compile` turns it into this compact binary and signs it.
The device (Flipper Zero `.fap` or Flipper One daemon) loads the `.marque`,
verifies the signature against a pinned public key, and enforces the rules.

Design goals: tiny, allocation-free to parse, and signed over its own literal
bytes so an MCU never has to re-canonicalize anything.

All integers are **little-endian**.

## Overall layout

```
+--------+------------------+------------------+-------------------------+
| magic  | header           | body (TLVs)      | trailer (signature)     |
| 4 B    | 8 B              | body_len B       | 2 + 64 + 8 B            |
+--------+------------------+------------------+-------------------------+
         \__________ signed region = magic+header+body ___________/
```

### magic (4 bytes)
ASCII `MARQ`.

### header (8 bytes)
| field     | type | notes                                  |
|-----------|------|----------------------------------------|
| version   | u16  | 1                                      |
| flags     | u16  | reserved, 0                            |
| body_len  | u32  | length of the TLV body in bytes        |

### body — a sequence of TLV records
Each record:
| field | type | notes                        |
|-------|------|------------------------------|
| type  | u8   | tag (table below)            |
| len   | u16  | length of `value`            |
| value | len B| payload                      |

Records may repeat where marked. Unknown tags are **skipped** (forward-compat),
but an unknown tag never grants permission — the device defaults to deny.

### trailer
| field     | type    | notes                                   |
|-----------|---------|-----------------------------------------|
| sig_len   | u16     | 64 for ed25519                          |
| signature | 64 B    | Ed25519 over the signed region          |
| key_id    | 8 B     | first 8 bytes of SHA-256(pubkey)        |

## TLV tag table

| tag  | name                | value encoding                 | repeat |
|------|---------------------|--------------------------------|--------|
| 0x01 | ENGAGEMENT_ID       | utf8                           | no     |
| 0x02 | NOT_BEFORE_EPOCH    | i64 (unix seconds)             | no     |
| 0x03 | NOT_AFTER_EPOCH     | i64 (unix seconds)             | no     |
| 0x10 | SUBGHZ_FLAGS        | u8 bit0=rx bit1=tx             | no     |
| 0x11 | SUBGHZ_FREQ_RANGE   | u32 lo_hz, u32 hi_hz           | yes    |
| 0x20 | RFID_FLAGS          | u8 bit0=read bit1=emu bit2=wr  | no     |
| 0x21 | RFID_ALLOW_UID      | utf8 (e.g. "EM4100:1A2B..")    | yes    |
| 0x22 | RFID_FACILITY       | u16                            | yes    |
| 0x30 | NFC_FLAGS           | u8 bit0=read bit1=emu bit2=wr  | no     |
| 0x31 | NFC_ALLOW_UID       | utf8 hex (e.g. "04A1B2..")     | yes    |
| 0x40 | IR_FLAGS            | u8 bit1=tx                     | no     |
| 0x50 | BADUSB_FLAGS        | u8 bit0=run                    | no     |
| 0x60 | GPIOWIFI_FLAGS      | u8 bit0=run                    | no     |
| 0x70 | NOGO_FREQ           | u32 hz                         | yes    |
| 0x71 | NOGO_UID            | utf8                           | yes    |
| 0x80 | MAX_TX_PER_MIN      | u16                            | no     |
| 0x0A | NET_CIDR            | utf8 (One only, e.g. 10.0.0/24)| yes    |
| 0x0B | NET_PORT_RANGE      | u16 lo, u16 hi (One only)      | yes    |

## Enforcement rule (both devices)
An action is permitted **only if** all hold:
1. `NOT_BEFORE_EPOCH <= now <= NOT_AFTER_EPOCH` (device RTC / system clock)
2. the action's capability flag is set
3. the target (freq / UID / facility / host:port) is inside an allow entry
4. the target matches **no** NOGO entry
Any parse error, missing field, or unknown-but-required condition => **deny**.
