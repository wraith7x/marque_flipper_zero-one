#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
marque.py - Author-side tool for Marque Rules-of-Engagement tokens.

The client's security authority (or test lead) uses this to turn a
human-readable ROE policy (JSON) into a compact, signed binary scope token
(.marque) that a Flipper Zero .fap or Flipper One daemon can verify and enforce.

Subcommands:
  keygen   create an Ed25519 signing keypair
  compile  JSON ROE  ->  signed .marque  (the thing you load on the device)
  verify   check a .marque against a public key (what the device does)
  dump     decode a .marque back to human-readable (confirm it matches intent)
  pin      emit the C array of the pubkey to bake into the device build

Binary format: see core/scope_token_format.md (SLTOK v1, little-endian).
Dependency: cryptography  (pip install cryptography)
"""
import argparse, json, hashlib, sys, base64, struct, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization

MAGIC = b"MARQ"
VERSION = 1

# TLV tags (keep in sync with core/scope_token.h)
T_ENGAGEMENT_ID   = 0x01
T_NOT_BEFORE      = 0x02
T_NOT_AFTER       = 0x03
T_SUBGHZ_FLAGS    = 0x10
T_SUBGHZ_RANGE    = 0x11
T_RFID_FLAGS      = 0x20
T_RFID_UID        = 0x21
T_RFID_FACILITY   = 0x22
T_NFC_FLAGS       = 0x30
T_NFC_UID         = 0x31
T_IR_FLAGS        = 0x40
T_BADUSB_FLAGS    = 0x50
T_GPIOWIFI_FLAGS  = 0x60
T_NOGO_FREQ       = 0x70
T_NOGO_UID        = 0x71
T_MAX_TX_PER_MIN  = 0x80
T_NET_CIDR        = 0x0A
T_NET_PORT_RANGE  = 0x0B

TAG_NAMES = {v: k for k, v in list(globals().items()) if k.startswith("T_")}


# ---- helpers ----------------------------------------------------------------
def _tlv(tag, value: bytes) -> bytes:
    return struct.pack("<BH", tag, len(value)) + value

def _epoch(iso: str) -> int:
    return int(datetime.datetime.fromisoformat(iso).timestamp())

def _flags(d, *bits) -> int:
    """bits: list of (key, bitpos)."""
    out = 0
    for key, pos in bits:
        if d.get(key):
            out |= (1 << pos)
    return out

def key_fingerprint(pub: Ed25519PublicKey) -> bytes:
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).digest()[:8]

def _load_priv(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def _load_pub(path):
    with open(path) as f:
        raw = base64.b64decode(f.read().strip())
    return Ed25519PublicKey.from_public_bytes(raw)


# ---- compile ----------------------------------------------------------------
def build_body(policy: dict) -> bytes:
    b = bytearray()
    eng = policy.get("engagement", {})
    b += _tlv(T_ENGAGEMENT_ID, eng.get("id", "").encode("utf-8"))

    w = policy.get("window", {})
    if "not_before" in w:
        b += _tlv(T_NOT_BEFORE, struct.pack("<q", _epoch(w["not_before"])))
    if "not_after" in w:
        b += _tlv(T_NOT_AFTER, struct.pack("<q", _epoch(w["not_after"])))

    scope = policy.get("scope", {})

    sg = scope.get("subghz")
    if sg is not None:
        b += _tlv(T_SUBGHZ_FLAGS,
                  bytes([_flags(sg, ("rx", 0), ("tx", 1))]))
        for lo, hi in sg.get("freq_ranges_hz", []):
            b += _tlv(T_SUBGHZ_RANGE, struct.pack("<II", lo, hi))

    rf = scope.get("rfid_125k")
    if rf is not None:
        b += _tlv(T_RFID_FLAGS,
                  bytes([_flags(rf, ("read", 0), ("emulate", 1), ("write", 2))]))
        for uid in rf.get("allow_uids", []):
            b += _tlv(T_RFID_UID, uid.encode("utf-8"))
        for fc in rf.get("allow_facility_codes", []):
            b += _tlv(T_RFID_FACILITY, struct.pack("<H", fc))

    nfc = scope.get("nfc")
    if nfc is not None:
        b += _tlv(T_NFC_FLAGS,
                  bytes([_flags(nfc, ("read", 0), ("emulate", 1), ("write", 2))]))
        for uid in nfc.get("allow_uids", []):
            b += _tlv(T_NFC_UID, uid.encode("utf-8"))

    ir = scope.get("infrared")
    if ir is not None:
        b += _tlv(T_IR_FLAGS, bytes([_flags(ir, ("tx", 1))]))
    bu = scope.get("badusb")
    if bu is not None:
        b += _tlv(T_BADUSB_FLAGS, bytes([_flags(bu, ("run", 0))]))
    gw = scope.get("gpio_wifi")
    if gw is not None:
        b += _tlv(T_GPIOWIFI_FLAGS, bytes([_flags(gw, ("run", 0))]))

    net = scope.get("network")
    if net is not None:
        for cidr in net.get("allow_cidrs", []):
            b += _tlv(T_NET_CIDR, cidr.encode("utf-8"))
        for lo, hi in net.get("allow_port_ranges", []):
            b += _tlv(T_NET_PORT_RANGE, struct.pack("<HH", lo, hi))

    nogo = policy.get("no_go", {})
    for f in nogo.get("freqs_hz", []):
        b += _tlv(T_NOGO_FREQ, struct.pack("<I", f))
    for uid in nogo.get("uids", []):
        b += _tlv(T_NOGO_UID, uid.encode("utf-8"))

    limits = policy.get("limits", {})
    if "max_tx_per_minute" in limits:
        b += _tlv(T_MAX_TX_PER_MIN, struct.pack("<H", limits["max_tx_per_minute"]))

    return bytes(b)


def cmd_compile(args):
    priv = _load_priv(args.priv)
    pub = priv.public_key()
    with open(args.policy) as f:
        policy = json.load(f)

    body = build_body(policy)
    header = struct.pack("<HHI", VERSION, 0, len(body))
    signed_region = MAGIC + header + body
    sig = priv.sign(signed_region)
    trailer = struct.pack("<H", len(sig)) + sig + key_fingerprint(pub)

    with open(args.out, "wb") as f:
        f.write(signed_region + trailer)
    print(f"compiled -> {args.out}  ({len(signed_region)+len(trailer)} bytes)")
    print(f"key_id   : {key_fingerprint(pub).hex()}")
    print(f"body     : {len(body)} bytes, signed region {len(signed_region)} bytes")


# ---- parse / verify / dump --------------------------------------------------
def parse_token(buf: bytes):
    if buf[:4] != MAGIC:
        raise ValueError("bad magic")
    version, flags, body_len = struct.unpack_from("<HHI", buf, 4)
    body_off = 12
    body = buf[body_off:body_off + body_len]
    trailer_off = body_off + body_len
    (sig_len,) = struct.unpack_from("<H", buf, trailer_off)
    sig = buf[trailer_off + 2: trailer_off + 2 + sig_len]
    key_id = buf[trailer_off + 2 + sig_len: trailer_off + 2 + sig_len + 8]
    signed_region = buf[:trailer_off]

    records = []
    i = 0
    while i < len(body):
        tag, ln = struct.unpack_from("<BH", body, i)
        val = body[i + 3: i + 3 + ln]
        records.append((tag, val))
        i += 3 + ln
    return dict(version=version, body_len=body_len, records=records,
                sig=sig, key_id=key_id, signed_region=signed_region)


def cmd_verify(args):
    pub = _load_pub(args.pub)
    with open(args.token, "rb") as f:
        buf = f.read()
    t = parse_token(buf)
    if t["key_id"] != key_fingerprint(pub):
        print(f"FAIL: key_id mismatch ({t['key_id'].hex()} != "
              f"{key_fingerprint(pub).hex()})"); sys.exit(2)
    try:
        pub.verify(t["sig"], t["signed_region"])
    except Exception:
        print("FAIL: bad signature (token altered or wrong signer)"); sys.exit(2)
    print("OK: signature valid")
    print(f"  key_id : {t['key_id'].hex()}")
    _summ(t)


def cmd_dump(args):
    with open(args.token, "rb") as f:
        buf = f.read()
    t = parse_token(buf)
    print(f"version {t['version']}, {len(t['records'])} records, "
          f"key_id {t['key_id'].hex()}")
    for tag, val in t["records"]:
        name = TAG_NAMES.get(tag, f"0x{tag:02x}")
        print(f"  {name:18} {val.hex()}")


def _summ(t):
    for tag, val in t["records"]:
        if tag == T_ENGAGEMENT_ID:
            print(f"  engagement: {val.decode()}")
        elif tag == T_NOT_BEFORE:
            e = struct.unpack("<q", val)[0]
            print(f"  not_before: {datetime.datetime.fromtimestamp(e)}")
        elif tag == T_NOT_AFTER:
            e = struct.unpack("<q", val)[0]
            print(f"  not_after : {datetime.datetime.fromtimestamp(e)}")


def cmd_keygen(args):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    with open(args.priv, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
    with open(args.pub, "w") as f:
        f.write(base64.b64encode(pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)).decode() + "\n")
    print(f"private -> {args.priv}  (KEEP SECRET)")
    print(f"public  -> {args.pub}")
    print(f"key_id  : {key_fingerprint(pub).hex()}")


def cmd_pin(args):
    pub = _load_pub(args.pub)
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    carr = ", ".join(f"0x{b:02x}" for b in raw)
    kid = ", ".join(f"0x{b:02x}" for b in key_fingerprint(pub))
    print("// Pin the authorized signer into the device build:")
    print(f"static const uint8_t MARQUE_PUBKEY[32] = {{ {carr} }};")
    print(f"static const uint8_t MARQUE_KEY_ID[8]  = {{ {kid} }};")


def main():
    p = argparse.ArgumentParser(description="Marque ROE token tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen"); g.set_defaults(func=cmd_keygen)
    g.add_argument("--priv", default="marque_private.pem")
    g.add_argument("--pub", default="marque_public.b64")

    c = sub.add_parser("compile"); c.set_defaults(func=cmd_compile)
    c.add_argument("policy")
    c.add_argument("--priv", default="marque_private.pem")
    c.add_argument("--out", default="engagement.marque")

    v = sub.add_parser("verify"); v.set_defaults(func=cmd_verify)
    v.add_argument("token")
    v.add_argument("--pub", default="marque_public.b64")

    d = sub.add_parser("dump"); d.set_defaults(func=cmd_dump)
    d.add_argument("token")

    k = sub.add_parser("pin"); k.set_defaults(func=cmd_pin)
    k.add_argument("--pub", default="marque_public.b64")

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
