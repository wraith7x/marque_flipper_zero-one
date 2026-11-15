# Marque

Put the Rules of Engagement *into the tool*. Marque turns an engagement's
authorized scope — frequencies, card IDs, testing window, no-go list (and, on
the Flipper One, network targets) — into a **signed policy the device verifies
and enforces**. An honest pentester can't accidentally act out of scope, and
every attempt is logged for the report.

Nobody ships on-device ROE enforcement today; the norm is a paper scope letter.
This makes the scope machine-checkable.

## Why two front-ends, one core

The Flipper Zero and Flipper One are different machines:

- **Flipper Zero** — STM32 Cortex-M, bare-metal. Apps are `.fap` (ELF)
  binaries. Has the sub-GHz / NFC / RFID / IR radios. "Scope" = RF + cards.
- **Flipper One** — Rockchip RK3576 running Debian-based Flipper OS (+ an RP2350
  MCU). It has *no* sub-GHz/NFC/RFID radios; it's a networking/Linux device.
  "Scope" = network (CIDRs, ports) and the testing window.

So there is no single binary for both. Instead there's **one portable C core**
(the signed-token parser + enforcement logic) and two thin front-ends:

```
            tools/marque.py            author side (client's security lead)
   ROE JSON ───────────────────▶ engagement.marque  (signed, ~300 bytes)
                                        │
                     ┌──────────────────┴───────────────────┐
             core/ (portable C: parse + verify + enforce)    │
                     │                                        │
        zero/  Flipper Zero .fap                  one/  Flipper One daemon
        (Monocypher ed25519)                      (libsodium ed25519)
        gates RF/NFC/RFID actions                 emits nftables egress rules
```

## Repo layout

| path | what |
|------|------|
| `core/scope_token_format.md` | the SLTOK v1 binary format spec |
| `core/scope_token.{h,c}` | portable parser + enforcement predicates (no malloc) |
| `core/crypto_backend.h` | the one-function ed25519 seam |
| `core/test_parse.c`, `core/Makefile` | host test (stub crypto) — proves the format |
| `tools/marque.py` | keygen / compile / verify / dump / pin |
| `tools/example.roe.json` | an example engagement policy |
| `zero/` | Flipper Zero `.fap`: manifest, app, Monocypher backend |
| `one/` | Flipper One Linux daemon: CLI, libsodium backend, nftables |

## Trust model (read this)

- **Authority key.** The *client's* security sponsor runs `keygen` and keeps the
  private key. They sign each engagement's scope. The device pins the public key
  (`pin` emits the C array). A tester cannot forge or widen scope without that
  private key — proven: flip one byte and verification fails.
- **Deny by default.** Any parse error, missing field, closed window, unknown
  tag, or unpinned signer => action refused.
- **Honest limits:**
  - *Clock.* The window is checked against the device clock. On the **Zero** the
    user can change the RTC, so the window stops *accidental* out-of-window work,
    not a determined insider — the signed, hash-chained log is what catches clock
    games in review. On the **One** (real Linux) use NTP + restricted time for
    trusted time.
  - *Boundary (Zero).* The `.fap` governs actions taken *through Marque*. A
    tester who opens the stock Sub-GHz app sidesteps it. That's fine for guarding
    an honest tester against mistakes and producing an evidence trail; it is not
    a kiosk lockdown. True device-wide enforcement needs a firmware fork sharing
    this same core (a later step).
  - *Enforcement strength (One).* Because it's Linux, nftables/network-namespace
    confinement makes scope genuinely hard to cross — effectively firmware-fork
    strength, for free.
- This tool supports **authorized** testing only. It constrains a tester to
  what the client signed off on; it grants no capability of its own.

## Quickstart

```bash
# host test of the core (no hardware needed)
cd core && make test

# author an engagement
cd tools
python3 marque.py keygen
python3 marque.py compile example.roe.json --out engagement.marque
python3 marque.py verify engagement.marque
python3 marque.py pin                 # paste output into the device build

# Flipper Zero: vendor Monocypher under zero/lib/monocypher, then in a
# firmware checkout:  ./fbt fap_marque   and copy engagement.marque to
# /ext/apps_data/marque/ on the SD card.

# Flipper One: make -C one   (needs libsodium-dev)
#   marqued verify engagement.marque
#   marqued nft    engagement.marque | sudo nft -f -
```

## Status

- [x] Signed binary token format + author tooling (tested, tamper-evident)
- [x] Portable C core: parser + enforcement (host-tested, `-Werror` clean)
- [x] Zero `.fap` skeleton: load, verify, window status, guarded + logged actions
- [x] One daemon skeleton: verify + nftables egress generation
- [ ] Wire Zero guards to real subghz/nfc/rfid workers
- [ ] Hash-chained signed evidence log + export (companion tool #2)
- [ ] One: CIDR matcher for `guard`, namespace confinement, window timer
- [ ] Optional: firmware-fork variant for device-wide Zero enforcement

## License

Marque is free software, licensed under the **GNU General Public License v3.0 or later** (see `LICENSE`). If you distribute a modified version, you must release your changes under the same license. It will always be free and open source.

Copyright (C) 2026 Wraith7x
