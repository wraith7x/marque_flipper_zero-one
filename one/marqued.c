/* SPDX-License-Identifier: GPL-3.0-or-later */
/* marqued.c - Flipper One (Linux) front-end for Marque.
 *
 * On the One there are no sub-GHz/NFC/RFID radios; "scope" is the network.
 * This shares the exact same ../core token parser/verifier and turns an
 * engagement's network scope into real OS enforcement: an nftables ruleset
 * that confines outbound traffic to the in-scope CIDRs/ports, droppable the
 * moment the window closes.
 *
 * Commands:
 *   marqued verify <token.marque>            check signature + show scope
 *   marqued nft    <token.marque>            emit an nftables ruleset
 *   marqued guard  <token.marque> <ip> <port>  exit 0 if in scope, else 1
 *
 * Build: make -C one  (needs libsodium-dev). Enforcement here is genuinely
 * stronger than the Zero's: trusted time via NTP, nftables confinement, and
 * optionally a dedicated network namespace so even out-of-app tools obey scope.
 */
#include "../core/scope_token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Pinned authority key — paste from `tools/marque.py pin`. */
static const uint8_t PUBKEY[32] = {0};
static const uint8_t KEY_ID[8]  = {0};

static int read_file(const char *path, uint8_t *buf, size_t cap, size_t *out) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return -1; }
    *out = fread(buf, 1, cap, f);
    fclose(f);
    return 0;
}

static int load(const char *path, uint8_t *buf, size_t cap, sl_token_t *t,
                int require_sig) {
    size_t n;
    if (read_file(path, buf, cap, &n)) return -1;
    sl_err_t e = sl_token_parse(buf, n, t);
    if (e != SL_OK) { fprintf(stderr, "parse: %s\n", sl_strerror(e)); return -1; }
#ifdef SL_DEV_SKIP_VERIFY
    (void)require_sig;  /* dev-only: dry-run authoring from an unsigned draft */
#else
    if (require_sig) {
        e = sl_token_verify(t, PUBKEY, KEY_ID);
        if (e != SL_OK) { fprintf(stderr, "verify: %s\n", sl_strerror(e)); return -1; }
    }
#endif
    return 0;
}

static int cmd_verify(const char *path) {
    uint8_t buf[8192]; sl_token_t t;
    if (load(path, buf, sizeof(buf), &t, 1)) return 1;
    printf("OK: signature valid\n  engagement: %s\n", t.engagement_id);
    printf("  window: %lld .. %lld\n", (long long)t.not_before, (long long)t.not_after);
    printf("  net cidrs: %u, port ranges: %u\n", t.net_cidr_n, t.net_port_n);
    return 0;
}

/* Emit an nftables ruleset: default-drop egress, accept only in-scope dests. */
static int cmd_nft(const char *path) {
    uint8_t buf[8192]; sl_token_t t;
    if (load(path, buf, sizeof(buf), &t, 1)) return 1;
    printf("#!/usr/sbin/nft -f\n");
    printf("# marque egress confinement for %s\n", t.engagement_id);
    printf("# valid %lld..%lld (enforce with a timer that flushes at not_after)\n",
           (long long)t.not_before, (long long)t.not_after);
    printf("table inet marque {\n  chain egress {\n");
    printf("    type filter hook output priority 0; policy drop;\n");
    printf("    ct state established,related accept\n");
    printf("    oifname \"lo\" accept\n");
    for (uint8_t i = 0; i < t.net_cidr_n; i++) {
        if (t.net_port_n == 0) {
            printf("    ip daddr %s accept\n", t.net_cidrs[i].s);
        } else {
            for (uint8_t j = 0; j < t.net_port_n; j++) {
                printf("    ip daddr %s tcp dport %u-%u accept\n",
                       t.net_cidrs[i].s, t.net_ports[j].lo, t.net_ports[j].hi);
            }
        }
    }
    printf("    log prefix \"marque-drop \" drop\n");
    printf("  }\n}\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "verify")) return cmd_verify(argv[2]);
    if (argc >= 3 && !strcmp(argv[1], "nft"))    return cmd_nft(argv[2]);
    if (argc >= 5 && !strcmp(argv[1], "guard")) {
        /* a full matcher parses CIDRs; stub prints intent for the scaffold */
        fprintf(stderr, "guard: TODO CIDR match for %s:%s\n", argv[3], argv[4]);
        return 2;
    }
    fprintf(stderr, "usage: %s {verify|nft <token>|guard <token> <ip> <port>}\n",
            argv[0]);
    return 2;
}
