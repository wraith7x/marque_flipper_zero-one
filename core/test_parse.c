/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test_parse.c - Host test: parse a real .marque and exercise enforcement.
 * Build: see core/Makefile  ->  ./test_parse engagement.marque           */
#include "scope_token.h"
#include <stdio.h>
#include <stdlib.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    printf("  [%s] %s\n", (cond) ? "PASS" : "FAIL", msg); \
    if (!(cond)) fails++; } while (0)

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s token.marque\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }
    static uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    sl_token_t t;
    sl_err_t e = sl_token_parse(buf, n, &t);
    printf("parse: %s  (%zu bytes)\n", sl_strerror(e), n);
    if (e != SL_OK) return 1;

    printf("engagement_id : %s\n", t.engagement_id);
    printf("window        : %lld .. %lld\n",
           (long long)t.not_before, (long long)t.not_after);
    printf("subghz ranges : %u, flags 0x%02x\n", t.subghz_range_n, t.subghz_flags);
    printf("rfid uids     : %u, nfc uids %u, nogo uids %u\n",
           t.rfid_uid_n, t.nfc_uid_n, t.nogo_uid_n);
    printf("net cidrs     : %u, port ranges %u\n", t.net_cidr_n, t.net_port_n);

    int64_t inside  = t.not_before + 3600;      /* 1h into the window */
    int64_t before  = t.not_before - 60;        /* 1 min too early    */
    int64_t after   = t.not_after + 60;         /* 1 min too late     */

    puts("\nenforcement:");
    CHECK(sl_window_open(&t, inside),  "window open mid-engagement");
    CHECK(!sl_window_open(&t, before), "window closed before start");
    CHECK(!sl_window_open(&t, after),  "window closed after end");

    CHECK(sl_allow_subghz_tx(&t, 433920000u, inside),
          "TX 433.92MHz in-scope allowed");
    CHECK(!sl_allow_subghz_tx(&t, 433920000u, before),
          "TX 433.92MHz denied outside window");
    CHECK(!sl_allow_subghz_tx(&t, 915000000u, inside),
          "TX 915MHz (out of range) denied");
    CHECK(!sl_allow_subghz_tx(&t, 868000000u, inside),
          "TX 868MHz (NOGO) denied");

    CHECK(sl_allow_rfid(&t, SL_RW_READ, "EM4100:1A2B3C4D5E", inside),
          "RFID read allowed UID permitted");
    CHECK(!sl_allow_rfid(&t, SL_RW_WRITE, "EM4100:1A2B3C4D5E", inside),
          "RFID write denied (write flag off)");
    CHECK(!sl_allow_rfid(&t, SL_RW_READ, "EM4100:00DEADBEEF", inside),
          "RFID read of NOGO UID denied");
    CHECK(!sl_allow_rfid(&t, SL_RW_READ, "EM4100:FFFFFFFFFF", inside),
          "RFID read of unlisted UID denied");

    CHECK(sl_allow_nfc(&t, SL_RW_EMULATE, "04A1B2C3D4E5F6", inside),
          "NFC emulate allowed UID permitted");

    printf("\n%s (%d failure%s)\n", fails ? "RESULT: FAILURES" : "RESULT: ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
