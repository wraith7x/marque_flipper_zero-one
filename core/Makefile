# SPDX-License-Identifier: GPL-3.0-or-later
# Host build of the portable core + test harness (stub crypto).
# Device builds do NOT use this Makefile; they link the real crypto backend.
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

test_parse: test_parse.c scope_token.c crypto_backend_stub.c scope_token.h crypto_backend.h
	$(CC) $(CFLAGS) -o test_parse test_parse.c scope_token.c crypto_backend_stub.c

.PHONY: test clean
test: test_parse
	./test_parse ../tools/engagement.marque

clean:
	rm -f test_parse
