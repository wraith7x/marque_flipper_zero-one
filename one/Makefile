# SPDX-License-Identifier: GPL-3.0-or-later
# Flipper One (Linux) build. Needs libsodium-dev.
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2 -I../core
LDLIBS ?= -lsodium

marqued: marqued.c ../core/scope_token.c crypto_backend_libsodium.c
	$(CC) $(CFLAGS) -o marqued marqued.c ../core/scope_token.c \
		crypto_backend_libsodium.c $(LDLIBS)

.PHONY: clean
clean:
	rm -f marqued
