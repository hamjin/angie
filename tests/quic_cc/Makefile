# Copyright (C) 2026 Web Server LLC

CC ?= cc
GO ?= go
CFLAGS ?= -O2 -Wall -Wextra -Werror
PKG_CONFIG ?= pkg-config
H3_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libnghttp3 openssl 2>/dev/null)
H3_LIBS ?= $(shell $(PKG_CONFIG) --libs libnghttp3 openssl 2>/dev/null)

all: test_cc_perf forwarder h3_client

test: all
	./test_cc_perf

test_cc_perf: test_cc_perf.c
	$(CC) $(CFLAGS) -o $@ test_cc_perf.c

forwarder: forwarder.c
	$(CC) $(CFLAGS) -o $@ forwarder.c

h3_client: h3_client.c ossl_nghttp3.c ossl_nghttp3.h
	$(CC) $(CFLAGS) $(H3_CFLAGS) -o $@ h3_client.c ossl_nghttp3.c $(H3_LIBS)

clean:
	rm -f test_cc_perf forwarder h3_client

.PHONY: all test clean
