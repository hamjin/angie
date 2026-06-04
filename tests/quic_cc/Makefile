# Copyright (C) 2026 Web Server LLC

CC ?= cc
GO ?= go
CFLAGS ?= -O2 -Wall -Wextra -Werror
PKG_CONFIG ?= pkg-config
H3_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libnghttp3 openssl 2>/dev/null)
H3_LIBS ?= $(shell $(PKG_CONFIG) --libs libnghttp3 openssl 2>/dev/null)
GO_CONTROL_SOURCES := $(wildcard go_control/*.go go_control/cmd/control_h3_server/*.go)

all: test_cc_perf test_bbr_conf forwarder h3_client control_h3_server

test: all
	./test_cc_perf
	./test_bbr_conf

test_cc_perf: test_cc_perf.c
	$(CC) $(CFLAGS) -o $@ test_cc_perf.c

test_bbr_conf: test_bbr_conf.c \
		../../src/event/quic/congestion_control/ngx_event_quic_bbr.c \
		../../src/event/quic/congestion_control/ngx_event_quic_bbr.h
	$(CC) $(CFLAGS) -ffunction-sections -fdata-sections \
		-I../../objs -I../../src/core -I../../src/event \
		-I../../src/event/quic -I../../src/event/quic/congestion_control \
		-I../../src/os/unix -Wl,--gc-sections -o $@ test_bbr_conf.c

forwarder: forwarder.c
	$(CC) $(CFLAGS) -o $@ forwarder.c

h3_client: h3_client.c ossl_nghttp3.c ossl_nghttp3.h
	$(CC) $(CFLAGS) $(H3_CFLAGS) -o $@ h3_client.c ossl_nghttp3.c $(H3_LIBS)

control_h3_server: go_control/go.mod $(GO_CONTROL_SOURCES)
	cd go_control && $(GO) test ./...
	cd go_control && $(GO) build -o ../control_h3_server ./cmd/control_h3_server

clean:
	rm -f test_cc_perf test_bbr_conf forwarder h3_client control_h3_server

.PHONY: all test clean
