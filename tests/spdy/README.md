SPDY test clients
=================

These standalone clients exercise Angie SPDY support over TLS with system
OpenSSL and zlib.  By default they send one request and exit with status 0 only
when the response status matches and the response body contains the marker
argument.

Protocol coverage:

- `spdy3_client` speaks Chromium SPDY/3 draft semantics over NPN token
  `spdy/3`.  It rejects connection-level `WINDOW_UPDATE sid=0` because SPDY/3
  only defines per-stream flow control.
- `spdy31_client` speaks Chromium SPDY/3.1 draft semantics.  It accepts
  either ALPN or NPN negotiation for `spdy/3.1`, and it verifies that large
  responses trigger both stream-level and connection-level `WINDOW_UPDATE`
  frames.

Build:

```sh
cc -Wall -Wextra -O2 tests/spdy/spdy3_client.c -o /tmp/spdy3_client \
  $(pkg-config --cflags --libs openssl zlib)

cc -Wall -Wextra -O2 tests/spdy/spdy31_client.c -o /tmp/spdy31_client \
  $(pkg-config --cflags --libs openssl zlib)
```

Run:

```sh
/tmp/spdy3_client 127.0.0.1 9443 ANGIE_SPDY_OK
/tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK
/tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK alpn
/tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK npn

SPDY_PATH=/large /tmp/spdy3_client 127.0.0.1 9443 ANGIE_SPDY_OK
SPDY_PATH=/large /tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK alpn
SPDY_PATH=/large /tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK npn
```

Request controls:

- `SPDY_METHOD=HEAD|GET|POST|PUT` overrides the HTTP method.
- `SPDY_PATH=/path?query=1` overrides the request target.
- `SPDY_BODY=text` sends a request DATA frame with `Content-Length` and
  `Content-Type: text/plain`.
- `SPDY_HEADER=name` and `SPDY_HEADER_VALUE=value` add one extra request
  header.
- `SPDY_STATUS=204` changes the expected response status.
- `SPDY_SUITE=1` runs a built-in request suite covering `GET /`, `HEAD /`,
  `GET /headers?case=spdy` with a custom header, `POST /echo` with a body,
  `PUT /echo` with a body, and `GET /large`.

Suite examples:

```sh
SPDY_SUITE=1 /tmp/spdy3_client 127.0.0.1 9443
SPDY_SUITE=1 /tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK npn
SPDY_SUITE=1 /tmp/spdy31_client 127.0.0.1 9443 ANGIE_SPDY_OK alpn
```
