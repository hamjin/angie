/*
 * Standalone SPDY/3.0 TLS GET client.
 *
 * Build:
 *   cc -Wall -Wextra -O2 /tmp/spdy3_client.c -o /tmp/spdy3_client \
 *      $(pkg-config --cflags --libs openssl zlib)
 *
 * Usage:
 *   /tmp/spdy3_client host [port] [marker]
 *   SPDY_EXPECT=marker /tmp/spdy3_client host [port]
 *   SPDY_PATH=/large /tmp/spdy3_client host [port] [marker]
 *   SPDY_SUITE=1 /tmp/spdy3_client host [port]
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#ifndef OPENSSL_NO_NEXTPROTONEG
#define HAVE_NPN 1
#endif

#define SPDY_VERSION 3
#define TYPE_SYN_STREAM 1
#define TYPE_SYN_REPLY 2
#define TYPE_RST_STREAM 3
#define TYPE_SETTINGS 4
#define TYPE_PING 6
#define TYPE_GOAWAY 7
#define TYPE_HEADERS 8
#define TYPE_WINDOW_UPDATE 9
#define FLAG_FIN 0x01
#define INITIAL_WINDOW_SIZE 65536

static const unsigned char spdy_dict[] =
    "\000\000\000\007options\000\000\000\004head\000\000\000\004post"
    "\000\000\000\003put\000\000\000\006delete\000\000\000\005trace"
    "\000\000\000\006accept\000\000\000\016accept-charset\000\000\000"
    "\017accept-encoding\000\000\000\017accept-language\000\000\000\015"
    "accept-ranges\000\000\000\003age\000\000\000\005allow\000\000\000"
    "\015authorization\000\000\000\015cache-control\000\000\000\012"
    "connection\000\000\000\014content-base\000\000\000\020"
    "content-encoding\000\000\000\020content-language\000\000\000\016"
    "content-length\000\000\000\020content-location\000\000\000\013"
    "content-md5\000\000\000\015content-range\000\000\000\014"
    "content-type\000\000\000\004date\000\000\000\004etag\000\000\000"
    "\006expect\000\000\000\007expires\000\000\000\004from\000\000\000"
    "\004host\000\000\000\010if-match\000\000\000\021if-modified-since"
    "\000\000\000\015if-none-match\000\000\000\010if-range\000\000\000"
    "\023if-unmodified-since\000\000\000\015last-modified\000\000\000"
    "\010location\000\000\000\014max-forwards\000\000\000\006pragma"
    "\000\000\000\022proxy-authenticate\000\000\000\023"
    "proxy-authorization\000\000\000\005range\000\000\000\007referer"
    "\000\000\000\013retry-after\000\000\000\006server\000\000\000\002te"
    "\000\000\000\007trailer\000\000\000\021transfer-encoding\000\000"
    "\000\007upgrade\000\000\000\012user-agent\000\000\000\004vary"
    "\000\000\000\003via\000\000\000\007warning\000\000\000\020"
    "www-authenticate\000\000\000\006method\000\000\000\003get\000\000"
    "\000\006status\000\000\000\006""200 OK\000\000\000\007version\000"
    "\000\000\010HTTP/1.1\000\000\000\003url\000\000\000\006public"
    "\000\000\000\012set-cookie\000\000\000\012keep-alive\000\000\000"
    "\006origin100101201202205206300302303304305306307402405406407408"
    "409410411412413414415416417502504505203 Non-Authoritative Information"
    "204 No Content301 Moved Permanently400 Bad Request401 Unauthorized"
    "403 Forbidden404 Not Found500 Internal Server Error501 Not Implemented"
    "503 Service UnavailableJan Feb Mar Apr May Jun Jul Aug Sept Oct Nov Dec "
    "00:00:00 Mon, Tue, Wed, Thu, Fri, Sat, Sun, GMTchunked,text/html,"
    "image/png,image/jpg,image/gif,application/xml,application/xhtml+xml,"
    "text/plain,text/javascript,publicprivatemax-age=gzip,deflate,sdch"
    "charset=utf-8charset=iso-8859-1,utf-,*,enq=0.";

struct bytes {
    unsigned char *p;
    size_t n;
    size_t cap;
};

struct response {
    int status;
    struct bytes body;
    unsigned sent_stream_window_updates;
    unsigned sent_connection_window_updates;
    unsigned received_connection_window_updates;
};

struct request_spec {
    const char *method;
    const char *path;
    const char *body;
    const char *marker;
    const char *extra_name;
    const char *extra_value;
    const char *content_type;
    int expected_status;
    int expect_no_body;
};

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static void die_errno(const char *msg)
{
    fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
    exit(2);
}

static void die_ssl(const char *msg)
{
    unsigned long e;

    fprintf(stderr, "error: %s\n", msg);
    while ((e = ERR_get_error()) != 0) {
        fprintf(stderr, "  %s\n", ERR_error_string(e, NULL));
    }

    exit(2);
}

static void append_bytes(struct bytes *b, const void *p, size_t n)
{
    unsigned char *q;
    size_t cap;

    if (n == 0) {
        return;
    }

    if (b->n > SIZE_MAX - n) {
        die("buffer overflow");
    }

    if (b->n + n > b->cap) {
        cap = b->cap ? b->cap : 1024;
        while (cap < b->n + n) {
            if (cap > SIZE_MAX / 2) {
                die("buffer too large");
            }
            cap *= 2;
        }

        q = realloc(b->p, cap);
        if (q == NULL) {
            die_errno("realloc");
        }

        b->p = q;
        b->cap = cap;
    }

    memcpy(b->p + b->n, p, n);
    b->n += n;
}

static void reset_response(struct response *r)
{
    free(r->body.p);
    memset(r, 0, sizeof(*r));
}

static void put16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char) (v >> 8);
    p[1] = (unsigned char) v;
}

static void put24(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) (v >> 16);
    p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) v;
}

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) (v >> 24);
    p[1] = (unsigned char) (v >> 16);
    p[2] = (unsigned char) (v >> 8);
    p[3] = (unsigned char) v;
}

static uint16_t get16(const unsigned char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t get24(const unsigned char *p)
{
    return ((uint32_t) p[0] << 16) | ((uint32_t) p[1] << 8) | p[2];
}

static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
        | ((uint32_t) p[2] << 8) | p[3];
}

static void ssl_write_all(SSL *ssl, const unsigned char *p, size_t n)
{
    int rc;

    while (n != 0) {
        if (n > INT32_MAX) {
            rc = SSL_write(ssl, p, INT32_MAX);
        } else {
            rc = SSL_write(ssl, p, (int) n);
        }

        if (rc <= 0) {
            die_ssl("SSL_write");
        }

        p += rc;
        n -= (size_t) rc;
    }
}

static int ssl_read_all(SSL *ssl, unsigned char *p, size_t n)
{
    int rc;

    while (n != 0) {
        if (n > INT32_MAX) {
            rc = SSL_read(ssl, p, INT32_MAX);
        } else {
            rc = SSL_read(ssl, p, (int) n);
        }

        if (rc == 0) {
            return 0;
        }

        if (rc < 0) {
            die_ssl("SSL_read");
        }

        p += rc;
        n -= (size_t) rc;
    }

    return 1;
}

static void set_socket_timeouts(int fd)
{
    struct timeval tv;

    tv.tv_sec = 15;
    tv.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        die_errno("setsockopt(SO_RCVTIMEO)");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        die_errno("setsockopt(SO_SNDTIMEO)");
    }
}

static int connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints, *res, *ai;
    int fd, rc, yes;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(rc));
        exit(2);
    }

    fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1) {
            continue;
        }

        yes = 1;
        (void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            set_socket_timeouts(fd);
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd == -1) {
        die_errno("connect");
    }

    return fd;
}

static void add_nv(struct bytes *b, const char *name, const char *value)
{
    size_t nl, vl;
    uint32_t l;
    unsigned char tmp[4];

    nl = strlen(name);
    vl = strlen(value);

    if (nl > UINT32_MAX || vl > UINT32_MAX) {
        die("name/value too large");
    }

    l = (uint32_t) nl;
    put32(tmp, l);
    append_bytes(b, tmp, 4);
    append_bytes(b, name, nl);

    l = (uint32_t) vl;
    put32(tmp, l);
    append_bytes(b, tmp, 4);
    append_bytes(b, value, vl);
}

static void compress_headers(struct bytes *out, const char *host,
    const struct request_spec *req)
{
    struct bytes raw = {0};
    z_stream z;
    unsigned char tmp[4096];
    unsigned char nheaders[4];
    char content_length[32];
    uint32_t count;
    size_t body_len;
    int rc;

    body_len = req->body ? strlen(req->body) : 0;

    count = 6;
    if (req->body != NULL) {
        count++;
    }
    if (req->content_type != NULL) {
        count++;
    }
    if (req->extra_name != NULL && req->extra_value != NULL) {
        count++;
    }

    put32(nheaders, count);
    append_bytes(&raw, nheaders, 4);
    add_nv(&raw, ":method", req->method);
    add_nv(&raw, ":path", req->path);
    add_nv(&raw, ":scheme", "https");
    add_nv(&raw, ":version", "HTTP/1.1");
    add_nv(&raw, ":host", host);
    add_nv(&raw, "user-agent", "spdy3-client/1");

    if (req->body != NULL) {
        snprintf(content_length, sizeof(content_length), "%zu", body_len);
        add_nv(&raw, "content-length", content_length);
    }
    if (req->content_type != NULL) {
        add_nv(&raw, "content-type", req->content_type);
    }
    if (req->extra_name != NULL && req->extra_value != NULL) {
        add_nv(&raw, req->extra_name, req->extra_value);
    }

    memset(&z, 0, sizeof(z));
    rc = deflateInit(&z, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        die("deflateInit failed");
    }

    rc = deflateSetDictionary(&z, spdy_dict, (uInt) (sizeof(spdy_dict) - 1));
    if (rc != Z_OK) {
        die("deflateSetDictionary failed");
    }

    z.next_in = raw.p;
    z.avail_in = (uInt) raw.n;

    do {
        z.next_out = tmp;
        z.avail_out = sizeof(tmp);
        rc = deflate(&z, Z_SYNC_FLUSH);
        if (rc != Z_OK) {
            die("deflate failed");
        }
        append_bytes(out, tmp, sizeof(tmp) - z.avail_out);
    } while (z.avail_out == 0);

    deflateEnd(&z);
    free(raw.p);
}

static void send_data_frame(SSL *ssl, uint32_t sid, const char *body)
{
    struct bytes frame = {0};
    unsigned char h[8];
    size_t len;

    len = body ? strlen(body) : 0;

    put32(h, sid & 0x7fffffffU);
    h[4] = FLAG_FIN;
    put24(h + 5, (uint32_t) len);

    append_bytes(&frame, h, sizeof(h));
    append_bytes(&frame, body ? body : "", len);
    ssl_write_all(ssl, frame.p, frame.n);

    free(frame.p);
}

static void send_syn_stream(SSL *ssl, const char *host,
    const struct request_spec *req)
{
    struct bytes hb = {0};
    struct bytes frame = {0};
    unsigned char h[18];
    uint32_t len;

    compress_headers(&hb, host, req);

    len = 10 + (uint32_t) hb.n;
    put16(h, 0x8000u | SPDY_VERSION);
    put16(h + 2, TYPE_SYN_STREAM);
    h[4] = req->body == NULL ? FLAG_FIN : 0;
    put24(h + 5, len);
    put32(h + 8, 1);
    put32(h + 12, 0);
    h[16] = 0x00;
    h[17] = 0x00;

    append_bytes(&frame, h, sizeof(h));
    append_bytes(&frame, hb.p, hb.n);
    ssl_write_all(ssl, frame.p, frame.n);

    free(hb.p);
    free(frame.p);

    if (req->body != NULL) {
        send_data_frame(ssl, 1, req->body);
    }
}

static void send_window_update(SSL *ssl, uint32_t sid, uint32_t delta)
{
    unsigned char frame[16];

    if (delta == 0) {
        return;
    }

    put16(frame, 0x8000u | SPDY_VERSION);
    put16(frame + 2, TYPE_WINDOW_UPDATE);
    frame[4] = 0;
    put24(frame + 5, 8);
    put32(frame + 8, sid & 0x7fffffffU);
    put32(frame + 12, delta & 0x7fffffffU);

    ssl_write_all(ssl, frame, sizeof(frame));
}

static void inflate_block(z_stream *z, const unsigned char *in, size_t in_len,
    struct bytes *out)
{
    unsigned char tmp[4096];
    int rc;

    z->next_in = (unsigned char *) in;
    z->avail_in = (uInt) in_len;

    do {
        z->next_out = tmp;
        z->avail_out = sizeof(tmp);
        rc = inflate(z, Z_SYNC_FLUSH);

        if (rc == Z_NEED_DICT) {
            rc = inflateSetDictionary(z, spdy_dict,
                (uInt) (sizeof(spdy_dict) - 1));
            if (rc != Z_OK) {
                die("inflateSetDictionary failed");
            }
            continue;
        }

        if (rc != Z_OK && rc != Z_STREAM_END) {
            die("inflate failed");
        }

        append_bytes(out, tmp, sizeof(tmp) - z->avail_out);
    } while (z->avail_out == 0 || z->avail_in != 0);
}

static char *dup_header_value(const unsigned char *p, size_t n)
{
    char *s;

    s = malloc(n + 1);
    if (s == NULL) {
        die_errno("malloc");
    }

    memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static void parse_headers(const unsigned char *p, size_t n, struct response *r)
{
    uint32_t count, nl, vl;
    size_t off, i;
    char *name, *value;

    if (n < 4) {
        die("short header block");
    }

    count = get32(p);
    off = 4;

    for (i = 0; i < count; i++) {
        if (off + 4 > n) {
            die("truncated header name length");
        }
        nl = get32(p + off);
        off += 4;

        if (nl > n - off) {
            die("truncated header name");
        }
        name = dup_header_value(p + off, nl);
        off += nl;

        if (off + 4 > n) {
            die("truncated header value length");
        }
        vl = get32(p + off);
        off += 4;

        if (vl > n - off) {
            die("truncated header value");
        }
        value = dup_header_value(p + off, vl);
        off += vl;

        if (strcmp(name, ":status") == 0 || strcmp(name, "status") == 0) {
            r->status = atoi(value);
        }

        printf("%s: %s\n", name, value);
        free(name);
        free(value);
    }
}

static void process_header_frame(z_stream *z, const unsigned char *payload,
    size_t len, uint16_t type, struct response *r)
{
    uint32_t sid;
    size_t off;
    struct bytes inflated = {0};

    if (type == TYPE_SYN_REPLY) {
        if (len < 4) {
            die("short SYN_REPLY");
        }
        sid = get32(payload) & 0x7fffffffU;
        off = 4;
    } else {
        if (len < 4) {
            die("short HEADERS");
        }
        sid = get32(payload) & 0x7fffffffU;
        off = 4;
    }

    if (sid != 1) {
        return;
    }

    inflate_block(z, payload + off, len - off, &inflated);
    parse_headers(inflated.p, inflated.n, r);
    putchar('\n');
    free(inflated.p);
}

static void read_response(SSL *ssl, struct response *r)
{
    unsigned char hdr[8];
    unsigned char *payload;
    uint32_t len, sid, delta;
    uint16_t type;
    int control, done, stream_recv_window;
    unsigned char flags;
    z_stream z;

    memset(&z, 0, sizeof(z));
    if (inflateInit(&z) != Z_OK) {
        die("inflateInit failed");
    }

    done = 0;
    stream_recv_window = INITIAL_WINDOW_SIZE;
    while (!done && ssl_read_all(ssl, hdr, sizeof(hdr))) {
        control = (hdr[0] & 0x80) != 0;
        flags = hdr[4];
        len = get24(hdr + 5);

        payload = NULL;
        if (len != 0) {
            if (len > 16 * 1024 * 1024) {
                die("frame too large");
            }
            payload = malloc(len);
            if (payload == NULL) {
                die_errno("malloc");
            }
            if (!ssl_read_all(ssl, payload, len)) {
                die("unexpected EOF in frame payload");
            }
        }

        if (!control) {
            sid = get32(hdr) & 0x7fffffffU;
            if (sid == 1) {
                if (len > (uint32_t) stream_recv_window) {
                    die("server exceeded SPDY/3 stream receive window");
                }

                stream_recv_window -= (int) len;
                append_bytes(&r->body, payload, len);
                fwrite(payload, 1, len, stdout);
                send_window_update(ssl, sid, len);
                r->sent_stream_window_updates++;
                stream_recv_window += (int) len;
                if ((flags & FLAG_FIN) != 0) {
                    done = 1;
                }
            }
        } else {
            if ((get16(hdr) & 0x7fffU) != SPDY_VERSION) {
                die("unexpected SPDY version");
            }

            type = get16(hdr + 2);
            switch (type) {
            case TYPE_SYN_REPLY:
            case TYPE_HEADERS:
                process_header_frame(&z, payload, len, type, r);
                if ((flags & FLAG_FIN) != 0) {
                    done = 1;
                }
                break;

            case TYPE_RST_STREAM:
                if (len >= 8 && ((get32(payload) & 0x7fffffffU) == 1)) {
                    fprintf(stderr, "error: RST_STREAM status %u\n",
                        get32(payload + 4));
                    exit(1);
                }
                break;

            case TYPE_PING:
                if (len == 4) {
                    unsigned char pong[12];
                    memcpy(pong, hdr, 8);
                    memcpy(pong + 8, payload, 4);
                    ssl_write_all(ssl, pong, sizeof(pong));
                }
                break;

            case TYPE_GOAWAY:
                done = 1;
                break;

            case TYPE_WINDOW_UPDATE:
                if (flags != 0) {
                    die("WINDOW_UPDATE with nonzero flags");
                }

                if (len != 8) {
                    die("incorrect WINDOW_UPDATE length");
                }

                sid = get32(payload) & 0x7fffffffU;
                delta = get32(payload + 4) & 0x7fffffffU;
                if (delta == 0) {
                    die("WINDOW_UPDATE with zero delta");
                }

                if (sid == 0) {
                    r->received_connection_window_updates++;
                    die("server sent connection WINDOW_UPDATE in SPDY/3");
                }
                break;

            case TYPE_SETTINGS:
            default:
                break;
            }
        }

        free(payload);
    }

    inflateEnd(&z);
}

static int body_contains(const struct bytes *b, const char *needle)
{
    size_t nl, i;

    if (needle == NULL || needle[0] == '\0') {
        return 1;
    }

    nl = strlen(needle);
    if (nl > b->n) {
        return 0;
    }

    for (i = 0; i <= b->n - nl; i++) {
        if (memcmp(b->p + i, needle, nl) == 0) {
            return 1;
        }
    }

    return 0;
}

static void check_response(const struct request_spec *req, struct response *r)
{
    int expected_status;

    expected_status = req->expected_status ? req->expected_status : 200;

    if (r->status != expected_status) {
        fprintf(stderr, "\nerror: %s %s status %d, expected %d\n",
            req->method, req->path, r->status, expected_status);
        exit(1);
    }

    if (req->expect_no_body && r->body.n != 0) {
        fprintf(stderr, "\nerror: %s %s returned unexpected body\n",
            req->method, req->path);
        exit(1);
    }

    if (!req->expect_no_body && !body_contains(&r->body, req->marker)) {
        fprintf(stderr, "\nerror: %s %s marker not found: %s\n",
            req->method, req->path, req->marker ? req->marker : "");
        exit(1);
    }

    if (r->received_connection_window_updates != 0) {
        fprintf(stderr, "\nerror: SPDY/3 received connection WINDOW_UPDATE\n");
        exit(1);
    }

    if (r->body.n > INITIAL_WINDOW_SIZE && r->sent_stream_window_updates == 0) {
        fprintf(stderr, "\nerror: SPDY/3 did not send stream WINDOW_UPDATE\n");
        exit(1);
    }

    if (r->sent_connection_window_updates != 0) {
        fprintf(stderr, "\nerror: SPDY/3 sent connection WINDOW_UPDATE\n");
        exit(1);
    }
}

#ifdef HAVE_NPN
static int npn_select_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char proto[] = "\006spdy/3";
    (void) ssl;
    (void) arg;

    if (SSL_select_next_proto(out, outlen, proto, sizeof(proto) - 1, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}
#endif

static void check_negotiated(SSL *ssl)
{
#ifdef HAVE_NPN
    const unsigned char *p;
    unsigned int n;

    SSL_get0_next_proto_negotiated(ssl, &p, &n);
    if (n == 6 && memcmp(p, "spdy/3", 6) == 0) {
        return;
    }
#else
    (void) ssl;
#endif

    die("TLS did not negotiate spdy/3");
}

static void run_request(SSL_CTX *ctx, const char *host, const char *port,
    const struct request_spec *req)
{
    SSL *ssl;
    int fd, rc;
    struct response r = {0};

    fd = connect_tcp(host, port);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        die_ssl("SSL_new");
    }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    rc = SSL_connect(ssl);
    if (rc != 1) {
        die_ssl("SSL_connect");
    }

    check_negotiated(ssl);
    send_syn_stream(ssl, host, req);
    read_response(ssl, &r);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);

    check_response(req, &r);
    reset_response(&r);
}

static void run_suite(SSL_CTX *ctx, const char *host, const char *port)
{
    static const struct request_spec suite[] = {
        { "GET", "/", NULL, "ANGIE_SPDY_OK", NULL, NULL, NULL, 200, 0 },
        { "HEAD", "/", NULL, NULL, NULL, NULL, NULL, 200, 1 },
        { "GET", "/headers?case=spdy", NULL, "HEADER:spdy-suite",
          "x-spdy-test", "spdy-suite", NULL, 200, 0 },
        { "POST", "/echo", "spdy-post-body", "BODY:spdy-post-body",
          "x-spdy-test", "post-suite", "text/plain", 200, 0 },
        { "PUT", "/echo", "spdy-put-body", "BODY:spdy-put-body",
          "x-spdy-test", "put-suite", "text/plain", 200, 0 },
        { "GET", "/large", NULL, "ANGIE_SPDY_OK",
          NULL, NULL, NULL, 200, 0 },
        { NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0 }
    };
    size_t i;

    for (i = 0; suite[i].method != NULL; i++) {
        run_request(ctx, host, port, &suite[i]);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s host [port] [expected-marker]\n", prog);
    fprintf(stderr, "       SPDY_EXPECT=marker %s host [port]\n", prog);
    fprintf(stderr, "       SPDY_PATH=/path %s host [port] [expected-marker]\n",
        prog);
    fprintf(stderr, "       SPDY_SUITE=1 %s host [port]\n", prog);
}

int main(int argc, char **argv)
{
    const char *host, *port, *marker, *path, *method, *body, *header, *value;
    const char *suite;
    SSL_CTX *ctx;
    struct request_spec req;

    if (argc < 2 || argc > 4) {
        usage(argv[0]);
        return 2;
    }

    host = argv[1];
    port = argc >= 3 ? argv[2] : "443";
    marker = argc >= 4 ? argv[3] : getenv("SPDY_EXPECT");
    suite = getenv("SPDY_SUITE");
    method = getenv("SPDY_METHOD");
    body = getenv("SPDY_BODY");
    header = getenv("SPDY_HEADER");
    value = getenv("SPDY_HEADER_VALUE");
    path = getenv("SPDY_PATH");
    if (path == NULL || path[0] == '\0') {
        path = "/";
    }
    if (path[0] != '/') {
        die("SPDY_PATH must start with /");
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        die_ssl("SSL_CTX_new");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

#ifdef HAVE_NPN
    SSL_CTX_set_next_proto_select_cb(ctx, npn_select_cb, NULL);
#endif

    if (suite != NULL && suite[0] != '\0' && strcmp(suite, "0") != 0) {
        run_suite(ctx, host, port);
    } else {
        memset(&req, 0, sizeof(req));
        req.method = (method != NULL && method[0] != '\0') ? method : "GET";
        req.path = path;
        req.body = (body != NULL && body[0] != '\0') ? body : NULL;
        req.marker = marker;
        req.extra_name = header;
        req.extra_value = value;
        req.content_type = req.body ? "text/plain" : NULL;
        req.expected_status = getenv("SPDY_STATUS")
                              ? atoi(getenv("SPDY_STATUS")) : 200;
        req.expect_no_body = strcasecmp(req.method, "HEAD") == 0;
        run_request(ctx, host, port, &req);
    }

    SSL_CTX_free(ctx);
    return 0;
}
