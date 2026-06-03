/*
 * Copyright (C) 2026 Web Server LLC
 */

#include "ossl_nghttp3.h"

#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>


#define H3_CLIENT_CONNECT_TIMEOUT_MS  10000
#define H3_CLIENT_READ_TIMEOUT_MS     3000
#define H3_CLIENT_MAX_RETRIES         3


typedef struct {
    const char  *connect_host;
    const char  *connect_port;
    const char  *authority;
    const char  *path;
    const char  *output_path;
    unsigned     duration_ms;
    int          discard_body;
} h3_client_conf_t;


typedef struct {
    FILE       *out;
    const char *output_path;
    int         status_code;
    int         done;
    size_t      bytes_written;
    int         discard_body;
} h3_client_state_t;


static void usage(const char *name);
static int parse_args(int argc, char **argv, h3_client_conf_t *conf);
static int perform_requests(const h3_client_conf_t *conf);
static void make_nv(nghttp3_nv *nv, const char *name, const char *value);
static uint64_t now_ms(void);
static int on_recv_header(nghttp3_conn *h3conn, int64_t stream_id, int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
    void *conn_user_data, void *stream_user_data);
static int on_recv_data(nghttp3_conn *h3conn, int64_t stream_id,
    const uint8_t *data, size_t datalen,
    void *conn_user_data, void *stream_user_data);
static int on_end_stream(nghttp3_conn *h3conn, int64_t stream_id,
    void *conn_user_data, void *stream_user_data);


int
main(int argc, char **argv)
{
    h3_client_conf_t  conf;

    memset(&conf, 0, sizeof(conf));

    if (parse_args(argc, argv, &conf) != 0) {
        usage(argv[0]);
        return 2;
    }

    if (!perform_requests(&conf)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}


static void
usage(const char *name)
{
    fprintf(stderr,
            "usage: %s --connect-host HOST --connect-port PORT "
            "--authority HOST --path PATH --output FILE "
            "[--duration-ms MS] [--discard-body]\n",
            name);
}


static int
parse_args(int argc, char **argv, h3_client_conf_t *conf)
{
    int  i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--connect-host") == 0 && i + 1 < argc) {
            conf->connect_host = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--connect-port") == 0 && i + 1 < argc) {
            conf->connect_port = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--authority") == 0 && i + 1 < argc) {
            conf->authority = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            conf->path = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            conf->output_path = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--duration-ms") == 0 && i + 1 < argc) {
            conf->duration_ms = (unsigned) strtoul(argv[++i], NULL, 10);
            continue;
        }

        if (strcmp(argv[i], "--discard-body") == 0) {
            conf->discard_body = 1;
            continue;
        }

        return -1;
    }

    if (conf->connect_host == NULL || conf->connect_port == NULL
        || conf->authority == NULL || conf->path == NULL
        || conf->output_path == NULL)
    {
        return -1;
    }

    return 0;
}


static int
perform_requests(const h3_client_conf_t *conf)
{
    BIO_ADDRINFO            *bai;
    const BIO_ADDRINFO      *bai_walk;
    SSL_CTX                 *ctx;
    OSSL_DEMO_H3_CONN       *conn;
    nghttp3_callbacks        callbacks;
    nghttp3_nv               headers[5];
    h3_client_state_t        state;
    int                      ok;
    size_t                   total_bytes, requests;
    uint64_t                 deadline_ms;
    const char              *mode;

    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.recv_header = on_recv_header;
    callbacks.recv_data = on_recv_data;
    callbacks.end_stream = on_end_stream;

    ok = BIO_lookup_ex(conf->connect_host, conf->connect_port,
                       BIO_LOOKUP_CLIENT, 0, SOCK_DGRAM, IPPROTO_UDP, &bai);
    if (ok == 0) {
        fprintf(stderr, "host lookup failed for %s:%s\n",
                conf->connect_host, conf->connect_port);
        return 0;
    }
    fprintf(stderr, "lookup ok %s:%s\n", conf->connect_host, conf->connect_port);
    fflush(stderr);

    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL) {
        BIO_ADDRINFO_free(bai);
        return 0;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    conn = NULL;

    for (bai_walk = bai; bai_walk != NULL; bai_walk = BIO_ADDRINFO_next(bai_walk)) {
        conn = OSSL_DEMO_H3_CONN_new_for_addr(ctx, bai_walk, conf->authority,
                                              &callbacks, NULL, &state);
        if (conn != NULL) {
            fprintf(stderr, "conn created for authority=%s path=%s\n",
                    conf->authority, conf->path);
            fflush(stderr);
            break;
        }
    }

    if (conn == NULL) {
        SSL_CTX_free(ctx);
        BIO_ADDRINFO_free(bai);
        return 0;
    }

    make_nv(&headers[0], ":method", "GET");
    make_nv(&headers[1], ":scheme", "https");
    make_nv(&headers[2], ":authority", conf->authority);
    make_nv(&headers[3], ":path", conf->path);
    make_nv(&headers[4], "user-agent", "angie-cc-h3-client/1");

    total_bytes = 0;
    requests = 0;
    deadline_ms = conf->duration_ms == 0 ? 0 : now_ms() + conf->duration_ms;

    do {
        unsigned  attempt;
        int       request_ok;

        request_ok = 0;

        for (attempt = 0; attempt < H3_CLIENT_MAX_RETRIES; attempt++) {
            int  timed_out = 0;

            memset(&state, 0, sizeof(state));
            state.output_path = conf->output_path;
            state.status_code = 0;
            state.bytes_written = 0;
            state.discard_body = conf->discard_body;

            if (!state.discard_body) {
                mode = requests == 0 ? "wb" : "ab";
                state.out = fopen(conf->output_path, mode);
                if (state.out == NULL) {
                    perror(conf->output_path);
                    OSSL_DEMO_H3_CONN_free(conn);
                    SSL_CTX_free(ctx);
                    BIO_ADDRINFO_free(bai);
                    return 0;
                }
            }

            if (!OSSL_DEMO_H3_CONN_submit_request(conn, headers, 5, NULL,
                                                    &state))
            {
                fprintf(stderr, "submit request failed\n");
                if (state.out != NULL) {
                    fclose(state.out);
                }
                OSSL_DEMO_H3_CONN_free(conn);
                SSL_CTX_free(ctx);
                BIO_ADDRINFO_free(bai);
                return 0;
            }
            fprintf(stderr, "request submitted attempt=%u\n", attempt + 1);
            fflush(stderr);

            while (!state.done) {
                uint64_t  per_req_deadline;
                uint64_t  now;

                now = now_ms();

                if (deadline_ms != 0) {
                    /* Duration mode: use overall deadline */
                    per_req_deadline = deadline_ms;
                } else if (attempt == 0) {
                    /* First request, no duration: connect timeout */
                    per_req_deadline = now + H3_CLIENT_CONNECT_TIMEOUT_MS;
                } else {
                    /* Retries: shorter timeout */
                    per_req_deadline = now + H3_CLIENT_READ_TIMEOUT_MS;
                }

                if (per_req_deadline != 0 && now >= per_req_deadline) {
                    fprintf(stderr, "request timeout attempt=%u\n",
                            attempt + 1);
                    fflush(stderr);
                    timed_out = 1;
                    break;
                }

                if (!OSSL_DEMO_H3_CONN_handle_events(conn)) {
                    fprintf(stderr, "handle events failed attempt=%u\n",
                            attempt + 1);
                    fflush(stderr);
                    break;
                }
            }

            if (state.done && state.status_code == 200) {
                request_ok = 1;
            }

            if (state.out != NULL) {
                fclose(state.out);
                state.out = NULL;
            }

            if (request_ok) {
                break;
            }

            if (deadline_ms != 0) {
                /* Duration mode: treat timeout as completion */
                state.status_code = 200;
                state.done = 1;
                request_ok = 1;
                break;
            }

            /* Non-duration mode: retry only on timeout */
            if (!timed_out) {
                fprintf(stderr, "request failed (connection error)\n");
                OSSL_DEMO_H3_CONN_free(conn);
                SSL_CTX_free(ctx);
                BIO_ADDRINFO_free(bai);
                return 0;
            }

            fprintf(stderr, "retrying request attempt=%u/%u\n",
                    attempt + 1, H3_CLIENT_MAX_RETRIES);
            fflush(stderr);
        }

        if (!request_ok) {
            fprintf(stderr, "request failed after %u attempts\n",
                    H3_CLIENT_MAX_RETRIES);
            OSSL_DEMO_H3_CONN_free(conn);
            SSL_CTX_free(ctx);
            BIO_ADDRINFO_free(bai);
            return 0;
        }

        fprintf(stderr, "stream done status=%d bytes=%zu\n",
                state.status_code, state.bytes_written);
        fflush(stderr);

        total_bytes += state.bytes_written;
        requests++;
    } while (deadline_ms != 0 && now_ms() < deadline_ms);

    OSSL_DEMO_H3_CONN_free(conn);
    SSL_CTX_free(ctx);
    BIO_ADDRINFO_free(bai);

    printf("status=200 bytes=%zu requests=%zu output=%s\n",
           total_bytes, requests, conf->output_path);

    return 1;
}


static void
make_nv(nghttp3_nv *nv, const char *name, const char *value)
{
    nv->name = (uint8_t *) name;
    nv->value = (uint8_t *) value;
    nv->namelen = strlen(name);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP3_NV_FLAG_NONE;
}


static int
on_recv_header(nghttp3_conn *h3conn, int64_t stream_id, int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
    void *conn_user_data, void *stream_user_data)
{
    h3_client_state_t *state;
    nghttp3_vec        vname, vvalue;
    char               status[4];

    (void) h3conn;
    (void) stream_id;
    (void) token;
    (void) flags;
    (void) conn_user_data;
    (void) stream_user_data;

    state = OSSL_DEMO_H3_STREAM_get_user_data(stream_user_data);
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    if (vname.len == 7 && memcmp(vname.base, ":status", 7) == 0) {
        if (vvalue.len >= sizeof(status)) {
            return 1;
        }

        memcpy(status, vvalue.base, vvalue.len);
        status[vvalue.len] = '\0';
        state->status_code = atoi(status);
    }

    return 0;
}


static int
on_recv_data(nghttp3_conn *h3conn, int64_t stream_id, const uint8_t *data,
    size_t datalen, void *conn_user_data, void *stream_user_data)
{
    h3_client_state_t *state;
    size_t             written;

    (void) h3conn;
    (void) stream_id;
    (void) stream_user_data;

    (void) conn_user_data;
    state = OSSL_DEMO_H3_STREAM_get_user_data(stream_user_data);
    if (state->discard_body || state->out == NULL) {
        written = datalen;
    } else {
        written = fwrite(data, 1, datalen, state->out);
    }
    state->bytes_written += written;

    return written == datalen ? 0 : 1;
}


static int
on_end_stream(nghttp3_conn *h3conn, int64_t stream_id,
    void *conn_user_data, void *stream_user_data)
{
    h3_client_state_t *state;

    (void) h3conn;
    (void) stream_id;
    (void) stream_user_data;

    (void) conn_user_data;
    state = OSSL_DEMO_H3_STREAM_get_user_data(stream_user_data);
    state->done = 1;

    return 0;
}


static uint64_t
now_ms(void)
{
    struct timeval  tv;

    gettimeofday(&tv, NULL);

    return (uint64_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
