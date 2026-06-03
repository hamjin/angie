#define _GNU_SOURCE

/*
 * Copyright (C) 2026 Web Server LLC
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>


#define FORWARDER_BATCH        96
#define FORWARDER_MAX_DATAGRAM 65536


typedef struct {
    unsigned  listen_port;
    unsigned  target_port;
    unsigned  rate_bps;
    unsigned  loss_ppm;
    unsigned  loss_warmup_ms;
    unsigned  loss_first_keep;
    unsigned  delay_ms;
    unsigned  jitter_ms;
    unsigned  outage_after_ms;
    unsigned  outage_duration_ms;
    unsigned  duration_ms;
    const char *stats_file;
} forwarder_conf_t;


typedef struct {
    uint64_t  packets_in;
    uint64_t  packets_out;
    uint64_t  packets_dropped;
    uint64_t  bytes_in;
    uint64_t  bytes_out;
} forwarder_stats_t;


typedef struct {
    struct mmsghdr       msgs[FORWARDER_BATCH];
    struct iovec         iov[FORWARDER_BATCH];
    struct sockaddr_in   peer[FORWARDER_BATCH];
    unsigned char        data[FORWARDER_BATCH][FORWARDER_MAX_DATAGRAM];
} forwarder_recv_batch_t;


typedef struct {
    struct mmsghdr       msgs[FORWARDER_BATCH];
    struct iovec         iov[FORWARDER_BATCH];
    struct sockaddr_in   dst[FORWARDER_BATCH];
    size_t               len[FORWARDER_BATCH];
    unsigned char       *data[FORWARDER_BATCH];
} forwarder_send_batch_t;


static volatile sig_atomic_t  forwarder_stop;
static uint64_t               forwarder_now_ms;


typedef struct queued_packet_s  queued_packet_t;

struct queued_packet_s {
    queued_packet_t        *next;
    struct sockaddr_in      dst;
    size_t                  len;
    uint64_t                due_us;
    unsigned char           data[];
};


static void usage(const char *name);
static int parse_uint(const char *value, unsigned *out);
static uint64_t now_us(void);
static uint64_t now_ms(void);
static uint32_t next_rand(uint32_t *state);
static int raw_passthrough(const forwarder_conf_t *conf);
static void stop_forwarder(int signo);
static void init_recv_batch(forwarder_recv_batch_t *batch);
static void reset_recv_batch(forwarder_recv_batch_t *batch);
static int run_raw_forwarder(int fd, const forwarder_conf_t *conf,
    const struct sockaddr_in *target, forwarder_stats_t *stats);
static int should_drop(const forwarder_conf_t *conf, uint64_t start,
    uint32_t *rnd, int from_server, unsigned *server_pkt_count);
static uint64_t packet_delay_us(const forwarder_conf_t *conf, uint32_t *rnd);
static uint64_t packet_send_time_us(const forwarder_conf_t *conf, size_t len);
static int tune_socket(int fd);
static int set_socket_blocking(int fd);
static int set_receive_timeout(int fd, unsigned timeout_ms);
static int enqueue_packet(queued_packet_t **queue, const unsigned char *buf,
    size_t len, const struct sockaddr_in *dst, uint64_t due_us,
    queued_packet_t **tail);
static int send_immediate_batch(int fd, forwarder_send_batch_t *batch,
    unsigned count, queued_packet_t **queue, queued_packet_t **tail,
    forwarder_stats_t *stats);
static int flush_due_packets(int fd, queued_packet_t **queue, uint64_t now,
    forwarder_stats_t *stats, unsigned *flushed, int *send_blocked,
    queued_packet_t **tail);
static int flush_due_batch(int fd, queued_packet_t **queue,
    uint64_t now, forwarder_stats_t *stats, unsigned *flushed, int *send_blocked,
    queued_packet_t **tail);
static int flush_due_gso(int fd, queued_packet_t *head, unsigned count,
    size_t segsize, unsigned *sent, int *send_blocked);
static uint64_t next_queue_wait_us(const queued_packet_t *queue, uint64_t now);
static void free_queue(queued_packet_t *queue);
static void write_stats(const forwarder_conf_t *conf,
    const forwarder_stats_t *stats);
static int parse_args(int argc, char **argv, forwarder_conf_t *conf);


int
main(int argc, char **argv)
{
    static forwarder_recv_batch_t  recv_batch;
    static forwarder_send_batch_t  send_batch;

    int                      fd, rc, nread, i;
    uint32_t                 rnd;
    uint64_t                 start_ms;
    fd_set                   rfds, wfds;
    struct timeval           tv;
    struct sockaddr_in       addr, target, client, dst;
    int                      have_client;
    int                      from_target;
    int                      accepting;
    int                      send_blocked, want_write;
    unsigned                 flushed, send_count;
    unsigned                 server_pkt_count;
    size_t                   pkt_len;
    uint64_t                 now, timeout_us, due_us, send_us;
    uint64_t                 client_due_us, target_due_us;
    queued_packet_t         *queue, *queue_tail;
    forwarder_conf_t         conf;
    forwarder_stats_t        stats;

    memset(&conf, 0, sizeof(conf));
    memset(&stats, 0, sizeof(stats));
    conf.duration_ms = 10000;
    conf.loss_first_keep = 5;

    if (parse_args(argc, argv, &conf) != 0) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGTERM, stop_forwarder);
    signal(SIGINT, stop_forwarder);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return 1;
    }

    if (tune_socket(fd) != 0) {
        close(fd);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t) conf.listen_port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        close(fd);
        return 1;
    }

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons((uint16_t) conf.target_port);

    if (raw_passthrough(&conf)) {
        rc = run_raw_forwarder(fd, &conf, &target, &stats);
        write_stats(&conf, &stats);
        close(fd);
        return rc == 0 ? 0 : 1;
    }

    memset(&client, 0, sizeof(client));
    have_client = 0;
    rnd = 0x9e3779b9u;
    start_ms = now_ms();
    forwarder_now_ms = start_ms;
    queue = NULL;
    queue_tail = NULL;
    client_due_us = 0;
    target_due_us = 0;
    server_pkt_count = 0;
    init_recv_batch(&recv_batch);

    for ( ;; ) {
        if (forwarder_stop) {
            break;
        }

        now = now_us();

        if (flush_due_packets(fd, &queue, now, &stats, &flushed,
                              &send_blocked, &queue_tail) != 0)
        {
            perror("sendmmsg");
            break;
        }

        accepting = !forwarder_stop
                    && (conf.duration_ms == 0
                        || now_ms() - start_ms < conf.duration_ms);

        if (!accepting && queue == NULL) {
            break;
        }

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        want_write = queue != NULL && queue->due_us <= now;

        if (accepting && !want_write) {
            FD_SET(fd, &rfds);
        }

        if (want_write || send_blocked) {
            FD_SET(fd, &wfds);
            timeout_us = 100000;

        } else if (queue != NULL) {
            timeout_us = next_queue_wait_us(queue, now);

        } else {
            timeout_us = 100000;
        }

        if (timeout_us > 100000) {
            timeout_us = 100000;
        }

        tv.tv_sec = (time_t) (timeout_us / 1000000);
        tv.tv_usec = (suseconds_t) (timeout_us % 1000000);

        rc = select((accepting || want_write || send_blocked) ? fd + 1 : 0,
                    &rfds, &wfds, NULL, &tv);
        if (rc == -1) {
            if (errno == EINTR) {
                continue;
            }

            perror("select");
            break;
        }

        if (rc == 0) {
            continue;
        }

        if ((want_write || send_blocked) && FD_ISSET(fd, &wfds)) {
            now = now_us();

            if (flush_due_packets(fd, &queue, now, &stats, &flushed,
                                  &send_blocked, &queue_tail) != 0)
            {
                perror("sendmmsg");
                break;
            }

            want_write = queue != NULL && queue->due_us <= now;
        }

        if (!accepting || !FD_ISSET(fd, &rfds)) {
            continue;
        }

        while (accepting && !forwarder_stop) {
            reset_recv_batch(&recv_batch);
            nread = recvmmsg(fd, recv_batch.msgs, FORWARDER_BATCH,
                             MSG_WAITFORONE, NULL);
            if (nread == -1) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }

                perror("recvmmsg");
                rc = -1;
                break;
            }

            now = now_us();
            forwarder_now_ms = now / 1000;
            send_count = 0;

            for (i = 0; i < nread; i++) {
                pkt_len = recv_batch.msgs[i].msg_len;
                stats.packets_in++;
                stats.bytes_in += (uint64_t) pkt_len;

                from_target = recv_batch.peer[i].sin_port == target.sin_port
                              && recv_batch.peer[i].sin_addr.s_addr
                                 == target.sin_addr.s_addr;

                if (from_target) {
                    if (!have_client) {
                        continue;
                    }

                    dst = client;

                } else {
                    client = recv_batch.peer[i];
                    have_client = 1;
                    dst = target;
                }

                if (!raw_passthrough(&conf)
                    && should_drop(&conf, start_ms, &rnd, from_target,
                                   &server_pkt_count))
                {
                    stats.packets_dropped++;
                    continue;
                }

                if (raw_passthrough(&conf) && queue == NULL) {
                    send_batch.dst[send_count] = dst;
                    send_batch.data[send_count] = recv_batch.data[i];
                    send_batch.len[send_count] = pkt_len;
                    send_count++;
                    continue;
                }

                due_us = now + packet_delay_us(&conf, &rnd);
                send_us = packet_send_time_us(&conf, pkt_len);

                if (from_target) {
                    if (due_us < target_due_us) {
                        due_us = target_due_us;
                    }

                    target_due_us = due_us + send_us;

                } else {
                    if (due_us < client_due_us) {
                        due_us = client_due_us;
                    }

                    client_due_us = due_us + send_us;
                }

                if (enqueue_packet(&queue, recv_batch.data[i], pkt_len, &dst,
                                   due_us, &queue_tail) != 0)
                {
                    perror("enqueue");
                    rc = -1;
                    break;
                }
            }

            accepting = conf.duration_ms == 0
                        || now / 1000 - start_ms < conf.duration_ms;

            if (rc == -1) {
                break;
            }

            if (send_count != 0
                && send_immediate_batch(fd, &send_batch, send_count, &queue,
                                        &queue_tail, &stats) != 0)
            {
                perror("sendmmsg");
                rc = -1;
                break;
            }

            if (queue != NULL) {
                now = now_us();

                if (flush_due_packets(fd, &queue, now, &stats, &flushed,
                                      &send_blocked, &queue_tail) != 0)
                {
                    perror("sendmmsg");
                    rc = -1;
                    break;
                }

                if (send_blocked) {
                    break;
                }
            }
        }

        if (rc == -1) {
            break;
        }
    }

    write_stats(&conf, &stats);
    free_queue(queue);

    close(fd);
    return 0;
}


static void
usage(const char *name)
{
    fprintf(stderr,
            "usage: %s --listen PORT --target PORT [--loss-ppm N] "
            "[--loss-warmup-ms N] [--loss-first-keep N] "
            "[--rate-bps N] [--delay-ms N] "
            "[--jitter-ms N] "
            "[--outage-after-ms N] [--outage-duration-ms N] [--duration-ms N] "
            "[--stats-file FILE]\n",
            name);
}


static int
parse_uint(const char *value, unsigned *out)
{
    char           *end;
    unsigned long  n;

    errno = 0;
    n = strtoul(value, &end, 10);

    if (errno != 0 || *end != '\0' || n > 1000000000UL) {
        return -1;
    }

    *out = (unsigned) n;
    return 0;
}


static uint64_t
now_us(void)
{
    struct timeval  tv;

    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000000 + (uint64_t) tv.tv_usec;
}


static uint64_t
now_ms(void)
{
    return now_us() / 1000;
}


static uint32_t
next_rand(uint32_t *state)
{
    *state = *state * 1664525u + 1013904223u;
    return *state;
}


static int
raw_passthrough(const forwarder_conf_t *conf)
{
    return conf->rate_bps == 0
           && conf->delay_ms == 0
           && conf->jitter_ms == 0
           && conf->loss_ppm == 0
           && conf->outage_duration_ms == 0;
}


static void
stop_forwarder(int signo)
{
    (void) signo;

    forwarder_stop = 1;
}


static void
init_recv_batch(forwarder_recv_batch_t *batch)
{
    unsigned  i;

    memset(batch, 0, sizeof(*batch));

    for (i = 0; i < FORWARDER_BATCH; i++) {
        batch->iov[i].iov_base = batch->data[i];
        batch->iov[i].iov_len = sizeof(batch->data[i]);
        batch->msgs[i].msg_hdr.msg_name = &batch->peer[i];
        batch->msgs[i].msg_hdr.msg_namelen = sizeof(batch->peer[i]);
        batch->msgs[i].msg_hdr.msg_iov = &batch->iov[i];
        batch->msgs[i].msg_hdr.msg_iovlen = 1;
    }
}


static void
reset_recv_batch(forwarder_recv_batch_t *batch)
{
    unsigned  i;

    for (i = 0; i < FORWARDER_BATCH; i++) {
        batch->msgs[i].msg_hdr.msg_namelen = sizeof(batch->peer[i]);
        batch->msgs[i].msg_hdr.msg_flags = 0;
        batch->msgs[i].msg_len = 0;
    }
}


static int
run_raw_forwarder(int fd, const forwarder_conf_t *conf,
    const struct sockaddr_in *target, forwarder_stats_t *stats)
{
    static forwarder_recv_batch_t  recv_batch;
    static forwarder_send_batch_t  send_batch;

    struct sockaddr_in  client, dst;
    uint64_t            start_ms;
    unsigned            send_count, i;
    int                 have_client, from_target, nread;

    if (set_socket_blocking(fd) != 0) {
        return -1;
    }

    if (set_receive_timeout(fd, 100) != 0) {
        return -1;
    }

    memset(&client, 0, sizeof(client));
    have_client = 0;
    start_ms = now_ms();
    init_recv_batch(&recv_batch);

    while (!forwarder_stop) {
        if (conf->duration_ms != 0 && now_ms() - start_ms >= conf->duration_ms)
        {
            break;
        }

        reset_recv_batch(&recv_batch);
        nread = recvmmsg(fd, recv_batch.msgs, FORWARDER_BATCH,
                         MSG_WAITFORONE, NULL);
        if (nread == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }

            perror("recvmmsg");
            return -1;
        }

        send_count = 0;

        for (i = 0; i < (unsigned) nread; i++) {
            stats->packets_in++;
            stats->bytes_in += (uint64_t) recv_batch.msgs[i].msg_len;

            from_target = recv_batch.peer[i].sin_port == target->sin_port
                          && recv_batch.peer[i].sin_addr.s_addr
                             == target->sin_addr.s_addr;

            if (from_target) {
                if (!have_client) {
                    continue;
                }

                dst = client;

            } else {
                client = recv_batch.peer[i];
                have_client = 1;
                dst = *target;
            }

            send_batch.dst[send_count] = dst;
            send_batch.data[send_count] = recv_batch.data[i];
            send_batch.len[send_count] = recv_batch.msgs[i].msg_len;
            send_count++;
        }

        if (send_count == 0) {
            continue;
        }

        for (i = 0; i < send_count; i++) {
            send_batch.iov[i].iov_base = send_batch.data[i];
            send_batch.iov[i].iov_len = send_batch.len[i];
            send_batch.msgs[i].msg_hdr.msg_name = &send_batch.dst[i];
            send_batch.msgs[i].msg_hdr.msg_namelen = sizeof(send_batch.dst[i]);
            send_batch.msgs[i].msg_hdr.msg_iov = &send_batch.iov[i];
            send_batch.msgs[i].msg_hdr.msg_iovlen = 1;
            send_batch.msgs[i].msg_hdr.msg_control = NULL;
            send_batch.msgs[i].msg_hdr.msg_controllen = 0;
            send_batch.msgs[i].msg_hdr.msg_flags = 0;
            send_batch.msgs[i].msg_len = 0;
        }

        for (i = 0; i < send_count; ) {
            nread = sendmmsg(fd, send_batch.msgs + i, send_count - i, 0);
            if (nread == -1) {
                if (errno == EINTR) {
                    continue;
                }

                perror("sendmmsg");
                return -1;
            }

            while (nread-- > 0) {
                stats->packets_out++;
                stats->bytes_out += (uint64_t) send_batch.len[i];
                i++;
            }
        }
    }

    return 0;
}


static int
should_drop(const forwarder_conf_t *conf, uint64_t start, uint32_t *rnd,
    int from_server, unsigned *server_pkt_count)
{
    uint64_t  elapsed;

    /* Never drop client-to-server packets */
    if (!from_server) {
        return 0;
    }

    /* Protect the first N server-to-client packets */
    if (conf->loss_first_keep != 0
        && *server_pkt_count < conf->loss_first_keep)
    {
        (*server_pkt_count)++;
        return 0;
    }

    (*server_pkt_count)++;

    elapsed = forwarder_now_ms - start;

    if (conf->outage_duration_ms != 0
        && elapsed >= conf->outage_after_ms
        && elapsed < conf->outage_after_ms + conf->outage_duration_ms)
    {
        return 1;
    }

    if (conf->loss_ppm >= 1000000) {
        return 1;
    }

    if (conf->loss_ppm != 0 && elapsed >= conf->loss_warmup_ms
        && next_rand(rnd) % 1000000u < conf->loss_ppm)
    {
        return 1;
    }

    return 0;
}


static uint64_t
packet_delay_us(const forwarder_conf_t *conf, uint32_t *rnd)
{
    unsigned  delay, jitter;

    delay = conf->delay_ms;

    if (conf->jitter_ms != 0) {
        jitter = next_rand(rnd) % (conf->jitter_ms + 1);
        delay += jitter;
    }

    return (uint64_t) delay * 1000;
}


static uint64_t
packet_send_time_us(const forwarder_conf_t *conf, size_t len)
{
    uint64_t  bits;

    if (conf->rate_bps == 0) {
        return 0;
    }

    bits = (uint64_t) len * 8 * 1000000;

    return (bits + conf->rate_bps - 1) / conf->rate_bps;
}


static int
tune_socket(int fd)
{
    int  flags, size;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        return -1;
    }

    size = 4 * 1024 * 1024;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) {
        perror("setsockopt SO_RCVBUF");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1) {
        perror("setsockopt SO_SNDBUF");
        return -1;
    }

    return 0;
}


static int
set_socket_blocking(int fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        return -1;
    }

    return 0;
}


static int
set_receive_timeout(int fd, unsigned timeout_ms)
{
    struct timeval  tv;

    tv.tv_sec = (time_t) (timeout_ms / 1000);
    tv.tv_usec = (suseconds_t) ((timeout_ms % 1000) * 1000);

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        perror("setsockopt SO_RCVTIMEO");
        return -1;
    }

    return 0;
}


static int
enqueue_packet(queued_packet_t **queue, const unsigned char *buf, size_t len,
    const struct sockaddr_in *dst, uint64_t due_us, queued_packet_t **tail)
{
    queued_packet_t  *pkt, **slot;

    pkt = malloc(sizeof(queued_packet_t) + len);
    if (pkt == NULL) {
        return -1;
    }

    memcpy(pkt->data, buf, len);
    pkt->len = len;
    pkt->dst = *dst;
    pkt->due_us = due_us;
    pkt->next = NULL;

    if (*tail != NULL && (*tail)->due_us <= due_us) {
        (*tail)->next = pkt;
        *tail = pkt;
        return 0;
    }

    for (slot = queue; *slot != NULL; slot = &(*slot)->next) {
        if ((*slot)->due_us > due_us) {
            break;
        }
    }

    pkt->next = *slot;
    *slot = pkt;

    if (pkt->next == NULL) {
        *tail = pkt;
    }

    return 0;
}


static int
send_immediate_batch(int fd, forwarder_send_batch_t *batch, unsigned count,
    queued_packet_t **queue, queued_packet_t **tail, forwarder_stats_t *stats)
{
    unsigned  i, sent;
    int       n;

    sent = 0;

    while (sent < count) {
        for (i = sent; i < count; i++) {
            batch->iov[i].iov_base = batch->data[i];
            batch->iov[i].iov_len = batch->len[i];
            batch->msgs[i].msg_hdr.msg_name = &batch->dst[i];
            batch->msgs[i].msg_hdr.msg_namelen = sizeof(batch->dst[i]);
            batch->msgs[i].msg_hdr.msg_iov = &batch->iov[i];
            batch->msgs[i].msg_hdr.msg_iovlen = 1;
            batch->msgs[i].msg_hdr.msg_control = NULL;
            batch->msgs[i].msg_hdr.msg_controllen = 0;
            batch->msgs[i].msg_hdr.msg_flags = 0;
            batch->msgs[i].msg_len = 0;
        }

        n = sendmmsg(fd, batch->msgs + sent, count - sent, 0);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        for (i = sent; i < sent + (unsigned) n; i++) {
            stats->packets_out++;
            stats->bytes_out += (uint64_t) batch->len[i];
        }

        sent += (unsigned) n;
    }

    for (i = sent; i < count; i++) {
        if (enqueue_packet(queue, batch->data[i], batch->len[i],
                           &batch->dst[i], 0, tail) != 0)
        {
            return -1;
        }
    }

    return 0;
}


static int
flush_due_packets(int fd, queued_packet_t **queue, uint64_t now,
    forwarder_stats_t *stats, unsigned *flushed, int *send_blocked,
    queued_packet_t **tail)
{
    *flushed = 0;
    *send_blocked = 0;

    while (*queue != NULL && (*queue)->due_us <= now) {
        if (flush_due_batch(fd, queue, now, stats, flushed, send_blocked, tail)
            != 0)
        {
            return -1;
        }

        if (*send_blocked) {
            break;
        }
    }

    return 0;
}


static int
flush_due_batch(int fd, queued_packet_t **queue, uint64_t now,
    forwarder_stats_t *stats, unsigned *flushed, int *send_blocked,
    queued_packet_t **tail)
{
    struct mmsghdr   msgs[FORWARDER_BATCH];
    struct iovec     iov[FORWARDER_BATCH];
    queued_packet_t *pkt, *head, *next;
    unsigned         count, i, sent;
    int              n;
    size_t           segsize;
    int              gso_ok;

    head = *queue;
    count = 0;
    segsize = 0;
    gso_ok = 1;

    pkt = head;
    while (count < FORWARDER_BATCH && pkt != NULL && pkt->due_us <= now) {
        memset(&msgs[count], 0, sizeof(msgs[count]));
        iov[count].iov_base = pkt->data;
        iov[count].iov_len = pkt->len;
        msgs[count].msg_hdr.msg_name = &pkt->dst;
        msgs[count].msg_hdr.msg_namelen = sizeof(pkt->dst);
        msgs[count].msg_hdr.msg_iov = &iov[count];
        msgs[count].msg_hdr.msg_iovlen = 1;

        if (count == 0) {
            segsize = pkt->len;

        } else if (pkt->len != segsize
                   || memcmp(&pkt->dst, &head->dst, sizeof(pkt->dst)) != 0)
        {
            gso_ok = 0;
        }

        pkt = pkt->next;
        count++;
    }

    sent = 0;

    if (gso_ok && count > 1 && segsize > 0 && segsize <= 65535) {
        if (flush_due_gso(fd, head, count, segsize, &sent, send_blocked) != 0) {
            return -1;
        }
    }

    while (sent < count && !*send_blocked) {
        n = sendmmsg(fd, msgs + sent, count - sent, 0);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                *send_blocked = 1;
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        sent += (unsigned) n;
    }

    for (i = 0; i < sent; i++) {
        pkt = head;
        next = head->next;
        stats->packets_out++;
        stats->bytes_out += (uint64_t) pkt->len;
        (*flushed)++;
        free(pkt);
        head = next;
    }

    *queue = head;
    if (head == NULL) {
        *tail = NULL;
    }

    return 0;
}


static int
flush_due_gso(int fd, queued_packet_t *head, unsigned count, size_t segsize,
    unsigned *sent, int *send_blocked)
{
#ifdef UDP_SEGMENT
    char                control[CMSG_SPACE(sizeof(uint16_t))];
    struct cmsghdr     *cmsg;
    struct iovec        iov[FORWARDER_BATCH];
    struct msghdr       msg;
    queued_packet_t    *pkt;
    uint16_t            gso;
    int                 n;
    unsigned            i;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));

    pkt = head;
    for (i = 0; i < count; i++) {
        iov[i].iov_base = pkt->data;
        iov[i].iov_len = pkt->len;
        pkt = pkt->next;
    }

    msg.msg_name = &head->dst;
    msg.msg_namelen = sizeof(head->dst);
    msg.msg_iov = iov;
    msg.msg_iovlen = count;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));

    gso = (uint16_t) segsize;
    memcpy(CMSG_DATA(cmsg), &gso, sizeof(gso));
    msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));

    n = sendmsg(fd, &msg, 0);
    if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *send_blocked = 1;
            return 0;
        }

        if (errno == EINTR) {
            return flush_due_gso(fd, head, count, segsize, sent, send_blocked);
        }

        if (errno == EINVAL || errno == EMSGSIZE || errno == ENOPROTOOPT) {
            return 0;
        }

        return -1;
    }

    *sent = (unsigned) (n / segsize);
    if (*sent > count) {
        *sent = count;
    }

    return 0;
#else
    (void) fd;
    (void) head;
    (void) count;
    (void) segsize;
    (void) sent;
    (void) send_blocked;
    return 0;
#endif
}


static uint64_t
next_queue_wait_us(const queued_packet_t *queue, uint64_t now)
{
    if (queue == NULL || queue->due_us <= now) {
        return 0;
    }

    return queue->due_us - now;
}


static void
free_queue(queued_packet_t *queue)
{
    queued_packet_t  *pkt;

    while (queue != NULL) {
        pkt = queue;
        queue = queue->next;
        free(pkt);
    }
}


static void
write_stats(const forwarder_conf_t *conf, const forwarder_stats_t *stats)
{
    FILE      *fp;
    uint64_t   loss_rate_ppm;

    if (conf->stats_file == NULL) {
        return;
    }

    loss_rate_ppm = stats->packets_in == 0 ? 0 :
                    stats->packets_dropped * 1000000 / stats->packets_in;

    fp = fopen(conf->stats_file, "w");
    if (fp == NULL) {
        perror("fopen stats-file");
        return;
    }

    fprintf(fp,
            "packets_in=%llu\n"
            "packets_out=%llu\n"
            "packets_dropped=%llu\n"
            "bytes_in=%llu\n"
            "bytes_out=%llu\n"
            "loss_rate_ppm=%llu\n"
            "rate_bps=%u\n",
            (unsigned long long) stats->packets_in,
            (unsigned long long) stats->packets_out,
            (unsigned long long) stats->packets_dropped,
            (unsigned long long) stats->bytes_in,
            (unsigned long long) stats->bytes_out,
            (unsigned long long) loss_rate_ppm,
            conf->rate_bps);

    fclose(fp);
}


static int
parse_args(int argc, char **argv, forwarder_conf_t *conf)
{
    int  i;

    for (i = 1; i < argc; i++) {
        if (i + 1 >= argc) {
            return -1;
        }

        if (strcmp(argv[i], "--listen") == 0) {
            if (parse_uint(argv[++i], &conf->listen_port) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--target") == 0) {
            if (parse_uint(argv[++i], &conf->target_port) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--loss-ppm") == 0) {
            if (parse_uint(argv[++i], &conf->loss_ppm) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--loss-warmup-ms") == 0) {
            if (parse_uint(argv[++i], &conf->loss_warmup_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--loss-first-keep") == 0) {
            if (parse_uint(argv[++i], &conf->loss_first_keep) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--rate-bps") == 0) {
            if (parse_uint(argv[++i], &conf->rate_bps) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--delay-ms") == 0) {
            if (parse_uint(argv[++i], &conf->delay_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--jitter-ms") == 0) {
            if (parse_uint(argv[++i], &conf->jitter_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--outage-after-ms") == 0) {
            if (parse_uint(argv[++i], &conf->outage_after_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--outage-duration-ms") == 0) {
            if (parse_uint(argv[++i], &conf->outage_duration_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--duration-ms") == 0) {
            if (parse_uint(argv[++i], &conf->duration_ms) != 0) {
                return -1;
            }

        } else if (strcmp(argv[i], "--stats-file") == 0) {
            conf->stats_file = argv[++i];

        } else {
            return -1;
        }
    }

    if (conf->listen_port == 0 || conf->target_port == 0
        || conf->listen_port > 65535 || conf->target_port > 65535)
    {
        return -1;
    }

    return 0;
}
