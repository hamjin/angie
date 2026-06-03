/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_cubic.h>


/* CUBIC parameters x10 */
#define NGX_QUIC_CUBIC_BETA                  7
#define NGX_QUIC_CUBIC_C                     4


static void ngx_quic_cubic_reset(ngx_quic_connection_t *qc);
static void ngx_quic_cubic_ack(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_cubic_lost(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_cubic_idle(ngx_connection_t *c, ngx_uint_t idle);
static void ngx_quic_cubic_persistent_congestion(ngx_connection_t *c);
static size_t ngx_quic_congestion_cubic(ngx_connection_t *c);
static ngx_msec_t ngx_quic_congestion_cubic_time(ngx_connection_t *c);


const ngx_quic_cc_algo_t  ngx_quic_cc_cubic = {
    0,
    NULL,
    NULL,
    NULL,
    ngx_quic_cubic_reset,
    ngx_quic_cubic_ack,
    ngx_quic_cubic_lost,
    ngx_quic_cubic_idle,
    ngx_quic_cubic_persistent_congestion,
    NULL,
    NULL,
    NULL,
    NULL,
    0
};


static void
ngx_quic_cubic_reset(ngx_quic_connection_t *qc)
{
    qc->congestion.w_prior = qc->congestion.window;
    qc->congestion.w_est = qc->congestion.window;
    qc->congestion.w_max = qc->congestion.window;
    qc->congestion.k = ngx_current_msec;
}


static void
ngx_quic_cubic_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    size_t                  w_cubic;
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    now = ngx_current_msec;
    (void) now;

    if (cg->window < cg->ssthresh) {
        cg->window += f->plen;

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack ss t:%M win:%uz ss:%z if:%uz",
                       now, cg->window, cg->ssthresh, cg->in_flight);

        return;
    }

    /* RFC 9438, 4.2. Window Increase Function */

    w_cubic = ngx_quic_congestion_cubic(c);

    if (cg->window < cg->w_prior) {
        cg->w_est += (uint64_t) cg->mtu * f->plen
                     * 3 * (10 - NGX_QUIC_CUBIC_BETA)
                     / (10 + NGX_QUIC_CUBIC_BETA) / cg->window;

    } else {
        cg->w_est += (uint64_t) cg->mtu * f->plen / cg->window;
    }

    if (w_cubic < cg->w_est) {
        cg->window = cg->w_est;

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack reno t:%M win:%uz c:%uz if:%uz",
                       now, cg->window, w_cubic, cg->in_flight);

    } else if (w_cubic > cg->window) {

        if (w_cubic >= cg->window * 3 / 2) {
            cg->window += cg->mtu / 2;

        } else {
            cg->window += (uint64_t) cg->mtu * (w_cubic - cg->window)
                          / cg->window;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack cubic t:%M win:%uz c:%uz if:%uz",
                       now, cg->window, w_cubic, cg->in_flight);

    } else {
        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack skip t:%M win:%uz c:%uz if:%uz",
                       now, cg->window, w_cubic, cg->in_flight);
    }
}


static void
ngx_quic_cubic_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    now = ngx_current_msec;

    /* RFC 9438, 4.6. Multiplicative Decrease */

    cg->w_prior = cg->window;

    /* RFC 9438, 4.7. Fast Convergence */

    cg->w_max = (cg->window < cg->w_max)
                ? cg->window * (10 + NGX_QUIC_CUBIC_BETA) / 20 : cg->window;
    cg->ssthresh = cg->in_flight * NGX_QUIC_CUBIC_BETA / 10;
    cg->window = ngx_max(cg->ssthresh, cg->mtu * 2);
    cg->w_est = cg->window;
    cg->k = now + ngx_quic_congestion_cubic_time(c);
    cg->idle_start = now;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion lost t:%M win:%uz if:%uz",
                   now, cg->window, cg->in_flight);
}


static void
ngx_quic_cubic_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (cg->window >= cg->ssthresh) {
        /* RFC 9438, 5.8. Behavior for Application-Limited Flows */

        now = ngx_current_msec;

        if (cg->idle) {
            cg->k += now - cg->idle_start;
        }

        cg->idle_start = now;
    }

    cg->idle = idle;
}


static void
ngx_quic_cubic_persistent_congestion(ngx_connection_t *c)
{
    (void) c;

    return;
}


static size_t
ngx_quic_congestion_cubic(ngx_connection_t *c)
{
    int64_t                 w, t, cc;
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    ngx_quic_cubic_idle(c, cg->idle);

    now = ngx_current_msec;
    t = (ngx_msec_int_t) (now - cg->k);

    if (t > 1000000) {
        w = NGX_MAX_SIZE_T_VALUE;
        goto done;
    }

    if (t < -1000000) {
        w = 0;
        goto done;
    }

    /*
     * RFC 9438, Figure 1
     *
     *   w_cubic = C * (t_msec / 1000) ^ 3 * mtu + w_max
     */

    cc = 10000000000ll / (int64_t) cg->mtu / NGX_QUIC_CUBIC_C;
    w = t * t * t / cc + (int64_t) cg->w_max;

    if (w > NGX_MAX_SIZE_T_VALUE) {
        w = NGX_MAX_SIZE_T_VALUE;
    }

    if (w < 0) {
        w = 0;
    }

done:

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cubic t:%L w:%L wm:%uz", t, w, cg->w_max);

    return w;
}


static ngx_msec_t
ngx_quic_congestion_cubic_time(ngx_connection_t *c)
{
    int64_t                 v, x, d, cc;
    ngx_uint_t              n;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    /*
     * RFC 9438, Figure 2
     *
     *   k_msec = ((w_max - cwnd_epoch) / C / mtu) ^ 1/3 * 1000
     */

    if (cg->w_max <= cg->window) {
        return 0;
    }

    cc = 10000000000ll / (int64_t) cg->mtu / NGX_QUIC_CUBIC_C;
    v = (int64_t) (cg->w_max - cg->window) * cc;

    /*
     * Newton-Raphson method for x ^ 3 = v:
     *
     *   x_next = (2 * x_prev + v / x_prev ^ 2) / 3
     */

    x = 5000;

    for (n = 1; n <= 10; n++) {
        d =  (v / x / x - x) / 3;
        x += d;

        if (ngx_abs(d) <= 100) {
            break;
        }
    }

    if (x > NGX_MAX_SIZE_T_VALUE) {
        return NGX_MAX_SIZE_T_VALUE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cubic time:%L n:%ui", x, n);

    return x;
}
