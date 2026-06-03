/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_reno.h>


static void ngx_quic_reno_reset(ngx_quic_connection_t *qc);
static void ngx_quic_reno_ack(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_reno_lost(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_reno_idle(ngx_connection_t *c, ngx_uint_t idle);
static void ngx_quic_reno_persistent_congestion(ngx_connection_t *c);


const ngx_quic_cc_algo_t  ngx_quic_cc_reno = {
    0,
    NULL,
    NULL,
    NULL,
    ngx_quic_reno_reset,
    ngx_quic_reno_ack,
    ngx_quic_reno_lost,
    ngx_quic_reno_idle,
    ngx_quic_reno_persistent_congestion,
    NULL,
    NULL,
    NULL,
    NULL,
    0
};


static void
ngx_quic_reno_reset(ngx_quic_connection_t *qc)
{
    qc->congestion.w_prior = qc->congestion.window;
}


static void
ngx_quic_reno_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
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

    cg->window += (uint64_t) cg->mtu * f->plen / cg->window;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion ack reno t:%M win:%uz if:%uz",
                   now, cg->window, cg->in_flight);
}


static void
ngx_quic_reno_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_msec_t              now;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    now = ngx_current_msec;

    cg->w_prior = cg->window;
    cg->ssthresh = ngx_max(cg->w_prior / 2, cg->mtu * 2);
    cg->window = cg->ssthresh;
    cg->idle_start = now;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion lost reno t:%M win:%uz if:%uz",
                   now, cg->window, cg->in_flight);
}


static void
ngx_quic_reno_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->congestion.idle = idle;
}


static void
ngx_quic_reno_persistent_congestion(ngx_connection_t *c)
{
    (void) c;

    return;
}
