/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_cc.h>
#include <ngx_event_quic_reno.h>
#include <ngx_event_quic_cubic.h>
#include <ngx_event_quic_bbr.h>


static const ngx_quic_cc_algo_t *ngx_quic_cc_get(ngx_quic_connection_t *qc);
static ngx_msec_t ngx_quic_cc_oldest_sent_packet(ngx_connection_t *c);
static void ngx_quic_cc_post_unblocked(ngx_connection_t *c, ngx_uint_t blocked);


const ngx_quic_cc_algo_t *
ngx_quic_cc_lookup(ngx_quic_cc_algorithm_e algo)
{
    switch (algo) {

    case NGX_QUIC_CC_RENO:
        return &ngx_quic_cc_reno;

    case NGX_QUIC_CC_BBR:
        return &ngx_quic_cc_bbr;

    case NGX_QUIC_CC_CUBIC:
    default:
        return &ngx_quic_cc_cubic;
    }
}


static const ngx_quic_cc_algo_t *
ngx_quic_cc_get(ngx_quic_connection_t *qc)
{
    return ngx_quic_cc_lookup(qc->conf->cc_algorithm);
}


void
ngx_quic_cc_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_uint_t                       blocked;
    ngx_msec_t                       now, timer;
    ngx_quic_congestion_t           *cg;
    ngx_quic_connection_t           *qc;
    const ngx_quic_cc_algo_t        *algo;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    now = ngx_current_msec;

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;

    /* prevent recovery_start from wrapping */

    timer = now - cg->recovery_start;

    if ((ngx_msec_int_t) timer < 0) {
        cg->recovery_start = ngx_quic_cc_oldest_sent_packet(c) - 1;
    }

    algo = ngx_quic_cc_get(qc);

    if (algo->flags & NGX_QUIC_CC_SKIP_RECOVERY)
        goto skip_recovery;

    timer = f->send_time - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack rec t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

skip_recovery:

    if (algo->flags & NGX_QUIC_CC_SKIP_IDLE)
        goto skip_idle;

    if (cg->idle) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack idle t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

skip_idle:

    algo->ack(c, f);

done:

    ngx_quic_cc_post_unblocked(c, blocked);
}


void
ngx_quic_cc_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_uint_t                       blocked;
    ngx_msec_t                       now, timer;
    ngx_quic_congestion_t           *cg;
    ngx_quic_connection_t           *qc;
    const ngx_quic_cc_algo_t        *algo;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (f->pnum < qc->rst_pnum) {
        return;
    }

    blocked = (cg->in_flight >= cg->window) ? 1 : 0;

    cg->in_flight -= f->plen;

    now = ngx_current_msec;

    cg->mtu = qc->path->mtu;
    cg->recovery_start = now;

    algo = ngx_quic_cc_get(qc);

    if (algo->flags & NGX_QUIC_CC_SKIP_RECOVERY)
        goto skip_lost_recovery;

    timer = f->send_time - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost rec t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

skip_lost_recovery:

    if (f->ignore_loss) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost ignore t:%M win:%uz if:%uz",
                       now, cg->window, cg->in_flight);

        goto done;
    }

    algo->lost(c, f);
    f->plen = 0;

done:

    ngx_quic_cc_post_unblocked(c, blocked);
}


void
ngx_quic_cc_reset(ngx_quic_connection_t *qc)
{
    ngx_memzero(&qc->congestion, sizeof(ngx_quic_congestion_t));

    qc->congestion.window = ngx_min(10 * NGX_QUIC_MIN_INITIAL_SIZE,
                                    ngx_max(2 * NGX_QUIC_MIN_INITIAL_SIZE,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.mtu = NGX_QUIC_MIN_INITIAL_SIZE;
    qc->congestion.recovery_start = ngx_current_msec - 1;

    ngx_quic_cc_get(qc)->reset(qc);
}


void
ngx_quic_cc_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion idle:%ui", idle);

    ngx_quic_cc_get(qc)->idle(c, idle);
}


void
ngx_quic_cc_persistent_congestion(ngx_connection_t *c, ngx_msec_t recovery_start)
{
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    cg->mtu = qc->path->mtu;
    cg->recovery_start = recovery_start;
    cg->window = cg->mtu * 2;

    ngx_quic_cc_get(qc)->persistent_congestion(c);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion persistent t:%M win:%uz",
                   ngx_current_msec, cg->window);
}


ngx_msec_t
ngx_quic_cc_pacing_delay(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (ngx_quic_cc_get(qc)->pacing_delay) {
        return ngx_quic_cc_get(qc)->pacing_delay(c);
    }

    return 0;
}


void
ngx_quic_cc_init_rate_sample(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f, ngx_msec_t now, size_t in_flight)
{
    const ngx_quic_cc_algo_t  *algo;

    algo = ngx_quic_cc_get(qc);

    if ((algo->flags & NGX_QUIC_CC_HAS_RATE_SAMPLE) && algo->init_rate_sample) {
        algo->init_rate_sample(qc, f, now, in_flight);
    }
}


void
ngx_quic_cc_update_pacing(ngx_quic_congestion_t *cg, size_t sent,
    ngx_msec_t now)
{
    ngx_quic_connection_t     *qc;
    const ngx_quic_cc_algo_t  *algo;

    qc = (ngx_quic_connection_t *)
         ((u_char *) cg - offsetof(ngx_quic_connection_t, congestion));
    algo = ngx_quic_cc_get(qc);

    if ((algo->flags & NGX_QUIC_CC_HAS_PACING) && algo->update_pacing) {
        algo->update_pacing(cg, sent, now);
    }
}


void
ngx_quic_cc_set_pacing_timer(ngx_quic_connection_t *qc, ngx_msec_t delay)
{
    const ngx_quic_cc_algo_t  *algo;

    algo = ngx_quic_cc_get(qc);

    if ((algo->flags & NGX_QUIC_CC_HAS_PACING) && algo->set_pacing_timer) {
        algo->set_pacing_timer(qc, delay);
    }
}


static ngx_msec_t
ngx_quic_cc_oldest_sent_packet(ngx_connection_t *c)
{
    ngx_msec_t              oldest;
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    oldest = ngx_current_msec;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (!ngx_queue_empty(&ctx->sent)) {
            q = ngx_queue_head(&ctx->sent);
            start = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if ((ngx_msec_int_t) (start->send_time - oldest) < 0) {
                oldest = start->send_time;
            }
        }
    }

    return oldest;
}


static void
ngx_quic_cc_post_unblocked(ngx_connection_t *c, ngx_uint_t blocked)
{
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    if (blocked && cg->in_flight < cg->window) {
        ngx_post_event(&qc->push, &ngx_posted_events);
    }
}


void *
ngx_quic_cc_create_conf(const ngx_quic_cc_algo_t *algo, ngx_pool_t *pool)
{
    void  *conf;

    if (algo == NULL || algo->conf_size == 0) {
        return NULL;
    }

    conf = ngx_pcalloc(pool, algo->conf_size);
    if (conf == NULL) {
        return NULL;
    }

    if (algo->init_conf) {
        algo->init_conf(conf);
    }

    return conf;
}


char *
ngx_quic_cc_init_conf(const ngx_quic_cc_algo_t *algo, void *conf)
{
    if (algo == NULL) {
        return NGX_CONF_ERROR;
    }

    if (algo->init_conf) {
        algo->init_conf(conf);
    }

    return NGX_CONF_OK;
}


char *
ngx_quic_cc_merge_conf(ngx_conf_t *cf, const ngx_quic_cc_algo_t *algo,
    void *conf, void *prev)
{
    if (algo == NULL) {
        return NGX_CONF_ERROR;
    }

    if (algo->merge_conf) {
        return algo->merge_conf(cf, conf, prev);
    }

    return NGX_CONF_OK;
}
