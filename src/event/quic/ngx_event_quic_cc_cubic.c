/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) OpenAI
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


static void ngx_quic_cc_cubic_reset(ngx_quic_connection_t *qc);
static void ngx_quic_cc_cubic_ack(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static void ngx_quic_cc_cubic_loss(ngx_connection_t *c,
    ngx_quic_cc_loss_sample_t *sample);
static void ngx_quic_cc_cubic_idle(ngx_connection_t *c, ngx_uint_t idle);
static ngx_int_t ngx_quic_cc_cubic_can_send(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now, ngx_msec_t *delay);


ngx_quic_cc_ops_t  ngx_quic_cc_cubic_ops = {
    ngx_quic_cc_cubic_reset,
    ngx_quic_cc_cubic_ack,
    ngx_quic_cc_cubic_loss,
    ngx_quic_cc_cubic_idle,
    ngx_quic_cc_cubic_can_send
};


static void
ngx_quic_cc_cubic_reset(ngx_quic_connection_t *qc)
{
    qc->congestion.window = ngx_min(10 * NGX_QUIC_MIN_INITIAL_SIZE,
                                    ngx_max(2 * NGX_QUIC_MIN_INITIAL_SIZE,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.mtu = NGX_QUIC_MIN_INITIAL_SIZE;
    qc->congestion.recovery_start = ngx_current_msec - 1;
    qc->congestion.pacing_rate = 0;
    qc->congestion.delivered = 0;
    qc->congestion.delivered_time = ngx_current_msec;
    qc->congestion.app_limited_at = 0;
    qc->congestion.next_send = 0;
}


static void
ngx_quic_cc_cubic_ack(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (sample == NULL || sample->acked == 0) {
        return;
    }

    qc->congestion.delivered += sample->acked;
    qc->congestion.delivered_time = ngx_current_msec;
}


static void
ngx_quic_cc_cubic_loss(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (sample == NULL || sample->lost == 0) {
        return;
    }

    qc->congestion.delivered_time = ngx_current_msec;
}


static void
ngx_quic_cc_cubic_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->congestion.idle = idle;
}


static ngx_int_t
ngx_quic_cc_cubic_can_send(ngx_connection_t *c, size_t bytes, ngx_msec_t now,
    ngx_msec_t *delay)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (delay) {
        *delay = 0;
    }

    if (qc->congestion.next_send > now) {
        if (delay) {
            *delay = qc->congestion.next_send - now;
        }
        return NGX_AGAIN;
    }

    if (qc->congestion.in_flight + bytes > qc->congestion.window) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}
