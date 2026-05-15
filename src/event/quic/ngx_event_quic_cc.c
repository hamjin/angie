/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) OpenAI
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


extern ngx_quic_cc_ops_t  ngx_quic_cc_cubic_ops;
extern ngx_quic_cc_ops_t  ngx_quic_cc_bbr1_ops;
extern ngx_quic_cc_ops_t  ngx_quic_cc_bbr_ops;


static ngx_quic_cc_ops_t *
ngx_quic_cc_ops(ngx_quic_connection_t *qc)
{
    switch (qc->conf->congestion_control) {
    case NGX_QUIC_CC_BBR1:
        return &ngx_quic_cc_bbr1_ops;
    case NGX_QUIC_CC_BBR:
        return &ngx_quic_cc_bbr_ops;
    default:
        return &ngx_quic_cc_cubic_ops;
    }
}


void
ngx_quic_cc_reset(ngx_quic_connection_t *qc)
{
    qc->congestion.type = qc->conf->congestion_control;
    qc->congestion.ops = ngx_quic_cc_ops(qc);

    if (qc->congestion.ops && qc->congestion.ops->reset) {
        qc->congestion.ops->reset(qc);
    }
}


void
ngx_quic_cc_ack(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->congestion.ops && qc->congestion.ops->on_ack) {
        qc->congestion.ops->on_ack(c, sample);
    }
}


void
ngx_quic_cc_loss(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->congestion.ops && qc->congestion.ops->on_loss) {
        qc->congestion.ops->on_loss(c, sample);
    }
}


void
ngx_quic_cc_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->congestion.ops && qc->congestion.ops->on_idle) {
        qc->congestion.ops->on_idle(c, idle);
    }
}


ngx_int_t
ngx_quic_cc_can_send(ngx_connection_t *c, size_t bytes, ngx_msec_t now,
    ngx_msec_t *delay)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->congestion.ops && qc->congestion.ops->can_send) {
        return qc->congestion.ops->can_send(c, bytes, now, delay);
    }

    return NGX_OK;
}


void
ngx_quic_cc_remove_in_flight(ngx_connection_t *c, ngx_quic_packet_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (pkt == NULL || !pkt->ack_eliciting || pkt->bytes == 0) {
        return;
    }

    if (qc->congestion.in_flight >= pkt->bytes) {
        qc->congestion.in_flight -= pkt->bytes;
    } else {
        qc->congestion.in_flight = 0;
    }
}


ngx_quic_packet_t *
ngx_quic_alloc_packet(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_packet_t      *pkt;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_packets)) {
        q = ngx_queue_head(&qc->free_packets);
        pkt = ngx_queue_data(q, ngx_quic_packet_t, queue);
        ngx_queue_remove(q);

    } else {
        pkt = ngx_palloc(c->pool, sizeof(ngx_quic_packet_t));
        if (pkt == NULL) {
            return NULL;
        }
    }

    ngx_memzero(pkt, sizeof(ngx_quic_packet_t));

    return pkt;
}


void
ngx_quic_free_packet(ngx_connection_t *c, ngx_quic_packet_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    ngx_queue_insert_head(&qc->free_packets, &pkt->queue);
}


void
ngx_quic_free_packets(ngx_connection_t *c, ngx_queue_t *packets)
{
    ngx_queue_t       *q;
    ngx_quic_packet_t *pkt;

    for ( ;; ) {
        q = ngx_queue_head(packets);

        if (q == ngx_queue_sentinel(packets)) {
            break;
        }

        ngx_queue_remove(q);
        pkt = ngx_queue_data(q, ngx_quic_packet_t, queue);
        ngx_quic_free_packet(c, pkt);
    }
}
