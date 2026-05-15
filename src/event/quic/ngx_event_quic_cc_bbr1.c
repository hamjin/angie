/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) OpenAI
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BBR_UNIT            256
#define NGX_QUIC_BBR_HIGH_GAIN       739
#define NGX_QUIC_BBR_DRAIN_GAIN      89
#define NGX_QUIC_BBR_CWND_GAIN       512
#define NGX_QUIC_BBR_PROBE_RTT_GAIN  256
#define NGX_QUIC_BBR_FULL_BW_THRESH  320
#define NGX_QUIC_BBR_MIN_RTT_WIN     10000
#define NGX_QUIC_BBR_PROBE_RTT_TIME  200
#define NGX_QUIC_BBR_ACK_EPOCH_RESET (1 << 20)
#define NGX_QUIC_BBR_EXTRA_ACKED_WIN 5
#define NGX_QUIC_BBR_EXTRA_ACKED_MAX 100
#define NGX_QUIC_BBR_CYCLE_LEN       8
#define NGX_QUIC_BBR_PACING_MARGIN   1


static void ngx_quic_cc_bbr1_reset(ngx_quic_connection_t *qc);
static void ngx_quic_cc_bbr1_ack(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static void ngx_quic_cc_bbr1_loss(ngx_connection_t *c,
    ngx_quic_cc_loss_sample_t *sample);
static void ngx_quic_cc_bbr1_idle(ngx_connection_t *c, ngx_uint_t idle);
static ngx_int_t ngx_quic_cc_bbr1_can_send(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now, ngx_msec_t *delay);
static void ngx_quic_cc_bbr1_update_model(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static void ngx_quic_cc_bbr1_update_gains(ngx_quic_bbr1_state_t *b);
static void ngx_quic_cc_bbr1_enter_probe_bw(ngx_connection_t *c);
static ngx_uint_t ngx_quic_cc_bbr1_next_cycle(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static size_t ngx_quic_cc_bbr1_bdp(ngx_connection_t *c, uint64_t bw,
    ngx_uint_t gain);
static size_t ngx_quic_cc_bbr1_target_cwnd(ngx_connection_t *c,
    uint64_t bw, ngx_uint_t gain);
static size_t ngx_quic_cc_bbr1_quantize(ngx_connection_t *c, size_t cwnd);
static size_t ngx_quic_cc_bbr1_extra_acked(ngx_connection_t *c);
static void ngx_quic_cc_bbr1_set_pacing_rate(ngx_connection_t *c,
    uint64_t bw, ngx_uint_t gain);
static void ngx_quic_cc_bbr1_update_pacing(ngx_connection_t *c,
    size_t bytes, ngx_msec_t now);

ngx_quic_cc_ops_t  ngx_quic_cc_bbr1_ops = {
    ngx_quic_cc_bbr1_reset,
    ngx_quic_cc_bbr1_ack,
    ngx_quic_cc_bbr1_loss,
    ngx_quic_cc_bbr1_idle,
    ngx_quic_cc_bbr1_can_send
};


static void
ngx_quic_cc_bbr1_reset(ngx_quic_connection_t *qc)
{
    ngx_quic_bbr1_state_t  *b;

    b = &qc->congestion.state.bbr1;

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
    qc->congestion.bw_sample = 0;
    qc->congestion.next_send = 0;
    qc->congestion.round_start_time = ngx_current_msec;
    b->bw = 0;
    b->full_bw = 0;
    b->next_round_delivered = 0;
    b->ack_epoch_acked = 0;
    b->extra_acked[0] = 0;
    b->extra_acked[1] = 0;
    b->prior_cwnd = qc->congestion.window;
    b->min_rtt = NGX_TIMER_INFINITE;
    b->min_rtt_stamp = ngx_current_msec;
    b->probe_rtt_done = 0;
    b->cycle_stamp = ngx_current_msec;
    b->ack_epoch_stamp = ngx_current_msec;
    b->mode = NGX_QUIC_BBR_STARTUP;
    b->cycle_idx = 0;
    b->full_bw_cnt = 0;
    b->round_start = 0;
    b->full_bw_reached = 0;
    b->probe_rtt_round_done = 0;
    b->extra_acked_win_idx = 0;
    b->extra_acked_win_rtts = 0;
    b->pacing_gain = NGX_QUIC_BBR_HIGH_GAIN;
    b->cwnd_gain = NGX_QUIC_BBR_HIGH_GAIN;

    ngx_quic_cc_bbr1_set_pacing_rate(NULL, b->bw, b->pacing_gain);
}


static void
ngx_quic_cc_bbr1_ack(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample)
{
    ngx_quic_connection_t  *qc;
    size_t                  target, cwnd;

    qc = ngx_quic_get_connection(c);

    if (sample == NULL || sample->acked == 0) {
        return;
    }

    qc->congestion.delivered += sample->acked;
    qc->congestion.delivered_time = ngx_current_msec;

    ngx_quic_cc_bbr1_update_model(c, sample);

    target = ngx_quic_cc_bbr1_target_cwnd(c,
                                          qc->congestion.state.bbr1.bw,
                                          qc->congestion.state.bbr1.cwnd_gain);
    cwnd = qc->congestion.window;

    if (qc->congestion.state.bbr1.full_bw_reached) {
        cwnd = ngx_min(cwnd + sample->acked, target);

    } else if (cwnd < target
               || qc->congestion.delivered < 2 * qc->congestion.window)
    {
        cwnd += sample->acked;
    }

    cwnd = ngx_max(cwnd, 4 * qc->congestion.mtu);

    if (qc->congestion.state.bbr1.mode == NGX_QUIC_BBR_PROBE_RTT) {
        cwnd = ngx_min(cwnd, 4 * qc->congestion.mtu);
    }

    qc->congestion.window = cwnd;
}


static void
ngx_quic_cc_bbr1_loss(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample)
{
    ngx_quic_connection_t  *qc;
    size_t                  floor;

    qc = ngx_quic_get_connection(c);

    if (sample == NULL || sample->lost == 0) {
        return;
    }

    qc->congestion.delivered_time = ngx_current_msec;
    floor = 4 * qc->congestion.mtu;
    qc->congestion.window = ngx_max(qc->congestion.window - sample->lost,
                                    floor);
    qc->congestion.state.bbr1.prior_cwnd =
        ngx_max(qc->congestion.state.bbr1.prior_cwnd,
                qc->congestion.window);
}


static void
ngx_quic_cc_bbr1_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;
    qc->congestion.idle = idle;

    if (idle) {
        b->next_round_delivered = qc->congestion.delivered;
        b->ack_epoch_stamp = ngx_current_msec;
        b->ack_epoch_acked = 0;

        if (b->mode == NGX_QUIC_BBR_PROBE_BW) {
            b->pacing_gain = NGX_QUIC_BBR_UNIT;
            ngx_quic_cc_bbr1_set_pacing_rate(c, b->bw, b->pacing_gain);
        }
    }
}


static ngx_int_t
ngx_quic_cc_bbr1_can_send(ngx_connection_t *c, size_t bytes, ngx_msec_t now,
    ngx_msec_t *delay)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (delay) {
        *delay = 0;
    }

    if (qc->congestion.in_flight + bytes > qc->congestion.window) {
        qc->congestion.app_limited_at = qc->congestion.delivered
                                        + qc->congestion.in_flight;
        return NGX_AGAIN;
    }

    if (qc->congestion.pacing_rate == 0) {
        return NGX_OK;
    }

    if (qc->congestion.next_send > now) {
        if (delay) {
            *delay = qc->congestion.next_send - now;
        }
        return NGX_AGAIN;
    }

    ngx_quic_cc_bbr1_update_pacing(c, bytes, now);

    return NGX_OK;
}


static void
ngx_quic_cc_bbr1_update_model(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *s)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;
    size_t                  extra;
    uint64_t                bw, expected, interval;
    ngx_msec_t              now, rtt;
    ngx_uint_t              expired;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;
    now = ngx_current_msec;

    b->round_start = 0;

    if (s->prior_delivered >= b->next_round_delivered) {
        b->next_round_delivered = qc->congestion.delivered;
        b->round_start = 1;
        qc->congestion.round_start_time = now;
    }

    bw = s->delivery_rate;
    qc->congestion.bw_sample = bw;

    if ((!s->app_limited || bw >= b->bw) && bw > b->bw) {
        b->bw = bw;
    }

    if (b->round_start) {
        b->extra_acked_win_rtts = ngx_min((ngx_uint_t) 31,
                                          b->extra_acked_win_rtts + 1);
        if (b->extra_acked_win_rtts >= NGX_QUIC_BBR_EXTRA_ACKED_WIN) {
            b->extra_acked_win_rtts = 0;
            b->extra_acked_win_idx ^= 1;
            b->extra_acked[b->extra_acked_win_idx] = 0;
        }
    }

    interval = ngx_max((ngx_msec_t) 1, now - b->ack_epoch_stamp);
    expected = b->bw * interval / 1000;

    if (b->ack_epoch_acked <= expected
        || b->ack_epoch_acked + s->acked >= NGX_QUIC_BBR_ACK_EPOCH_RESET)
    {
        b->ack_epoch_acked = 0;
        b->ack_epoch_stamp = now;
        expected = 0;
    }

    b->ack_epoch_acked += s->acked;
    extra = (b->ack_epoch_acked > expected)
            ? (size_t) (b->ack_epoch_acked - expected) : 0;
    extra = ngx_min(extra, qc->congestion.window);

    if (extra > b->extra_acked[b->extra_acked_win_idx]) {
        b->extra_acked[b->extra_acked_win_idx] = extra;
    }

    if (b->round_start && !s->app_limited && !b->full_bw_reached) {
        if (b->full_bw == 0
            || b->bw >= b->full_bw * NGX_QUIC_BBR_FULL_BW_THRESH
                     / NGX_QUIC_BBR_UNIT)
        {
            b->full_bw = b->bw;
            b->full_bw_cnt = 0;

        } else if (++b->full_bw_cnt >= 3) {
            b->full_bw_reached = 1;
        }
    }

    if (b->mode == NGX_QUIC_BBR_STARTUP && b->full_bw_reached) {
        b->mode = NGX_QUIC_BBR_DRAIN;

    } else if (b->mode == NGX_QUIC_BBR_DRAIN
               && qc->congestion.in_flight <=
                  ngx_quic_cc_bbr1_bdp(c, b->bw, NGX_QUIC_BBR_UNIT))
    {
        ngx_quic_cc_bbr1_enter_probe_bw(c);
    }

    if (b->mode == NGX_QUIC_BBR_PROBE_BW
        && ngx_quic_cc_bbr1_next_cycle(c, s))
    {
        b->cycle_idx = (b->cycle_idx + 1) & (NGX_QUIC_BBR_CYCLE_LEN - 1);
        b->cycle_stamp = now;
    }

    rtt = qc->latest_rtt ? qc->latest_rtt : qc->min_rtt;
    expired = (b->min_rtt != NGX_TIMER_INFINITE
               && now - b->min_rtt_stamp > NGX_QUIC_BBR_MIN_RTT_WIN);

    if (rtt && rtt != NGX_TIMER_INFINITE
        && (rtt < b->min_rtt || expired))
    {
        b->min_rtt = rtt;
        b->min_rtt_stamp = now;
        expired = 0;
    }

    if (expired && !qc->congestion.idle
        && b->mode != NGX_QUIC_BBR_PROBE_RTT)
    {
        b->prior_cwnd = qc->congestion.window;
        b->mode = NGX_QUIC_BBR_PROBE_RTT;
        b->probe_rtt_done = 0;
        b->probe_rtt_round_done = 0;
    }

    if (b->mode == NGX_QUIC_BBR_PROBE_RTT) {
        qc->congestion.app_limited_at = qc->congestion.delivered
                                        + qc->congestion.in_flight;

        if (b->probe_rtt_done == 0
            && qc->congestion.in_flight <= 4 * qc->congestion.mtu)
        {
            b->probe_rtt_done = now + NGX_QUIC_BBR_PROBE_RTT_TIME;
            b->probe_rtt_round_done = 0;
            b->next_round_delivered = qc->congestion.delivered;

        } else if (b->probe_rtt_done) {
            if (b->round_start) {
                b->probe_rtt_round_done = 1;
            }

            if (b->probe_rtt_round_done
                && (ngx_msec_int_t) (now - b->probe_rtt_done) >= 0)
            {
                b->min_rtt_stamp = now;
                qc->congestion.window = ngx_max(qc->congestion.window,
                                                b->prior_cwnd);

                if (b->full_bw_reached) {
                    ngx_quic_cc_bbr1_enter_probe_bw(c);
                } else {
                    b->mode = NGX_QUIC_BBR_STARTUP;
                }

                b->probe_rtt_done = 0;
            }
        }
    }

    ngx_quic_cc_bbr1_update_gains(b);
    ngx_quic_cc_bbr1_set_pacing_rate(c, b->bw, b->pacing_gain);
}


static void
ngx_quic_cc_bbr1_update_gains(ngx_quic_bbr1_state_t *b)
{
    static ngx_uint_t  gains[NGX_QUIC_BBR_CYCLE_LEN] = {
        320, 192, 256, 256, 256, 256, 256, 256
    };

    switch (b->mode) {

    case NGX_QUIC_BBR_STARTUP:
        b->pacing_gain = NGX_QUIC_BBR_HIGH_GAIN;
        b->cwnd_gain = NGX_QUIC_BBR_HIGH_GAIN;
        break;

    case NGX_QUIC_BBR_DRAIN:
        b->pacing_gain = NGX_QUIC_BBR_DRAIN_GAIN;
        b->cwnd_gain = NGX_QUIC_BBR_HIGH_GAIN;
        break;

    case NGX_QUIC_BBR_PROBE_BW:
        b->pacing_gain = gains[b->cycle_idx];
        b->cwnd_gain = NGX_QUIC_BBR_CWND_GAIN;
        break;

    case NGX_QUIC_BBR_PROBE_RTT:
        b->pacing_gain = NGX_QUIC_BBR_UNIT;
        b->cwnd_gain = NGX_QUIC_BBR_PROBE_RTT_GAIN;
        break;
    }
}


static void
ngx_quic_cc_bbr1_enter_probe_bw(ngx_connection_t *c)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;

    b->mode = NGX_QUIC_BBR_PROBE_BW;
    b->cycle_idx = (NGX_QUIC_BBR_CYCLE_LEN - 1
                    - (ngx_random() % (NGX_QUIC_BBR_CYCLE_LEN - 1)))
                   & (NGX_QUIC_BBR_CYCLE_LEN - 1);
    b->cycle_idx = (b->cycle_idx + 1) & (NGX_QUIC_BBR_CYCLE_LEN - 1);
    b->cycle_stamp = ngx_current_msec;
}


static ngx_uint_t
ngx_quic_cc_bbr1_next_cycle(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;
    size_t                  inflight, target;
    ngx_msec_t              now, min_rtt;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;
    now = ngx_current_msec;

    min_rtt = (b->min_rtt == NGX_TIMER_INFINITE) ? 1 : b->min_rtt;

    if ((ngx_msec_int_t) (now - b->cycle_stamp) <
        (ngx_msec_int_t) ngx_max((ngx_msec_t) 1, min_rtt))
    {
        return 0;
    }

    if (b->pacing_gain == NGX_QUIC_BBR_UNIT) {
        return 1;
    }

    inflight = qc->congestion.in_flight;

    if (b->pacing_gain > NGX_QUIC_BBR_UNIT) {
        target = ngx_quic_cc_bbr1_bdp(c, b->bw, b->pacing_gain);
        return inflight >= target;
    }

    target = ngx_quic_cc_bbr1_bdp(c, b->bw, NGX_QUIC_BBR_UNIT);

    return inflight <= target || sample->blocked;
}


static size_t
ngx_quic_cc_bbr1_bdp(ngx_connection_t *c, uint64_t bw, ngx_uint_t gain)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;
    uint64_t                rtt, target;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;

    bw = bw ? bw : ((uint64_t) qc->congestion.window * 1000 / 10);
    rtt = (b->min_rtt == NGX_TIMER_INFINITE) ? 10 : b->min_rtt;

    target = bw * rtt / 1000;
    target = target * gain / NGX_QUIC_BBR_UNIT;

    return (size_t) target;
}


static size_t
ngx_quic_cc_bbr1_target_cwnd(ngx_connection_t *c, uint64_t bw, ngx_uint_t gain)
{
    size_t                  target;

    target = ngx_quic_cc_bbr1_bdp(c, bw, gain);
    target += ngx_quic_cc_bbr1_extra_acked(c);

    return ngx_quic_cc_bbr1_quantize(c, target);
}


static size_t
ngx_quic_cc_bbr1_quantize(ngx_connection_t *c, size_t cwnd)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;

    cwnd += 3 * qc->congestion.mtu;
    cwnd = (cwnd + qc->congestion.mtu - 1) / qc->congestion.mtu
           * qc->congestion.mtu;

    if (b->mode == NGX_QUIC_BBR_PROBE_BW && b->cycle_idx == 0) {
        cwnd += 2 * qc->congestion.mtu;
    }

    return ngx_max(cwnd, 4 * qc->congestion.mtu);
}


static size_t
ngx_quic_cc_bbr1_extra_acked(ngx_connection_t *c)
{
    ngx_quic_bbr1_state_t  *b;
    ngx_quic_connection_t  *qc;
    size_t                  extra, cap;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr1;

    if (!b->full_bw_reached || b->bw == 0) {
        return 0;
    }

    extra = ngx_max(b->extra_acked[0], b->extra_acked[1]);
    cap = b->bw * NGX_QUIC_BBR_EXTRA_ACKED_MAX / 1000;

    return ngx_min(extra, cap);
}


static void
ngx_quic_cc_bbr1_set_pacing_rate(ngx_connection_t *c, uint64_t bw,
    ngx_uint_t gain)
{
    ngx_quic_connection_t  *qc;
    uint64_t                rate;

    if (c == NULL) {
        return;
    }

    qc = ngx_quic_get_connection(c);

    bw = bw ? bw : ((uint64_t) qc->congestion.window * 1000 / 10);
    rate = bw * gain / NGX_QUIC_BBR_UNIT;
    rate = rate * (100 - NGX_QUIC_BBR_PACING_MARGIN) / 100;

    if (qc->congestion.state.bbr1.full_bw_reached
        || rate > qc->congestion.pacing_rate)
    {
        qc->congestion.pacing_rate = ngx_max(rate, (uint64_t) 1);
    }
}


static void
ngx_quic_cc_bbr1_update_pacing(ngx_connection_t *c, size_t bytes, ngx_msec_t now)
{
    ngx_quic_connection_t  *qc;
    ngx_msec_t              delta;

    qc = ngx_quic_get_connection(c);

    if (qc->congestion.pacing_rate == 0) {
        return;
    }

    delta = (ngx_msec_t) (((uint64_t) bytes * 1000)
                          / qc->congestion.pacing_rate);

    if (delta == 0) {
        return;
    }

    qc->congestion.next_send = now + delta;
}
