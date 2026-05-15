/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) OpenAI
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BBR_UNIT              256
#define NGX_QUIC_BBR_STARTUP_GAIN      710
#define NGX_QUIC_BBR_DRAIN_GAIN        89
#define NGX_QUIC_BBR_CWND_GAIN         512
#define NGX_QUIC_BBR_PROBE_RTT_GAIN    128
#define NGX_QUIC_BBR_FULL_BW_THRESH    320
#define NGX_QUIC_BBR_MIN_RTT_WIN       10000
#define NGX_QUIC_BBR_PROBE_RTT_TIME    200
#define NGX_QUIC_BBR_ACK_EPOCH_RESET   (1 << 20)
#define NGX_QUIC_BBR_EXTRA_ACKED_WIN   5
#define NGX_QUIC_BBR_EXTRA_ACKED_MAX   100
#define NGX_QUIC_BBR_PROBE_WAIT        2000
#define NGX_QUIC_BBR_BETA              77
#define NGX_QUIC_BBR_LOSS_THRESH       5
#define NGX_QUIC_BBR_HEADROOM          38
#define NGX_QUIC_BBR_PACING_MARGIN     1


static void ngx_quic_cc_bbr_reset(ngx_quic_connection_t *qc);
static void ngx_quic_cc_bbr_ack(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static void ngx_quic_cc_bbr_loss(ngx_connection_t *c,
    ngx_quic_cc_loss_sample_t *sample);
static void ngx_quic_cc_bbr_idle(ngx_connection_t *c, ngx_uint_t idle);
static ngx_int_t ngx_quic_cc_bbr_can_send(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now, ngx_msec_t *delay);
static void ngx_quic_cc_bbr_update_model(ngx_connection_t *c,
    ngx_quic_cc_ack_sample_t *sample);
static void ngx_quic_cc_bbr_update_gains(ngx_quic_bbr_state_t *b);
static void ngx_quic_cc_bbr_enter_probe_bw(ngx_connection_t *c);
static void ngx_quic_cc_bbr_start_probe_refill(ngx_connection_t *c);
static void ngx_quic_cc_bbr_start_probe_up(ngx_connection_t *c);
static void ngx_quic_cc_bbr_start_probe_down(ngx_connection_t *c);
static void ngx_quic_cc_bbr_start_probe_cruise(ngx_connection_t *c);
static void ngx_quic_cc_bbr_reset_lower_bounds(ngx_quic_bbr_state_t *b);
static void ngx_quic_cc_bbr_bound_cwnd(ngx_connection_t *c);
static size_t ngx_quic_cc_bbr_bdp(ngx_connection_t *c, uint64_t bw,
    ngx_uint_t gain);
static size_t ngx_quic_cc_bbr_target_cwnd(ngx_connection_t *c,
    uint64_t bw, ngx_uint_t gain);
static size_t ngx_quic_cc_bbr_quantize(ngx_connection_t *c, size_t cwnd);
static size_t ngx_quic_cc_bbr_extra_acked(ngx_connection_t *c);
static size_t ngx_quic_cc_bbr_inflight_headroom(ngx_connection_t *c);
static uint64_t ngx_quic_cc_bbr_bw(ngx_connection_t *c);
static void ngx_quic_cc_bbr_set_pacing_rate(ngx_connection_t *c, uint64_t bw,
    ngx_uint_t gain);
static void ngx_quic_cc_bbr_update_pacing(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now);


ngx_quic_cc_ops_t  ngx_quic_cc_bbr_ops = {
    ngx_quic_cc_bbr_reset,
    ngx_quic_cc_bbr_ack,
    ngx_quic_cc_bbr_loss,
    ngx_quic_cc_bbr_idle,
    ngx_quic_cc_bbr_can_send
};


static void
ngx_quic_cc_bbr_reset(ngx_quic_connection_t *qc)
{
    ngx_quic_bbr_state_t  *b;

    b = &qc->congestion.state.bbr;

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
    b->bw_lo = (uint64_t) -1;
    b->bw_hi = 0;
    b->full_bw = 0;
    b->next_round_delivered = 0;
    b->ack_epoch_acked = 0;
    b->extra_acked[0] = 0;
    b->extra_acked[1] = 0;
    b->inflight_lo = (size_t) -1;
    b->inflight_hi = (size_t) -1;
    b->prior_cwnd = qc->congestion.window;
    b->min_rtt = NGX_TIMER_INFINITE;
    b->min_rtt_stamp = ngx_current_msec;
    b->probe_rtt_done = 0;
    b->cycle_stamp = ngx_current_msec;
    b->ack_epoch_stamp = ngx_current_msec;
    b->probe_wait = NGX_QUIC_BBR_PROBE_WAIT;
    b->mode = NGX_QUIC_BBR_STARTUP;
    b->phase = NGX_QUIC_BBR_PHASE_REFILL;
    b->full_bw_cnt = 0;
    b->round_start = 0;
    b->full_bw_reached = 0;
    b->full_bw_now = 0;
    b->probe_rtt_round_done = 0;
    b->extra_acked_win_idx = 0;
    b->extra_acked_win_rtts = 0;
    b->prev_probe_too_high = 0;
    b->bw_probe_samples = 0;
    b->probe_rounds = 0;
    b->pacing_gain = NGX_QUIC_BBR_STARTUP_GAIN;
    b->cwnd_gain = NGX_QUIC_BBR_CWND_GAIN;
}


static void
ngx_quic_cc_bbr_ack(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 target, cwnd;
    uint64_t               bw;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    if (sample == NULL || sample->acked == 0) {
        return;
    }

    qc->congestion.delivered += sample->acked;
    qc->congestion.delivered_time = ngx_current_msec;

    ngx_quic_cc_bbr_update_model(c, sample);
    ngx_quic_cc_bbr_update_gains(b);

    bw = ngx_quic_cc_bbr_bw(c);
    ngx_quic_cc_bbr_set_pacing_rate(c, bw, b->pacing_gain);

    target = ngx_quic_cc_bbr_target_cwnd(c, bw, b->cwnd_gain);
    cwnd = qc->congestion.window;

    if (b->full_bw_reached) {
        cwnd += sample->acked;
        if (cwnd >= target) {
            cwnd = target;
        }

    } else if (cwnd < target
               || qc->congestion.delivered < 2 * qc->congestion.window)
    {
        cwnd += sample->acked;
    }

    cwnd = ngx_max(cwnd, 4 * qc->congestion.mtu);

    if (b->mode == NGX_QUIC_BBR_PROBE_RTT) {
        cwnd = ngx_min(cwnd, ngx_quic_cc_bbr_target_cwnd(c, bw,
                                           NGX_QUIC_BBR_PROBE_RTT_GAIN));
    }

    qc->congestion.window = ngx_max(cwnd, 4 * qc->congestion.mtu);
    ngx_quic_cc_bbr_bound_cwnd(c);
}


static void
ngx_quic_cc_bbr_loss(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 floor, loss_thresh, tx_in_flight;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    if (sample == NULL || sample->lost == 0) {
        return;
    }

    qc->congestion.delivered_time = ngx_current_msec;

    floor = 4 * qc->congestion.mtu;

    tx_in_flight = sample->tx_in_flight ? sample->tx_in_flight
                                        : qc->congestion.window;
    loss_thresh = ngx_max((size_t) 1,
                          tx_in_flight * NGX_QUIC_BBR_LOSS_THRESH
                          / NGX_QUIC_BBR_UNIT);

    if (sample->lost > loss_thresh) {
        if (b->mode == NGX_QUIC_BBR_PROBE_BW
            && b->phase == NGX_QUIC_BBR_PHASE_UP
            && b->bw_probe_samples)
        {
            b->prev_probe_too_high = 1;
            b->bw_probe_samples = 0;

            if (!b->inflight_hi || b->inflight_hi == (size_t) -1
                || tx_in_flight < b->inflight_hi)
            {
                b->inflight_hi = ngx_max(tx_in_flight, floor);
            }

            b->inflight_hi = ngx_max(floor,
                b->inflight_hi * (NGX_QUIC_BBR_UNIT - NGX_QUIC_BBR_BETA)
                / NGX_QUIC_BBR_UNIT);

            ngx_quic_cc_bbr_start_probe_down(c);

        } else if (b->mode != NGX_QUIC_BBR_PROBE_BW) {
            if (b->inflight_lo == (size_t) -1) {
                b->inflight_lo = qc->congestion.window;
            }

            b->inflight_lo = ngx_max(floor,
                b->inflight_lo * (NGX_QUIC_BBR_UNIT - NGX_QUIC_BBR_BETA)
                / NGX_QUIC_BBR_UNIT);

            if (b->bw_lo == (uint64_t) -1) {
                b->bw_lo = ngx_max(ngx_quic_cc_bbr_bw(c), (uint64_t) 1);
            }

            b->bw_lo = ngx_max((uint64_t) 1,
                b->bw_lo * (NGX_QUIC_BBR_UNIT - NGX_QUIC_BBR_BETA)
                / NGX_QUIC_BBR_UNIT);
        }
    }

    qc->congestion.window = ngx_max(qc->congestion.window - sample->lost,
                                    floor);
    ngx_quic_cc_bbr_bound_cwnd(c);
}


static void
ngx_quic_cc_bbr_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;
    qc->congestion.idle = idle;

    if (idle) {
        b->next_round_delivered = qc->congestion.delivered;
        b->ack_epoch_stamp = ngx_current_msec;
        b->ack_epoch_acked = 0;

        if (b->mode == NGX_QUIC_BBR_PROBE_BW) {
            b->pacing_gain = NGX_QUIC_BBR_UNIT;
            ngx_quic_cc_bbr_set_pacing_rate(c, ngx_quic_cc_bbr_bw(c),
                                            NGX_QUIC_BBR_UNIT);
        }
    }
}


static ngx_int_t
ngx_quic_cc_bbr_can_send(ngx_connection_t *c, size_t bytes, ngx_msec_t now,
    ngx_msec_t *delay)
{
    ngx_quic_connection_t *qc;

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

    ngx_quic_cc_bbr_update_pacing(c, bytes, now);

    return NGX_OK;
}


static void
ngx_quic_cc_bbr_update_model(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *s)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 extra, inflight, cruise;
    uint64_t               bw, expected, interval;
    ngx_msec_t             now, rtt;
    ngx_uint_t             expired;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;
    now = ngx_current_msec;

    b->round_start = 0;

    if (s->prior_delivered >= b->next_round_delivered) {
        b->next_round_delivered = qc->congestion.delivered;
        b->round_start = 1;
        qc->congestion.round_start_time = now;

        if (b->probe_rounds < 0xff) {
            b->probe_rounds++;
        }
    }

    bw = s->delivery_rate;
    qc->congestion.bw_sample = bw;

    if ((!s->app_limited || bw >= b->bw) && bw > b->bw) {
        b->bw = bw;
    }

    if (b->bw_hi < b->bw) {
        b->bw_hi = b->bw;
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
    expected = ngx_quic_cc_bbr_bw(c) * interval / 1000;

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

    b->full_bw_now = 0;

    if (!s->app_limited) {
        if (b->full_bw == 0
            || bw >= b->full_bw * NGX_QUIC_BBR_FULL_BW_THRESH
                     / NGX_QUIC_BBR_UNIT)
        {
            b->full_bw = bw;
            b->full_bw_cnt = 0;

        } else if (b->round_start) {
            b->full_bw_cnt++;
            b->full_bw_now = (b->full_bw_cnt >= 3);
            b->full_bw_reached |= b->full_bw_now;
        }
    }

    if (b->mode == NGX_QUIC_BBR_STARTUP && b->full_bw_reached) {
        b->mode = NGX_QUIC_BBR_DRAIN;

    } else if (b->mode == NGX_QUIC_BBR_DRAIN
               && qc->congestion.in_flight <=
                  ngx_quic_cc_bbr_bdp(c, ngx_quic_cc_bbr_bw(c),
                                      NGX_QUIC_BBR_UNIT))
    {
        ngx_quic_cc_bbr_enter_probe_bw(c);
    }

    if (b->mode == NGX_QUIC_BBR_PROBE_BW) {
        inflight = qc->congestion.in_flight;

        switch (b->phase) {

        case NGX_QUIC_BBR_PHASE_CRUISE:
            if ((ngx_msec_int_t) (now - b->cycle_stamp) >=
                (ngx_msec_int_t) b->probe_wait)
            {
                ngx_quic_cc_bbr_start_probe_refill(c);
            }
            break;

        case NGX_QUIC_BBR_PHASE_REFILL:
            if (b->round_start) {
                b->bw_probe_samples = 1;
                ngx_quic_cc_bbr_start_probe_up(c);
            }
            break;

        case NGX_QUIC_BBR_PHASE_UP:
            if (b->inflight_hi != (size_t) -1
                && inflight > b->inflight_hi)
            {
                b->inflight_hi = inflight;
            }

            if ((b->prev_probe_too_high
                 && b->inflight_hi != (size_t) -1
                 && inflight >= b->inflight_hi)
                || b->full_bw_now)
            {
                b->prev_probe_too_high = 0;
                ngx_quic_cc_bbr_start_probe_down(c);
            }
            break;

        case NGX_QUIC_BBR_PHASE_DOWN:
            if ((ngx_msec_int_t) (now - b->cycle_stamp) >=
                (ngx_msec_int_t) b->probe_wait)
            {
                ngx_quic_cc_bbr_start_probe_refill(c);
                break;
            }

            cruise = ngx_min(ngx_quic_cc_bbr_inflight_headroom(c),
                             ngx_quic_cc_bbr_bdp(c, ngx_quic_cc_bbr_bw(c),
                                                 NGX_QUIC_BBR_UNIT));
            if (inflight <= cruise) {
                ngx_quic_cc_bbr_start_probe_cruise(c);
            }
            break;
        }
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
            && qc->congestion.in_flight <=
               ngx_quic_cc_bbr_target_cwnd(c, ngx_quic_cc_bbr_bw(c),
                                           NGX_QUIC_BBR_PROBE_RTT_GAIN))
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
                ngx_quic_cc_bbr_reset_lower_bounds(b);

                if (b->full_bw_reached) {
                    ngx_quic_cc_bbr_enter_probe_bw(c);
                    ngx_quic_cc_bbr_start_probe_down(c);
                    ngx_quic_cc_bbr_start_probe_cruise(c);
                } else {
                    b->mode = NGX_QUIC_BBR_STARTUP;
                }

                b->probe_rtt_done = 0;
            }
        }
    }
}


static void
ngx_quic_cc_bbr_update_gains(ngx_quic_bbr_state_t *b)
{
    switch (b->mode) {

    case NGX_QUIC_BBR_STARTUP:
        b->pacing_gain = NGX_QUIC_BBR_STARTUP_GAIN;
        b->cwnd_gain = NGX_QUIC_BBR_CWND_GAIN;
        break;

    case NGX_QUIC_BBR_DRAIN:
        b->pacing_gain = NGX_QUIC_BBR_DRAIN_GAIN;
        b->cwnd_gain = NGX_QUIC_BBR_CWND_GAIN;
        break;

    case NGX_QUIC_BBR_PROBE_BW:
        switch (b->phase) {
        case NGX_QUIC_BBR_PHASE_UP:
            b->pacing_gain = 320;
            break;
        case NGX_QUIC_BBR_PHASE_DOWN:
            b->pacing_gain = 233;
            break;
        case NGX_QUIC_BBR_PHASE_CRUISE:
        case NGX_QUIC_BBR_PHASE_REFILL:
        default:
            b->pacing_gain = NGX_QUIC_BBR_UNIT;
            break;
        }

        b->cwnd_gain = NGX_QUIC_BBR_CWND_GAIN;
        if (b->phase == NGX_QUIC_BBR_PHASE_UP) {
            b->cwnd_gain += NGX_QUIC_BBR_UNIT / 4;
        }
        break;

    case NGX_QUIC_BBR_PROBE_RTT:
        b->pacing_gain = NGX_QUIC_BBR_UNIT;
        b->cwnd_gain = NGX_QUIC_BBR_PROBE_RTT_GAIN;
        break;
    }
}


static void
ngx_quic_cc_bbr_enter_probe_bw(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    b->mode = NGX_QUIC_BBR_PROBE_BW;
    ngx_quic_cc_bbr_start_probe_down(c);
}


static void
ngx_quic_cc_bbr_start_probe_refill(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    b->bw_probe_samples = 0;
    b->prev_probe_too_high = 0;
    b->probe_rounds = 0;
    ngx_quic_cc_bbr_reset_lower_bounds(b);
    b->phase = NGX_QUIC_BBR_PHASE_REFILL;
    b->cycle_stamp = ngx_current_msec;
    b->next_round_delivered = qc->congestion.delivered;
}


static void
ngx_quic_cc_bbr_start_probe_up(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    b->phase = NGX_QUIC_BBR_PHASE_UP;
    b->cycle_stamp = ngx_current_msec;
    b->full_bw = qc->congestion.bw_sample;
    b->full_bw_cnt = 0;
    b->full_bw_now = 0;

    if (b->inflight_hi != (size_t) -1) {
        b->inflight_hi += ngx_max(qc->congestion.mtu,
                                  b->inflight_hi / 4);
    }
}


static void
ngx_quic_cc_bbr_start_probe_down(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    b->phase = NGX_QUIC_BBR_PHASE_DOWN;
    b->cycle_stamp = ngx_current_msec;
    b->probe_wait = NGX_QUIC_BBR_PROBE_WAIT;
    b->bw_probe_samples = 0;
    b->next_round_delivered = qc->congestion.delivered;
}


static void
ngx_quic_cc_bbr_start_probe_cruise(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    if (b->inflight_lo != (size_t) -1 && b->inflight_hi != (size_t) -1) {
        b->inflight_lo = ngx_min(b->inflight_lo, b->inflight_hi);
    }

    b->phase = NGX_QUIC_BBR_PHASE_CRUISE;
    b->cycle_stamp = ngx_current_msec;
}


static void
ngx_quic_cc_bbr_reset_lower_bounds(ngx_quic_bbr_state_t *b)
{
    b->bw_lo = (uint64_t) -1;
    b->inflight_lo = (size_t) -1;
}


static void
ngx_quic_cc_bbr_bound_cwnd(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 cap, floor;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    cap = (size_t) -1;
    floor = 4 * qc->congestion.mtu;

    if (b->mode == NGX_QUIC_BBR_PROBE_BW
        && b->phase != NGX_QUIC_BBR_PHASE_CRUISE)
    {
        cap = b->inflight_hi;

    } else if (b->mode == NGX_QUIC_BBR_PROBE_RTT
               || (b->mode == NGX_QUIC_BBR_PROBE_BW
                   && b->phase == NGX_QUIC_BBR_PHASE_CRUISE))
    {
        cap = ngx_quic_cc_bbr_inflight_headroom(c);
    }

    if (b->inflight_lo != (size_t) -1 && b->inflight_lo < cap) {
        cap = b->inflight_lo;
    }

    if (cap == (size_t) -1) {
        return;
    }

    qc->congestion.window = ngx_min(qc->congestion.window,
                                    ngx_max(cap, floor));
}


static size_t
ngx_quic_cc_bbr_bdp(ngx_connection_t *c, uint64_t bw, ngx_uint_t gain)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    uint64_t               rtt, target;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    bw = bw ? bw : ((uint64_t) qc->congestion.window * 1000 / 10);
    rtt = (b->min_rtt == NGX_TIMER_INFINITE) ? 10 : b->min_rtt;

    target = bw * rtt / 1000;
    target = target * gain / NGX_QUIC_BBR_UNIT;

    return (size_t) target;
}


static size_t
ngx_quic_cc_bbr_target_cwnd(ngx_connection_t *c, uint64_t bw, ngx_uint_t gain)
{
    size_t                 target;

    target = ngx_quic_cc_bbr_bdp(c, bw, gain);
    target += ngx_quic_cc_bbr_extra_acked(c);
    target = ngx_quic_cc_bbr_quantize(c, target);

    return target;
}


static size_t
ngx_quic_cc_bbr_quantize(ngx_connection_t *c, size_t cwnd)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    cwnd = ngx_max(cwnd, 3 * qc->congestion.mtu);
    cwnd = (cwnd + qc->congestion.mtu - 1) / qc->congestion.mtu
           * qc->congestion.mtu;

    if (b->mode == NGX_QUIC_BBR_PROBE_BW
        && b->phase == NGX_QUIC_BBR_PHASE_UP)
    {
        cwnd += 2 * qc->congestion.mtu;
    }

    return ngx_max(cwnd, 4 * qc->congestion.mtu);
}


static size_t
ngx_quic_cc_bbr_extra_acked(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 extra, cap;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    if (b->bw == 0) {
        return 0;
    }

    extra = ngx_max(b->extra_acked[0], b->extra_acked[1]);
    cap = ngx_quic_cc_bbr_bw(c) * NGX_QUIC_BBR_EXTRA_ACKED_MAX / 1000;

    return ngx_min(extra, cap);
}


static size_t
ngx_quic_cc_bbr_inflight_headroom(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;
    ngx_quic_connection_t *qc;
    size_t                 headroom;

    qc = ngx_quic_get_connection(c);
    b = &qc->congestion.state.bbr;

    if (b->inflight_hi == (size_t) -1) {
        return ngx_quic_cc_bbr_bdp(c, ngx_quic_cc_bbr_bw(c),
                                  NGX_QUIC_BBR_UNIT);
    }

    headroom = b->inflight_hi * NGX_QUIC_BBR_HEADROOM / NGX_QUIC_BBR_UNIT;

    return ngx_max(4 * qc->congestion.mtu, b->inflight_hi - headroom);
}


static uint64_t
ngx_quic_cc_bbr_bw(ngx_connection_t *c)
{
    ngx_quic_bbr_state_t  *b;

    b = &ngx_quic_get_connection(c)->congestion.state.bbr;

    if (b->bw_lo != (uint64_t) -1) {
        return ngx_min(b->bw, b->bw_lo);
    }

    return b->bw_hi ? ngx_min(b->bw, b->bw_hi) : b->bw;
}


static void
ngx_quic_cc_bbr_set_pacing_rate(ngx_connection_t *c, uint64_t bw,
    ngx_uint_t gain)
{
    ngx_quic_connection_t *qc;
    uint64_t              rate;

    qc = ngx_quic_get_connection(c);

    bw = bw ? bw : ((uint64_t) qc->congestion.window * 1000 / 10);
    rate = bw * gain / NGX_QUIC_BBR_UNIT;
    rate = rate * (100 - NGX_QUIC_BBR_PACING_MARGIN) / 100;

    if (qc->congestion.state.bbr.full_bw_reached
        || rate > qc->congestion.pacing_rate)
    {
        qc->congestion.pacing_rate = ngx_max(rate, (uint64_t) 1);
    }
}


static void
ngx_quic_cc_bbr_update_pacing(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now)
{
    ngx_quic_connection_t *qc;
    ngx_msec_t            delta;

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
