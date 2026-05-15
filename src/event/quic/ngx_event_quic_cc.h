/*
 * Copyright (C) 2026 Web Server LLC
 * Copyright (C) OpenAI
 */


#ifndef _NGX_EVENT_QUIC_CC_H_INCLUDED_
#define _NGX_EVENT_QUIC_CC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_quic_packet_s              ngx_quic_packet_t;
typedef struct ngx_quic_cc_ops_s             ngx_quic_cc_ops_t;
typedef struct ngx_quic_cc_ack_sample_s      ngx_quic_cc_ack_sample_t;
typedef struct ngx_quic_cc_loss_sample_s     ngx_quic_cc_loss_sample_t;
typedef struct ngx_quic_bbr1_state_s         ngx_quic_bbr1_state_t;
typedef struct ngx_quic_bbr_state_s          ngx_quic_bbr_state_t;


typedef enum {
    NGX_QUIC_BBR_STARTUP = 0,
    NGX_QUIC_BBR_DRAIN,
    NGX_QUIC_BBR_PROBE_BW,
    NGX_QUIC_BBR_PROBE_RTT
} ngx_quic_bbr_mode_e;


typedef enum {
    NGX_QUIC_BBR_PHASE_REFILL = 0,
    NGX_QUIC_BBR_PHASE_UP,
    NGX_QUIC_BBR_PHASE_DOWN,
    NGX_QUIC_BBR_PHASE_CRUISE
} ngx_quic_bbr_phase_e;


struct ngx_quic_bbr1_state_s {
    uint64_t              bw;
    uint64_t              full_bw;
    uint64_t              next_round_delivered;
    uint64_t              ack_epoch_acked;
    size_t                extra_acked[2];
    size_t                prior_cwnd;
    ngx_msec_t            min_rtt;
    ngx_msec_t            min_rtt_stamp;
    ngx_msec_t            probe_rtt_done;
    ngx_msec_t            cycle_stamp;
    ngx_msec_t            ack_epoch_stamp;
    ngx_uint_t            mode;
    ngx_uint_t            cycle_idx;
    ngx_uint_t            full_bw_cnt;
    ngx_uint_t            round_start;
    ngx_uint_t            full_bw_reached;
    ngx_uint_t            probe_rtt_round_done;
    ngx_uint_t            extra_acked_win_idx;
    ngx_uint_t            extra_acked_win_rtts;
    ngx_uint_t            pacing_gain;
    ngx_uint_t            cwnd_gain;
};


struct ngx_quic_bbr_state_s {
    uint64_t              bw;
    uint64_t              bw_lo;
    uint64_t              bw_hi;
    uint64_t              full_bw;
    uint64_t              next_round_delivered;
    uint64_t              ack_epoch_acked;
    size_t                extra_acked[2];
    size_t                inflight_lo;
    size_t                inflight_hi;
    size_t                prior_cwnd;
    ngx_msec_t            min_rtt;
    ngx_msec_t            min_rtt_stamp;
    ngx_msec_t            probe_rtt_done;
    ngx_msec_t            cycle_stamp;
    ngx_msec_t            ack_epoch_stamp;
    ngx_msec_t            probe_wait;
    ngx_uint_t            mode;
    ngx_uint_t            phase;
    ngx_uint_t            full_bw_cnt;
    ngx_uint_t            round_start;
    ngx_uint_t            full_bw_reached;
    ngx_uint_t            full_bw_now;
    ngx_uint_t            probe_rtt_round_done;
    ngx_uint_t            extra_acked_win_idx;
    ngx_uint_t            extra_acked_win_rtts;
    ngx_uint_t            prev_probe_too_high;
    ngx_uint_t            bw_probe_samples;
    ngx_uint_t            probe_rounds;
    ngx_uint_t            pacing_gain;
    ngx_uint_t            cwnd_gain;
};


struct ngx_quic_cc_ack_sample_s {
    ngx_quic_packet_t    *pkt;
    size_t                acked;
    uint64_t              prior_delivered;
    ngx_msec_t            prior_time;
    size_t                tx_in_flight;
    ngx_uint_t            npackets;
    ngx_msec_t            interval;
    ngx_msec_t            send_elapsed;
    uint64_t              delivery_rate;
    ngx_uint_t            blocked;
    ngx_uint_t            app_limited;
};


struct ngx_quic_cc_loss_sample_s {
    ngx_quic_packet_t    *pkt;
    size_t                lost;
    size_t                tx_in_flight;
    ngx_uint_t            blocked;
};


struct ngx_quic_cc_ops_s {
    void (*reset)(ngx_quic_connection_t *qc);
    void (*on_ack)(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample);
    void (*on_loss)(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample);
    void (*on_idle)(ngx_connection_t *c, ngx_uint_t idle);
    ngx_int_t (*can_send)(ngx_connection_t *c, size_t bytes, ngx_msec_t now,
        ngx_msec_t *delay);
};


void ngx_quic_cc_reset(ngx_quic_connection_t *qc);
void ngx_quic_cc_ack(ngx_connection_t *c, ngx_quic_cc_ack_sample_t *sample);
void ngx_quic_cc_loss(ngx_connection_t *c, ngx_quic_cc_loss_sample_t *sample);
void ngx_quic_cc_idle(ngx_connection_t *c, ngx_uint_t idle);
ngx_int_t ngx_quic_cc_can_send(ngx_connection_t *c, size_t bytes,
    ngx_msec_t now, ngx_msec_t *delay);
void ngx_quic_cc_remove_in_flight(ngx_connection_t *c, ngx_quic_packet_t *pkt);

ngx_quic_packet_t *ngx_quic_alloc_packet(ngx_connection_t *c);
void ngx_quic_free_packet(ngx_connection_t *c, ngx_quic_packet_t *pkt);
void ngx_quic_free_packets(ngx_connection_t *c, ngx_queue_t *packets);


#endif /* _NGX_EVENT_QUIC_CC_H_INCLUDED_ */
