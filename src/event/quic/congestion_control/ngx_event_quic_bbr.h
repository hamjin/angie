/*
 * Copyright (C) 2026 Web Server LLC
 */


#ifndef _NGX_EVENT_QUIC_BBR_H_INCLUDED_
#define _NGX_EVENT_QUIC_BBR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_cc.h>


#define NGX_QUIC_BBR_SCALE                  8
#define NGX_QUIC_BBR_UNIT                   (1 << NGX_QUIC_BBR_SCALE)
#define NGX_QUIC_BBR_MS_PER_SEC             1000


typedef enum {
    NGX_QUIC_BBR_PROFILE_DEFAULT = 0,
    NGX_QUIC_BBR_PROFILE_GOOGLE,
    NGX_QUIC_BBR_PROFILE_SING,
    NGX_QUIC_BBR_PROFILE_HY2
} ngx_quic_bbr_profile_e;


/*
 * BBR configuration struct.
 * version=1: BBRv1 uses v1_params only; v3_params are NGX_CONF_UNSET.
 * version=3: BBRv3 uses v3_params; v1-only params are ignored.
 */
typedef struct {
    ngx_uint_t  version;        /* 1 or 3, default 1 */
    ngx_uint_t  profile;
    uint64_t    set;            /* parameters set by conf_handler */

    /* --- v1 parameters --- */
    ngx_int_t   high_gain;
    ngx_int_t   drain_gain;
    ngx_int_t   cwnd_gain;
    ngx_int_t   pacing_margin_percent;
    ngx_int_t   min_rtt_win_sec;
    ngx_msec_t  probe_rtt_mode_ms;
    ngx_int_t   min_tso_rate;
    ngx_int_t   cwnd_min_target;
    ngx_int_t   full_bw_thresh;
    ngx_int_t   full_bw_cnt;
    ngx_int_t   bw_rtts;
    ngx_int_t   cycle_rand;
    ngx_int_t   lt_intvl_min_rtts;
    ngx_int_t   lt_loss_thresh;
    ngx_int_t   lt_bw_ratio;
    ngx_int_t   lt_bw_diff;
    ngx_int_t   lt_bw_max_rtts;
    ngx_int_t   extra_acked_gain;
    ngx_int_t   extra_acked_win_rtts;
    ngx_int_t   ack_epoch_acked_reset_thresh;
    ngx_int_t   extra_acked_max_us;

    ngx_int_t   startup_cwnd_gain;
    ngx_int_t   initial_cwnd_packets;
    ngx_int_t   max_cwnd_packets;
    ngx_flag_t  drain_to_target;
    ngx_flag_t  detect_overshooting;
    ngx_flag_t  enable_ack_aggregation_startup;
    ngx_flag_t  expire_ack_aggregation_startup;
    ngx_flag_t  overestimate_avoidance;
    ngx_int_t   num_startup_rtts;
    ngx_int_t   bytes_lost_multiplier;
    ngx_int_t   max_ack_height_tracker_window_multiplier;
    ngx_flag_t  use_derived_high_gain;
    ngx_flag_t  start_new_aggregation_epoch_after_full_round;
    ngx_flag_t  limit_max_ack_height_tracker_by_send_rate;
    ngx_flag_t  exit_startup_on_loss;
    ngx_flag_t  exit_startup_on_loss_even_if_app_limited;
    ngx_flag_t  reduce_extra_acked_on_bandwidth_increase;

    /* --- v3 parameters (reserved, used only when version=3) --- */
    ngx_int_t   startup_pacing_gain;
    ngx_int_t   beta;
    ngx_int_t   loss_thresh;
    ngx_int_t   ecn_factor;
    ngx_int_t   ecn_thresh;
    ngx_int_t   ecn_alpha_gain;
    ngx_int_t   ecn_alpha_init;
    ngx_int_t   ecn_max_rtt_us;
    ngx_int_t   ecn_reprobe_gain;
    ngx_int_t   full_loss_cnt;
    ngx_int_t   full_ecn_cnt;
    ngx_int_t   inflight_headroom;
    ngx_int_t   bw_probe_max_rounds;
    ngx_int_t   bw_probe_rand_rounds;
    ngx_int_t   bw_probe_base_us;
    ngx_int_t   bw_probe_rand_us;
    ngx_int_t   bw_probe_cwnd_gain;
    ngx_int_t   probe_rtt_win_ms;
    ngx_int_t   probe_rtt_cwnd_gain;
    ngx_int_t   tso_rtt_shift;
    ngx_flag_t  fast_path;
    ngx_flag_t  fast_ack_mode;
    ngx_flag_t  precise_ece_ack;
    ngx_flag_t  loss_probe_recovery;
} ngx_quic_bbr_conf_t;


/*
 * Per-connection BBR algorithm private state.
 * Allocated in ngx_quic_bbr_reset() via ngx_alloc,
 * stored in ngx_quic_congestion_t.cc_priv.
 * Access pattern: container_of(cg->cc_priv, ngx_quic_bbr_state_t, base)
 */
typedef struct {
    ngx_quic_cc_priv_t  base;  /* must be first; type = NGX_QUIC_CC_BBR */
    ngx_uint_t          version; /* cached from conf; 1 or 3 */

    /* --- state machine --- */
    ngx_uint_t        mode;
    ngx_uint_t        prev_mode;
    ngx_uint_t        cycle_idx;
    ngx_uint_t        round_start;
    ngx_uint_t        full_bw_reached;
    ngx_uint_t        full_bw_cnt;
    ngx_uint_t        packet_conservation;
    ngx_uint_t        probe_rtt_round_done;

    /* --- long-term sampling --- */
    ngx_uint_t        lt_is_sampling;
    ngx_uint_t        lt_use_bw;
    ngx_uint_t        lt_rtt_cnt;

    /* --- RTT tracking --- */
    ngx_msec_t        min_rtt;
    ngx_msec_t        min_rtt_stamp;
    ngx_msec_t        probe_rtt_done_stamp;
    ngx_msec_t        cycle_stamp;

    /* --- delivery rate --- */
    uint64_t          ack_epoch_stamp;
    uint64_t          first_sent_time;
    uint64_t          delivered;
    uint64_t          delivered_time;
    uint64_t          next_round_delivered;
    uint64_t          rtt_cnt;

    /* --- bandwidth filter --- */
    uint64_t          bw[16];
    uint64_t          bw_stamp[16];
    uint64_t          lt_bw;
    uint64_t          lt_last_delivered;
    uint64_t          lt_last_stamp;
    uint64_t          lt_last_lost;

    /* --- loss accounting --- */
    uint64_t          lost;
    uint64_t          loss_in_round;
    uint64_t          startup_loss_in_round;

    /* --- recovery --- */
    uint64_t          recovery_delivered;
    uint64_t          recovery_pnum;
    uint64_t          recovery_window;
    uint64_t          congestion_window;

    /* --- pacing --- */
    uint64_t          full_bw;
    uint64_t          pacing_rate;
    uint64_t          pacing_debt;
    uint64_t          next_send_time;
    uint64_t          prior_cwnd;

    /* --- ACK aggregation --- */
    uint64_t          ack_epoch_acked;
    uint64_t          last_sent_pnum;
    uint64_t          ack_epoch_last_sent_pnum;
    uint64_t          extra_acked[2];
    ngx_uint_t        extra_acked_win_idx;
    ngx_uint_t        extra_acked_win_rtts;
    ngx_uint_t        loss_events_in_round;

    /* --- gain --- */
    ngx_uint_t        pacing_gain;
    ngx_uint_t        cwnd_gain;

    /* --- v3 reserved fields (used only when version=3) --- */
    uint64_t          bw_latest;
    uint64_t          bw_lo;
    uint64_t          bw_hi[2];
    uint64_t          inflight_latest;
    uint64_t          inflight_lo;
    uint64_t          inflight_hi;
    uint64_t          bw_probe_up_cnt;
    uint64_t          bw_probe_up_acks;
    uint64_t          probe_wait_us;
    uint64_t          loss_round_delivered;
    uint64_t          undo_bw_lo;
    uint64_t          undo_inflight_lo;
    uint64_t          undo_inflight_hi;
    uint64_t          alpha_last_delivered;
    uint64_t          alpha_last_delivered_ce;
    uint64_t          delivered_ce;         /* cumulative CE-marked bytes */
    uint64_t          last_ce_counter;      /* last ACK_ECN ce counter value */
    ngx_uint_t        bw_probe_up_rounds;
    ngx_uint_t        bw_probe_samples;
    ngx_uint_t        prev_probe_too_high;
    ngx_uint_t        stopped_risky_probe;
    ngx_uint_t        rounds_since_probe;
    ngx_uint_t        ack_phase;
    ngx_uint_t        try_fast_path;
    ngx_uint_t        idle_restart;      /* set when resuming from idle */
    ngx_uint_t        ecn_eligible;
    ngx_uint_t        ecn_alpha;
    ngx_uint_t        ecn_in_round;
    ngx_uint_t        ecn_in_cycle;
    ngx_uint_t        startup_ecn_rounds;
    ngx_uint_t        loss_in_cycle;
    ngx_uint_t        loss_round_start;
    ngx_uint_t        init_cwnd;
    ngx_uint_t        initialized;
    ngx_uint_t        full_bw_now;
    ngx_msec_t        probe_rtt_min_us;
    ngx_msec_t        probe_rtt_min_stamp;
} ngx_quic_bbr_state_t;


extern const ngx_quic_cc_algo_t  ngx_quic_cc_bbr;


void ngx_quic_bbr_init_conf(void *conf);
char *ngx_quic_bbr_merge_conf(ngx_conf_t *cf, void *conf, void *prev);
ngx_msec_t ngx_quic_bbr_pacing_delay(ngx_connection_t *c);


#endif /* _NGX_EVENT_QUIC_BBR_H_INCLUDED_ */
