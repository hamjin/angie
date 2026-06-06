/*
 * Copyright (C) 2026 Web Server LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_bbr.h>


#define NGX_QUIC_BBR_BW_SCALE              24
#define NGX_QUIC_BBR_BW_UNIT               (1 << NGX_QUIC_BBR_BW_SCALE)
#define NGX_QUIC_BBR_CYCLE_LEN             8
#define NGX_QUIC_BBR_INITIAL_RTT           1 /* ms */
#define NGX_QUIC_BBR_STARTUP_FULL_LOSS_COUNT  8
#define NGX_QUIC_BBR_STARTUP_LOSS_THRESH_PCT  2
#define NGX_QUIC_BBR_CONF_SET_BITS         (sizeof(uint64_t) * 8)


#ifndef container_of
#define container_of(ptr, type, member)                                       \
    ((type *)((u_char *)(ptr) - offsetof(type, member)))
#endif


typedef enum {
    BBR_STARTUP = 0,
    BBR_DRAIN,
    BBR_PROBE_BW,
    BBR_PROBE_RTT
} ngx_quic_bbr_mode_e;


typedef enum {
    BBR_RECOVERY_NOT_IN_RECOVERY = 0,
    BBR_RECOVERY_CONSERVATION,
    BBR_RECOVERY_GROWTH
} ngx_quic_bbr_recovery_e;


/* BBRv3 PROBE_BW cycle phase */
typedef enum {
    BBR_BW_PROBE_UP = 0,
    BBR_BW_PROBE_DOWN = 1,
    BBR_BW_PROBE_CRUISE = 2,
    BBR_BW_PROBE_REFILL = 3
} ngx_quic_bbr_cycle_phase_e;


/* BBRv3 ACK phase */
typedef enum {
    BBR_ACKS_INIT = 0,
    BBR_ACKS_REFILLING,
    BBR_ACKS_PROBE_STARTING,
    BBR_ACKS_PROBE_FEEDBACK,
    BBR_ACKS_PROBE_STOPPING
} ngx_quic_bbr_ack_phase_e;


typedef struct {
    uint64_t    delivered;
    uint64_t    acked;
    uint64_t    prior_delivered;
    uint64_t    prior_in_flight;
    uint64_t    bandwidth;
    uint64_t    send_rate;
    uint64_t    delivered_ce;       /* CE-marked bytes in this ACK */
    uint64_t    packet_number;
    uint64_t    last_sent_packet_number;
    uint64_t    interval;
    uint64_t    prior_delivered_time;
    uint64_t    lost_packets;
    ngx_uint_t  is_app_limited;
    ngx_uint_t  is_acking_tlp;
} bbr_rate_sample_t;


static void ngx_quic_bbr_reset(ngx_quic_connection_t *qc);
static void ngx_quic_bbr_ack(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_bbr_lost(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_bbr_idle(ngx_connection_t *c, ngx_uint_t idle);
static void ngx_quic_bbr_persistent_congestion(ngx_connection_t *c);
static const ngx_quic_bbr_conf_t *ngx_quic_bbr_conf(ngx_connection_t *c);
static void bbr_profile_google(ngx_quic_bbr_conf_t *conf);
static void bbr_profile_sing(ngx_quic_bbr_conf_t *conf);
static void bbr_profile_hy2(ngx_quic_bbr_conf_t *conf);
static void bbr_apply_profile(ngx_quic_bbr_conf_t *conf, ngx_uint_t profile);
static void bbr_apply_overrides(ngx_quic_bbr_conf_t *conf,
    ngx_quic_bbr_conf_t *prev);
static ngx_uint_t bbr_param_is_set(ngx_quic_bbr_conf_t *conf,
    ngx_uint_t offset);
static void bbr_normalize_conf(ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_max_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_bdp(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain);
static ngx_uint_t ngx_quic_bbr_tso_goal(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_quantize(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t cwnd);
static uint64_t ngx_quic_bbr_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain);
static void ngx_quic_bbr_save_cwnd(ngx_quic_congestion_t *cg);
static void ngx_quic_bbr_rate_sample(ngx_quic_congestion_t *cg,
    ngx_quic_frame_t *f, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_update_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_lt_sampling(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t delivered, ngx_uint_t losses,
    ngx_uint_t app_limited);
static void ngx_quic_bbr_reset_lt_sampling(ngx_quic_congestion_t *cg);
static void ngx_quic_bbr_update_ack_aggregation(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_check_full_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_check_drain(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_update_min_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_quic_connection_t *qc);
static void ngx_quic_bbr_update_gains(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_reset_probe_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_advance_cycle(ngx_quic_congestion_t *cg);
static void ngx_quic_bbr_update_cycle(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_uint_t losses,
    uint64_t prior_in_flight);
static ngx_uint_t ngx_quic_bbr_set_cwnd_to_recover_or_restore(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_cap_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_set_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_set_pacing_rate(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_init_rate_sample(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f, ngx_msec_t now, size_t in_flight);
static void ngx_quic_bbr_update_pacing(ngx_quic_congestion_t *cg,
    size_t sent, ngx_msec_t now);
static void ngx_quic_bbr_set_pacing_timer(ngx_quic_connection_t *qc,
    ngx_msec_t delay);


static const ngx_uint_t  ngx_quic_bbr_pacing_gain[NGX_QUIC_BBR_CYCLE_LEN] = {
    NGX_QUIC_BBR_UNIT * 5 / 4,
    NGX_QUIC_BBR_UNIT * 3 / 4,
    NGX_QUIC_BBR_UNIT,
    NGX_QUIC_BBR_UNIT,
    NGX_QUIC_BBR_UNIT,
    NGX_QUIC_BBR_UNIT,
    NGX_QUIC_BBR_UNIT,
    NGX_QUIC_BBR_UNIT
};

static const ngx_uint_t  ngx_quic_bbr_v3_pacing_gain[] = {
    NGX_QUIC_BBR_UNIT * 5 / 4,   /* BBR_BW_PROBE_UP */
    NGX_QUIC_BBR_UNIT * 3 / 4,   /* BBR_BW_PROBE_DOWN */
    NGX_QUIC_BBR_UNIT,           /* BBR_BW_PROBE_CRUISE */
    NGX_QUIC_BBR_UNIT            /* BBR_BW_PROBE_REFILL */
};

/* BBRv3 PROBE_BW cycle functions and orchestration */
static void ngx_quic_bbr_v3_advance_max_bw_filter(
    ngx_quic_congestion_t *cg);
static uint64_t ngx_quic_bbr_v3_max_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_v3_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_take_max_bw_sample(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw);
static void ngx_quic_bbr_v3_reset_full_bw(ngx_quic_congestion_t *cg);
static uint64_t ngx_quic_bbr_v3_target_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static ngx_uint_t ngx_quic_bbr_v3_is_probing_bandwidth(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_init_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_uint_t init_bw);
static void ngx_quic_bbr_v3_loss_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t *bw_out,
    uint64_t *inflight_out);
static void ngx_quic_bbr_v3_ecn_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t *inflight_out);
static void ngx_quic_bbr_v3_adapt_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static uint64_t ngx_quic_bbr_v3_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain);
static uint64_t ngx_quic_bbr_v3_inflight_with_headroom(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_reset_lower_bounds(
    ngx_quic_congestion_t *cg);
static void ngx_quic_bbr_v3_reset_congestion_signals(
    ngx_quic_congestion_t *cg);
static void ngx_quic_bbr_v3_update_ecn_alpha(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_check_ecn_too_high_in_startup(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);


/* BBRv3 PROBE_BW cycle start functions */
static ngx_uint_t ngx_quic_bbr_v3_is_reno_coexistence_probe_time(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_pick_probe_wait(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_raise_inflight_hi_slope(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_start_bw_probe_refill(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    ngx_uint_t bw_probe_up_rounds);
static void ngx_quic_bbr_v3_start_bw_probe_up(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_start_bw_probe_down(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_start_bw_probe_cruise(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);

/* BBRv3 congestion signal helpers */
static ngx_uint_t ngx_quic_bbr_v3_is_inflight_too_high(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_handle_inflight_too_high(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_probe_inflight_hi_upward(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);

/* BBRv3 PROBE_BW cycle orchestration (higher-level) */
static ngx_uint_t ngx_quic_bbr_v3_check_time_to_probe_bw(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static ngx_uint_t ngx_quic_bbr_v3_check_time_to_cruise(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    uint64_t inflight, uint64_t bw);
static void ngx_quic_bbr_v3_adapt_upper_bounds(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void
ngx_quic_bbr_v3_update_cycle_phase(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);

/* BBRv3 model update and control */
static void ngx_quic_bbr_v3_calculate_bw_sample(ngx_quic_congestion_t *cg,
    bbr_rate_sample_t *sample);
static uint64_t ngx_quic_bbr_v3_update_round_start(ngx_quic_congestion_t *cg,
    ngx_quic_frame_t *f, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_update_ack_aggregation(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_check_full_bw_reached(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    uint64_t ctx_sample_bw);
static void ngx_quic_bbr_v3_check_loss_too_high_in_startup(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);

static void ngx_quic_bbr_v3_check_drain(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_update_min_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_quic_connection_t *qc);
static uint64_t ngx_quic_bbr_v3_probe_rtt_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_check_probe_rtt_done(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_handle_queue_too_high_in_startup(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_exit_probe_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_update_gains(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_set_pacing_rate(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf);
static void ngx_quic_bbr_v3_set_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_update_model(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    uint64_t ctx_sample_bw, ngx_quic_connection_t *qc);
static uint64_t ngx_quic_bbr_v3_quantize(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t cwnd);
static uint64_t ngx_quic_bbr_v3_ack_aggregation_cwnd(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf);
static ngx_uint_t ngx_quic_bbr_v3_run_fast_path(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    ngx_uint_t *update_model);
static void ngx_quic_bbr_v3_update_congestion_signals(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_update_latest_delivery_signals(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);
static void ngx_quic_bbr_v3_advance_latest_delivery_signals(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample);

/* BBRv3 callback entry functions (version=3 dispatch targets) */
static void ngx_quic_bbr_v3_reset(ngx_quic_connection_t *qc);
static void ngx_quic_bbr_v3_ack(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_bbr_v3_lost(ngx_connection_t *c, ngx_quic_frame_t *f);
static void ngx_quic_bbr_v3_idle(ngx_connection_t *c, ngx_uint_t idle);
static void ngx_quic_bbr_v3_persistent_congestion(ngx_connection_t *c);

static ngx_conf_enum_t  ngx_quic_bbr_profile[] = {
    { ngx_string("default"), NGX_QUIC_BBR_PROFILE_DEFAULT },
    { ngx_string("google"), NGX_QUIC_BBR_PROFILE_GOOGLE },
    { ngx_string("sing"),  NGX_QUIC_BBR_PROFILE_SING },
    { ngx_string("hy2"),   NGX_QUIC_BBR_PROFILE_HY2 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_quic_bbr_versions[] = {
    { ngx_string("1"), 1 },
    { ngx_string("3"), 3 },
    { ngx_null_string, 0 }
};


static ngx_conf_num_set_t  ngx_quic_bbr_params[] = {
    { ngx_string("version"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, version),
      NULL, NULL, (void *) &ngx_quic_bbr_versions },
    { ngx_string("profile"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, profile),
      NULL, NULL, (void *) &ngx_quic_bbr_profile },
    { ngx_string("high_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, high_gain), NULL, NULL, NULL },
    { ngx_string("drain_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, drain_gain), NULL, NULL, NULL },
    { ngx_string("cwnd_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, cwnd_gain), NULL, NULL, NULL },
    { ngx_string("pacing_margin_percent"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, pacing_margin_percent), NULL, NULL, NULL },
    { ngx_string("min_rtt_win_sec"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, min_rtt_win_sec), NULL, NULL, NULL },
    { ngx_string("probe_rtt_mode_ms"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, probe_rtt_mode_ms), NULL, NULL, NULL },
    { ngx_string("min_tso_rate"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, min_tso_rate), NULL, NULL, NULL },
    { ngx_string("cwnd_min_target"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, cwnd_min_target), NULL, NULL, NULL },
    { ngx_string("full_bw_thresh"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, full_bw_thresh), NULL, NULL, NULL },
    { ngx_string("full_bw_cnt"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, full_bw_cnt), NULL, NULL, NULL },
    { ngx_string("bw_rtts"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, bw_rtts), NULL, NULL, NULL },
    { ngx_string("cycle_rand"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, cycle_rand), NULL, NULL, NULL },
    { ngx_string("lt_intvl_min_rtts"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, lt_intvl_min_rtts), NULL, NULL, NULL },
    { ngx_string("lt_loss_thresh"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, lt_loss_thresh), NULL, NULL, NULL },
    { ngx_string("lt_bw_ratio"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, lt_bw_ratio), NULL, NULL, NULL },
    { ngx_string("lt_bw_diff"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, lt_bw_diff), NULL, NULL, NULL },
    { ngx_string("lt_bw_max_rtts"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, lt_bw_max_rtts), NULL, NULL, NULL },
    { ngx_string("extra_acked_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, extra_acked_gain), NULL, NULL, NULL },
    { ngx_string("extra_acked_win_rtts"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, extra_acked_win_rtts), NULL, NULL, NULL },
    { ngx_string("ack_epoch_acked_reset_thresh"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, ack_epoch_acked_reset_thresh),
      NULL, NULL, NULL },
    { ngx_string("extra_acked_max_us"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, extra_acked_max_us), NULL, NULL, NULL },
    { ngx_string("startup_cwnd_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, startup_cwnd_gain), NULL, NULL, NULL },
    { ngx_string("initial_cwnd_packets"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, initial_cwnd_packets), NULL, NULL, NULL },
    { ngx_string("max_cwnd_packets"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, max_cwnd_packets), NULL, NULL, NULL },
    { ngx_string("drain_to_target"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, drain_to_target), NULL, NULL, NULL },
    { ngx_string("detect_overshooting"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, detect_overshooting), NULL, NULL, NULL },
    { ngx_string("enable_ack_aggregation_startup"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, enable_ack_aggregation_startup),
      NULL, NULL, NULL },
    { ngx_string("expire_ack_aggregation_startup"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, expire_ack_aggregation_startup),
      NULL, NULL, NULL },
    { ngx_string("overestimate_avoidance"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, overestimate_avoidance), NULL, NULL, NULL },
    { ngx_string("num_startup_rtts"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, num_startup_rtts), NULL, NULL, NULL },
    { ngx_string("bytes_lost_multiplier"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, bytes_lost_multiplier), NULL, NULL, NULL },
    { ngx_string("max_ack_height_tracker_window_multiplier"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t,
               max_ack_height_tracker_window_multiplier),
      NULL, NULL, NULL },
    { ngx_string("use_derived_high_gain"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, use_derived_high_gain),
      NULL, NULL, NULL },
    { ngx_string("start_new_aggregation_epoch_after_full_round"),
      NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t,
               start_new_aggregation_epoch_after_full_round),
      NULL, NULL, NULL },
    { ngx_string("limit_max_ack_height_tracker_by_send_rate"),
      NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t,
               limit_max_ack_height_tracker_by_send_rate),
      NULL, NULL, NULL },
    { ngx_string("exit_startup_on_loss"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, exit_startup_on_loss),
      NULL, NULL, NULL },
    { ngx_string("exit_startup_on_loss_even_if_app_limited"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, exit_startup_on_loss_even_if_app_limited),
      NULL, NULL, NULL },
    { ngx_string("reduce_extra_acked_on_bandwidth_increase"), NGX_CONF_TAKE1,
      offsetof(ngx_quic_bbr_conf_t, reduce_extra_acked_on_bandwidth_increase),
      NULL, NULL, NULL },
    { ngx_null_string, 0, 0, NULL, NULL, NULL }
};


static char *
ngx_quic_bbr_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *algo_conf)
{
    ngx_str_t           *value;
    ngx_conf_num_set_t  *pset;
    ngx_uint_t           i;
    ngx_int_t            n = 0;
    ngx_conf_enum_t     *profile;

    value = cf->args->elts;

    for (i = 0; ngx_quic_bbr_params[i].name.len != 0; i++) {
        pset = &ngx_quic_bbr_params[i];

        if (value[1].len != pset->name.len
            || ngx_strncasecmp(value[1].data, pset->name.data, pset->name.len)
               != 0)
        {
            continue;
        }

        if (pset->post) {
            profile = (ngx_conf_enum_t *) pset->post;

            for (/**/; profile->name.len != 0; profile++) {
                if (value[2].len == profile->name.len
                    && ngx_strncasecmp(value[2].data, profile->name.data,
                                       profile->name.len) == 0)
                {
                    n = profile->value;
                    break;
                }
            }

            if (profile->name.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\" for \"%V\"",
                                   &value[2], &value[1]);
                return NGX_CONF_ERROR;
            }

        } else {
            n = ngx_atoi(value[2].data, value[2].len);
            if (n == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid number \"%V\"", &value[2]);
                return NGX_CONF_ERROR;
            }
        }

        *((ngx_int_t *) ((u_char *) algo_conf + pset->offset)) = n;

        if (i < NGX_QUIC_BBR_CONF_SET_BITS) {
            ((ngx_quic_bbr_conf_t *) algo_conf)->set |= (uint64_t) 1 << i;
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown parameter \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


const ngx_quic_cc_algo_t  ngx_quic_cc_bbr = {
    sizeof(ngx_quic_bbr_conf_t),
    ngx_quic_bbr_init_conf,
    ngx_quic_bbr_merge_conf,
    ngx_quic_bbr_conf_handler,
    ngx_quic_bbr_reset,
    ngx_quic_bbr_ack,
    ngx_quic_bbr_lost,
    ngx_quic_bbr_idle,
    ngx_quic_bbr_persistent_congestion,
    ngx_quic_bbr_pacing_delay,
    ngx_quic_bbr_init_rate_sample,
    ngx_quic_bbr_update_pacing,
    ngx_quic_bbr_set_pacing_timer,
    NGX_QUIC_CC_SKIP_RECOVERY | NGX_QUIC_CC_SKIP_IDLE
    | NGX_QUIC_CC_HAS_PACING | NGX_QUIC_CC_HAS_RATE_SAMPLE
};


void
ngx_quic_bbr_init_conf(void *data)
{
    ngx_quic_bbr_conf_t  *conf = data;

    conf->profile = NGX_CONF_UNSET_UINT;
    conf->version = NGX_CONF_UNSET_UINT;
    conf->set = 0;

    conf->high_gain = NGX_QUIC_BBR_UNIT * 2885 / 1000 + 1;
    conf->drain_gain = NGX_QUIC_BBR_UNIT * 1000 / 2885;
    conf->cwnd_gain = NGX_QUIC_BBR_UNIT * 2;
    conf->pacing_margin_percent = 1;
    conf->min_rtt_win_sec = 10;
    conf->probe_rtt_mode_ms = 200;
    conf->min_tso_rate = 1200000;
    conf->cwnd_min_target = 4;
    conf->full_bw_thresh = NGX_QUIC_BBR_UNIT * 5 / 4;
    conf->full_bw_cnt = 3;
    conf->bw_rtts = NGX_QUIC_BBR_CYCLE_LEN + 2;
    conf->cycle_rand = 7;
    conf->lt_intvl_min_rtts = 4;
    conf->lt_loss_thresh = 50;
    conf->lt_bw_ratio = NGX_QUIC_BBR_UNIT / 8;
    conf->lt_bw_diff = 4000 / 8;
    conf->lt_bw_max_rtts = 48;
    conf->extra_acked_gain = NGX_QUIC_BBR_UNIT;
    conf->extra_acked_win_rtts = 5;
    conf->ack_epoch_acked_reset_thresh = 1 << 20;
    conf->extra_acked_max_us = 100 * 1000;
    conf->startup_cwnd_gain = NGX_QUIC_BBR_UNIT * 2885 / 1000 + 1;
    conf->initial_cwnd_packets = 10;
    conf->max_cwnd_packets = 0;
    conf->drain_to_target = 0;
    conf->detect_overshooting = 0;
    conf->enable_ack_aggregation_startup = 0;
    conf->expire_ack_aggregation_startup = 0;
    conf->overestimate_avoidance = 0;
    conf->num_startup_rtts = 3;
    conf->bytes_lost_multiplier = 2;
    conf->max_ack_height_tracker_window_multiplier = 0;
    conf->use_derived_high_gain = 0;
    conf->start_new_aggregation_epoch_after_full_round = 0;
    conf->limit_max_ack_height_tracker_by_send_rate = 0;
    conf->exit_startup_on_loss = 0;
    conf->exit_startup_on_loss_even_if_app_limited = 0;
    conf->reduce_extra_acked_on_bandwidth_increase = 0;

    /* v3 parameters — defaults from tcp_bbr.c static const */
    conf->startup_pacing_gain = NGX_QUIC_BBR_UNIT * 277 / 100 + 1;
    conf->beta = NGX_QUIC_BBR_UNIT * 30 / 100;
    conf->loss_thresh = NGX_QUIC_BBR_UNIT * 2 / 100;
    conf->ecn_factor = NGX_QUIC_BBR_UNIT * 1 / 3;
    conf->ecn_thresh = NGX_QUIC_BBR_UNIT * 1 / 2;
    conf->ecn_alpha_gain = NGX_QUIC_BBR_UNIT * 1 / 16;
    conf->ecn_alpha_init = NGX_QUIC_BBR_UNIT;
    conf->ecn_max_rtt_us = 5000;
    conf->ecn_reprobe_gain = NGX_QUIC_BBR_UNIT * 1 / 2;
    conf->full_loss_cnt = 6;
    conf->full_ecn_cnt = 2;
    conf->inflight_headroom = NGX_QUIC_BBR_UNIT * 15 / 100;
    conf->bw_probe_max_rounds = 63;
    conf->bw_probe_rand_rounds = 2;
    conf->bw_probe_base_us = 2000000;
    conf->bw_probe_rand_us = 1000000;
    conf->bw_probe_cwnd_gain = 1;
    conf->probe_rtt_win_ms = 5000;
    conf->probe_rtt_cwnd_gain = NGX_QUIC_BBR_UNIT * 1 / 2;
    conf->tso_rtt_shift = 9;
    conf->fast_path = 1;
    conf->fast_ack_mode = 1;
    conf->precise_ece_ack = 1;
    conf->loss_probe_recovery = 1;
}


char *
ngx_quic_bbr_merge_conf(ngx_conf_t *cf, void *conf_data, void *prev_data)
{
    ngx_quic_bbr_conf_t  *conf = conf_data;
    ngx_quic_bbr_conf_t  *prev = prev_data;
    ngx_quic_bbr_conf_t    saved;

    if (conf->version == NGX_CONF_UNSET_UINT) {
        if (prev != NULL && prev->version != NGX_CONF_UNSET_UINT) {
            conf->version = prev->version;
        } else {
            conf->version = 1;
        }
    }

    if (conf->profile == NGX_CONF_UNSET_UINT) {
        if (prev == NULL || prev->profile == NGX_CONF_UNSET_UINT) {
            saved = *conf;
            bbr_apply_profile(conf, NGX_QUIC_BBR_PROFILE_DEFAULT);
            bbr_apply_overrides(conf, &saved);
            bbr_normalize_conf(conf);
        } else {
            saved = *conf;
            *conf = *prev;
            bbr_apply_overrides(conf, &saved);
            bbr_normalize_conf(conf);
        }
    } else {
        saved = *conf;
        bbr_apply_profile(conf, conf->profile);
        bbr_apply_overrides(conf, &saved);
        bbr_normalize_conf(conf);
    }

    return NGX_CONF_OK;
}


static void
bbr_profile_google(ngx_quic_bbr_conf_t *conf)
{
    conf->profile = NGX_QUIC_BBR_PROFILE_GOOGLE;
}


static void
bbr_profile_sing(ngx_quic_bbr_conf_t *conf)
{
    conf->profile = NGX_QUIC_BBR_PROFILE_SING;
    conf->high_gain = NGX_QUIC_BBR_UNIT * 2885 / 1000;
    conf->lt_intvl_min_rtts = 0;
    conf->lt_loss_thresh = 0;
    conf->lt_bw_ratio = 0;
    conf->lt_bw_diff = 0;
    conf->lt_bw_max_rtts = 0;
    conf->exit_startup_on_loss = 1;
    conf->pacing_margin_percent = 0;
    conf->extra_acked_win_rtts = 10;
    conf->ack_epoch_acked_reset_thresh = 0;
    conf->extra_acked_max_us = 0;
    conf->startup_cwnd_gain = NGX_QUIC_BBR_UNIT * 2;
}


static void
bbr_profile_hy2(ngx_quic_bbr_conf_t *conf)
{
    /* Standalone hy2 profile — inherits sing traits plus hy2-specific */
    conf->profile = NGX_QUIC_BBR_PROFILE_HY2;
    conf->high_gain = NGX_QUIC_BBR_UNIT * 2885 / 1000;
    conf->lt_intvl_min_rtts = 0;
    conf->lt_loss_thresh = 0;
    conf->lt_bw_ratio = 0;
    conf->lt_bw_diff = 0;
    conf->lt_bw_max_rtts = 0;
    conf->exit_startup_on_loss = 1;
    conf->pacing_margin_percent = 0;
    conf->extra_acked_win_rtts = 10;
    conf->ack_epoch_acked_reset_thresh = 0;
    conf->extra_acked_max_us = 0;
    conf->startup_cwnd_gain = NGX_QUIC_BBR_UNIT * 2;
    conf->initial_cwnd_packets = 32;
}


static void
bbr_apply_profile(ngx_quic_bbr_conf_t *conf, ngx_uint_t profile)
{
    /* Each profile is self-contained — no cascading.
       init_conf already provides the google baseline defaults. */
    switch (profile) {
    case NGX_QUIC_BBR_PROFILE_GOOGLE:
        bbr_profile_google(conf);
        break;

    case NGX_QUIC_BBR_PROFILE_SING:
        bbr_profile_sing(conf);
        break;

    case NGX_QUIC_BBR_PROFILE_HY2:
        bbr_profile_hy2(conf);
        break;

    case NGX_QUIC_BBR_PROFILE_DEFAULT:
    default:
        conf->profile = NGX_QUIC_BBR_PROFILE_DEFAULT;
        conf->high_gain = NGX_QUIC_BBR_UNIT * 2;
        conf->drain_gain = NGX_QUIC_BBR_UNIT * 1000 / 2000;
        conf->startup_cwnd_gain = NGX_QUIC_BBR_UNIT * 2;
        conf->enable_ack_aggregation_startup = 1;
        conf->exit_startup_on_loss = 1;
        break;
    }
}


static void
bbr_apply_overrides(ngx_quic_bbr_conf_t *conf, ngx_quic_bbr_conf_t *prev)
{
    /* Replay only user-supplied parameters; init_conf already has a baseline. */
#define ngx_quic_bbr_merge_field(name, unset)                                \
    if (bbr_param_is_set(prev, offsetof(ngx_quic_bbr_conf_t, name))           \
        && prev->name != (unset))                                             \
    {                                                                         \
        conf->name = prev->name;                                              \
    }

    ngx_quic_bbr_merge_field(version, NGX_CONF_UNSET_UINT);
    ngx_quic_bbr_merge_field(high_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(drain_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(cwnd_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(pacing_margin_percent, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(min_rtt_win_sec, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(probe_rtt_mode_ms, NGX_CONF_UNSET_MSEC);
    ngx_quic_bbr_merge_field(min_tso_rate, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(cwnd_min_target, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(full_bw_thresh, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(full_bw_cnt, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(bw_rtts, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(cycle_rand, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(lt_intvl_min_rtts, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(lt_loss_thresh, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(lt_bw_ratio, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(lt_bw_diff, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(lt_bw_max_rtts, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(extra_acked_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(extra_acked_win_rtts, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(ack_epoch_acked_reset_thresh, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(extra_acked_max_us, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(startup_cwnd_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(initial_cwnd_packets, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(max_cwnd_packets, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(drain_to_target, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(detect_overshooting, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(enable_ack_aggregation_startup, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(expire_ack_aggregation_startup, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(overestimate_avoidance, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(num_startup_rtts, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(bytes_lost_multiplier, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(max_ack_height_tracker_window_multiplier,
                              NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(use_derived_high_gain, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(start_new_aggregation_epoch_after_full_round,
                              NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(limit_max_ack_height_tracker_by_send_rate,
                              NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(exit_startup_on_loss, NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(exit_startup_on_loss_even_if_app_limited,
                              NGX_CONF_UNSET);
    ngx_quic_bbr_merge_field(reduce_extra_acked_on_bandwidth_increase,
                              NGX_CONF_UNSET);

#undef ngx_quic_bbr_merge_field

    conf->set |= prev->set;
}


static ngx_uint_t
bbr_param_is_set(ngx_quic_bbr_conf_t *conf, ngx_uint_t offset)
{
    ngx_uint_t  i;

    for (i = 0; ngx_quic_bbr_params[i].name.len != 0; i++) {
        if (ngx_quic_bbr_params[i].offset == offset) {
            return i < NGX_QUIC_BBR_CONF_SET_BITS
                   && (conf->set & ((uint64_t) 1 << i)) != 0;
        }
    }

    return 0;
}


static void
bbr_normalize_conf(ngx_quic_bbr_conf_t *conf)
{
    if (conf->bw_rtts < 1) {
        conf->bw_rtts = 1;
    }

    if (conf->pacing_margin_percent > 99) {
        conf->pacing_margin_percent = 99;
    }

    if (conf->initial_cwnd_packets < conf->cwnd_min_target) {
        conf->initial_cwnd_packets = conf->cwnd_min_target;
    }

    if (conf->num_startup_rtts < 1) {
        conf->num_startup_rtts = 1;
    }

    if (conf->bytes_lost_multiplier < 1) {
        conf->bytes_lost_multiplier = 1;
    }

    if (conf->max_ack_height_tracker_window_multiplier > 0) {
        conf->extra_acked_win_rtts =
            conf->max_ack_height_tracker_window_multiplier * conf->bw_rtts;
    }

    if (conf->use_derived_high_gain) {
        conf->high_gain = NGX_QUIC_BBR_UNIT * 2773 / 1000;
        conf->startup_cwnd_gain = NGX_QUIC_BBR_UNIT * 2;
        conf->drain_gain = NGX_QUIC_BBR_UNIT / 2;
    }

    /* v3-specific: fix-up inherited v1 params that harm v3 algorithm.
       init_conf already sets all v3 defaults matching tcp_bbr.c. */
    if (conf->version == 3) {
        if (conf->ack_epoch_acked_reset_thresh == 0) {
            conf->ack_epoch_acked_reset_thresh = 1 << 20;
        }

        if (conf->extra_acked_max_us == 0) {
            conf->extra_acked_max_us = 100 * 1000;
        }
    }
}


static void
ngx_quic_bbr_reset(ngx_quic_connection_t *qc)
{
    ngx_uint_t                    i;
    ngx_quic_congestion_t        *cg;
    ngx_quic_bbr_state_t         *state;
    const ngx_quic_bbr_conf_t   *conf;

    conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

    if (conf->version == 3) {
        ngx_quic_bbr_v3_reset(qc);
        return;
    }

    cg = &qc->congestion;

    if (cg->cc_priv == NULL) {
        cg->cc_priv = ngx_alloc(sizeof(ngx_quic_bbr_state_t),
                                 ngx_cycle->log);
        if (cg->cc_priv == NULL) {
            return;
        }
    }

    ngx_memzero(cg->cc_priv, sizeof(ngx_quic_bbr_state_t));
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);
    state->base.type = NGX_QUIC_CC_BBR;

    state->version = conf->version;

    if (conf->initial_cwnd_packets > 0) {
        cg->window = ngx_max(cg->window,
                             (size_t) conf->initial_cwnd_packets * cg->mtu);
    }

    state->congestion_window = cg->window;
    cg->ssthresh = (size_t) -1;
    cg->w_prior = cg->window;
    state->prior_cwnd = cg->window;
    state->mode = BBR_STARTUP;
    state->prev_mode = BBR_STARTUP;
    state->cycle_idx = 0;
    state->min_rtt = qc->min_rtt == NGX_TIMER_INFINITE ?
                       NGX_QUIC_BBR_INITIAL_RTT : qc->min_rtt;
    state->min_rtt_stamp = qc->min_rtt == NGX_TIMER_INFINITE ? 0 :
                              ngx_current_msec;
    state->probe_rtt_done_stamp = 0;
    state->probe_rtt_round_done = 0;
    state->cycle_stamp = ngx_current_msec;
    state->first_sent_time = ngx_current_msec;
    state->delivered = 0;
    state->delivered_time = ngx_current_msec;
    state->next_round_delivered = 0;
    state->rtt_cnt = 0;
    state->full_bw = 0;
    state->full_bw_reached = 0;
    state->full_bw_cnt = 0;
    state->packet_conservation = BBR_RECOVERY_NOT_IN_RECOVERY;
    state->lt_is_sampling = 0;
    state->lt_use_bw = 0;
    state->lt_rtt_cnt = 0;
    state->lt_bw = 0;
    state->lt_last_delivered = 0;
    state->lt_last_stamp = ngx_current_msec;
    state->lt_last_lost = 0;
    state->lost = 0;
    state->loss_in_round = 0;
    state->startup_loss_in_round = 0;
    state->recovery_delivered = 0;
    state->recovery_pnum = NGX_QUIC_UNSET_PN;
    state->recovery_window = 0;
    state->ack_epoch_stamp = ngx_current_msec;
    state->ack_epoch_acked = 0;
    state->last_sent_pnum = NGX_QUIC_UNSET_PN;
    state->ack_epoch_last_sent_pnum = NGX_QUIC_UNSET_PN;
    state->extra_acked[0] = 0;
    state->extra_acked[1] = 0;
    state->extra_acked_win_idx = 0;
    state->extra_acked_win_rtts = 0;
    state->loss_events_in_round = 0;
    state->pacing_gain = conf->high_gain;
    state->cwnd_gain = conf->startup_cwnd_gain;

    for (i = 0; i < ngx_min((ngx_uint_t) conf->bw_rtts,
                            (ngx_uint_t) NGX_QUIC_BBR_CYCLE_LEN + 2); i++)
    {
        state->bw[i] = 0;
        state->bw_stamp[i] = 0;
    }

    ngx_quic_bbr_set_pacing_rate(cg, conf);
}


static void
ngx_quic_bbr_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    bbr_rate_sample_t            sample;
    const ngx_quic_bbr_conf_t   *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->version == 3) {
        ngx_quic_bbr_v3_ack(c, f);
        return;
    }

    conf = ngx_quic_bbr_conf(c);

    ngx_quic_bbr_rate_sample(cg, f, &sample);

    ngx_quic_bbr_update_bw(cg, conf, &sample);
    ngx_quic_bbr_update_ack_aggregation(cg, conf, &sample);
    ngx_quic_bbr_update_cycle(cg, conf, 0, sample.prior_in_flight);
    ngx_quic_bbr_check_full_bw(cg, conf, &sample);

    if (state->round_start) {
        state->loss_events_in_round = 0;
        state->startup_loss_in_round = 0;
    }

    ngx_quic_bbr_check_drain(cg, conf);
    ngx_quic_bbr_update_min_rtt(cg, conf, qc);
    ngx_quic_bbr_update_gains(cg, conf);
    ngx_quic_bbr_set_pacing_rate(cg, conf);
    ngx_quic_bbr_set_cwnd(cg, conf, &sample);

    ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic bbr ack mode:%ui bw:%uL gain:%ui cwnd:%uz "
                   "rate:%uL if:%uz rtt:%M",
                   state->mode, ngx_quic_bbr_bw(cg, conf),
                   state->pacing_gain, cg->window, state->pacing_rate,
                   cg->in_flight, state->min_rtt);
}


static void
ngx_quic_bbr_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    const ngx_quic_bbr_conf_t   *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->version == 3) {
        ngx_quic_bbr_v3_lost(c, f);
        return;
    }

    conf = ngx_quic_bbr_conf(c);

    state->lost += f->plen;
    state->loss_in_round += f->plen;
    state->startup_loss_in_round += f->plen;
    state->loss_events_in_round++;
    ngx_quic_bbr_save_cwnd(cg);

    if (state->mode != BBR_PROBE_RTT && state->full_bw_reached) {
        if (state->packet_conservation == BBR_RECOVERY_NOT_IN_RECOVERY) {
            state->recovery_pnum = state->last_sent_pnum;
            state->packet_conservation = BBR_RECOVERY_CONSERVATION;
            state->recovery_delivered = state->delivered;
            state->next_round_delivered = state->delivered;
            state->recovery_window = 0;
        }
    }

    ngx_quic_bbr_lt_sampling(cg, conf, 0, f->plen,
                              state->mode == BBR_PROBE_RTT);
    state->round_start = 0;
    ngx_quic_bbr_update_cycle(cg, conf, 1, cg->in_flight);
    ngx_quic_bbr_check_drain(cg, conf);
    ngx_quic_bbr_update_gains(cg, conf);
    ngx_quic_bbr_set_pacing_rate(cg, conf);

    /* Also update cwnd on loss path, matching Google tcp_bbr.c
       which runs bbr_set_cwnd on both ack and loss events.
       Use a zeroed sample since we have no ACK data here. */
    {
        bbr_rate_sample_t  loss_sample;

        ngx_memzero(&loss_sample, sizeof(bbr_rate_sample_t));
        loss_sample.prior_in_flight = cg->in_flight;
        ngx_quic_bbr_set_cwnd(cg, conf, &loss_sample);
    }

    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic bbr lost mode:%ui win:%uz prior:%uL lost:%uL "
                   "bw:%uL if:%uz",
                   state->mode, cg->window, state->prior_cwnd,
                   state->lost, ngx_quic_bbr_bw(cg, conf), cg->in_flight);
}


static void
ngx_quic_bbr_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    uint64_t                      bw;
    const ngx_quic_bbr_conf_t   *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    cg->idle = idle;

    if (!idle) {
        state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

        if (state->version == 3) {
            ngx_quic_bbr_v3_idle(c, idle);
            return;
        }

        conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

        state->ack_epoch_stamp = ngx_current_msec;
        state->ack_epoch_acked = 0;
        state->ack_epoch_last_sent_pnum = state->last_sent_pnum;

        /* reset pacing rate to bw * 1.0 (no gain overshoot) for
           PROBE_BW mode, matching Google CA_EVENT_TX_START */
        if (state->mode == BBR_PROBE_BW) {
            bw = ngx_quic_bbr_bw(cg, conf);
            if (bw) {
                state->pacing_rate = bw
                    * (100 - conf->pacing_margin_percent) / 100;
            }
        }

        state->round_start = 0;

        /* reset pacing debt to prevent accumulated burst */
        state->pacing_debt = 0;
        state->next_send_time = 0;
    }
}


static void
ngx_quic_bbr_persistent_congestion(ngx_connection_t *c)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    const ngx_quic_bbr_conf_t   *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->version == 3) {
        ngx_quic_bbr_v3_persistent_congestion(c);
        return;
    }

    conf = ngx_quic_bbr_conf(c);

    state->full_bw = 0;
    state->full_bw_cnt = 0;
    state->round_start = 1;
    state->packet_conservation = BBR_RECOVERY_NOT_IN_RECOVERY;
    state->recovery_delivered = 0;
    state->recovery_pnum = NGX_QUIC_UNSET_PN;
    state->recovery_window = 0;
    state->loss_in_round = 0;
    state->startup_loss_in_round = 0;
    state->loss_events_in_round = 0;

    ngx_quic_bbr_lt_sampling(cg, conf, 0, cg->mtu, 0);
}


static const ngx_quic_bbr_conf_t *
ngx_quic_bbr_conf(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    return (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;
}


static uint64_t
ngx_quic_bbr_max_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    /* layer 0 of the minmax filter always holds the running max */
    return state->bw[0];
}


static uint64_t
ngx_quic_bbr_minmax_update(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t t, uint64_t val)
{
    uint64_t               win;
    uint64_t              *v, *s;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    win = (uint64_t) conf->bw_rtts;
    v = state->bw;
    s = state->bw_stamp;

    if (val >= v[0] || v[0] == 0 || t - s[0] >= win) {
        v[0] = val;
        s[0] = t;
        return v[0];
    }

    if (val >= v[1] || v[1] == 0 || t - s[1] >= win) {
        v[1] = val;
        s[1] = t;
    } else if (val >= v[2] || v[2] == 0 || t - s[2] >= win) {
        v[2] = val;
        s[2] = t;
    }

    if (s[1] != 0 && t - s[1] >= win) {
        v[0] = v[1]; s[0] = s[1];
        v[1] = v[2]; s[1] = s[2];
        v[2] = 0;    s[2] = 0;
    } else if (s[2] != 0 && t - s[2] >= win) {
        v[1] = v[2]; s[1] = s[2];
        v[2] = 0;    s[2] = 0;
    }

    return v[0];
}


static uint64_t
ngx_quic_bbr_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->lt_use_bw && state->lt_bw) {
        return state->lt_bw;
    }

    return ngx_quic_bbr_max_bw(cg, conf);
}


static uint64_t
ngx_quic_bbr_bdp(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain)
{
    uint64_t               bdp;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (bw == 0) {
        return (uint64_t) conf->initial_cwnd_packets * cg->mtu;
    }

    bdp = bw * ngx_max(state->min_rtt, (ngx_msec_t) 1) / 1000;
    bdp = (bdp * gain + NGX_QUIC_BBR_UNIT - 1) / NGX_QUIC_BBR_UNIT;

    return ngx_max(bdp, (uint64_t) conf->cwnd_min_target * cg->mtu);
}


static ngx_uint_t
ngx_quic_bbr_tso_goal(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (conf->min_tso_rate <= 0
        || state->pacing_rate < (uint64_t) conf->min_tso_rate / 8)
    {
        return 1;
    }

    return ngx_min(ngx_max((ngx_uint_t) (state->pacing_rate / 1000 / 8
                                         / cg->mtu),
                           (ngx_uint_t) 2),
                   (ngx_uint_t) 0x7f);
}


static uint64_t
ngx_quic_bbr_quantize(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t cwnd)
{
    ngx_uint_t              tso_goal;
    ngx_quic_bbr_state_t   *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    tso_goal = ngx_quic_bbr_tso_goal(cg, conf);

    cwnd += 3 * tso_goal * cg->mtu;
    cwnd = (((cwnd + cg->mtu - 1) / cg->mtu + 1) & ~1) * cg->mtu;

    if (state->mode == BBR_PROBE_BW && state->cycle_idx == 0) {
        cwnd += 2 * cg->mtu;
    }

    return cwnd;
}


static uint64_t
ngx_quic_bbr_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain)
{
    return ngx_quic_bbr_quantize(cg, conf,
                                  ngx_quic_bbr_bdp(cg, conf, bw, gain));
}


static void
ngx_quic_bbr_save_cwnd(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->packet_conservation == BBR_RECOVERY_NOT_IN_RECOVERY
        && state->mode != BBR_PROBE_RTT)
    {
        state->prior_cwnd = state->congestion_window;
        return;
    }

    state->prior_cwnd = ngx_max(state->prior_cwnd,
                                  state->congestion_window);
}


static void
ngx_quic_bbr_rate_sample(ngx_quic_congestion_t *cg, ngx_quic_frame_t *f,
    bbr_rate_sample_t *sample)
{
    uint64_t               ack_interval, now, send_interval;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    ngx_memzero(sample, sizeof(bbr_rate_sample_t));

    sample->acked = f->plen;
    sample->prior_delivered = f->prior_delivered;
    sample->prior_delivered_time = f->prior_delivered_time;
    sample->prior_in_flight = f->tx_in_flight;
    sample->packet_number = f->pnum;
    sample->last_sent_packet_number = state->last_sent_pnum;
    sample->is_app_limited = f->is_app_limited;

    if (state->mode == BBR_PROBE_RTT) {
        sample->is_app_limited = 1;
    }

    now = ngx_current_msec;
    state->delivered += f->plen;
    state->delivered_time = now;

    if (state->delivered < sample->prior_delivered
        || sample->prior_delivered_time == 0)
    {
        sample->interval = 0;
        return;
    }

    sample->delivered = state->delivered - sample->prior_delivered;

    ack_interval = now - sample->prior_delivered_time;
    send_interval = f->send_time - f->first_sent_time;

    sample->interval = ngx_max(ack_interval, send_interval);
    sample->send_rate = (send_interval == 0) ? 0
                                             : sample->delivered * 1000
                                               / send_interval;

    state->first_sent_time = f->send_time;
}


static void
ngx_quic_bbr_update_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    uint64_t               bw;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->round_start = 0;

    if (sample->delivered == 0 || sample->interval == 0) {
        return;
    }

    if (sample->prior_delivered >= state->next_round_delivered) {
        state->next_round_delivered = state->delivered;
        state->rtt_cnt++;
        state->round_start = 1;
        state->packet_conservation = BBR_RECOVERY_NOT_IN_RECOVERY;
    }

    sample->bandwidth = sample->delivered * 1000 / sample->interval;
    bw = sample->bandwidth;
    ngx_quic_bbr_lt_sampling(cg, conf, sample->delivered, 0,
                              sample->is_app_limited);

    if (!sample->is_app_limited || bw >= ngx_quic_bbr_max_bw(cg, conf)) {
        (void) ngx_quic_bbr_minmax_update(cg, conf, state->rtt_cnt, bw);
    }
}


static void
ngx_quic_bbr_lt_sampling(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t delivered, ngx_uint_t losses,
    ngx_uint_t app_limited)
{
    uint64_t               bw, diff, elapsed, lost, delivered_total, now;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (conf->lt_intvl_min_rtts == 0 || conf->lt_loss_thresh == 0) {
        return;
    }

    if (state->lt_use_bw) {
        if (state->mode == BBR_PROBE_BW && state->round_start
            && ++state->lt_rtt_cnt >= (ngx_uint_t) conf->lt_bw_max_rtts)
        {
            ngx_quic_bbr_reset_lt_sampling(cg);
            ngx_quic_bbr_reset_probe_bw(cg, conf);
        }

        return;
    }

    if (!state->lt_is_sampling) {
        if (!losses) {
            return;
        }

        state->lt_is_sampling = 1;
        state->lt_last_stamp = ngx_current_msec;
        state->lt_last_delivered = state->delivered;
        state->lt_last_lost = state->lost;
        state->lt_rtt_cnt = 0;
    }

    if (app_limited) {
        ngx_quic_bbr_reset_lt_sampling(cg);
        return;
    }

    if (state->round_start) {
        state->lt_rtt_cnt++;
    }

    if (state->lt_rtt_cnt < (ngx_uint_t) conf->lt_intvl_min_rtts) {
        return;
    }

    if (state->lt_rtt_cnt
        > (ngx_uint_t) 4 * conf->lt_intvl_min_rtts)
    {
        ngx_quic_bbr_reset_lt_sampling(cg);
        return;
    }

    if (!losses) {
        return;
    }

    now = ngx_current_msec;
    elapsed = now - state->lt_last_stamp;
    if (elapsed == 0) {
        return;
    }

    delivered_total = state->delivered - state->lt_last_delivered
                      + delivered;
    lost = state->lost - state->lt_last_lost + losses;

    if (delivered_total == 0
        || (lost << NGX_QUIC_BBR_SCALE)
           < (uint64_t) conf->lt_loss_thresh * delivered_total)
    {
        return;
    }

    bw = delivered_total * 1000 / elapsed;

    if (state->lt_bw) {
        diff = (bw > state->lt_bw) ? bw - state->lt_bw:
                                      state->lt_bw - bw;

        if (diff * NGX_QUIC_BBR_UNIT <= (uint64_t) conf->lt_bw_ratio
                                          * state->lt_bw
            || diff <= (uint64_t) conf->lt_bw_diff)
        {
            state->lt_bw = (bw + state->lt_bw) / 2;
            state->lt_use_bw = 1;
            state->pacing_gain = NGX_QUIC_BBR_UNIT;
            state->lt_rtt_cnt = 0;
            return;
        }
    }

    state->lt_bw = bw;
    state->lt_last_stamp = now;
    state->lt_last_delivered = state->delivered;
    state->lt_last_lost = state->lost;
    state->lt_rtt_cnt = 0;
}


static void
ngx_quic_bbr_reset_lt_sampling(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->lt_bw = 0;
    state->lt_use_bw = 0;
    state->lt_is_sampling = 0;
    state->lt_last_stamp = ngx_current_msec;
    state->lt_last_delivered = state->delivered;
    state->lt_last_lost = state->lost;
    state->lt_rtt_cnt = 0;
}


static void
ngx_quic_bbr_update_ack_aggregation(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    uint64_t               elapsed, bw, expected, extra, ack_epoch_reset_threshold;
    ngx_uint_t             force_new_epoch;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (conf->extra_acked_gain == 0 || sample->acked == 0
        || sample->delivered == 0 || sample->interval == 0)
    {
        return;
    }

    if (state->round_start) {
        state->extra_acked_win_rtts++;

        if (state->extra_acked_win_rtts
            >= (ngx_uint_t) conf->extra_acked_win_rtts)
        {
            state->extra_acked_win_rtts = 0;
            state->extra_acked_win_idx ^= 1;
            state->extra_acked[state->extra_acked_win_idx] = 0;
        }
    }

    if (conf->reduce_extra_acked_on_bandwidth_increase
        && sample->bandwidth > ngx_quic_bbr_max_bw(cg, conf))
    {
        state->extra_acked[0] = 0;
        state->extra_acked[1] = 0;
    }

    elapsed = state->delivered_time - state->ack_epoch_stamp;
    bw = ngx_quic_bbr_bw(cg, conf);

    if (conf->limit_max_ack_height_tracker_by_send_rate
        && sample->send_rate != 0)
    {
        bw = ngx_max(bw, sample->send_rate);
    }

    expected = bw * elapsed / 1000;
    ack_epoch_reset_threshold = expected;

    if (conf->overestimate_avoidance) {
        if (ack_epoch_reset_threshold > UINT64_MAX / 2) {
            ack_epoch_reset_threshold = UINT64_MAX;

        } else {
            ack_epoch_reset_threshold *= 2;
        }
    }

    force_new_epoch = 0;

    if (conf->start_new_aggregation_epoch_after_full_round
        && state->ack_epoch_last_sent_pnum != NGX_QUIC_UNSET_PN
        && sample->packet_number != NGX_QUIC_UNSET_PN
        && sample->packet_number > state->ack_epoch_last_sent_pnum)
    {
        force_new_epoch = 1;
    }

    if (force_new_epoch) {
        state->ack_epoch_acked = sample->acked;
        state->ack_epoch_stamp = state->delivered_time;
        state->ack_epoch_last_sent_pnum = sample->last_sent_packet_number;
        return;
    }

    if (state->ack_epoch_acked <= ack_epoch_reset_threshold
        || (conf->ack_epoch_acked_reset_thresh > 0
            && state->ack_epoch_acked + sample->acked
               >= (uint64_t) conf->ack_epoch_acked_reset_thresh * cg->mtu))
    {
        state->ack_epoch_acked = 0;
        state->ack_epoch_stamp = state->delivered_time;
        state->ack_epoch_last_sent_pnum = sample->last_sent_packet_number;
        expected = 0;
    }

    state->ack_epoch_acked += sample->acked;
    extra = state->ack_epoch_acked - expected;
    extra = ngx_min(extra, (uint64_t) cg->window);

    if (extra > state->extra_acked[state->extra_acked_win_idx]) {
        state->extra_acked[state->extra_acked_win_idx] = extra;
    }
}


static void
ngx_quic_bbr_check_full_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    uint64_t               bw, thresh;
    ngx_uint_t             loss_exit;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->full_bw_reached || !state->round_start) {
        return;
    }

    loss_exit = state->loss_events_in_round
                >= NGX_QUIC_BBR_STARTUP_FULL_LOSS_COUNT
                && sample->prior_in_flight > 0
                && state->startup_loss_in_round * 100
                   > sample->prior_in_flight
                     * NGX_QUIC_BBR_STARTUP_LOSS_THRESH_PCT;

    if (conf->exit_startup_on_loss && loss_exit
        && conf->exit_startup_on_loss_even_if_app_limited)
    {
        state->full_bw_reached = 1;
        return;
    }

    if (sample->is_app_limited) {
        return;
    }

    bw = ngx_quic_bbr_max_bw(cg, conf);
    thresh = state->full_bw * conf->full_bw_thresh / NGX_QUIC_BBR_UNIT;

    if (bw >= thresh) {
        state->full_bw = bw;
        state->full_bw_cnt = 0;

        if (conf->expire_ack_aggregation_startup) {
            state->extra_acked[0] = 0;
            state->extra_acked[1] = 0;
        }

        return;
    }

    state->full_bw_cnt++;
    state->full_bw_reached = state->full_bw_cnt >= (ngx_uint_t)
                               ngx_max(conf->full_bw_cnt,
                                       conf->num_startup_rtts)
                               || (conf->exit_startup_on_loss
                                   && !conf->exit_startup_on_loss_even_if_app_limited
                                   && loss_exit);
}


static void
ngx_quic_bbr_check_drain(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->mode == BBR_STARTUP && state->full_bw_reached) {
        state->mode = BBR_DRAIN;
        cg->ssthresh = ngx_quic_bbr_bdp(cg, conf,
                                         ngx_quic_bbr_max_bw(cg, conf),
                                         NGX_QUIC_BBR_UNIT);
    }

    if (state->mode == BBR_DRAIN
        && cg->in_flight <= ngx_quic_bbr_inflight(cg, conf,
                                                   ngx_quic_bbr_max_bw(cg,
                                                                        conf),
                                                   NGX_QUIC_BBR_UNIT))
    {
        ngx_quic_bbr_reset_probe_bw(cg, conf);
    }
}


static void
ngx_quic_bbr_update_min_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_quic_connection_t *qc)
{
    ngx_uint_t             expired;
    ngx_msec_t             now, sample;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    now = ngx_current_msec;
    sample = qc->min_rtt;

    if (sample == NGX_TIMER_INFINITE || sample == 0) {
        return;
    }

    expired = state->min_rtt_stamp != 0
              && (now - state->min_rtt_stamp
                  > (ngx_msec_t) conf->min_rtt_win_sec * 1000);

    if (state->min_rtt_stamp == 0 || sample < state->min_rtt
        || (expired && sample <= state->min_rtt))
    {
        state->min_rtt = sample;
        state->min_rtt_stamp = now;
    }

    if (conf->probe_rtt_mode_ms > 0 && expired && !cg->idle
        && state->mode != BBR_PROBE_RTT)
    {
        state->prev_mode = state->mode;
        state->mode = BBR_PROBE_RTT;
        ngx_quic_bbr_save_cwnd(cg);
        state->probe_rtt_done_stamp = 0;
    }

    if (state->mode == BBR_PROBE_RTT) {
        if (!state->probe_rtt_done_stamp
            && cg->in_flight < ((size_t) conf->cwnd_min_target + 1) * cg->mtu)
        {
            state->probe_rtt_done_stamp = now + conf->probe_rtt_mode_ms;
            state->probe_rtt_round_done = 0;
            state->next_round_delivered = state->delivered;

        } else if (state->probe_rtt_done_stamp) {
            if (state->round_start) {
                state->probe_rtt_round_done = 1;
            }

            if (state->probe_rtt_round_done
                && now >= state->probe_rtt_done_stamp)
            {
                state->min_rtt_stamp = now;
                state->congestion_window = ngx_max(
                    state->congestion_window, state->prior_cwnd);
                cg->window = (size_t) state->congestion_window;

                if (state->full_bw_reached) {
                    ngx_quic_bbr_reset_probe_bw(cg, conf);
                } else {
                    state->mode = BBR_STARTUP;
                }
            }
        }
    }
}


static void
ngx_quic_bbr_update_gains(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    switch (state->mode) {
    case BBR_STARTUP:
        state->pacing_gain = conf->high_gain;
        state->cwnd_gain = conf->startup_cwnd_gain;
        break;

    case BBR_DRAIN:
        state->pacing_gain = conf->drain_gain;
        state->cwnd_gain = conf->startup_cwnd_gain;
        break;

    case BBR_PROBE_BW:
        state->pacing_gain = state->lt_use_bw ? NGX_QUIC_BBR_UNIT:
                               ngx_quic_bbr_pacing_gain[state->cycle_idx];
        state->cwnd_gain = conf->cwnd_gain;
        break;

    case BBR_PROBE_RTT:
        state->pacing_gain = NGX_QUIC_BBR_UNIT;
        state->cwnd_gain = NGX_QUIC_BBR_UNIT;
        break;
    }
}


static void
ngx_quic_bbr_reset_probe_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->mode = BBR_PROBE_BW;

    if (conf->cycle_rand == 0) {
        state->cycle_idx = 0;

    } else {
        state->cycle_idx = ngx_random() % (ngx_uint_t) conf->cycle_rand;

        if (state->cycle_idx >= 1) {
            state->cycle_idx++;
        }
    }

    if (state->cycle_idx >= NGX_QUIC_BBR_CYCLE_LEN) {
        state->cycle_idx = 0;
    }

    state->cycle_stamp = ngx_current_msec;
}


static void
ngx_quic_bbr_advance_cycle(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->cycle_idx = (state->cycle_idx + 1) & (NGX_QUIC_BBR_CYCLE_LEN
                                                     - 1);
    state->cycle_stamp = ngx_current_msec;
}


static void
ngx_quic_bbr_update_cycle(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_uint_t losses,
    uint64_t prior_in_flight)
{
    ngx_uint_t             full_length, advance;
    uint64_t               target;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->mode != BBR_PROBE_BW) {
        return;
    }

    full_length = ngx_current_msec - state->cycle_stamp > state->min_rtt;
    advance = 0;
    target = ngx_quic_bbr_inflight(cg, conf, ngx_quic_bbr_max_bw(cg, conf),
                                    state->pacing_gain);

    if (state->pacing_gain == NGX_QUIC_BBR_UNIT) {
        advance = full_length;

    } else if (state->pacing_gain > NGX_QUIC_BBR_UNIT) {
        advance = full_length && (losses || prior_in_flight >= target);

    } else {
        advance = full_length
                  || cg->in_flight <= ngx_quic_bbr_inflight(cg, conf,
                                      ngx_quic_bbr_max_bw(cg, conf),
                                      NGX_QUIC_BBR_UNIT);
    }

    if (advance) {
        if (conf->drain_to_target
            && state->pacing_gain < NGX_QUIC_BBR_UNIT
            && cg->in_flight > ngx_quic_bbr_inflight(cg, conf,
                             ngx_quic_bbr_max_bw(cg, conf),
                             NGX_QUIC_BBR_UNIT))
        {
            return;
        }

        ngx_quic_bbr_advance_cycle(cg);
    }
}


static ngx_uint_t
ngx_quic_bbr_set_cwnd_to_recover_or_restore(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    uint64_t               cwnd;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    cwnd = state->congestion_window;

    if (state->packet_conservation == BBR_RECOVERY_NOT_IN_RECOVERY) {
        state->recovery_window = 0;

        if (state->loss_in_round > 0) {
            cwnd = (state->loss_in_round >= cwnd) ? cg->mtu:
                   cwnd - state->loss_in_round;
            state->loss_in_round = 0;
        }

        state->congestion_window = cwnd;
        return 0;
    }

    if (state->packet_conservation == BBR_RECOVERY_CONSERVATION
        && sample->prior_delivered > state->recovery_delivered)
    {
        state->packet_conservation = BBR_RECOVERY_GROWTH;
    }

    if (state->packet_conservation == BBR_RECOVERY_GROWTH
        && state->loss_in_round == 0
        && state->recovery_pnum != NGX_QUIC_UNSET_PN
        && sample->packet_number > state->recovery_pnum)
    {
        state->packet_conservation = BBR_RECOVERY_NOT_IN_RECOVERY;
        state->recovery_delivered = 0;
        state->recovery_pnum = NGX_QUIC_UNSET_PN;
        state->recovery_window = 0;

        /* Restore cwnd to at least prior_cwnd (pre-recovery level).
           This matches Google tcp_bbr.c recovery exit:
           bbr->prior_cwnd = max(bbr->prior_cwnd, cwnd); cwnd = bbr->prior_cwnd;
           Without this, cwnd jumps to the full BDP target after recovery,
           causing re-congestion oscillation on lossy networks. */
        state->prior_cwnd = ngx_max(state->prior_cwnd,
                                       state->congestion_window);
        state->congestion_window = state->prior_cwnd;
        return 0;
    }

    if (state->recovery_window == 0) {
        state->next_round_delivered = state->delivered;
        cwnd = cg->in_flight + sample->acked;
        state->recovery_window = ngx_max(cwnd,
            (uint64_t) conf->cwnd_min_target * cg->mtu);
        return 1;
    }

    if (state->loss_in_round > 0) {
        if (state->recovery_window >= state->loss_in_round) {
            state->recovery_window -= state->loss_in_round;

        } else {
            state->recovery_window = cg->mtu;
        }

        /* Also reduce congestion_window to match Google's behavior:
           cwnd = max(cwnd - losses, 1).
           Without this, congestion_window stays at the full BDP target
           during recovery and jumps back on exit. */
        if (state->congestion_window >= state->loss_in_round) {
            state->congestion_window -= state->loss_in_round;

        } else {
            state->congestion_window = cg->mtu;
        }
    }

    if (state->packet_conservation == BBR_RECOVERY_GROWTH) {
        state->recovery_window += sample->acked;
    }

    state->recovery_window = ngx_max(state->recovery_window,
                                       cg->in_flight + sample->acked);
    state->recovery_window = ngx_max(state->recovery_window,
                                       (uint64_t) conf->cwnd_min_target
                                       * cg->mtu);
    state->loss_in_round = 0;

    if (state->packet_conservation != BBR_RECOVERY_NOT_IN_RECOVERY) {
        return 1;
    }

    state->congestion_window = cwnd;
    return 0;
}


static void
ngx_quic_bbr_cap_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    uint64_t               max_cwnd;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->congestion_window = ngx_max(state->congestion_window,
        (uint64_t) conf->cwnd_min_target * cg->mtu);

    if (state->mode == BBR_PROBE_RTT) {
        state->congestion_window = ngx_min(state->congestion_window,
            (uint64_t) conf->cwnd_min_target * cg->mtu);
    }

    if (conf->max_cwnd_packets > 0) {
        max_cwnd = (uint64_t) conf->max_cwnd_packets * cg->mtu;
        state->congestion_window = ngx_min(state->congestion_window,
                                             max_cwnd);
    }
}


static void
ngx_quic_bbr_set_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    uint64_t               target, aggr;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (ngx_quic_bbr_set_cwnd_to_recover_or_restore(cg, conf, sample)) {
        /* in recovery: continue to compute target cwnd below;
           the effective window will be min(target, recovery_window)
           applied at the end of this function */
    }

    if (sample->acked == 0) {
        goto done;
    }

    target = ngx_quic_bbr_bdp(cg, conf, ngx_quic_bbr_bw(cg, conf),
                               state->cwnd_gain);

    if (state->full_bw_reached) {
        aggr = ngx_max(state->extra_acked[0], state->extra_acked[1]);
        aggr = aggr * conf->extra_acked_gain / NGX_QUIC_BBR_UNIT;
        if (conf->extra_acked_max_us > 0) {
            aggr = ngx_min(aggr, ngx_quic_bbr_bw(cg, conf)
                                 * conf->extra_acked_max_us / 1000000);
        }
        target += aggr;

    } else if (conf->enable_ack_aggregation_startup) {
        target += state->extra_acked[state->extra_acked_win_idx];
    }

    target = ngx_quic_bbr_quantize(cg, conf, target);

    if (state->full_bw_reached) {
        state->congestion_window = ngx_min(
            (uint64_t) state->congestion_window + sample->acked, target);

    } else if ((uint64_t) state->congestion_window < target
               || state->delivered < (uint64_t) conf->initial_cwnd_packets
                                       * cg->mtu)
    {
        state->congestion_window += sample->acked;
    }

done:

    ngx_quic_bbr_cap_cwnd(cg, conf);
    cg->window = state->congestion_window;

    if (state->packet_conservation != BBR_RECOVERY_NOT_IN_RECOVERY) {
        cg->window = ngx_min(state->congestion_window,
                             state->recovery_window);
    }
}


static void
ngx_quic_bbr_set_pacing_rate(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    uint64_t               rate, bw, min_rate;
    ngx_msec_t             rtt;
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    bw = ngx_quic_bbr_bw(cg, conf);

    if (bw == 0) {
        rtt = (state->min_rtt_stamp == 0) ? NGX_QUIC_BBR_INITIAL_RTT :
              ngx_max(state->min_rtt, (ngx_msec_t) 1);
        bw = (uint64_t) conf->initial_cwnd_packets * cg->mtu
             * 1000 / rtt;
    }

    rate = bw * state->pacing_gain / NGX_QUIC_BBR_UNIT;
    rate = rate * (100 - conf->pacing_margin_percent) / 100;

    /* minimum rate floor: 65536 bytes/s (matches sing-quic and hy2) */
    min_rate = 65536;
    if (rate < min_rate) {
        rate = min_rate;
    }

    if (state->full_bw_reached || rate > state->pacing_rate) {
        state->pacing_rate = rate;
    }
}


ngx_msec_t
ngx_quic_bbr_pacing_delay(ngx_connection_t *c)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    ngx_msec_t                    delay;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->next_send_time == 0 || state->pacing_rate == 0) {
        return 0;
    }

    delay = state->next_send_time;

    if ((ngx_msec_int_t) (ngx_current_msec - delay) >= 0) {
        return 0;
    }

    return delay - ngx_current_msec;
}


static void
ngx_quic_bbr_init_rate_sample(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f, ngx_msec_t now, size_t in_flight)
{
    ngx_quic_congestion_t   *cg;
    ngx_quic_bbr_state_t    *state;

    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    f->prior_delivered = state->delivered;
    f->prior_delivered_time = state->delivered_time;
    f->first_sent_time = state->first_sent_time;
    f->tx_in_flight = in_flight;

    /* mark app-limited if no stream data pending */
    f->is_app_limited = (ngx_queue_empty(&qc->streams.uninitialized)
                            && ngx_queue_empty(&qc->streams.free));
}


static void
ngx_quic_bbr_update_pacing(ngx_quic_congestion_t *cg,
    size_t sent, ngx_msec_t now)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               rate;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->pacing_rate == 0) {
        return;
    }

    /* accumulate pacing debt */
    state->pacing_debt += sent;

    /* compute next send time based on debt and pacing rate */
    if (state->pacing_debt > 0) {
        /* delay = debt / rate (bytes / bytes-per-ms) */
        rate = state->pacing_rate / 1000;
        if (rate == 0) {
            rate = 1;
        }
        state->next_send_time = now + (state->pacing_debt + rate - 1) / rate;
    }
}


static void
ngx_quic_bbr_set_pacing_timer(ngx_quic_connection_t *qc,
    ngx_msec_t delay)
{
    ngx_msec_t  timer;

    if (delay == 0) {
        return;
    }

    /* The output.c calls ngx_quic_cc_set_pacing_timer when
       pacing_delay returns non-zero. We set the push event timer
       to fire after the specified delay, which will trigger
       another output attempt. */
    timer = ngx_current_msec + delay;

    if (!qc->push.timer_set
        || (ngx_msec_int_t) (timer - qc->push.timer.key) < 0)
    {
        ngx_add_timer(&qc->push, delay);
    }
}


/* BBRv3 bandwidth/congestion model -- faithful ports of tcp_bbr.c */

/*
 * Return the windowed max recent bandwidth sample.
 * Matches tcp_bbr.c: bbr_max_bw() -> max(bbr->bw_hi[0], bbr->bw_hi[1])
 */
static uint64_t
ngx_quic_bbr_v3_max_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    return ngx_max(state->bw_hi[0], state->bw_hi[1]);
}


/*
 * Return the estimated bandwidth of the path.
 * Matches tcp_bbr.c: bbr_bw() -> min(bbr_max_bw(sk), bbr->bw_lo)
 * Note: bw_lo defaults to ~0ULL (no constraint), so min naturally returns max_bw.
 */
static uint64_t
ngx_quic_bbr_v3_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    return ngx_min(ngx_quic_bbr_v3_max_bw(cg, conf), state->bw_lo);
}


/*
 * Incorporate a new bw sample into the current window of the max filter.
 * Matches tcp_bbr.c: bbr_take_max_bw_sample() -> bbr->bw_hi[1] = max(bw, bbr->bw_hi[1])
 */
static void
ngx_quic_bbr_v3_take_max_bw_sample(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->bw_hi[1] = ngx_max(bw, state->bw_hi[1]);
}


/*
 * Keep max of last 1-2 cycles. Each PROBE_BW cycle, flip filter window.
 * Matches tcp_bbr.c: bbr_advance_max_bw_filter()
 */
static void
ngx_quic_bbr_v3_advance_max_bw_filter(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (!state->bw_hi[1]) {
        return;  /* no samples in this window; remember old window */
    }

    state->bw_hi[0] = state->bw_hi[1];
    state->bw_hi[1] = 0;
}


/*
 * Reset the estimator for reaching full bandwidth based on bw plateau.
 * Matches tcp_bbr.c: bbr_reset_full_bw()
 */
static void
ngx_quic_bbr_v3_reset_full_bw(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->full_bw = 0;
    state->full_bw_cnt = 0;
    state->full_bw_now = 0;
}


/*
 * How much do we want in flight? Our BDP, unless congestion cut cwnd.
 * Matches tcp_bbr.c: bbr_target_inflight() -> min(bbr_inflight(sk, bbr_bw(sk), BBR_UNIT), snd_cwnd)
 */
static uint64_t
ngx_quic_bbr_v3_target_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    uint64_t               bdp;

    bdp = ngx_quic_bbr_v3_inflight(cg, conf,
              ngx_quic_bbr_v3_bw(cg, conf), NGX_QUIC_BBR_UNIT);

    return ngx_min(bdp, (uint64_t) cg->window);
}


/*
 * Are we probing bandwidth (STARTUP, or PROBE_BW REFILL/UP)?
 * Matches tcp_bbr.c: bbr_is_probing_bandwidth()
 */
static ngx_uint_t
ngx_quic_bbr_v3_is_probing_bandwidth(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    return (state->mode == BBR_STARTUP)
        || (state->mode == BBR_PROBE_BW
            && (state->cycle_idx == BBR_BW_PROBE_REFILL
                || state->cycle_idx == BBR_BW_PROBE_UP));
}


static uint64_t
ngx_quic_bbr_v3_inflight(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t bw, ngx_uint_t gain)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               bdp;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (bw == 0) {
        return (uint64_t) conf->initial_cwnd_packets * cg->mtu;
    }

    bdp = bw * ngx_max(state->min_rtt, (ngx_msec_t) 1) / 1000;
    bdp = (bdp * gain + NGX_QUIC_BBR_UNIT - 1) / NGX_QUIC_BBR_UNIT;

    return ngx_max(bdp, (uint64_t) conf->cwnd_min_target * cg->mtu);
}


/*
 * With pacing at lower layers, there's often less data "in the network" than
 * "in flight". Return inflight_hi minus headroom for fairness headroom.
 * Matches tcp_bbr.c: bbr_inflight_with_headroom()
 */
static uint64_t
ngx_quic_bbr_v3_inflight_with_headroom(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               headroom;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->inflight_hi == ~0ULL) {
        return ~0ULL;
    }

    headroom = state->inflight_hi * (uint64_t) conf->inflight_headroom
               / NGX_QUIC_BBR_UNIT;
    headroom = ngx_max(headroom, (uint64_t) 1);

    return ngx_max(state->inflight_hi - headroom,
                   (uint64_t) conf->cwnd_min_target * cg->mtu);
}


/*
 * Init lower bounds if not inited yet.
 * Matches tcp_bbr.c: bbr_init_lower_bounds()
 */
static void
ngx_quic_bbr_v3_init_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_uint_t init_bw)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (init_bw && state->bw_lo == ~0ULL) {
        state->bw_lo = ngx_quic_bbr_v3_max_bw(cg, conf);
    }

    if (state->inflight_lo == ~0ULL) {
        state->inflight_lo = state->congestion_window;
    }
}


/*
 * Reduce bw and inflight to (1 - beta).
 * Matches tcp_bbr.c: bbr_loss_lower_bounds()
 */
static void
ngx_quic_bbr_v3_loss_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t *bw_out,
    uint64_t *inflight_out)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               loss_cut;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    loss_cut = NGX_QUIC_BBR_UNIT - (uint64_t) conf->beta;

    *bw_out = ngx_max(state->bw_latest,
                       state->bw_lo * loss_cut / NGX_QUIC_BBR_UNIT);
    *inflight_out = ngx_max(state->inflight_latest,
                             state->inflight_lo * loss_cut / NGX_QUIC_BBR_UNIT);
}


/*
 * How should we multiplicatively cut inflight limits based on ECN?
 * Matches tcp_bbr.c: bbr_ecn_cut() and bbr_ecn_lower_bounds()
 */
static void
ngx_quic_bbr_v3_ecn_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t *inflight_out)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               ecn_cut;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    ecn_cut = NGX_QUIC_BBR_UNIT
              - (state->ecn_alpha * (uint64_t) conf->ecn_factor
                 / NGX_QUIC_BBR_UNIT);

    *inflight_out = state->inflight_lo * ecn_cut / NGX_QUIC_BBR_UNIT;
}


/*
 * Estimate a short-term lower bound on capacity. When not probing bw and
 * seeing loss/ECN, cut bw_lo and inflight_lo multiplicatively.
 * Matches tcp_bbr.c: bbr_adapt_lower_bounds()
 */
static void
ngx_quic_bbr_v3_adapt_lower_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               ecn_inflight_lo;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    /* We only use lower-bound estimates when not probing bw. */
    if (ngx_quic_bbr_v3_is_probing_bandwidth(cg, conf)) {
        return;
    }

    ecn_inflight_lo = ~0ULL;

    /* ECN response */
    if (state->ecn_in_round && conf->ecn_factor) {
        ngx_quic_bbr_v3_init_lower_bounds(cg, conf, 0);
        ngx_quic_bbr_v3_ecn_lower_bounds(cg, conf, &ecn_inflight_lo);
    }

    /* Loss response */
    if (state->loss_in_round) {
        ngx_quic_bbr_v3_init_lower_bounds(cg, conf, 1);
        ngx_quic_bbr_v3_loss_lower_bounds(cg, conf,
                                            &state->bw_lo,
                                            &state->inflight_lo);
    }

    /* Adjust to the lower of the levels implied by loss/ECN */
    state->inflight_lo = ngx_min(state->inflight_lo, ecn_inflight_lo);
    state->bw_lo = ngx_max((uint64_t) 1, state->bw_lo);
}


/*
 * Reset any short-term lower-bound adaptation to congestion.
 * Matches tcp_bbr.c: bbr_reset_lower_bounds()
 */
static void
ngx_quic_bbr_v3_reset_lower_bounds(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->bw_lo = ~0ULL;
    state->inflight_lo = ~0ULL;
}


/*
 * After bw probing (STARTUP/PROBE_UP), reset signals before entering a
 * state machine phase where we adapt our lower bound based on congestion.
 * Matches tcp_bbr.c: bbr_reset_congestion_signals()
 */
static void
ngx_quic_bbr_v3_reset_congestion_signals(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->loss_in_round = 0;
    state->ecn_in_round = 0;
    state->loss_in_cycle = 0;
    state->ecn_in_cycle = 0;
    state->bw_latest = 0;
    state->inflight_latest = 0;
}


/*
 * Update ecn_alpha as EWMA of CE/delivered ratio.
 * Matches tcp_bbr.c: bbr_update_ecn_alpha()
 */
static void
ngx_quic_bbr_v3_update_ecn_alpha(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               delivered, delivered_ce, alpha, ce_ratio;
    ngx_uint_t             gain;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (!state->ecn_eligible || conf->ecn_factor == 0) {
        return;
    }

    delivered = state->delivered - state->alpha_last_delivered;
    delivered_ce = state->delivered_ce - state->alpha_last_delivered_ce;

    if (delivered == 0) {
        return;
    }

    ce_ratio = (delivered_ce << NGX_QUIC_BBR_SCALE) / delivered;

    gain = (ngx_uint_t) conf->ecn_alpha_gain;
    alpha = ((NGX_QUIC_BBR_UNIT - gain) * state->ecn_alpha)
            >> NGX_QUIC_BBR_SCALE;
    alpha += (gain * ce_ratio) >> NGX_QUIC_BBR_SCALE;
    state->ecn_alpha = ngx_min(alpha, (uint64_t) NGX_QUIC_BBR_UNIT);

    state->alpha_last_delivered = state->delivered;
    state->alpha_last_delivered_ce = state->delivered_ce;
}


/*
 * Exit STARTUP upon N consecutive rounds with ECN mark rate > ecn_thresh.
 * Matches tcp_bbr.c: bbr_check_ecn_too_high_in_startup()
 */
static void
ngx_quic_bbr_v3_check_ecn_too_high_in_startup(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               ce_ratio;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->full_bw_reached || !state->ecn_eligible
        || conf->full_ecn_cnt == 0 || conf->ecn_thresh == 0)
    {
        return;
    }

    if (state->delivered == 0) {
        return;
    }

    ce_ratio = (state->delivered_ce << NGX_QUIC_BBR_SCALE)
               / state->delivered;

    if (ce_ratio >= (uint64_t) conf->ecn_thresh) {
        state->startup_ecn_rounds++;
    } else {
        state->startup_ecn_rounds = 0;
    }

    if (state->startup_ecn_rounds >= (ngx_uint_t) conf->full_ecn_cnt) {
        state->full_bw_reached = 1;
        state->inflight_hi = ngx_max(
            ngx_quic_bbr_v3_inflight(cg, conf,
                                      ngx_quic_bbr_v3_max_bw(cg, conf),
                                      NGX_QUIC_BBR_UNIT),
            state->inflight_latest);
    }
}

static void
ngx_quic_bbr_v3_start_bw_probe_down(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    ngx_quic_bbr_v3_reset_congestion_signals(cg);
    state->bw_probe_up_cnt = ~0ULL;
    ngx_quic_bbr_v3_pick_probe_wait(cg, conf);
    state->cycle_stamp = ngx_current_msec;
    state->ack_phase = BBR_ACKS_PROBE_STOPPING;
    state->next_round_delivered = state->delivered;
    state->cycle_idx = BBR_BW_PROBE_DOWN;
}


static ngx_uint_t
ngx_quic_bbr_v3_is_inflight_too_high(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               loss_thresh_val;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (sample->lost_packets > 0 && sample->prior_in_flight > 0) {
        loss_thresh_val = sample->prior_in_flight
                          * (uint64_t) conf->loss_thresh
                          / NGX_QUIC_BBR_UNIT;

        if (sample->lost_packets > loss_thresh_val) {
            return 1;
        }
    }

    /* ECN check */
    if (sample->delivered_ce > 0 && sample->delivered > 0
        && state->ecn_eligible && conf->ecn_thresh > 0)
    {
        uint64_t  ecn_thresh_val;

        ecn_thresh_val = sample->delivered
                         * (uint64_t) conf->ecn_thresh
                         / NGX_QUIC_BBR_UNIT;

        if (sample->delivered_ce > ecn_thresh_val) {
            return 1;
        }
    }

    return 0;
}


static void
ngx_quic_bbr_v3_handle_inflight_too_high(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               target;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->prev_probe_too_high = 1;
    state->bw_probe_samples = 0;

    if (!sample->is_app_limited) {
        target = ngx_quic_bbr_v3_target_inflight(cg, conf);
        state->inflight_hi = ngx_max(sample->prior_in_flight,
            target * (NGX_QUIC_BBR_UNIT - (uint64_t) conf->beta)
                     / NGX_QUIC_BBR_UNIT);
    }

    if (state->mode == BBR_PROBE_BW
        && state->cycle_idx == BBR_BW_PROBE_UP)
    {
        ngx_quic_bbr_v3_start_bw_probe_down(cg, conf);
    }
}


static void
ngx_quic_bbr_v3_probe_inflight_hi_upward(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               delta;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->congestion_window < state->inflight_hi) {
        return;
    }

    state->bw_probe_up_acks += sample->acked;

    if (state->bw_probe_up_acks >= state->bw_probe_up_cnt) {
        delta = state->bw_probe_up_acks / state->bw_probe_up_cnt;
        state->bw_probe_up_acks -= delta * state->bw_probe_up_cnt;
        state->inflight_hi += delta;
        state->try_fast_path = 0;
    }

    if (state->round_start) {
        ngx_quic_bbr_v3_raise_inflight_hi_slope(cg, conf);
    }
}


static ngx_uint_t
ngx_quic_bbr_v3_is_reno_coexistence_probe_time(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               target;
    uint32_t               rounds;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    target = ngx_quic_bbr_v3_inflight(cg, conf,
                 ngx_quic_bbr_v3_bw(cg, conf), NGX_QUIC_BBR_UNIT)
             / cg->mtu;
    rounds = (uint32_t) ngx_min((uint64_t) conf->bw_probe_max_rounds, target);

    return state->rounds_since_probe >= rounds;
}


static void
ngx_quic_bbr_v3_pick_probe_wait(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->rounds_since_probe = (ngx_uint_t) (ngx_random()
        % (ngx_uint_t) conf->bw_probe_rand_rounds);
    state->probe_wait_us = (uint64_t) conf->bw_probe_base_us
        + (uint64_t) (ngx_random()
                      % (ngx_uint_t) conf->bw_probe_rand_us);
}


static void
ngx_quic_bbr_v3_raise_inflight_hi_slope(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               growth, cnt;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    growth = 1ULL << state->bw_probe_up_rounds;
    state->bw_probe_up_rounds = ngx_min(state->bw_probe_up_rounds + 1, 30);
    cnt = state->congestion_window / cg->mtu / growth;
    cnt = ngx_max(cnt, 1ULL);
    state->bw_probe_up_cnt = cnt;
    state->bw_probe_up_acks = 0;
}


static void
ngx_quic_bbr_v3_start_bw_probe_refill(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_uint_t bw_probe_up_rounds)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    ngx_quic_bbr_v3_reset_lower_bounds(cg);
    state->bw_probe_up_rounds = bw_probe_up_rounds;
    state->bw_probe_up_acks = 0;
    state->stopped_risky_probe = 0;
    state->ack_phase = BBR_ACKS_REFILLING;
    state->next_round_delivered = state->delivered;
    state->cycle_idx = BBR_BW_PROBE_REFILL;
    state->try_fast_path = 0;
}


static void
ngx_quic_bbr_v3_start_bw_probe_up(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->ack_phase = BBR_ACKS_PROBE_STARTING;
    state->next_round_delivered = state->delivered;
    state->cycle_stamp = ngx_current_msec;
    ngx_quic_bbr_v3_reset_full_bw(cg);
    state->full_bw = sample->bandwidth;
    state->cycle_idx = BBR_BW_PROBE_UP;
    ngx_quic_bbr_v3_raise_inflight_hi_slope(cg, conf);
}


static void
ngx_quic_bbr_v3_start_bw_probe_cruise(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->inflight_lo != ~0ULL) {
        state->inflight_lo = ngx_min(state->inflight_lo, state->inflight_hi);
    }

    state->cycle_idx = BBR_BW_PROBE_CRUISE;
    state->try_fast_path = 0;
}


/* BBRv3 PROBE_BW cycle orchestration -- higher-level entry points */

static ngx_uint_t
ngx_quic_bbr_v3_check_time_to_probe_bw(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    ngx_msec_t             now;
    uint64_t               reprobe;
    ngx_uint_t             n;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    /* ECN-based reprobe */
    if (conf->ecn_reprobe_gain > 0
        && state->ecn_eligible
        && state->ecn_in_cycle
        && !state->loss_in_cycle)
    {
        reprobe = state->inflight_hi
                  * (uint64_t) conf->ecn_reprobe_gain
                  / NGX_QUIC_BBR_UNIT;

        n = 0;
        while ((1ULL << n) < reprobe && n < 30) {
            n++;
        }

        ngx_quic_bbr_v3_start_bw_probe_refill(cg, conf, n);
        return 1;
    }

    /* Timer-based or Reno-coexistence probe */
    now = ngx_current_msec;

    if (now - state->cycle_stamp
            > (ngx_msec_t) (state->probe_wait_us / 1000)
        || ngx_quic_bbr_v3_is_reno_coexistence_probe_time(cg, conf))
    {
        ngx_quic_bbr_v3_start_bw_probe_refill(cg, conf, 0);
        return 1;
    }

    return 0;
}


static ngx_uint_t
ngx_quic_bbr_v3_check_time_to_cruise(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t inflight, uint64_t bw)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    (void) state;

    if (inflight > ngx_quic_bbr_v3_inflight_with_headroom(cg, conf)) {
        return 0;
    }

    return inflight <= ngx_quic_bbr_v3_inflight(cg, conf, bw,
                                                   NGX_QUIC_BBR_UNIT);
}


static void
ngx_quic_bbr_v3_adapt_upper_bounds(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->ack_phase == BBR_ACKS_PROBE_STARTING
        && state->round_start)
    {
        state->ack_phase = BBR_ACKS_PROBE_FEEDBACK;
    }

    if (state->ack_phase == BBR_ACKS_PROBE_STOPPING
        && state->round_start)
    {
        state->bw_probe_samples = 0;
        state->ack_phase = BBR_ACKS_INIT;

        if (state->mode == BBR_PROBE_BW && !sample->is_app_limited) {
            ngx_quic_bbr_v3_advance_max_bw_filter(cg);
        }

        if (state->mode == BBR_PROBE_BW
            && state->stopped_risky_probe
            && !state->prev_probe_too_high)
        {
            ngx_quic_bbr_v3_start_bw_probe_refill(cg, conf, 0);
            return;
        }
    }

    if (ngx_quic_bbr_v3_is_inflight_too_high(cg, conf, sample)) {
        if (state->bw_probe_samples) {
            ngx_quic_bbr_v3_handle_inflight_too_high(cg, conf, sample);
        }

    } else {
        if (state->inflight_hi != ~0ULL) {
            if (sample->prior_in_flight > state->inflight_hi) {
                state->inflight_hi = sample->prior_in_flight;
            }

            if (state->mode == BBR_PROBE_BW
                && state->cycle_idx == BBR_BW_PROBE_UP)
            {
                ngx_quic_bbr_v3_probe_inflight_hi_upward(cg, conf, sample);
            }
        }
    }
}


static void
ngx_quic_bbr_v3_update_cycle_phase(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               inflight;
    uint64_t               bw;
    ngx_uint_t             is_bw_probe_done;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (!state->full_bw_reached) {
        return;
    }

    ngx_quic_bbr_v3_adapt_upper_bounds(cg, conf, sample);

    /* adapt_upper_bounds may change mode; re-read */
    if (state->mode != BBR_PROBE_BW) {
        return;
    }

    inflight = cg->in_flight;
    bw = ngx_quic_bbr_v3_max_bw(cg, conf);

    switch (state->cycle_idx) {

    case BBR_BW_PROBE_CRUISE:
        if (ngx_quic_bbr_v3_check_time_to_probe_bw(cg, conf)) {
            return;
        }
        break;

    case BBR_BW_PROBE_REFILL:
        if (state->round_start) {
            state->bw_probe_samples = 1;
            ngx_quic_bbr_v3_start_bw_probe_up(cg, conf, sample);
        }
        break;

    case BBR_BW_PROBE_UP:
        is_bw_probe_done = 0;

        if (state->prev_probe_too_high
            && inflight >= state->inflight_hi)
        {
            state->stopped_risky_probe = 1;
            is_bw_probe_done = 1;

        } else if (state->full_bw_now) {
            is_bw_probe_done = 1;

        } else if (state->congestion_window >= state->inflight_hi) {
            state->full_bw = sample->bandwidth;
            state->full_bw_cnt = 0;
        }

        if (is_bw_probe_done) {
            state->prev_probe_too_high = 0;
            ngx_quic_bbr_v3_start_bw_probe_down(cg, conf);
        }
        break;

    case BBR_BW_PROBE_DOWN:
        if (ngx_quic_bbr_v3_check_time_to_probe_bw(cg, conf)) {
            return;
        }

        if (ngx_quic_bbr_v3_check_time_to_cruise(cg, conf, inflight, bw))
        {
            ngx_quic_bbr_v3_start_bw_probe_cruise(cg, conf);
        }
        break;

    default:
        break;
    }
}


/* BBRv3 model update and control functions */


static void
ngx_quic_bbr_v3_calculate_bw_sample(ngx_quic_congestion_t *cg,
    bbr_rate_sample_t *sample)
{
    sample->bandwidth = 0;

    if (sample->interval > 0 && sample->delivered > 0) {
        sample->bandwidth = sample->delivered * 1000 / sample->interval;
    }
}


static uint64_t
ngx_quic_bbr_v3_update_round_start(ngx_quic_congestion_t *cg,
    ngx_quic_frame_t *f, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               round_delivered;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    (void) f;

    round_delivered = 0;
    state->round_start = 0;

    if (sample->interval > 0
        && sample->prior_delivered >= state->next_round_delivered)
    {
        round_delivered = state->delivered - state->next_round_delivered;
        state->next_round_delivered = state->delivered;
        state->round_start = 1;
    }

    return round_delivered;
}


static void
ngx_quic_bbr_v3_update_ack_aggregation(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               elapsed, bw, expected, extra;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (conf->extra_acked_gain == 0 || sample->acked == 0
        || sample->delivered == 0 || sample->interval == 0)
    {
        return;
    }

    if (state->round_start) {
        state->extra_acked_win_rtts = ngx_min((ngx_uint_t) 0x1F,
                                        state->extra_acked_win_rtts + 1);

        if (state->extra_acked_win_rtts
            >= (ngx_uint_t) conf->extra_acked_win_rtts)
        {
            state->extra_acked_win_rtts = 0;
            state->extra_acked_win_idx ^= 1;
            state->extra_acked[state->extra_acked_win_idx] = 0;
        }
    }

    elapsed = state->delivered_time - state->ack_epoch_stamp;
    bw = ngx_quic_bbr_v3_bw(cg, conf);
    expected = bw * elapsed / 1000;

    if (state->ack_epoch_acked <= expected
        || (conf->ack_epoch_acked_reset_thresh > 0
            && state->ack_epoch_acked + sample->acked
               >= (uint64_t) conf->ack_epoch_acked_reset_thresh * cg->mtu))
    {
        state->ack_epoch_acked = 0;
        state->ack_epoch_stamp = state->delivered_time;
        expected = 0;
    }

    state->ack_epoch_acked += sample->acked;
    extra = state->ack_epoch_acked - expected;
    extra = ngx_min(extra, (uint64_t) state->congestion_window);

    if (extra > state->extra_acked[state->extra_acked_win_idx]) {
        state->extra_acked[state->extra_acked_win_idx] = extra;
    }
}


/*
 * Check if we've reached full bandwidth in STARTUP.
 * Matches tcp_bbr.c: bbr_check_full_bw_reached()
 *
 * Uses ctx_sample_bw (the bandwidth from the current rate sample, i.e.
 * ctx->sample_bw in the kernel) rather than sample->bandwidth directly.
 */
static void
ngx_quic_bbr_v3_check_full_bw_reached(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    uint64_t ctx_sample_bw)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               bw_thresh;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    (void) sample;

    if (state->full_bw_now || sample->is_app_limited) {
        return;
    }

    bw_thresh = state->full_bw * (uint64_t) conf->full_bw_thresh
                / NGX_QUIC_BBR_UNIT;

    if (ctx_sample_bw >= bw_thresh) {
        ngx_quic_bbr_v3_reset_full_bw(cg);
        state->full_bw = ctx_sample_bw;
        return;
    }

    if (!state->round_start) {
        return;
    }

    state->full_bw_cnt++;
    state->full_bw_now = (state->full_bw_cnt
                          >= (ngx_uint_t) conf->full_bw_cnt);
    state->full_bw_reached |= state->full_bw_now;
}


/*
 * Handle the case where queue is too high in STARTUP: mark full_bw_reached
 * and set inflight_hi to protect the network.
 * Matches tcp_bbr.c: bbr_handle_queue_too_high_in_startup()
 */
static void
ngx_quic_bbr_v3_handle_queue_too_high_in_startup(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               bdp;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->full_bw_reached = 1;

    bdp = ngx_quic_bbr_v3_inflight(cg, conf,
              ngx_quic_bbr_v3_max_bw(cg, conf), NGX_QUIC_BBR_UNIT);
    state->inflight_hi = ngx_max(bdp, state->inflight_latest);
}


/*
 * Check if loss is too high during STARTUP. If so, declare full bandwidth
 * reached and cap inflight.
 * Matches tcp_bbr.c: bbr_check_loss_too_high_in_startup()
 */
static void
ngx_quic_bbr_v3_check_loss_too_high_in_startup(
    ngx_quic_congestion_t *cg, const ngx_quic_bbr_conf_t *conf,
    bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->full_bw_reached) {
        return;
    }

    if (sample->lost_packets > 0
        && state->loss_events_in_round < 0xf)
    {
        state->loss_events_in_round++;
    }

    if (conf->full_loss_cnt > 0
        && state->loss_round_start
        && state->loss_events_in_round
           >= (ngx_uint_t) conf->full_loss_cnt
        && ngx_quic_bbr_v3_is_inflight_too_high(cg, conf, sample))
    {
        ngx_quic_bbr_v3_handle_queue_too_high_in_startup(cg, conf);
    }

    if (state->loss_round_start) {
        state->loss_events_in_round = 0;
    }
}


/*
 * Check if we should transition from STARTUP to DRAIN, or from DRAIN to
 * PROBE_BW. Matches tcp_bbr.c: bbr_check_drain()
 */
static void
ngx_quic_bbr_v3_check_drain(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    (void) sample;

    /* STARTUP -> DRAIN: we've reached full bandwidth, now drain. */
    if (state->mode == BBR_STARTUP && state->full_bw_reached) {
        state->mode = BBR_DRAIN;
        cg->ssthresh = (size_t) ngx_quic_bbr_v3_inflight(cg, conf,
                           ngx_quic_bbr_v3_max_bw(cg, conf),
                           NGX_QUIC_BBR_UNIT);
        ngx_quic_bbr_v3_reset_congestion_signals(cg);
    }

    /* DRAIN -> PROBE_BW: in_flight has drained to BDP target. */
    if (state->mode == BBR_DRAIN
        && cg->in_flight <= ngx_quic_bbr_v3_inflight(cg, conf,
                              ngx_quic_bbr_v3_max_bw(cg, conf),
                              NGX_QUIC_BBR_UNIT))
    {
        state->mode = BBR_PROBE_BW;
        ngx_quic_bbr_v3_start_bw_probe_down(cg, conf);
    }
}


static void
ngx_quic_bbr_v3_update_min_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, ngx_quic_connection_t *qc)
{
    ngx_quic_bbr_state_t  *state;
    ngx_msec_t             now, sample;
    ngx_uint_t             probe_expired, min_expired;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (qc == NULL) {
        return;
    }

    now = ngx_current_msec;
    sample = qc->min_rtt;

    if (sample == NGX_TIMER_INFINITE || sample == 0) {
        return;
    }

    /* Clear idle_restart once we see actual delivery. */
    if (state->delivered > 0) {
        state->idle_restart = 0;
    }

    /* Track probe_rtt_min_us with probe_rtt_win_ms sliding window. */
    probe_expired = (state->probe_rtt_min_stamp != 0
                     && (now - state->probe_rtt_min_stamp
                         > (ngx_msec_t) conf->probe_rtt_win_ms));

    if (state->probe_rtt_min_stamp == 0
        || sample < state->probe_rtt_min_us
        || (probe_expired && sample <= state->probe_rtt_min_us))
    {
        state->probe_rtt_min_us = sample;
        state->probe_rtt_min_stamp = now;
    }

    /* Track min_rtt with min_rtt_win_sec sliding window. */
    min_expired = (state->min_rtt_stamp != 0
                   && (now - state->min_rtt_stamp
                       > (ngx_msec_t) conf->min_rtt_win_sec * 1000));

    if (state->probe_rtt_min_us <= state->min_rtt || min_expired) {
        state->min_rtt = state->probe_rtt_min_us;
        state->min_rtt_stamp = state->probe_rtt_min_stamp;
    }

    /* Enter PROBE_RTT when probe_rtt expired, not restarting from idle,
       and not already in PROBE_RTT. */
    if (conf->probe_rtt_mode_ms > 0
        && probe_expired
        && !state->idle_restart
        && state->mode != BBR_PROBE_RTT)
    {
        state->prev_mode = state->mode;
        state->mode = BBR_PROBE_RTT;
        state->probe_rtt_done_stamp = 0;
        state->ack_phase = BBR_ACKS_PROBE_STOPPING;
        state->next_round_delivered = state->delivered;
        state->prior_cwnd = state->congestion_window;
    }

    /* In PROBE_RTT: arm the done timer once in_flight drops low enough,
       then check for completion. */
    if (state->mode == BBR_PROBE_RTT) {
        if (!state->probe_rtt_done_stamp
            && cg->in_flight <= ngx_quic_bbr_v3_probe_rtt_cwnd(cg, conf))
        {
            state->probe_rtt_done_stamp = now + conf->probe_rtt_mode_ms;
            state->probe_rtt_round_done = 0;
            state->next_round_delivered = state->delivered;
        }

        ngx_quic_bbr_v3_check_probe_rtt_done(cg, conf);
    }
}


/*
 * Check if PROBE_RTT has completed: done timer set, round finished,
 * and enough time has elapsed. If so, update min_rtt_stamp, restore
 * prior_cwnd, and exit PROBE_RTT.
 * Matches tcp_bbr.c: bbr_check_probe_rtt_done()
 */
static void
ngx_quic_bbr_v3_check_probe_rtt_done(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    ngx_msec_t             now;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (!state->probe_rtt_done_stamp) {
        return;
    }

    now = ngx_current_msec;

    if (state->round_start) {
        state->probe_rtt_round_done = 1;
    }

    if (state->probe_rtt_round_done
        && (ngx_msec_int_t) (now - state->probe_rtt_done_stamp) >= 0)
    {
        state->min_rtt_stamp = now;
        state->congestion_window = ngx_max(state->congestion_window,
                                           state->prior_cwnd);
        cg->window = (size_t) state->congestion_window;
        ngx_quic_bbr_v3_exit_probe_rtt(cg, conf);
    }
}


static uint64_t
ngx_quic_bbr_v3_probe_rtt_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    (void) state;

    return ngx_quic_bbr_v3_inflight(cg, conf,
               ngx_quic_bbr_v3_bw(cg, conf),
               (ngx_uint_t) conf->probe_rtt_cwnd_gain);
}


static void
ngx_quic_bbr_v3_exit_probe_rtt(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    ngx_quic_bbr_v3_reset_lower_bounds(cg);

    if (state->full_bw_reached) {
        state->mode = BBR_PROBE_BW;
        ngx_quic_bbr_v3_start_bw_probe_down(cg, conf);
        ngx_quic_bbr_v3_start_bw_probe_cruise(cg, conf);

    } else {
        state->mode = BBR_STARTUP;
    }
}


static void
ngx_quic_bbr_v3_update_gains(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    switch (state->mode) {

    case BBR_STARTUP:
        state->pacing_gain = (ngx_uint_t) conf->startup_pacing_gain;
        state->cwnd_gain = (ngx_uint_t) conf->startup_cwnd_gain;
        break;

    case BBR_DRAIN:
        state->pacing_gain = (ngx_uint_t) conf->drain_gain;
        state->cwnd_gain = (ngx_uint_t) conf->startup_cwnd_gain;
        break;

    case BBR_PROBE_BW:
        state->pacing_gain = ngx_quic_bbr_v3_pacing_gain[state->cycle_idx];
        state->cwnd_gain = (ngx_uint_t) conf->cwnd_gain;

        if (conf->bw_probe_cwnd_gain > 0
            && state->cycle_idx == BBR_BW_PROBE_UP)
        {
            state->cwnd_gain += (ngx_uint_t) conf->bw_probe_cwnd_gain
                                * NGX_QUIC_BBR_UNIT / 4;
        }
        break;

    case BBR_PROBE_RTT:
        state->pacing_gain = NGX_QUIC_BBR_UNIT;
        state->cwnd_gain = NGX_QUIC_BBR_UNIT;
        break;
    }
}


static void
ngx_quic_bbr_v3_set_pacing_rate(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               bw, rate, min_rate;
    ngx_msec_t             rtt;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    bw = ngx_quic_bbr_v3_bw(cg, conf);

    if (bw == 0) {
        rtt = (state->min_rtt_stamp == 0) ? NGX_QUIC_BBR_INITIAL_RTT :
              ngx_max(state->min_rtt, (ngx_msec_t) 1);
        bw = (uint64_t) conf->initial_cwnd_packets * cg->mtu
             * 1000 / rtt;
    }

    rate = bw * state->pacing_gain / NGX_QUIC_BBR_UNIT;
    rate = rate * (100 - (uint64_t) conf->pacing_margin_percent) / 100;

    /* minimum rate floor: 65536 bytes/s (matches sing-quic and hy2) */
    min_rate = 65536;
    if (rate < min_rate) {
        rate = min_rate;
    }

    if (state->full_bw_reached || rate > state->pacing_rate) {
        state->pacing_rate = rate;
    }
}


static void
ngx_quic_bbr_v3_set_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               target_cwnd;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (sample->acked == 0) {
        goto done;
    }

    target_cwnd = ngx_quic_bbr_v3_inflight(cg, conf,
                     ngx_quic_bbr_v3_bw(cg, conf), state->cwnd_gain);
    target_cwnd += ngx_quic_bbr_v3_ack_aggregation_cwnd(cg, conf);
    target_cwnd = ngx_quic_bbr_v3_quantize(cg, conf, target_cwnd);

    state->try_fast_path = 0;

    if (state->full_bw_reached) {
        state->congestion_window += sample->acked;

        if (state->congestion_window >= target_cwnd) {
            state->congestion_window = target_cwnd;
            state->try_fast_path = 1;
        }

    } else if (state->congestion_window < target_cwnd
               || state->congestion_window
                  < (uint64_t) 2 * conf->initial_cwnd_packets * cg->mtu)
    {
        state->congestion_window += sample->acked;

    } else {
        state->try_fast_path = 1;
    }

    state->congestion_window = ngx_max(state->congestion_window,
        (uint64_t) conf->cwnd_min_target * cg->mtu);

done:

    cg->window = (size_t) ngx_min(state->congestion_window,
                                   (uint64_t) ((size_t) -1));

    if (state->mode == BBR_PROBE_RTT) {
        cg->window = ngx_min(cg->window,
            (size_t) ngx_quic_bbr_v3_probe_rtt_cwnd(cg, conf));
    }
}


/*
 * Top-level model update for BBRv3. Calls sub-functions in the canonical
 * order defined by tcp_bbr.c: bbr_update_model().
 */
static void
ngx_quic_bbr_v3_update_model(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    uint64_t ctx_sample_bw, ngx_quic_connection_t *qc)
{
    ngx_quic_bbr_v3_update_congestion_signals(cg, conf, sample);
    ngx_quic_bbr_v3_update_ack_aggregation(cg, conf, sample);
    ngx_quic_bbr_v3_check_loss_too_high_in_startup(cg, conf, sample);
    ngx_quic_bbr_v3_check_full_bw_reached(cg, conf, sample, ctx_sample_bw);
    ngx_quic_bbr_v3_check_drain(cg, conf, sample);
    ngx_quic_bbr_v3_update_cycle_phase(cg, conf, sample);
    ngx_quic_bbr_v3_update_min_rtt(cg, conf, qc);
}


static uint64_t
ngx_quic_bbr_v3_quantize(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, uint64_t cwnd)
{
    /* Round up to even number of packets */
    cwnd = (((cwnd + cg->mtu - 1) / cg->mtu + 1) & ~1ULL) * cg->mtu;
    return cwnd;
}


static uint64_t
ngx_quic_bbr_v3_ack_aggregation_cwnd(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               max_aggr, aggr;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (conf->extra_acked_gain == 0) {
        return 0;
    }

    max_aggr = ngx_quic_bbr_v3_bw(cg, conf)
               * (uint64_t) conf->extra_acked_max_us / 1000000;

    aggr = (uint64_t) conf->extra_acked_gain
           * ngx_max(state->extra_acked[0], state->extra_acked[1])
           / NGX_QUIC_BBR_UNIT;

    return ngx_min(aggr, max_aggr);
}


static ngx_uint_t
ngx_quic_bbr_v3_run_fast_path(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample,
    ngx_uint_t *update_model)
{
    ngx_quic_bbr_state_t  *state;
    ngx_msec_t             prev_min_rtt;
    ngx_uint_t             prev_mode;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    prev_min_rtt = state->min_rtt;
    prev_mode = state->mode;

    if (conf->fast_path && state->try_fast_path
        && sample->is_app_limited
        && sample->bandwidth < ngx_quic_bbr_v3_max_bw(cg, conf)
        && !state->loss_in_round
        && !state->ecn_in_round)
    {
        ngx_quic_bbr_v3_check_drain(cg, conf, sample);
        ngx_quic_bbr_v3_update_cycle_phase(cg, conf, sample);

        /* fast_path has no qc; skip min_rtt update */

        if (state->mode == prev_mode
            && state->min_rtt == prev_min_rtt
            && state->try_fast_path)
        {
            return 1;
        }

        *update_model = 0;
    }

    return 0;
}


/*
 * Update (most of) our congestion signals: track the recent rate and volume
 * of delivered data, presence of loss.
 * Matches tcp_bbr.c: bbr_update_congestion_signals()
 *
 * NOTE: In the Google reference, bw comes from ctx->sample_bw (computed by
 * bbr_calculate_bw_sample). In this port, that corresponds to sample->bandwidth
 * which is passed in as ctx_sample_bw (already computed by the caller).
 */
static void
ngx_quic_bbr_v3_update_congestion_signals(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               bw;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (sample->interval <= 0 || sample->acked == 0) {
        return;  /* Not a valid observation */
    }

    bw = sample->bandwidth;

    if (!sample->is_app_limited || bw >= ngx_quic_bbr_v3_max_bw(cg, conf)) {
        ngx_quic_bbr_v3_take_max_bw_sample(cg, conf, bw);
    }

    state->loss_in_round |= (sample->lost_packets > 0);

    if (!state->loss_round_start) {
        return;  /* skip the per-round-trip updates */
    }

    /* Now do per-round-trip updates. */
    ngx_quic_bbr_v3_adapt_lower_bounds(cg, conf);

    state->loss_in_round = 0;
    state->ecn_in_round = 0;
}


/*
 * Update rate and volume of delivered data from latest round trip.
 * Matches tcp_bbr.c: bbr_update_latest_delivery_signals()
 *
 * NOTE: ctx->sample_bw maps to sample->bandwidth in this port.
 */
static void
ngx_quic_bbr_v3_update_latest_delivery_signals(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->loss_round_start = 0;

    if (sample->interval <= 0 || sample->acked == 0) {
        return;  /* Not a valid observation */
    }

    state->bw_latest = ngx_max(state->bw_latest, sample->bandwidth);
    state->inflight_latest = ngx_max(state->inflight_latest,
                                      sample->delivered);

    if (sample->prior_delivered >= state->loss_round_delivered) {
        state->loss_round_delivered = state->delivered;
        state->loss_round_start = 1;  /* mark start of new round trip */
    }
}


/*
 * Once per round, reset filter for latest rate and volume of delivered data.
 * Matches tcp_bbr.c: bbr_advance_latest_delivery_signals()
 *
 * NOTE: ctx->sample_bw maps to sample->bandwidth in this port.
 * If ACK matches a TLP retransmit, persist the filter.
 */
static void
ngx_quic_bbr_v3_advance_latest_delivery_signals(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf, bbr_rate_sample_t *sample)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    if (state->loss_round_start && !sample->is_acking_tlp) {
        state->bw_latest = sample->bandwidth;
        state->inflight_latest = sample->delivered;
    }
}


static void
ngx_quic_bbr_v3_bound_cwnd_for_inflight_model(ngx_quic_congestion_t *cg,
    const ngx_quic_bbr_conf_t *conf)
{
    ngx_quic_bbr_state_t  *state;
    uint64_t               cap;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    /* If neither inflight bound has been initialized, skip. */
    if (state->inflight_lo == ~0ULL && state->inflight_hi == ~0ULL) {
        return;
    }

    cap = ~0ULL;

    if (state->mode == BBR_PROBE_BW
        && state->cycle_idx != BBR_BW_PROBE_CRUISE)
    {
        cap = state->inflight_hi;

    } else if (state->mode == BBR_PROBE_RTT
               || (state->mode == BBR_PROBE_BW
                   && state->cycle_idx == BBR_BW_PROBE_CRUISE))
    {
        cap = ngx_quic_bbr_v3_inflight_with_headroom(cg, conf);
    }

    cap = ngx_min(cap, state->inflight_lo);
    cap = ngx_max(cap, (uint64_t) conf->cwnd_min_target * cg->mtu);

    state->congestion_window = ngx_min(cap, state->congestion_window);
    cg->window = (size_t) state->congestion_window;
}


/*
 * BBRv3 callback entry functions (version=3)
 */

static void
ngx_quic_bbr_v3_save_cwnd(ngx_quic_congestion_t *cg)
{
    ngx_quic_bbr_state_t  *state;

    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->prior_cwnd = state->congestion_window;
}


static void
ngx_quic_bbr_v3_reset(ngx_quic_connection_t *qc)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_bbr_state_t         *state;
    const ngx_quic_bbr_conf_t    *conf;

    cg = &qc->congestion;
    conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

    if (cg->cc_priv == NULL) {
        cg->cc_priv = ngx_alloc(sizeof(ngx_quic_bbr_state_t),
                                ngx_cycle->log);
        if (cg->cc_priv == NULL) {
            return;
        }
    }

    ngx_memzero(cg->cc_priv, sizeof(ngx_quic_bbr_state_t));
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);
    state->base.type = NGX_QUIC_CC_BBR;
    state->version = conf->version;

    if (conf->initial_cwnd_packets > 0) {
        cg->window = ngx_max(cg->window,
                             (size_t) conf->initial_cwnd_packets * cg->mtu);
    }

    state->congestion_window = cg->window;
    cg->ssthresh = (size_t) -1;
    state->prior_cwnd = cg->window;
    state->mode = BBR_STARTUP;
    state->prev_mode = BBR_STARTUP;
    state->cycle_idx = BBR_BW_PROBE_CRUISE;
    state->min_rtt = qc->min_rtt == NGX_TIMER_INFINITE
                     ? NGX_QUIC_BBR_INITIAL_RTT : qc->min_rtt;
    state->min_rtt_stamp = qc->min_rtt == NGX_TIMER_INFINITE
                           ? 0 : ngx_current_msec;

    state->bw_lo = ~0ULL;
    state->bw_hi[0] = 0;
    state->bw_hi[1] = 0;
    state->inflight_lo = ~0ULL;
    state->inflight_hi = ~0ULL;
    state->probe_rtt_min_us = state->min_rtt;
    state->probe_rtt_min_stamp = state->min_rtt_stamp;
    state->probe_rtt_done_stamp = 0;
    state->probe_rtt_round_done = 0;
    state->cycle_stamp = ngx_current_msec;
    state->first_sent_time = ngx_current_msec;
    state->delivered = 0;
    state->delivered_time = ngx_current_msec;
    state->next_round_delivered = 0;
    state->rtt_cnt = 0;
    state->full_bw = 0;
    state->full_bw_reached = 0;
    state->full_bw_cnt = 0;
    state->full_bw_now = 0;
    state->bw_latest = 0;
    state->inflight_latest = 0;
    state->bw_probe_up_cnt = ~0ULL;
    state->bw_probe_up_acks = 0;
    state->bw_probe_up_rounds = 0;
    state->probe_wait_us = 0;
    state->stopped_risky_probe = 0;
    state->ack_phase = BBR_ACKS_INIT;
    state->rounds_since_probe = 0;
    state->bw_probe_samples = 0;
    state->prev_probe_too_high = 0;
    state->loss_round_delivered = state->delivered + 1;
    state->loss_round_start = 0;
    state->loss_in_round = 0;
    state->loss_in_cycle = 0;
    state->loss_events_in_round = 0;
    state->ecn_eligible = 1;  /* QUIC with ACK_ECN implies ECN support */
    state->ecn_alpha = (ngx_uint_t) conf->ecn_alpha_init;
    state->ecn_in_round = 0;
    state->ecn_in_cycle = 0;
    state->startup_ecn_rounds = 0;
    state->alpha_last_delivered = 0;
    state->alpha_last_delivered_ce = 0;
    state->delivered_ce = 0;
    state->last_ce_counter = 0;
    state->try_fast_path = 0;
    state->idle_restart = 0;
    state->ack_epoch_stamp = ngx_current_msec;
    state->ack_epoch_acked = 0;
    state->extra_acked_win_rtts = 0;
    state->extra_acked_win_idx = 0;
    state->extra_acked[0] = 0;
    state->extra_acked[1] = 0;
    state->lost = 0;
    state->pacing_gain = (ngx_uint_t) conf->startup_pacing_gain;
    state->cwnd_gain = (ngx_uint_t) conf->startup_cwnd_gain;
    state->init_cwnd = (ngx_uint_t) conf->initial_cwnd_packets;
    state->pacing_rate = 0;
    state->pacing_debt = 0;
    state->next_send_time = 0;

    ngx_quic_bbr_v3_set_pacing_rate(cg, conf);
}


static void
ngx_quic_bbr_v3_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    bbr_rate_sample_t             sample;
    const ngx_quic_bbr_conf_t    *conf;
    ngx_uint_t                    update_model;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);
    conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

    ngx_quic_bbr_rate_sample(cg, f, &sample);

    /* 1. Round tracking */
    ngx_quic_bbr_v3_update_round_start(cg, f, &sample);

    if (state->round_start) {
        state->rounds_since_probe += 1;
    }

    /* 2. ECN: extract CE counter from ACK_ECN frame */
    if (f->type == NGX_QUIC_FT_ACK_ECN) {
        uint64_t  ce_delta;

        ce_delta = f->u.ack.ce - state->last_ce_counter;
        state->last_ce_counter = f->u.ack.ce;

        if (ce_delta > 0) {
            state->ecn_in_round = 1;
            state->ecn_in_cycle = 1;
            state->delivered_ce += ce_delta * cg->mtu;
        }

        if (state->round_start) {
            ngx_quic_bbr_v3_update_ecn_alpha(cg, conf);
            ngx_quic_bbr_v3_check_ecn_too_high_in_startup(cg, conf);
        }
    }

    /* 3. Calculate bandwidth sample */
    ngx_quic_bbr_v3_calculate_bw_sample(cg, &sample);

    /* 4. Update latest delivery signals */
    ngx_quic_bbr_v3_update_latest_delivery_signals(cg, conf, &sample);

    /* 5. Fast path -- may skip full model update */
    update_model = 1;

    if (ngx_quic_bbr_v3_run_fast_path(cg, conf, &sample, &update_model)) {
        goto out;
    }

    /* 6. Full model update (if not fast-pathed) */
    if (update_model) {
        ngx_quic_bbr_v3_update_model(cg, conf, &sample, sample.bandwidth,
                                     qc);
    }

    /* 7-11. Gains, pacing, cwnd */
    ngx_quic_bbr_v3_update_gains(cg, conf);

    ngx_quic_bbr_v3_set_pacing_rate(cg, conf);
    ngx_quic_bbr_v3_set_cwnd(cg, conf, &sample);
    ngx_quic_bbr_v3_bound_cwnd_for_inflight_model(cg, conf);

out:

    /* 12. Advance delivery signals after main logic */
    ngx_quic_bbr_v3_advance_latest_delivery_signals(cg, conf, &sample);

    /* 13. Track loss in this cycle */
    state->loss_in_cycle |= (sample.lost_packets > 0);

    /* 14. ECN in cycle tracking */
    state->ecn_in_cycle |= (sample.delivered_ce > 0);

    /* 15. Debug log */
    ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic bbr v3 ack mode:%ui bw:%uL gain:%ui cwnd:%uz "
                   "rate:%uL if:%uz rtt:%M",
                   state->mode, ngx_quic_bbr_v3_bw(cg, conf),
                   state->pacing_gain, cg->window, state->pacing_rate,
                   cg->in_flight, state->min_rtt);
}


static void
ngx_quic_bbr_v3_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    const ngx_quic_bbr_conf_t    *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);
    conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

    /* bbr_note_loss: mark loss in this round */
    if (!state->loss_in_round) {
        state->loss_round_delivered = state->delivered;
    }

    state->loss_in_round = 1;
    state->loss_in_cycle = 1;
    state->lost += f->plen;

    ngx_quic_bbr_v3_save_cwnd(cg);

    (void)conf;
    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic bbr v3 lost mode:%ui win:%uz prior:%uL lost:%uL "
                   "bw:%uL if:%uz",
                   state->mode, cg->window, state->prior_cwnd,
                   state->lost, ngx_quic_bbr_v3_bw(cg, conf),
                   cg->in_flight);
}


static void
ngx_quic_bbr_v3_idle(ngx_connection_t *c, ngx_uint_t idle)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;
    uint64_t                      bw;
    const ngx_quic_bbr_conf_t    *conf;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    cg->idle = idle;

    if (!idle) {
        state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);
        conf = (const ngx_quic_bbr_conf_t *) qc->conf->cc_algo_conf;

        /* bbr_cwnd_event(CA_EVENT_TX_START) */
        state->idle_restart = 1;
        state->ack_epoch_stamp = ngx_current_msec;
        state->ack_epoch_acked = 0;

        if (state->mode == BBR_PROBE_BW) {
            bw = ngx_quic_bbr_v3_bw(cg, conf);
            if (bw) {
                state->pacing_rate = bw
                    * (100 - conf->pacing_margin_percent) / 100;
            }
        } else if (state->mode == BBR_PROBE_RTT) {
            ngx_quic_bbr_v3_check_probe_rtt_done(cg, conf);
        }

        state->pacing_debt = 0;
        state->next_send_time = 0;
    }
}


static void
ngx_quic_bbr_v3_persistent_congestion(ngx_connection_t *c)
{
    ngx_quic_congestion_t        *cg;
    ngx_quic_connection_t        *qc;
    ngx_quic_bbr_state_t         *state;

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;
    state = container_of(cg->cc_priv, ngx_quic_bbr_state_t, base);

    state->full_bw = 0;
    state->full_bw_cnt = 0;
    state->round_start = 1;
    state->loss_in_round = 0;
    state->loss_events_in_round = 0;
    state->inflight_lo = ~0ULL;
    state->bw_lo = ~0ULL;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic bbr v3 persistent congestion mode:%ui win:%uz",
                   state->mode, cg->window);
}
