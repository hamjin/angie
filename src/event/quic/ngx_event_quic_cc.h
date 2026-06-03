/*
 * Copyright (C) 2026 Web Server LLC
 */


#ifndef _NGX_EVENT_QUIC_CC_H_INCLUDED_
#define _NGX_EVENT_QUIC_CC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_CC_SKIP_RECOVERY    0x01
#define NGX_QUIC_CC_SKIP_IDLE        0x02
#define NGX_QUIC_CC_HAS_PACING       0x04
#define NGX_QUIC_CC_HAS_RATE_SAMPLE  0x08


typedef struct ngx_quic_cc_priv_s {
    ngx_uint_t  type;
} ngx_quic_cc_priv_t;


typedef struct {
    ngx_str_t      name;
    ngx_uint_t     type;
    ngx_uint_t     offset;
    void          *set;
    void          *conf;
    void          *post;
} ngx_conf_num_set_t;


typedef struct ngx_quic_cc_algo_s {
    size_t       conf_size;
    void       (*init_conf)(void *conf);
    char       *(*merge_conf)(ngx_conf_t *cf, void *conf, void *prev);
    char       *(*conf_handler)(ngx_conf_t *cf, ngx_command_t *cmd,
                   void *algo_conf);
    void       (*reset)(ngx_quic_connection_t *qc);
    void       (*ack)(ngx_connection_t *c, ngx_quic_frame_t *f);
    void       (*lost)(ngx_connection_t *c, ngx_quic_frame_t *f);
    void       (*idle)(ngx_connection_t *c, ngx_uint_t idle);
    void       (*persistent_congestion)(ngx_connection_t *c);
    ngx_msec_t (*pacing_delay)(ngx_connection_t *c);
    void       (*init_rate_sample)(ngx_quic_connection_t *qc,
        ngx_quic_frame_t *f, ngx_msec_t now, size_t in_flight);
    void       (*update_pacing)(ngx_quic_congestion_t *cg,
        size_t sent, ngx_msec_t now);
    void       (*set_pacing_timer)(ngx_quic_connection_t *qc,
        ngx_msec_t delay);
    unsigned     flags;
} ngx_quic_cc_algo_t;


void ngx_quic_cc_ack(ngx_connection_t *c, ngx_quic_frame_t *f);
void ngx_quic_cc_lost(ngx_connection_t *c, ngx_quic_frame_t *f);
void ngx_quic_cc_reset(ngx_quic_connection_t *qc);
void ngx_quic_cc_idle(ngx_connection_t *c, ngx_uint_t idle);
void ngx_quic_cc_persistent_congestion(ngx_connection_t *c,
    ngx_msec_t recovery_start);
ngx_msec_t ngx_quic_cc_pacing_delay(ngx_connection_t *c);
void ngx_quic_cc_init_rate_sample(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f, ngx_msec_t now, size_t in_flight);
void ngx_quic_cc_update_pacing(ngx_quic_congestion_t *cg, size_t sent,
    ngx_msec_t now);
void ngx_quic_cc_set_pacing_timer(ngx_quic_connection_t *qc,
    ngx_msec_t delay);

void *ngx_quic_cc_create_conf(const ngx_quic_cc_algo_t *algo, ngx_pool_t *pool);
char *ngx_quic_cc_init_conf(const ngx_quic_cc_algo_t *algo, void *conf);
char *ngx_quic_cc_merge_conf(ngx_conf_t *cf, const ngx_quic_cc_algo_t *algo,
    void *conf, void *prev);
const ngx_quic_cc_algo_t *ngx_quic_cc_lookup(
    ngx_quic_cc_algorithm_e algo);
char *ngx_quic_cc_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* _NGX_EVENT_QUIC_CC_H_INCLUDED_ */
