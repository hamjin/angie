/*
 * Copyright (C) 2026 Web Server LLC
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>


#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#include "../../src/event/quic/congestion_control/ngx_event_quic_bbr.c"

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif


static unsigned  test_no;
static unsigned  test_failed;


ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    u_char  c1, c2;

    while (n) {
        c1 = (u_char) *s1++;
        c2 = (u_char) *s2++;

        c1 = (u_char) ((c1 >= 'A' && c1 <= 'Z') ? c1 | 0x20 : c1);
        c2 = (u_char) ((c2 >= 'A' && c2 <= 'Z') ? c2 | 0x20 : c2);

        if (c1 == c2) {
            if (c1) {
                n--;
                continue;
            }

            return 0;
        }

        return c1 - c2;
    }

    return 0;
}


ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    value = 0;

    while (n--) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line++ - '0');
    }

    return value;
}


void ngx_cdecl
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level;
    (void) cf;
    (void) err;
    (void) fmt;
}


static void
ok(unsigned condition, const char *name)
{
    test_no++;

    printf("%s %u - %s\n", condition ? "ok" : "not ok", test_no, name);

    if (!condition) {
        test_failed = 1;
    }
}


static void
ok_param(unsigned condition, const char *name, ngx_str_t *param)
{
    test_no++;

    printf("%s %u - %s %.*s\n", condition ? "ok" : "not ok", test_no, name,
           (int) param->len, param->data);

    if (!condition) {
        test_failed = 1;
    }
}


static char *
set_bbr_param(ngx_quic_bbr_conf_t *conf, const char *name, const char *value)
{
    ngx_str_t    args_elts[3];
    ngx_array_t  args;
    ngx_conf_t   cf;

    memset(&args, 0, sizeof(args));
    memset(&cf, 0, sizeof(cf));

    args_elts[0].data = (u_char *) "quic_cc_conf";
    args_elts[0].len = sizeof("quic_cc_conf") - 1;
    args_elts[1].data = (u_char *) name;
    args_elts[1].len = strlen(name);
    args_elts[2].data = (u_char *) value;
    args_elts[2].len = strlen(value);

    args.elts = args_elts;
    args.nelts = 3;
    args.size = sizeof(ngx_str_t);
    args.nalloc = 3;

    cf.args = &args;

    return ngx_quic_bbr_conf_handler(&cf, NULL, conf);
}


static ngx_uint_t
count_inherited_replay_params(void)
{
    ngx_uint_t  i, n;

    n = 0;

    for (i = 0; ngx_quic_bbr_params[i].name.len != 0; i++) {
        if (ngx_quic_bbr_params[i].offset
            == offsetof(ngx_quic_bbr_conf_t, profile))
        {
            continue;
        }

        n++;
    }

    return n;
}


static const char *
inherited_replay_value(ngx_uint_t offset, ngx_int_t *expected)
{
    if (offset == offsetof(ngx_quic_bbr_conf_t, version)) {
        *expected = 3;
        return "3";
    }

    if (offset == offsetof(ngx_quic_bbr_conf_t, exit_startup_on_loss)) {
        *expected = 0;
        return "0";
    }

    if (offset == offsetof(ngx_quic_bbr_conf_t, drain_to_target)
        || offset == offsetof(ngx_quic_bbr_conf_t, detect_overshooting)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              enable_ack_aggregation_startup)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              expire_ack_aggregation_startup)
        || offset == offsetof(ngx_quic_bbr_conf_t, overestimate_avoidance)
        || offset == offsetof(ngx_quic_bbr_conf_t, use_derived_high_gain)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              start_new_aggregation_epoch_after_full_round)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              limit_max_ack_height_tracker_by_send_rate)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              exit_startup_on_loss_even_if_app_limited)
        || offset == offsetof(ngx_quic_bbr_conf_t,
                              reduce_extra_acked_on_bandwidth_increase))
    {
        *expected = 1;
        return "1";
    }

    *expected = 73;

    return "73";
}


static ngx_int_t
bbr_conf_field_value(ngx_quic_bbr_conf_t *conf, ngx_uint_t offset)
{
    return *((ngx_int_t *) ((u_char *) conf + offset));
}


static void
test_explicit_default_profile_keeps_profile_defaults(void)
{
    ngx_quic_bbr_conf_t  conf;

    ngx_quic_bbr_init_conf(&conf);

    ok(set_bbr_param(&conf, "profile", "default") == NGX_CONF_OK,
       "bbr profile default parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &conf, NULL) == NGX_CONF_OK,
       "bbr explicit default profile merges");

    ok(conf.high_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr explicit default keeps default high_gain");
    ok(conf.drain_gain == NGX_QUIC_BBR_UNIT * 1000 / 2000,
       "bbr explicit default keeps default drain_gain");
    ok(conf.startup_cwnd_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr explicit default keeps default startup_cwnd_gain");
    ok(conf.enable_ack_aggregation_startup == 1,
       "bbr explicit default enables startup ack aggregation");
    ok(conf.exit_startup_on_loss == 1,
       "bbr explicit default exits startup on loss");
}


static void
test_explicit_overrides_win_over_profile_defaults(void)
{
    ngx_quic_bbr_conf_t  conf;

    ngx_quic_bbr_init_conf(&conf);

    ok(set_bbr_param(&conf, "profile", "default") == NGX_CONF_OK,
       "bbr profile default parses before overrides");
    ok(set_bbr_param(&conf, "high_gain", "640") == NGX_CONF_OK,
       "bbr high_gain override parses");
    ok(set_bbr_param(&conf, "enable_ack_aggregation_startup", "0")
       == NGX_CONF_OK, "bbr startup ack aggregation override parses");
    ok(set_bbr_param(&conf, "exit_startup_on_loss", "0") == NGX_CONF_OK,
       "bbr startup loss override parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &conf, NULL) == NGX_CONF_OK,
       "bbr default profile with overrides merges");

    ok(conf.high_gain == 640,
       "bbr explicit high_gain override wins over profile");
    ok(conf.drain_gain == NGX_QUIC_BBR_UNIT * 1000 / 2000,
       "bbr unspecified drain_gain keeps profile default with overrides");
    ok(conf.startup_cwnd_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr unspecified startup_cwnd_gain keeps profile default with overrides");
    ok(conf.enable_ack_aggregation_startup == 0,
       "bbr explicit startup ack aggregation override wins over profile");
    ok(conf.exit_startup_on_loss == 0,
       "bbr explicit startup loss override wins over profile");
}


static void
test_child_version_override_survives_inherited_profile(void)
{
    ngx_quic_bbr_conf_t  parent, child;

    ngx_quic_bbr_init_conf(&parent);

    ok(set_bbr_param(&parent, "profile", "default") == NGX_CONF_OK,
       "bbr parent default profile parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &parent, NULL) == NGX_CONF_OK,
       "bbr parent default profile merges");

    ngx_quic_bbr_init_conf(&child);

    ok(set_bbr_param(&child, "version", "3") == NGX_CONF_OK,
       "bbr child version override parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &child, &parent) == NGX_CONF_OK,
       "bbr child inherits parent profile with version override");

    ok(child.version == 3,
       "bbr child explicit version survives inherited profile");
    ok(child.profile == NGX_QUIC_BBR_PROFILE_DEFAULT,
       "bbr child inherits parent default profile");
    ok(child.high_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr child inherited default profile keeps high_gain");
    ok(child.drain_gain == NGX_QUIC_BBR_UNIT * 1000 / 2000,
       "bbr child inherited default profile keeps drain_gain");
    ok(child.startup_cwnd_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr child inherited default profile keeps startup_cwnd_gain");
    ok(child.enable_ack_aggregation_startup == 1,
       "bbr child inherited default profile keeps startup ack aggregation");
    ok(child.exit_startup_on_loss == 1,
       "bbr child inherited default profile keeps startup loss exit");
}


static void
test_child_override_survives_inherited_profile(void)
{
    ngx_quic_bbr_conf_t  parent, child;

    ngx_quic_bbr_init_conf(&parent);

    ok(set_bbr_param(&parent, "profile", "hy2") == NGX_CONF_OK,
       "bbr parent hy2 profile parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &parent, NULL) == NGX_CONF_OK,
       "bbr parent hy2 profile merges");

    ngx_quic_bbr_init_conf(&child);

    ok(set_bbr_param(&child, "high_gain", "640") == NGX_CONF_OK,
       "bbr child high_gain override parses");
    ok(ngx_quic_bbr_merge_conf(NULL, &child, &parent) == NGX_CONF_OK,
       "bbr child inherits parent profile with high_gain override");

    ok(child.profile == NGX_QUIC_BBR_PROFILE_HY2,
       "bbr child inherits parent hy2 profile");
    ok(child.high_gain == 640,
       "bbr child high_gain override wins over inherited profile");
    ok(child.startup_cwnd_gain == NGX_QUIC_BBR_UNIT * 2,
       "bbr child inherited hy2 profile keeps startup_cwnd_gain");
    ok(child.initial_cwnd_packets == 32,
       "bbr child inherited hy2 profile keeps initial_cwnd_packets");
    ok(child.exit_startup_on_loss == 1,
       "bbr child inherited hy2 profile keeps startup loss exit");
}


static void
test_all_child_overrides_survive_inherited_profile(void)
{
    ngx_int_t            expected;
    ngx_uint_t           i;
    const char          *value;
    ngx_quic_bbr_conf_t  parent, child;

    printf("# bbr inherited replay skips profile: profile selection is "
           "merged separately from scalar overrides\n");

    for (i = 0; ngx_quic_bbr_params[i].name.len != 0; i++) {
        if (ngx_quic_bbr_params[i].offset
            == offsetof(ngx_quic_bbr_conf_t, profile))
        {
            continue;
        }

        ngx_quic_bbr_init_conf(&parent);

        if (set_bbr_param(&parent, "profile", "hy2") != NGX_CONF_OK
            || ngx_quic_bbr_merge_conf(NULL, &parent, NULL) != NGX_CONF_OK)
        {
            ok_param(0, "bbr parent hy2 setup for inherited replay",
                     &ngx_quic_bbr_params[i].name);
            continue;
        }

        ngx_quic_bbr_init_conf(&child);

        value = inherited_replay_value(ngx_quic_bbr_params[i].offset,
                                       &expected);

        ok_param(set_bbr_param(&child,
                               (const char *) ngx_quic_bbr_params[i].name.data,
                               value)
                 == NGX_CONF_OK
                 && ngx_quic_bbr_merge_conf(NULL, &child, &parent)
                    == NGX_CONF_OK
                 && bbr_conf_field_value(&child,
                                          ngx_quic_bbr_params[i].offset)
                    == expected,
                 "bbr inherited merge preserves child explicit",
                 &ngx_quic_bbr_params[i].name);
    }
}


int
main(void)
{
    printf("1..%u\n", (unsigned) (37 + count_inherited_replay_params()));

    test_explicit_default_profile_keeps_profile_defaults();
    test_explicit_overrides_win_over_profile_defaults();
    test_child_version_override_survives_inherited_profile();
    test_child_override_survives_inherited_profile();
    test_all_child_overrides_survive_inherited_profile();

    return test_failed ? 1 : 0;
}
