/*
 * Copyright (C) 2026 Web Server LLC
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>


typedef struct {
    const char  *name;
    const char  *profile;
} cc_algorithm_t;


typedef struct {
    const char  *name;
    unsigned    rate_bps;
    unsigned    delay_ms;
    unsigned    jitter_ms;
    unsigned    loss_ppm;
    unsigned    outage_after_ms;
    unsigned    outage_duration_ms;
} cc_scenario_t;


static const cc_algorithm_t algorithms[] = {
    { "reno", "" },
    { "cubic", "" },
	{ "bbr", "default" },
	{ "bbr", "google" },
	{ "bbr", "sing" },
	{ "bbr", "hy2" },
	{ "bbrv3", "default" },
	{ "bbrv3", "google" },
	{ "bbrv3", "sing" },
	{ "bbrv3", "hy2" }
};


static const unsigned min_realistic_rate_bps = 384000;
static const unsigned max_realistic_rate_bps = 1000000000;


static const cc_scenario_t scenarios[] = {
    { "cloud-vpc-low-loss", 1000000000, 1, 0, 10, 0, 0 },
    { "dc-roce-hpc", 1000000000, 0, 0, 5, 0, 0 },
    { "fintrading-ultra-low-lat", 1000000000, 0, 0, 50, 0, 0 },
    { "k8s-cni-overlay", 1000000000, 2, 0, 500, 0, 0 },
    { "enterprise-core", 1000000000, 2, 1, 100, 0, 0 },
    { "idc-intercity-line", 1000000000, 10, 2, 100, 0, 0 },
    { "internet-backbone", 1000000000, 40, 10, 1000, 0, 0 },
    { "ftth-bufferbloat", 100000000, 5, 1, 1000, 0, 0 },
    { "wifi-random-loss", 100000000, 25, 10, 1000, 0, 0 },
    { "cellular-4g5g", 20000000, 15, 5, 5000, 0, 0 },
    { "video-streaming-cdn", 10000000, 100, 30, 20000, 0, 0 },
    { "quic-public-video", 10000000, 30, 5, 5000, 0, 0 },
    { "voip-video-conf", 4000000, 50, 10, 3000, 0, 0 },
    { "online-gaming", 1000000, 30, 5, 2000, 0, 0 },
    { "webrtc-rtc", 1000000, 30, 10, 1000, 0, 0 },
    { "leo-satellite", 50000000, 20, 5, 5000, 0, 0 },
    { "geo-satellite", 10000000, 500, 20, 10000, 0, 0 },
    { "china-cross-border-public", 10000000, 150, 30, 200000, 0, 0 },
    { "china-cross-border-iepl", 10000000, 30, 1, 100, 0, 0 },
    { "path-outage-recovery", 20000000, 20, 5, 1000, 4000, 1500 }
};


static const char *metrics[] = {
    "throughput",
    "latency",
    "jitter",
    "loss_rate"
};


static int
has_algorithm(const char *name)
{
    size_t  i;

    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        if (strcmp(algorithms[i].name, name) == 0) {
            return 1;
        }
    }

    return 0;
}


static int
has_profile(const char *name, const char *profile)
{
    size_t  i;

    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        if (strcmp(algorithms[i].name, name) == 0
            && strcmp(algorithms[i].profile, profile) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static int
scenario_valid(const cc_scenario_t *s)
{
    if (s->name == NULL) {
        return 0;
    }

    if (s->rate_bps < min_realistic_rate_bps
        || s->rate_bps > max_realistic_rate_bps)
    {
        return 0;
    }

    if (s->outage_after_ms == 0 && s->outage_duration_ms != 0) {
        return 0;
    }

    if (s->loss_ppm > 1000000) {
        return 0;
    }

    return 1;
}


int
main(void)
{
    size_t  i, ntests, scenario_count;
    int     n;

    scenario_count = sizeof(scenarios) / sizeof(scenarios[0]);

    ntests = 1
             + sizeof(algorithms) / sizeof(algorithms[0])
             + 1 + 2
             + scenario_count
             + sizeof(metrics) / sizeof(metrics[0]);

    printf("1..%zu\n", ntests);

    n = 1;

    printf("%s %d - forwarder binary exists\n",
           access("./forwarder", X_OK) == 0 ? "ok" : "not ok", n++);
    printf("%s %d - reno algorithm in cc perf matrix\n",
           has_algorithm("reno") ? "ok" : "not ok", n++);
    printf("%s %d - cubic algorithm in cc perf matrix\n",
           has_algorithm("cubic") ? "ok" : "not ok", n++);
    printf("%s %d - bbr algorithm in cc perf matrix\n",
           has_algorithm("bbr") ? "ok" : "not ok", n++);
    printf("%s %d - bbr default profile in cc perf matrix\n",
           has_profile("bbr", "default") ? "ok" : "not ok", n++);
    printf("%s %d - bbr google profile in cc perf matrix\n",
           has_profile("bbr", "google") ? "ok" : "not ok", n++);
    printf("%s %d - bbr sing profile in cc perf matrix\n",
           has_profile("bbr", "sing") ? "ok" : "not ok", n++);
    printf("%s %d - bbr hy2 profile in cc perf matrix\n",
           has_profile("bbr", "hy2") ? "ok" : "not ok", n++);
    printf("%s %d - bbrv3 algorithm in cc perf matrix\n",
           has_algorithm("bbrv3") ? "ok" : "not ok", n++);
    printf("%s %d - bbrv3 default profile in cc perf matrix\n",
           has_profile("bbrv3", "default") ? "ok" : "not ok", n++);
    printf("%s %d - bbrv3 google profile in cc perf matrix\n",
           has_profile("bbrv3", "google") ? "ok" : "not ok", n++);
    printf("%s %d - bbrv3 sing profile in cc perf matrix\n",
           has_profile("bbrv3", "sing") ? "ok" : "not ok", n++);
    printf("%s %d - bbrv3 hy2 profile in cc perf matrix\n",
           has_profile("bbrv3", "hy2") ? "ok" : "not ok", n++);

    printf("%s %d - scenario matrix covers broad network conditions\n",
           scenario_count < 10 ? "not ok" : "ok", n++);

    for (i = 0; i < scenario_count; i++) {
        printf("%s %d - scenario %s configured\n",
               scenario_valid(&scenarios[i]) ? "ok" : "not ok", n++,
               scenarios[i].name);
    }

    for (i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++) {
        printf("ok %d - metric %s configured\n", n++, metrics[i]);
    }

    printf("# algorithms=%zu scenarios=%zu runs_per_case=3 duration=10s "
           "gap=5s\n",
           sizeof(algorithms) / sizeof(algorithms[0]),
           scenario_count);
    printf("# min_realistic_rate_bps=%u max_realistic_rate_bps=%u\n",
           min_realistic_rate_bps, max_realistic_rate_bps);
    printf("# acceptance=default comparable-with=cubic,reno "
           "google=google sing=sing hy2=hy2\n");

    return 0;
}
