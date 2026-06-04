#!/usr/bin/perl

# Copyright (C) 2026 Web Server LLC

# Tests for QUIC congestion-control framework and performance-test wiring.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

###############################################################################

my $root = '..';

my @required = qw(
	src/event/quic/ngx_event_quic_cc.h
	src/event/quic/ngx_event_quic_cc.c
	src/event/quic/congestion_control/ngx_event_quic_reno.h
	src/event/quic/congestion_control/ngx_event_quic_reno.c
	src/event/quic/congestion_control/ngx_event_quic_cubic.h
	src/event/quic/congestion_control/ngx_event_quic_cubic.c
	src/event/quic/congestion_control/ngx_event_quic_bbr.h
	src/event/quic/congestion_control/ngx_event_quic_bbr.c
	tests/quic_cc_perf.t
	tests/quic_cc/Makefile
	tests/quic_cc/h3_client.c
	tests/quic_cc/ossl_nghttp3.c
	tests/quic_cc/ossl_nghttp3.h
	tests/quic_cc/test_cc_perf.c
	tests/quic_cc/forwarder.c
);

for my $path (@required) {
	ok(-f "$root/$path", "$path exists");
}

ok(!-e "$root/tests/quic_cc/control_h3_server.c",
	'control_h3_server source is discarded');

my $modules = read_file("$root/auto/modules");
like($modules, qr/src\/event\/quic\/ngx_event_quic_cc\.h/,
	'cc framework header is a QUIC module dependency');
like($modules, qr/src\/event\/quic\/ngx_event_quic_cc\.c/,
	'cc framework source is built');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_reno\.h/,
	'reno header is a QUIC module dependency');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_reno\.c/,
	'reno source is built');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_cubic\.h/,
	'cubic header is a QUIC module dependency');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_cubic\.c/,
	'cubic source is built');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_bbr\.h/,
	'bbr header is a QUIC module dependency');
like($modules, qr/src\/event\/quic\/congestion_control\/ngx_event_quic_bbr\.c/,
	'bbr source is built');
my $h3 = read_file("$root/src/http/v3/ngx_http_v3_module.c");
like($h3, qr/NGX_QUIC_CC_BBR/, 'quic_cc can select bbr');
like($h3, qr/ngx_string\("quic_cc_conf"\)/,
	'quic_cc_conf directive is present');

like($h3, qr/ngx_string\("quic_cc"\)/, 'quic_cc directive exists');
like($h3, qr/NGX_CONF_TAKE1/, 'quic_cc takes one argument');
like($h3, qr/NGX_QUIC_CC_RENO/, 'quic_cc can select reno');
like($h3, qr/NGX_QUIC_CC_CUBIC/, 'quic_cc can select cubic');

my $quic_perf = read_file("$root/tests/quic_cc_perf.t");
like($quic_perf, qr/use constant RUNS_PER_CASE\s*=>\s*3;/,
	'h3 cc perf runs each case scenario tuple three times');
like($quic_perf, qr/use constant SCENARIO_DURATION_MS\s*=>\s*10000;/,
	'h3 cc perf defines 10 second scenario duration');
like($quic_perf, qr/use constant RUN_GAP_MS\s*=>\s*5000;/,
	'h3 cc perf waits five seconds between measured runs');
like($quic_perf, qr/use constant FORWARDER_DRAIN_MS\s*=>\s*5000;/,
	'h3 cc perf leaves forwarder drain time after scenario window');
like($quic_perf, qr/use constant PERF_STREAM_RESPONSE_BYTES\s*=>\s*256\s*\*\s*1024;/,
	'h3 cc perf uses quarter-megabyte per-stream samples');
like($quic_perf, qr/use constant PERF_PARALLEL_STREAMS\s*=>\s*2;/,
	'h3 cc perf keeps low parallel stream fanout');
like($quic_perf, qr/use constant PERF_ACK_EVERY\s*=>\s*16;/,
	'h3 cc perf batches client ACKs for perf runs');
like($quic_perf, qr/MAX_MEANINGFUL_THROUGHPUT_BPS\s*\/\s*8[\s\S]+
	SCENARIO_DURATION_MS\s*\+\s*FORWARDER_DRAIN_MS/sx,
	'h3 cc perf flow-control credit covers a 1Gbps 10s sample window');
like($quic_perf, qr/use constant PERF_READ_TIMEOUT_SEC\s*=>\s*30;/,
	'h3 cc perf extends H3 reads for realistic high-latency paths');
like($quic_perf, qr/use constant H3_CLIENT\s*=>/,
	'h3 cc perf defines tests/cc C client path');
like($quic_perf, qr/use constant MIN_MEANINGFUL_THROUGHPUT_BPS\s*=>\s*384000;/,
	'h3 cc perf enforces at least WCDMA-class throughput');
like($quic_perf, qr/use constant MAX_MEANINGFUL_THROUGHPUT_BPS\s*=>\s*1000\s*\*\s*1000\s*\*\s*1000;/,
	'h3 cc perf keeps the matrix open to 1Gbps samples');
like($quic_perf, qr/my \@cases\s*=/, 'h3 cc perf centralizes algorithm cases');
for my $case (qw(reno cubic)) {
	like($quic_perf, qr/name\s*=>\s*'$case'/,
		"h3 cc perf case $case configured");
}
like($quic_perf, qr/my \@scenarios\s*=/, 'h3 cc perf centralizes scenarios');
unlike($quic_perf, qr/base_scenarios/,
	'h3 cc perf does not split base scenarios from the scenario matrix');
for my $scenario (qw(
	cloud-vpc-low-loss enterprise-core idc-intercity-line
	internet-backbone ftth-bufferbloat wifi-random-loss cellular-4g5g
	quic-public-video webrtc-rtc leo-satellite
	china-cross-border-iepl path-outage-recovery
)) {
	like($quic_perf, qr/name\s*=>\s*'$scenario'/,
		"h3 cc perf scenario $scenario configured");
}
like($quic_perf, qr/rate_bps\s*=>\s*1000\s*\*\s*1000\s*\*\s*1000/,
	'h3 cc perf includes 1Gbps-capable scenario rates');
like($quic_perf, qr/name\s*=>\s*'china-cross-border-iepl'[\s\S]+?delay_ms\s*=>\s*30/,
	'h3 cc perf keeps IEPL RTT in the realistic range');
like($quic_perf, qr/scalar\(\@scenarios\)\s*<\s*10/,
	'h3 cc perf requires broad unified scenario coverage');
like($quic_perf, qr/check_scenario_matrix\(\);/,
	'h3 cc perf validates the scenario matrix before running');
like($quic_perf, qr/unrealistic rate_bps/,
	'h3 cc perf rejects unrealistic scenario rates');
unlike($quic_perf, qr/full_h3/,
	'h3 cc perf runs the full scenario matrix without hidden skips');
like($quic_perf, qr/\@active_scenarios\s*=\s*\$full\s*\?\s*\@scenarios\s*:\s*\(\$scenarios\[0\]\)/s,
	'h3 cc perf full mode uses every configured scenario');
like($quic_perf, qr/ANGIE_CC_PERF_SCENARIO/,
	'h3 cc perf can isolate one scenario for diagnostic reruns');
like($quic_perf, qr/defined\s+\$ENV\{ANGIE_CC_PERF_SCENARIO\}[\s\S]+
	\@active_scenarios\s*=\s*grep\s*\{[\s\S]+
	ANGIE_CC_PERF_SCENARIO[\s\S]+\}\s*\@scenarios/sx,
	'h3 cc perf diagnostic scenario filter can select any configured scenario');
like($quic_perf, qr/scalar\(\@active_scenarios\)/,
	'h3 cc perf derives run count from configured scenario count');
like($quic_perf, qr/'--rate-bps',\s*\$scenario->\{rate_bps\}/,
	'h3 cc perf wires configured scenario rate to forwarder');
like($quic_perf, qr/'--loss-warmup-ms',\s*loss_warmup_ms\(\$scenario\)/,
	'h3 cc perf defers synthetic ppm loss until after path warmup');
like($quic_perf, qr/sub loss_warmup_ms/,
	'h3 cc perf derives loss warmup from scenario RTT');
like($quic_perf, qr/sub forwarder_delay_ms/,
	'h3 cc perf converts scenario RTT to one-way forwarder delay');
like($quic_perf, qr/'--delay-ms',\s*forwarder_delay_ms\(\$scenario\)/,
	'h3 cc perf wires derived one-way delay to forwarder');
like($quic_perf, qr/'--outage-after-ms',\s*\$scenario->\{outage_after_ms\}/,
	'h3 cc perf wires outage start to forwarder');
like($quic_perf, qr/'--outage-duration-ms',\s*\$scenario->\{outage_duration_ms\}/,
	'h3 cc perf wires outage duration to forwarder');
like($quic_perf, qr/name\s*=>\s*'path-outage-recovery'[\s\S]+outage_after_ms\s*=>\s*4000[\s\S]+outage_duration_ms\s*=>\s*1500/s,
	'h3 cc perf includes explicit outage and recovery scenario');
like($quic_perf, qr/'--duration-ms',\s*SCENARIO_DURATION_MS/,
	'h3 cc perf runs forwarder for scenario duration');
like($quic_perf, qr/SCENARIO_DURATION_MS\s*\+\s*FORWARDER_DRAIN_MS/,
	'h3 cc perf keeps delayed packets meaningful after scenario window');
like($quic_perf, qr/ANGIE_CC_PERF_FULL/,
	'h3 cc perf exposes full matrix mode');
like($quic_perf, qr/\$runs_per_case\s*=\s*RUNS_PER_CASE/,
	'h3 cc perf uses three measured runs in smoke and full modes');
like($quic_perf, qr/if\s*\(\$executed\s*<\s*\$tuple_count\)[\s\S]+
	RUN_GAP_MS\s*\/\s*1000/sx,
	'h3 cc perf applies configured run gap between every measured tuple');
like($quic_perf, qr/run_case\(\$case,\s*\$scenario,\s*\$run\)/,
	'h3 cc perf executes each case/scenario/run tuple through one path');
like($quic_perf, qr/for\s+my\s+\$scenario\s+\(\@active_scenarios\)\s+\{[\s\S]+
	for\s+my\s+\$case\s+\(\@cases\)\s+\{[\s\S]+
	for\s+my\s+\$run\s+\(1\s+\.\.\s+\$runs_per_case\)/sx,
	'h3 cc perf repeats each case scenario combination before moving on');
like($quic_perf, qr/\$servers\s*\.=\s*<<"EOF";[\s\S]+
	listen\s+127\.0\.0\.1:\$listen\s+quic;[\s\S]+
	quic_cc\s+\$case->\{cc\};/sx,
	'h3 cc perf builds Angie QUIC server blocks for every case');
like($quic_perf, qr/\$t->run\(\);/,
	'h3 cc perf starts the Angie binary as the QUIC server');
like($quic_perf, qr/quic_gso\s+on;/,
	'h3 cc perf enables QUIC GSO on perf servers');
like($quic_perf, qr/http3_stream_buffer_size\s+\$perf_stream_buffer_size;/,
	'h3 cc perf raises the H3 stream buffer for perf responses');
like($quic_perf, qr/keepalive_requests\s+100000;/,
	'h3 cc perf avoids server keepalive throttling during 10s samples');
unlike($quic_perf, qr/control_h3_server|run_source_control/,
	'h3 cc perf does not use a standalone control server runtime path');
like($quic_perf, qr/my %perf_results;/,
	'h3 cc perf stores metrics for each case/scenario/run');
like($quic_perf, qr/record_perf_result\(\$case,\s*\$scenario,\s*\$run,/,
	'h3 cc perf records measured throughput latency and jitter');
like($quic_perf, qr/PERF_STREAM_RESPONSE_BYTES/,
	'h3 cc perf uses the configured performance response size');
like($quic_perf, qr/PERF_PARALLEL_STREAMS/,
	'h3 cc perf uses the configured parallel perf stream count');
like($quic_perf, qr/run_h3_client\(\$listen_id,\s*'\/perf\.bin'/,
	'h3 cc perf uses tests/cc C client for sustained samples');
like($quic_perf, qr/PERF_READ_TIMEOUT_SEC/,
	'h3 cc perf keeps configured read timeout for perf path');
like($quic_perf, qr/status=200 bytes=\(\\d\+\) requests=\(\\d\+\) output=/s,
	'h3 cc perf measures throughput from C-client reported bytes');
like($quic_perf, qr/\$summary\s*=\s*run_h3_client\(\$listen_id,\s*'\/perf\.bin',/s,
	'h3 cc perf keeps requesting payload until the 10s sample window ends');
like($quic_perf, qr/\$expected\s*=\s*PERF_STREAM_RESPONSE_BYTES\s*\*\s*\(\$reported_requests \|\| 0\)/,
	'h3 cc perf accounts every payload batch in the sample window');
like($quic_perf, qr/sample duration/,
	'h3 cc perf asserts the measured sample reaches the scenario duration');
like($quic_perf, qr/payload_bytes=.*sample_ms=.*samples=/s,
	'h3 cc perf emits sample duration and payload diagnostics');
like($quic_perf, qr/sub inline_certificates/,
	'h3 cc perf inlines generated test certificates before startup');
like($quic_perf, qr/run_h3_client\(/,
	'h3 cc perf routes requests through tests/cc C client wrapper');
like($quic_perf, qr/--authority',\s*\$authority/s,
	'h3 cc perf passes authority to tests/cc C client');
like($quic_perf, qr/--connect-port',\s*port\(\$listen_id,\s*udp\s*=>\s*1\)/s,
	'h3 cc perf passes forwarder port to tests/cc C client');
like($quic_perf, qr/--path',\s*\$path/s,
	'h3 cc perf passes request path to tests/cc C client');
like($quic_perf, qr/--output',\s*\$output/s,
	'h3 cc perf writes response bodies via tests/cc C client');
like($quic_perf, qr/Test::Nginx::HTTP3->new\(\$listen_id,\s*opts\s*=>\s*perf_transport_params\(\)\)/,
	'h3 cc perf still creates a control H3 connection for setup');
like($quic_perf, qr/push\s+\@cmd,\s*'--duration-ms',\s*\$args\{duration_ms\}/s,
	'h3 cc perf drives sustained samples through one C client duration window');
like($quic_perf, qr/--discard-body'/,
	'h3 cc perf can discard large response bodies during sustained samples');
like($quic_perf, qr/assert_default_profile_acceptance\(\);/,
	'h3 cc perf runs default profile acceptance after collecting metrics');
like($quic_perf, qr/my \@source_profiles\s*=/,
	'h3 cc perf centralizes source profiles');
for my $profile (qw(google sing hy2)) {
	like($quic_perf, qr/profile\s*=>\s*'$profile'/,
		"h3 cc perf source profile $profile configured");
}
like($quic_perf, qr/assert_source_profile_equivalence\(\);/,
	'h3 cc perf runs source profile equivalence gates');
like($quic_perf, qr/sub aggregate_perf_results/,
	'h3 cc perf aggregates repeated performance runs');
like($quic_perf, qr/sub perf_score/,
	'h3 cc perf computes a composite performance score');
like($quic_perf, qr/\$metric->\{throughput\}/,
	'h3 cc perf score uses measured throughput');
like($quic_perf, qr/\$metric->\{latency_ms\}/,
	'h3 cc perf score uses measured latency');
like($quic_perf, qr/\$metric->\{jitter\}/,
	'h3 cc perf score uses measured jitter');
like($quic_perf, qr/perf_metrics.*throughput_bps.*loss_rate_ppm.*jitter/s,
	'h3 cc perf outputs rate loss and jitter metrics');
like($quic_perf, qr/\$bytes\s*\*\s*8\s*\/\s*\$elapsed/,
	'h3 cc perf reports throughput_bps as bits per second');
like($quic_perf, qr/meaningful_throughput_bps/,
	'h3 cc perf requires meaningful scenario throughput');
like($quic_perf, qr/scenario_rate_bps/,
	'h3 cc perf emits scenario rate with performance metrics');
like($quic_perf, qr/rate_bps.*MIN_MEANINGFUL_THROUGHPUT_BPS/s,
	'h3 cc perf validates scenario rates against the WCDMA floor');
like($quic_perf, qr/MAX_MEANINGFUL_THROUGHPUT_BPS/,
	'h3 cc perf validates scenario rates against the 1Gbps ceiling');
like($quic_perf, qr/forwarder_metrics/,
	'h3 cc perf reads forwarder network statistics');
like($quic_perf, qr/finalize_forwarder\(\$pid\);/,
	'h3 cc perf finalizes forwarder before reading final stats');
like($quic_perf, qr/cmp_ok\(\$fw->\{packets_in\} \|\| 0,\s*'>',\s*0/s,
	'h3 cc perf requires nonzero inbound forwarder stats');
like($quic_perf, qr/cmp_ok\(\$fw->\{packets_out\} \|\| 0,\s*'>',\s*0/s,
	'h3 cc perf requires nonzero outbound forwarder stats');
like($quic_perf, qr/perf_comparison scenario=[\s\S]*baseline=[\s\S]*ratio=/,
	'h3 cc perf emits default profile comparison diagnostics');

my $conf = read_file("$root/src/event/quic/ngx_event_quic.h");
like($conf, qr/ngx_uint_t\s+cc_algorithm/,
	'QUIC config stores selected cc algorithm');
like($conf, qr/NGX_QUIC_CC_RENO/, 'QUIC config exposes reno enum');
like($conf, qr/NGX_QUIC_CC_CUBIC/, 'QUIC config exposes cubic enum');

my $cc_h = read_file("$root/src/event/quic/ngx_event_quic_cc.h");
like($cc_h, qr/persistent_congestion/,
	'cc framework exposes persistent congestion callback');

my $transport = read_file("$root/src/event/quic/ngx_event_quic_transport.h");

my $connection = read_file("$root/src/event/quic/ngx_event_quic_connection.h");

my $ack = read_file("$root/src/event/quic/ngx_event_quic_ack.c");
like($ack, qr/ngx_quic_cc_ack\(/, 'ACK path delegates to cc framework');
like($ack, qr/ngx_quic_cc_lost\(/, 'loss path delegates to cc framework');
like($ack, qr/ngx_quic_cc_reset\(/, 'reset path delegates to cc framework');
like($ack, qr/ngx_quic_cc_idle\(/, 'idle path delegates to cc framework');
unlike($ack, qr/NGX_QUIC_CUBIC_(?:BETA|C)/,
	'ACK path no longer owns CUBIC constants');
unlike($ack, qr/static size_t ngx_quic_congestion_cubic/,
	'ACK path no longer owns CUBIC implementation');

my $cc = read_file("$root/src/event/quic/ngx_event_quic_cc.c");
like($cc, qr/ngx_quic_cc_get\(qc\)->persistent_congestion\(c\)/,
	'cc framework notifies selected algorithm about persistent congestion');
like($cc, qr/algo->lost\(c,\s*f\);\s*f->plen = 0/s,
	'cc framework lets loss callbacks inspect lost bytes');

my $output = read_file("$root/src/event/quic/ngx_event_quic_output.c");

my $native_perf = read_file("$root/tests/quic_cc/test_cc_perf.c");
my $cc_makefile = read_file("$root/tests/quic_cc/Makefile");
my $forwarder = read_file("$root/tests/quic_cc/forwarder.c");
unlike($native_perf, qr/base_scenarios|base_scenario_count/,
	'native cc performance matrix uses one unified scenario list');
like($native_perf, qr/scenario_count\s*<\s*10/,
	'native cc performance matrix requires broad scenario coverage');
like($native_perf, qr/max_realistic_rate_bps/,
	'native cc performance matrix documents 1Gbps upper rate');
like($native_perf, qr/min_realistic_rate_bps/,
	'native cc performance matrix documents WCDMA lower rate');
like($native_perf, qr/unsigned\s+rate_bps/,
	'native cc performance matrix stores per-scenario rates');
like($native_perf, qr/s->rate_bps\s*<\s*min_realistic_rate_bps/,
	'native cc performance matrix validates per-scenario rates');
like($native_perf, qr/\{\s*"geo-satellite",\s*10000000,\s*500,\s*20,\s*10000,\s*0,\s*0\s*\}/,
	'native cc performance matrix keeps GEO satellite RTT realistic');
like($native_perf, qr/\{\s*"china-cross-border-iepl",\s*10000000,\s*30,\s*1,\s*100,\s*0,\s*0\s*\}/,
	'native cc performance matrix keeps IEPL RTT realistic');
unlike($native_perf, qr/control_h3_server|control_selftest|source_controls/,
	'native cc performance matrix does not use a control H3 server');
like($cc_makefile, qr/h3_client/,
	'cc Makefile builds C HTTP3 client');
like($cc_makefile, qr/nghttp3/,
	'cc Makefile links libnghttp3 for C client');
like($cc_makefile, qr/ssl|crypto/,
	'cc Makefile links OpenSSL QUIC dependencies for C client');
like($forwarder, qr/queued_packet_t/,
	'forwarder queues packets instead of serializing delay');
like($forwarder, qr/flush_due_packets/,
	'forwarder flushes delayed packets by due time');
like($forwarder, qr/strcmp\(argv\[i\],\s*"--rate-bps"\)/,
	'forwarder accepts a configured link rate');
like($forwarder, qr/strcmp\(argv\[i\],\s*"--loss-warmup-ms"\)/,
	'forwarder accepts a loss warmup interval');
like($forwarder, qr/elapsed\s*>=\s*conf->loss_warmup_ms/,
	'forwarder applies ppm loss after the warmup interval');
like($forwarder, qr/next_rand\(rnd\)\s*%\s*1000000u\s*<\s*conf->loss_ppm/,
	'forwarder uses deterministic pseudo-random ppm loss');
like($forwarder, qr/from_target/,
	'forwarder identifies server-to-client packets');
like($forwarder, qr/should_drop\(&conf,\s*start_ms,\s*&rnd,\s*from_target\)/,
	'forwarder applies ppm loss only to response data direction');
like($forwarder, qr/packet_send_time_us/,
	'forwarder paces packets by configured link rate');
like($forwarder, qr/unsigned char\s+data\[\]/,
	'forwarder queue allocates packet payloads by actual datagram length');
like($forwarder, qr/write_stats\(&conf,\s*&stats\);\s*free_queue/s,
	'forwarder writes final stats once after the run completes');
like($forwarder, qr/fcntl\(fd,\s*F_SETFL,\s*flags\s*\|\s*O_NONBLOCK\)/,
	'forwarder switches the UDP socket to nonblocking mode');
like($forwarder, qr/setsockopt\(fd,\s*SOL_SOCKET,\s*SO_RCVBUF/s,
	'forwarder raises the UDP receive buffer');
like($forwarder, qr/setsockopt\(fd,\s*SOL_SOCKET,\s*SO_SNDBUF/s,
	'forwarder raises the UDP send buffer');
like($forwarder, qr/errno\s*==\s*EAGAIN\s*\|\|\s*errno\s*==\s*EWOULDBLOCK/s,
	'forwarder drains all readable datagrams before returning to select');
like($forwarder, qr/client_due_us/,
	'forwarder preserves client-side packet order under jitter');
like($forwarder, qr/target_due_us/,
	'forwarder preserves target-side packet order under jitter');
unlike($forwarder, qr/due_us\s*=\s*(?:client|target)_due_us\s*\+\s*1000/,
	'forwarder order preservation does not add a hidden 1ms packet throttle');
like($forwarder, qr/if\s*\(due_us\s*<\s*client_due_us\)\s*\{\s*
	\s*due_us\s*=\s*client_due_us;/sx,
	'forwarder clamps client-side packets without spacing same-ms bursts');
like($forwarder, qr/if\s*\(due_us\s*<\s*target_due_us\)\s*\{\s*
	\s*due_us\s*=\s*target_due_us;/sx,
	'forwarder clamps target-side packets without spacing same-ms bursts');

my $log = "quic_cc/cc_native.log";
my $rc = system("make -C quic_cc clean test "
	. "> $log 2>&1");
is($rc, 0, 'native cc performance harness builds and runs');
my $native_log = read_file($log);
my ($scenario_count) = $native_log =~
	/algorithms=6 scenarios=(\d+) runs_per_case=3 duration=10s gap=5s/;
ok(defined $scenario_count,
	'native cc performance matrix reports parseable scenario counts');
cmp_ok($scenario_count, '>=', 10,
	'native cc performance matrix covers broad unified scenarios');
for my $scenario (qw(
	internet-backbone ftth-bufferbloat wifi-random-loss cellular-4g5g
	quic-public-video webrtc-rtc leo-satellite geo-satellite
	china-cross-border-iepl
)) {
	like($native_log, qr/scenario $scenario configured/,
		"native cc performance matrix includes $scenario");
}
unlike($native_log, qr/source_controls/,
	'native cc performance matrix omits source-profile control servers');

done_testing();

###############################################################################

sub read_file {
	my ($path) = @_;

	open my $fh, '<', $path or die "open $path failed: $!";
	local $/;
	return <$fh>;
}

###############################################################################
