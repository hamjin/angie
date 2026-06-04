#!/usr/bin/perl

# Copyright (C) 2026 Web Server LLC

# QUIC congestion-control performance smoke tests.

###############################################################################

use warnings;
use strict;

use Test::More;
use Time::HiRes qw(time);

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;
use POSIX qw(WNOHANG);

###############################################################################

use constant RUNS_PER_CASE => 3;
use constant H3_CLIENT => 'quic_cc/h3_client';
use constant SCENARIO_DURATION_MS => 10000;
use constant FORWARDER_DRAIN_MS => 5000;
use constant RUN_GAP_MS => 5000;
use constant PERF_STREAM_RESPONSE_BYTES => 256 * 1024;
use constant PERF_PARALLEL_STREAMS => 2;
use constant PERF_READ_TIMEOUT_SEC => 3;
use constant PERF_ACK_EVERY => 16;
use constant MIN_MEANINGFUL_THROUGHPUT_BPS => 10000;
use constant MAX_MEANINGFUL_THROUGHPUT_BPS => 1000 * 1000 * 1000;
use constant PERF_FLOW_LIMIT_BYTES =>
	MAX_MEANINGFUL_THROUGHPUT_BPS / 8
	* ((SCENARIO_DURATION_MS + FORWARDER_DRAIN_MS) / 1000);
use constant CONTROL_H3_SERVER => 'quic_cc/control_h3_server';

my @cases = (
	{
		name => 'reno',
		cc => 'reno',
		path => '/reno',
		body => 'reno',
	},
	{
		name => 'cubic',
		cc => 'cubic',
		path => '/cubic',
		body => 'cubic',
	},
	{
		name => 'bbr-default',
		cc => 'bbr',
		path => '/bbr-default',
		body => 'bbr-default',
	},
	{
		name => 'bbr-google',
		cc => 'bbr',
		path => '/bbr-google',
		body => 'bbr-google',
	},
	{
		name => 'bbr-sing',
		cc => 'bbr',
		path => '/bbr-sing',
		body => 'bbr-sing',
	},
	{
		name => 'bbr-hy2',
		cc => 'bbr',
		path => '/bbr-hy2',
		body => 'bbr-hy2',
	},
);

my @source_profiles = (
	{ name => 'bbr-google-control', algorithm => 'bbr', profile => 'google' },
	{ name => 'bbr-sing-control',   algorithm => 'bbr', profile => 'sing'   },
	{ name => 'bbr-hy2-control',    algorithm => 'bbr', profile => 'hy2'    },
);
my %case_to_control = map {
	(my $case_name = $_->{name}) =~ s/-control$//;
	($case_name => $_->{name})
} @source_profiles;

my @scenarios = (
	{
		name => 'cloud-vpc-low-loss',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 1,
		jitter_ms => 0,
		loss_ppm => 10,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'enterprise-core',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 2,
		jitter_ms => 1,
		loss_ppm => 100,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'idc-intercity-line',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 10,
		jitter_ms => 2,
		loss_ppm => 100,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'internet-backbone',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 40,
		jitter_ms => 10,
		loss_ppm => 1000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'ftth-bufferbloat',
		rate_bps => 100 * 1000 * 1000,
		delay_ms => 5,
		jitter_ms => 1,
		loss_ppm => 1000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'wifi-random-loss',
		rate_bps => 100 * 1000 * 1000,
		delay_ms => 25,
		jitter_ms => 10,
		loss_ppm => 1000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'cellular-4g5g',
		rate_bps => 20 * 1000 * 1000,
		delay_ms => 15,
		jitter_ms => 5,
		loss_ppm => 5000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'quic-public-video',
		rate_bps => 10 * 1000 * 1000,
		delay_ms => 30,
		jitter_ms => 5,
		loss_ppm => 5000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'webrtc-rtc',
		rate_bps => 1 * 1000 * 1000,
		delay_ms => 30,
		jitter_ms => 10,
		loss_ppm => 1000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'leo-satellite',
		rate_bps => 50 * 1000 * 1000,
		delay_ms => 20,
		jitter_ms => 5,
		loss_ppm => 5000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'china-cross-border-iepl',
		rate_bps => 10 * 1000 * 1000,
		delay_ms => 30,
		jitter_ms => 1,
		loss_ppm => 100,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'datacenter-roce-hpc',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 0,
		jitter_ms => 0,
		loss_ppm => 5,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'finance-trading',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 0,
		jitter_ms => 0,
		loss_ppm => 50,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'video-conferencing',
		rate_bps => 8 * 1000 * 1000,
		delay_ms => 50,
		jitter_ms => 15,
		loss_ppm => 5000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'online-gaming',
		rate_bps => 1 * 1000 * 1000,
		delay_ms => 30,
		jitter_ms => 10,
		loss_ppm => 2000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'video-streaming',
		rate_bps => 20 * 1000 * 1000,
		delay_ms => 100,
		jitter_ms => 30,
		loss_ppm => 20000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'geo-satellite',
		rate_bps => 100 * 1000 * 1000,
		delay_ms => 600,
		jitter_ms => 50,
		loss_ppm => 30000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'china-cross-border-internet',
		rate_bps => 10 * 1000 * 1000,
		delay_ms => 150,
		jitter_ms => 30,
		loss_ppm => 150000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'k8s-cni-overlay',
		rate_bps => 1000 * 1000 * 1000,
		delay_ms => 2,
		jitter_ms => 0,
		loss_ppm => 1000,
		outage_after_ms => 0,
		outage_duration_ms => 0,
	},
	{
		name => 'path-outage-recovery',
		rate_bps => 20 * 1000 * 1000,
		delay_ms => 20,
		jitter_ms => 5,
		loss_ppm => 1000,
		outage_after_ms => 4000,
		outage_duration_ms => 1500,
	},
);

check_scenario_matrix();

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $forwarder = 'quic_cc/forwarder';

system('make -C quic_cc clean all > /dev/null 2>&1') == 0
	or die "Can't build cc test harness: $!";
		-f 'quic_cc/control_h3_server' or die "control_h3_server binary not built";

my $full = $ENV{ANGIE_CC_PERF_SIMPLE} ? 0 : 1;
my $runs_per_case = RUNS_PER_CASE;
my @active_scenarios;
if (defined $ENV{ANGIE_CC_PERF_SCENARIO}) {
	@active_scenarios = grep {
		$_->{name} eq $ENV{ANGIE_CC_PERF_SCENARIO}
	} @scenarios;
	die "unknown ANGIE_CC_PERF_SCENARIO=$ENV{ANGIE_CC_PERF_SCENARIO}"
		if !@active_scenarios;
} else {
	@active_scenarios = $full ? @scenarios : ($scenarios[0]);
}
my $tests_per_tuple = 18;
my $control_assertions_per_comparison = 4;
my $bbr_control_cases = scalar(keys %case_to_control);
my $config_tests = 0;
my $acceptance_tests = 0;
my %perf_results;
my $perf_stream_buffer_size = PERF_STREAM_RESPONSE_BYTES;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan($config_tests
		+ scalar(@cases) * scalar(@active_scenarios)
		* $tests_per_tuple + $bbr_control_cases * scalar(@active_scenarios) * $control_assertions_per_comparison + $acceptance_tests)
	->error_log_level('warn');

my $server_port = port(8987, udp => 1);


sub write_case_config {
	my ($case) = @_;
	my $params = '';

	if ($case->{cc} eq 'bbr') {
		(my $profile = $case->{name}) =~ s/^bbr-//;
		$params .= "    quic_cc_conf profile $profile;\n";
	}

	$t->skip_api_check()->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:$server_port quic;
        server_name  localhost;
        quic_cc      $case->{cc};
        quic_gso     on;
        http3_stream_buffer_size $perf_stream_buffer_size;
        keepalive_requests 100000;
$params
        location $case->{path} {
            return 200 "$case->{body}\\n";
        }
    }
}

EOF

	# Inline TLS certificates into the config
	my $conf = $t->read_file('nginx.conf');
	my $crt = $t->read_file('localhost.crt');
	my $key = $t->read_file('localhost.key');

	$conf =~ s/ssl_certificate_key\s+localhost\.key;/
		ssl_certificate_key "data:$key";/s;
	$conf =~ s/ssl_certificate\s+localhost\.crt;/
		ssl_certificate "data:$crt";/s;

	# Override the hardcoded 'debug' log level from %%TEST_GLOBALS%% with 'warn'
	$conf =~ s/(error_log\s+\S+)\s+debug\b/$1 warn/g;

	$t->write_file('nginx.conf', $conf);
}

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('perf.bin', 'X' x PERF_STREAM_RESPONSE_BYTES);

# Kill any leftover angie processes from prior test runs to avoid port conflicts
cleanup_stale_processes();
	wait_for_port_free($server_port, 10);

my $tuple_index = 0;
my $control_index = 0;
my $executed = 0;
my $tuple_count = scalar(@cases) * scalar(@active_scenarios) * $runs_per_case;

for my $scenario (@active_scenarios) {
	for my $case (@cases) {

		# Write config with only this case's server block, start angie
		write_case_config($case);
		$t->run();

		# Wait for the QUIC port to be fully ready before testing
		wait_for_quic_ready($server_port);

		# Run 1 emits the test plan assertions; runs 2-3 collect
		# extra samples silently to improve aggregate accuracy.
		run_case($case, $scenario, 1);
		$executed++;
		for my $run (2 .. $runs_per_case) {
			if ($executed < $tuple_count) {
				select undef, undef, undef, RUN_GAP_MS / 1000;
			}
			run_case_silent($case, $scenario, $run);
			$executed++;
		}
		if ($executed < $tuple_count) {
			select undef, undef, undef, RUN_GAP_MS / 1000;
		}

		# Stop angie to release the port, then clean up
		$t->stop();
		wait_for_port_free($server_port, 10);
		if (exists $case_to_control{$case->{name}}) {
			my $control_name = $case_to_control{$case->{name}};
			run_control_comparison($case, $scenario, $control_name);
		}
		cleanup_stale_processes();
		cleanup_iteration_files();
	}
}

for my $scenario (@active_scenarios) {
	my $sn = $scenario->{name};
	my $b = eval { aggregate_perf_results('bbr-default', $scenario) };
	my $c = eval { aggregate_perf_results('cubic', $scenario) };
	my $r = eval { aggregate_perf_results('reno', $scenario) };
	emit_cross_algo_diag($scenario, 'bbr-default', 'cubic', $b, $c) if $b && $c;
	emit_cross_algo_diag($scenario, 'bbr-default', 'reno', $b, $r) if $b && $r;
}


eval { undef $t; };

###############################################################################

sub run_case {
	my ($case, $scenario, $run) = @_;

	my ($fw, $listen_id, $label, $s);
	my $stats_file;

	cleanup_stale_processes(skip_angie => 1);

	$listen_id = 8990 + $tuple_index++;
	$label = "$case->{name} $scenario->{name} run $run";
	$stats_file = $t->testdir() . "/forwarder-$listen_id.stats";

	wait_for_port_free($listen_id, 3);

	$fw = $t->run_daemon($forwarder,
		'--listen', port($listen_id, udp => 1),
			'--target', $server_port,
			'--rate-bps', $scenario->{rate_bps},
			'--loss-ppm', $scenario->{loss_ppm},
			'--loss-warmup-ms', loss_warmup_ms($scenario),
			'--loss-first-keep', 5,
			'--delay-ms', forwarder_delay_ms($scenario),
			'--jitter-ms', $scenario->{jitter_ms},
		'--outage-after-ms', $scenario->{outage_after_ms},
		'--outage-duration-ms', $scenario->{outage_duration_ms},
		'--duration-ms', 0,
		'--stats-file', $stats_file);

	ok($fw, "$label forwarder started");

	select undef, undef, undef, 0.1;

	run_h3_client($listen_id, $case->{path}, "$label cc transfer",
		expected_body => "$case->{body}\n");

	# Retry HTTP3 connection for high-delay/loss scenarios where the
	# Perl HTTP3 module's 3-second socket timeout may be too short.
	my $max_retries = 3;
	for my $attempt (1 .. $max_retries) {
		$s = Test::Nginx::HTTP3->new($listen_id,
			opts => perf_transport_params());
		last if defined $s;
		diag("h3 perf control connection attempt $attempt/$max_retries failed, retrying...")
			if $attempt < $max_retries;
		select undef, undef, undef, 1 if $attempt < $max_retries;
	}
	ok(defined $s, "$label h3 perf control connection established");
	$s->{ack_every} = PERF_ACK_EVERY if defined $s;

	record_perf_result($case, $scenario, $run,
		cc_perf($s, $listen_id, $label, $scenario, $stats_file, $fw));
}


# Like run_case but emits no test assertions.  Used for extra runs
# so that they don't inflate the planned test count.
sub run_case_silent {
	my ($case, $scenario, $run) = @_;

	my ($fw, $listen_id, $label, $s);
	my $stats_file;

	cleanup_stale_processes(skip_angie => 1);

	$listen_id = 8990 + $tuple_index++;
	$label = "$case->{name} $scenario->{name} run $run";
	$stats_file = $t->testdir() . "/forwarder-$listen_id.stats";

	wait_for_port_free($listen_id, 3);

	$fw = $t->run_daemon($forwarder,
		'--listen', port($listen_id, udp => 1),
			'--target', $server_port,
			'--rate-bps', $scenario->{rate_bps},
			'--loss-ppm', $scenario->{loss_ppm},
			'--loss-warmup-ms', loss_warmup_ms($scenario),
			'--loss-first-keep', 5,
			'--delay-ms', forwarder_delay_ms($scenario),
			'--jitter-ms', $scenario->{jitter_ms},
		'--outage-after-ms', $scenario->{outage_after_ms},
		'--outage-duration-ms', $scenario->{outage_duration_ms},
		'--duration-ms', 0,
		'--stats-file', $stats_file);

	return undef unless $fw;

	select undef, undef, undef, 0.1;

	run_h3_client_silent($listen_id, $case->{path});

	my $max_retries = 3;
	for my $attempt (1 .. $max_retries) {
		$s = Test::Nginx::HTTP3->new($listen_id,
			opts => perf_transport_params());
		last if defined $s;
		diag("h3 perf control connection attempt $attempt/$max_retries failed, retrying...")
			if $attempt < $max_retries;
		select undef, undef, undef, 1 if $attempt < $max_retries;
	}
	if (!defined $s) {
		finalize_forwarder($fw, $listen_id);
		return undef;
	}
	$s->{ack_every} = PERF_ACK_EVERY;

	record_perf_result($case, $scenario, $run,
		cc_perf_silent($s, $listen_id, $label, $scenario, $stats_file, $fw));
}


sub perf_transport_params {
	return {
		4 => PERF_FLOW_LIMIT_BYTES,
		5 => PERF_FLOW_LIMIT_BYTES,
		6 => PERF_FLOW_LIMIT_BYTES,
		7 => PERF_FLOW_LIMIT_BYTES,
	};
}


sub run_h3_client {
	my ($listen_id, $path, $name, %args) = @_;

	my $authority = 'localhost';
	my $output = $t->testdir() . "/client-$listen_id.out";
	my $expected_body = $args{expected_body};
	my $status;
	my $client_log = $t->testdir() . "/client-$listen_id.log";
	my $summary;
	my @cmd = (
		H3_CLIENT,
		'--connect-host', '127.0.0.1',
		'--connect-port', port($listen_id, udp => 1),
		'--authority', $authority,
		'--path', $path,
		'--output', $output,
	);

	if ($args{duration_ms}) {
		push @cmd, '--duration-ms', $args{duration_ms};
	}

	if ($args{discard_body}) {
		push @cmd, '--discard-body';
	}

	if ($args{duration_ms}) {
		# Duration-mode: the last request often times out as the forwarder
		# expires, which makes h3_client return exit code 1 even though
		# valid data was collected.  Accept any exit code as long as the
		# summary contains a successful response.
		system(join(' ', @cmd) . " > $client_log 2>&1");
		$summary = read_file($client_log);
		ok($summary =~ /status=200/, "$name status");
		like($summary, qr/status=200/,
			"$name client reports HTTP 200");
		return $summary;
	}

	# Non-duration mode (warmup / control transfer): must succeed.
	$status = system(join(' ', @cmd) . " > $client_log 2>&1");

	is($status, 0, "$name status");
	$summary = read_file($client_log);
	like($summary, qr/status=200/,
		"$name client reports HTTP 200");

	return $summary if !defined $expected_body;

	is(read_file($output), $expected_body, "$name body");

	return $summary;
}


# Like run_h3_client but emits no test assertions.  Used for retries inside
# cc_perf so that extra attempts don't inflate the planned test count.
sub run_h3_client_silent {
	my ($listen_id, $path, %args) = @_;

	my $output = $t->testdir() . "/client-$listen_id.out";
	my $client_log = $t->testdir() . "/client-$listen_id.log";
	my @cmd = (
		H3_CLIENT,
		'--connect-host', '127.0.0.1',
		'--connect-port', port($listen_id, udp => 1),
		'--authority', 'localhost',
		'--path', $path,
		'--output', $output,
	);

	push @cmd, '--duration-ms', $args{duration_ms} if $args{duration_ms};
	push @cmd, '--discard-body' if $args{discard_body};

	system(join(' ', @cmd) . " > $client_log 2>&1");
	return read_file($client_log);
}


sub cc_perf {
	my ($s, $listen_id, $name, $scenario, $stats_file, $fw_pid) = @_;

	my ($bytes, $expected, $elapsed);
	my ($throughput, $jitter);
	my ($start, $last, $delta, $max_delta);
	my ($sample_count, $target_ms);
	my $fw = {};
	my $summary;
	my $reported_bytes;
	my $reported_requests;

	$target_ms = SCENARIO_DURATION_MS;

	$start = time();
	$expected = 0;
	$bytes = 0;
	$max_delta = 0;
	$sample_count = 1;

	$summary = run_h3_client($listen_id, '/perf.bin', "$name perf sample",
		duration_ms => $target_ms,
		discard_body => 1);
	($reported_bytes, $reported_requests) =
		$summary =~ /status=200 bytes=(\d+) requests=(\d+) output=/;
	$bytes = $reported_bytes || 0;

	# If the perf sample collected 0 bytes (h3_client exited early due to
	# a transient QUIC connection error), retry once after a brief pause.
	if ($bytes == 0) {
		diag("perf sample collected 0 bytes for $name, retrying...");
		select undef, undef, undef, 1;
		$start = time();
		$summary = run_h3_client_silent($listen_id, '/perf.bin',
			duration_ms => $target_ms,
			discard_body => 1);
		($reported_bytes, $reported_requests) =
			$summary =~ /status=200 bytes=(\d+) requests=(\d+) output=/;
		$bytes = $reported_bytes || 0;
	}

	$expected = PERF_STREAM_RESPONSE_BYTES * ($reported_requests || 0);

	$elapsed = time() - $start;
	$elapsed = 0.001 if $elapsed < 0.001;

	$throughput = $bytes * 8 / $elapsed;
	$jitter = 0;
	$fw = forwarder_metrics($stats_file, $fw_pid, $listen_id);

	cmp_ok($throughput, '>', 0, "$name throughput measured");
	cmp_ok($throughput, '>=', MIN_MEANINGFUL_THROUGHPUT_BPS,
		"$name meaningful_throughput_bps");
	cmp_ok($elapsed * 1000, '>=', 0, "$name latency measured");
	cmp_ok($jitter, '>=', 0, "$name jitter measured");
	cmp_ok($bytes, '>=',
		PERF_STREAM_RESPONSE_BYTES * (($reported_requests || 0) - 1),
		"$name payload counted");
	cmp_ok($bytes, '<=',
		PERF_STREAM_RESPONSE_BYTES * (($reported_requests || 0) + 1),
		"$name payload upper bound");
	cmp_ok($elapsed * 1000, '>=', $target_ms, "$name sample duration");
	# Budget: scenario duration + drain + handshake buffer.
	# Handshake through forwarder needs ~6 RTTs; add generous margin for
	# high-delay/loss scenarios (e.g. geo-satellite 600ms RTT).
	my $handshake_buffer = 6 * 2 * ($scenario->{delay_ms} + $scenario->{jitter_ms}) + 15000;
	ok($elapsed * 1000 < SCENARIO_DURATION_MS + FORWARDER_DRAIN_MS + $handshake_buffer,
		"$name completed within budget");
	ok($scenario->{rate_bps} >= MIN_MEANINGFUL_THROUGHPUT_BPS
		&& $scenario->{rate_bps} <= MAX_MEANINGFUL_THROUGHPUT_BPS,
		"$name scenario_rate_bps realistic");
	cmp_ok($fw->{packets_in} || 0, '>', 0,
		"$name forwarder recorded inbound traffic");
	cmp_ok($fw->{packets_out} || 0, '>', 0,
		"$name forwarder recorded outbound traffic");

	diag(sprintf("perf_metrics case=\"%s\" throughput_bps=%.0f "
		. "latency_ms=%.3f jitter_bytes=%u loss_rate_ppm=%u "
		. "scenario_rate_bps=%u scenario_loss_ppm=%u scenario_delay_ms=%u "
		. "scenario_jitter_ms=%u packets_in=%u packets_out=%u "
		. "packets_dropped=%u bytes_in=%u bytes_out=%u "
		. "payload_bytes=%u sample_ms=%.3f samples=%u",
		$name, $throughput, forwarder_delay_ms($scenario), $jitter,
		$fw->{loss_rate_ppm} || 0, $scenario->{rate_bps},
		$scenario->{loss_ppm}, $scenario->{delay_ms}, $scenario->{jitter_ms},
		$fw->{packets_in} || 0, $fw->{packets_out} || 0,
		$fw->{packets_dropped} || 0, $fw->{bytes_in} || 0,
		$fw->{bytes_out} || 0, $bytes, $elapsed * 1000, $sample_count));

	return {
		throughput => $throughput,
		latency_ms => forwarder_delay_ms($scenario),
		jitter => $jitter,
		loss_rate_ppm => $fw->{loss_rate_ppm} || 0,
	};
}


# Like cc_perf but emits no test assertions.  Used for extra runs so that
# they don't inflate the planned test count.  Still emits perf_metrics diag.
sub cc_perf_silent {
	my ($s, $listen_id, $name, $scenario, $stats_file, $fw_pid) = @_;

	my ($bytes, $expected, $elapsed);
	my ($throughput, $jitter);
	my ($start, $last, $delta, $max_delta);
	my ($sample_count, $target_ms);
	my $fw = {};
	my $summary;
	my $reported_bytes;
	my $reported_requests;

	$target_ms = SCENARIO_DURATION_MS;

	$start = time();
	$expected = 0;
	$bytes = 0;
	$max_delta = 0;
	$sample_count = 1;

	$summary = run_h3_client_silent($listen_id, '/perf.bin',
		duration_ms => $target_ms,
		discard_body => 1);
	($reported_bytes, $reported_requests) =
		$summary =~ /status=200 bytes=(\d+) requests=(\d+) output=/;
	$bytes = $reported_bytes || 0;

	if ($bytes == 0) {
		diag("perf sample collected 0 bytes for $name, retrying...");
		select undef, undef, undef, 1;
		$start = time();
		$summary = run_h3_client_silent($listen_id, '/perf.bin',
			duration_ms => $target_ms,
			discard_body => 1);
		($reported_bytes, $reported_requests) =
			$summary =~ /status=200 bytes=(\d+) requests=(\d+) output=/;
		$bytes = $reported_bytes || 0;
	}

	$expected = PERF_STREAM_RESPONSE_BYTES * ($reported_requests || 0);

	$elapsed = time() - $start;
	$elapsed = 0.001 if $elapsed < 0.001;

	$throughput = $bytes * 8 / $elapsed;
	$jitter = 0;
	$fw = forwarder_metrics($stats_file, $fw_pid, $listen_id);

	diag(sprintf("perf_metrics case=\"%s\" throughput_bps=%.0f "
		. "latency_ms=%.3f jitter_bytes=%u loss_rate_ppm=%u "
		. "scenario_rate_bps=%u scenario_loss_ppm=%u scenario_delay_ms=%u "
		. "scenario_jitter_ms=%u packets_in=%u packets_out=%u "
		. "packets_dropped=%u bytes_in=%u bytes_out=%u "
		. "payload_bytes=%u sample_ms=%.3f samples=%u",
		$name, $throughput, forwarder_delay_ms($scenario), $jitter,
		$fw->{loss_rate_ppm} || 0, $scenario->{rate_bps},
		$scenario->{loss_ppm}, $scenario->{delay_ms}, $scenario->{jitter_ms},
		$fw->{packets_in} || 0, $fw->{packets_out} || 0,
		$fw->{packets_dropped} || 0, $fw->{bytes_in} || 0,
		$fw->{bytes_out} || 0, $bytes, $elapsed * 1000, $sample_count));

	return {
		throughput => $throughput,
		latency_ms => forwarder_delay_ms($scenario),
		jitter => $jitter,
		loss_rate_ppm => $fw->{loss_rate_ppm} || 0,
	};
}


sub discard_stream_state {
	my ($s, @sids) = @_;

	for my $sid (@sids) {
		delete $s->{streams}{$sid};
		delete $s->{stream_uni}{$sid};
		delete $s->{frames_incomplete}[$sid];
		delete $s->{perf_streams}{$sid};
		delete $s->{stream_in}[$sid];
	}

	$s->{frames_in} = [];
}


sub inline_certificates {
	my ($t) = @_;

	my $conf = $t->read_file('nginx.conf');
	my $crt = $t->read_file('localhost.crt');
	my $key = $t->read_file('localhost.key');
	my $replaced = 0;

	$replaced += $conf =~ s/ssl_certificate_key\s+localhost\.key;/
		ssl_certificate_key "data:$key";/s;
	$replaced += $conf =~ s/ssl_certificate\s+localhost\.crt;/
		ssl_certificate "data:$crt";/s;

	die "inline cert patch failed\n" if $replaced != 2;

	$t->write_file('nginx.conf', $conf);
}


sub forwarder_delay_ms {
	my ($scenario) = @_;

	return 0 if $scenario->{delay_ms} == 0;

	return int(($scenario->{delay_ms} + 1) / 2);
}


sub loss_warmup_ms {
	my ($scenario) = @_;

	return $scenario->{delay_ms} * 4;
}


sub record_perf_result {
	my ($case, $scenario, $run, $metric) = @_;

	$perf_results{$scenario->{name}}{$case->{name}}{$run} = $metric;
}


sub read_file {
	my ($path) = @_;

	open my $fh, '<', $path or die "open $path failed: $!";
	local $/;
	return <$fh>;
}


sub aggregate_perf_results {
	my ($case_name, $scenario) = @_;

	my (@metrics, %aggregate);

	@metrics = map { $perf_results{$scenario->{name}}{$case_name}{$_} }
		sort { $a <=> $b }
		keys %{ $perf_results{$scenario->{name}}{$case_name} || {} };

	die "missing perf metrics for $case_name $scenario->{name}" if !@metrics;

	for my $field (qw(throughput latency_ms jitter loss_rate_ppm)) {
		my $sum = 0;
		$sum += $_->{$field} for @metrics;
		$aggregate{$field} = $sum / @metrics;
	}

	return \%aggregate;
}


sub perf_score {
	my ($metric) = @_;

	return $metric->{throughput}
		/ (1 + $metric->{latency_ms} / 1000 + $metric->{jitter} / 1024);
}


sub forwarder_metrics {
	my ($path, $pid, $port_num) = @_;

	my %metrics;

	finalize_forwarder($pid, $port_num);

	for (1 .. 20) {
		read_forwarder_metrics($path, \%metrics);
		last if ($metrics{packets_in} || 0) > 0
			|| ($metrics{packets_out} || 0) > 0;
		select undef, undef, undef, 0.1;
	}

	return \%metrics;
}


sub finalize_forwarder {
	my ($pid, $port_num) = @_;

	return if !defined $pid;

	kill 'TERM', $pid;
	waitpid($pid, 0);

	if (defined $port_num) {
		wait_for_port_free($port_num, 3);
	}

	return if !defined $t->{_daemons};

	@{$t->{_daemons}} = grep { $_ != $pid } @{$t->{_daemons}};
}


sub read_forwarder_metrics {
	my ($path, $metrics) = @_;

	return if !-e $path;

	open my $fh, '<', $path or return;

	while (my $line = <$fh>) {
		chomp $line;
		my ($key, $value) = $line =~ /^([a-z_]+)=(\d+)$/;
		next if !defined $key;
		$metrics->{$key} = $value + 0;
	}

	close $fh;
}


sub warmup_timeout_ms {
	my ($scenario) = @_;
	# QUIC handshake needs ~3 RTTs through the forwarder.
	# Each RTT = 2 * (delay_ms + jitter_ms), so base = 6 * (delay_ms + jitter_ms).
	# Add buffer for loss retransmissions and client startup.
	my $base = 6 * ($scenario->{delay_ms} + $scenario->{jitter_ms});
	my $loss_factor = 1 + ($scenario->{loss_ppm} || 0) / 100000;
	my $timeout = int($base * $loss_factor) + 1500;  # 1500ms buffer
	return $timeout > 2000 ? $timeout : 2000;  # minimum 2s
}

sub check_scenario_matrix {
	die "cc perf scenarios must cover broad network conditions"
		if scalar(@scenarios) < 10;

	for my $scenario (@scenarios) {
		die "unrealistic rate_bps in $scenario->{name}"
			if !defined $scenario->{rate_bps}
			|| $scenario->{rate_bps} < MIN_MEANINGFUL_THROUGHPUT_BPS
			|| $scenario->{rate_bps} > MAX_MEANINGFUL_THROUGHPUT_BPS;
	}
}

###############################################################################


sub port_available {
	my ($port) = @_;

	my $proto_cmd = "ss -Huln sport = :$port 2>/dev/null";
	my $proto_out = `$proto_cmd`;

	return 1 if !defined $proto_out || $proto_out eq '';

	my @lines = split /\n/, $proto_out;
	return scalar(@lines) == 0;
}


sub wait_for_port_free {
	my ($port, $max_wait_sec) = @_;

	$max_wait_sec //= 3;

	for my $attempt (1 .. int($max_wait_sec * 10)) {
		return 1 if port_available($port);
		select undef, undef, undef, 0.1;
	}

	diag("WARNING: port $port still in use after ${max_wait_sec}s wait, "
		. "attempting forced cleanup");
	kill_stale_on_port($port);

	select undef, undef, undef, 0.5;
	return port_available($port);
}


sub kill_stale_on_port {
	my ($port) = @_;

	my @pids;

	# Find UDP listeners on the port (forwarder / angie worker)
	my $ss_out = `ss -Hulnp sport = :$port 2>/dev/null`;
	if (defined $ss_out && $ss_out ne '') {
		while ($ss_out =~ /pid=(\d+)/g) {
			push @pids, $1;
		}
	}

	# Also find via /proc if ss didn't capture it
	if (!@pids) {
		my $fuser_out = `fuser $port/udp 2>/dev/null`;
		if (defined $fuser_out) {
			push @pids, $fuser_out =~ /(\d+)/g;
		}
	}

	return if !@pids;

	my %seen;
	@pids = grep { !$seen{$_}++ && $_ > 0 } @pids;

	diag("killing stale PIDs on port $port: @pids");

	for my $pid (@pids) {
		kill('TERM', $pid);
	}

	select undef, undef, undef, 0.3;

	for my $pid (@pids) {
		kill('KILL', $pid) if kill(0, $pid);
	}
}


sub wait_for_quic_ready {
	my ($port) = @_;
	my $port_num = $port;
	$port_num =~ s/.*://;  # strip "127.0.0.1:" prefix if present

	for my $attempt (1 .. 50) {
		my $out = `ss -Hulnp sport = :$port_num 2>/dev/null`;
		return 1 if defined $out && $out =~ /angie/;
		select undef, undef, undef, 0.1;
	}

	diag("WARNING: QUIC port $port_num not ready after 5s");
	return 0;
}


sub cleanup_stale_processes {
	my (%opts) = @_;

	# Kill all test-related processes left from prior runs:
	# forwarder, h3_client, control_h3_server, and angie master/worker.
	# When $opts{skip_angie} is true, angie is excluded (used inside
	# run_case / run_case_silent where angie must stay alive).
	my @patterns = (
		$forwarder,
		H3_CLIENT,
		CONTROL_H3_SERVER,
	);

	if (!$opts{skip_angie}) {
		push @patterns, (
			'objs/angie.*-p.*angie-test-',
			'objs/angie.*-p.*/tmp/',
			'angie: master process',
			'angie: worker process',
		);
	}

	my %seen;
	my @stale;
	for my $pat (@patterns) {
		my $esc = quotemeta($pat);
		my $pids = `pgrep -f '$esc' 2>/dev/null`;
		next if !defined $pids || $pids eq '';
		for my $pid (split /\s+/, $pids) {
			next unless $pid =~ /^\d+$/ && $pid > 0;
			next if $seen{$pid}++;
			push @stale, $pid;
		}
	}

	return if !@stale;

	diag("cleanup: killing stale test PIDs: @stale");

	for my $pid (@stale) {
		kill('TERM', $pid);
	}

	select undef, undef, undef, 1;

	for my $pid (@stale) {
		kill('KILL', $pid) if kill(0, $pid);
	}

	# Wait for all killed processes to fully exit and release ports
	for my $attempt (1 .. 10) {
		my $alive = 0;
		for my $pid (@stale) {
			$alive++ if kill(0, $pid);
		}
		last if $alive == 0;
		select undef, undef, undef, 0.5;
	}

	# Extra wait for OS to release TCP/UDP sockets
	select undef, undef, undef, 1;
}


sub wait_for_control_ready {
	my ($port) = @_;
	for my $attempt (1 .. 50) {
		my $out = `ss -Hulnp sport = :$port 2>/dev/null`;
		return 1 if defined $out && $out ne '';
		select undef, undef, undef, 0.1;
	}
	diag("WARNING: control server port $port not ready after 5s");
	return 0;
}

sub stop_control_server {
	my ($pid, $port) = @_;
	return if !defined $pid;
	if (defined $t->{_daemons}) {
		@{$t->{_daemons}} = grep { $_ != $pid } @{$t->{_daemons}};
	}
	for (1 .. 30) {
		my $exited = waitpid($pid, WNOHANG);
		return if $exited == $pid || $exited == -1;
		select undef, undef, undef, 0.1;
	}
	kill 'TERM', $pid;
	waitpid($pid, 0);
	wait_for_port_free($port, 3);
}

sub run_control_comparison {
	my ($case, $scenario, $control_name) = @_;
	my ($fw, $control_pid, $listen_id, $label);
	my $stats_file;
	my $d = $t->testdir();
	cleanup_stale_processes();
	$listen_id = 8990 + $tuple_index++;
	my $control_port = 9500 + $control_index++;
	$label = "control $control_name $scenario->{name}";
	$stats_file = "$d/forwarder-$listen_id.stats";
	wait_for_port_free($listen_id, 3);
	wait_for_port_free($control_port, 3);
	$control_pid = $t->run_daemon(CONTROL_H3_SERVER,
		'--listen', $control_port,
		'--control', $control_name,
		'--duration-ms', 0,
		'--cert', "$d/localhost.crt",
		'--key', "$d/localhost.key");
	ok($control_pid, "$label control server started");
	wait_for_control_ready($control_port);
	$fw = $t->run_daemon($forwarder,
		'--listen', port($listen_id, udp => 1),
		'--target', $control_port,
		'--rate-bps', $scenario->{rate_bps},
		'--loss-ppm', $scenario->{loss_ppm},
		'--loss-warmup-ms', loss_warmup_ms($scenario),
		'--loss-first-keep', 5,
		'--delay-ms', forwarder_delay_ms($scenario),
		'--jitter-ms', $scenario->{jitter_ms},
		'--outage-after-ms', $scenario->{outage_after_ms},
		'--outage-duration-ms', $scenario->{outage_duration_ms},
		'--duration-ms', 0,
		'--stats-file', $stats_file);
	ok($fw, "$label forwarder started");
	select undef, undef, undef, 0.1;
	my $start = time();
	my $summary = run_h3_client($listen_id, "/$control_name",
		"$label control perf",
		duration_ms => SCENARIO_DURATION_MS,
		discard_body => 1);
	my ($reported_bytes, $reported_requests) =
		$summary =~ /status=200 bytes=(\d+) requests=(\d+) output=/;
	my $bytes = $reported_bytes || 0;
	my $elapsed = time() - $start;
	$elapsed = 0.001 if $elapsed < 0.001;
	my $throughput = $bytes * 8 / $elapsed;
	my $fw_metrics = forwarder_metrics($stats_file, $fw, $listen_id);
	stop_control_server($control_pid, $control_port);
	my $control_metrics = {
		throughput => $throughput,
		latency_ms => forwarder_delay_ms($scenario),
		jitter => 0,
		loss_rate_ppm => $fw_metrics->{loss_rate_ppm} || 0,
	};
	$perf_results{$scenario->{name}}{"control-$control_name"}{1} = $control_metrics;
	emit_control_comparison($case, $scenario, $control_name);
}

sub emit_control_comparison {
	my ($case, $scenario, $control_name) = @_;
	my $case_name = $case->{name};
	my $scenario_name = $scenario->{name};
	my $angie_agg = aggregate_perf_results($case_name, $scenario);
	my $control_metrics = $perf_results{$scenario_name}{"control-$control_name"}{1};
	return if !defined $angie_agg || !defined $control_metrics;
	my $angie_tp = $angie_agg->{throughput};
	my $control_tp = $control_metrics->{throughput};
	my $tp_ratio = $angie_tp > 0 ? $control_tp / $angie_tp : 0;
	my $angie_loss = $angie_agg->{loss_rate_ppm};
	my $control_loss = $control_metrics->{loss_rate_ppm};
	diag(sprintf("cc_control_comparison case=\"%s\" control=\"%s\" scenario=\"%s\" "
		. "angie_throughput_bps=%.0f control_throughput_bps=%.0f "
		. "throughput_ratio=%.3f "
		. "angie_loss_rate_ppm=%u control_loss_rate_ppm=%u",
		$case_name, $control_name, $scenario_name,
		$angie_tp, $control_tp, $tp_ratio,
		$angie_loss, $control_loss));
}

sub emit_cross_algo_diag {
	my ($scenario, $algo_a, $algo_b, $metrics_a, $metrics_b) = @_;
	return if !defined $metrics_a || !defined $metrics_b;
	my $tp_a = $metrics_a->{throughput} || 0;
	my $tp_b = $metrics_b->{throughput} || 0;
	my $ratio = $tp_a > 0 ? $tp_b / $tp_a : 0;
	my $loss_a = $metrics_a->{loss_rate_ppm} || 0;
	my $loss_b = $metrics_b->{loss_rate_ppm} || 0;
	diag(sprintf("cc_cross_algo_comparison algo_a=\"%s\" algo_b=\"%s\" scenario=\"%s\" "
		. "a_throughput_bps=%.0f b_throughput_bps=%.0f "
		. "throughput_ratio_b_vs_a=%.3f "
		. "a_loss_rate_ppm=%u b_loss_rate_ppm=%u",
		$algo_a, $algo_b, $scenario->{name},
		$tp_a, $tp_b, $ratio, $loss_a, $loss_b));
}


sub cleanup_iteration_files {
	my $d = $t->testdir();

	# Truncate error.log to prevent /tmp from filling up during long runs.
	# Safe because angie is already stopped before this is called.
	my $elog = "$d/error.log";
	if (-f $elog && -s $elog > 0) {
		open my $fh, '>', $elog or return;
		close $fh;
	}

	# Remove per-tuple client and forwarder files
	for my $f (glob("$d/client-*.out $d/client-*.log $d/forwarder-*.stats")) {
		unlink $f if -f $f;
	}
}

###############################################################################
