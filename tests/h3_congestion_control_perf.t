#!/usr/bin/perl

# (C) OpenAI
#
# Local QUIC congestion control comparison harness.

###############################################################################

use warnings;
use strict;

use Test::More;
use Time::HiRes qw(time);

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3 qw/http3_get/;

###############################################################################

plan(skip_all => 'set TEST_ANGIE_PERF=1 to run perf harness')
	unless $ENV{TEST_ANGIE_PERF};

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan(196)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;
        quic_congestion_control cubic;

        location / {
            add_header X-CC cubic;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;
        quic_congestion_control bbr1;

        location / {
            add_header X-CC bbr1;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8982_UDP%% quic;
        server_name  localhost;
        quic_congestion_control bbr;

        location / {
            add_header X-CC bbr;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

# keep body small enough for stable helper reads; accumulate by repetitions
$t->write_file('index.html', 'xPERF-THISx' x 512);
$t->run();

my @cases = (
	[8980, 'cubic'],
	[8981, 'bbr1'],
	[8982, 'bbr'],
);

my %stats;

for my $case (@cases) {
	my ($port, $name) = @$case;
	my (@elapsed, @throughput);
	my $total = 0;

	http3_get('localhost', $port, '127.0.0.1', undef);

	for (1 .. 3) {
		my $bytes = 0;
		my $start = time();

		for (1 .. 20) {
			my $body = http3_get('localhost', $port, '127.0.0.1', undef);
			ok(defined $body && length($body) > 0, "$name body received");
			$bytes += length($body // '');
		}

		my $elapsed = time() - $start;
		$elapsed = 0.001 if $elapsed < 0.001;

		push @elapsed, $elapsed;
		push @throughput, $bytes / $elapsed;
		$total += $bytes;

		ok($bytes > 0, "$name nonzero bytes");
	}

	$stats{$name}{bytes} = $total;
	$stats{$name}{elapsed} = median(@elapsed);
	$stats{$name}{throughput} = median(@throughput);
	ok($total > 0, "$name total bytes");
}

cmp_ok($stats{bbr1}{throughput}, '>=', $stats{cubic}{throughput} * 0.85,
	'bbr1 throughput not far below cubic');
cmp_ok($stats{bbr}{throughput}, '>=', $stats{cubic}{throughput} * 0.85,
	'bbr throughput not far below cubic');
cmp_ok($stats{bbr1}{elapsed}, '<=',
	$stats{cubic}{elapsed} * 1.15 + 0.01,
	'bbr1 elapsed not far above cubic');
cmp_ok($stats{bbr}{elapsed}, '<=',
	$stats{cubic}{elapsed} * 1.15 + 0.01,
	'bbr elapsed not far above cubic');

###############################################################################

sub median {
	my @v = sort { $a <=> $b } @_;
	return $v[int(@v / 2)];
}
