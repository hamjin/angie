#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for custom and empty Host values with HTTP/2 and HTTP/3 upstreams.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl http_v2 http_v3 proxy rewrite debug cache/)
	->has_daemon('openssl')->skip_api_check();

my @cases = (
	{ name => 'literal', value => '' },
	{ name => 'variable', value => '$arg_host' },
	{ name => 'volatile', value => '$empty_host' },
	{ name => 'http_inherit' },
	{ name => 'server_inherit', server => 1 },
	{ name => 'override', value => '', server => 2 },
	{ name => 'dynamic', value => '$arg_host', dynamic => 1 },
	{ name => 'cache', value => '$arg_host', cache => 1 },
	{ name => 'static', value => 'custom.example', host => 'custom.example' },
	{ name => 'nonempty', value => '$arg_host', args => 'host=variable.example',
	  host => 'variable.example' },
);

my $servers = '';

for my $version (2, 3) {
	my $backend = $version == 2 ? '127.0.0.1:%%PORT_8081%%'
		: '127.0.0.1:%%PORT_8980_UDP%%';
	my $scheme = $version == 2 ? 'http' : 'https';

	for my $server (0 .. 2) {
		my $listen = 8090 + $version * 3 + $server;
		$servers .= "server {\n"
			. "listen 127.0.0.1:%%PORT_${listen}%%;\n"
			. "proxy_http_version $version;\n";
		$servers .= "proxy_set_header Host \"\";\n" if $server == 1;
		$servers .= "proxy_set_header Host parent.example;\n" if $server == 2;

		for my $case (grep { ($_->{server} || 0) == $server } @cases) {
			my $target = $case->{dynamic} ? '$arg_backend' : $backend;
			$servers .= "location /$case->{name} {\n"
				. "proxy_pass $scheme://$target;\n";
			$servers .= "proxy_set_header Host \"$case->{value}\";\n"
				if exists $case->{value};
			$servers .= "proxy_cache authority;\n"
				. "proxy_cache_valid 200 1m;\n"
				. "add_header X-Cache \$upstream_cache_status always;\n"
				if $case->{cache};
			$servers .= "}\n";
		}
		$servers .= "}\n";
	}
}

$t->prepare_ssl()->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_set_header Host "";
    map \$arg_host \$empty_host { volatile; default \$arg_host; }
    proxy_cache_path %%TESTDIR%%/cache keys_zone=authority:1m;
    proxy_cache_key "\$proxy_host|\$request_uri";

    $servers

    server {
        listen 127.0.0.1:8081;
        http2 on;
        error_log %%TESTDIR%%/h2.log debug;

        location / { return 200 "backend received"; }
    }

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        error_log %%TESTDIR%%/h3.log debug;

        location / { return 200 "backend received"; }
    }
}

EOF

$t->run()->plan(5 * @cases * 2 + 4);

###############################################################################

for my $version (2, 3) {
	my $backend = '127.0.0.1:' . ($version == 2 ? port(8081)
		: port(8980, udp => 1));
	my $logfile = "h$version.log";

	for my $case (@cases) {
		my $label = "HTTP/$version $case->{name}";
		my $listen = 8090 + $version * 3 + ($case->{server} || 0);
		my $args = $case->{dynamic} ? "backend=$backend"
			: $case->{args};
		my $path = '/' . $case->{name}
			. (defined $args ? "?$args" : '');
		my $before = -f $t->testdir() . "/$logfile"
			? length($t->read_file($logfile)) : 0;
		my $response = http_get($path, host => 'client.example',
			PeerAddr => '127.0.0.1:' . port($listen));
		my $log = substr($t->read_file($logfile), $before);
		my @authority = $version == 2
			? $log =~ /http2 header: ":authority: ([^"]*)"/g
			: $log =~ /http3 authority "([^"]*)"/g;
		my @host = $log =~ /http[23] header: "host: ([^"]*)"/gi;
		# HTTP/2 logs authority after host validation strips the port.
		my $expected = $case->{host}
			|| ($version == 2 ? '127.0.0.1' : $backend);

		like($response, qr/200 OK.*backend received/s, "$label accepted");
		is(scalar @authority, 1, "$label has one authority");
		is($authority[0], $expected, "$label authority value");
		is(scalar @host, $case->{host} ? 1 : 0,
			"$label ordinary Host presence");
		is($host[0], $case->{host}, "$label ordinary Host value");

		if ($case->{cache}) {
			like($response, qr/X-Cache: MISS/i, "$label cache MISS");
			my $cached = http_get($path,
				PeerAddr => '127.0.0.1:' . port($listen));
			like($cached, qr/200 OK.*X-Cache: HIT.*backend received/s,
				"$label cache HIT");
		}
	}
}

###############################################################################
