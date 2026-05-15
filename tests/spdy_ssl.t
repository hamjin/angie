#!/usr/bin/perl

# (C) 2026 Web Server LLC

# Tests for SPDY protocol with ssl.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::SPDY qw/ spdy_client spdy_suite /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl http_spdy proxy/)
	->skip_api_check()
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        spdy on;
        spdy_chunk_size 16k;

        location / {
            return 200 "ANGIE_SPDY_OK\n";
        }

        location /headers {
            add_header X-Spdy-Result "HEADER:$http_x_spdy_test";
            return 200 "HEADER:$http_x_spdy_test\nURI:$request_uri\n";
        }

        location /echo {
            proxy_pass http://127.0.0.1:8081;
            add_header X-Spdy-Method $request_method;
            add_header X-Spdy-Body $request_body;
        }

        location /large {
            alias %%TESTDIR%%/large.txt;
        }
    }

    server {
        listen       127.0.0.1:8444 ssl spdy;
        server_name  deprecated;

        location / {
            return 200 "ANGIE_SPDY_DEPRECATED_OK\n";
        }
    }

    spdy on;

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  inherited;

        location / {
            return 200 "ANGIE_SPDY_INHERITED_OK\n";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  disabled;

        spdy off;

        location / {
            return 200 "ANGIE_SPDY_DISABLED\n";
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
	or die "Can't create certificate: $!\n";

$t->write_file('large.txt', 'ANGIE_SPDY_OK' . ("\n0123456789abcdef" x 8192));

$t->run_daemon(\&http_echo_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->try_run('no spdy')->plan(7);

###############################################################################

my $r = spdy_suite($t, version => '3', mode => 'npn');
ok($r->{ok}, 'SPDY/3 NPN request suite')
	or diag($r->{output});

$r = spdy_suite($t, version => '3.1', mode => 'npn');
ok($r->{ok}, 'SPDY/3.1 NPN request suite')
	or diag($r->{output});

$r = spdy_client($t, version => '3.1', mode => 'npn', port => 8444,
	expect => 'ANGIE_SPDY_DEPRECATED_OK');
ok($r->{ok}, 'SPDY/3.1 deprecated listen parameter')
	or diag($r->{output});

$r = spdy_client($t, version => '3.1', mode => 'npn', port => 8445,
	expect => 'ANGIE_SPDY_INHERITED_OK');
ok($r->{ok}, 'SPDY/3.1 inherited from http context')
	or diag($r->{output});

$r = spdy_client($t, version => '3.1', mode => 'npn', port => 8446,
	expect => 'ANGIE_SPDY_DISABLED');
ok(!$r->{ok}, 'SPDY/3.1 disabled in server context');

like($t->read_file('error.log'),
	qr/the "listen \.\.\. spdy" directive is deprecated, use the "spdy" directive instead/,
	'deprecated listen spdy warning');

SKIP: {
skip 'no ALPN support in OpenSSL', 1
	if $t->has_module('OpenSSL') and not $t->has_feature('openssl:1.0.2');

$r = spdy_suite($t, version => '3.1', mode => 'alpn');
ok($r->{ok}, 'SPDY/3.1 ALPN request suite')
	or diag($r->{output});

}

###############################################################################

sub http_echo_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $request = '';

		eval {
			local $SIG{ALRM} = sub { die "timeout\n" };
			alarm(5);

			while ($request !~ /\x0d?\x0a\x0d?\x0a/s) {
				my $n = sysread($client, my $buf, 4096);
				die "closed\n" unless $n;
				$request .= $buf;
			}

			alarm(0);
		};
		alarm(0);
		next if $@;

		my ($headers, $body) =
			$request =~ /(.*?\x0d?\x0a\x0d?\x0a)(.*)/s;

		my ($len) = $headers =~ /^Content-Length:\s*(\d+)/mi;
		$len ||= 0;

		while (length($body) < $len) {
			my $n = sysread($client, my $buf, $len - length($body));
			last unless $n;
			$body .= $buf;
		}

		$body = substr($body, 0, $len);

		my $response = "BODY:$body\n";
		print $client "HTTP/1.1 200 OK\x0d\x0a";
		print $client "Connection: close\x0d\x0a";
		print $client "Content-Length: " . length($response) . "\x0d\x0a";
		print $client "\x0d\x0a";
		print $client $response;
	}
}
