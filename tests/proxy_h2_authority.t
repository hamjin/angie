#!/usr/bin/perl

# (C) Web Server LLC

# Tests for Host to :authority mapping while proxying to HTTP/2.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /host {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 2;
            proxy_set_header Host backend.example.com;
        }

        location /host_var {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 2;
            proxy_set_header Host $arg_host;
        }

        location /pass_var {
            proxy_pass http://$arg_backend;
            proxy_http_version 2;
            proxy_set_header Host $arg_host;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->try_run('no proxy_http_version 2');

###############################################################################

my $p = port(8081);

like(http_get('/host'), qr/200 OK/, 'authority from host');
like(http_get('/host_var?host=dynamic.example.com'), qr/200 OK/,
	'authority from host variable');
like(http_get("/pass_var?backend=127.0.0.1:$p&host=pass.example.com"),
	qr/200 OK/, 'authority from host variable with proxy_pass variable');

###############################################################################

sub http_daemon {
	my $client;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	while ($client = $server->accept()) {
		$client->autoflush(1);
		$client->sysread(my $buf, 24) == 24 or next; # preface

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => "") or next;

		$c->h2_settings(0);
		$c->h2_settings(1);

		my $frames = $c->read(all => [{ fin => 4 }]);
		my ($frame) =
			grep { $_->{type} =~ "HEADERS|CONTINUATION"
				&& ($_->{flags} & 4) }
			@$frames;

		my $sid = $frame->{sid};
		my $uri = $frame->{headers}{':path'};
		my $authority = $frame->{headers}{':authority'} || '';
		my $host = $frame->{headers}{'host'} || '';

		my $want = $uri eq '/host' ? 'backend.example.com'
			: $uri eq '/host_var?host=dynamic.example.com'
				? 'dynamic.example.com'
			: $uri eq '/pass_var?backend=127.0.0.1:' . port(8081)
			    . '&host=pass.example.com' ? 'pass.example.com'
			: '';

		if ($authority eq $want && $host eq $want) {
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} else {
			$c->h2_rst($sid, 1);
		}
	}
}

###############################################################################
