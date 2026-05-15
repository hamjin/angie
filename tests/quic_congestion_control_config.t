#!/usr/bin/perl

# (C) OpenAI
#
# Tests for QUIC congestion control directives.

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

my $t = Test::Nginx->new()->has(qw/http http_v3 proxy/)
	->plan(17);

my ($code, $log);
my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        quic_congestion_control cubic;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'server quic_congestion_control cubic syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    quic_congestion_control cubic;

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'http quic_congestion_control cubic syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        quic_congestion_control bbr1;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'server quic_congestion_control bbr1 syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        quic_congestion_control bbr;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'server quic_congestion_control bbr syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_quic_congestion_control cubic;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'proxy_quic_congestion_control cubic syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_quic_congestion_control bbr1;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'proxy_quic_congestion_control bbr1 syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_quic_congestion_control bbr;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'proxy_quic_congestion_control bbr syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        quic_congestion_control badalgo;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
isnt($code, 0, 'server invalid quic_congestion_control rejected');
like($log, qr/\Qinvalid value "badalgo"\E/,
	'server invalid cc value logged');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
    quic_congestion_control cubic;
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;
        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            return 200 OK;
        }
    }
}

EOF

($code, $log) = $t->test_config();
isnt($code, 0, 'events quic_congestion_control rejected');
like($log, qr/"quic_congestion_control" directive is not allowed here/,
	'events quic_congestion_control context error logged');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_quic_congestion_control wrong;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
isnt($code, 0, 'proxy invalid quic_congestion_control rejected');
like($log, qr/\Qinvalid value "wrong"\E/, 'proxy invalid cc value logged');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    proxy_quic_congestion_control cubic;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'http proxy_quic_congestion_control cubic syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        proxy_quic_congestion_control cubic;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
is($code, 0, 'server proxy_quic_congestion_control cubic syntax');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:%%PORT_8980_UDP%%;
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            proxy_ssl_certificate     localhost.crt;
            proxy_ssl_certificate_key localhost.key;
            proxy_http_version        3;
            if ($host) {
                proxy_quic_congestion_control cubic;
            }
            proxy_pass https://u;
        }
    }
}

EOF

($code, $log) = $t->test_config();
isnt($code, 0, 'location if proxy_quic_congestion_control rejected');
like($log, qr/"proxy_quic_congestion_control" directive is not allowed here/,
	'location if proxy_quic_congestion_control context error logged');

$t->write_file('error.log', '') unless -f $t->testdir() . '/error.log';

###############################################################################
