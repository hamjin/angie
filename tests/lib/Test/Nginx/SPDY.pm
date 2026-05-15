package Test::Nginx::SPDY;

# (C) 2026 Web Server LLC

# Module for Angie SPDY tests.  Protocol coverage is delegated to small
# temporary OpenSSL/zlib helpers when Perl SSL bindings are unavailable.

###############################################################################

use warnings;
use strict;

use Exporter qw/ import /;
use File::Spec qw//;
use IPC::Open3 qw/ open3 /;
use Symbol qw/ gensym /;
use Test::More qw//;

use Test::Nginx;

our @EXPORT_OK = qw/ spdy_client spdy_suite /;

###############################################################################

my %source = (
	'3' => 'spdy/spdy3_client.c',
	'3.1' => 'spdy/spdy31_client.c',
);

sub spdy_client {
	my ($t, %extra) = @_;

	my $version = $extra{version} || '3.1';
	my $src = $source{$version}
		or die "unsupported SPDY version: $version\n";

	my ($helper, $build_error) = build_helper($t, $version, $src);
	return {
		ok => 0,
		status => 255,
		output => $build_error,
		command => 'build ' . $src,
	} if defined $build_error;
	my $port = defined $extra{port} ? $extra{port} : 8443;
	my $host = $extra{host} || '127.0.0.1';
	my @cmd = ($helper, $host, port($port));
	push @cmd, defined $extra{expect} ? $extra{expect} : 'ANGIE_SPDY_OK'
		if defined $extra{mode} && $version eq '3.1';
	push @cmd, $extra{expect}
		if defined $extra{expect} && !(defined $extra{mode}
		&& $version eq '3.1');
	push @cmd, $extra{mode} if defined $extra{mode} && $version eq '3.1';

	my %env = %ENV;
	$env{SPDY_SUITE} = 1 if $extra{suite};
	$env{SPDY_METHOD} = $extra{method} if defined $extra{method};
	$env{SPDY_PATH} = $extra{path} if defined $extra{path};
	$env{SPDY_BODY} = $extra{body} if defined $extra{body};
	$env{SPDY_HEADER} = $extra{header} if defined $extra{header};
	$env{SPDY_HEADER_VALUE} = $extra{header_value}
		if defined $extra{header_value};
	$env{SPDY_EXPECT} = $extra{expect} if defined $extra{expect};
	$env{SPDY_STATUS} = $extra{status} if defined $extra{status};

	my ($status, $out) = run_helper(\%env, @cmd);
	return {
		ok => ($status == 0),
		status => $status,
		output => $out,
		command => join(' ', @cmd),
	};
}

sub spdy_suite {
	my ($t, %extra) = @_;

	$extra{suite} = 1;
	return spdy_client($t, %extra);
}

sub build_helper {
	my ($t, $version, $src) = @_;

	my $d = $t->testdir();
	my $bin = File::Spec->catfile($d, "spdy$version-client");
	$bin =~ s/3\.1/31/;

	return $bin if -x $bin;

	my $cc = $ENV{CC} || 'cc';
	my ($pkg, $pkg_error) = pkg_config(qw/openssl zlib/);
	return (undef, $pkg_error) if defined $pkg_error;

	my @cmd = (
		$cc, qw/-Wall -Wextra -Werror -O2/,
		$src, '-o', $bin, @$pkg
	);

	my ($status, $out) = run_command(undef, @cmd);
	return (undef, "cannot build SPDY helper: $out") if $status != 0;

	return ($bin, undef);
}

sub pkg_config {
	my (@libs) = @_;
	my $cmd = 'pkg-config --cflags --libs ' . join(' ', @libs);
	my $out = `$cmd 2>&1`;

	return (undef, "pkg-config failed for @libs: $out") if $? != 0;

	chomp $out;
	return ([ shellwords($out) ], undef);
}

sub run_command {
	my ($env, @cmd) = @_;

	my $err = gensym();
	my $pid = open3(undef, my $out, $err, @cmd);
	my $data = do { local $/; <$out> // '' };
	$data .= do { local $/; <$err> // '' };
	waitpid($pid, 0);

	return ($? >> 8, $data);
}

sub run_helper {
	my ($env, @cmd) = @_;

	pipe(my $reader, my $writer) or die "cannot pipe: $!\n";

	my $pid = fork();
	die "cannot fork SPDY helper: $!\n" unless defined $pid;

	if ($pid == 0) {
		close $reader;
		open STDOUT, '>&', $writer or die "cannot redirect stdout: $!\n";
		open STDERR, '>&', $writer or die "cannot redirect stderr: $!\n";
		close $writer;
		%ENV = %$env;
		exec @cmd;
		die "cannot exec $cmd[0]: $!\n";
	}

	close $writer;

	local $SIG{ALRM} = sub { die "SPDY helper timed out\n" };
	alarm(20);

	my $data = do { local $/; <$reader> // '' };
	close $reader;
	waitpid($pid, 0);
	alarm(0);

	return ($? >> 8, $data);
}

sub shellwords {
	my ($s) = @_;
	my @words;

	while ($s =~ /\G\s*(?:
		'([^']*)'
		|"((?:\\"|[^"])*)"
		|(\S+)
	)/xg) {
		my $w = defined $1 ? $1 : defined $2 ? $2 : $3;
		$w =~ s/\\"/"/g;
		push @words, $w;
	}

	return @words;
}

###############################################################################

1;
