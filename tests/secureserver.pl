#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

# This is the HTTPS, FTPS, POP3S, IMAPS, SMTPS, server used for curl test
# harness. Actually just a layer that runs stunnel properly using the
# non-secure test harness servers.

use strict;
use warnings;

BEGIN {
    push(@INC, $ENV{'srcdir'}) if(defined $ENV{'srcdir'});
    push(@INC, ".");
}

use Cwd;
use Cwd 'abs_path';
use File::Basename;

use serverhelp qw(
    server_pidfilename
    server_logfilename
    );

use pathhelp;

my $stunnel = "stunnel";

my $verbose=0; # set to 1 for debugging

my $accept_port = 8991; # just our default, weird enough
my $target_port = 8999; # default test http-server port

my $stuncert;

my $ver_major;
my $ver_minor;
my $fips_support;
my $stunnel_version;
my $tstunnel_windows;
my $socketopt;
my $cmd;

my $pidfile;          # stunnel pid file
my $logfile;          # stunnel log file
my $loglevel = 5;     # stunnel log level
my $ipvnum = 4;       # default IP version of stunneled server
my $idnum = 1;        # default stunneled server instance number
my $proto = 'https';  # default secure server protocol
my $conffile;         # stunnel configuration file
my $cafile;           # certificate CA PEM file
my $certfile;         # certificate chain PEM file
my $mtls = 0;         # Whether to verify client certificates

#***************************************************************************
# stunnel requires full path specification for several files.
#
my $path   = getcwd();
my $srcdir = $path;
my $logdir = $path .'/log';
my $piddir;

#***************************************************************************
# Signal handler to remove our stunnel 4.00 and newer configuration file.
#
sub exit_signal_handler {
    my $signame = shift;
    local $!; # preserve errno
    local $?; # preserve exit status
    unlink($conffile) if($conffile && (-f $conffile));
    exit;
}

#***************************************************************************
# Process command line options
#
while(@ARGV) {
    if($ARGV[0] eq '--verbose') {
        $verbose = 1;
    }
    elsif($ARGV[0] eq '--proto') {
        if($ARGV[1]) {
            $proto = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--accept') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $accept_port = $1;
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--connect') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $target_port = $1;
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--stunnel') {
        if($ARGV[1]) {
            $stunnel = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--srcdir') {
        if($ARGV[1]) {
            $srcdir = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--certfile') {
        if($ARGV[1]) {
            $stuncert = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--id') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $idnum = $1 if($1 > 0);
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--ipv4') {
        $ipvnum = 4;
    }
    elsif($ARGV[0] eq '--ipv6') {
        $ipvnum = 6;
    }
    elsif($ARGV[0] eq '--pidfile') {
        if($ARGV[1]) {
            $pidfile = "$path/". $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logfile') {
        if($ARGV[1]) {
            $logfile = "$path/". $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logdir') {
        if($ARGV[1]) {
            $logdir = "$path/". $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--mtls') {
        $mtls = 1;
    }
    else {
        print STDERR "\nWarning: secureserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

#***************************************************************************
# Initialize command line option dependent variables
#
if($pidfile) {
    # Use our pidfile directory to store the conf files
    $piddir = dirname($pidfile);
}
else {
    # Use the current directory to store the conf files
    $piddir = $path;
    $pidfile = server_pidfilename($piddir, $proto, $ipvnum, $idnum);
}
if(!$logfile) {
    $logfile = server_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$conffile = "$piddir/${proto}_stunnel.conf";

$cafile = abs_path("$path/certs/test-ca.cacert");
$certfile = $stuncert ? "certs/$stuncert" : "certs/test-localhost.pem";
$certfile = abs_path($certfile);

my $ssltext = uc($proto) ." SSL/TLS:";

my $host_ip = ($ipvnum == 6)? '::1' : '127.0.0.1';

#***************************************************************************
# Find out version info for the given stunnel binary
#
foreach my $veropt (('-version', '-V')) {
    foreach my $verstr (qx("$stunnel" $veropt 2>&1)) {
        if($verstr =~ /^stunnel (\d+)\.(\d+) on /) {
            $ver_major = $1;
            $ver_minor = $2;
        }
        elsif($verstr =~ /^sslVersion.*fips *= *yes/) {
            # the fips option causes an error if stunnel doesn't support it
            $fips_support = 1;
            last
        }
    }
    last if($ver_major);
}
if((!$ver_major) || !defined($ver_minor)) {
    if(-x "$stunnel" && ! -d "$stunnel") {
        print "$ssltext Unknown stunnel version\n";
    }
    else {
        print "$ssltext No stunnel\n";
    }
    exit 1;
}
$stunnel_version = (100*$ver_major) + $ver_minor;

#***************************************************************************
# Verify minimum stunnel required version
#
if($stunnel_version < 310) {
    print "$ssltext Unsupported stunnel version $ver_major.$ver_minor\n";
    exit 1;
}

#***************************************************************************
# Find out if we are running on Windows using the tstunnel binary
#
if($stunnel =~ /tstunnel(\.exe)?$/) {
    $tstunnel_windows = 1;

    # convert Cygwin/MinGW paths to Windows format
    $cafile = pathhelp::sys_native_abs_path($cafile);
    $certfile = pathhelp::sys_native_abs_path($certfile);
}

#***************************************************************************
# Build command to execute for stunnel 3.X versions
#
if($stunnel_version < 400) {
    if($stunnel_version >= 319) {
        $socketopt = "-O a:SO_REUSEADDR=1";
    }
    # TODO: we do not use $host_ip in this old version. I simply find
    # no documentation how to. But maybe ipv6 is not available anyway?
    $cmd  = "\"$stunnel\" -p $certfile -P $pidfile ";
    $cmd .= "-d $accept_port -r $target_port -f -D $loglevel ";
    $cmd .= ($socketopt) ? "$socketopt " : "";
    $cmd .= ">$logfile 2>&1";
    if($verbose) {
        print uc($proto) ." server (stunnel $ver_major.$ver_minor)\n";
        print "cmd: $cmd\n";
        print "pem cert file: $certfile\n";
        print "pid file: $pidfile\n";
        print "log file: $logfile\n";
        print "log level: $loglevel\n";
        print "listen on port: $accept_port\n";
        print "connect to port: $target_port\n";
    }
}

#***************************************************************************
# Build command to execute for stunnel 4.00 and newer
#
if($stunnel_version >= 400) {
    $socketopt = "a:SO_REUSEADDR=1";
    if(($stunnel_version >= 534) && $tstunnel_windows) {
        # SO_EXCLUSIVEADDRUSE is on by default on Vista or newer,
        # but does not work together with SO_REUSEADDR being on.
        $socketopt .= "\nsocket = a:SO_EXCLUSIVEADDRUSE=0";
    }
    $cmd  = "\"$stunnel\" $conffile ";
    $cmd .= ">$logfile 2>&1";
    # setup signal handler
    $SIG{INT} = \&exit_signal_handler;
    $SIG{TERM} = \&exit_signal_handler;
    # stunnel configuration file
    if(open(my $stunconf, ">", "$conffile")) {
        print $stunconf "cert = $certfile\n";
        print $stunconf "debug = $loglevel\n";
        print $stunconf "socket = $socketopt\n";
        if($mtls) {
            print $stunconf "CAfile = $cafile\n";
            print $stunconf "verifyChain = yes\n";
        }
        if($fips_support) {
            # disable fips in case OpenSSL doesn't support it
            print $stunconf "fips = no\n";
        }
        if(!$tstunnel_windows) {
            # do not use Linux-specific options on Windows
            print $stunconf "output = $logfile\n";
            print $stunconf "pid = $pidfile\n";
            print $stunconf "foreground = yes\n";
        }
        print $stunconf "\n";
        print $stunconf "[curltest]\n";
        print $stunconf "accept = $host_ip:$accept_port\n";
        print $stunconf "connect = $host_ip:$target_port\n";
        if(!close($stunconf)) {
            print "$ssltext Error closing file $conffile\n";
            exit 1;
        }
    }
    else {
        print "$ssltext Error writing file $conffile\n";
        exit 1;
    }
    if($verbose) {
        print uc($proto) ." server (stunnel $ver_major.$ver_minor)\n";
        print "cmd: $cmd\n";
        print "stunnel config at $conffile:\n";
        open (my $writtenconf, '<', "$conffile") or die "$ssltext could not open the config file after writing\n";
        print <$writtenconf>;
        print "\n";
        close ($writtenconf);
    }
}

#***************************************************************************
# Set file permissions on certificate pem file.
#
chmod(0600, $certfile) if(-f $certfile);
print STDERR "RUN: $cmd\n" if($verbose);

#***************************************************************************
# Run tstunnel on Windows.
#
if($tstunnel_windows) {
    # Fake pidfile for tstunnel on Windows.
    if(open(my $out, ">", "$pidfile")) {
        print $out $$ . "\n";
        close($out);
    }

    # Flush output.
    $| = 1;

    # Put an "exec" in front of the command so that the child process
    # keeps this child's process ID by being tied to the spawned shell.
    exec("exec $cmd") || die "Can't exec() $cmd: $!";
    # exec() will create a new process, but ties the existence of the
    # new process to the parent waiting perl.exe and sh.exe processes.

    # exec() should never return back here to this process. We protect
    # ourselves by calling die() just in case something goes really bad.
    die "error: exec() has returned";
}

#***************************************************************************
# Run stunnel.
#
my $rc = system($cmd);

$rc >>= 8;

unlink($conffile) if($conffile && -f $conffile);

exit $rc;
