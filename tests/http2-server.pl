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

# This script invokes nghttpx properly to have it serve HTTP/2 for us.
# nghttpx runs as a proxy in front of our "actual" HTTP/1 server.
use Cwd;
use Cwd 'abs_path';

my $pidfile = "log/nghttpx.pid";
my $logfile = "log/http2.log";
my $nghttpx = "nghttpx";
my $listenport = 9015;
my $listenport2 = 9016;
my $connect = "127.0.0.1,8990";
my $conf = "nghttpx.conf";
my $cert = "Server-localhost-sv";

#***************************************************************************
# Process command line options
#
while(@ARGV) {
    if($ARGV[0] eq '--verbose') {
        $verbose = 1;
    }
    elsif($ARGV[0] eq '--pidfile') {
        if($ARGV[1]) {
            $pidfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--nghttpx') {
        if($ARGV[1]) {
            $nghttpx = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--port') {
        if($ARGV[1]) {
            $listenport = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--port2') {
        if($ARGV[1]) {
            $listenport2 = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--connect') {
        if($ARGV[1]) {
            $connect = $ARGV[1];
            $connect =~ s/:/,/;
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logfile') {
        if($ARGV[1]) {
            $logfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--conf') {
        if($ARGV[1]) {
            $conf = $ARGV[1];
            shift @ARGV;
        }
    }
    else {
        print STDERR "\nWarning: http2-server.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

my $path   = getcwd();
my $srcdir = $path;
$certfile = "$srcdir/certs/$cert.pem";
$keyfile = "$srcdir/certs/$cert.key";
$certfile = abs_path($certfile);
$keyfile = abs_path($keyfile);

my $cmdline="$nghttpx --backend=$connect ".
    "--frontend=\"*,$listenport;no-tls\" ".
    "--frontend=\"*,$listenport2\" ".
    "--log-level=INFO ".
    "--pid-file=$pidfile ".
    "--conf=$conf ".
    "--errorlog-file=$logfile ".
    "$keyfile $certfile";
print "RUN: $cmdline\n" if($verbose);
system("$cmdline 2>/dev/null");
