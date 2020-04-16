#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
#***************************************************************************

BEGIN {
    push(@INC, $ENV{'srcdir'}) if(defined $ENV{'srcdir'});
    push(@INC, ".");
}

use strict;
use warnings;

use serverhelp qw(
    server_pidfilename
    server_logfilename
    );

use sshhelp qw(
    exe_ext
    );

my $verbose = 0;     # set to 1 for debugging
my $port = 8990;     # just a default
my $unix_socket;     # location to place a listening Unix socket
my $ipvnum = 4;      # default IP version of http server
my $idnum = 1;       # default http server instance number
my $proto = 'http';  # protocol the http server speaks
my $pidfile;         # pid file
my $portfile;        # port number file
my $logfile;         # log file
my $connect;         # IP to connect to on CONNECT
my $srcdir;
my $gopher = 0;

my $flags  = "";
my $path   = '.';
my $logdir = $path .'/log';

while(@ARGV) {
    if($ARGV[0] eq '--pidfile') {
        if($ARGV[1]) {
            $pidfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--portfile') {
        if($ARGV[1]) {
            $portfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logfile') {
        if($ARGV[1]) {
            $logfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--srcdir') {
        if($ARGV[1]) {
            $srcdir = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--ipv4') {
        $ipvnum = 4;
    }
    elsif($ARGV[0] eq '--ipv6') {
        $ipvnum = 6;
    }
    elsif($ARGV[0] eq '--unix-socket') {
        $ipvnum = 'unix';
        if($ARGV[1]) {
            $unix_socket = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--gopher') {
        $gopher = 1;
    }
    elsif($ARGV[0] eq '--port') {
        if($ARGV[1] =~ /^(\d+)$/) {
            $port = $1;
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--connect') {
        if($ARGV[1]) {
            $connect = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--id') {
        if($ARGV[1] =~ /^(\d+)$/) {
            $idnum = $1 if($1 > 0);
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--verbose') {
        $verbose = 1;
    }
    else {
        print STDERR "\nWarning: httpserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

if(!$srcdir) {
    $srcdir = $ENV{'srcdir'} || '.';
}
if(!$pidfile) {
    $pidfile = "$path/". server_pidfilename($proto, $ipvnum, $idnum);
}
if(!$portfile) {
    $portfile = "$path/". server_portfilename($proto, $ipvnum, $idnum);
}
if(!$logfile) {
    $logfile = server_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$flags .= "--pidfile \"$pidfile\" ".
    "--logfile \"$logfile\" ".
    "--portfile \"$portfile\" ";
$flags .= "--gopher " if($gopher);
$flags .= "--connect $connect " if($connect);
if($ipvnum eq 'unix') {
    $flags .= "--unix-socket '$unix_socket' ";
} else {
    $flags .= "--ipv$ipvnum --port $port ";
}
$flags .= "--srcdir \"$srcdir\"";

if($verbose) {
    print STDERR "RUN: server/sws".exe_ext('SRV')." $flags\n";
}

exec("server/sws".exe_ext('SRV')." $flags");
