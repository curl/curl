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

use strict;
use warnings;

BEGIN {
    push(@INC, $ENV{'srcdir'}) if(defined $ENV{'srcdir'});
    push(@INC, ".");
}

use File::Basename;

use serverhelp qw(
    server_pidfilename
    server_logfilename
    server_exe
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
my $cmdfile;         # command file
my $connect;         # IP to connect to on CONNECT
my $keepalive_secs;  # number of seconds to keep idle connections
my $srcdir;
my $gopher = 0;

my $flags  = "";
my $path   = '.';
my $logdir = $path .'/log';
my $piddir;

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
    elsif($ARGV[0] eq '--config') {
        if($ARGV[1]) {
            $cmdfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logfile') {
        if($ARGV[1]) {
            $logfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logdir') {
        if($ARGV[1]) {
            $logdir = $ARGV[1];
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
    elsif($ARGV[0] eq '--keepalive') {
        if($ARGV[1]) {
            $keepalive_secs = $ARGV[1];
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
        print STDERR "\nWarning: http-server.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

#***************************************************************************
# Initialize command line option dependent variables
#

if($pidfile) {
    # Use our pidfile directory to store the other pidfiles
    $piddir = dirname($pidfile);
}
else {
    # Use the current directory to store all the pidfiles
    $piddir = $path;
    $pidfile = server_pidfilename($piddir, $proto, $ipvnum, $idnum);
}
if(!$portfile) {
    $portfile = server_portfilename($piddir, $proto, $ipvnum, $idnum);
}
if(!$srcdir) {
    $srcdir = $ENV{'srcdir'} || '.';
}
if(!$logfile) {
    $logfile = server_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$flags .= "--pidfile \"$pidfile\" ".
    "--cmdfile \"$cmdfile\" ".
    "--logfile \"$logfile\" ".
    "--logdir \"$logdir\" ".
    "--portfile \"$portfile\" ";
$flags .= "--gopher " if($gopher);
$flags .= "--connect $connect " if($connect);
$flags .= "--keepalive $keepalive_secs " if($keepalive_secs);
if($ipvnum eq 'unix') {
    $flags .= "--unix-socket '$unix_socket' ";
} else {
    $flags .= "--ipv$ipvnum --port $port ";
}
$flags .= "--srcdir \"$srcdir\"";

if($verbose) {
    print STDERR "RUN: ".server_exe('sws')." $flags\n";
}

$| = 1;
exec("exec ".server_exe('sws')." $flags");
