#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
my $ipvnum = 4;      # default IP version of rtsp server
my $idnum = 1;       # default rtsp server instance number
my $proto = 'rtsp';  # protocol the rtsp server speaks
my $pidfile;         # rtsp server pid file
my $portfile;
my $logfile;         # rtsp server log file
my $srcdir;

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
    elsif($ARGV[0] eq '--port') {
        if($ARGV[1] =~ /^(\d+)$/) {
            $port = $1;
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
        print STDERR "\nWarning: rtspserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

if(!$srcdir) {
    $srcdir = $ENV{'srcdir'} || '.';
}
if(!$pidfile) {
    $pidfile = "$path/". server_pidfilename($proto, $ipvnum, $idnum);
}
if(!$logfile) {
    $logfile = server_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$flags .= "--pidfile \"$pidfile\" ".
    "--portfile \"$portfile\" ".
    "--logfile \"$logfile\" ";
$flags .= "--ipv$ipvnum --port $port --srcdir \"$srcdir\"";

$| = 1;
exec("exec server/rtspd".exe_ext('SRV')." $flags");
