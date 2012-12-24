#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
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

my $verbose = 0;     # set to 1 for debugging
my $port = 8997;     # just a default
my $ipvnum = 4;      # default IP version of tftp server
my $idnum = 1;       # dafault tftp server instance number
my $proto = 'tftp';  # protocol the tftp server speaks
my $pidfile;         # tftp server pid file
my $logfile;         # tftp server log file
my $srcdir;
my $fork;

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
        print STDERR "\nWarning: tftpserver.pl unknown parameter: $ARGV[0]\n";
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

$flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
$flags .= "--ipv$ipvnum --port $port --srcdir \"$srcdir\"";

exec("server/tftpd $flags");
