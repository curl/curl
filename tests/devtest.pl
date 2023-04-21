#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Fandrich, et al.
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
###########################################################################

# This script is intended for developers to test some internals of the
# runtests.pl harneess. Don't try to use this unless you know what you're
# doing!

# An example command-line that starts a test http server for test 11 and waits
# for the user before stopping it:
#   ./devtest.pl --verbose serverfortest https echo "Started https" protoport https preprocess 11 pause echo Stopping stopservers echo Done
# curl can connect to the server while it's running like this:
#   curl -vkL https://localhost:<protoport>/11

use strict;
use warnings;
use 5.006;

BEGIN {
    # Define srcdir to the location of the tests source directory. This is
    # usually set by the Makefile, but for out-of-tree builds with direct
    # invocation of runtests.pl, it may not be set.
    if(!defined $ENV{'srcdir'}) {
        use File::Basename;
        $ENV{'srcdir'} = dirname(__FILE__);
    }
    push(@INC, $ENV{'srcdir'});
}

use globalconfig;
use servers qw(
    initserverconfig
    protoport
    serverfortest
    stopservers
);
use runner qw(
    readtestkeywords
    singletest_preprocess
);
use testutil qw(
    setlogfunc
);
use getpart;


#######################################################################
# logmsg is our general message logging subroutine.
# This function is currently required to be here by servers.pm
# This is copied from runtests.pl
#
my $uname_release = `uname -r`;
my $is_wsl = $uname_release =~ /Microsoft$/;
sub logmsg {
    for(@_) {
        my $line = $_;
        if ($is_wsl) {
            # use \r\n for WSL shell
            $line =~ s/\r?\n$/\r\n/g;
        }
        print "$line";
    }
}

#######################################################################
# Parse and store the protocols in curl's Protocols: line
# This is copied from runtests.pl
#
sub parseprotocols {
    my ($line)=@_;

    @protocols = split(' ', lc($line));

    # Generate a "proto-ipv6" version of each protocol to match the
    # IPv6 <server> name and a "proto-unix" to match the variant which
    # uses Unix domain sockets. This works even if support isn't
    # compiled in because the <features> test will fail.
    push @protocols, map(("$_-ipv6", "$_-unix"), @protocols);

    # 'http-proxy' is used in test cases to do CONNECT through
    push @protocols, 'http-proxy';

    # 'none' is used in test cases to mean no server
    push @protocols, 'none';
}


#######################################################################
# Initialize @protocols from the curl binary under test
#
sub init_protocols {
    for (`$CURL -V 2>/dev/null`) {
        if(m/^Protocols: (.*)$/) {
            parseprotocols($1);
        }
    }
}


#######################################################################
# Initialize the test harness to run tests
#
sub init_tests {
    setlogfunc(\&logmsg);
    init_protocols();
    initserverconfig();
}

#######################################################################
# Main test loop

init_tests();

#***************************************************************************
# Parse command-line options and commands
#
while(@ARGV) {
    if($ARGV[0] eq "-h") {
        print "Usage: devtest.pl [--verbose] [command [arg]...]\n";
        print "command is one of:\n";
        print "  echo X\n";
        print "  pause\n";
        print "  preprocess\n";
        print "  protocols *|X[,Y...]\n";
        print "  protoport X\n";
        print "  serverfortest X[,Y...]\n";
        print "  stopservers\n";
        print "  sleep N\n";
        exit 0;
    }
    elsif($ARGV[0] eq "--verbose") {
        $verbose = 1;
    }
    elsif($ARGV[0] eq "sleep") {
        shift @ARGV;
        sleep $ARGV[0];
    }
    elsif($ARGV[0] eq "echo") {
        shift @ARGV;
        print $ARGV[0] . "\n";
    }
    elsif($ARGV[0] eq "pause") {
        print "Press Enter to continue: ";
        readline STDIN;
    }
    elsif($ARGV[0] eq "protocols") {
        shift @ARGV;
        if($ARGV[0] eq "*") {
            init_protocols();
        }
        else {
            @protocols = split(",", $ARGV[0]);
        }
        print "Set " . scalar @protocols . " protocols\n";
    }
    elsif($ARGV[0] eq "preprocess") {
        shift @ARGV;
        loadtest("${TESTDIR}/test${ARGV[0]}");
        readtestkeywords();
        singletest_preprocess($ARGV[0]);
    }
    elsif($ARGV[0] eq "protoport") {
        shift @ARGV;
        my $port = protoport($ARGV[0]);
        print "protoport: $port\n";
    }
    elsif($ARGV[0] eq "serverfortest") {
        shift @ARGV;
        my ($why, $e) = serverfortest(split(/,/, $ARGV[0]));
        print "serverfortest: $e $why\n";
    }
    elsif($ARGV[0] eq "stopservers") {
        my $err = stopservers();
        print "stopservers: $err\n";
    }
    else {
        print "Error: Unknown command: $ARGV[0]\n";
        print "Continuing anyway\n";
    }
    shift @ARGV;
}
