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
###########################################################################

# This module contains global variables used in multiple modules in the test
# harness but not really "owned" by any one.

package globalconfig;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        $anyway
        $automakestyle
        $CURL
        $CURLVERSION
        $FTPDCMD
        $has_shared
        $LIBDIR
        $listonly
        $LOGDIR
        $memanalyze
        $memdump
        $perl
        $PIDDIR
        $proxy_address
        $PROXYIN
        $pwd
        $run_event_based
        $SERVER2IN
        $SERVERIN
        $srcdir
        $TESTDIR
        $torture
        $valgrind
        $VCURL
        $verbose
        %feature
        %keywords
        @protocols
        %timesrvrend
        %timesrvrini
        %timesrvrlog
        %timetoolend
        %timetoolini
        %timevrfyend
    );
}
use pathhelp qw(exe_ext);
use Cwd qw(getcwd);


#######################################################################
# global configuration variables
#

# config variables overridden by command-line options
our $verbose;         # 1 to show verbose test output
our $torture;         # 1 to enable torture testing
our $proxy_address;   # external HTTP proxy address
our $listonly;        # only list the tests
our $run_event_based; # run curl with --test-event to test the event API
our $automakestyle;   # use automake-like test status output format
our $anyway;          # continue anyway, even if a test fail
our $CURLVERSION="";  # curl's reported version number

# paths
our $pwd = getcwd();  # current working directory
our $srcdir = $ENV{'srcdir'} || '.';  # root of the test source code
our $perl="perl -I$srcdir"; # invoke perl like this
our $LOGDIR="log";  # root of the log directory
# TODO: $LOGDIR could eventually change later on, so must regenerate all the
# paths depending on it after $LOGDIR itself changes.
our $PIDDIR = "$LOGDIR/server";  # root of the server directory with PID files
# TODO: change this to use server_inputfilename()
our $SERVERIN="$LOGDIR/server.input";    # what curl sent the server
our $SERVER2IN="$LOGDIR/server2.input";  # what curl sent the second server
our $PROXYIN="$LOGDIR/proxy.input";      # what curl sent the proxy
our $memdump="$LOGDIR/memdump";  # file that the memory debugging creates
our $FTPDCMD="$LOGDIR/ftpserver.cmd";    # copy server instructions here
our $LIBDIR="./libtest";
our $TESTDIR="$srcdir/data";
our $CURL="../src/curl".exe_ext('TOOL'); # what curl binary to run on the tests
our $VCURL=$CURL;  # what curl binary to use to verify the servers with
                   # VCURL is handy to set to the system one when the one you
                   # just built hangs or crashes and thus prevent verification
# the path to the script that analyzes the memory debug output file
our $memanalyze="$perl $srcdir/memanalyze.pl";
our $valgrind;     # path to valgrind, or empty if disabled

# other config variables
our @protocols;   # array of lowercase supported protocol servers
our %feature;     # hash of enabled features
our $has_shared;  # built as a shared library
our %keywords;    # hash of keywords from the test spec
our %timesrvrini; # timestamp for each test required servers verification start
our %timesrvrend; # timestamp for each test required servers verification end
our %timetoolini; # timestamp for each test command run starting
our %timetoolend; # timestamp for each test command run stopping
our %timesrvrlog; # timestamp for each test server logs lock removal
our %timevrfyend; # timestamp for each test result verification end

1;
