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
        $has_shared
        $LIBDIR
        $listonly
        $LOCKDIR
        $LOGDIR
        $memanalyze
        $MEMDUMP
        $perl
        $PIDDIR
        $proxy_address
        $PROXYIN
        $pwd
        $randseed
        $run_event_based
        $SERVERCMD
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
our $randseed = 0;    # random number seed

# paths
our $pwd = getcwd();  # current working directory
our $srcdir = $ENV{'srcdir'} || '.';  # root of the test source code
our $perl="perl -I$srcdir"; # invoke perl like this
our $LOGDIR="log";  # root of the log directory; this will be different for
                    # each runner in multiprocess mode
our $LIBDIR="./libtest";
our $TESTDIR="$srcdir/data";
our $CURL="../src/curl".exe_ext('TOOL'); # what curl binary to run on the tests
our $VCURL=$CURL;  # what curl binary to use to verify the servers with
                   # VCURL is handy to set to the system one when the one you
                   # just built hangs or crashes and thus prevent verification
# the path to the script that analyzes the memory debug output file
our $memanalyze="$perl $srcdir/memanalyze.pl";
our $valgrind;     # path to valgrind, or empty if disabled

# paths in $LOGDIR
our $LOCKDIR = "lock";          # root of the server directory with lock files
our $PIDDIR = "server";         # root of the server directory with PID files
our $SERVERIN="server.input";   # what curl sent the server
our $PROXYIN="proxy.input";     # what curl sent the proxy
our $MEMDUMP="memdump";         # file that the memory debugging creates
our $SERVERCMD="server.cmd";    # copy server instructions here

# other config variables
our @protocols;   # array of lowercase supported protocol servers
our %feature;     # hash of enabled features
our $has_shared;  # built as a shared library
our %keywords;    # hash of keywords from the test spec

1;
