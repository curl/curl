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
        $CURLVERNUM
        $DATE
        $has_shared
        $LIBDIR
        $UNITDIR
        $SRVDIR
        $listonly
        $LOCKDIR
        $LOGDIR
        $memanalyze
        $MEMDUMP
        $perlcmd
        $perl
        $PIDDIR
        $proxy_address
        $PROXYIN
        $pwd
        $randseed
        $run_duphandle
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
        $bundle
        $dev_null
    );
}
use pathhelp qw(
    exe_ext
    dirsepadd
);
use Cwd qw(getcwd);
use testutil qw(
    shell_quote
);


#######################################################################
# global configuration variables
#

# config variables overridden by command-line options
our $verbose;         # 1 to show verbose test output
our $torture;         # 1 to enable torture testing
our $proxy_address;   # external HTTP proxy address
our $listonly;        # only list the tests
our $run_duphandle;   # run curl with --test-duphandle to verify handle duplication
our $run_event_based; # run curl with --test-event to test the event API
our $automakestyle;   # use automake-like test status output format
our $anyway;          # continue anyway, even if a test fail
our $CURLVERSION="";  # curl's reported version number
our $CURLVERNUM="";   # curl's reported version number (without -DEV)
our $randseed = 0;    # random number seed

# paths
our $pwd = getcwd();  # current working directory
our $srcdir = $ENV{'srcdir'} || '.';  # root of the test source code
our $perlcmd=shell_quote($^X);
our $perl="$perlcmd -I. " . shell_quote("-I$srcdir"); # invoke perl like this
our $LOGDIR="log";  # root of the log directory; this will be different for
                    # each runner in multiprocess mode
our $LIBDIR=dirsepadd("./libtest/" . ($ENV{'CURL_DIRSUFFIX'} || ''));
our $UNITDIR=dirsepadd("./unit/" . ($ENV{'CURL_DIRSUFFIX'} || ''));
our $SRVDIR=dirsepadd("./server/" . ($ENV{'CURL_DIRSUFFIX'} || ''));
our $TESTDIR="$srcdir/data";
our $CURL=dirsepadd("../src/" . ($ENV{'CURL_DIRSUFFIX'} || '')) . "curl".exe_ext('TOOL'); # what curl binary to run on the tests
our $VCURL=$CURL;  # what curl binary to use to verify the servers with
                   # VCURL is handy to set to the system one when the one you
                   # just built hangs or crashes and thus prevent verification
# the path to the script that analyzes the memory debug output file
our $memanalyze="$perl " . shell_quote("$srcdir/memanalyze.pl");
our $valgrind;     # path to valgrind, or empty if disabled
our $bundle = 0;   # use bundled server, libtest, unit binaries
our $dev_null = ($^O eq 'MSWin32' ? 'NUL' : '/dev/null');

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
