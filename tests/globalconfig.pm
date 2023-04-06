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
        $CURL
        $FTPDCMD
        $LOGDIR
        $perl
        $PIDDIR
        $proxy_address
        $srcdir
        $torture
        $VCURL
        $verbose
        @protocols
    );
}
use pathhelp qw(exe_ext);


#######################################################################
# global configuration variables
#

# config variables overridden by command-line options
our $verbose;       # 1 to show verbose test output
our $torture;       # 1 to enable torture testing
our $proxy_address;  # external HTTP proxy address

# paths
our $srcdir = $ENV{'srcdir'} || '.';  # root of the test source code
our $perl="perl -I$srcdir"; # invoke perl like this
our $LOGDIR="log";  # root of the log directory
our $PIDDIR = "$LOGDIR/server";  # root of the server directory with PID files
our $FTPDCMD="$LOGDIR/ftpserver.cmd"; # copy server instructions here
our $CURL="../src/curl".exe_ext('TOOL'); # what curl binary to run on the tests
our $VCURL=$CURL;  # what curl binary to use to verify the servers with
                   # VCURL is handy to set to the system one when the one you
                   # just built hangs or crashes and thus prevent verification

# other config variables
our @protocols;    # array of lowercase supported protocol servers

1;
