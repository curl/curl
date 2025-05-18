#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats
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

# Bundle up individual tests into a single binary. The resulting binary can run
# individual tests by passing their name (without '.c') as the first argument.
#
# Usage: mk-bundle.pl [<directory>]

use strict;
use warnings;

my $src_dir = @ARGV ? $ARGV[0] : ".";

# Read list of tests
open my $fh, "<", "$src_dir/Makefile.inc" or die "Cannot open '$src_dir/Makefile.inc': $!";

print <<HEADER
/* !checksrc! disable COPYRIGHT all */
/* !checksrc! disable INCLUDEDUP all */
/* !checksrc! disable UNUSEDIGNORE all */

#define CURLTESTS_BUNDLED
#define CURLTESTS_BUNDLED_TEST_H
#include "first.h"
HEADER
    ;

# TODO: Some of these might be subject for de-duplication or sync.
my @reused_symbols = (
    "ReadThis",
    "ReadWriteSockets",
    "Sockets",
    "Tdata",
    "WriteThis",
    "addFd",
    "checkFdSet",
    "checkForCompletion",
    "close_file_descriptors",
    "curl",  # shadow
    "curlSocketCallback",
    "curlTimerCallback",
    "cyclic_add",
    "easy",  # unit
    "fopen_works",
    "getMicroSecondTimeout",
    "geterr",
    "hash_static",  # unit
    "header_callback",
    "ioctlcallback",
    "msgbuff",
    "mydtor",  # unit
    "num_open",
    "progress_callback",
    "read_callback",
    "readcallback",
    "recv_pong",
    "removeFd",
    "rlim2str",
    "run_thread",
    "seek_callback",
    "send_ping",
    "showem",
    "store_errmsg",
    "suburl",
    "test_failure",  # shadow
    "test_fire",
    "test_lock",
    "test_once",
    "test_parse",  # unit
    "test_rlimit",
    "test_unlock",
    "testbuf",
    "testcase",  # unit
    "testdata",
    "testfd",
    "testname",
    "testpost",
    "tests",  # unit
    "teststring",
    "trailers_callback",
    "transfer_status",
    "unit_setup",  # unit
    "unit_stop",  # unit
    "updateFdSet",
    "userdata",
    "websocket",
    "websocket_close",
    "write_callback",
    "write_cb",
    "writecb",
    "xferinfo",
    );

# TODO: Some of these may be #undef-ed manually at the end of each source
my @reused_macros = (
    "HEADER_REQUEST",
    "NUM_HANDLES",
    "SAFETY_MARGIN",
    "TEST_HANG_TIMEOUT",
    );

my $tlist = "";

while(my $line = <$fh>) {
    chomp $line;
    if($line =~ /([a-z0-9]+)_SOURCES\ =\ ([a-z0-9]+)\.c/) {
        my $name = $1;
        my $namu = uc($name);
        my $src = "$2.c";

        # Make common symbols unique across test sources
        foreach my $symb ("test", @reused_symbols) {
            print "#undef $symb\n";
            print "#define $symb ${symb}_$name\n";
        }

        print "#define $namu\n";
        print "#include \"$src\"\n";
        print "#undef $namu\n";

        # Reset macros re-used by multiple tests
        foreach my $undef ("test", @reused_macros) {
            print "#undef $undef\n";
        }

        print "\n";

        $tlist .= "  {\"$name\", test_$name},\n";
    }
}

close $fh;

print <<FOOTER
static const struct onetest s_tests[] = {
$tlist};

#undef CURLTESTS_BUNDLED_TEST_H

#include "first.c"
FOOTER
    ;
