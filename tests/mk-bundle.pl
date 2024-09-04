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

use strict;
use warnings;

if(@ARGV < 1) {
    die "Usage: $0 [<directory>]\n";
}

my $src_dir = $ARGV[0] // ".";

print "#define CURLTESTS_BUNDLED\n";
print "#define CURLTESTS_BUNDLED_TEST_H\n";
# Some tests need it. Must be set before the first "curl/curl.h" include.
print "#define CURL_DISABLE_DEPRECATION\n";
print '#include "first.h"' . "\n\n";

my $tlist = "";

# Read list of tests
open my $fh, "<", "$src_dir/Makefile.inc" or die "Could not open '$src_dir/Makefile.inc': $!";

while(my $line = <$fh>) {
    chomp $line;
    if($line =~ /([a-z0-9]+)_SOURCES\ =\ ([a-z0-9]+)\.c/) {
        my $nam = $1;
        my $namu = uc($nam);
        my $src = "$2.c";

        # Make common symbols unique
        # TODO: Some of these might be subject for de-duplication or sync,
        #       to shorten the list?
        foreach my $symb (
                "test",
                "ReadThis",
                "ReadWriteSockets",
                "Sockets",
                "Tdata",
                "WriteThis",
                "addFd",
                "buf",
                "buffer",
                "checkFdSet",
                "checkForCompletion",
                "close_file_descriptors",
                "curl",
                "curlSocketCallback",
                "curlTimerCallback",
                "cyclic_add",
                "fire",
                "fopen_works",
                "getMicroSecondTimeout",
                "geterr",
                "header_callback",
                "ioctlcallback",
                "msgbuff",
                "my_lock",
                "my_rlimit",
                "my_unlock",
                "num_open",
                "params",
                "post",
                "progress_callback",
                "read_callback",
                "readcallback",
                "removeFd",
                "rlim2str",
                "run_thread",
                "showem",
                "store_errmsg",
                "suburl",
                "test_failure",
                "test_once",
                "testbuf",
                "testdata",
                "testeh",
                "testfd",
                "testname",
                "teststring",
                "trailers_callback",
                "transfer_status",
                "updateFdSet",
                "userdata",
                "websocket",
                "websocket_close",
                "write_callback",
                "write_cb",
                "writecb",
                "xferinfo",
                # unit
                "easy",
                "hash_static",
                "mydtor",
                "password",
                "test_parse",
                "testcase",
                "tests",
                "unit_setup",
                "unit_stop",
                 ) {
            print "#undef $symb\n";
            print "#define $symb ${symb}_$nam\n";
        }
        print "#define $namu\n";
        print "#include \"$src\"\n";
        print "#undef $namu\n";
        # Reset macros used by multiple tests
        foreach my $undef (
                "test",
                "HEADER_REQUEST",
                "NUM_HANDLES",
                "SAFETY_MARGIN",
                "TEST_HANG_TIMEOUT"
                ) {
            print "#undef $undef\n";
        }
        print "\n";

        $tlist .= "  { \"$nam\", test_$nam },\n";
    }
}

close $fh;

# Name, pointer table
print "static const struct onetest s_tests[] = {\n";
print "$tlist";
print "};\n\n";

print "#undef CURLTESTS_BUNDLED_TEST_H\n\n";

print '#include "first.c"' . "\n";
