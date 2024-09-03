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

# Usage:
#   perl mk-bundle.pl > bundle.c

use strict;
use warnings;

my $src_dir = ".";
if(@ARGV) {
    $src_dir = $ARGV[0];
}

print "#define CURLTESTS_BUNDLED\n";

print '#include "testutil.c"' . "\n";
print '#include "testtrace.c"' . "\n";
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
        foreach my $symb ("test",
                "my_rlimit", "read_callback", "write_callback", "header_callback",
                "trailers_callback", "transfer_status", "my_lock", "writecb", "write_cb",
                "readcallback", "ioctlcallback", "progress_callback", "showem", "my_unlock",
                "store_errmsg", "close_file_descriptors", "fopen_works", "rlim2str",
                "ReadThis", "WriteThis", "Sockets", "ReadWriteSockets",
                "Tdata", "curlSocketCallback", "curlTimerCallback", "checkForCompletion",
                "getMicroSecondTimeout", "removeFd", "addFd", "updateFdSet", "checkFdSet",
                "curl", "buffer", "userdata", "buf", "suburl", "post", "params",
                "testname", "testdata", "testfd", "teststring", "testeh",
                "xferinfo", "cyclic_add", "geterr", "once", "fire") {
            print "#undef $symb\n";
            print "#define $symb ${symb}_$nam\n";
        }
        print "#define $namu\n";
        print "#include \"$src\"\n";
        print "#undef $namu\n";
        # Reset macros used by multiple tests
        foreach my $undef (
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
#print "  { NULL, NULL }\n";
print "};\n\n";

print '#include "first.c"' . "\n";
