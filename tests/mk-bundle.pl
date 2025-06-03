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
    "curl",  # shadow
    "easy",  # unit
    "hash_static",  # unit
    "mydtor",  # unit
    "test_failure",  # shadow
    "test_parse",  # unit
    "testcase",  # unit
    "tests",  # unit
    "unit_setup",  # unit
    "unit_stop",  # unit
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
