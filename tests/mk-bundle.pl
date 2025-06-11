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

my $tlist = "";

while(my $line = <$fh>) {
    chomp $line;
    if($line =~ /([a-z0-9]+)_SOURCES\ =/) {
        my $name = $1;

        # Make common symbols unique across test sources
        foreach my $symb ("test", "unit_setup", "unit_stop") {
            print "#undef $symb\n";
            print "#define $symb ${symb}_$name\n";
        }

        print "#include \"$name.c\"\n";
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
