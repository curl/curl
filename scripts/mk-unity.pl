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

# Helper script for "unity"-like support in autotools and to bundle up tests
# for both autotools and cmake. It generates the umbrella C source that
# includes the individual source files and tests.

use strict;
use warnings;

if(!@ARGV) {
    die "Usage: $0 [--test <tests>] [--include <include-c-sources>]\n";
}

my @src;
my %include;
my $in_include = 0;
my $any_test = 0;
foreach my $src (@ARGV) {
    if($src eq "--test") {
        $in_include = 0;
    }
    elsif($src eq "--include") {
        $in_include = 1;
    }
    elsif($in_include) {
        $include{$src} = 1;
        push @src, $src;
    }
    else {
        push @src, $src;
        $any_test = 1;
    }
}

print "/* !checksrc! disable COPYRIGHT all */\n\n";
if($any_test) {
    print "#include \"first.h\"\n\n";
}

my $tlist = "";

foreach my $src (@src) {
    if($src =~ /([a-z0-9_]+)\.c$/) {
        my $name = $1;
        print "#include \"$src\"\n";
        if(not exists $include{$src}) {  # register test entry function
            $tlist .= "  {\"$name\", test_$name},\n";
        }
    }
}

if($any_test) {
    print "\nconst struct entry_s s_entries[] = {\n$tlist  {NULL, NULL}\n};\n";
    print "\n#include \"first.c\"\n";
}
