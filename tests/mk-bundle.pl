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

if(!@ARGV) {
    die "Usage: $0 [--first] [--input] [<inputs>] [--util <util-c-sources>] [--exclude <exclude-c-sources>]\n";
}

# Specific sources to exclude or add as an extra source file
my @src;
my %exclude;
my %util;
my $in_exclude = 0;
my $in_util = 0;
my $first = 0;  # enclose generated code between first.h and first.c
foreach my $src (@ARGV) {
    if($src eq "--input") {
        $in_exclude = 0;
        $in_util = 0;
    }
    elsif($src eq "--exclude") {
        $in_exclude = 1;
        $in_util = 0;
    }
    elsif($src eq "--util") {
        $in_exclude = 0;
        $in_util = 1;
    }
    elsif($src eq "--first") {
        $first = 1;
    }
    elsif($in_exclude) {
        $exclude{$src} = 1;
    }
    elsif($in_util) {
        $util{$src} = 1;
        push @src, $src;
    }
    else {
        push @src, $src;
    }
}

print "/* !checksrc! disable COPYRIGHT all */\n\n";
if($first) {
    print "#include \"first.h\"\n\n";
}

my $tlist = "";

foreach my $src (@src) {
    if($src =~ /([a-z0-9]+)\.c$/ && !exists $exclude{$src}) {
        my $name = $1;
        if(exists $util{$src}) {
            print "#include \"$src\"\n\n";  # Misc .c source to include
        }
        else {
            # Make entry functions unique across sources
            print "#undef test\n";
            print "#define test test_$name\n";
            print "#include \"$src\"\n";
            print "\n";
            $tlist .= "  {\"$name\", test_$name},\n";
        }
    }
}

if($tlist ne "") {
    print "static const struct entry_s s_entries[] = {\n$tlist};\n";
}

if($first) {
    print "\n#include \"first.c\"\n";
}
