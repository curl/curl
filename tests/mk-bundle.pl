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
    die "Usage: $0 [--input] [<inputs>] [--util <util-c-sources>] [--exclude <exclude-c-sources>]\n";
}

# Specific sources to exclude or add as an extra source file
my @src;
my %exclude;
my %util;
my $in_exclude = 0;
my $in_util = 0;
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

print <<HEADER
/* !checksrc! disable COPYRIGHT all */

#include "first.h"

HEADER
    ;

my $tlist = "";

foreach my $src (@src) {
    if($src =~ /([a-z0-9]+)\.c$/) {
        my $name = $1;
        if(exists $util{$src}) {
            if(!exists $exclude{$src}) {
                print "#include \"$src\"\n\n";  # Misc .c source to include
            }
        }
        else {
            # Make common symbols unique across sources
            foreach my $symb ("test", "unit_setup", "unit_stop") {
                print "#undef $symb\n";
                print "#define $symb ${symb}_$name\n";
            }
            print "#include \"$src\"\n";
            foreach my $symb ("test", "unit_setup", "unit_stop") {
                print "#undef $symb\n";
            }
            print "\n";
            $tlist .= "  {\"$name\", test_$name},\n";
        }
    }
}

print <<FOOTER
static const struct entry_s s_entries[] = {
$tlist};

#include "first.c"
FOOTER
    ;
