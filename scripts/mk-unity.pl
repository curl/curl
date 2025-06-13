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
    die "Usage: $0 [--test <tests>] [--include <include-c-sources>] [--exclude <exclude-c-sources>] [--srcdir <srcdir>] [--embed]\n";
}

# Specific sources to exclude or add as an extra source file
my @src;
my %exclude;
my %include;
my $in_exclude = 0;
my $in_include = 0;
my $srcdir = "";
my $in_srcdir = 0;
my $any_test = 0;
my $embed = 0;
foreach my $src (@ARGV) {
    if($src eq "--test") {
        $in_exclude = 0;
        $in_include = 0;
    }
    elsif($src eq "--exclude") {
        $in_exclude = 1;
        $in_include = 0;
    }
    elsif($src eq "--include") {
        $in_exclude = 0;
        $in_include = 1;
    }
    elsif($src eq "--embed") {
        $embed = 1;
    }
    elsif($src eq "--srcdir") {
        $in_srcdir = 1;
    }
    elsif($in_srcdir) {
        $srcdir = $src;
        $in_srcdir = 0;
    }
    elsif($in_exclude) {
        $exclude{$src} = 1;
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
    if($src =~ /([a-z0-9]+)\.c$/ && !exists $exclude{$src}) {
        my $name = $1;
        my $fn = $src;
        if($srcdir ne "" && (exists $include{$src} || $embed) && -e "$srcdir/$fn") {
            $fn = $srcdir . "/" . $fn;
        }
        if($embed) {
            my $content = do { local $/; open my $fh, '<', $fn or die $!; <$fh> };
            print $content;
        }
        else {
            print "#include \"$fn\"\n";
        }
        if(not exists $include{$src}) {  # register test entry function
            $tlist .= "  {\"$name\", test_$name},\n";
        }
    }
}

if($any_test) {
    print "\nstatic const struct entry_s s_entries[] = {\n$tlist};\n";
    print "\n#include \"first.c\"\n";
}
