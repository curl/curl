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

# Helper script for "unity"-like support in autotools, to generate the umbrella
# C source that includes the individual source files. Reads Makefile.inc and
# accepts the variable name containing all the source files to include. Also
# allow a list of exceptions that are to be excluded from the generated file.

use strict;
use warnings;

if(!@ARGV) {
    die "Usage: $0 [<c-sources>] [--exclude <exclude-c-sources>]\n";
}

my $srcdir = shift @ARGV;

# Specific sources to exclude or add as an extra source file
my @src;
my %exclude;
my $in_exclude = 0;
foreach my $src (@ARGV) {
    if($in_exclude) {
        $exclude{$src} = 1;
    }
    elsif($src eq "--exclude") {
        $in_exclude = 1;
    }
    else {
        push @src, $src;
    }
}

print <<HEADER
/* !checksrc! disable COPYRIGHT all */
HEADER
    ;

foreach my $src (@src) {
    if($src =~ /\.c$/g && !exists $exclude{$src}) {
        if(-e "$srcdir/$src") {
            print "#include \"$srcdir/$src\"\n";
        }
        else {
            print "#include \"$src\"\n";
        }
    }
}
