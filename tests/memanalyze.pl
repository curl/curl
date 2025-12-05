#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

use strict;
use warnings;

use memanalyzer;

my $showlimit = 0;
my $verbose = 0;
my $trace = 0;

while(@ARGV) {
    if($ARGV[0] eq "-v") {
        $verbose=1;
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-t") {
        $trace=1;
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-l") {
        # only show what alloc that caused a memlimit failure
        $showlimit=1;
        shift @ARGV;
    }
    else {
        last;
    }
}

my $file = $ARGV[0] || '';

my @res = memanalyze($file, $verbose, $trace, $showlimit);

for (@res) {
    print $_;
}
