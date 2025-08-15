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

my $ok = 1;
my $exp_duration = $ARGV[1] + 0.0;

# Read the output of curl --version
open(F, $ARGV[0]) || die "Can't open test result from $ARGV[0]\n";
$_ = <F>;
chomp;
/\s*([\.\d]+)\s*/;
my $duration = $1 + 0.0;
close F;

if ($duration <= $exp_duration) {
    print "OK: duration of $duration in expected range\n";
    $ok = 0;
}
else {
    print "FAILED: duration of $duration is larger than $exp_duration\n";
}
exit $ok;
