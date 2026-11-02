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
#
# Verify that test 1792 stopped at the connect timeout, not at the total
# timeout. The first line of the file holds the time_total and time_appconnect
# values written by curl. Subtract the control connection setup so a slow
# runner does not count it against the connect timeout.
#
use strict;
use warnings;

use constant LIMIT_SECONDS => 2.8;

my $file = shift @ARGV;
open(my $fh, "<", $file) or exit 1;
my $line = <$fh>;
close($fh);
$line = '' unless(defined $line);
my ($total, $appconnect) = split(' ', $line);
exit 1 unless(defined $appconnect);
my $elapsed = ($total + 0) - ($appconnect + 0);
exit($elapsed >= LIMIT_SECONDS);
