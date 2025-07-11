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

# populate the %pastversion hash table with the version number as key and
# release date as value

use strict;
use warnings;

our %pastversion;

sub allversions {
    my ($file) = @_;
    open(A, "<$file") ||
        die "can't open the versions file $file\n";
    my $before = 1;
    my $relcount;
    while(<A>) {
        if(/^## Past releases/) {
            $before = 0;
        }
        elsif(!$before &&
              /^- ([0-9.]+): (.*)/) {
            $pastversion{$1}=$2;
            $relcount++;
        }
    }
    close(A);
    die "too few releases ($relcount) found in $file" if($relcount < 100);
}

1;
