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

sub showline {
    my ($l) = @_;
    $l =~ s/([^\x20-\x7f])/sprintf "%%%02x", ord $1/eg;
    return $l;
}

my $root = $ARGV[0] || '..';

open(my $fh, "-|", "perl $root/lib/optiontable.pl < $root/include/curl/curl.h");
binmode $fh;
my @gen=<$fh>;
close($fh);

open($fh, "<", "$root/lib/easyoptions.c");
binmode $fh;
my @file=<$fh>;
close($fh);

if(join("", @gen) ne join("", @file)) {
    print "easyoptions.c need to be regenerated!\n";

    printf "easyoptions.c is %u lines\n", scalar(@file);
    printf "generated file is %u lines\n", scalar(@gen);
    my $e = 0;
    for my $i (0 .. $#gen) {
        # strip CRLFs to unify
        $gen[$i] =~ s/[\r\n]//g;
        $file[$i] =~ s/[\r\n]//g;
        if($gen[$i] ne $file[$i]) {
            printf "File: %u:%s\nGen:  %u:%s\n",
                $i+1, showline($file[$i]),
                $i+1, showline($gen[$i]);
            $e++;
            if($e > 10) {
                # only show 10 lines diff
                last;
            }
        }
    }
    exit 1 if($e);
}
