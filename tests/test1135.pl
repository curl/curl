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
#

use strict;
use warnings;

my $sort = 0;

# we may get the dir root pointed out
my $root = shift @ARGV;
while(defined $root) {

    if($root =~ /--heading=(.*)/) {
        print "$1\n";
        $root = shift @ARGV;
        next;
    }
    elsif($root =~ /--sort/) {
        $sort = 1;
        $root = shift @ARGV;
        next;
    }

    last;
}

if(!defined $root) {
    $root = ".";
}

$root = "$root/include/curl";
opendir(D, "$root") || die "Cannot open directory $root: $!\n";
my @dir = readdir(D);
closedir(D);

my @incs;
foreach (sort(@dir)) {
    if($_ =~ /\.h$/) {
        push(@incs, "$root/$_");
    }
}

my $verbose=0;
my $summary=0;
my $misses=0;

my @out;
foreach my $f (@incs) {
    open H, "<$f" || die;
    my $first = "";
    while(<H>) {
        s/CURL_DEPRECATED\(.*"\)//;
        s/  */ /g;
        if (/^(^CURL_EXTERN .*?)\(/) {
            my $decl = $1;
            $decl =~ s/\r$//;
            $decl =~ /([a-z_]+)$/;
            push(@out, "$1");
        }
        elsif (/^(^CURL_EXTERN .*)/) {
            # handle two-line declarations
            my $decl = $1;
            $decl =~ s/\r$//;
            $first = $decl;
        }
        elsif($first) {
            if (/^ *(.*)\(/) {
                my $decl = $1;
                $decl =~ s/\r$//;
                $first .= $decl;
                $first =~ /([a-z_]+)$/;
                push(@out, "$1");
            }
            $first = "";
        }
    }
    close H;
}

if($sort) {
    @out = sort(@out);
}

foreach (@out) {
    print("$_\n");
}
