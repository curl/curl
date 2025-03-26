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

# This scripts scans the entire git repository for binary files.

use strict;
use warnings;

my $root = ".";
if($ARGV[0]) {
    $root = $ARGV[0];
}

my @bin;
my $error = 0;

sub checkfile {
    my ($file) = @_;
    open(my $mh, "<", "$file") || die "can't read $file";
    my $line = 0;
    while(<$mh>) {
        my $l = $_;
        $line++;
        if($l =~ /([\x00-\x08\x0b\x0c\x0e-\x1f\x7f])/) {
            push @bin, $file;

            printf STDERR "$file:$line has binary contents\n";
            $error++;
            last;
        }
    }
    close($mh);
}

my @files = `git ls-files -- $root`;

if(scalar(@files) < 3000) {
    # this means this is not the git source code repository or that git does
    # not work, error out!
    print STDERR "too few files in the git repository!\n";
    exit 1;
}

for my $f (@files) {
    chomp $f;
    checkfile("$root/$f");
}

exit $error;
