#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Given: a libcurl curldown man page
# Outputs: the same file, minus the header
#

use strict;
use warnings;

my $f = $ARGV[0] || '';

open(F, "<$f") or die;

my @out;
my $line = 0;
my $hideheader = 0;

while(<F>) {
    if($hideheader) {
        if(/^---/) {
            # end if hiding
            $hideheader = 0;
        }
        push @out, "\n"; # replace with blank
        next;
    }
    elsif(!$line++ && /^---/) {
        # starts with a header, strip off the header
        $hideheader = 1;
        push @out, "\n"; # replace with blank
        next;
    }
    push @out, $_;
}
close(F);

open(O, ">$f") or die;
for my $l (@out) {
    print O $l;
}
close(O);
