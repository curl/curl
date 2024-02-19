#!/usr/bin/perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Input: a cmdline docs markdown, it gets modfied *in place*
#
# The main purpose is to strip off the leading meta-data part, but also to
# clean up whatever else the spell checker might have a problem with that we
# still deem is fine.

my $header = 1;
while(1) {
    # set this if the markdown has no meta-data header to skip
    if($ARGV[0] eq "--no-header") {
        shift @ARGV;
        $header = 0;
    }
    else {
        last;
    }
}

my $f = $ARGV[0];

open(F, "<$f") or die;

my $ignore = $header;
my $sepcount = 0;
my @out;
while(<F>) {
    if(/^---/ && $header) {
        if(++$sepcount == 2) {
            $ignore = 0;
        }
        next;
    }
    next if($ignore);

    # strip out all long command line options
    $_ =~ s/--[a-z0-9-]+//g;

    # strip out https URLs, we don't want them spellchecked
    $_ =~ s!https://[a-z0-9\#_/.-]+!!gi;

    push @out, $_;
}
close(F);

if(!$ignore) {
    open(O, ">$f") or die;
    print O @out;
    close(O);
}
