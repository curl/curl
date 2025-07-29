#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Input: cmdline docs markdown files, they get modified *in place*
#
# Strip off the leading meta-data/header part, remove all known curl symbols
# and long command line options. Also clean up whatever else the spell checker
# might have a problem with that we still deem is fine.
#

use strict;
use warnings;

my @asyms;

open(S, "<./docs/libcurl/symbols-in-versions")
    || die "can't find symbols-in-versions";
while(<S>) {
    if(/^([^ ]*) /) {
        push @asyms, $1;
    }
}
close(S);

# init the opts table with "special" options not easy to figure out
my @aopts = (
    '--ftp-ssl-reqd', # old alias
    );

open(O, "<./docs/options-in-versions")
    || die "can't find options-in-versions";
while(<O>) {
    chomp;
    if(/^([^ ]+)/) {
        my $o = $1;
        push @aopts, $o;
        if($o =~ /^--no-(.*)/) {
            # for the --no options, also make one without it
            push @aopts, "--$1";
        }
        elsif($o =~ /^--disable-(.*)/) {
            # for the --disable options, also make the special ones
            push @aopts, "--$1";
            push @aopts, "--no-$1";
        }
    }
}
close(O);

open(C, "<./.github/scripts/spellcheck.curl")
    || die "can't find spellcheck.curl";
while(<C>) {
    if(/^\#/) {
        next;
    }
    chomp;
    if(/^([^ ]+)/) {
        push @asyms, $1;
    }
}
close(C);

# longest symbols first
my @syms = sort { length($b) <=> length($a) } @asyms;

# longest cmdline options first
my @opts = sort { length($b) <=> length($a) } @aopts;

sub process {
    my ($f) = @_;

    my $ignore = 0;
    my $sepcount = 0;
    my $out;
    my $line = 0;
    open(F, "<$f") or die;

    while(<F>) {
        $line++;
        if(/^---/ && ($line == 1)) {
            $ignore = 1;
            next;
        }
        elsif(/^---/ && $ignore) {
            $ignore = 0;
            next;
        }
        next if($ignore);

        my $l = $_;

        # strip out backticked words
        $l =~ s/`[^`]+`//g;

        # **bold**
        $l =~ s/\*\*(\S.*?)\*\*//g;
        # *italics*
        $l =~ s/\*(\S.*?)\*//g;

        # strip out https URLs, we don't want them spellchecked
        $l =~ s!https://[a-z0-9\#_/.-]+!!gi;

        $out .= $l;
    }
    close(F);

    # cut out all known curl cmdline options
    map { $out =~ s/$_//g; } (@opts);

    # cut out all known curl symbols
    map { $out =~ s/\b$_\b//g; } (@syms);

    if(!$ignore) {
        open(O, ">$f") or die;
        print O $out;
        close(O);
    }
}

for my $f (@ARGV) {
    process($f);
}
