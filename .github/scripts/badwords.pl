#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# bad[:=]correct
#
# If separator is '=', the string will be compared case sensitively.
# If separator is ':', the check is done case insensitively.
#
# To add white listed uses of bad words that are removed before checking for
# the bad ones:
#
# ---(accepted word)
#

use strict;
use warnings;

my @whitelist;
my %alt;
my %exactcase;

my %wl;
if($ARGV[0] eq "-w") {
    shift @ARGV;
    my $file = shift @ARGV;
    open(W, "<$file");
    while(<W>) {
        if(/^#/) {
            # allow #-comments
            next;
        }
        if(/^([^:]*):(\d+):(.*)/) {
            $wl{"$1:$2:$3"}=1;
            #print STDERR "whitelisted $1:$2:$3\n";
        }
    }
    close(W);
}

my @w;
while(<STDIN>) {
    chomp;
    if($_ =~ /^#/) {
        next;
    }
    if($_ =~ /^---(.*)/) {
        push @whitelist, $1;
    }
    elsif($_ =~ /^(.*)([:=])(.*)/) {
        my ($bad, $sep, $better)=($1, $2, $3);
        push @w, $bad;
        $alt{$bad} = $better;
        if($sep eq "=") {
            $exactcase{$bad} = 1;
        }
    }
}

my $errors = 0;

sub file {
    my ($f) = @_;
    my $l = 0;
    open(F, "<$f");
    while(<F>) {
        my $in = $_;
        $l++;
        chomp $in;
        if($in =~ /^    /) {
            next;
        }
        # remove the link part
        $in =~ s/(\[.*\])\(.*\)/$1/g;
        # remove backticked texts
        $in =~ s/\`.*\`//g;
        # remove whitelisted patterns
        for my $p (@whitelist) {
            $in =~ s/$p//g;
        }
        foreach my $w (@w) {
            my $case = $exactcase{$w};
            if(($in =~ /^(.*)$w/i && !$case) ||
               ($in =~ /^(.*)$w/ && $case) ) {
                my $p = $1;
                my $c = length($p)+1;

                my $ch = "$f:$l:$w";
                if($wl{$ch}) {
                    # whitelisted
                    print STDERR "$ch found but whitelisted\n";
                    next;
                }

                print STDERR  "$f:$l:$c: error: found bad word \"$w\"\n";
                printf STDERR " %4d | %s\n", $l, $in;
                printf STDERR "      | %*s^%s\n", length($p), " ",
                    "~" x (length($w)-1);
                printf STDERR " maybe use \"%s\" instead?\n", $alt{$w};
                $errors++;
            }
        }
    }
    close(F);
}

my @filemasks = @ARGV;
open(my $git_ls_files, '-|', 'git', 'ls-files', '--', @filemasks) or die "Failed running git ls-files: $!";
while(my $each = <$git_ls_files>) {
    chomp $each;
    file($each);
}
close $git_ls_files;
exit $errors;
