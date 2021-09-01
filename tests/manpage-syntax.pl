#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2019 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
#
# Scan man page(s) and detect some simple and yet common formatting mistakes.
#
# Output all deviances to stderr.

use strict;
use warnings;

# get the file name first
my $symbolsinversions=shift @ARGV;

# we may get the dir roots pointed out
my @manpages=@ARGV;
my $errors = 0;

my %blessed;
my @order = (
    'NAME',
    'SYNOPSIS',
    'DESCRIPTION',
     #'DEFAULT', # CURLINFO_ has no default
    'PROTOCOLS',
    'EXAMPLE',
    'AVAILABILITY',
    'RETURN VALUE',
    'SEE ALSO'
    );
my %shline; # section => line number

my %symbol;
sub allsymbols {
    open(F, "<$symbolsinversions") ||
        die "$symbolsinversions: $|";
    while(<F>) {
        if($_ =~ /^([^ ]*)/) {
            $symbol{$1}=$1;
        }
    }
    close(F);
}

sub scanmanpage {
    my ($file) = @_;
    my $reqex = 0;
    my $inex = 0;
    my $exsize = 0;
    my $shc = 0;
    my @sh;

    open(M, "<$file") || die "no such file: $file";
    if($file =~ /[\/\\]CURL[^\/\\]*.3/) {
        # This is the man page for an libcurl option. It requires an example!
        $reqex = 1;
    }
    my $line = 1;
    while(<M>) {
        chomp;
        if($_ =~ /^\.SH EXAMPLE/i) {
            $inex = 1;
        }
        elsif($_ =~ /^\.SH/i) {
            $inex = 0;
        }
        elsif($inex)  {
            $exsize++;
        }
        if($_ =~ /^\.SH ([^\r\n]*)/i) {
            my $n = $1;
            # remove enclosing quotes
            $n =~ s/\"(.*)\"\z/$1/;
            push @sh, $n;
            $shline{$n} = $line;
        }

        if($_ =~ /^\'/) {
            print STDERR "$file:$line line starts with single quote!\n";
            $errors++;
        }
        if($_ =~ /\\f([BI])(.*)/) {
            my ($format, $rest) = ($1, $2);
            if($rest !~ /\\fP/) {
                print STDERR "$file:$line missing \\f${format} terminator!\n";
                $errors++;
            }
        }
        if($_ =~ /[ \t]+$/) {
            print STDERR "$file:$line trailing whitespace\n";
            $errors++;
        }
        if($_ =~ /\\f([BI])([^\\]*)\\fP/) {
            my $r = $2;
            if($r =~ /^(CURL.*)\(3\)/) {
                my $rr = $1;
                if(!$symbol{$rr}) {
                    print STDERR "$file:$line link to non-libcurl option $rr!\n";
                    $errors++;
                }
            }
        }
        $line++;
    }
    close(M);

    if($reqex) {
        # only for libcurl options man-pages

        my $shcount = scalar(@sh); # before @sh gets shifted
        if($exsize < 2) {
            print STDERR "$file:$line missing EXAMPLE section\n";
            $errors++;
        }

        if($shcount < 3) {
            print STDERR "$file:$line too few man page sections!\n";
            $errors++;
            return;
        }

        my $got = "start";
        my $i = 0;
        my $shused = 1;
        my @shorig = @sh;
        while($got) {
            my $finesh;
            $got = shift(@sh);
            if($got) {
                if($blessed{$got}) {
                    $i = $blessed{$got};
                    $finesh = $got; # a mandatory one
                }
            }
            if($i && defined($finesh)) {
                # mandatory section

                if($i != $shused) {
                    printf STDERR "$file:%u Got %s, when %s was expected\n",
                        $shline{$finesh},
                        $finesh,
                        $order[$shused-1];
                    $errors++;
                    return;
                }
                $shused++;
                if($i == scalar(@order)) {
                    # last mandatory one, exit
                    last;
                }
            }
        }

        if($i != scalar(@order)) {
            printf STDERR "$file:$line missing mandatory section: %s\n",
                $order[$i];
            printf STDERR "$file:$line section found at index %u: '%s'\n",
                $i, $shorig[$i];
            printf STDERR " Found %u used sections\n", $shcount;
            $errors++;
        }
    }
}

allsymbols();

if(!$symbol{'CURLALTSVC_H1'}) {
    print STDERR "didn't get the symbols-in-version!\n";
    exit;
}

my $ind = 1;
for my $s (@order) {
    $blessed{$s} = $ind++
}

for my $m (@manpages) {
    scanmanpage($m);
}

print STDERR "ok\n" if(!$errors);

exit $errors;
