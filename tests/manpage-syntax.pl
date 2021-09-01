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

sub scanmanpage {
    my ($file) = @_;
    my $reqex = 0;
    my $inex = 0;
    my $exsize = 0;
    my $shc = 0;
    my @sh;

    print "Check $file\n";
    open(M, "<$file") || die "no such file: $file";
    if($file =~ /\/CURL[^\/]*.3/) {
        # This is the man page for an libcurl option. It requires an example!
        $reqex = 1;
    }
    my $line = 1;
    while(<M>) {
        if($_ =~ /^.SH EXAMPLE/i) {
            $inex = 1;
        }
        elsif($_ =~ /^.SH/i) {
            $inex = 0;
        }
        elsif($inex)  {
            $exsize++;
        }
        if($_ =~ /^.SH (.*)/i) {
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
        $line++;
    }
    close(M);

    if($reqex) {
        # only for libcurl options man-pages

        if($exsize < 2) {
            print STDERR "$file:$line missing EXAMPLE section\n";
            $errors++;
        }

        my $got;
        my $i = 0;
        my $shused = 1;
        do {
            $got = shift(@sh);
            if($got) {
                $i = $blessed{$got};
            }
            if($i && $got) {
                # mandatory section

                if($i != $shused) {
                    printf STDERR "$file:%u Got $got, when %s was expected\n",
                        $shline{$got},
                        $order[$shused-1];
                    $errors++;
                    return;
                }
                $shused++;
                if($i == 9) {
                    # last mandatory one, exit
                    $got="";
                }
            }
        } while($got);

        if($i != 8) {
            printf STDERR "$file:$line missing mandatory section: %s\n",
                $order[$i];
            $errors++;
        }
    }
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
