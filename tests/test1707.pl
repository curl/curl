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
# This script grew out of help from Przemyslaw Iskra and Balint Szilakszi
# a late evening in the #curl IRC channel.
#

use strict;
use warnings;

my $curl = shift @ARGV;
my $opt = shift @ARGV;
my $output = shift @ARGV;
my $txt = shift @ARGV;

my $longopt;
my $shortopt;
if($opt =~ /^--/) {
    $longopt = $opt;
}
else {
    $shortopt = $opt;
}

# first run the help command
system("$curl -h $opt > $output");
my @curlout;
open(O, "<$output");
push @curlout, <O>;
close(O);

# figure out the short+long option combo using -h all*/
open(C, "$curl -h all|");
if($shortopt) {
    while(<C>) {
        if(/^ +$opt, ([^ ]*)/) {
            $longopt = $1;
            last;
        }
    }
}
else {
    while(<C>) {
        my $f  = $_;
        if(/ $opt /) {
            if($f =~ /^ *(-(.)), $longopt/) {
                $shortopt = $1;
            }
            last;
        }
    }
}
close(C);

my $fullopt;
if($shortopt) {
    $fullopt = "$shortopt, $longopt";
}
else {
    $fullopt = $longopt;
}

open(R, "<$txt");
my $show = 0;
my @txtout;
while(<R>) {
    if(/^    $fullopt/) {
        $show = 1;
    }
    elsif(/^    -/ && $show) {
        last;
    }
    if($show) {
        push @txtout, $_;
    }
}
close(R);

my $error = 0;
if(scalar(@curlout) != scalar(@txtout)) {
    printf "curl -h $opt is %d lines, $txt says %d lines\n",
        scalar(@curlout), scalar(@txtout);
    $error++;
}
else {
    # same size, compare line by line
    for my $i (0 .. $#curlout) {
        # trim CRLF from the data
        $curlout[$i] =~ s/[\r\n]//g;
        $txtout[$i] =~ s/[\r\n]//g;
        if($curlout[$i] ne $txtout[$i]) {
            printf "Line %d\n", $i;
            printf "-h   : %s (%d bytes)\n", $curlout[$i],
                length($curlout[$i]);
            printf "file : %s (%d bytes)\n", $txtout[$i],
                length($txtout[$i]);

            if(length($curlout[$i]) == length($txtout[$i])) {
                my $l = length($curlout[$i]);
                for my $c (0 .. $l) {
                    my $o = substr($curlout[$i], $c, 1);
                    my $t = substr($txtout[$i], $c, 1);
                    if($o ne $t) {
                        print "-h   col %d: %02x\n", $c, ord($o);
                        print "file col %d: %02x\n", $c, ord($t);
                    }
                }
            }
            $error++;
        }
    }
}
exit $error;
