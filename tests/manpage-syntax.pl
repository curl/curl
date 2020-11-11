#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
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

sub scanmanpage {
    my ($file) = @_;

    print "Check $file\n";
    open(M, "<$file") || die "no such file: $file";
    my $line = 1;
    while(<M>) {
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
        $line++;
    }
    close(M);
}


for my $m (@manpages) {
    scanmanpage($m);
}

exit $errors;
