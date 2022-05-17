#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2016 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# scan nroff pages to find basic syntactic problems such as unbalanced \f
# codes or references to non-existing curl man pages.

my $docsroot = $ARGV[0];

if(!$docsroot || ($docsroot eq "-g")) {
    print "Usage: nroff-scan.pl <docs root dir> [nroff files]\n";
    exit;
}


shift @ARGV;

my @f = @ARGV;

my %manp;

sub manpresent {
    my ($man) = @_;
    if($manp{$man}) {
        return 1;
    }
    elsif(-r "$docsroot/$man" ||
          -r "$docsroot/libcurl/$man" ||
          -r "$docsroot/libcurl/opts/$man") {
        $manp{$man}=1;
        return 1;
    }
    return 0;
}

sub file {
    my ($f) = @_;
    open(F, "<$f") ||
        die "no file";
    my $line = 1;
    while(<F>) {
        chomp;
        my $l = $_;
        while($l =~ s/\\f(.)([^ ]*)\\f(.)//) {
            my ($pre, $str, $post)=($1, $2, $3);
            if($post ne "P") {
                print "error: $f:$line: missing \\fP after $str\n";
                $errors++;
            }
            if($str =~ /((libcurl|curl)([^ ]*))\(3\)/i) {
                my $man = "$1.3";
                if(!manpresent($man)) {
                    print "error: $f:$line: referring to non-existing man page $man\n";
                    $errors++;
                }
                if($pre ne "I") {
                    print "error: $f:$line: use \\fI before $str\n";
                    $errors++;
                }
            }
        }
        if($l =~ /(curl([^ ]*)\(3\))/i) {
            print "error: $f:$line: non-referencing $1\n";
            $errors++;
        }
        if($l =~ /^\.BR (.*)/) {
            my $i= $1;
            while($i =~ s/((lib|)curl([^ ]*)) *\"\(3\)(,|) *\" *//i ) {
                my $man = "$1.3";
                if(!manpresent($man)) {
                    print "error: $f:$line: referring to non-existing man page $man\n";
                    $errors++;
                }
            }
        }
        $line++;
    }
    close(F);
}

foreach my $f (@f) {
    file($f);
}

print "OK\n" if(!$errors);

exit $errors?1:0;
