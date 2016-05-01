#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# scan nroff pages to find basic syntactic problems such as unbalanced \f
# codes

my $docsroot = $ARGV[0];

if(!$docsroot || ($docsroot eq "-g")) {
    print "Usage: nroff-scan.pl <docs root dir> [nroff files]\n";
    exit;
}


shift @ARGV;

my @f = @ARGV;

my %manp;

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
                print STDERR "error: $f:$line: missing \\fP after $str\n";
            }
            if($str =~ /(curl([^ ]*))\(3\)/i) {
                my $man = "$1.3";
                if($manp{$man}) {
                    ;
                }
                elsif(-r "$docsroot/$man" ||
                      -r "$docsroot/libcurl/$man" ||
                      -r "$docsroot/libcurl/opts/$man") {
                    $manp{$man}=1;
                }
                else {
                    print STDERR "error: $f:$line: refering to non-existing man page $man\n";
                }
            }
        }
        if($l =~ /(curl([^ ]*)\(3\))/i) {
            print STDERR "error: $f:$line: non-referencing $1\n";
        }
        $line++;
    }
    close(F);
}

foreach my $f (@f) {
    file($f);
}
