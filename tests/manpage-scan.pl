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
# Scan symbols-in-version (which is verified to be correct by test 1119), then
# verify that each option mention in there that should have its own man page
# actually does.
#
# In addition, make sure that every current option to curl_easy_setopt,
# curl_easy_getinfo and curl_multi_setopt are also mentioned in their
# corresponding main (index) man page.
#
# Output all deviances to stderr.

use strict;
use warnings;

# we may get the dir root pointed out
my $root=$ARGV[0] || ".";
my $syms = "$root/docs/libcurl/symbols-in-versions";
my $curlh = "$root/include/curl/curl.h";
my $errors;

# the prepopulated alias list is the CURLINFO_* defines that are used for the
# debug function callback and the fact that they use the same prefix as the
# curl_easy_getinfo options was a mistake.
my %alias = (
    'CURLINFO_DATA_IN' => 'none',
    'CURLINFO_DATA_OUT' => 'none',
    'CURLINFO_END' => 'none',
    'CURLINFO_HEADER_IN' => 'none',
    'CURLINFO_HEADER_OUT' => 'none',
    'CURLINFO_LASTONE' => 'none',
    'CURLINFO_NONE' => 'none',
    'CURLINFO_SSL_DATA_IN' => 'none',
    'CURLINFO_SSL_DATA_OUT' => 'none',
    'CURLINFO_TEXT' => 'none'
    );

sub scanmanpage {
    my ($file, @words) = @_;

    open(M, "<$file");
    my @m = <M>;
    close(M);

    foreach my $m (@words) {

        my @g = grep(/^\.IP $m/, @m);
        if(!$g[0]) {
            print STDERR "Missing mention of $m in $file\n";
            $errors++;
        }
    }
}

# check for define alises
open(R, "<$curlh") ||
    die "no curl.h";
while(<R>) {
    if(/^\#define (CURL(OPT|INFO|MOPT)_\w+) (.*)/) {
        $alias{$1}=$3;
    }
}
close(R);

my @curlopt;
my @curlinfo;
my @curlmopt;
open(R, "<$syms") ||
    die "no input file";
while(<R>) {
    chomp;
    my $l= $_;
    if($l =~ /(CURL(OPT|INFO|MOPT)_\w+) *([0-9.]*) *([0-9.-]*) *([0-9.]*)/) {
        my ($opt, $type, $add, $dep, $rem) = ($1, $2, $3, $4, $5);

        if($alias{$opt}) {
            #print "$opt => $alias{$opt}\n";
        }
        elsif($rem) {
            # $opt was removed in $rem
            # so don't check for that
        }
        else {
            if($type eq "OPT") {
                push @curlopt, $opt,
            }
            elsif($type eq "INFO") {
                push @curlinfo, $opt,
            }
            elsif($type eq "MOPT") {
                push @curlmopt, $opt,
            }
            if(! -f "$root/docs/libcurl/opts/$opt.3") {
                print STDERR "Missing $opt.3\n";
                $errors++;
            }
        }
    }
}
close(R);

scanmanpage("$root/docs/libcurl/curl_easy_setopt.3", @curlopt);
scanmanpage("$root/docs/libcurl/curl_easy_getinfo.3", @curlinfo);
scanmanpage("$root/docs/libcurl/curl_multi_setopt.3", @curlmopt);

exit $errors;
