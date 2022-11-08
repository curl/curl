#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2010 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Verify that curl_version_info.3 documents all the CURL_VERSION_ bits
# from the header.
#

use strict;
use warnings;

my $manpage=$ARGV[0];
my $header=$ARGV[1];
my $source=$ARGV[2];
my %manversion;
my %headerversion;
my %manname;
my %sourcename;
my $error=0;

open(M, "<$manpage");
while(<M>) {
    if($_ =~ / mask bit: (CURL_VERSION_[A-Z0-9_]+)/i) {
        $manversion{$1}++;
    }
    if($_ =~ /^\.ip """([^"]+)"""/i) {
        $manname{$1}++;
    }
}
close(M);

open(H, "<$header");
while(<H>) {
    if($_ =~ /^\#define (CURL_VERSION_[A-Z0-9_]+)/i) {
        $headerversion{$1}++;
    }
}
close(H);

open(S, "<$source");
while(<S>) {
    if($_ =~ /FEATURE\("([^"]*)"/) {
      $sourcename{$1}++;
    }
}
close(S);

for my $h (keys %headerversion) {
    if(!$manversion{$h}) {
        print STDERR "$manpage: missing $h\n";
        $error++;
    }
}
for my $h (keys %manversion) {
    if(!$headerversion{$h}) {
        print STDERR "$manpage: $h is not in the header!\n";
        $error++;
    }
}
for my $n (keys %sourcename) {
    if(!$manname{$n}) {
        print STDERR "$manpage: missing feature name $n\n";
        $error++;
    }
}
for my $n (keys %manname) {
    if(!$sourcename{$n}) {
        print STDERR "$manpage: $n is not in the source!\n";
        $error++;
    }
}

exit $error;
