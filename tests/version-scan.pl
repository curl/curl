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
my %manversion;
my %headerversion;
my $error;

open(M, "<$manpage");
while(<M>) {
    if($_ =~ /^.ip (CURL_VERSION_[A-Z0-9_]+)/i) {
        $manversion{$1}++;
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

exit $error;
