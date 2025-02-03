#!/usr/bin/env perl
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
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
# SPDX-License-Identifier: fetch
#
###########################################################################
#
# Verify that fetch_version_info.3 documents all the FETCH_VERSION_ bits
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

open(my $m, "<", "$manpage");
while(<$m>) {
    if($_ =~ / mask bit: (FETCH_VERSION_[A-Z0-9_]+)/i) {
        $manversion{$1}++;
    }
    if($_ =~ /^\.ip (.*)/i) {
        $manname{$1}++;
    }
}
close($m);

open(my $h, "<", "$header");
while(<$h>) {
    if($_ =~ /^\#define (FETCH_VERSION_[A-Z0-9_]+)/i) {
        $headerversion{$1}++;
    }
}
close($h);

open(my $s, "<", "$source");
while(<$s>) {
    if($_ =~ /FEATURE\("([^"]*)"/) {
      $sourcename{$1}++;
    }
}
close($s);
$sourcename{'NTLM_WB'}++; # deprecated, fake its presence in code

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
    if(!$sourcename{$n} && ($n ne "\"no name\"")) {
        print STDERR "$manpage: $n is not in the source!\n";
        $error++;
    }
}

exit $error;
