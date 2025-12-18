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

# pass files as argument(s)

use strict;
use warnings;

my $docroot="https://curl.se/libcurl/c";

for my $f (@ARGV) {
    open(NEW, ">$f.new");
    open(F, "<$f");
    while(<F>) {
        my $l = $_;
        if($l =~ /\/* $docroot/) {
            # just ignore preciously added refs
        }
        elsif($l =~ /^( *).*curl_easy_setopt\([^,]*, *([^ ,]*) *,/) {
            my ($prefix, $anchor) = ($1, $2);
            $anchor =~ s/_//g;
            print NEW "$prefix/* $docroot/curl_easy_setopt.html#$anchor */\n";
            print NEW $l;
        }
        elsif($l =~ /^( *).*(curl_([^\(]*))\(/) {
            my ($prefix, $func) = ($1, $2);
            print NEW "$prefix/* $docroot/$func.html */\n";
            print NEW $l;
        }
        else {
            print NEW $l;
        }
    }
    close(F);
    close(NEW);

    system("mv $f $f.org");
    system("mv $f.new $f");
}
