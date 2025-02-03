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
# are also available at https://fetch.se/docs/copyright.html.
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

# pass files as argument(s)

my $docroot="https://fetch.se/libfetch/c";

for $f (@ARGV) {
    open(NEW, ">$f.new");
    open(F, "<$f");
    while(<F>) {
        my $l = $_;
        if($l =~ /\/* $docroot/) {
            # just ignore preciously added refs
        }
        elsif($l =~ /^( *).*fetch_easy_setopt\([^,]*, *([^ ,]*) *,/) {
            my ($prefix, $anc) = ($1, $2);
            $anc =~ s/_//g;
            print NEW "$prefix/* $docroot/fetch_easy_setopt.html#$anc */\n";
            print NEW $l;
        }
        elsif($l =~ /^( *).*(fetch_([^\(]*))\(/) {
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
