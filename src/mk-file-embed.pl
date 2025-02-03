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

my $varname = "var";
if($ARGV[0] eq "--var") {
    shift;
    $varname = shift @ARGV;
}

my $varname_upper = uc($varname);

print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mk-file-embed.pl script instead!
 */
#ifndef FETCH_DECLARED_${varname_upper}
#define FETCH_DECLARED_${varname_upper}
extern const unsigned char ${varname}[];
#endif
const unsigned char ${varname}[] = {
HEAD
    ;

while (<STDIN>) {
    my $line = $_;
    foreach my $n (split //, $line) {
        my $ord = ord($n);
        printf("%s,", $ord);
        if($ord == 10) {
             printf("\n");
        }
    }
}

print <<ENDLINE
0
};
ENDLINE
    ;
