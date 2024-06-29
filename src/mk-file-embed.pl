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

my $varname = "var";
if($ARGV[0] eq "--var") {
    shift;
    $varname = shift @ARGV;
}

print <<HEAD
/*
 * NEVER EVER edit this manually, fix the mk-file-embed.pl script instead!
 */
extern const unsigned char ${varname}[];
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
