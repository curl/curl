#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
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
# Experience has shown that the symbols-in-versions file is very useful to
# applications that want to build with a wide range of libcurl versions.
# It is however easy to get it wrong and the source gets a bit messy with all
# the fixed numerical comparisons.
#
# The point of this script is to provide an easy-to-use macro for libcurl-
# using applications to do preprocessor checks for specific libcurl defines,
# and yet make the code clearly show what the macro is used for.
#
# Run this script and generate libcurl-symbols.h and then use that header in
# a fashion similar to:
#
# #include "libcurl-symbols.h"
#
# #if LIBCURL_HAS(CURLOPT_MUTE)
#   has mute
# #else
#   no mute
# #endif
#
#
open F, "<symbols-in-versions";

sub str2num {
    my ($str)=@_;
    if($str =~ /([0-9]*)\.([0-9]*)\.*([0-9]*)/) {
        return sprintf("0x%06x", $1<<16 | $2 << 8 | $3);
    }
}

print <<EOS

#include <curl/curl.h>

#define LIBCURL_HAS(x) \\
  (defined(x ## _FIRST) && (x ## _FIRST <= LIBCURL_VERSION_NUM) && \\
   (!defined(x ## _LAST) || ( x ## _LAST >= LIBCURL_VERSION_NUM)))

EOS
    ;

while(<F>) {
    if(/^(CURL[^ ]*)[ \t]*(.*)/) {
        my ($sym, $vers)=($1, $2);

        my $intr;
        my $rm;
        my $dep;

        # is there removed info?
        if($vers =~ /([\d.]+)[ \t-]+([\d.-]+)[ \t]+([\d.]+)/) {
            ($intr, $dep, $rm)=($1, $2, $3);
        }
        # is it a dep-only line?
        elsif($vers =~ /([\d.]+)[ \t-]+([\d.]+)/) {
            ($intr, $dep)=($1, $2);
        }
        else {
            $intr = $vers;
        }

        my $inum = str2num($intr);

        print <<EOS
#define ${sym}_FIRST $inum /* Added in $intr */
EOS
;
        my $irm = str2num($rm);
        if($rm) {
        print <<EOS
#define ${sym}_LAST $irm /* Last featured in $rm */
EOS
;
        }

    }
}
