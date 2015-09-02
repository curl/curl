#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2011-2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Run this script and generate curl/has.h and then use that header in
# a fashion similar to:
#
# #include <curl/has.h>
#
# #if CURL_HAS(CURLOPT_MUTE)
#   has mute
# #else
#   no mute
# #endif
#
#

sub str2num {
    my ($str)=@_;
    if($str =~ /([0-9]*)\.([0-9]*)\.*([0-9]*)/) {
        return sprintf("0x%06x", $1<<16 | $2 << 8 | $3);
    }
}

print <<EOS
#ifndef __CURL_HAS_H
#define __CURL_HAS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \\| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \\___|\\___/|_| \\_\\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * This file is generated. Do not edit by hand. Edit
 * docs/libcurl/symbols-in-versions and regenerate this with has.pl
 */
#include <curl/curlver.h>

/*
 * #include <curl/has.h>
 *
 * #if CURL_HAS(CURLOPT_MUTE)
 *    use_mute();
 * #else
 *    without_mute();
 * #endif
 */
#define CURL_HAS_IN(x,y) \\
  (defined(CURLHAS_ ## x ) && (CURLHAS_ ## x <= y) && \\
   (!defined(CURLHAS_ ## x ## _L) || ( CURLHAS_ ## x ## _L >= y)))

#define CURL_HAS(x) CURL_HAS_IN(x, LIBCURL_VERSION_NUM)

EOS
    ;

while(<STDIN>) {
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
#define CURLHAS_${sym} $inum /* $intr */
EOS
;
        my $irm = str2num($rm);
        if($rm) {
        print <<EOS
#define CURLHAS_${sym}_L $irm /* Last $rm */
EOS
;
        }

    }
}

print <<EOS
#endif /* __CURL_HAS_H */

EOS
    ;
