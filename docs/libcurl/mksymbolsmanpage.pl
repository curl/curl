#!/usr/bin/env perl
# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at https://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************

my $version="7.41.0";

use POSIX qw(strftime);
my $date = strftime "%b %e, %Y", localtime;
my $year = strftime "%Y", localtime;

print <<HEADER
.\\" **************************************************************************
.\\" *                                  _   _ ____  _
.\\" *  Project                     ___| | | |  _ \\| |
.\\" *                             / __| | | | |_) | |
.\\" *                            | (__| |_| |  _ <| |___
.\\" *                             \\___|\\___/|_| \\_\\_____|
.\\" *
.\\" * Copyright (C) 1998 - $year, Daniel Stenberg, <daniel\@haxx.se>, et al.
.\\" *
.\\" * This software is licensed as described in the file COPYING, which
.\\" * you should have received as part of this distribution. The terms
.\\" * are also available at https://curl.haxx.se/docs/copyright.html.
.\\" *
.\\" * You may opt to use, copy, modify, merge, publish, distribute and/or sell
.\\" * copies of the Software, and permit persons to whom the Software is
.\\" * furnished to do so, under the terms of the COPYING file.
.\\" *
.\\" * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
.\\" * KIND, either express or implied.
.\\" *
.\\" **************************************************************************
.TH libcurl-symbols 3 "$date" "libcurl $version" "libcurl symbols"
.SH NAME
libcurl-symbols \\- libcurl symbol version information
.SH "libcurl symbols"
This man page details version information for public symbols provided in the
libcurl header files. This lists the first version in which the symbol was
introduced and for some symbols two additional information pieces:

The first version in which the symbol is marked "deprecated" - meaning that
since that version no new code should be written to use the symbol as it is
marked for getting removed in a future.

The last version that featured the specific symbol. Using the symbol in source
code will make it no longer compile error-free after that specified version.

This man page is automatically generated from the symbols-in-versions file.
HEADER
    ;

while(<STDIN>) {
    if($_ =~ /^(CURL[A-Z0-9_.]*) *(.*)/) {
        my ($symbol, $rest)=($1,$2);
        my ($intro, $dep, $rem);
        if($rest =~ s/^([0-9.]*) *//) {
           $intro = $1;
        }
        if($rest =~ s/^([0-9.]*) *//) {
           $dep = $1;
        }
        if($rest =~ s/^([0-9.]*) *//) {
           $rem = $1;
        }
        print ".IP $symbol\nIntroduced in $intro\n";
        if($dep) {
          print "Deprecated since $dep\n";
        }
        if($rem) {
          print "Last used in $dep\n";
        }
    }

}
