#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2010 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
#
# This script scans C source files. If they seem to use memory functions,
# it also makes sure that it #includes the correct two header files!
#
# You can also mark a C source as fine by using 'mem-include-scan' anywhere in
# it.
#

use strict;
use warnings;

my $dir = $ARGV[0] || die "specify directory!";

sub scanfile {
    my ($file) = @_;
    my @includes;
    my $problems = 0;
    my $libcurl;
    my $curltool;

    open(F, "<$file");
    while(<F>) {
        if(/mem-include-scan/) {
            # free pass
            close(F);
            return 0;
        }
        if(/^ *# *include [<"](.+)[">]$/) {
            push @includes, $1;
        }
    }
    close(F);

    if(defined($includes[0]) && $includes[0] eq "curl_setup.h") {
        $libcurl = 1;
    }
    elsif(defined($includes[0]) && $includes[0] eq "tool_setup.h") {
        $curltool = 1;
    }
    else {
        print STDERR "$file has unexpected first include! " .
                     "Expected curl_setup.h (libcurl) or " .
                     "tool_setup.h (curltool).\n";
        return 1;
    }

    if(!defined($includes[-1]) || $includes[-1] ne "memdebug.h") {
        print STDERR "$file doesn't include \"memdebug.h\" as last include!\n";
        $problems++;
    }
    if(!defined($includes[-2]) || $includes[-2] ne "curl_memory.h") {
        print STDERR "$file doesn't include \"curl_memory.h\" " .
                     "as 2nd to last include!\n";
        $problems++;
    }

    return $problems;
}

opendir(my $dh, $dir) || die "can't opendir $dir: $!";
my @cfiles = grep { /\.c\z/ && -f "$dir/$_" } readdir($dh);
closedir $dh;

my $errs;
for(@cfiles) {
    $errs += scanfile("$dir/$_");
}

if($errs) {
    print STDERR "----\n$errs errors detected!\n";
    exit 2;
}
