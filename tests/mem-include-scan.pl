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
    my $memfunc;
    my $memdebug;
    my $curlmem;

    print STDERR "checking $file...\n";

    open(F, "<$file");
    while(<F>) {
        if($_ =~ /\W(free|alloc|strdup)\(/) {
            $memfunc++;
        }
        elsif($_ =~ /^ *# *include \"memdebug.h\"/) {
            $memdebug++;
        }
        elsif($_ =~ /^ *# *include \"curl_memory.h\"/) {
            $curlmem++;
        }
        elsif($_ =~ /mem-include-scan/) {
            # free pass
            close(F);
            return 0;
        }
        if($memfunc && $memdebug && $curlmem) {
            last;
        }
    }
    close(F);


    if($memfunc) {
        if($memdebug && $curlmem) {
            return 0;
        }
        else {
            if(!$memdebug) {
                print STDERR "$file doesn't include \"memdebug.h\"!\n";
            }
            if(!$curlmem) {
                print STDERR "$file doesn't include \"curl_memory.h\"!\n";
            }
            return 1;
        }
    }
    return 0;
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
