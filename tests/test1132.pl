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
    my $fetchmem;

    print STDERR "checking $file...\n";

    open(my $f, "<", "$file");
    while(<$f>) {
        if($_ =~ /\W(free|alloc|strdup)\(/) {
            $memfunc++;
        }
        elsif($_ =~ /^ *# *include \"memdebug.h\"/) {
            $memdebug++;
        }
        elsif($_ =~ /^ *# *include \"fetch_memory.h\"/) {
            $fetchmem++;
        }
        elsif($_ =~ /mem-include-scan/) {
            # free pass
            close($f);
            return 0;
        }
        if($memfunc && $memdebug && $fetchmem) {
            last;
        }
    }
    close($f);


    if($memfunc) {
        if($memdebug && $fetchmem) {
            return 0;
        }
        else {
            if(!$memdebug) {
                print STDERR "$file doesn't include \"memdebug.h\"!\n";
            }
            if(!$fetchmem) {
                print STDERR "$file doesn't include \"fetch_memory.h\"!\n";
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
