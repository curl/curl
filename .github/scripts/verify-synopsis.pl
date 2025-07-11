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

use strict;
use warnings;

my @files = @ARGV;
my $cfile = "test.c";

if(!@files || $files[0] eq "-h") {
    print "Usage: verify-synopsis [man pages]\n";
    exit;
}

sub testcompile {
    my $rc = system("gcc -c test.c -DCURL_DISABLE_TYPECHECK -DCURL_ALLOW_OLD_MULTI_SOCKET -I include") >> 8;
    return $rc;
}


sub extract {
    my($f) = @_;
    my $syn = 0;
    my $l = 0;
    my $iline = 0;
    open(F, "<$f");
    open(O, ">$cfile");
    while(<F>) {
        $iline++;
        if(/^# SYNOPSIS/) {
            $syn = 1
        }
        elsif($syn == 1) {
            if(/^\~\~\~/) {
                $syn++;
                print O "#line $iline \"$f\"\n";
            }
        }
        elsif($syn == 2) {
            if(/^\~\~\~/) {
                last;
            }
            # turn the vararg argument into vararg
            $_ =~ s/, parameter\)\;/, ...);/;
            print O $_;
            $l++;
        }
    }
    close(F);
    close(O);

    if($syn < 2) {
        print STDERR "Found no synopsis in $f\n";
        return 1;
    }

    return 0;
}

my $error;
for my $m (@files) {
    $error |= extract($m);
    $error |= testcompile($m);
}
exit $error;
