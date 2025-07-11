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

# we may get the dir root pointed out
my $root = $ARGV[0] || ".";

my %error; # from the include file
my %docs; # from libcurl-errors.3

sub getdocserrors {
    open(my $f, "<", "$root/docs/libcurl/libcurl-errors.md");
    while(<$f>) {
        if($_ =~ /^## (CURL[EM]_[^ ]*)/) {
            my ($symbol) = ($1);
            if($symbol =~ /OBSOLETE/) {
                ;
            }
            else {
                $docs{$symbol}=1;
            }
        }
    }
    close($f);
}

sub getincludeerrors {
    open(my $f, "<", "$root/docs/libcurl/symbols-in-versions");
    while(<$f>) {
        if($_ =~ /^(CURL[EM]_[^ \t]*)[ \t]*([0-9.]+)[ \t]*(.*)/) {
            my ($symbol, $added, $rest) = ($1,$2,$3);
            if($rest =~ /^([0-9.]+)/) {
                # removed!
            }
            else {
                $error{$symbol}=$added;
            }
        }
    }
    close($f);
}

getincludeerrors();
getdocserrors();

for(sort keys %error) {
    if($error{$_} && !$docs{$_}) {
        print "$_ is not in libcurl-errors.md\n";
    }
}

for(sort keys %docs) {
    if($docs{$_} && !$error{$_}) {
        print "$_ is not in symbols-in-versions\n";
    }
}
