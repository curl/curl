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
#
#

use strict;
use warnings;

# we may get the dir root pointed out
my $root=$ARGV[0] || ".";

my %typecheck; # from the include file
my %enum; # from libcurl-errors.3

sub gettypecheck {
    open(my $f, "<", "$root/include/curl/typecheck-gcc.h")
        || die "no typecheck file";
    while(<$f>) {
        chomp;
        if($_ =~ /\(option\) == (CURL[^ \)]*)/) {
            $typecheck{$1}++;
        }
    }
    close($f);
}

sub getinclude {
    open(my $f, "<", "$root/include/curl/curl.h")
        || die "no curl.h";
    while(<$f>) {
        if($_ =~ /\((CURLOPT[^,]*), (CURLOPTTYPE_[^,]*)/) {
            my ($opt, $type) = ($1, $2);
            if($type !~ /LONG|VALUES|BLOB|OFF_T/) {
                $enum{$opt}++;
            }
        }
    }
    $enum{"CURLOPT_SOCKS5_GSSAPI_SERVICE"}++;
    $enum{"CURLOPT_CONV_FROM_NETWORK_FUNCTION"}++;
    $enum{"CURLOPT_CONV_FROM_UTF8_FUNCTION"}++;
    $enum{"CURLOPT_CONV_TO_NETWORK_FUNCTION"}++;
    close($f);
}

gettypecheck();
getinclude();

my $error;
for(sort keys %typecheck) {
    if($typecheck{$_} && !$enum{$_}) {
        print "$_ is not in curl.h\n";
        $error++;
    }
}

for(sort keys %enum) {
    if($enum{$_} && !$typecheck{$_}) {
        print "$_ is not checked in typecheck-gcc-h\n";
        $error++;
    }
}
print "OK\n" if(!$error);
