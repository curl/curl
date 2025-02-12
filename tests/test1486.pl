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

my %insrc; # variable set in source
my %indocs; # variable described in docs

my $srccount = 1;
sub getsrcvars {
    open(my $f, "<", "$root/../src/tool_writeout.c");
    my $mode = 0;
    while(<$f>) {
        if(!$mode &&
           ($_ =~ /^static const struct writeoutvar/)) {
            $mode = 1;
        }
        if($mode) {
            if($_ =~ /^}/) {
                last;
            }
            if($_ =~ /^  \{\"([^\"]*)/) {
                my $var = $1;
                $insrc{$var} = $srccount++;
            }
        }
    }
    close($f);
}

sub getdocsvars {
    open(my $f, "<", "$root/../docs/cmdline-opts/write-out.md");
    while(<$f>) {
        if($_ =~ /^\#\# \`([^\`]*)\`/) {
            if($1 ne "header{name}" && $1 ne "output{filename}") {
                $indocs{$1} = 1;
            }
        }
    }
    close($f);
}

getsrcvars();
getdocsvars();

my $error = 0;

if((scalar(keys %indocs) < 10) || (scalar(keys %insrc) < 10)) {
    print "problems to extract variables\n";
    $error++;
}

# also verify that the source code lists them alphabetically
my $check = 1;
for(sort keys %insrc) {
    if($insrc{$_} && !$indocs{$_}) {
        print "$_ is not mentioned in write.out.md\n";
        $error++;
    }
    if($insrc{$_} ne $check) {
        print "$_ is not in alphabetical order\n";
        $error++;
    }
    $check++;
}

for(sort keys %indocs) {
    if($indocs{$_} && !$insrc{$_}) {
        print "$_ documented, but not used in source code\n";
        $error++;
    }
}

print "OK\n" if(!$error);

exit $error;
