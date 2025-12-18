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

# Perform simple file and directory manipulation in a portable way
if($#ARGV <= 0) {
    print "Usage: $0 mkdir|rmdir|rm|move|gone path1 [path2] [more commands...]\n";
    exit 1;
}

use File::Copy;
while(@ARGV) {
    my $cmd = shift @ARGV;
    my $arg = shift @ARGV;
    if($cmd eq "mkdir") {
        mkdir $arg || die "$!";
    }
    elsif($cmd eq "rmdir") {
        rmdir $arg || die "$!";
    }
    elsif($cmd eq "rm") {
        unlink $arg || die "$!";
    }
    elsif($cmd eq "move") {
        my $arg2 = shift @ARGV;
        move($arg,$arg2) || die "$!";
    }
    elsif($cmd eq "gone") {
        ! -e $arg || die "Path $arg exists";
    } else {
        print "Unsupported command $cmd\n";
        exit 1;
    }
}
exit 0;
