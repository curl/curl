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

use Time::HiRes;

my $has_win32_process;

BEGIN {
    if($^O eq 'cygwin' || $^O eq 'msys') {
        $has_win32_process = eval {
            no warnings "all";
            # https://metacpan.org/pod/Win32::Process
            require Win32::Process;
            # https://metacpan.org/pod/Win32::Process::List
            require Win32::Process::List;
        };
    } else {
      $has_win32_process = 0;
    }
}

if($has_win32_process) {
  print "!!! Win32::Process* modules loaded\n";
} else {
  print "!!! Win32::Process* modules NOT loaded\n";
}
