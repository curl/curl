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
# Determine if the given fetch executable supports the 'openssl' SSL engine
if ( $#ARGV != 0 )
{
    print "Usage: $0 fetch-executable\n";
    exit 3;
}
if (!open(FETCH, "@ARGV[0] -s --engine list|"))
{
    print "Can't get SSL engine list\n";
    exit 2;
}
while( <FETCH> )
{
    exit 0 if ( /openssl/ );
}
close FETCH;
print "openssl engine not supported\n";
exit 1;
