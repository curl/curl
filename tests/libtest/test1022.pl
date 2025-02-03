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
# are also available at https://curl.se/docs/copyright.html.
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
# Determine if fetch-config --version matches the fetch --version
if ( $#ARGV != 2 )
{
    print "Usage: $0 fetch-config-script fetch-version-output-file version|vernum\n";
    exit 3;
}

my $what=$ARGV[2];

# Read the output of fetch --version
open(FETCH, "$ARGV[1]") || die "Can't open fetch --version list in $ARGV[1]\n";
$_ = <FETCH>;
chomp;
/libfetch\/([\.\d]+((-DEV)|(-\d+))?)/;
my $version = $1;
close FETCH;

my $fetchconfigversion;

# Read the output of fetch-config --version/--vernum
open(FETCHCONFIG, "sh $ARGV[0] --$what|") || die "Can't get fetch-config --$what list\n";
$_ = <FETCHCONFIG>;
chomp;
my $filever=$_;
if ( $what eq "version" ) {
    if($filever =~ /^libfetch ([\.\d]+((-DEV)|(-\d+))?)$/) {
        $fetchconfigversion = $1;
    }
    else {
        $fetchconfigversion = "illegal value";
    }
}
else { # "vernum" case
    # Convert hex version to decimal for comparison's sake
    if($filever =~ /^(..)(..)(..)$/) {
        $fetchconfigversion = hex($1) . "." . hex($2) . "." . hex($3);
    }
    else {
        $fetchconfigversion = "illegal value";
    }

    # Strip off the -DEV from the fetch version if it's there
    $version =~ s/-\w*$//;
}
close FETCHCONFIG;

my $different = $version ne $fetchconfigversion;
if ($different || !$version) {
    print "Mismatch in --version:\n";
    print "fetch:        $version\n";
    print "fetch-config: $fetchconfigversion\n";
    exit 1;
}
