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
# Determine if curl-config --version matches the curl --version
if ( $#ARGV != 2 )
{
    print "Usage: $0 curl-config-script curl-version-output-file version|vernum\n";
    exit 3;
}

my $what=$ARGV[2];

# Read the output of curl --version
open(CURL, "$ARGV[1]") || die "Can't open curl --version list in $ARGV[1]\n";
$_ = <CURL>;
chomp;
/libcurl\/([\.\d]+((-DEV)|(-rc\d)|(-\d+))?)/;
my $version = $1;
close CURL;

my $curlconfigversion;

# Read the output of curl-config --version/--vernum
open(CURLCONFIG, "sh $ARGV[0] --$what|") || die "Can't get curl-config --$what list\n";
$_ = <CURLCONFIG>;
chomp;
my $filever=$_;
if ( $what eq "version" ) {
    if($filever =~ /^libcurl ([\.\d]+((-DEV)|(-rc\d)|(-\d+))?)$/) {
        $curlconfigversion = $1;
    }
    else {
        $curlconfigversion = "illegal value";
    }
}
else { # "vernum" case
    # Convert hex version to decimal for comparison's sake
    if($filever =~ /^(..)(..)(..)$/) {
        $curlconfigversion = hex($1) . "." . hex($2) . "." . hex($3);
    }
    else {
        $curlconfigversion = "illegal value";
    }

    # Strip off the -DEV and -rc suffixes from the curl version if they're there
    $version =~ s/-\w*$//;
}
close CURLCONFIG;

my $different = $version ne $curlconfigversion;
if ($different || !$version) {
    print "Mismatch in --version:\n";
    print "curl:        $version\n";
    print "curl-config: $curlconfigversion\n";
    exit 1;
}
