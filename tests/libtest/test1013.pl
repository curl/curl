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
# Determine if curl-config --protocols/--features matches the
# curl --version protocols/features
if ( $#ARGV != 2 )
{
    print "Usage: $0 curl-config-script curl-version-output-file features|protocols\n";
    exit 3;
}

my $what=$ARGV[2];

# Read the output of curl --version
my $curl_protocols="";
open(CURL, "$ARGV[1]") || die "Can't get curl $what list\n";
while( <CURL> )
{
    $curl_protocols = lc($_) if ( /$what:/i );
}
close CURL;

$curl_protocols =~ s/\r//;
$curl_protocols =~ /\w+: (.*)$/;
@curl = split / /,$1;
@curl = sort @curl;

# Read the output of curl-config
my @curl_config;
open(CURLCONFIG, "sh $ARGV[0] --$what|") || die "Can't get curl-config $what list\n";
while( <CURLCONFIG> )
{
    chomp;
    # ignore curl-config --features not in curl's feature list
    push @curl_config, lc($_);
}
close CURLCONFIG;

@curl_config = sort @curl_config;

my $curlproto = join ' ', @curl;
my $curlconfigproto = join ' ', @curl_config;

my $different = $curlproto ne $curlconfigproto;
if ($different) {
    print "Mismatch in $what lists:\n";
    print "curl:        $curlproto\n";
    print "curl-config: $curlconfigproto\n";
}
exit $different;
