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
# Determine if fetch-config --protocols/--features matches the
# fetch --version protocols/features
if ( $#ARGV != 2 )
{
    print "Usage: $0 fetch-config-script fetch-version-output-file features|protocols\n";
    exit 3;
}

my $what=$ARGV[2];

# Read the output of fetch --version
my $fetch_protocols="";
open(FETCH, "$ARGV[1]") || die "Can't get fetch $what list\n";
while( <FETCH> )
{
    $fetch_protocols = $_ if ( /$what:/i );
}
close FETCH;

$fetch_protocols =~ s/\r//;
$fetch_protocols =~ /\w+: (.*)$/;
@fetch = split / /,$1;

# Read the output of fetch-config
my @fetch_config;
open(FETCHCONFIG, "sh $ARGV[0] --$what|") || die "Can't get fetch-config $what list\n";
while( <FETCHCONFIG> )
{
    chomp;
    $_ = lc($_) if($what eq "protocols");  # accept uppercase protocols in fetch-config
    push @fetch_config, $_;
}
close FETCHCONFIG;

# allow order mismatch to handle autotools builds with no 'sort -f' available
if($what eq "features") {
    @fetch = sort @fetch;
    @fetch_config = sort @fetch_config;
}

my $fetchproto = join ' ', @fetch;
my $fetchconfigproto = join ' ', @fetch_config;

my $different = $fetchproto ne $fetchconfigproto;
if ($different) {
    print "Mismatch in $what lists:\n";
    print "fetch:        $fetchproto\n";
    print "fetch-config: $fetchconfigproto\n";
}
exit $different;
