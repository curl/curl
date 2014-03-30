#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

use strict;

push(@INC, $ENV{'srcdir'}) if(defined $ENV{'srcdir'});
push(@INC, ".");

require "getpart.pm"; # array functions

my $srcdir = $ENV{'srcdir'} || '.';
my $TESTDIR="$srcdir/data";

# Get all commands and find out their test numbers
opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
my @cmds = grep { /^test([0-9]+)$/ && -f "$TESTDIR/$_" } readdir(DIR);
closedir DIR;

my $TESTCASES; # start with no test cases

# cut off everything but the digits
for(@cmds) {
    $_ =~ s/[a-z\/\.]*//g;
}
# the the numbers from low to high
for(sort { $a <=> $b } @cmds) {
    $TESTCASES .= " $_";
}

my $t;

my %k; # keyword count
my %t; # keyword to test case mapping
my @miss; # test cases without keywords set

my $count;

my %errors;

for $t (split(/ /, $TESTCASES)) {
    if(loadtest("${TESTDIR}/test${t}")) {
        # bad case
        next;
    }

    my @ec = getpart("verify", "errorcode");
    if($ec[0]) {
        # count number of check error codes
        $errors{ 0 + $ec[0] } ++;
    }


    my @what = getpart("info", "keywords");

    if(!$what[0]) {
        push @miss, $t;
        next;
    }

    for(@what) {
        chomp;
        #print "Test $t: $_\n";
        $k{$_}++;
        $t{$_} .= "$t ";
    }








    $count++;
}

sub show {
    my ($list)=@_;
    my @a = split(" ", $list);
    my $ret;

    my $c;
    my @l = sort {rand(100) - 50} @a;
    my @ll;

    for(1 .. 11) {
        my $v = shift @l;
        if($v) {
            push @ll, $v;
        }
    }

    for (sort {$a <=> $b} @ll) {
        if($c++ == 10) {
            $ret .= "...";
            last;
        }
        $ret .= "$_ ";
    }
    return $ret;
}

# sort alphabetically 
my @mtest = reverse sort { lc($b) cmp lc($a) } keys %k;

print <<TOP
<table><tr><th>Num</th><th>Keyword</th><th>Test Cases</th></tr>
TOP
    ;
for $t (@mtest) {
    printf "<tr><td>%d</td><td>$t</td><td>%s</td></tr>\n", $k{$t},
    show($t{$t});
}
printf "</table><p> $count out of %d tests (%d lack keywords)\n",
    scalar(@miss) + $count,
    scalar(@miss);

for(@miss) {
    print "$_ ";
}

print "\n";

printf "<p> %d different error codes tested for:<br>\n",
    scalar(keys %errors);

# numerically on amount, or alphebetically if same amount
my @etest = sort { $a <=> $b} keys %errors;

for(@etest) {
    print "$_ ";
}
print "\n";
