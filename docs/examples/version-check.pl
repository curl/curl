#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# This script accepts a source file as input on the command line.
#
# It first loads the 'symbols-in-versions' document and stores a lookup
# table for all known symbols for which version they were introduced.
#
# It then scans the given source file to dig up all symbols starting with CURL.
# Finally, it sorts the internal list of found symbols (using the version
# number as sort key) and then it outputs the most recent version number and
# the symbols from that version that are used.
#
# Usage:
#
#    version-check.pl [source file]
#

open(S, "<../libcurl/symbols-in-versions") || die;

my %doc;
my %rem;
while(<S>) {
    if(/(^CURL[^ \n]*) *(.*)/) {
        my ($sym, $rest)=($1, $2);
        my @a=split(/ +/, $rest);

        $doc{$sym}=$a[0]; # when it was introduced

        if($a[2]) {
            # this symbol is documented to have been present the last time
            # in this release
            $rem{$sym}=$a[2];
        }
    }

}

close(S);

sub age {
    my ($ver)=@_;

    my @s=split(/\./, $ver);
    return $s[0]*10000+$s[1]*100+$s[2];
}

my %used;
open(C, "<$ARGV[0]") || die;

while(<C>) {
    if(/\W(CURL[_A-Z0-9v]+)\W/) {
        #print "$1\n";
        $used{$1}++;
    }
}

close(C);

sub sortversions {
    my $r = age($doc{$a}) <=> age($doc{$b});
    if(!$r) {
        $r = $a cmp $b;
    }
    return $r;
}

my @recent = reverse sort sortversions keys %used;

# the most recent symbol
my $newsym = $recent[0];
# the most recent version
my $newver = $doc{$newsym}; 

print "The scanned source uses these symbols introduced in $newver:\n";

for my $w (@recent) {
    if($doc{$w} eq $newver) {
        printf "  $w\n";
        next;
    }
    last;
}


