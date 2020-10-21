#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

###############################################
#
# ==== How to use this script ====
#
# 1. Get recent commits added to RELEASE-NOTES:
#
# $ ./scripts/release-notes.pl
#
# 2. Edit RELEASE-NOTES and remove all entries that don't belong.  Unused
# references below will be cleaned up in the next step. Make sure to move
# "changes" up to the changes section. All entries will by default be listed
# under bug-fixes as this script can't know where to put them.
#
# 3. Run the cleanup script and let it sort the entries and remove unused
# references from lines you removed in step (2):
#
# $ ./script/release-notes.pl cleanup
#
# 4. Reload RELEASE-NOTES and verify that things look okay. The cleanup
# procedure can and should be re-run when lines are removed or rephrased.
#
# 5. Run ./scripts/contributors.sh and update the contributor list of names
# The list can also be extended or edited manually.
#
# 6. Run ./scripts/delta and update the contributor count at the top, and
# double-check/update the other counters.
#
# 7. Commit the file using "RELEASE-NOTES: synced" as commit message.
#
################################################

my $cleanup = ($ARGV[0] eq "cleanup");
my @gitlog=`git log @^{/RELEASE-NOTES:.synced}..` if(!$cleanup);
my @releasenotes=`cat RELEASE-NOTES`;

my @o; # the entire new RELEASE-NOTES
my @refused; # [num] = [2 bits of use info]
my @refs; # [number] = [URL]
for my $l (@releasenotes) {
    if($l =~ /^ o .*\[(\d+)\]/) {
        # referenced, set bit 0
        $refused[$1]=1;
    }
    elsif($l =~ /^ \[(\d+)\] = (.*)/) {
        # listed in a reference, set bit 1
        $refused[$1] |= 2;
        $refs[$1] = $2;
    }
}

# Return a new fresh reference number
sub getref {
    for my $r (1 .. $#refs) {
        if(!$refused[$r] & 1) {
            return $r;
        }
    }
    # add at the end
    return $#refs + 1;
}

my $short;
my $first;
for my $l (@gitlog) {
    chomp $l;
    if($l =~ /^commit/) {
        if($first) {
            onecommit($short);
        }
        # starts a new commit
        undef @fixes;
        undef @closes;
        undef @bug;
        $short = "";
        $first = 0;
    }
    elsif(($l =~ /^    (.*)/) && !$first) {
        # first line
        $short = $1;
        $first = 1;
        push @line, $short;
    }
    elsif(($l =~ /^    (.*)/) && $first) {
        # not the first
        my $line = $1;

        if($line =~ /^Fixes(:|) .*[^0-9](\d+)/i) {
            push @fixes, $2;
        }
        elsif($line =~ /^Closes(:|) .*[^0-9](\d+)/i) {
            push @closes, $2;
        }
        elsif($line =~ /^Bug: (.*)/i) {
            push @bug, $1;
        }
    }
}
if($first) {
    onecommit($short);
}

# call at the end of a parsed commit
sub onecommit {
    my ($short)=@_;
    my $ref;

    if($bug[0]) {
        $ref = $bug[0];
    }
    elsif($fixes[0]) {
        $ref = $fixes[0];
    }
    elsif($closes[0]) {
        $ref = $closes[0];
    }

    if($ref =~ /^(\d+)/) {
        $ref = "https://curl.haxx.se/bug/?i=$1"
    }
    if($ref) {
        my $r = getref();
        $refs[$r] = $ref;
        $moreinfo{$short}=$r;
        $refused[$r] |= 1;
    }
}

#### Output the new RELEASE-NOTES

my @bullets;
for my $l (@releasenotes) {
    if(($l =~ /^This release includes the following bugfixes:/) && !$cleanup) {
        push @o, $l;
        push @o, "\n";
        for my $f (@line) {
            push @o, sprintf " o %s%s\n", $f,
                $moreinfo{$f}? sprintf(" [%d]", $moreinfo{$f}): "";
            $refused[$moreinfo{$f}]=3;
        }
        push @o, " --- new entries are listed above this ---";
        next;
    }
    elsif($cleanup) {
        if($l =~ /^ --- new entries are listed/) {
            # ignore this if still around
            next;
        }
        elsif($l =~ /^ o .*/) {
            push @bullets, $l;
            next;
        }
        elsif($bullets[0]) {
            # output them case insensitively
            for my $b (sort { "\L$a" cmp "\L$b" } @bullets) {
                push @o, $b;
            }
            undef @bullets;
        }
    }
    if($l =~ /^ \[(\d+)\] = /) {
        # stop now
        last;
    }
    else {
        push @o, $l;
    }
}

my @srefs;
my $ln;
for my $n (1 .. $#refs) {
    my $r = $refs[$n];
    if($r && ($refused[$n] & 1)) {
        push @o, sprintf " [%d] = %s\n", $n, $r;
    }
}

open(O, ">RELEASE-NOTES");
for my $l (@o) {
    print O $l;
}
close(O);

exit;

# Debug: show unused references
for my $r (1 .. $#refs) {
    if($refused[$r] != 3) {
        printf "%s is %d!\n", $r, $refused[$r];
    }
}
