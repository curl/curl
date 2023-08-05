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

# git log --pretty=fuller --no-color --date=short --decorate=full

my @mname = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' );

sub nicedate {
    my ($date)=$_;

    if($date =~ /(\d\d\d\d)-(\d\d)-(\d\d)/) {
        return sprintf("%d %s %4d", $3, $mname[$2-1], $1);
    }
    return $date;
}

sub printmsg {
    my ($p, $msg)=@_;
    while(length($msg) > 77) {
        print $p.substr($msg, 0, 77, "")."\n";
        $p="  ";
    }
    if($msg eq "") {
        $p = "";
    }
    print "$p$msg\n";
}

print
'                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

                                  Changelog
';

my $tag;
while(<STDIN>) {
    my $l = $_;

    if($l =~/^commit ([[:xdigit:]]*) ?(.*)/) {
        $co = $1;
        my $ref = $2;
        if ($ref =~ /refs\/tags\/curl-([0-9_]*)/) {
            $tag = $1;
            $tag =~ tr/_/./;
        }
    }
    elsif($l =~ /^Author: *(.*) +</) {
        $c = $1;
    }
    elsif($l =~ /^CommitDate: (.*)/) {
        $date = nicedate($1);
    }
    elsif($l =~ /^(    )(.*)/) {
        my $pref = "  ";
        if ($tag) {
            # Version entries have a special format
            print "\nVersion " . $tag." ($date)\n";
            $oldc = "";
            $tag = "";
        }
        if($co ne $oldco) {
            if($c ne $oldc) {
                print "\n$c ($date)\n\n";
            }
            else {
                print "\n";
            }
            $pref = "- ";
        }

        $oldco = $co;
        $oldc = $c;
        $olddate = $date;
        printmsg($pref, $2);
    }
}
