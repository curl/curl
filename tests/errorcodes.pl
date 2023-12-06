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

# Check that libcurl-errors.3 and the public header files have the same set of
# error codes.

use strict;
use warnings;

# we may get the dir roots pointed out
my $root=$ARGV[0] || ".";
my $manpge = "$root/docs/libcurl/libcurl-errors.3";
my $curlh = "$root/include/curl";
my $errors=0;

my @hnames;
my %wherefrom;
my @mnames;
my %manfrom;

sub scanheader {
    my ($file)=@_;
    open H, "<$file";
    my $line = 0;
    while(<H>) {
        $line++;
        if($_ =~ /^  (CURL(E|UE|SHE|HE|M)_[A-Z0-9_]*)/) {
            my ($name)=($1);
            if(($name !~ /OBSOLETE/) && ($name !~ /_LAST\z/)) {
                push @hnames, $name;
                if($wherefrom{$name}) {
                    print STDERR "double: $name\n";
                }
                $wherefrom{$name}="$file:$line";
            }
        }
    }
    close(H);
}

sub scanmanpage {
    my ($file)=@_;
    open H, "<$file";
    my $line = 0;
    while(<H>) {
        $line++;
        if($_ =~ /^\.IP \"(CURL(E|UE|SHE|HE|M)_[A-Z0-9_]*)/) {
            my ($name)=($1);
            push @mnames, $name;
            $manfrom{$name}="$file:$line";
        }
    }
    close(H);
}


opendir(my $dh, $curlh) || die "Can't opendir $curlh: $!";
my @hfiles = grep { /\.h$/ } readdir($dh);
closedir $dh;

for(sort @hfiles) {
    scanheader("$curlh/$_");
}
scanmanpage($manpge);

print "Result\n";
for my $h (sort @hnames) {
    if(!$manfrom{$h}) {
        printf "$h from %s, not in man page\n", $wherefrom{$h};
    }
}

for my $m (sort @mnames) {
    if(!$wherefrom{$m}) {
        printf "$m from %s, not in any header\n", $manfrom{$m};
    }
}
