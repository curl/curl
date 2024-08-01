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

# This scripts scans the entire git repository for binary files.
#
# All files in the git repo that contain signs of being binary are then
# collected and a sha256sum is generated for all of them. That summary is then
# compared to the list of pre-vetted files so that only the exact copies of
# already scrutinized files are deemed okay to "appear binary".
#

use strict;
use warnings;

my $root = ".";
my $sumsfile = ".github/scripts/binarycheck.sums";
if($ARGV[0]) {
    $root = $ARGV[0];
}

my @bin;
my %known;
my $error = 0;

sub knownbins {
    open(my $mh, "<", "$sumsfile") ||
        die "can't read known binaries";
    while(<$mh>) {
        my $l = $_;
        chomp $l;
        if($l =~ /^([a-f0-9]+)  (.*)/) {
            my ($sum, $file) = ($1, $2);
            $known{$file} = 1;
        }
        elsif($l =~ /^#/) {
            # skip comments
        }
        else {
            print STDERR "suspicious line in $sumsfile\n";
            $error++;
        }
    }
    close($mh);
}

sub checkfile {
    my ($file) = @_;
    open(my $mh, "<", "$file") || die "can't read $file";
    my $line = 0;
    while(<$mh>) {
        my $l = $_;
        $line++;
        if($l =~ /([\x00-\x08\x0b\x0c\x0e-\x1f\x7f])/) {
            push @bin, $file;

            if(!$known{$file}) {
                printf STDERR "$file:$line has unknown binary contents\n";
                $error++;
            }
            last;
        }
    }
    close($mh);
}

my @files = `git ls-files -- $root`;

if(scalar(@files) < 3000) {
    # this means this is not the git source code repository or that git does
    # not work, error out!
    print STDERR "too few files in the git repository!\n";
    exit 1;
}

knownbins();

if(scalar(keys %known) < 10) {
    print STDERR "too few known binaries in $sumsfile\n";
    exit 2;
}

for my $f (@files) {
    chomp $f;
    checkfile("$root/$f");
}

my $check=system("sha256sum -c $sumsfile");
if($check) {
    print STDERR "sha256sum detected a problem\n";
    $error++;
}

exit $error;
