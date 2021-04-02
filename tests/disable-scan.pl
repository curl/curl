#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2010 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
#

use strict;
use warnings;

# the DISABLE options that can be set by configure
my %disable;
# the DISABLE options that are used in C files
my %file;
# the DISABLE options that are documented
my %docs;

# we may get the dir root pointed out
my $root=$ARGV[0] || ".";
my $DOCS="CURL-DISABLE.md";

sub scan_configure {
    open S, "<$root/configure.ac";
    while(<S>) {
        if(/(CURL_DISABLE_[A-Z_]+)/g) {
            my ($sym)=($1);
            $disable{$sym} = 1;
        }
    }
    close S;
}

sub scan_file {
    my ($source)=@_;
    open F, "<$source";
    while(<F>) {
        if(/(CURL_DISABLE_[A-Z_]+)/g) {
            my ($sym)=($1);
            $file{$sym} = $source;
        }
    }
    close F;
}

sub scan_dir {
    my ($dir)=@_;
    opendir(my $dh, $dir) || die "Can't opendir $dir: $!";
    my @cfiles = grep { /\.[ch]\z/ && -f "$dir/$_" } readdir($dh);
    closedir $dh;
    for my $f (sort @cfiles) {
        scan_file("$dir/$f");
    }
}

sub scan_sources {
    scan_dir("$root/src");
    scan_dir("$root/lib");
    scan_dir("$root/lib/vtls");
    scan_dir("$root/lib/vauth");
}

sub scan_docs {
    open F, "<$root/docs/$DOCS";
    my $line = 0;
    while(<F>) {
        $line++;
        if(/^## (CURL_DISABLE_[A-Z_]+)/g) {
            my ($sym)=($1);
            $docs{$sym} = $line;
        }
    }
    close F;
}

scan_configure();
scan_sources();
scan_docs();


my $error = 0;
# Check the configure symbols for use in code
for my $s (sort keys %disable) {
    if(!$file{$s}) {
        printf "Present in configure.ac, not used by code: %s\n", $s;
        $error++;
    }
    if(!$docs{$s}) {
        printf "Present in configure.ac, not documented in $DOCS: %s\n", $s;
        $error++;
    }
}

# Check the code symbols for use in configure
for my $s (sort keys %file) {
    if(!$disable{$s}) {
        printf "Not set by configure: %s (%s)\n", $s, $file{$s};
        $error++;
    }
    if(!$docs{$s}) {
        printf "Used in code, not documented in $DOCS: %s\n", $s;
        $error++;
    }
}

# Check the documented symbols
for my $s (sort keys %docs) {
    if(!$disable{$s}) {
        printf "Documented but not in configure: %s\n", $s;
        $error++;
    }
    if(!$file{$s}) {
        printf "Documented, but not used by code: %s\n", $s;
        $error++;
    }
}

exit $error;
