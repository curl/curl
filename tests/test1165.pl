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
#

use strict;
use warnings;

# the DISABLE options that can be set by configure
my %disable;
# the DISABLE options that can be set by CMakeLists.txt
my %disable_cmake;
# the DISABLE options propagated via curl_config.h.cmake
my %disable_cmake_config_h;
# the DISABLE options that are used in C files
my %file;
# the DISABLE options that are documented
my %docs;

# we may get the dir root pointed out
my $root=$ARGV[0] || ".";
my $DOCS="CURL-DISABLE.md";

sub scanconf {
    my ($f)=@_;
    open S, "<$f";
    while(<S>) {
        if(/(CURL_DISABLE_[A-Z0-9_]+)/g) {
            my ($sym)=($1);
            $disable{$sym} = 1;
        }
    }
    close S;
}

sub scan_configure {
    opendir(my $m, "$root/m4") || die "Can't opendir $root/m4: $!";
    my @m4 = grep { /\.m4$/ } readdir($m);
    closedir $m;
    scanconf("$root/configure.ac");
    # scan all m4 files too
    for my $e (@m4) {
        scanconf("$root/m4/$e");
    }
}

sub scanconf_cmake {
    my ($hashr, $f)=@_;
    open S, "<$f";
    while(<S>) {
        if(/(CURL_DISABLE_[A-Z0-9_]+)/g) {
            my ($sym)=($1);
            if(not $sym =~ /^(CURL_DISABLE_INSTALL|CURL_DISABLE_TESTS|CURL_DISABLE_SRP)$/) {
                $hashr->{$sym} = 1;
            }
        }
    }
    close S;
}

sub scan_cmake {
    scanconf_cmake(\%disable_cmake, "$root/CMakeLists.txt");
}

sub scan_cmake_config_h {
    scanconf_cmake(\%disable_cmake_config_h, "$root/lib/curl_config.h.cmake");
}

my %whitelisted = ("CURL_DISABLE_TYPECHECK" => 1);

sub scan_file {
    my ($source)=@_;
    open F, "<$source";
    while(<F>) {
        while(s/(CURL_DISABLE_[A-Z0-9_]+)//) {
            my ($sym)=($1);

            if(!$whitelisted{$sym}) {
                $file{$sym} = $source;
            }
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
        if(/^## `(CURL_DISABLE_[A-Z0-9_]+)`/g) {
            my ($sym)=($1);
            $docs{$sym} = $line;
        }
    }
    close F;
}

scan_configure();
scan_cmake();
scan_cmake_config_h();
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

# Check the CMakeLists.txt symbols for use in code
for my $s (sort keys %disable_cmake) {
    if(!$file{$s}) {
        printf "Present in CMakeLists.txt, not used by code: %s\n", $s;
        $error++;
    }
    if(!$docs{$s}) {
        printf "Present in CMakeLists.txt, not documented in $DOCS: %s\n", $s;
        $error++;
    }
}

# Check the CMakeLists.txt symbols for use in curl_config.h.cmake
for my $s (sort keys %disable_cmake) {
    if(!$disable_cmake_config_h{$s}) {
        printf "Present in CMakeLists.txt, not propagated via curl_config.h.cmake: %s\n", $s;
        $error++;
    }
}

# Check the code symbols for use in configure
for my $s (sort keys %file) {
    if(!$disable{$s}) {
        printf "Not set by configure: %s (%s)\n", $s, $file{$s};
        $error++;
    }
    if(!$disable_cmake{$s}) {
        printf "Not set by CMakeLists.txt: %s (%s)\n", $s, $file{$s};
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
    if(!$disable_cmake{$s}) {
        printf "Documented but not in CMakeLists.txt: %s\n", $s;
        $error++;
    }
    if(!$file{$s}) {
        printf "Documented, but not used by code: %s\n", $s;
        $error++;
    }
}

exit $error;
