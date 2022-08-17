#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Invoke script in the root of the git checkout. Scans all files in git unless
# given a specific single file.
#
# Usage: copyright.pl [file]
#

my %skips;

# file names
my %skiplist = (
    # REUSE-specific file
    ".reuse/dep5" => "<built-in>",

    # License texts
    "LICENSES/BSD-3-Clause.txt" => "<built-in>",
    "LICENSES/BSD-4-Clause-UC.txt" => "<built-in>",
    "LICENSES/ISC.txt" => "<built-in>",
    "LICENSES/curl.txt" => "<built-in>",
    "COPYING" => "<built-in>",

    # imported, leave be
    'm4/ax_compile_check_sizeof.m4' => "<built-in>",

    # an empty control file
    "zuul.d/playbooks/.zuul.ignore" => "<built-in>",
    );

sub scanfile {
    my ($f) = @_;
    my $line=1;
    my $found = 0;
    open(F, "<$f") || return -1;
    while (<F>) {
        chomp;
        my $l = $_;
        # check for a copyright statement and save the years
        if($l =~ /.* ?copyright .* *\d\d\d\d/i) {
            while($l =~ /([\d]{4})/g) {
                push @copyright, {
                  year => $1,
                  line => $line,
                  col => index($l, $1),
                  code => $l
                };
                $found++;
            }
        }
        if($l =~ /SPDX-License-Identifier:/) {
            $spdx = 1;
        }
        # allow within the first 100 lines
        if(++$line > 100) {
            last;
        }
    }
    close(F);
    return $found;
}

sub checkfile {
    my ($file, $skipped, $pattern) = @_;
    my $fine = 0;
    @copyright=();
    $spdx = 0;
    my $found = scanfile($file);

    if($found < 1) {
        if($skipped) {
            # just move on
            $skips{$pattern}++;
            return 0;
        }
        if(!$found) {
            print "$file:1: missing copyright range\n";
            return 2;
        }
        # this means the file couldn't open - it might not exist, consider
        # that fine
        return 1;
    }
    if(!$spdx) {
        if($skipped) {
            # move on
            $skips{$pattern}++;
            return 0;
        }
        print "$file:1: missing SPDX-License-Identifier\n";
        return 2;
    }

    my $commityear = undef;
    @copyright = sort {$$b{year} cmp $$a{year}} @copyright;

    # if the file is modified, assume commit year this year
    if(`git status -s -- $file` =~ /^ [MARCU]/) {
        $commityear = (localtime(time))[5] + 1900;
    }
    else {
        # min-parents=1 to ignore wrong initial commit in truncated repos
        my $grl = `git rev-list --max-count=1 --min-parents=1 --timestamp HEAD -- $file`;
        if($grl) {
            chomp $grl;
            $commityear = (localtime((split(/ /, $grl))[0]))[5] + 1900;
        }
    }

    if(defined($commityear) && scalar(@copyright) &&
       $copyright[0]{year} != $commityear) {
        printf "$file:%d: copyright year out of date, should be $commityear, " .
            "is $copyright[0]{year}\n",
            $copyright[0]{line} if(!$skipped || $verbose);
        $skips{$pattern}++ if($skipped);
    }
    else {
        $fine = 1;
    }
    if($skipped && $fine) {
        print "$file:1: ignored superfluously by $pattern\n" if($verbose);
        $superf{$pattern}++;
    }

    return $fine;
}

sub dep5 {
    my ($file) = @_;
    my @files;
    my $copy;
    open(F, "<$file") || die "can't open $file";
    my $line = 0;
    while(<F>) {
        $line++;
        if(/^Files: (.*)/i) {
            push @files, `git ls-files $1`;
        }
        elsif(/^Copyright: (.*)/i) {
            $copy = $1;
        }
        elsif(/^License: (.*)/i) {
            my $license = $1;
            for my $f (@files) {
                chomp $f;
                if($f =~ /\.gitignore\z/) {
                    # ignore .gitignore
                }
                else {
                    if($skiplist{$f}) {
                        print STDERR "$f already skipped at $skiplist{$f}\n";
                    }
                    $skiplist{$f} = "dep5:$line";
                }
            }
            undef @files;
        }
    }
    close(F);
}

dep5(".reuse/dep5");

my @all;
my $verbose;
if($ARGV[0] eq "-v") {
    $verbose = 1;
    shift @ARGV;
}
if($ARGV[0]) {
    push @all, @ARGV;
}
else {
    @all = `git ls-files`;
}

for my $f (@all) {
    chomp $f;
    my $skipped = 0;
    my $miss;
    my $wro;
    my $pattern;
    if($skiplist{$f}) {
        $pattern = $skip;
        $skiplisted++;
        $skipped = 1;
    }

    my $r = checkfile($f, $skipped, $pattern);
    $mis=1 if($r == 2);
    $wro=1 if(!$r);

    if(!$skipped) {
        $missing += $mis;
        $wrong += $wro;
    }
}

if($verbose) {
    print STDERR "$missing files have no copyright\n" if($missing);
    print STDERR "$wrong files have wrong copyright year\n" if ($wrong);
    print STDERR "$skiplisted files are skipped\n" if ($skiplisted);

    for my $s (@skiplist) {
        if(!$skips{$s}) {
            printf ("Never skipped pattern: %s\n", $s);
        }
        if($superf{$s}) {
            printf ("%s was skipped superfluously %u times and legitimately %u times\n",
                    $s, $superf{$s}, $skips{$s});
        }
    }
}

exit 1 if($missing || $wrong);
