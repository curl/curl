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
#
###########################################################################
#
# Check the OS/400 translating wrapper properly handles all translatable
# string options.

use strict;
use warnings;

my $root=$ARGV[0] || ".";
my $incdir = "$root/include/curl";
my $os400dir = "$root/packages/OS400";
my $errcount = 0;

# Scan header file for string option definitions.
sub scan_header {
    my ($f)=@_;
    my $line = "";
    my $incomment = 0;
    my @stringopts;

    open(my $h, "<", "$f");
    while(<$h>) {
        s/^\s*(.*?)\s*$/$1/;      # Trim.
        # Remove multi-line comment trail.
        if($incomment) {
            if($_ !~ /.*?\*\/\s*(.*)$/) {
                next;
            }
            $_ = $1;
            $incomment = 0;
        }
        if($line ne "") {
            # Unfold line.
            $_ = "$line $1";
            $line = "";
        }
        if($_ =~ /^(.*)\\$/) {
            $line = "$1 ";
            next;
        }
        # Remove comments.
        while($_ =~ /^(.*?)\/\*.*?\*\/(.*)$/) {
            $_ = "$1 $2";
        }
        if($_ =~ /^(.*)\/\*/) {
            $_ = "$1 ";
            $incomment = 1;
        }
        s/^\s*(.*?)\s*$/$1/;      # Trim again.
        # Ignore preprocessor directives and blank lines.
        if($_ =~ /^(?:#|$)/) {
            next;
        }
        # Handle lines that may be continued as if they were folded.
        if($_ !~ /[;,{}]$/ || $_ =~ /[^)],$/) {
            # Folded line.
            $line = $_;
            next;
        }
        # Keep string options only.
        if($_ =~ /CURLOPT(?:DEPRECATED)?\s*\(\s*([^, \t]+)\s*,\s*CURLOPTTYPE_STRINGPOINT/) {
            push(@stringopts, $1);
        }
    }
    close $h;
    return @stringopts;
}

# Scan packages/OS400/ccsidcurl.c for translatable string option cases.
sub scan_wrapper_for_strings {
    my ($f)=@_;
    my $inarmor = 0;
    my @stringopts;

    open(my $h, "<", "$f");
    while(<$h>) {
        if($_ =~ /(BEGIN|END) TRANSLATABLE STRING OPTIONS/) {
            $inarmor = $1 eq "BEGIN";
        }
        elsif($inarmor && $_ =~ /case\s+([^:]+):/) {
            push(@stringopts, $1);
        }
    }
    close $h;
    return @stringopts;
}

# Get translatable string options from header file.
my @stringdefs = scan_header("$incdir/curl.h");

# Get translated string options.
my @stringrefs = scan_wrapper_for_strings("$os400dir/ccsidcurl.c");

# Lists should be equal: check differences.
my %diff;
@diff{@stringdefs} = 0..$#stringdefs;
delete @diff{@stringrefs};

foreach(keys %diff) {
    print "$_ is not translated\n";
    delete $diff{$_};
    $errcount++;
}

@diff{@stringrefs} = 0..$#stringrefs;
delete @diff{@stringdefs};

foreach(keys %diff) {
    print "translated option $_ does not exist\n";
    $errcount++;
}

# Check translated string option cases are sorted alphanumerically.
foreach(my $i = 1; $i < $#stringrefs; $i++) {
    if($stringrefs[$i] lt $stringrefs[$i - 1]) {
        print("Translated string options are not sorted (" . $stringrefs[$i - 1] .
              "/" . $stringrefs[$i] . ")\n");
        $errcount++;
        last;
    }
}

exit !!$errcount;
