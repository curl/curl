#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats
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

use strict;
use warnings;

my @tabs = (
    "^m4/zz40-xc-ovr.m4",
    "Makefile\\.(am|example)\$",
    "/mkfile",
    "\\.(sln|vc)\$",
    "^tests/data/test",
);

my @mixed_eol = (
    "^tests/data/test",
);

my @need_crlf = (
    "\\.(bat|sln)\$",
    "^winbuild/.+\\.md\$",
);

my @space_at_eol = (
    "^tests/data/test",
);

my @non_ascii_allowed = (
    '\xC3\xB6',  # UTF-8 for https://codepoints.net/U+00F6 LATIN SMALL LETTER O WITH DIAERESIS
);

my $non_ascii_allowed = join(', ', @non_ascii_allowed);

my @non_ascii = (
    ".github/scripts/spellcheck.words",
    ".mailmap",
    "RELEASE-NOTES",
    "docs/BINDINGS.md",
    "docs/THANKS",
    "docs/THANKS-filter",
);

sub fn_match {
    my ($filename, @masklist) = @_;

    foreach my $mask (@masklist) {
        if($filename =~ $mask) {
            return 1;
        }
    }
    return 0;
}

sub eol_detect {
    my ($content) = @_;

    my $cr = () = $content =~ /\r/g;
    my $lf = () = $content =~ /\n/g;

    if($cr > 0 && $lf == 0) {
        return "cr";
    }
    elsif($cr == 0 && $lf > 0) {
        return "lf";
    }
    elsif($cr == 0 && $lf == 0) {
        return "bin";
    }
    elsif($cr == $lf) {
        return "crlf";
    }

    return "";
}

my $issues = 0;

open my $git_ls_files, '-|', 'git ls-files' or die "Failed running git ls-files: $!";
while(my $filename = <$git_ls_files>) {
    chomp $filename;

    open my $fh, '<', $filename or die "Cannot open '$filename': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    my @err = ();

    if(!fn_match($filename, @tabs) &&
        $content =~ /\t/) {
        push @err, "content: has tab";
    }

    my $eol = eol_detect($content);

    if($eol eq "" &&
        !fn_match($filename, @mixed_eol)) {
        push @err, "content: has mixed EOL types";
    }

    if($eol ne "crlf" &&
        fn_match($filename, @need_crlf)) {
        push @err, "content: must use CRLF EOL for this file type";
    }

    if($eol ne "lf" && $content ne "" &&
        !fn_match($filename, @need_crlf) &&
        !fn_match($filename, @mixed_eol)) {
        push @err, "content: must use LF EOL for this file type";
    }

    if(!fn_match($filename, @space_at_eol) &&
       $content =~ /[ \t]\n/) {
        my $line;
        for my $l (split(/\n/, $content)) {
            $line++;
            if($l =~ /[ \t]$/) {
                push @err, "line $line: trailing whitespace";
            }
        }
    }

    if($content ne "" &&
        $content !~ /\n\z/) {
        push @err, "content: has no EOL at EOF";
    }

    if($content =~ /\n\n\z/ ||
        $content =~ /\r\n\r\n\z/) {
        push @err, "content: has multiple EOL at EOF";
    }

    if($content =~ /\n\n\n\n/ ||
        $content =~ /\r\n\r\n\r\n\r\n/) {
        push @err, "content: has 3 or more consecutive empty lines";
    }

    if($content =~ /([\x00-\x08\x0b\x0c\x0e-\x1f\x7f])/) {
        push @err, "content: has binary contents";
    }

    if($filename !~ /tests\/data/) {
        # the tests have no allowed UTF bytes
        $content =~ s/[$non_ascii_allowed]//g;
    }

    if(!fn_match($filename, @non_ascii) &&
       ($content =~ /([\x80-\xff]+)/)) {
        my $non = $1;
        my $hex;
        for my $e (split(//, $non)) {
            $hex .= sprintf("%s%02x", $hex ? " ": "", ord($e));
        }
        my $line;
        for my $l (split(/\n/, $content)) {
            $line++;
            if($l =~ /([\x80-\xff]+)/) {
                push @err, "line $line: has non-ASCII: '$non' ($hex)";
            }
        }
    }

    if(@err) {
        $issues++;
        foreach my $err (@err) {
            print "$filename: $err\n";
        }
    }
}
close $git_ls_files;

if($issues) {
    exit 1;
}
