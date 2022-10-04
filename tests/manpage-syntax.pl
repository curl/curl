#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2019 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Scan man page(s) and detect some simple and yet common formatting mistakes.
#
# Output all deviances to stderr.

use strict;
use warnings;

# get the file name first
my $symbolsinversions=shift @ARGV;

# we may get the dir roots pointed out
my @manpages=@ARGV;
my $errors = 0;

my %optblessed;
my %funcblessed;
my @optorder = (
    'NAME',
    'SYNOPSIS',
    'DESCRIPTION',
     #'DEFAULT', # CURLINFO_ has no default
    'PROTOCOLS',
    'EXAMPLE',
    'AVAILABILITY',
    'RETURN VALUE',
    'SEE ALSO'
    );
my @funcorder = (
    'NAME',
    'SYNOPSIS',
    'DESCRIPTION',
    'EXAMPLE',
    'AVAILABILITY',
    'RETURN VALUE',
    'SEE ALSO'
    );
my %shline; # section => line number

my %symbol;

# some CURLINFO_ symbols are not actual options for curl_easy_getinfo,
# mark them as "deprecated" to hide them from link-warnings
my %deprecated = (
    CURLINFO_TEXT => 1,
    CURLINFO_HEADER_IN => 1,
    CURLINFO_HEADER_OUT => 1,
    CURLINFO_DATA_IN => 1,
    CURLINFO_DATA_OUT => 1,
    CURLINFO_SSL_DATA_IN => 1,
    CURLINFO_SSL_DATA_OUT => 1,
    );
sub allsymbols {
    open(F, "<$symbolsinversions") ||
        die "$symbolsinversions: $|";
    while(<F>) {
        if($_ =~ /^([^ ]*) +(.*)/) {
            my ($name, $info) = ($1, $2);
            $symbol{$name}=$name;

            if($info =~ /([0-9.]+) +([0-9.]+)/) {
                $deprecated{$name}=$info;
            }
        }
    }
    close(F);
}

sub scanmanpage {
    my ($file) = @_;
    my $reqex = 0;
    my $inex = 0;
    my $insynop = 0;
    my $exsize = 0;
    my $synopsize = 0;
    my $shc = 0;
    my $optpage = 0; # option or function
    my @sh;
    my $SH="";

    open(M, "<$file") || die "no such file: $file";
    if($file =~ /[\/\\](CURL|curl_)[^\/\\]*.3/) {
        # This is a man page for libcurl. It requires an example!
        $reqex = 1;
        if($1 eq "CURL") {
            $optpage = 1;
        }
    }
    my $line = 1;
    while(<M>) {
        chomp;
        if($_ =~ /^.so /) {
            # this man page is just a referral
            close(M);
            return;
        }
        if(($_ =~ /^\.SH SYNOPSIS/i) && ($reqex)) {
            # this is for libcurl man page SYNOPSIS checks
            $insynop = 1;
            $inex = 0;
        }
        elsif($_ =~ /^\.SH EXAMPLE/i) {
            $insynop = 0;
            $inex = 1;
        }
        elsif($_ =~ /^\.SH/i) {
            $insynop = 0;
            $inex = 0;
        }
        elsif($inex)  {
            $exsize++;
            if($_ =~ /[^\\]\\n/) {
                print STDERR "$file:$line '\\n' need to be '\\\\n'!\n";
            }
        }
        elsif($insynop)  {
            $synopsize++;
            if(($synopsize == 1) && ($_ !~ /\.nf/)) {
                print STDERR "$file:$line:1:ERROR: be .nf for proper formatting\n";
            }
        }
        if($_ =~ /^\.SH ([^\r\n]*)/i) {
            my $n = $1;
            # remove enclosing quotes
            $n =~ s/\"(.*)\"\z/$1/;
            push @sh, $n;
            $shline{$n} = $line;
            $SH = $n;
        }

        if($_ =~ /^\'/) {
            print STDERR "$file:$line line starts with single quote!\n";
            $errors++;
        }
        if($_ =~ /\\f([BI])(.*)/) {
            my ($format, $rest) = ($1, $2);
            if($rest !~ /\\fP/) {
                print STDERR "$file:$line missing \\f${format} terminator!\n";
                $errors++;
            }
        }
        if($_ =~ /(.*)\\f([^BIP])/) {
            my ($pre, $format) = ($1, $2);
            if($pre !~ /\\\z/) {
                # only if there wasn't another backslash before the \f
                print STDERR "$file:$line suspicious \\f format!\n";
                $errors++;
            }
        }
        if($optpage && $SH && ($SH !~ /^(SYNOPSIS|EXAMPLE|NAME|SEE ALSO)/i) &&
           ($_ =~ /(.*)(CURL(OPT_|MOPT_|INFO_)[A-Z0-9_]*)/)) {
            # an option with its own man page, check that it is tagged
            # for linking
            my ($pref, $symbol) = ($1, $2);
            if($deprecated{$symbol}) {
                # let it be
            }
            elsif($pref !~ /\\fI\z/) {
                print STDERR "$file:$line option $symbol missing \\fI tagging\n";
                $errors++;
            }
        }
        if($_ =~ /[ \t]+$/) {
            print STDERR "$file:$line trailing whitespace\n";
            $errors++;
        }
        if($_ =~ /\\f([BI])([^\\]*)\\fP/) {
            my $r = $2;
            if($r =~ /^(CURL.*)\(3\)/) {
                my $rr = $1;
                if(!$symbol{$rr}) {
                    print STDERR "$file:$line link to non-libcurl option $rr!\n";
                    $errors++;
                }
            }
        }
        $line++;
    }
    close(M);

    if($reqex) {
        # only for libcurl options man-pages

        my $shcount = scalar(@sh); # before @sh gets shifted
        if($exsize < 2) {
            print STDERR "$file:$line missing EXAMPLE section\n";
            $errors++;
        }

        if($shcount < 3) {
            print STDERR "$file:$line too few man page sections!\n";
            $errors++;
            return;
        }

        my $got = "start";
        my $i = 0;
        my $shused = 1;
        my @shorig = @sh;
        my @order = $optpage ? @optorder : @funcorder;
        my $blessed = $optpage ? \%optblessed : \%funcblessed;

        while($got) {
            my $finesh;
            $got = shift(@sh);
            if($got) {
                if($$blessed{$got}) {
                    $i = $$blessed{$got};
                    $finesh = $got; # a mandatory one
                }
            }
            if($i && defined($finesh)) {
                # mandatory section

                if($i != $shused) {
                    printf STDERR "$file:%u Got %s, when %s was expected\n",
                        $shline{$finesh},
                        $finesh,
                        $order[$shused-1];
                    $errors++;
                    return;
                }
                $shused++;
                if($i == scalar(@order)) {
                    # last mandatory one, exit
                    last;
                }
            }
        }

        if($i != scalar(@order)) {
            printf STDERR "$file:$line missing mandatory section: %s\n",
                $order[$i];
            printf STDERR "$file:$line section found at index %u: '%s'\n",
                $i, $shorig[$i];
            printf STDERR " Found %u used sections\n", $shcount;
            $errors++;
        }
    }
}

allsymbols();

if(!$symbol{'CURLALTSVC_H1'}) {
    print STDERR "didn't get the symbols-in-version!\n";
    exit;
}

my $ind = 1;
for my $s (@optorder) {
    $optblessed{$s} = $ind++
}
$ind = 1;
for my $s (@funcorder) {
    $funcblessed{$s} = $ind++
}

for my $m (@manpages) {
    scanmanpage($m);
}

print STDERR "ok\n" if(!$errors);

exit $errors;
