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
# Scan man page(s) and detect some simple and yet common formatting mistakes.
#
# Output all deviances to stderr.

use strict;
use warnings;
use File::Basename;

# get the file name first
my $symbolsinversions=shift @ARGV;

# we may get the dir roots pointed out
my @manpages=@ARGV;
my $errors = 0;

my %docsdirs;
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
    open(my $f, "<", "$symbolsinversions") ||
        die "$symbolsinversions: $|";
    while(<$f>) {
        if($_ =~ /^([^ ]*) +(.*)/) {
            my ($name, $info) = ($1, $2);
            $symbol{$name}=$name;

            if($info =~ /([0-9.]+) +([0-9.]+)/) {
                $deprecated{$name}=$info;
            }
        }
    }
    close($f);
}


my %ref = (
    'curl.1' => 1
    );
sub checkref {
    my ($f, $sec, $file, $line)=@_;
    my $present = 0;
    #print STDERR "check $f.$sec\n";
    if($ref{"$f.$sec"}) {
        # present
        return;
    }
    foreach my $d (keys %docsdirs) {
        if( -f "$d/$f.$sec") {
            $present = 1;
            $ref{"$f.$sec"}=1;
            last;
        }
    }
    if(!$present) {
        print STDERR "$file:$line broken reference to $f($sec)\n";
        $errors++;
    }
}

sub scanmanpage {
    my ($file) = @_;
    my $reqex = 0;
    my $inseealso = 0;
    my $inex = 0;
    my $insynop = 0;
    my $exsize = 0;
    my $synopsize = 0;
    my $shc = 0;
    my $optpage = 0; # option or function
    my @sh;
    my $SH="";
    my @separators;
    my @sepline;

    open(my $m, "<", "$file") || die "no such file: $file";
    if($file =~ /[\/\\](CURL|curl_)[^\/\\]*.3/) {
        # This is a man page for libcurl. It requires an example!
        $reqex = 1;
        if($1 eq "CURL") {
            $optpage = 1;
        }
    }
    my $line = 1;
    while(<$m>) {
        chomp;
        if($_ =~ /^.so /) {
            # this man page is just a referral
            close($m);
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
        elsif($_ =~ /^\.SH \"SEE ALSO\"/i) {
            $inseealso = 1;
        }
        elsif($_ =~ /^\.SH/i) {
            $insynop = 0;
            $inex = 0;
        }
        elsif($inseealso) {
            if($_ =~ /^\.BR (.*)/i) {
                my $f = $1;
                if($f =~ /^(lib|)curl/i) {
                    $f =~ s/[\n\r]//g;
                    if($f =~ s/([a-z_0-9-]*) \(([13])\)([, ]*)//i) {
                        push @separators, $3;
                        push @sepline, $line;
                        checkref($1, $2, $file, $line);
                    }
                    if($f !~ /^ *$/) {
                        print STDERR "$file:$line bad SEE ALSO format\n";
                        $errors++;
                    }
                }
                else {
                    if($f =~ /.*(, *)\z/) {
                        push @separators, $1;
                        push @sepline, $line;
                    }
                    else {
                        push @separators, " ";
                        push @sepline, $line;
                    }
                }
            }
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
        my $c = $_;
        while($c =~ s/\\f([BI])((lib|)curl[a-z_0-9-]*)\(([13])\)//i) {
            checkref($2, $4, $file, $line);
        }
        if(($_ =~ /\\f([BI])((libcurl|CURLOPT_|CURLSHOPT_|CURLINFO_|CURLMOPT_|curl_easy_|curl_multi_|curl_url|curl_mime|curl_global|curl_share)[a-zA-Z_0-9-]+)(.)/) &&
           ($4 ne "(")) {
            print STDERR "$file:$line curl ref to $2 without section\n";
            $errors++;
        }
        if($_ =~ /(.*)\\f([^BIP])/) {
            my ($pre, $format) = ($1, $2);
            if($pre !~ /\\\z/) {
                # only if there wasn't another backslash before the \f
                print STDERR "$file:$line suspicious \\f format!\n";
                $errors++;
            }
        }
        if(($SH =~ /^(DESCRIPTION|RETURN VALUE|AVAILABILITY)/i) &&
           ($_ =~ /(.*)((curl_multi|curl_easy|curl_url|curl_global|curl_url|curl_share)[a-zA-Z_0-9-]+)/) &&
           ($1 !~ /\\fI$/)) {
            print STDERR "$file:$line unrefed curl call: $2\n";
            $errors++;
        }


        if($optpage && $SH && ($SH !~ /^(SYNOPSIS|EXAMPLE|NAME|SEE ALSO)/i) &&
           ($_ =~ /(.*)(CURL(OPT_|MOPT_|INFO_|SHOPT_)[A-Z0-9_]*)/)) {
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
        $line++;
    }
    close($m);

    if(@separators) {
        # all except the last one need comma
        for(0 .. $#separators - 1) {
            my $l = $_;
            my $sep = $separators[$l];
            if($sep ne ",") {
                printf STDERR "$file:%d: bad not-last SEE ALSO separator: '%s'\n",
                    $sepline[$l], $sep;
                $errors++;
            }
        }
        # the last one should not do comma
        my $sep = $separators[$#separators];
        if($sep eq ",") {
            printf STDERR "$file:%d: superfluous comma separator\n",
                $sepline[$#separators];
            $errors++;
        }
    }

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
    $docsdirs{dirname($m)}++;
}

for my $m (@manpages) {
    scanmanpage($m);
}

print STDERR "ok\n" if(!$errors);

exit $errors;
