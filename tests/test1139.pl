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
# Scan symbols-in-version (which is verified to be correct by test 1119), then
# verify that each option mention in there that should have its own manpage
# actually does.
#
# In addition, make sure that every current option to curl_easy_setopt,
# curl_easy_getinfo and curl_multi_setopt are also mentioned in their
# corresponding main (index) manpage.
#
# src/tool_getparam.c lists all options curl can parse
# docs/curl.1 documents all command line options
# src/tool_listhelp.c outputs all options with curl -h
# - make sure they're all in sync
#
# Output all deviances to stderr.

use strict;
use warnings;

# we may get the dir roots pointed out
my $root=$ARGV[0] || ".";
my $buildroot=$ARGV[1] || ".";
my $syms = "$root/docs/libcurl/symbols-in-versions";
my $curlh = "$root/include/curl/curl.h";
my $errors=0;

# the prepopulated alias list is the CURLINFO_* defines that are used for the
# debug function callback and the fact that they use the same prefix as the
# curl_easy_getinfo options was a mistake.
my %alias = (
    'CURLINFO_DATA_IN' => 'none',
    'CURLINFO_DATA_OUT' => 'none',
    'CURLINFO_END' => 'none',
    'CURLINFO_HEADER_IN' => 'none',
    'CURLINFO_HEADER_OUT' => 'none',
    'CURLINFO_LASTONE' => 'none',
    'CURLINFO_NONE' => 'none',
    'CURLINFO_SSL_DATA_IN' => 'none',
    'CURLINFO_SSL_DATA_OUT' => 'none',
    'CURLINFO_TEXT' => 'none'
    );

sub scanmdpage {
    my ($file, @words) = @_;

    open(my $mh, "<", "$file") ||
        die "could not open $file";
    my @m;
    while(<$mh>) {
        if($_ =~ /^## (.*)/) {
            my $w = $1;
            # "unquote" minuses
            $w =~ s/\\-/-/g;
            push @m, $w;
        }
    }
    close($mh);

    my @ms = sort @m;
    for my $i (0 .. $#m) {
        if($ms[$i] ne $m[$i]) {
            print STDERR "$file:1:ERROR: $m[$i] is not alphabetical (expected $ms[$i])\n";
            $errors++;
            # no point in reporting many
            last;
        }
    }
    foreach my $m (@words) {
        my @g = grep(/$m/, @m);
        if(!$g[0]) {
            print STDERR "Missing mention of $m in $file\n";
            $errors++;
        }
    }
}

my $r;

# check for define aliases
open($r, "<", "$curlh") ||
    die "no curl.h";
while(<$r>) {
    if(/^\#define (CURL(OPT|INFO|MOPT)_\w+) (.*)/) {
        $alias{$1}=$3;
    }
}
close($r);

my @curlopt;
my @curlinfo;
my @curlmopt;
open($r, "<", "$syms") ||
    die "no input file";
while(<$r>) {
    chomp;
    my $l= $_;
    if($l =~ /(CURL(OPT|INFO|MOPT)_\w+) *([0-9.]*) *([0-9.-]*) *([0-9.]*)/) {
        my ($opt, $type, $add, $dep, $rem) = ($1, $2, $3, $4, $5);

        if($alias{$opt}) {
            #print "$opt => $alias{$opt}\n";
        }
        elsif($rem) {
            # $opt was removed in $rem
            # so don't check for that
        }
        else {
            if($type eq "OPT") {
                push @curlopt, $opt,
            }
            elsif($type eq "INFO") {
                push @curlinfo, $opt,
            }
            elsif($type eq "MOPT") {
                push @curlmopt, $opt,
            }
            if(! -f "$root/docs/libcurl/opts/$opt.md") {
                print STDERR "Missing $opt.md\n";
                $errors++;
            }
        }
    }
}
close($r);

scanmdpage("$root/docs/libcurl/curl_easy_setopt.md", @curlopt);
scanmdpage("$root/docs/libcurl/curl_easy_getinfo.md", @curlinfo);
scanmdpage("$root/docs/libcurl/curl_multi_setopt.md", @curlmopt);

# using this hash array, we can skip specific options
my %opts = (
    # pretend these --no options exists in tool_getparam.c
    '--no-alpn' => 1,
    '--no-npn' => 1,
    '-N, --no-buffer' => 1,
    '--no-sessionid' => 1,
    '--no-keepalive' => 1,
    '--no-progress-meter' => 1,
    '--no-clobber' => 1,

    # pretend these options without -no exist in curl.1 and tool_listhelp.c
    '--alpn' => 6,
    '--npn' => 6,
    '--eprt' => 6,
    '--epsv' => 6,
    '--keepalive' => 6,
    '-N, --buffer' => 6,
    '--sessionid' => 6,
    '--progress-meter' => 6,
    '--clobber' => 6,

    # deprecated options do not need to be in tool_help.c nor curl.1
    '--krb4' => 6,
    '--ftp-ssl' => 6,
    '--ftp-ssl-reqd' => 6,
    '--include' => 6,

    # for tests and debug only, can remain hidden
    '--test-duphandle' => 6,
    '--test-event' => 6,
    '--wdebug' => 6,
    );


#########################################################################
# parse the curl code that parses the command line arguments!
open($r, "<", "$root/src/tool_getparam.c") ||
    die "no input file";
my $list;
my @getparam; # store all parsed parameters

my $prevlong = "";
my $no = 0;
while(<$r>) {
    $no++;
    chomp;
    if(/struct LongShort aliases/) {
        $list=1;
    }
    elsif($list) {
        if( /^  \{(\"[^,]*\").*\'(.)\', (.*)\}/) {
            my ($l, $s, $rd)=($1, $2, $3);
            my $sh;
            my $lo;
            my $title;
            if(($l cmp $prevlong) < 0) {
                print STDERR "tool_getparam.c:$no: '$l' is NOT placed in alpha-order\n";
            }
            if($l =~ /\"(.*)\"/) {
                # long option
                $lo = $1;
                $title="--$lo";
            }
            if($s ne " ") {
                # a short option
                $sh = $s;
                $title="-$sh, $title";
            }
            push @getparam, $title;
            $opts{$title} |= 1;
            $prevlong = $l;
        }
    }
}
close($r);

#########################################################################
# parse the curl.1 manpage, extract all documented command line options
# The manpage may or may not be rebuilt, so check both possible locations
open($r, "<", "$buildroot/docs/cmdline-opts/curl.1") || open($r, "<", "$root/docs/cmdline-opts/curl.1") ||
    die "failed getting curl.1";
my @manpage; # store all parsed parameters
while(<$r>) {
    chomp;
    my $l= $_;
    $l =~ s/\\-/-/g;
    if($l =~ /^\.IP \"(-[^\"]*)\"/) {
        my $str = $1;
        my $combo;
        if($str =~ /^-(.), --([a-z0-9.-]*)/) {
            # figure out the -short, --long combo
            $combo = "-$1, --$2";
        }
        elsif($str =~ /^--([a-z0-9.-]*)/) {
            # figure out the --long name
            $combo = "--$1";
        }
        if($combo) {
            push @manpage, $combo;
            $opts{$combo} |= 2;
        }
    }
}
close($r);


#########################################################################
# parse the curl code that outputs the curl -h list
open($r, "<", "$root/src/tool_listhelp.c") ||
    die "no input file";
my @toolhelp; # store all parsed parameters
while(<$r>) {
    chomp;
    my $l= $_;
    if(/^  \{\" *(.*)/) {
        my $str=$1;
        my $combo;
        if($str =~ /^-(.), --([a-z0-9.-]*)/) {
            # figure out the -short, --long combo
            $combo = "-$1, --$2";
        }
        elsif($str =~ /^--([a-z0-9.-]*)/) {
            # figure out the --long name
            $combo = "--$1";
        }
        if($combo) {
            push @toolhelp, $combo;
            $opts{$combo} |= 4;
        }

    }
}
close($r);

#
# Now we have three arrays with options to cross-reference.

foreach my $o (keys %opts) {
    my $where = $opts{$o};

    if($where != 7) {
        # this is not in all three places
        $errors++;
        my $exists;
        my $missing;
        if($where & 1) {
            $exists=" tool_getparam.c";
        }
        else {
            $missing=" tool_getparam.c";
        }
        if($where & 2) {
            $exists.= " curl.1";
        }
        else {
            $missing.= " curl.1";
        }
        if($where & 4) {
            $exists .= " tool_listhelp.c";
        }
        else {
            $missing .= " tool_listhelp.c";
        }

        print STDERR "$o is not in$missing (but in$exists)\n";
    }
}

print STDERR "$errors\n";
