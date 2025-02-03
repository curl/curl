#!/usr/bin/env perl
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
#
# Scan symbols-in-version (which is verified to be correct by test 1119), then
# verify that each option mention in there that should have its own manpage
# actually does.
#
# In addition, make sure that every current option to fetch_easy_setopt,
# fetch_easy_getinfo and fetch_multi_setopt are also mentioned in their
# corresponding main (index) manpage.
#
# src/tool_getparam.c lists all options fetch can parse
# docs/fetch.1 documents all command line options
# src/tool_listhelp.c outputs all options with fetch -h
# - make sure they're all in sync
#
# Output all deviances to stderr.

use strict;
use warnings;

# we may get the dir roots pointed out
my $root=$ARGV[0] || ".";
my $buildroot=$ARGV[1] || ".";
my $syms = "$root/docs/libfetch/symbols-in-versions";
my $fetchh = "$root/include/fetch/fetch.h";
my $errors=0;

# the prepopulated alias list is the FETCHINFO_* defines that are used for the
# debug function callback and the fact that they use the same prefix as the
# fetch_easy_getinfo options was a mistake.
my %alias = (
    'FETCHINFO_DATA_IN' => 'none',
    'FETCHINFO_DATA_OUT' => 'none',
    'FETCHINFO_END' => 'none',
    'FETCHINFO_HEADER_IN' => 'none',
    'FETCHINFO_HEADER_OUT' => 'none',
    'FETCHINFO_LASTONE' => 'none',
    'FETCHINFO_NONE' => 'none',
    'FETCHINFO_SSL_DATA_IN' => 'none',
    'FETCHINFO_SSL_DATA_OUT' => 'none',
    'FETCHINFO_TEXT' => 'none'
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
open($r, "<", "$fetchh") ||
    die "no fetch.h";
while(<$r>) {
    if(/^\#define (FETCH(OPT|INFO|MOPT)_\w+) (.*)/) {
        $alias{$1}=$3;
    }
}
close($r);

my @fetchopt;
my @fetchinfo;
my @fetchmopt;
open($r, "<", "$syms") ||
    die "no input file";
while(<$r>) {
    chomp;
    my $l= $_;
    if($l =~ /(FETCH(OPT|INFO|MOPT)_\w+) *([0-9.]*) *([0-9.-]*) *([0-9.]*)/) {
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
                push @fetchopt, $opt,
            }
            elsif($type eq "INFO") {
                push @fetchinfo, $opt,
            }
            elsif($type eq "MOPT") {
                push @fetchmopt, $opt,
            }
            if(! -f "$root/docs/libfetch/opts/$opt.md") {
                print STDERR "Missing $opt.md\n";
                $errors++;
            }
        }
    }
}
close($r);

scanmdpage("$root/docs/libfetch/fetch_easy_setopt.md", @fetchopt);
scanmdpage("$root/docs/libfetch/fetch_easy_getinfo.md", @fetchinfo);
scanmdpage("$root/docs/libfetch/fetch_multi_setopt.md", @fetchmopt);

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

    # pretend these options without -no exist in fetch.1 and tool_listhelp.c
    '--alpn' => 6,
    '--npn' => 6,
    '--eprt' => 6,
    '--epsv' => 6,
    '--keepalive' => 6,
    '-N, --buffer' => 6,
    '--sessionid' => 6,
    '--progress-meter' => 6,
    '--clobber' => 6,

    # deprecated options do not need to be in tool_help.c nor fetch.1
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
# parse the fetch code that parses the command line arguments!
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
# parse the fetch.1 manpage, extract all documented command line options
# The manpage may or may not be rebuilt, so check both possible locations
open($r, "<", "$buildroot/docs/cmdline-opts/fetch.1") || open($r, "<", "$root/docs/cmdline-opts/fetch.1") ||
    die "failed getting fetch.1";
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
# parse the fetch code that outputs the fetch -h list
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
            $exists.= " fetch.1";
        }
        else {
            $missing.= " fetch.1";
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
