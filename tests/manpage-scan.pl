#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2016 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Scan symbols-in-version (which is verified to be correct by test 1119), then
# verify that each option mention in there that should have its own man page
# actually does.
#
# In addition, make sure that every current option to curl_easy_setopt,
# curl_easy_getinfo and curl_multi_setopt are also mentioned in their
# corresponding main (index) man page.
#
# src/tool_getparam.c lists all options curl can parse
# docs/curl.1 documents all command line options
# src/tool_help.c outputs all options with curl -h
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

sub scanmanpage {
    my ($file, @words) = @_;

    open(M, "<$file");
    my @m;
    while(<M>) {
        if($_ =~ /^\.IP (.*)/) {
            my $w = $1;
            # "unquote" minuses
            $w =~ s/\\-/-/g;
            push @m, $w;
        }
    }
    close(M);

    foreach my $m (@words) {
        my @g = grep(/$m/, @m);
        if(!$g[0]) {
            print STDERR "Missing mention of $m in $file\n";
            $errors++;
        }
    }
}

# check for define alises
open(R, "<$curlh") ||
    die "no curl.h";
while(<R>) {
    if(/^\#define (CURL(OPT|INFO|MOPT)_\w+) (.*)/) {
        $alias{$1}=$3;
    }
}
close(R);

my @curlopt;
my @curlinfo;
my @curlmopt;
open(R, "<$syms") ||
    die "no input file";
while(<R>) {
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
            if(! -f "$root/docs/libcurl/opts/$opt.3") {
                print STDERR "Missing $opt.3\n";
                $errors++;
            }
        }
    }
}
close(R);

scanmanpage("$root/docs/libcurl/curl_easy_setopt.3", @curlopt);
scanmanpage("$root/docs/libcurl/curl_easy_getinfo.3", @curlinfo);
scanmanpage("$root/docs/libcurl/curl_multi_setopt.3", @curlmopt);

# using this hash array, we can skip specific options
my %opts = (
    # pretend these --no options exists in tool_getparam.c
    '--no-alpn' => 1,
    '--no-npn' => 1,
    '-N, --no-buffer' => 1,
    '--no-sessionid' => 1,
    '--no-keepalive' => 1,
    '--no-progress-meter' => 1,

    # pretend these options without -no exist in curl.1 and tool_help.c
    '--alpn' => 6,
    '--npn' => 6,
    '--eprt' => 6,
    '--epsv' => 6,
    '--keepalive' => 6,
    '-N, --buffer' => 6,
    '--sessionid' => 6,
    '--progress-meter' => 6,

    # deprecated options do not need to be in tool_help.c nor curl.1
    '--krb4' => 6,
    '--ftp-ssl' => 6,
    '--ftp-ssl-reqd' => 6,

    # for tests and debug only, can remain hidden
    '--test-event' => 6,
    '--wdebug' => 6,
    );


#########################################################################
# parse the curl code that parses the command line arguments!
open(R, "<$root/src/tool_getparam.c") ||
    die "no input file";
my $list;
my @getparam; # store all parsed parameters

while(<R>) {
    chomp;
    my $l= $_;
    if(/struct LongShort aliases/) {
        $list=1;
    }
    elsif($list) {
        if( /^  \{([^,]*), *([^ ]*)/) {
            my ($s, $l)=($1, $2);
            my $sh;
            my $lo;
            my $title;
            if($l =~ /\"(.*)\"/) {
                # long option
                $lo = $1;
                $title="--$lo";
            }
            if($s =~ /\"(.)\"/) {
                # a short option
                $sh = $1;
                $title="-$sh, $title";
            }
            push @getparam, $title;
            $opts{$title} |= 1;
        }
    }
}
close(R);

#########################################################################
# parse the curl.1 man page, extract all documented command line options
# The man page may or may not be rebuilt, so check both possible locations
open(R, "<$buildroot/docs/curl.1") || open(R, "<$root/docs/curl.1") ||
    die "no input file";
my @manpage; # store all parsed parameters
while(<R>) {
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
close(R);


#########################################################################
# parse the curl code that outputs the curl -h list
open(R, "<$root/src/tool_help.c") ||
    die "no input file";
my @toolhelp; # store all parsed parameters
while(<R>) {
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
close(R);

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
            $exists .= " tool_help.c";
        }
        else {
            $missing .= " tool_help.c";
        }

        print STDERR "$o is not in$missing (but in$exists)\n";
    }
}

print STDERR "$errors\n";
