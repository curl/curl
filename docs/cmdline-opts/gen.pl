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

=begin comment

This script generates the manpage.

Example: gen.pl <command> [files] > curl.1

Dev notes:

We open *input* files in :crlf translation (a no-op on many platforms) in
case we have CRLF line endings in Windows but a perl that defaults to LF.
Unfortunately it seems some perls like msysgit can't handle a global input-only
:crlf so it has to be specified on each file open for text input.

=end comment
=cut

my %optshort;
my %optlong;
my %helplong;
my %arglong;
my %redirlong;
my %protolong;
my %catlong;

use POSIX qw(strftime);
my $date = strftime "%B %d %Y", localtime;
my $year = strftime "%Y", localtime;
my $version = "unknown";

open(INC, "<../../include/curl/curlver.h");
while(<INC>) {
    if($_ =~ /^#define LIBCURL_VERSION \"([0-9.]*)/) {
        $version = $1;
        last;
    }
}
close(INC);

# get the long name version, return the man page string
sub manpageify {
    my ($k)=@_;
    my $l;
    if($optlong{$k} ne "") {
        # both short + long
        $l = "\\fI-".$optlong{$k}.", --$k\\fP";
    }
    else {
        # only long
        $l = "\\fI--$k\\fP";
    }
    return $l;
}

sub printdesc {
    my @desc = @_;
    my $exam = 0;
    for my $d (@desc) {
        if($d =~ /\(Added in ([0-9.]+)\)/i) {
            my $ver = $1;
            if(too_old($ver)) {
                $d =~ s/ *\(Added in $ver\)//gi;
            }
        }
        if($d !~ /^.\\"/) {
            # **bold**
            $d =~ s/\*\*([^ ]*)\*\*/\\fB$1\\fP/g;
            # *italics*
            $d =~ s/\*([^ ]*)\*/\\fI$1\\fP/g;
        }
        if(!$exam && ($d =~ /^ /)) {
            # start of example
            $exam = 1;
            print ".nf\n"; # no-fill
        }
        elsif($exam && ($d !~ /^ /)) {
            # end of example
            $exam = 0;
            print ".fi\n"; # fill-in
        }
        # skip lines starting with space (examples)
        if($d =~ /^[^ ]/) {
            for my $k (keys %optlong) {
                my $l = manpageify($k);
                $d =~ s/--$k([^a-z0-9_-])(\W)/$l$1$2/;
            }
        }
        # quote "bare" minuses in the output
        $d =~ s/( |\\fI|^)--/$1\\-\\-/g;
        $d =~ s/([ -]|\\fI|^)-/$1\\-/g;
        # handle single quotes first on the line
        $d =~ s/(\s*)\'/$1\\(aq/;
        print $d;
    }
    if($exam) {
        print ".fi\n"; # fill-in
    }
}

sub seealso {
    my($standalone, $data)=@_;
    if($standalone) {
        return sprintf
            ".SH \"SEE ALSO\"\n$data\n";
    }
    else {
        return "See also $data. ";
    }
}

sub overrides {
    my ($standalone, $data)=@_;
    if($standalone) {
        return ".SH \"OVERRIDES\"\n$data\n";
    }
    else {
        return $data;
    }
}

sub protocols {
    my ($standalone, $data)=@_;
    if($standalone) {
        return ".SH \"PROTOCOLS\"\n$data\n";
    }
    else {
        return "($data) ";
    }
}

sub too_old {
    my ($version)=@_;
    my $a = 999999;
    if($version =~ /^(\d+)\.(\d+)\.(\d+)/) {
        $a = $1 * 1000 + $2 * 10 + $3;
    }
    elsif($version =~ /^(\d+)\.(\d+)/) {
        $a = $1 * 1000 + $2 * 10;
    }
    if($a < 7300) {
        # we consider everything before 7.30.0 to be too old to mention
        # specific changes for
        return 1;
    }
    return 0;
}

sub added {
    my ($standalone, $data)=@_;
    if(too_old($data)) {
        # don't mention ancient additions
        return "";
    }
    if($standalone) {
        return ".SH \"ADDED\"\nAdded in curl version $data\n";
    }
    else {
        return "Added in $data. ";
    }
}

sub single {
    my ($f, $standalone)=@_;
    open(F, "<:crlf", "$f") ||
        return 1;
    my $short;
    my $long;
    my $tags;
    my $added;
    my $protocols;
    my $arg;
    my $mutexed;
    my $requires;
    my $category;
    my $seealso;
    my $copyright;
    my $spdx;
    my @examples; # there can be more than one
    my $magic; # cmdline special option
    my $line;
    while(<F>) {
        $line++;
        if(/^Short: *(.)/i) {
            $short=$1;
        }
        elsif(/^Long: *(.*)/i) {
            $long=$1;
        }
        elsif(/^Added: *(.*)/i) {
            $added=$1;
        }
        elsif(/^Tags: *(.*)/i) {
            $tags=$1;
        }
        elsif(/^Arg: *(.*)/i) {
            $arg=$1;
        }
        elsif(/^Magic: *(.*)/i) {
            $magic=$1;
        }
        elsif(/^Mutexed: *(.*)/i) {
            $mutexed=$1;
        }
        elsif(/^Protocols: *(.*)/i) {
            $protocols=$1;
        }
        elsif(/^See-also: *(.*)/i) {
            $seealso=$1;
        }
        elsif(/^Requires: *(.*)/i) {
            $requires=$1;
        }
        elsif(/^Category: *(.*)/i) {
            $category=$1;
        }
        elsif(/^Example: *(.*)/i) {
            push @examples, $1;
        }
        elsif(/^C: (.*)/i) {
            $copyright=$1;
        }
        elsif(/^SPDX-License-Identifier: (.*)/i) {
            $spdx=$1;
        }
        elsif(/^Help: *(.*)/i) {
            ;
        }
        elsif(/^---/) {
            if(!$long) {
                print STDERR "ERROR: no 'Long:' in $f\n";
                return 1;
            }
            if(!$category) {
                print STDERR "ERROR: no 'Category:' in $f\n";
                return 2;
            }
            if(!$examples[0]) {
                print STDERR "$f:$line:1:ERROR: no 'Example:' present\n";
                return 2;
            }
            if(!$added) {
                print STDERR "$f:$line:1:ERROR: no 'Added:' version present\n";
                return 2;
            }
            if(!$seealso) {
                print STDERR "$f:$line:1:ERROR: no 'See-also:' field present\n";
                return 2;
            }
            if(!$copyright) {
                print STDERR "$f:$line:1:ERROR: no 'C:' field present\n";
                return 2;
            }
            if(!$spdx) {
                print STDERR "$f:$line:1:ERROR: no 'SPDX-License-Identifier:' field present\n";
                return 2;
            }
            last;
        }
        else {
            chomp;
            print STDERR "WARN: unrecognized line in $f, ignoring:\n:'$_';"
        }
    }
    my @desc;
    while(<F>) {
        push @desc, $_;
    }
    close(F);
    my $opt;
    if(defined($short) && $long) {
        $opt = "-$short, --$long";
    }
    elsif($short && !$long) {
        $opt = "-$short";
    }
    elsif($long && !$short) {
        $opt = "--$long";
    }

    if($arg) {
        $opt .= " $arg";
    }

    # quote "bare" minuses in opt
    $opt =~ s/( |^)--/$1\\-\\-/g;
    $opt =~ s/( |^)-/$1\\-/g;
    if($standalone) {
        print ".TH curl 1 \"30 Nov 2016\" \"curl 7.52.0\" \"curl manual\"\n";
        print ".SH OPTION\n";
        print "curl $opt\n";
    }
    else {
        print ".IP \"$opt\"\n";
    }
    if($protocols) {
        print protocols($standalone, $protocols);
    }

    if($standalone) {
        print ".SH DESCRIPTION\n";
    }

    printdesc(@desc);
    undef @desc;

    my @foot;
    if($seealso) {
        my @m=split(/ /, $seealso);
        my $mstr;
        my $and = 0;
        my $num = scalar(@m);
        if($num > 2) {
            # use commas up to this point
            $and = $num - 1;
        }
        my $i = 0;
        for my $k (@m) {
            if(!$helplong{$k}) {
                print STDERR "$f:$line:1:WARN: see-also a non-existing option: $k\n";
            }
            my $l = manpageify($k);
            my $sep = " and";
            if($and && ($i < $and)) {
                $sep = ",";
            }
            $mstr .= sprintf "%s$l", $mstr?"$sep ":"";
            $i++;
        }
        push @foot, seealso($standalone, $mstr);
    }
    if($requires) {
        my $l = manpageify($long);
        push @foot, "$l requires that the underlying libcurl".
            " was built to support $requires. ";
    }
    if($mutexed) {
        my @m=split(/ /, $mutexed);
        my $mstr;
        for my $k (@m) {
            if(!$helplong{$k}) {
                print STDERR "WARN: $f mutexes a non-existing option: $k\n";
            }
            my $l = manpageify($k);
            $mstr .= sprintf "%s$l", $mstr?" and ":"";
        }
        push @foot, overrides($standalone,
                              "This option is mutually exclusive to $mstr. ");
    }
    if($examples[0]) {
        my $s ="";
        $s="s" if($examples[1]);
        print "\nExample$s:\n.nf\n";
        foreach my $e (@examples) {
            $e =~ s!\$URL!https://example.com!g;
            print " curl $e\n";
        }
        print ".fi\n";
    }
    if($added) {
        push @foot, added($standalone, $added);
    }
    if($foot[0]) {
        print "\n";
        my $f = join("", @foot);
        $f =~ s/ +\z//; # remove trailing space
        print "$f\n";
    }
    return 0;
}

sub getshortlong {
    my ($f)=@_;
    open(F, "<:crlf", "$f");
    my $short;
    my $long;
    my $help;
    my $arg;
    my $protocols;
    my $category;
    while(<F>) {
        if(/^Short: (.)/i) {
            $short=$1;
        }
        elsif(/^Long: (.*)/i) {
            $long=$1;
        }
        elsif(/^Help: (.*)/i) {
            $help=$1;
        }
        elsif(/^Arg: (.*)/i) {
            $arg=$1;
        }
        elsif(/^Protocols: (.*)/i) {
            $protocols=$1;
        }
        elsif(/^Category: (.*)/i) {
            $category=$1;
        }
        elsif(/^---/) {
            last;
        }
    }
    close(F);
    if($short) {
        $optshort{$short}=$long;
    }
    if($long) {
        $optlong{$long}=$short;
        $helplong{$long}=$help;
        $arglong{$long}=$arg;
        $protolong{$long}=$protocols;
        $catlong{$long}=$category;
    }
}

sub indexoptions {
    my (@files) = @_;
    foreach my $f (@files) {
        getshortlong($f);
    }
}

sub header {
    my ($f)=@_;
    open(F, "<:crlf", "$f");
    my @d;
    while(<F>) {
        s/%DATE/$date/g;
        s/%VERSION/$version/g;
        push @d, $_;
    }
    close(F);
    printdesc(@d);
}

sub listhelp {
    print <<HEAD
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \\| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \\___|\\___/|_| \\_\\_____|
 *
 * Copyright (C) 1998 - $year, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "tool_setup.h"
#include "tool_help.h"

/*
 * DO NOT edit tool_listhelp.c manually.
 * This source file is generated with the following command:

  cd \$srcroot/docs/cmdline-opts
  ./gen.pl listhelp *.d > \$srcroot/src/tool_listhelp.c
 */

const struct helptxt helptext[] = {
HEAD
        ;
    foreach my $f (sort keys %helplong) {
        my $long = $f;
        my $short = $optlong{$long};
        my @categories = split ' ', $catlong{$long};
        my $bitmask;
        my $opt;

        if(defined($short) && $long) {
            $opt = "-$short, --$long";
        }
        elsif($long && !$short) {
            $opt = "    --$long";
        }
        for my $i (0 .. $#categories) {
            $bitmask .= 'CURLHELP_' . uc $categories[$i];
            # If not last element, append |
            if($i < $#categories) {
                $bitmask .= ' | ';
            }
        }
        my $arg = $arglong{$long};
        if($arg) {
            $opt .= " $arg";
        }
        my $desc = $helplong{$f};
        $desc =~ s/\"/\\\"/g; # escape double quotes

        my $line = sprintf "  {\"%s\",\n   \"%s\",\n   %s},\n", $opt, $desc, $bitmask;

        if(length($opt) > 78) {
            print STDERR "WARN: the --$long name is too long\n";
        }
        elsif(length($desc) > 78) {
            print STDERR "WARN: the --$long description is too long\n";
        }
        print $line;
    }
    print <<FOOT
  { NULL, NULL, CURLHELP_HIDDEN }
};
FOOT
        ;
}

sub listcats {
    my %allcats;
    foreach my $f (sort keys %helplong) {
        my @categories = split ' ', $catlong{$f};
        foreach (@categories) {
            $allcats{$_} = undef;
        }
    }
    my @categories;
    foreach my $key (keys %allcats) {
        push @categories, $key;
    }
    @categories = sort @categories;
    unshift @categories, 'hidden';
    for my $i (0..$#categories) {
        print '#define ' . 'CURLHELP_' . uc($categories[$i]) . ' ' . "1u << " . $i . "u\n";
    }
}

sub mainpage {
    my (@files) = @_;
    my $ret;
    # show the page header
    header("page-header");

    # output docs for all options
    foreach my $f (sort @files) {
        $ret += single($f, 0);
    }

    header("page-footer");
    exit $ret if($ret);
}

sub showonly {
    my ($f) = @_;
    if(single($f, 1)) {
        print STDERR "$f: failed\n";
    }
}

sub showprotocols {
    my %prots;
    foreach my $f (keys %optlong) {
        my @p = split(/ /, $protolong{$f});
        for my $p (@p) {
            $prots{$p}++;
        }
    }
    for(sort keys %prots) {
        printf "$_ (%d options)\n", $prots{$_};
    }
}

sub getargs {
    my ($f, @s) = @_;
    if($f eq "mainpage") {
        mainpage(@s);
        return;
    }
    elsif($f eq "listhelp") {
        listhelp();
        return;
    }
    elsif($f eq "single") {
        showonly($s[0]);
        return;
    }
    elsif($f eq "protos") {
        showprotocols();
        return;
    }
    elsif($f eq "listcats") {
        listcats();
        return;
    }

    print "Usage: gen.pl <mainpage/listhelp/single FILE/protos/listcats> [files]\n";
}

#------------------------------------------------------------------------

my $cmd = shift @ARGV;
my @files = @ARGV; # the rest are the files

# learn all existing options
indexoptions(@files);

getargs($cmd, @files);
