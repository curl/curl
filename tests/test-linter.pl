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

# If the build is done out-of-source-tree, specify the build root dir as an
# argument to this script. Necessary to find the generated buildprotos.h
# header file.
my $root = "..";

if($ARGV[0]) {
    $root = $ARGV[0];
}

# return all known test cases
sub alltests {
    my @a;
    open(M, "<./data/Makefile.am") ||
        print STDERR "can't open data/Makefile.am\n";
    while(<M>) {
        if(/^  test(\d+)/) {
            push @a, $1; # just the number
        }
    }
    close(M);
    return @a;
}

sub libtests {
    my @a;
    open(M, "<./libtest/Makefile.inc") ||
        print STDERR "can't open Makefile.inc\n";
    while(<M>) {
        if(/^ *lib(\d+)\.c/) {
            push @a, $1; # just the number
        }
    }
    close(M);
    return @a;
}

sub tunittests {
    my @a;
    open(M, "<./tunit/Makefile.inc") ||
        print STDERR "can't open Makefile.inc\n";
    while(<M>) {
        if(/^ *tool(\d+)\.c/) {
            push @a, $1; # just the number
        }
    }
    close(M);
    return @a;
}

sub unittests {
    my @a;
    open(M, "<./unit/Makefile.inc") ||
        print STDERR "can't open Makefile.inc\n";
    while(<M>) {
        if(/^ *unit(\d+)\.c/) {
            push @a, $1; # just the number
        }
    }
    close(M);
    return @a;
}

# provided a test number, return the keywords it uses
sub keywords {
    my ($num) = @_;
    open(my $fh, "<./data/test$num") ||
        print STDERR "can't open test$num\n";
    local $/;
    my $c = <$fh>;
    close($fh);

    # Match and extract the <keywords> block
    if ($c =~ /<keywords>\n(.*?)<\/keywords>/s) {
        return split(/\n/, $1);
    }
    return undef;
}

# provided a test number, return the <tool> it uses
sub tool {
    my ($num) = @_;
    open(my $fh, "<./data/test$num") ||
        print STDERR "can't open test$num\n";
    local $/;
    my $c = <$fh>;
    close($fh);

    # Match and extract the <tool> block
    if ($c =~ /<tool>\n(.*?)<\/tool>/s) {
        return split(/\n/, $1);
    }
    return undef;
}

# return all the function names that are prototyped here, as a hash
sub unitprotos {
    my ($num) = @_;
    my %protos;
    open(my $fh, "<$root/lib/unitprotos.h") ||
        print STDERR "can't open unitprotos.h\n";
    while(<$fh>) {
        if(/^UNITTEST .*[* ]([a-z0-9_]+)\(/i) {
            $protos{$1} = 1;
        }
    }
    close($fh);
    return %protos;
}

# check if this unit test actually uses any internal symbols
sub checkunit {
    my ($num, $protref) = @_;
    open(my $fh, "<./unit/unit$num.c") ||
        print STDERR "can't open unit$num.c\n";
    my $private = 0;
    while(<$fh>) {
        # check all function calls
        while(/([a-z0-9_]+)\(/cig) {
            my $f = $1;
            #print "Check ($num) $f\n";
            if($f =~ /^(Curl_|curlx_)/) {
                $private = 1;
                last;
            }
            elsif($$protref{$f}) {
                # it uses prototyped one
                $private = 1;
                last;
            }
        }
        if(/struct (Curl_|connectdata)/) {
            $private = 1;
            last;
        }
        elsif(/\bCURLPROTO_(WS|WSS|MQTTS|SOCKS)\b/) {
            $private = 1;
            last;
        }
    }
    close($fh);
    if(!$private) {
        print "Unit test $num uses no private functions or structs\n";
    }
    return !$private;
}

sub checkxml {
    my ($num) = @_;
    open(my $fh, "<./data/test$num") ||
        print STDERR "can't open test$num\n";
    my $bad = 1;
    while(<$fh>) {
        if(/^<\?xml/) {
            $bad = 0;
            last;
        }
        print "data/test$num lacks <xml> tag\n";
        last;
    }
    close($fh);
    return $bad;
}

my $error;
my @l = libtests();

print "- Tests with source code in libtests/ have 'libtest' as <keyword>\n";
for my $t (@l) {
    my $lt = 0;
    my @k = keywords($t);
    for my $w (@k) {
        if($w eq "libtest") {
            $lt = 1;
        }
    }
    if(!$lt) {
        print "Test $t in data/test$t lacks the 'libtest' keyword\n";
        $error++;
    }
}

print "- Tests with source code in tunit/ have 'tunittest' as <keyword>\n";
my @l = tunittests();
for my $t (@l) {
    my $lt = 0;
    my @k = keywords($t);
    for my $w (@k) {
        if($w eq "tunittest") {
            $lt = 1;
        }
        elsif($w eq "unittest") {
            print "Test $t in data/test$t wrongly has the 'unittest' keyword\n";
        }
    }
    if(!$lt) {
        print "Test $t in data/test$t lacks the 'tunittest' keyword\n";
        $error++;
    }
}

print "- Tests with source code in unit/ have 'unittest' as <keyword>\n";
my @l = unittests();
for my $t (@l) {
    my $lt = 0;
    my @k = keywords($t);
    for my $w (@k) {
        if($w eq "unittest") {
            $lt = 1;
        }
        elsif($w eq "tunittest") {
            print "Test $t in data/test$t wrongly has the 'tunittest' keyword\n";
        }
    }
    if(!$lt) {
        print "Test $t in data/test$t lacks the 'unittest' keyword\n";
        $error++;
    }
}

my @a = alltests();
print "- Tests that set lib* in <tool> have 'libtest' as <keyword>\n";
for my $t (@a) {
    my @k = tool($t);
    for my $w (@k) {
        if($w =~ /lib%TESTNUMBER/) {
            print "test $t invokes default tool\n";
            $error++;
        }
        elsif($w =~ /lib(\d+)/) {
            my $num = $1;
            if($num == $t) {
                print "test $t invokes default tool\n";
                $error++;
            }
            my $lt = 0;

            # get the keywords for test $num
            my @k = keywords($t);
            for my $w (@k) {
                if($w eq "libtest") {
                    $lt = 1;
                }
            }
            if(!$lt) {
                print "Test $t in data/test$t lacks the 'libtest' keyword\n";
                $error++;
            }
        }
    }
}

print "- Tests that set tool* in <tool> have 'tunittest' as <keyword>\n";
for my $t (@a) {
    my @k = tool($t);
    for my $w (@k) {
        if($w =~ /tool%TESTNUMBER/) {
            print "test $t invokes default tool\n";
            $error++;
        }
        elsif($w =~ /tool(\d+)/) {
            my $num = $1;
            if($num == $t) {
                print "test $t invokes default tool\n";
                $error++;
            }
            my $lt = 0;

            # get the keywords for test $num
            my @k = keywords($num);
            for my $w (@k) {
                if($w eq "tunittest") {
                    $lt = 1;
                }
            }
            if(!$lt) {
                print "Test $t in data/test$t lacks the 'tunittest' keyword\n";
                $error++;
            }
        }
    }
}

print "- Tests that set unit* in <tool> have 'unittest' as <keyword>\n";
for my $t (@a) {
    my @k = tool($t);
    for my $w (@k) {
        if($w =~ /unit%TESTNUMBER/) {
            print "test $t invokes default tool\n";
            $error++;
        }
        elsif($w =~ /unit(\d+)/) {
            my $num = $1;
            if($num == $t) {
                print "test $t invokes default tool\n";
                $error++;
            }
            my $lt = 0;

            # get the keywords for test $num
            my @k = keywords($num);
            for my $w (@k) {
                if($w eq "unittest") {
                    $lt = 1;
                }
            }
            if(!$lt) {
                print "Test $t in data/test$t lacks the 'unittest' keyword\n";
                $error++;
            }
        }
    }
}

print "- Unit tests actually use private symbols\n";
my @l = unittests();
my %protos = unitprotos();
for my $t (@l) {
    $error += checkunit($t, \%protos);
}

print "- All tests have <xml> tag on first line\n";
for my $t (@a) {
    $error += checkxml($t);
}

exit $error;
