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

my @files = @ARGV;
my $cfile = "test.c";
my $check = "./scripts/checksrc.pl";
my $error;

if($files[0] eq "-h") {
    print "Usage: verify-synopsis [man pages]\n";
    exit;
}

sub testcompile {
    my $rc = system("gcc -c test.c -DCURL_DISABLE_TYPECHECK -DCURL_ALLOW_OLD_MULTI_SOCKET -DCURL_DISABLE_DEPRECATION -Wunused -Werror -Wno-unused-but-set-variable -I include") >> 8;
    return $rc;
}

sub checksrc {
    my $rc = system("$check test.c") >> 8;
    return $rc;
}

sub extract {
    my($f) = @_;
    my $syn = 0;
    my $l = 0;
    my $iline = 0;
    my $fail = 0;
    open(F, "<$f") or die "failed opening input file $f : $!";
    open(O, ">$cfile") or die "failed opening output file $cfile : $!";
    print O "#include <curl/curl.h>\n";
    while(<F>) {
        $iline++;
        if(/^.SH EXAMPLE/) {
            $syn = 1
        }
        elsif($syn == 1) {
            if(/^.nf/) {
                $syn++;
                print O "/* !checksrc! disable UNUSEDIGNORE all */\n";
                print O "/* !checksrc! disable COPYRIGHT all */\n";
                print O "/* !checksrc! disable FOPENMODE all */\n";
                printf O "#line %d \"$f\"\n", $iline+1;
            }
        }
        elsif($syn == 2) {
            if(/^.fi/) {
                last;
            }
            if(/(?<!\\)(?:\\{2})*\\(?!\\)/) {
                print STDERR
                  "Error while processing file $f line $iline:\n$_" .
                  "Error: Single backslashes \\ are not properly shown in " .
                  "manpage EXAMPLE output unless they are escaped \\\\.\n";
                $fail = 1;
                $error = 1;
                last;
            }
            # two backslashes become one
            $_ =~ s/\\\\/\\/g;
            print O $_;
            $l++;
        }
    }
    close(F);
    close(O);

    return ($fail ? 0 : $l);
}

for my $m (@files) {
    print "Verify $m\n";
    my $out = extract($m);
    if($out) {
      $error |= testcompile($m);
      $error |= checksrc($m);
    }
}
exit $error;
