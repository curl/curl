#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

use File::Basename;

sub valgrindparse {
    my ($srcdir,     # the dir in which the runtests script resides
        $sslenabled,
        $file) = @_;
    my $leak;
    my $invalidread;
    my $uninitedvar;
    my $error;
    my $partial;
    my $us;

    my @o;

    my $bt=0;
    my $nssinit=0;

    open(VAL, "<$file");
    while(<VAL>) {
        if($bt) {
            # back trace parsing
            if($_ =~ /^==(\d+)== *(at|by) 0x([0-9A-F]+): (.*)/) {
                my $w = $4;
                if($w =~ /(.*) \(([^:]*):(\d+)/) {
                    my ($func, $source, $line)=($1, $2, $3);
                    my $sourcename = basename($source);
                    if(-f "$srcdir/../src/$sourcename" ||
                       -f "$srcdir/../lib/$sourcename") {
                        # this is our source
 #                       print "$func() at $source:$line\n";
                        $us++;
                    } #else {print "Not our source: $func, $source, $line\n";}
                }

                # the memory leakage within NSS_InitContext is not a bug of curl
                if($w =~ /NSS_InitContext/) {
                    $nssinit++;
                }
            }
            else {
                if($us and not $nssinit) {
                    # the stack trace included source details about us

                    $error++;
                    if($leak) {
                        push @o, "\n Leaked $leak bytes\n";
                    }
                    if($invalidread) {
                        push @o, "\n Read $invalidread invalid bytes\n";
                    }
                    if($uninitedvar) {
                        push @o, "\n Conditional jump or move depends on uninitialised value(s)\n";
                    }
                }
                $bt = 0; # no more backtrace
                $us = 0;
                $nssinit = 0;
            }
        }
        else {
            if($_ =~ /(\d+) bytes in (\d+) blocks are definitely lost/) {
                $leak = $1;
                if($leak) {
                    $error++;
                }
                $bt = 1;
            }
            elsif($_ =~ /Invalid read of size (\d+)/) {
                $invalidread = $1;
                $error++;
                $bt = 1;
            }
            elsif($_ =~ /Conditional jump or move/) {
                # If we require SSL, this test case most probaly makes
                # us use OpenSSL. OpenSSL produces numerous valgrind
                # errors of this kind, rendering it impossible for us to
                # detect (valid) reports on actual curl or libcurl code.

                if(!$sslenabled) {
                    $uninitedvar = 1;
                    $error++;
                    $bt = 1;
                }
                else {
                    $partial=1;
                }
            }
        }
    }
    close(VAL);
    return @o;
}

1;
