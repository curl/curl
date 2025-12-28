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
# Example input:
#
# MEM mprintf.c:1094 malloc(32) = e5718
# MEM mprintf.c:1103 realloc(e5718, 64) = e6118
# MEM sendf.c:232 free(f6520)

package memanalyzer;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        memanalyze
    );
}

my $memsum;
my $maxmem;

sub newtotal {
    my ($newtot)=@_;
    # count a max here

    if($newtot > $maxmem) {
        $maxmem = $newtot;
    }
}

sub memanalyze {
    my ($file, $verbose, $trace, $showlimit) = @_;
    my @res;

    my $mallocs = 0;
    my $callocs = 0;
    my $reallocs = 0;
    my $strdups = 0;
    my $wcsdups = 0;
    my $sockets = 0;

    $memsum = 0; # the total number of memory allocated over the lifetime
    $maxmem = 0; # the high water mark

    open(my $fileh, "<", "$file") or return ();

    if($showlimit) {
        while(<$fileh>) {
            if(/^LIMIT.*memlimit$/) {
                push @res, $_;
                last;
            }
        }
        close($fileh);
        return @res;
    }

    my %sizeataddr;
    my %getmem;

    my $totalmem = 0;
    my $frees = 0;

    my $dup;
    my $size;
    my $addr;

    my %filedes;
    my %getfile;

    my %fopen;
    my %fopenfile;
    my $openfile = 0;
    my $fopens = 0;

    my %addrinfo;
    my %addrinfofile;
    my $addrinfos = 0;

    my $source;
    my $linenum;
    my $function;

    my $lnum = 0;

    while(<$fileh>) {
        chomp $_;
        my $line = $_;
        $lnum++;
        if($line =~ /^BT/) {
            # back-trace, ignore
        }
        elsif($line =~ /^LIMIT ([^ ]*):(\d*) (.*)/) {
            # new memory limit test prefix
            my $i = $3;
            my ($source, $linenum) = ($1, $2);
            if($trace && ($i =~ /([^ ]*) reached memlimit/)) {
                push @res, "LIMIT: $1 returned error at $source:$linenum\n";
            }
        }
        elsif($line =~ /^MEM ([^ ]*):(\d*) (.*)/) {
            # generic match for the filename+linenumber
            $source = $1;
            $linenum = $2;
            $function = $3;

            if($function =~ /free\((\(nil\)|0x([0-9a-f]*))/) {
                $addr = $2;
                if($1 eq "(nil)") {
                    ; # do nothing when free(NULL)
                }
                elsif(!exists $sizeataddr{$addr}) {
                    push @res, "FREE ERROR: No memory allocated: $line\n";
                }
                elsif(-1 == $sizeataddr{$addr}) {
                    push @res, "FREE ERROR: Memory freed twice: $line\n";
                    push @res, "FREE ERROR: Previously freed at: $getmem{$addr}\n";
                }
                else {
                    $totalmem -= $sizeataddr{$addr};
                    if($trace) {
                        push @res, "FREE: malloc at $getmem{$addr} is freed again at $source:$linenum\n";
                        push @res, "FREE: $sizeataddr{$addr} bytes freed, left allocated: $totalmem bytes\n";
                    }

                    newtotal($totalmem);
                    $frees++;

                    $sizeataddr{$addr}=-1; # set -1 to mark as freed
                    $getmem{$addr}="$source:$linenum";

                }
            }
            elsif($function =~ /malloc\((\d*)\) = 0x([0-9a-f]*)/) {
                $size = $1;
                $addr = $2;

                if($sizeataddr{$addr} && $sizeataddr{$addr}>0) {
                    # this means weeeeeirdo
                    push @res, "Mixed debug compile ($source:$linenum at line $lnum), rebuild curl now\n";
                    push @res, "We think $sizeataddr{$addr} bytes are already allocated at that memory address: $addr!\n";
                }

                $sizeataddr{$addr} = $size;
                $totalmem += $size;
                $memsum += $size;

                if($trace) {
                    push @res, "MALLOC: malloc($size) at $source:$linenum makes totally $totalmem bytes\n";
                }

                newtotal($totalmem);
                $mallocs++;

                $getmem{$addr}="$source:$linenum";
            }
            elsif($function =~ /calloc\((\d*),(\d*)\) = 0x([0-9a-f]*)/) {
                $size = $1 * $2;
                $addr = $3;

                my $arg1 = $1;
                my $arg2 = $2;

                if($sizeataddr{$addr} && $sizeataddr{$addr}>0) {
                    # this means weeeeeirdo
                    push @res, "Mixed debug compile ($source:$linenum at line $lnum), rebuild curl now\n";
                    push @res, "We think $sizeataddr{$addr} bytes are already allocated at that memory address: $addr!\n";
                }

                $sizeataddr{$addr} = $size;
                $totalmem += $size;
                $memsum += $size;

                if($trace) {
                    push @res, "CALLOC: calloc($arg1,$arg2) at $source:$linenum makes totally $totalmem bytes\n";
                }

                newtotal($totalmem);
                $callocs++;

                $getmem{$addr}="$source:$linenum";
            }
            elsif($function =~ /realloc\((\(nil\)|0x([0-9a-f]*)), (\d*)\) = 0x([0-9a-f]*)/) {
                my ($oldaddr, $newsize, $newaddr) = ($2, $3, $4);
                my $oldsize = '-';

                if($oldaddr) {
                    $oldsize = $sizeataddr{$oldaddr} ? $sizeataddr{$oldaddr} : 0;

                    $totalmem -= $oldsize;
                    if($trace) {
                    }
                    $sizeataddr{$oldaddr} = 0;

                    $getmem{$oldaddr} = "";
                }

                $totalmem += $newsize;
                $memsum += $newsize;
                $sizeataddr{$newaddr} = $newsize;

                if($trace) {
                    push @res, "REALLOC: $oldsize less bytes and $newsize more bytes ($source:$linenum)\n";
                }

                newtotal($totalmem);
                $reallocs++;

                $getmem{$newaddr}="$source:$linenum";
            }
            elsif($function =~ /strdup\(0x([0-9a-f]*)\) \((\d*)\) = 0x([0-9a-f]*)/) {
                # strdup(a5b50) (8) = df7c0

                $dup = $1;
                $size = $2;
                $addr = $3;
                $getmem{$addr} = "$source:$linenum";
                $sizeataddr{$addr} = $size;

                $totalmem += $size;
                $memsum += $size;

                if($trace) {
                    push @res, "STRDUP: $size bytes at $getmem{$addr}, makes totally: $totalmem bytes\n";
                }

                newtotal($totalmem);
                $strdups++;
            }
            elsif($function =~ /wcsdup\(0x([0-9a-f]*)\) \((\d*)\) = 0x([0-9a-f]*)/) {
                # wcsdup(a5b50) (8) = df7c0

                $dup = $1;
                $size = $2;
                $addr = $3;
                $getmem{$addr}="$source:$linenum";
                $sizeataddr{$addr}=$size;

                $totalmem += $size;
                $memsum += $size;

                if($trace) {
                    push @res, "WCSDUP: $size bytes at $getmem{$addr}, makes totally: $totalmem bytes\n";
                }

                newtotal($totalmem);
                $wcsdups++;
            }
            else {
                push @res, "Not recognized input line: $function\n";
            }
        }
        # FD url.c:1282 socket() = 5
        elsif($_ =~ /^FD ([^ ]*):(\d*) (.*)/) {
            # generic match for the filename+linenumber
            $source = $1;
            $linenum = $2;
            $function = $3;

            if($function =~ /socket\(\) = (\d*)/) {
                $filedes{$1} = 1;
                $getfile{$1} = "$source:$linenum";
                $openfile++;
                $sockets++; # number of socket() calls
            }
            elsif($function =~ /socketpair\(\) = (\d*) (\d*)/) {
                $filedes{$1} = 1;
                $getfile{$1} = "$source:$linenum";
                $openfile++;
                $filedes{$2} = 1;
                $getfile{$2} = "$source:$linenum";
                $openfile++;
            }
            elsif($function =~ /accept\(\) = (\d*)/) {
                $filedes{$1} = 1;
                $getfile{$1} = "$source:$linenum";
                $openfile++;
            }
            elsif($function =~ /sclose\((\d*)\)/) {
                if($filedes{$1} != 1) {
                    push @res, "Close without open: $line\n";
                }
                else {
                    $filedes{$1}=0; # closed now
                    $openfile--;
                }
            }
        }
        # FILE url.c:1282 fopen("blabla") = 0x5ddd
        elsif($_ =~ /^FILE ([^ ]*):(\d*) (.*)/) {
            # generic match for the filename+linenumber
            $source = $1;
            $linenum = $2;
            $function = $3;

            if($function =~ /f[d]*open\(\"(.*)\",\"([^\"]*)\"\) = (\(nil\)|0x([0-9a-f]*))/) {
                if($3 eq "(nil)") {
                    ;
                }
                else {
                    $fopen{$4} = 1;
                    $fopenfile{$4} = "$source:$linenum";
                    $fopens++;
                }
            }
            # fclose(0x1026c8)
            elsif($function =~ /fclose\(0x([0-9a-f]*)\)/) {
                if(!$fopen{$1}) {
                    push @res, "fclose() without fopen(): $line\n";
                }
                else {
                    $fopen{$1} = 0;
                    $fopens--;
                }
            }
        }
        # GETNAME url.c:1901 getnameinfo()
        elsif($_ =~ /^GETNAME ([^ ]*):(\d*) (.*)/) {
            # not much to do
        }

        # ADDR url.c:1282 getaddrinfo() = 0x5ddd
        elsif($_ =~ /^ADDR ([^ ]*):(\d*) (.*)/) {
            # generic match for the filename+linenumber
            $source = $1;
            $linenum = $2;
            $function = $3;

            if($function =~ /getaddrinfo\(\) = (\(nil\)|0x([0-9a-f]*))/) {
                my $add = $1;
                if($add eq "(nil)") {
                    ;
                }
                else {
                    $addrinfo{$add} = 1;
                    $addrinfofile{$add} = "$source:$linenum";
                    $addrinfos++;
                }
                if($trace) {
                    push @res, "GETADDRINFO ($source:$linenum)\n";
                }
            }
            # fclose(0x1026c8)
            elsif($function =~ /freeaddrinfo\((0x[0-9a-f]*)\)/) {
                my $addr = $1;
                if(!$addrinfo{$addr}) {
                    push @res, "freeaddrinfo() without getaddrinfo(): $line\n";
                }
                else {
                    $addrinfo{$addr} = 0;
                    $addrinfos--;
                }
                if($trace) {
                    push @res, "FREEADDRINFO ($source:$linenum)\n";
                }
            }

        }
        else {
            push @res, "Not recognized prefix line: $line\n";
        }
    }
    close($fileh);

    if($totalmem) {
        push @res, "Leak detected: memory still allocated: $totalmem bytes\n";

        for(keys %sizeataddr) {
            $addr = $_;
            $size = $sizeataddr{$addr};
            if($size > 0) {
                push @res, "At $addr, there is $size bytes.\n";
                push @res, " allocated by $getmem{$addr}\n";
            }
        }
    }

    if($openfile) {
        for(keys %filedes) {
            if($filedes{$_} == 1) {
                push @res, "Open file descriptor created at $getfile{$_}.\n";
            }
        }
    }

    if($fopens) {
        push @res, "Open FILE handles left at:\n";
        for(keys %fopen) {
            if($fopen{$_} == 1) {
                push @res, "fopen() called at $fopenfile{$_}.\n";
            }
        }
    }

    if($addrinfos) {
        push @res, "IPv6-style name resolve data left at:\n";
        for(keys %addrinfofile) {
            if($addrinfo{$_} == 1) {
                push @res, "getaddrinfo() called at $addrinfofile{$_}.\n";
            }
        }
    }

    if($verbose) {
        push @res,
            "Mallocs: $mallocs\n",
            "Reallocs: $reallocs\n",
            "Callocs: $callocs\n",
            "Strdups: $strdups\n",
            "Wcsdups: $wcsdups\n",
            "Frees: $frees\n",
            "Sockets: $sockets\n",
            "Allocations: ".($mallocs + $callocs + $reallocs + $strdups + $wcsdups)."\n",
            "Operations: ".($mallocs + $callocs + $reallocs + $strdups + $wcsdups + $sockets)."\n",
            "Maximum allocated: $maxmem\n",
            "Total allocated: $memsum\n";
    }

    return @res;
}

1;
