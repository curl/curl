#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
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
# Example input:
#
# MEM mprintf.c:1094 malloc(32) = e5718
# MEM mprintf.c:1103 realloc(e5718, 64) = e6118
# MEM sendf.c:232 free(f6520)

my $mallocs=0;
my $callocs=0;
my $reallocs=0;
my $strdups=0;
my $wcsdups=0;
my $showlimit;

while(1) {
    if($ARGV[0] eq "-v") {
        $verbose=1;
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-t") {
        $trace=1;
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-l") {
        # only show what alloc that caused a memlimit failure
        $showlimit=1;
        shift @ARGV;
    }
    else {
        last;
    }
}

my $maxmem;

sub newtotal {
    my ($newtot)=@_;
    # count a max here

    if($newtot > $maxmem) {
        $maxmem= $newtot;
    }
}

my $file = $ARGV[0];

if(! -f $file) {
    print "Usage: memanalyze.pl [options] <dump file>\n",
    "Options:\n",
    " -l  memlimit failure displayed\n",
    " -v  Verbose\n",
    " -t  Trace\n";
    exit;
}

open(FILE, "<$file");

if($showlimit) {
    while(<FILE>) {
        if(/^LIMIT.*memlimit$/) {
            print $_;
            last;
        }
    }
    close(FILE);
    exit;
}


my $lnum=0;
while(<FILE>) {
    chomp $_;
    $line = $_;
    $lnum++;
    if($line =~ /^LIMIT ([^ ]*):(\d*) (.*)/) {
        # new memory limit test prefix
        my $i = $3;
        my ($source, $linenum) = ($1, $2);
        if($trace && ($i =~ /([^ ]*) reached memlimit/)) {
            print "LIMIT: $1 returned error at $source:$linenum\n";
        }
    }
    elsif($line =~ /^MEM ([^ ]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /free\(0x([0-9a-f]*)/) {
            $addr = $1;
            if(!exists $sizeataddr{$addr}) {
                print "FREE ERROR: No memory allocated: $line\n";
            }
            elsif(-1 == $sizeataddr{$addr}) {
                print "FREE ERROR: Memory freed twice: $line\n";
                print "FREE ERROR: Previously freed at: ".$getmem{$addr}."\n";
            }
            else {
                $totalmem -= $sizeataddr{$addr};
                if($trace) {
                    print "FREE: malloc at ".$getmem{$addr}." is freed again at $source:$linenum\n";
                    printf("FREE: %d bytes freed, left allocated: $totalmem bytes\n", $sizeataddr{$addr});
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

            if($sizeataddr{$addr}>0) {
                # this means weeeeeirdo
                print "Mixed debug compile ($source:$linenum at line $lnum), rebuild curl now\n";
                print "We think $sizeataddr{$addr} bytes are already allocated at that memory address: $addr!\n";
            }

            $sizeataddr{$addr}=$size;
            $totalmem += $size;

            if($trace) {
                print "MALLOC: malloc($size) at $source:$linenum",
                " makes totally $totalmem bytes\n";
            }

            newtotal($totalmem);
            $mallocs++;

            $getmem{$addr}="$source:$linenum";
        }
        elsif($function =~ /calloc\((\d*),(\d*)\) = 0x([0-9a-f]*)/) {
            $size = $1*$2;
            $addr = $3;

            $arg1 = $1;
            $arg2 = $2;

            if($sizeataddr{$addr}>0) {
                # this means weeeeeirdo
                print "Mixed debug compile, rebuild curl now\n";
            }

            $sizeataddr{$addr}=$size;
            $totalmem += $size;

            if($trace) {
                print "CALLOC: calloc($arg1,$arg2) at $source:$linenum",
                " makes totally $totalmem bytes\n";
            }

            newtotal($totalmem);
            $callocs++;

            $getmem{$addr}="$source:$linenum";
        }
        elsif($function =~ /realloc\((\(nil\)|0x([0-9a-f]*)), (\d*)\) = 0x([0-9a-f]*)/) {
            my ($oldaddr, $newsize, $newaddr) = ($2, $3, $4);

            $totalmem -= $sizeataddr{$oldaddr};
            if($trace) {
                printf("REALLOC: %d less bytes and ", $sizeataddr{$oldaddr});
            }
            $sizeataddr{$oldaddr}=0;

            $totalmem += $newsize;
            $sizeataddr{$newaddr}=$newsize;

            if($trace) {
                printf("%d more bytes ($source:$linenum)\n", $newsize);
            }

            newtotal($totalmem);
            $reallocs++;

            $getmem{$oldaddr}="";
            $getmem{$newaddr}="$source:$linenum";
        }
        elsif($function =~ /strdup\(0x([0-9a-f]*)\) \((\d*)\) = 0x([0-9a-f]*)/) {
            # strdup(a5b50) (8) = df7c0

            $dup = $1;
            $size = $2;
            $addr = $3;
            $getmem{$addr}="$source:$linenum";
            $sizeataddr{$addr}=$size;

            $totalmem += $size;

            if($trace) {
                printf("STRDUP: $size bytes at %s, makes totally: %d bytes\n",
                       $getmem{$addr}, $totalmem);
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

            if($trace) {
                printf("WCSDUP: $size bytes at %s, makes totally: %d bytes\n",
                       $getmem{$addr}, $totalmem);
            }

            newtotal($totalmem);
            $wcsdups++;
        }
        else {
            print "Not recognized input line: $function\n";
        }
    }
    # FD url.c:1282 socket() = 5
    elsif($_ =~ /^FD ([^ ]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /socket\(\) = (\d*)/) {
            $filedes{$1}=1;
            $getfile{$1}="$source:$linenum";
            $openfile++;
        }
        elsif($function =~ /socketpair\(\) = (\d*) (\d*)/) {
            $filedes{$1}=1;
            $getfile{$1}="$source:$linenum";
            $openfile++;
            $filedes{$2}=1;
            $getfile{$2}="$source:$linenum";
            $openfile++;
        }
        elsif($function =~ /accept\(\) = (\d*)/) {
            $filedes{$1}=1;
            $getfile{$1}="$source:$linenum";
            $openfile++;
        }
        elsif($function =~ /sclose\((\d*)\)/) {
            if($filedes{$1} != 1) {
                print "Close without open: $line\n";
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
                $fopen{$4}=1;
                $fopenfile{$4}="$source:$linenum";
                $fopens++;
            }
        }
        # fclose(0x1026c8)
        elsif($function =~ /fclose\(0x([0-9a-f]*)\)/) {
            if(!$fopen{$1}) {
                print "fclose() without fopen(): $line\n";
            }
            else {
                $fopen{$1}=0;
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
            my $add = $2;
            if($add eq "(nil)") {
                ;
            }
            else {
                $addrinfo{$add}=1;
                $addrinfofile{$add}="$source:$linenum";
                $addrinfos++;
            }
            if($trace) {
                printf("GETADDRINFO ($source:$linenum)\n");
            }
        }
        # fclose(0x1026c8)
        elsif($function =~ /freeaddrinfo\(0x([0-9a-f]*)\)/) {
            if(!$addrinfo{$1}) {
                print "freeaddrinfo() without getaddrinfo(): $line\n";
            }
            else {
                $addrinfo{$1}=0;
                $addrinfos--;
            }
            if($trace) {
                printf("FREEADDRINFO ($source:$linenum)\n");
            }
        }

    }
    else {
        print "Not recognized prefix line: $line\n";
    }
}
close(FILE);

if($totalmem) {
    print "Leak detected: memory still allocated: $totalmem bytes\n";

    for(keys %sizeataddr) {
        $addr = $_;
        $size = $sizeataddr{$addr};
        if($size > 0) {
            print "At $addr, there's $size bytes.\n";
            print " allocated by ".$getmem{$addr}."\n";
        }
    }
}

if($openfile) {
    for(keys %filedes) {
        if($filedes{$_} == 1) {
            print "Open file descriptor created at ".$getfile{$_}."\n";
        }
    }
}

if($fopens) {
    print "Open FILE handles left at:\n";
    for(keys %fopen) {
        if($fopen{$_} == 1) {
            print "fopen() called at ".$fopenfile{$_}."\n";
        }
    }
}

if($addrinfos) {
    print "IPv6-style name resolve data left at:\n";
    for(keys %addrinfofile) {
        if($addrinfo{$_} == 1) {
            print "getaddrinfo() called at ".$addrinfofile{$_}."\n";
        }
    }
}

if($verbose) {
    print "Mallocs: $mallocs\n",
    "Reallocs: $reallocs\n",
    "Callocs: $callocs\n",
    "Strdups:  $strdups\n",
    "Wcsdups:  $wcsdups\n",
    "Frees: $frees\n",
    "Allocations: ".($mallocs + $callocs + $reallocs + $strdups + $wcsdups)."\n";

    print "Maximum allocated: $maxmem\n";
}
