#!/usr/bin/env perl
#
# Example input:
#
# MEM mprintf.c:1094 malloc(32) = e5718
# MEM mprintf.c:1103 realloc(e5718, 64) = e6118
# MEM sendf.c:232 free(f6520)

do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-t") {
        $trace=1;
    }
} while (shift @ARGV);

my $maxmem;

sub newtotal {
    my ($newtot)=@_;
    # count a max here

    if($newtot > $maxmem) {
        $maxmem= $newtot;
    }
}

while(<STDIN>) {
    chomp $_;
    $line = $_;

    if($line =~ /^MEM ([^:]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /free\(0x([0-9a-f]*)/) {
            $addr = $1;
            if($sizeataddr{$addr} == 0) {
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
                print "Fucked up debug compile, rebuild curl now\n";
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
        elsif($function =~ /realloc\(0x([0-9a-f]*), (\d*)\) = 0x([0-9a-f]*)/) {
            $oldaddr = $1;
            $newsize = $2;
            $newaddr = $3;

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
        else {
            print "Not recognized input line: $function\n";
        }        
    }
    # FD url.c:1282 socket() = 5
    elsif($_ =~ /^FD ([^:]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /socket\(\) = (\d*)/) {
            $filedes{$1}=1;
            $getfile{$1}="$source:$linenum";
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
    elsif($_ =~ /^FILE ([^:]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /fopen\(\"([^\"]*)\"\) = (\(nil\)|0x([0-9a-f]*))/) {
            if($2 eq "(nil)") {
                ;
            }
            else {
                $fopen{$3}=1;
                $fopenfile{$3}="$source:$linenum";
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
    # ADDR url.c:1282 getaddrinfo() = 0x5ddd
    elsif($_ =~ /^ADDR ([^:]*):(\d*) (.*)/) {
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
        }

        
    }
    else {
        print "Not recognized prefix line: $line\n";
    }
}

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
    "Strdups:  $strdups\n",
    "Frees: $frees\n";

    print "Maximum allocated: $maxmem\n";
}
