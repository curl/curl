#!/usr/bin/perl
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
                if(0 && $verbose) {
                    print "malloc at ".$getmem{$addr}." is freed again at $source:$linenum\n";
                }

                $totalmem -= $sizeataddr{$addr};

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

            if(0 && $verbose) {
                print "malloc($size) at $source:$linenum\n";
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
            $sizeataddr{$oldaddr}=0;

            $totalmem += $newsize;
            $sizeataddr{$newaddr}=$newsize;

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

if($verbose) {
    print "Mallocs: $mallocs\n",
    "Reallocs: $reallocs\n",
    "Strdups:  $strdups\n",
    "Frees: $frees\n";

    print "Maximum allocated: $maxmem\n";
}
