#!/usr/bin/perl
#
# Example input:
#
# MEM mprintf.c:1094 malloc(32) = e5718
# MEM mprintf.c:1103 realloc(e5718, 64) = e6118
# MEM mprintf.c:1103 realloc(e6118, 128) = e6118
# MEM url.c:268 malloc(52208) = e6288
# MEM url.c:276 malloc(256) = f2e80
# MEM url.c:692 malloc(4520) = f2f88
# MEM hostip.c:122 malloc(9000) = f4138
# MEM mprintf.c:1094 malloc(32) = e5740
# MEM sendf.c:254 malloc(394) = f6628
# MEM sendf.c:232 free(f6520)
# MEM sendf.c:211 free(f6628)

do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
} while (shift @ARGV);


while(<STDIN>) {
    chomp $_;
    $line = $_;
    if($verbose) {
        print "IN: $line\n";
    }
    if($line =~ /^MEM ([^:]*):(\d*) (.*)/) {
        # generic match for the filename+linenumber
        $source = $1;
        $linenum = $2;
        $function = $3;

        if($function =~ /free\(([0-9a-f]*)/) {
            $addr = $1;
            if($sizeataddr{$addr} <= 0) {
                print "FREE ERROR: No memory allocated: $line\n";
            }
            else {
                $totalmem -= $sizeataddr{$addr};
                $sizeataddr{$addr}=0;
                $getmem{$addr}=""; # forget after a good free()
            }
        }
        elsif($function =~ /malloc\((\d*)\) = ([0-9a-f]*)/) {
            $size = $1;
            $addr = $2;
            $sizeataddr{$addr}=$size;
            $totalmem += $size;

            $getmem{$addr}="$source:$linenum";
        }
        elsif($function =~ /realloc\(([0-9a-f]*), (\d*)\) = ([0-9a-f]*)/) {
            $oldaddr = $1;
            $newsize = $2;
            $newaddr = $3;

            $totalmem -= $sizeataddr{$oldaddr};
            $sizeataddr{$oldaddr}=0;

            $totalmem += $newsize;
            $sizeataddr{$newaddr}=$newsize;

            $getmem{$oldaddr}="";
            $getmem{$newaddr}="$source:$linenum";
        }
        elsif($function =~ /strdup\(([0-9a-f]*)\) \((\d*)\) = ([0-9a-f]*)/) {
            # strdup(a5b50) (8) = df7c0

            $dup = $1;
            $size = $2;
            $addr = $3;
            $getmem{$addr}="$source:$linenum";
            $sizeataddr{$addr}=$size;

            $totalmem += $size;
        }
        else {
            print "Not recognized input line: $function\n";
        }        
    }
    else {
        print "Not recognized prefix line: $line\n";
    }
    if($verbose) {
        print "TOTAL: $totalmem\n";
    }
}

if(0 == $totalmem) {
    print "No leak found\n";
    exit;
}

print "Leak detected: memory still allocated: $totalmem bytes\n";

for(keys %sizeataddr) {
    $addr = $_;
    $size = $sizeataddr{$addr};
    if($size) {
        print "At $addr, there's $size bytes.\n";
        print " allocated by ".$getmem{$addr}."\n";
    }
}

