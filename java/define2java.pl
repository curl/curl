#!/usr/bin/perl

open(GCC, "gcc -E ../include/curl/curl.h|");

while(<GCC>) {
    if($_ =~ /(CURLOPT_(.*)) += (.*)/) {
        $var= $1;
        $expr = $3;
        $f=$3;
        if($expr =~ / *(\d+) *\+ *(\d+)/) {
            $expr = $1+$2;
        }

        # nah, keep the CURL prefix to make them look like other
        # languages' defines
        # $var =~ s/^CURL//g;

        print "  public static final int $var = $expr;\n";
    }
}

close(GCC);
