#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Input: number of seconds to run.
#
# 1. Figure out all existing command line options
# 2. Generate random command line using supported options
# 3. Run the command line
# 4. Verify that it does not return an unexpected return code
# 5. Iterate until the time runs out
#
# Do the same with regular command lines as well as reading the options from a
# -K config file
#
# BEWARE: this may create a large amount of files using random names in the
# directory where it runs.
#

use strict;
use warnings;

my $curl = "../src/curl";
my $url = "localhost:7777"; # not listening to this

my $seconds = $ARGV[0];
if($ARGV[1]) {
    $curl = $ARGV[1];
}

if(!$seconds) {
    $seconds = 10;
}
print "Run $curl for $seconds seconds\n";

my @opt;
my %arg;
my %uniq;
my %allrc;

my $totalargs = 0;
my $totalcmds = 0;

my $counter = 0xabcdef + time();
sub getnum {
    my ($max) = @_;
    return int(rand($max));
}

sub storedata {
    my ($short, $long, $arg) = @_;
    push @opt, "-$short" if($short);
    push @opt, "--$long";

    if($arg =~ /^</) {
        # these take an argument
        $arg{"-$short"} = $arg if($short);
        $arg{"--$long"} = $arg;
    }
}

sub getoptions {
    my @all = `$curl --help all`;
    for my $o (@all) {
        chomp $o;
        if($o =~ /^ -(.), --([^ ]*) (.*)/) {
            storedata($1, $2, $3);
        }
        elsif($o =~ /^     --([^ ]*) (.*)/) {
            storedata("", $1, $2);
        }
    }
}

# this adds a fake randomly generated command line option
sub addarg {
    my $nice = "abcdefhijklmnopqrstuvwqxyz".
        "ABCDEFHIJKLMNOPQRSTUVWQXYZ".
        "0123456789-";
    my $len = getnum(20) + 2;
    my $o;
    for (1 .. $len) {
        $o .= substr($nice, getnum(length($nice)), 1);
    }
    return "--$o";
}

sub randarg {
    my $nice = "abcdefhijklmnopqrstuvwqxyz".
        "ABCDEFHIJKLMNOPQRSTUVWQXYZ".
        "0123456789".
        ",-?#$%!@ ";
    my $len = getnum(20);
    my $o = '';
    for (1 .. $len) {
        $o .= substr($nice, getnum(length($nice)), 1);
    }
    return "\'$o\'";
}

getoptions();

my $nopts = scalar(@opt);

my %useropt = (
    '-U' => 1,
    '-u' => 1,
    '--user' => 1,
    '--proxy-user' => 1);

my %commonrc = (
    '0' => 1,
    '1' => 1,
    '2' => 1,
    '26' => 1,
    );


sub runone {
    my $a;
    my $nargs = getnum(60) + 1;

    $totalargs += $nargs;
    $totalcmds++;
    for (1 .. $nargs) {
        my $o = getnum($nopts);
        my $option = $opt[$o];
        my $ar = "";
        $uniq{$option}++;
        if($arg{$option}) {
            $ar = " ".randarg();

            if($useropt{$option}) {
                # append password to avoid prompting
                $ar .= ":".randarg();
            }
        }
        $a .= sprintf(" %s%s", $option, $ar);
    }
    if(getnum(100) < 15) {
        # add a fake arg
        $a .= " ".addarg();
    }

    my $cmd="$curl$a $url";

    my $rc = system("$cmd >curl-output 2>&1 </dev/null -M 0.1") >> 8;
    #my $rc = system("valgrind -q $cmd >/dev/null 2>&1 </dev/null -M 0.1") >> 8;

    $allrc{$rc}++;

    #print "CMD: $cmd\n";
    if(!$commonrc{$rc}) {
        print "CMD: $cmd\n";
        print "RC: $rc\n";
        print "== curl-output == \n";
        open(D, "<curl-output");
        my @out = <D>;
        print @out;
        close(D);
        exit;
    }
}

sub runconfig {
    my $a;
    my $nargs = getnum(80) + 1;

    open(C, ">config");

    $totalargs += $nargs;
    $totalcmds++;
    for (1 .. $nargs) {
        my $o = getnum($nopts);
        my $option = $opt[$o];
        my $ar = "";
        $uniq{$option} = 0 if(!exists $uniq{$option});
        $uniq{$option}++;
        if($arg{$option}) {
            $ar = " ".randarg();

            if($useropt{$option}) {
                # append password
                $ar .= ":".randarg();
            }
        }
        $a .= sprintf("\n%s%s", $option, $ar);
    }
    if(getnum(100) < 15) {
        # add a fake arg
        $a .= "\n".addarg();
    }

    print C "$a\n";
    close(C);

    my $cmd="$curl -K config $url";

    my $rc = system("$cmd >curl-output 2>&1 </dev/null -M 0.1") >> 8;

    $allrc{$rc}++;

    if(!$commonrc{$rc}) {
        print "CMD: $cmd\n";
        print "RC: $rc\n";
        print "== config == \n";
        open(D, "<config");
        my @all = <D>;
        print @all;
        close(D);
        print "\n== curl-output == \n";
        open(D, "<curl-output");
        my @out = <D>;
        print @out;
        close(D);
        exit 2;
    }
}

# run curl command lines using -K
my $end = time() + $seconds/2;
my $c = 0;
print "Running command lines\n";
do {
    runconfig();
    $c++;
} while(time() <= $end);
print "$c command lines\n";

# run curl command lines
$end = time() + $seconds/2;
$c = 0;
print "Running config lines\n";
do {
    runone();
    $c++;
} while(time() <= $end);

print "$c config line uses\n";

print "Recorded exit codes:\n";
for my $rc (keys %allrc) {
    printf " %2d: %d times\n", $rc, $allrc{$rc};
}
printf "Number or command lines tested:\n".
    " $totalcmds (%.1f/second)\n", $totalcmds/$seconds;
printf "Number or command line options tested:\n".
    " $totalargs (average %.1f per command line)\n",
    $totalargs/$totalcmds;
printf "Number or different options tested:\n".
    " %u out of %u\n", scalar(keys %uniq), $nopts;
