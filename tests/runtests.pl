#!/usr/bin/perl
# $Id$
#
# Main curl test script, in perl to run on more platforms
#
#######################################################################
# These should be the only variables that might be needed to get edited:

use strict;

my $HOSTIP="127.0.0.1";
my $HOSTPORT=8999;
my $CURL="../src/curl";
my $LOGDIR="log";
my $TESTDIR="data";
my $SERVERIN="$LOGDIR/server.input";
my $CURLOUT="$LOGDIR/curl.out";

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

my $PIDFILE=".server.pid";

# this gets set if curl is compiled with memory debugging:
my $memory_debug=0;

# name of the file that the memory debugging creates:
my $memdump="memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="../memanalyze.pl";

#######################################################################
# variables the command line options may set
#

my $short;
my $verbose;
my $anyway;

#######################################################################
# Return the pid of the http server as found in the pid file
#
sub serverpid {
    open(PFILE, "<$PIDFILE");
    my $PID=<PFILE>;
    close(PFILE);
    chomp $PID;
    return $PID;
}

#######################################################################
# stop the test http server
#
sub stopserver {
    # check for pidfile
    if ( -f $PIDFILE ) {
        my $PID = serverpid();
        my $res = kill (9, $PID); # die!
        unlink $PIDFILE; # server is killed

        if($res && $verbose) {
            print "TCP server signalled to die\n";
        }
    }
}

#######################################################################
# start the http server, or if it already runs, verify that it is our
# test server on the test-port!
#
sub runserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    # check for pidfile
    if ( -f $PIDFILE ) {
        my $PID=serverpid();
        if ($PID ne "" && kill(0, $PID)) {
            $STATUS="httpd (pid $PID) running";
            $RUNNING=1;
        }
        else {
            $STATUS="httpd (pid $PID?) not running";
            $RUNNING=0;
        }
    }
    else {
        $STATUS="httpd (no pid file) not running";
        $RUNNING=0;
    }

    if ($RUNNING != 1) {
        system("perl ./httpserver.pl $HOSTPORT &");
        sleep 1; # give it a little time to start
    }
    else {
        print "$STATUS\n";

        # verify that our server is one one running on this port:
        my $data=`$CURL --silent -i $HOSTIP:$HOSTPORT/verifiedserver`;

        if ( $data !~ /WE ROOLZ/ ) {
            print "Another HTTP server is running on port $HOSTPORT\n",
            "Edit runtests.pl to use another port and rerun the test script\n";
            exit;
        }

        print "The running HTTP server has been verified to be our server\n";
    }
}

#######################################################################
# This function compares two binary files and return non-zero if they
# differ
#
sub comparefiles {
    my $source=$_[0];
    my $dest=$_[1];
    my $res=0;

    open(S, "<$source") ||
        return 1;
    open(D, "<$dest") ||
        return 1;

    # silly win-crap
    binmode S;
    binmode D;
    
    my $m = 20;
    my ($snum, $dnum, $s, $d);
    do {
        $snum = read(S, $s, $m);
        $dnum = read(D, $d, $m);
        if(($snum != $dnum) ||
           ($s ne $d)) {
            print "$source and $dest differ\n";
            $res=1;
            last;
        }
    } while($snum);
    close(S);
    close(D);
    return $res;
}

#######################################################################
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $count;
    my $file;

    # Get all files
    opendir(DIR, $dir) ||
        return 0; # can't open dir
    while($file = readdir(DIR)) {
        if($file !~ /^\./) {
            unlink("$dir/$file");
            $count++;
        }
    }
    closedir DIR;
    return $count;
}

#######################################################################
# filter out the specified pattern from the given input file and store the
# results in the given output file
#
sub filteroff {
    my $infile=$_[0];
    my $filter=$_[1];
    my $ofile=$_[2];

    open(IN, "<$infile")
        || return 1;

    open(OUT, ">$ofile")
        || return 1;

    # print "FILTER: off $filter from $infile to $ofile\n";

    while(<IN>) {
        $_ =~ s/$filter//;
        print OUT $_;
    }
    close(IN);
    close(OUT);    
    return 0;
}

#######################################################################
# compare test results with the expected output, we might filter off
# some pattern that is allowed to differ, output test results
#

sub compare {
    # filter off the 4 pattern before compare!

    my $first=$_[0];
    my $sec=$_[1];
    my $text=$_[2];
    my $strip=$_[3];
    my $res;

    if ($strip ne "") {
        filteroff($first, $strip, "$LOGDIR/generated.tmp");
        filteroff($sec, $strip, "$LOGDIR/stored.tmp");
                
        $first="$LOGDIR/generated.tmp";
        $sec="$LOGDIR/stored.tmp";
    }

    $res = comparefiles($first, $sec);
    if ($res != 0) {
        print " $text FAILED";
        return 1;
    }

    if(!$short) {
        print " $text OK";
    }
    return 0;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub displaydata {

    unlink($memdump); # remove this if there was one left

    my $version=`$CURL -V`;
    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    print "Running tests on:\n",
    "* $version",
    "* Host: $hostname",
    "* System: $hosttype";

    if( -r $memdump) {
        # if this exists, curl was compiled with memory debugging
        # enabled and we shall verify that no memory leaks exist
        # after each and every test!
        $memory_debug=1;
    }
    printf("* Memory debugging: %s\n", $memory_debug?"ON":"OFF");

}

#######################################################################
# Run a single specified test case
#

sub singletest {
    my $NUMBER=$_[0];
    my $REPLY="${TESTDIR}/reply${NUMBER}.txt";

    if ( -f "$TESTDIR/reply${NUMBER}0001.txt" ) {
        # we use this file instead to check the final output against
        $REPLY="$TESTDIR/reply${NUMBER}0001.txt";
    }

    # curl command to run
    my $CURLCMD="$TESTDIR/command$NUMBER.txt";

    # this is the valid HTTP we should generate
    my $HTTP="$TESTDIR/http$NUMBER.txt";

    # name of the test
    open(N, "<$TESTDIR/name$NUMBER.txt") ||
        print "** Couldn't read name on test $NUMBER\n";
    my $DESC=<N>;
    close(N);
    $DESC =~ s/[\r\n]//g;

    # redirected stdout/stderr here
    $STDOUT="$LOGDIR/stdout$NUMBER";
    $STDERR="$LOGDIR/stderr$NUMBER";

    # if this file exist, we verify that the stdout contained this:
    my $VALIDOUT="$TESTDIR/stdout$NUMBER.txt";

    print "test $NUMBER...";
    if(!$short) {
        print "[$DESC]\n";
    }

    # get the command line options to use

    open(COMMAND, "<$CURLCMD");
    my $cmd=<COMMAND>;
    chomp $cmd;
    close(COMMAND);

    # make some nice replace operations
    $cmd =~ s/%HOSTIP/$HOSTIP/g;
    $cmd =~ s/%HOSTPORT/$HOSTPORT/g;
    #$cmd =~ s/%HOSTNAME/$HOSTNAME/g;

    if($memory_debug) {
        unlink($memdump);
    }

    my $out="";
    if ( ! -r "$VALIDOUT" ) {
        $out="--output $CURLOUT ";
    }

    # run curl, add -v for debug information output
    my $CMDLINE="$CURL $out--include --silent $cmd >$STDOUT 2>$STDERR";

    my $STDINFILE="$TESTDIR/stdin$NUMBER.txt";
    if(-f $STDINFILE) {
        $CMDLINE .= " < $STDINFILE";
    }

    if($verbose) {
        print "$CMDLINE\n";
    }

    # run the command line we built
    my $res = system("$CMDLINE");
    $res /= 256;

    if ($res != 0) {
        print "*** Failed to invoke curl for test $NUMBER ***\n",
        "*** [$DESC] ***\n",
        "*** The command line was: ***\n $CMDLINE\n";
        return 1;
    }
    else {
        if ( -r "$VALIDOUT" ) {
            # verify redirected stdout
            $res = compare($STDOUT, $VALIDOUT, "data");
            if($res) {
                return 1;
            }
        }
        else {
            if (! -r $REPLY) {
                print "** Missing reply data file for test $NUMBER",
                ", should be similar to $CURLOUT\n";
                return 1;            
            }

            # verify the received data
            $res = compare($CURLOUT, $REPLY, "data");
            if ($res) {
                return 1;
            }
        }

        if (! -r $HTTP) {
            print "** Missing HTTP file for test $NUMBER",
            ", should be similar to $SERVERIN\n";
            return 1;
        }

        # The strip pattern below is for stripping off User-Agent: since
        # that'll be different in all versions, and the lines in a
        # RFC1876-post that are randomly generated and therefore are doomed to
        # always differ!

        # verify the sent request
        $res = compare($SERVERIN, $HTTP, "http",
                       "^(User-Agent:|--curl|Content-Type: multipart/form-data; boundary=).*\r\n");
        if($res) {
            return 1;
        }

        # remove the stdout and stderr files
        unlink($STDOUT);
        unlink($STDERR);

        if($memory_debug) {
            if(! -f $memdump) {
                print "\n** ALERT! memory debuggin without any output file?\n";
            }
            else {
                my @memdata=`$memanalyze < $memdump`;
                my $leak=0;
                for(@memdata) {
                    if($_ =~ /Leak detected/) {
                        $leak=1;
                    }
                }
                if($leak) {
                    print "\n** MEMORY LEAK\n";
                    print @memdata;
                    return 1;
                }
                else {
                    if(!$short) {
                        print " memory OK";
                    }
                }
            }
        }
    }
    if($short) {
        print "OK";
    }
    print "\n";

    return 0;
}


#######################################################################
# Check options to this test program
#

do {
    if ($ARGV[0] eq "-v") {
        # verbose output
        $verbose=1;
    }
    elsif($ARGV[0] eq "-s") {
        # short output
        $short=1;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-h") {
        # show help text
        print <<EOHELP
Usage: runtests.pl [-h][-s][-v][numbers]
  -a       continue even if a test fails
  -h       this help text
  -s       short output
  -v       verbose output
  [num]    as string like "5 6 9" to run those tests only
EOHELP
    ;
        exit;
    }
    elsif($ARGV[0] =~ /^(\d+)/) {
        $TESTCASES=$ARGV[0]; # run these tests
    }
} while(shift @ARGV);

#######################################################################
# Output curl version and host info being tested
#

displaydata();

#######################################################################
# clear and create logging directory:
#
cleardir($LOGDIR);
mkdir($LOGDIR, 0777);

#######################################################################
# First, start the TCP server
#

runserver($verbose);

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^command/ && -f "$TESTDIR/$_" } readdir(DIR);
    closedir DIR;

    $TESTCASES=""; # start with no test cases

    # cut off everything but the digits 
    for(@cmds) {
        $_ =~ s/[a-z\/\.]*//g;
    }
    # the the numbers from low to high
    for(sort { $a <=> $b } @cmds) {
        $TESTCASES .= " $_";
    }
}

#######################################################################
# The main test-loop
#

my $testnum;
foreach $testnum (split(" ", $TESTCASES)) {

    if(singletest($testnum) && !$anyway) {
        # a test failed, abort
        print "\n - abort tests\n";
        last;
    }

    # loop for next test
}

#######################################################################
# Tests done, stop the server
#

stopserver();
