#!/usr/bin/perl
#
# Main curl test script, in perl to run on more platforms
#
#######################################################################
# These should be the only variables that might be needed to get edited:

$HOSTIP="127.0.0.1";
$HOSTPORT=8999;
$CURL="../src/curl";
$LOGDIR="log";
$TESTDIR="data";
$SERVERIN="$LOGDIR/server.input";
$CURLOUT="$LOGDIR/curl.out";

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
$TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

$PIDFILE=".server.pid";

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
        $PID = serverpid();
        $res = kill (9, $PID); # die!
        unlink $PIDFILE; # server is killed

        if($res) {
            print "TCP server signalled to die\n";
        }
    }
}

#######################################################################
# start the http server, or if it already runs, verify that it is our
# test server on the test-port!
#
sub runserver {
    # check for pidfile
    if ( -f $PIDFILE ) {
        $PID=serverpid();
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
        $data=`$CURL --silent -i $HOSTIP:$HOSTPORT/verifiedserver`;

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

    open(S, "<$source") ||
        return 1;
    open(D, "<$dest") ||
        return 1;

    # silly win-crap
    binmode S;
    binmode D;
    
    $m = 20;
    do {
        $snum = read(S, $s, $m);
        $dnum = read(D, $d, $m);
        if(($snum != $dnum) ||
           ($s ne $d)) {
            print "$source and $dest differ\n";
            last;
        }
    } while($snum);
    close(S);
    close(D);
    return 0;
}

#######################################################################
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $count;

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

    if ($strip ne "") {
        filteroff($first, $strip, "$LOGDIR/generated.tmp");
        filteroff($sec, $strip, "$LOGDIR/stored.tmp");
                
        $first="$LOGDIR/generated.tmp";
        $sec="$LOGDIR/stored.tmp";
    }

#    $res = system("cmp $first $sec");
#    $res /= 256;

    comparefiles($first, $sec);
    if ($res != 0) {
        print " $text FAILED";
        return 1;
    }

    print " $text OK";
    return 0;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub displaydata {
    my $version=`$CURL -V`;
    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    print "Running tests on:\n",
    "* $version",
    "* host $hostname",
    "* system $hosttype";
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
    $CURLCMD="$TESTDIR/command$NUMBER.txt";

    # this is the valid HTTP we should generate
    $HTTP="$TESTDIR/http$NUMBER.txt";

    # name of the test
    open(N, "<$TESTDIR/name$NUMBER.txt");
    $DESC=<N>;
    close(N);
    $DESC =~ s/[\r\n]//g;

    # redirected stdout/stderr here
    $STDOUT="$LOGDIR/stdout$NUMBER";
    $STDERR="$LOGDIR/stderr$NUMBER";

    # if this file exist, we verify that the stdout contained this:
    $VALIDOUT="$TESTDIR/stdout$NUMBER.txt";

    print "test $NUMBER...";
    if(!$short) {
        print "[$DESC]\n";
    }

    # get the command line options to use

    open(COMMAND, "<$CURLCMD");
    $cmd=<COMMAND>;
    chomp $cmd;
    close(COMMAND);

    # make some nice replace operations
    $cmd =~ s/%HOSTIP/$HOSTIP/g;
    $cmd =~ s/%HOSTPORT/$HOSTPORT/g;
    $cmd =~ s/%HOSTNAME/$HOSTNAME/g;

    # run curl, add -v for debug information output
    $CMDLINE="$CURL --output $CURLOUT --include --silent $cmd >$STDOUT 2>$STDERR";

    if($verbose) {
        print "$CMDLINE\n";
    }

    # run the command line we built
    $res = system("$CMDLINE");
    $res /= 256;

    if ($res != 0) {
        print "*** Failed to invoke curl for test $NUMBER ***\n",
        "*** [$DESC] ***\n",
        "*** The command line was: ***\n $CMDLINE\n";
        exit;
    }
    else {
        # verify the received data
        $res = compare($CURLOUT, $REPLY, "data");
        $res /= 256;

        if ($res) {
            exit;
        }

        # verify the sent request
        $res = compare($SERVERIN, $HTTP, "http",
                       "^(User-Agent:|--curl|Content-Type: multipart/form-data; boundary=).*\r\n");
        $res /= 256;

        # The strip pattern above is for stripping off User-Agent: since
        # that'll be different in all versions, and the lines in a
        # RFC1876-post that are randomly generated and therefore are doomed to
        # always differ!

        if($res) {
            exit;
        }

        if ( -r "$VALIDOUT" ) {

            $res = compare($STDOUT, $VALIDOUT, "stdout");
            $res /= 256;
            if($res) {
                exit;
            }
        }

        # remove the stdout and stderr files
        unlink($STDOUT);
        unlink($STDERR);

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

runserver();

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^command/ && -f "$TESTDIR/$_" } readdir(DIR);
    closedir DIR;

    $TESTCASES="";
    for(@cmds) {
        # cut off everything but the digits 
        $_ =~ s/[a-z\/\.]*//g;
        $TESTCASES .= " $_";
    }
}

#######################################################################
# The main test-loop
#

foreach $testnum (split(" ", $TESTCASES)) {

    singletest($testnum);

    # loop for next test
}

#######################################################################
# Tests done, stop the server
#

stopserver();
