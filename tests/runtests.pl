#!/usr/bin/env perl
# $Id$
#
# Main curl test script, in perl to run on more platforms
#
#######################################################################
# These should be the only variables that might be needed to get edited:

use strict;

@INC=(@INC, $ENV{'srcdir'}, ".");

require "stunnel.pm"; # stunnel functions
require "getpart.pm"; # array functions

my $srcdir = $ENV{'srcdir'} || '.';
my $HOSTIP="127.0.0.1";
my $HOSTPORT=8999; # bad name, but this is the HTTP server port
my $HTTPSPORT=8433; # this is the HTTPS server port
my $FTPPORT=8921;  # this is the FTP server port
my $FTPSPORT=8821;  # this is the FTPS server port
my $CURL="../src/curl"; # what curl executable to run on the tests
my $LOGDIR="log";
my $TESTDIR="data";
my $SERVERIN="$LOGDIR/server.input"; # what curl sent the server
my $CURLLOG="$LOGDIR/curl.log"; # all command lines run
my $FTPDCMD="$LOGDIR/ftpserver.cmd"; # copy ftp server instructions here

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

my $HTTPPIDFILE=".http.pid";
my $HTTPSPIDFILE=".https.pid";
my $FTPPIDFILE=".ftp.pid";
my $FTPSPIDFILE=".ftps.pid";

# invoke perl like this:
my $perl="perl -I$srcdir";

# this gets set if curl is compiled with memory debugging:
my $memory_debug=0;

# name of the file that the memory debugging creates:
my $memdump="memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="../memanalyze.pl";

my $checkstunnel = &checkstunnel;

my $ssl_version; # set if libcurl is built with SSL support

#######################################################################
# variables the command line options may set
#

my $short;
my $verbose;
my $debugprotocol;
my $anyway;
my $gdbthis;      # run test case with gdb debugger
my $keepoutfiles; # keep stdout and stderr files after tests
my $listonly;     # only list the tests

my $pwd;          # current working directory

chomp($pwd = `pwd`);

#######################################################################
# Return the pid of the server as found in the given pid file
#
sub serverpid {
    my $PIDFILE = $_[0];
    open(PFILE, "<$PIDFILE");
    my $PID=<PFILE>;
    close(PFILE);
    return $PID;
}

#######################################################################
# stop the given test server
#
sub stopserver {
    my $PIDFILE = $_[0];
    # check for pidfile
    if ( -f $PIDFILE ) {
        my $PID = serverpid($PIDFILE);

        my $res = kill (9, $PID); # die!
        unlink $PIDFILE; # server is killed

        if($res && $verbose) {
            print "Test server pid $PID signalled to die\n";
        }
        elsif($verbose) {
            print "Test server pid $PID didn't exist\n";
        }
    }
}

#######################################################################
# check the given test server if it is still alive
#
sub checkserver {
    my ($pidfile)=@_;
    my $RUNNING=0;
    my $PID=0;

    # check for pidfile
    if ( -f $pidfile ) {
        $PID=serverpid($pidfile);
        if ($PID ne "" && kill(0, $PID)) {
            $RUNNING=1;
        }
        else {
            $RUNNING=0;
            $PID = -$PID; # negative means dead process
        }
    }
    else {
        $RUNNING=0;
    }
    return $PID
}

#######################################################################
# start the http server, or if it already runs, verify that it is our
# test server on the test-port!
#
sub runhttpserver {
    my $verbose = $_[0];
    my $RUNNING;
    my $pid;

    $pid = checkserver ($HTTPPIDFILE);

    # verify if our/any server is running on this port
    my $data=`$CURL --silent -i $HOSTIP:$HOSTPORT/verifiedserver`;

    if ( $data =~ /WE ROOLZ(: |)(\d*)/ ) {
        if($2) {
            $pid = 0+$2;
        }

        if(!$pid) {
            print "Test server already running with unknown pid! Use it...\n";
            return;
        }

        if($verbose) {
            print "Test server already running with pid $pid, killing it...\n";
        }
    }
    elsif($data ne "") {
        print "GOT: $data\n";
        print "An alien HTTP server is running on port $HOSTPORT\n",
        "Edit runtests.pl to use another port and rerun the test script\n";
        exit;
    }
    else {
        if($verbose) {
            print "No server running, start it\n";
        }
    }

    if($pid) {
        my $res = kill (9, $pid); # die!
        if(!$res) {
            print "Failed to kill our HTTP test server, do it manually and",
            " restart the tests.\n";
            exit;
        }
        sleep(2);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/httpserver.pl $flag $HOSTPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }

}

#######################################################################
# start the https server (or rather, tunnel) if needed
#
sub runhttpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    my $PID=checkserver($HTTPSPIDFILE );

    if($PID > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "kills off running stunnel at $PID\n";
        }
        stopserver($HTTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/httpsserver.pl $flag -r $HOSTPORT $HTTPSPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }
}

#######################################################################
# start the ftp server if needed
#
sub runftpserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    # check for pidfile
    my $pid = checkserver ($FTPPIDFILE );

    if ($pid <= 0) {
        my $flag=$debugprotocol?"-v ":"";

        # verify that our server is NOT running on this port:
        my $data=`$CURL --silent -i ftp://$HOSTIP:$FTPPORT/verifiedserver`;

        if ( $data =~ /WE ROOLZ/ ) {
            print "A previous FTP server session is already running and we ",
            "can't kill it!\n";
            exit;
        }

        my $cmd="$perl $srcdir/ftpserver.pl $flag $FTPPORT &";
        if($verbose) {
            print "CMD: $cmd\n";
        }
        system($cmd);
    }
    else {
        if($verbose) {
            print "ftpd ($pid) is already running\n";
        }

        # verify that our server is one one running on this port:
        my $data=`$CURL --silent -i ftp://$HOSTIP:$FTPPORT/verifiedserver`;

        if ( $data !~ /WE ROOLZ/ ) {
            print "Another FTP server is running on port $FTPPORT\n",
            "Edit runtests.pl to use another FTP port and rerun the ",
            "test script\n";
            exit;
        }

        if($verbose) {
            print "The running FTP server has been verified to be our server\n";
        }
    }
}

#######################################################################
# start the ftps server (or rather, tunnel) if needed
#
sub runftpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    my $PID=checkserver($FTPSPIDFILE );

    if($PID > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "kills off running stunnel at $PID\n";
        }
        stopserver($FTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/ftpsserver.pl $flag -r $FTPPORT $FTPSPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }
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
    # filter off patterns _before_ this comparison!
    my ($firstref, $secondref)=@_;

    my $result = compareparts($firstref, $secondref);

    if(!$short && $result) {
        print showdiff($firstref, $secondref);
    }
    return $result;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub displaydata {

    unlink($memdump); # remove this if there was one left

    my $version=`$CURL -V`;
    chomp $version;

    my $curl = $version;

    $curl =~ s/^(.*)(libcurl.*)/$1/g;
    my $libcurl = $2;

    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    print "********* System characteristics ******** \n",
    "* $curl\n",
    "* $libcurl\n",
    "* Host: $hostname",
    "* System: $hosttype";

    if($libcurl =~ /SSL/i) {
        $ssl_version=1;
    }

    if( -r $memdump) {
        # if this exists, curl was compiled with memory debugging
        # enabled and we shall verify that no memory leaks exist
        # after each and every test!
        $memory_debug=1;
    }
    printf("* Memory debugging: %s\n", $memory_debug?"ON":"OFF");
    printf("* HTTPS server:     %s\n", $checkstunnel?"ON":"OFF");
    printf("* FTPS server:      %s\n", $checkstunnel?"ON":"OFF");
    printf("* libcurl SSL:      %s\n", $ssl_version?"ON":"OFF");
    print "***************************************** \n";
}

#######################################################################
# Run a single specified test case
#

sub singletest {
    my $testnum=$_[0];

    # load the test case file definition
    if(loadtest("${TESTDIR}/test${testnum}")) {
        if($verbose) {
            # this is not a test
            print "$testnum doesn't look like a test case!\n";
        }
        return -1;
    }

    # extract the reply data
    my @reply = getpart("reply", "data");
    my @replycheck = getpart("reply", "datacheck");

    if (@replycheck) {
        # we use this file instead to check the final output against
        @reply=@replycheck;
    }

    # curl command to run
    my @curlcmd= getpart("client", "command");

    # this is the valid protocol blurb curl should generate
    my @protocol= getpart("verify", "protocol");

    # redirected stdout/stderr to these files
    $STDOUT="$LOGDIR/stdout$testnum";
    $STDERR="$LOGDIR/stderr$testnum";

    # if this section exists, we verify that the stdout contained this:
    my @validstdout = getpart("verify", "stdout");

    # if this section exists, we verify upload
    my @upload = getpart("verify", "upload");

    # if this section exists, it is FTP server instructions:
    my @ftpservercmd = getpart("server", "instruction");

    my $CURLOUT="$LOGDIR/curl$testnum.out"; # curl output if not stdout

    # name of the test
    my @testname= getpart("client", "name");

    print "test $testnum...";
    if(!$short) {
        my $name = $testname[0];
        $name =~ s/\n//g;
        print "[$name]\n";
    }

    if($listonly) {
        return 0; # look successful
    }

    # remove previous server output logfile
    unlink($SERVERIN);

    if(@ftpservercmd) {
        # write the instructions to file
        writearray($FTPDCMD, \@ftpservercmd);
    }

    # get the command line options to use
    my ($cmd, @blaha)= getpart("client", "command");

    # make some nice replace operations
    $cmd =~ s/\n//g; # no newlines please
    $cmd =~ s/%HOSTIP/$HOSTIP/g;
    $cmd =~ s/%HOSTPORT/$HOSTPORT/g;
    $cmd =~ s/%HTTPSPORT/$HTTPSPORT/g;
    $cmd =~ s/%FTPPORT/$FTPPORT/g;
    $cmd =~ s/%FTPSPORT/$FTPSPORT/g;
    $cmd =~ s/%SRCDIR/$srcdir/g;
    $cmd =~ s/%PWD/$pwd/g;

    #$cmd =~ s/%HOSTNAME/$HOSTNAME/g;

    if($memory_debug) {
        unlink($memdump);
    }

    my @inputfile=getpart("client", "file");
    if(@inputfile) {
        # we need to generate a file before this test is invoked
        my %hash = getpartattr("client", "file");

        my $filename=$hash{'name'};
        if(!$filename) {
            print "ERROR: section client=>file has no name attribute!\n";
            exit;
        }
        writearray($filename, \@inputfile);
    }

    my %cmdhash = getpartattr("client", "command");

    my $out="";

    if($cmdhash{'option'} eq "no-output") {
        #print "*** We don't slap on --output\n";
    }
    else {
        if (!@validstdout) {
            $out="--output $CURLOUT ";
        }
    }

    # run curl, add -v for debug information output
    my $cmdargs="$out--include -v $cmd";

    my @stdintest = getpart("client", "stdin");

    if(@stdintest) {
        my $stdinfile="$LOGDIR/stdin-for-$testnum";
        writearray($stdinfile, \@stdintest);

        $cmdargs .= " <$stdinfile";
    }
    my $CMDLINE="$CURL $cmdargs >$STDOUT 2>$STDERR";

    if($verbose) {
        print "$CMDLINE\n";
    }

    print CMDLOG "$CMDLINE\n";

    my $res;
    # run the command line we built
    if($gdbthis) {
        open(GDBCMD, ">log/gdbcmd");
        print GDBCMD "set args $cmdargs\n";
        print GDBCMD "show args\n";
        close(GDBCMD);
        system("gdb $CURL -x log/gdbcmd");
        $res =0; # makes it always continue after a debugged run
    }
    else {
        $res = system("$CMDLINE");
        $res /= 256;
    }

    # remove the special FTP command file after each test!
    unlink($FTPDCMD);

    my @err = getpart("verify", "errorcode");
    my $errorcode = $err[0];

    if($errorcode || $res) {
        if($errorcode == $res) {
            if(!$short) {
                print " error OK";
            }
        }
        else {
            if(!$short) {
                print "curl returned $res, ".(0+$errorcode)." was expected\n";
            }
            print " error FAILED\n";
            return 1;
        }
    }

    if (@validstdout) {
        # verify redirected stdout
        my @actual = loadarray($STDOUT);

        $res = compare(\@actual, \@validstdout);
        if($res) {
            print " stdout FAILED\n";
            return 1;
        }
        if(!$short) {
            print " stdout OK";
        }
    }

    my %replyattr = getpartattr("reply", "data");
    if(!$replyattr{'nocheck'} &&
       @reply) {
        # verify the received data
        my @out = loadarray($CURLOUT);
        $res = compare(\@out, \@reply);
        if ($res) {
            print " data FAILED\n";
            return 1;
        }
        if(!$short) {
            print " data OK";
        }
    }

    if(@upload) {
        # verify uploaded data
        my @out = loadarray("$LOGDIR/upload.$testnum");
        $res = compare(\@out, \@upload);
        if ($res) {
            print " upload FAILED\n";
            return 1;
        }
        if(!$short) {
            print " upload OK";
        }
    }

    if(@protocol) {
        # verify the sent request
        my @out = loadarray($SERVERIN);

        # what to cut off from the live protocol sent by curl
        my @strip = getpart("verify", "strip");

        my @protstrip=@protocol;

        # check if there's any attributes on the verify/protocol section
        my %hash = getpartattr("verify", "protocol");

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($protstrip[$#protstrip]);
        }

        for(@strip) {
            # strip all patterns from both arrays
            @out = striparray( $_, \@out);
            @protstrip= striparray( $_, \@protstrip);
        }

        $res = compare(\@out, \@protstrip);
        if($res) {
            print " protocol FAILED\n";
            return 1;
        }
        if(!$short) {
            print " protocol OK";
        }
    }

    my @outfile=getpart("verify", "file");
    if(@outfile) {
        # we're supposed to verify a dynamicly generated file!
        my %hash = getpartattr("verify", "file");

        my $filename=$hash{'name'};
        if(!$filename) {
            print "ERROR: section verify=>file has no name attribute!\n";
            exit;
        }
        my @generated=loadarray($filename);

        $res = compare(\@generated, \@outfile);
        if($res) {
            print " output FAILED\n";
            return 1;
        }
        if(!$short) {
            print " output OK";
        }        
    }

    if(!$keepoutfiles) {
        # remove the stdout and stderr files
        unlink($STDOUT);
        unlink($STDERR);
        unlink($CURLOUT); # remove the downloaded results

        unlink("$LOGDIR/upload.$testnum");  # remove upload leftovers
    }

    unlink($FTPDCMD); # remove the instructions for this test

    if($memory_debug) {
        if(! -f $memdump) {
            print "\n** ALERT! memory debuggin without any output file?\n";
        }
        else {
            my @memdata=`$memanalyze < $memdump`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                print "\n** MEMORY FAILURE\n";
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
    if($short) {
        print "OK";
    }
    print "\n";

    return 0;
}

my %run;

##############################################################################
# This function makes sure the right set of server is running for the
# specified test case. This is a useful design when we run single tests as not
# all servers need to run then!

sub serverfortest {
    my ($testnum)=@_;

    if($testnum< 100) {
        # 0 - 99 is for HTTP
        if(!$run{'http'}) {
            runhttpserver($verbose);
            $run{'http'}=$HTTPPIDFILE;
        }
    }
    elsif($testnum< 200) {
        # 100 - 199 is for FTP
        if(!$run{'ftp'}) {
            runftpserver($verbose);
            $run{'ftp'}=$FTPPIDFILE;
        }
    }
    elsif($testnum< 300) {
        # 200 - 299 is for FILE, no server!
        $run{'file'}="moo";
    }
    elsif($testnum< 400) {
        # 300 - 399 is for HTTPS, two servers!

        if(!$checkstunnel || !$ssl_version) {
            # we can't run https tests without stunnel
            # or if libcurl is SSL-less
            return 1;
        }

        if(!$run{'http'}) {
            runhttpserver($verbose);
            $run{'http'}=$HTTPPIDFILE;
        }
        if(!$run{'https'}) {
            runhttpsserver($verbose);
            $run{'https'}=$HTTPSPIDFILE;
        }
    }
    elsif($testnum< 500) {
        # 400 - 499 is for FTPS, also two servers

        if(!$checkstunnel || !$ssl_version) {
            # we can't run https tests without stunnel
            # or if libcurl is SSL-less
            return 1;
        }
        if(!$run{'ftp'}) {
            runftpserver($verbose);
            $run{'ftp'}=$FTPPIDFILE;
        }
        if(!$run{'ftps'}) {
            runftpsserver($verbose);
            $run{'ftps'}=$FTPSPIDFILE;
        }
    }
    else {
        print "Bad test number, no server available\n";
        return 100;
    }
    sleep 1; # give a second for the server(s) to startup
    return 0; # ok
}

#######################################################################
# Check options to this test program
#

my $number=0;
my $fromnum=-1;
my @testthis;
do {
    if ($ARGV[0] eq "-v") {
        # verbose output
        $verbose=1;
    }
    elsif ($ARGV[0] eq "-c") {
        # use this path to curl instead of default        
        $CURL=$ARGV[1];
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-d") {
        # have the servers display protocol output 
        $debugprotocol=1;
    }
    elsif ($ARGV[0] eq "-g") {
        # run this test with gdb
        $gdbthis=1;
    }
    elsif($ARGV[0] eq "-s") {
        # short output
        $short=1;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-l") {
        # lists the test case names only
        $listonly=1;
    }
    elsif($ARGV[0] eq "-k") {
        # keep stdout and stderr files after tests
        $keepoutfiles=1;
    }
    elsif($ARGV[0] eq "-h") {
        # show help text
        print <<EOHELP
Usage: runtests.pl [options]
  -a       continue even if a test fails
  -d       display server debug info
  -g       run the test case with gdb
  -h       this help text
  -k       keep stdout and stderr files present after tests
  -l       list all test case names/descriptions
  -s       short output
  -v       verbose output
  [num]    like "5 6 9" or " 5 to 22 " to run those tests only
EOHELP
    ;
        exit;
    }
    elsif($ARGV[0] =~ /^(\d+)/) {
        $number = $1;
        if($fromnum >= 0) {
            for($fromnum .. $number) {
                push @testthis, $_;
            }
            $fromnum = -1;
        }
        else {
            push @testthis, $1;
        }
    }
    elsif($ARGV[0] =~ /^to$/i) {
        $fromnum = $number+1;
    }
} while(shift @ARGV);

if($testthis[0] ne "") {
    $TESTCASES=join(" ", @testthis);
}

#######################################################################
# Output curl version and host info being tested
#

if(!$listonly) {
    displaydata();
}

#######################################################################
# clear and create logging directory:
#
cleardir($LOGDIR);
mkdir($LOGDIR, 0777);

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^test([0-9]+)$/ && -f "$TESTDIR/$_" } readdir(DIR);
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
# Start the command line log
#
open(CMDLOG, ">$CURLLOG") ||
    print "can't log command lines to $CURLLOG\n";

#######################################################################
# The main test-loop
#

my $failed;
my $testnum;
my $ok=0;
my $total=0;
my $skipped=0;

foreach $testnum (split(" ", $TESTCASES)) {

    my $serverproblem = serverfortest($testnum);

    if($serverproblem) {
        # there's a problem with the server, don't run
        # this particular server, but count it as "skipped"
        $skipped++;
        next;
    }

    my $error = singletest($testnum);
    if(-1 != $error) {
        # valid test case number
        $total++;
    }
    if($error>0) {
        $failed.= "$testnum ";
        if(!$anyway) {
            # a test failed, abort
            print "\n - abort tests\n";
            last;
        }
    }
    elsif(!$error) {
        $ok++;
    }

    # loop for next test
}

#######################################################################
# Close command log
#
close(CMDLOG);

#######################################################################
# Tests done, stop the servers
#

for(keys %run) {
    stopserver($run{$_}); # the pid file is in the hash table
}

if($total) {
    printf("$ok tests out of $total reported OK: %d%%\n",
           $ok/$total*100);

    if($ok != $total) {
        print "These test cases failed: $failed\n";
    }
}
else {
    print "No tests were performed!\n";
}
if($skipped) {
    print "$skipped tests were skipped due to restraints\n";
}
if($total && ($ok != $total)) {
    exit 1;
}
