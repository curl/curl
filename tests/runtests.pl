#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# $Id$
###########################################################################
# These should be the only variables that might be needed to get edited:

use strict;
#use warnings;

@INC=(@INC, $ENV{'srcdir'}, ".");

require "getpart.pm"; # array functions

my $srcdir = $ENV{'srcdir'} || '.';
my $HOSTIP="127.0.0.1";
my $HOSTPORT=8999; # bad name, but this is the HTTP server port
my $HTTPSPORT=8433; # this is the HTTPS server port
my $FTPPORT=8921;  # this is the FTP server port
my $FTPSPORT=8821;  # this is the FTPS server port
my $CURL="../src/curl"; # what curl executable to run on the tests
my $DBGCURL=$CURL; #"../src/.libs/curl";  # alternative for debugging
my $LOGDIR="log";
my $TESTDIR="$srcdir/data";
my $LIBDIR="./libtest";
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

# this gets set if curl is compiled with debugging:
my $curl_debug=0;

# name of the file that the memory debugging creates:
my $memdump="memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="./memanalyze.pl";

my $stunnel = checkcmd("stunnel");
my $valgrind = checkcmd("valgrind");
my $gdb = checkcmd("gdb");

my $ssl_version; # set if libcurl is built with SSL support
my $large_file;  # set if libcurl is built with large file support
my $has_idn;     # set if libcurl is built with IDN support

my $skipped=0;  # number of tests skipped; reported in main loop
my %skipped;    # skipped{reason}=counter, reasons for skip
my @teststat;   # teststat[testnum]=reason, reasons for skip

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
my $postmortem;   # display detailed info about failed tests

my $pwd;          # current working directory

my %run;	  # running server

# torture test variables
my $torture;
my $tortnum;
my $tortalloc;

chomp($pwd = `pwd`);

# enable memory debugging if curl is compiled with it
$ENV{'CURL_MEMDEBUG'} = 1;
$ENV{'HOME'}=$pwd;

##########################################################################
# Clear all possible '*_proxy' environment variables for various protocols
# to prevent them to interfere with our testing!

my $protocol;
foreach $protocol (('ftp', 'http', 'ftps', 'https', 'gopher', 'no')) {
    my $proxy = "${protocol}_proxy";
    # clear lowercase version
    $ENV{$proxy}=undef;
    # clear uppercase version
    $ENV{uc($proxy)}=undef;
}

#######################################################################
# Check for a command in the PATH.
#
sub checkcmd {
    my ($cmd)=@_;
    my @paths=("/usr/sbin", "/usr/local/sbin", "/sbin", "/usr/bin",
               "/usr/local/bin", split(":", $ENV{'PATH'}));
    for(@paths) {
        if( -x "$_/$cmd") {
            return "$_/$cmd";
        }
    }
}

#######################################################################
# Return the pid of the server as found in the given pid file
#
sub serverpid {
    my $PIDFILE = $_[0];
    open(PFILE, "<$PIDFILE");
    my $PID=0+<PFILE>;
    close(PFILE);
    return $PID;
}

#######################################################################
# Memory allocation test and failure torture testing.
#
sub torture {
    my $testcmd = shift;
    my $gdbline = shift;

    # remove memdump first to be sure we get a new nice and clean one
    unlink($memdump);

    # First get URL from test server, ignore the output/result
    system($testcmd);

    print " CMD: $testcmd\n" if($verbose);

    # memanalyze -v is our friend, get the number of allocations made
    my $count=0;
    my @out = `$memanalyze -v $memdump`;
    for(@out) {
        if(/^Allocations: (\d+)/) {
            $count = $1;
            last;
        }
    }
    if(!$count) {
        print " found no allocs to make fail\n";
        return 0;
    }

    print " $count allocations to make fail\n";

    for ( 1 .. $count ) {
        my $limit = $_;
        my $fail;
        my $dumped_core;

        if($tortalloc && ($tortalloc != $limit)) {
            next;
        }

        print "Fail alloc no: $limit\r" if($verbose);

        # make the memory allocation function number $limit return failure
        $ENV{'CURL_MEMLIMIT'} = $limit;

        # remove memdump first to be sure we get a new nice and clean one
        unlink($memdump);

        print "**> Alloc number $limit is now set to fail <**\n" if($gdbthis);

        my $ret;
        if($gdbthis) {
            system($gdbline)
        }
        else {
            $ret = system($testcmd);
        }

        # Now clear the variable again
        $ENV{'CURL_MEMLIMIT'} = undef;

        if(-r "core") {
            # there's core file present now!
            print " core dumped!\n";
            $dumped_core = 1;
            $fail = 2;
        }

        # verify that it returns a proper error code, doesn't leak memory
        # and doesn't core dump
        if($ret & 255) {
            print " system() returned $ret\n";
            $fail=1;
        }
        else {
            my @memdata=`$memanalyze $memdump`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                print "** MEMORY FAILURE\n";
                print @memdata;
                print `$memanalyze -l $memdump`;
                $fail = 1;
            }
        }
        if($fail) {
            print " Failed on alloc number $limit in test.\n",
            " invoke with -t$limit to repeat this single case.\n";
            stopservers();
            exit 1;
        }
    }

    print "torture OK\n";
    return 0;

    #stopservers();
    #exit; # for now, we stop after these tests
}

#######################################################################
# stop the given test server
#
sub stopserver {
    my $pid = $_[0];
    # check for pidfile
    if ( -f $pid ) {
        my $PIDFILE = $pid;
        $pid = serverpid($PIDFILE);
        unlink $PIDFILE; # server is killed
    }
    elsif($pid <= 0) {
        return; # this is not a good pid
    }

    my $res = kill (9, $pid); # die!

    if($res && $verbose) {
        print "RUN: Test server pid $pid signalled to die\n";
    }
    elsif($verbose) {
        print "RUN: Test server pid $pid didn't exist\n";
    }
}

#######################################################################
# check the given test server if it is still alive
#
sub checkserver {
    my ($pidfile)=@_;
    my $pid=0;

    # check for pidfile
    if ( -f $pidfile ) {
        $pid=serverpid($pidfile);
        if ($pid ne "" && kill(0, $pid)) {
            return $pid;
        }
        else {
            return -$pid; # negative means dead process
        }
    }
    return 0;
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
    my $cmd = "$CURL -o log/verifiedserver http://$HOSTIP:$HOSTPORT/verifiedserver 2>/dev/null";
    print "CMD; $cmd\n" if ($verbose);
    my $res = system($cmd);

    $res >>= 8; # rotate the result
    my $data;

    print "RUN: curl command returned $res\n" if ($verbose);

    open(FILE, "<log/verifiedserver");
    my @file=<FILE>;
    close(FILE);
    $data=$file[0]; # first line

    if ( $data =~ /WE ROOLZ: (\d+)/ ) {
        $pid = 0+$1;
    }
    elsif($data || ($res != 7)) {
        print "RUN: Unknown HTTP server is running on port $HOSTPORT\n";
        return -2;
    }

    if($pid > 0) {
        my $res = kill (9, $pid); # die!
        if(!$res) {
            print "RUN: Failed to kill test HTTP server, do it manually and",
            " restart the tests.\n";
            exit;
        }
        sleep(1);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $dir=$ENV{'srcdir'};
    if($dir) {
        $flag .= "-d \"$dir\" ";
    }
    $cmd="$perl $srcdir/httpserver.pl $flag $HOSTPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }

    my $verified;
    for(1 .. 10) {
        # verify that our server is up and running:
        my $data=`$CURL --silent $HOSTIP:$HOSTPORT/verifiedserver 2>/dev/null`;

        if ( $data =~ /WE ROOLZ: (\d+)/ ) {
            $pid = 0+$1;
            $verified = 1;
            last;
        }
        else {
            if($verbose) {
                print STDERR "RUN: Retrying HTTP server existence in 3 sec\n";
            }
            sleep(3);
            next;
        }
    }
    if(!$verified) {
        print STDERR "RUN: failed to start our HTTP server\n";
        return -1;
    }

    if($verbose) {
        print "RUN: HTTP server is now verified to be our server\n";
    }

    return $pid;
}

#######################################################################
# start the https server (or rather, tunnel) if needed
#
sub runhttpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;

    if(!$stunnel) {
        return 0;
    }

    my $pid=checkserver($HTTPSPIDFILE );

    if($pid > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "RUN: kills off running stunnel at $pid\n";
        }
        stopserver($HTTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/httpsserver.pl $flag -s \"$stunnel\" -d $srcdir -r $HOSTPORT $HTTPSPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }
    sleep(1);

    for(1 .. 10) {
        $pid=checkserver($HTTPSPIDFILE);

        if($pid <= 0) {
            if($verbose) {
                print STDERR "RUN: waiting 3 sec for HTTPS server\n";
            }
            sleep(3);
        }
        else {
            last;
        }
    }

    return $pid;
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
        print "RUN: Check port $FTPPORT for our own FTP server\n"
            if ($verbose);

        my $time=time();
        # check if this is our server running on this port:
        my @data=`$CURL -m4 --silent ftp://$HOSTIP:$FTPPORT/verifiedserver 2>/dev/null`;
        my $line;

        # if this took more than 2 secs, we assume it "hung" on a weird server
        my $took = time()-$time;

        foreach $line (@data) {
            if ( $line =~ /WE ROOLZ: (\d+)/ ) {
                # this is our test server with a known pid!
                $pid = 0+$1;
            }
        }
        if(!$pid && $data[0]) {
            # this is not a known server
            print "RUN: Unknown server on our favourite FTP port: $FTPPORT\n";
            return -1;
        }
    }

    if($pid > 0) {
        print "RUN: Killing a previous server using pid $pid\n" if($verbose);
        my $res = kill (9, $pid); # die!
        if(!$res) {
            print "RUN: Failed to kill our FTP test server, do it manually and",
            " restart the tests.\n";
            return -1;
        }
        sleep(1);
    }

    # now (re-)start our server:
    my $flag=$debugprotocol?"-v ":"";
    $flag .= "-s \"$srcdir\"";
    my $cmd="$perl $srcdir/ftpserver.pl $flag $FTPPORT &";
    if($verbose) {
        print "CMD: $cmd\n";
    }
    system($cmd);

    my $verified;
    $pid = 0;
    for(1 .. 10) {
        # verify that our server is up and running:
        my $line;
        my $cmd="$CURL --silent ftp://$HOSTIP:$FTPPORT/verifiedserver 2>/dev/null";
        print "$cmd\n" if($verbose);
        my @data = `$cmd`;
        foreach $line (@data) {
            if ( $line =~ /WE ROOLZ: (\d+)/ ) {
                $pid = 0+$1;
                $verified = 1;
                last;
            }
        }
        if(!$pid) {
            if($verbose) {
                print STDERR "RUN: Retrying FTP server existence in 3 sec\n";
            }
            sleep(3);
            next;
        }
        else {
            last;
        }
    }
    if(!$verified) {
        warn "RUN: failed to start our FTP server\n";
        return -2;
    }

    if($verbose) {
        print "RUN: FTP server is now verified to be our server\n";
    }

    return $pid;
}

#######################################################################
# start the ftps server (or rather, tunnel) if needed
#
sub runftpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;

    if(!$stunnel) {
        return 0;
    }
    my $pid=checkserver($FTPSPIDFILE );

    if($pid > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "kills off running stunnel at $pid\n";
        }
        stopserver($FTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/ftpsserver.pl $flag -s \"$stunnel\" -d $srcdir -r $FTPPORT $FTPSPORT &";
    system($cmd);
    if($verbose) {
        print "CMD: $cmd\n";
    }
    sleep(1);

    for(1 .. 10) {

        $pid=checkserver($FTPSPIDFILE );

        if($pid <= 0) {
            if($verbose) {
                print STDERR "RUN: waiting 3 sec for FTPS server\n";
            }
            sleep(3);
        }
        else {
            last;
        }
    }

    return $pid;
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
    my ($subject, $firstref, $secondref)=@_;

    my $result = compareparts($firstref, $secondref);

    if($result) {
        if(!$short) {
            print "\n $subject FAILED:\n";
            print showdiff($firstref, $secondref);
        }
        else {
            print "FAILED\n";
        }
    }
    return $result;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub checkcurl {

    unlink($memdump); # remove this if there was one left

    my $curl;
    my $libcurl;
    my @version=`$CURL --version 2>/dev/null`;
    for(@version) {
        chomp;

        if($_ =~ /^curl/) {
            $curl = $_;
            $curl =~ s/^(.*)(libcurl.*)/$1/g;
            $libcurl = $2;
            if($curl =~ /mingw32/) {
                # This is a windows minw32 build, we need to translate the
                # given path to the "actual" windows path.

                my @m = `mount`;
                my $matchlen;
                my $bestmatch;
                my $mount;

# example mount output:
# C:\DOCUME~1\Temp on /tmp type user (binmode,noumount)
# c:\ActiveState\perl on /perl type user (binmode)
# C:\msys\1.0\bin on /usr/bin type user (binmode,cygexec,noumount)
# C:\msys\1.0\bin on /bin type user (binmode,cygexec,noumount)

                foreach $mount (@m) {
                    if( $mount =~ /(.*) on ([^ ]*) type /) {
                        my ($mingw, $real)=($2, $1);
                        if($pwd =~ /^$mingw/) {
                            # the path we got from pwd starts with the path
                            # we found on this line in the mount output

                            my $len = length($real);
                            if($len > $matchlen) {
                                # we remember the match that is the longest
                                $matchlen = $len;
                                $bestmatch = $real;
                            }
                        }
                    }
                }
                if(!$matchlen) {
                    print "Serious error, can't find our \"real\" path!\n";
                }
                else {
                    # now prepend the prefix from the mount command to build
                    # our "actual path"
                    $pwd = "$bestmatch$pwd";
                }
                $pwd =~ s#\\#/#g;
            }
            elsif ($curl =~ /win32/)
            {
               # Native Windows builds don't understand the
               # output of cygwin's pwd.  It will be
               # something like /cygdrive/c/<some path>.
               #
               # Use the cygpath utility to convert the
               # working directory to a Windows friendly
               # path.  The -m option converts to use drive
               # letter:, but it uses / instead \.  Forward
               # slashes (/) are easier for us.  We don't
               # have to escape them to get them to curl
               # through a shell.
               chomp($pwd = `cygpath -m $pwd`);
           }
        }
        elsif($_ =~ /^Protocols: (.*)/i) {
            # these are the supported protocols, we don't use this knowledge
            # at this point
        }
        elsif($_ =~ /^Features: (.*)/i) {
            my $feat = $1;
            if($feat =~ /debug/i) {
                # debug is a listed "feature", use that knowledge
                $curl_debug = 1;
                # set the NETRC debug env
                $ENV{'CURL_DEBUG_NETRC'} = 'log/netrc';
            }
            if($feat =~ /SSL/i) {
                # ssl enabled
                $ssl_version=1;
            }
            if($feat =~ /Largefile/i) {
                # large file support
                $large_file=1;
            }
            if($feat =~ /IDN/i) {
                # IDN support
                $has_idn=1;
            }
        }
    }
    if(!$curl) {
        die "couldn't run '$CURL'"
    }

    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    print "********* System characteristics ******** \n",
    "* $curl\n",
    "* $libcurl\n",
    "* Host: $hostname",
    "* System: $hosttype";

    printf("* Server SSL:       %s\n", $stunnel?"ON":"OFF");
    printf("* libcurl SSL:      %s\n", $ssl_version?"ON":"OFF");
    printf("* libcurl debug:    %s\n", $curl_debug?"ON":"OFF");
    printf("* valgrind:         %s\n", $valgrind?"ON":"OFF");
    print "***************************************** \n";
}

#######################################################################
# substitute the variable stuff into either a joined up file or
# a command, in either case passed by reference
#
sub subVariables {
  my ($thing) = @_;
  $$thing =~ s/%HOSTIP/$HOSTIP/g;
  $$thing =~ s/%HOSTPORT/$HOSTPORT/g;
  $$thing =~ s/%HTTPPORT/$HOSTPORT/g;
  $$thing =~ s/%HTTPSPORT/$HTTPSPORT/g;
  $$thing =~ s/%FTPPORT/$FTPPORT/g;
  $$thing =~ s/%FTPSPORT/$FTPSPORT/g;
  $$thing =~ s/%SRCDIR/$srcdir/g;
  $$thing =~ s/%PWD/$pwd/g;
}

#######################################################################
# Run a single specified test case
#

sub singletest {
    my $testnum=$_[0];

    my @what;
    my $why;
    my $serverproblem;

    # load the test case file definition
    if(loadtest("${TESTDIR}/test${testnum}")) {
        if($verbose) {
            # this is not a test
            print "RUN: $testnum doesn't look like a test case!\n";
        }
        $serverproblem = 100;
    }
    else {
        @what = getpart("client", "features");
    }

    printf("test %03d...", $testnum);

    for(@what) {
        my $f = $_;
        $f =~ s/\s//g;

        if($f eq "SSL") {
            if($ssl_version) {
                next;
            }
        }
        elsif($f eq "netrc_debug") {
            if($curl_debug) {
                next;
            }
        }
        elsif($f eq "large_file") {
            if($large_file) {
                next;
            }
        }
        elsif($f eq "idn") {
            if($has_idn) {
                next;
            }
        }

        $why = "curl lacks $f support";
        $serverproblem = 15; # set it here
        last;
    }

    if(!$serverproblem) {
        $serverproblem = serverfortest($testnum);
    }

    if($serverproblem) {
        # there's a problem with the server, don't run
        # this particular server, but count it as "skipped"
        if($serverproblem == 2) {
            $why = "server problems";
        }
        elsif($serverproblem == 100) {
            $why = "no test";
        }
        elsif($serverproblem == 99) {
            $why = "bad test";
        }
        elsif($serverproblem == 15) {
            # set above, a lacking prereq
        }
        elsif($serverproblem == 1) {
            $why = "no HTTPS server";
        }
        elsif($serverproblem == 3) {
            $why = "no FTPS server";
        }
        else {
            $why = "unfulfilled requirements";
        }
        $skipped++;
        $skipped{$why}++;
        $teststat[$testnum]=$why; # store reason for this test case

        print "SKIPPED\n";
        if(!$short) {
            print "* Test $testnum: $why\n";
        }

        return -1;
    }

    # extract the reply data
    my @reply = getpart("reply", "data");
    my @replycheck = getpart("reply", "datacheck");

    if (@replycheck) {
        # we use this file instead to check the final output against

        my %hash = getpartattr("reply", "datacheck");
        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the datacheck
            chomp($replycheck[$#replycheck]);
        }

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

    if(!$short) {
        my $name = $testname[0];
        $name =~ s/\n//g;
        print "[$name]\n";
    }

    if($listonly) {
        return 0; # look successful
    }

    my @codepieces = getpart("client", "tool");

    my $tool="";
    if(@codepieces) {
        $tool = $codepieces[0];
        chomp $tool;
    }

    # remove previous server output logfile
    unlink($SERVERIN);

    if(@ftpservercmd) {
        # write the instructions to file
        writearray($FTPDCMD, \@ftpservercmd);
    }

    my (@setenv)= getpart("client", "setenv");
    my @envs;

    my $s;
    for $s (@setenv) {
        chomp $s; # cut off the newline

        subVariables \$s;

        if($s =~ /([^=]*)=(.*)/) {
            my ($var, $content)=($1, $2);
            $ENV{$var}=$content;
            # remember which, so that we can clear them afterwards!
            push @envs, $var;
        }
    }

    # get the command line options to use
    my ($cmd, @blaha)= getpart("client", "command");

    # make some nice replace operations
    $cmd =~ s/\n//g; # no newlines please

    # substitute variables in the command line
    subVariables \$cmd;

    if($curl_debug) {
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
        my $fileContent = join('', @inputfile);
        subVariables \$fileContent;
#        print "DEBUG: writing file " . $filename . "\n";
        open OUTFILE, ">$filename";
        binmode OUTFILE; # for crapage systems, use binary
        print OUTFILE $fileContent;
        close OUTFILE;
    }

    my %cmdhash = getpartattr("client", "command");

    my $out="";

    if($cmdhash{'option'} !~ /no-output/) {
        #We may slap on --output!
        if (!@validstdout) {
            $out=" --output $CURLOUT ";
        }
    }

    my $cmdargs;
    if(!$tool) {
        # run curl, add -v for debug information output
        $cmdargs ="$out --include -v $cmd";
    }
    else {
        $cmdargs = " $cmd"; # $cmd is the command line for the test file
        $CURLOUT = $STDOUT; # sends received data to stdout
    }

    my @stdintest = getpart("client", "stdin");

    if(@stdintest) {
        my $stdinfile="$LOGDIR/stdin-for-$testnum";
        writearray($stdinfile, \@stdintest);

        $cmdargs .= " <$stdinfile";
    }
    my $CMDLINE;

    if(!$tool) {
        $CMDLINE="$CURL";
    }
    else {
        $CMDLINE="$LIBDIR/$tool";
        $DBGCURL=$CMDLINE;
    }

    if($valgrind) {
        $CMDLINE = "valgrind --leak-check=yes --logfile=log/valgrind$testnum -q $CMDLINE";
    }

    $CMDLINE .= "$cmdargs >>$STDOUT 2>>$STDERR";

    if($verbose) {
        print "$CMDLINE\n";
    }

    print CMDLOG "$CMDLINE\n";

    unlink("core");

    my $dumped_core;
    my $cmdres;


    if($gdbthis) {
        open(GDBCMD, ">log/gdbcmd");
        print GDBCMD "set args $cmdargs\n";
        print GDBCMD "show args\n";
        close(GDBCMD);
    }
    # run the command line we built
    if ($torture) {
        return torture($CMDLINE,
                       "gdb --directory libtest $DBGCURL -x log/gdbcmd");
    }
    elsif($gdbthis) {
        system("gdb --directory libtest $DBGCURL -x log/gdbcmd");
        $cmdres=0; # makes it always continue after a debugged run
    }
    else {
        $cmdres = system("$CMDLINE");
        my $signal_num  = $cmdres & 127;
        $dumped_core = $cmdres & 128;

        if(!$anyway && ($signal_num || $dumped_core)) {
            $cmdres = 1000;
        }
        else {
            $cmdres /= 256;
        }
    }
    if(!$dumped_core) {
        if(-r "core") {
            # there's core file present now!
            $dumped_core = 1;
        }
    }

    if($dumped_core) {
        print "core dumped!\n";
        if(0 && $gdb) {
            print "running gdb for post-mortem analysis:\n";
            open(GDBCMD, ">log/gdbcmd2");
            print GDBCMD "bt\n";
            close(GDBCMD);
            system("gdb --directory libtest -x log/gdbcmd2 -batch $DBGCURL core ");
     #       unlink("log/gdbcmd2");
        }
    }

    # remove the special FTP command file after each test!
    unlink($FTPDCMD);

    my $e;
    for $e (@envs) {
        $ENV{$e}=""; # clean up
    }

    my @err = getpart("verify", "errorcode");
    my $errorcode = $err[0];

    my $res;
    if (@validstdout) {
        # verify redirected stdout
        my @actual = loadarray($STDOUT);

        $res = compare("stdout", \@actual, \@validstdout);
        if($res) {
            return 1;
        }
        if(!$short) {
            print " stdout OK";
        }
    }

    my %replyattr = getpartattr("reply", "data");
    if(!$replyattr{'nocheck'} && @reply) {
        # verify the received data
        my @out = loadarray($CURLOUT);
        $res = compare("data", \@out, \@reply);
        if ($res) {
            return 1;
        }
        if(!$short) {
            print " data OK";
        }
    }

    if(@upload) {
        # verify uploaded data
        my @out = loadarray("$LOGDIR/upload.$testnum");
        $res = compare("upload", \@out, \@upload);
        if ($res) {
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
            # strip off all lines that match the patterns from both arrays
            chomp $_;
            @out = striparray( $_, \@out);
            @protstrip= striparray( $_, \@protstrip);
        }

        $res = compare("protocol", \@out, \@protstrip);
        if($res) {
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

        $res = compare("output", \@generated, \@outfile);
        if($res) {
            return 1;
        }
        if(!$short) {
            print " output OK";
        }
    }

    if($errorcode == $cmdres) {
        $errorcode =~ s/\n//;
        if($verbose) {
            print " received exitcode $errorcode OK";
        }
        elsif(!$short) {
            print " exit OK";
        }
    }
    else {
        if(!$short) {
            print "curl returned $cmdres, ".(0+$errorcode)." was expected\n";
        }
        print " exit FAILED\n";
        return 1;
    }

    # the test succeeded, remove all log files
    if(!$keepoutfiles) {
        cleardir($LOGDIR);
    }

    unlink($FTPDCMD); # remove the instructions for this test

    @what = getpart("client", "killserver");
    for(@what) {
        my $serv = $_;
        chomp $serv;
        if($run{$serv}) {
            stopserver($run{$serv}); # the pid file is in the hash table
            $run{$serv}=0; # clear pid
        }
        else {
            print STDERR "RUN: The $serv server is not running\n";
        }
    }

    if($curl_debug) {
        if(! -f $memdump) {
            print "\n** ALERT! memory debuggin without any output file?\n";
        }
        else {
            my @memdata=`$memanalyze $memdump`;
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
    if($valgrind) {
        opendir(DIR, "log") ||
            return 0; # can't open log dir
        my @files = readdir(DIR);
        closedir DIR;
        my $f;
        my $l;
        foreach $f (@files) {
            if($f =~ /^valgrind$testnum/) {
                $l = $f;
                last;
            }
        }
        my $leak;
        open(VAL, "<$l");
        while(<VAL>) {
            if($_ =~ /definitely lost: (\d*) bytes/) {
                $leak = $1;
                last;
            }
        }
        close(VAL);
        if($leak) {
            print " valgrind ERROR ";
        }
        elsif(!$short) {
            print " valgrind OK";
        }


    }
    if($short) {
        print "OK";
    }
    print "\n";

    return 0;
}

#######################################################################
# Stop all running test servers
sub stopservers {
    print "Shutting down test suite servers:\n" if ($verbose);
    for(keys %run) {
        printf ("* kill pid for %-5s => %-5d\n", $_, $run{$_}) if($verbose);
        stopserver($run{$_}); # the pid file is in the hash table
    }
}

#######################################################################
# startservers() starts all the named servers
#
sub startservers {
    my @what = @_;
    my $pid;
    for(@what) {
        my $what = lc($_);
        $what =~ s/[^a-z]//g;
        if($what eq "ftp") {
            if(!$run{'ftp'}) {
                $pid = runftpserver($verbose);
                if($pid <= 0) {
                    return 2; # error starting it
                }
                printf ("* pid ftp => %-5d\n", $pid) if($verbose);
                $run{'ftp'}=$pid;
            }
        }
        elsif($what eq "http") {
            if(!$run{'http'}) {
                $pid = runhttpserver($verbose);
                if($pid <= 0) {
                    return 2; # error starting
                }
                printf ("* pid http => %-5d\n", $pid) if($verbose);
                $run{'http'}=$pid;
            }
        }
        elsif($what eq "ftps") {
            if(!$stunnel || !$ssl_version) {
                # we can't run ftps tests without stunnel
                # or if libcurl is SSL-less
                return 3;
            }
            if(!$run{'ftp'}) {
                $pid = runftpserver($verbose);
                if($pid <= 0) {
                    return 2; # error starting it
                }
                printf ("* pid ftp => %-5d\n", $pid) if($verbose);
                $run{'ftp'}=$pid;
            }
            if(!$run{'ftps'}) {
                return 2;

                $pid = runftpsserver($verbose);
                if($pid <= 0) {
                    return 2;
                }
                printf ("* pid ftps => %-5d\n", $pid) if($verbose);
                $run{'ftps'}=$pid;
            }
        }
        elsif($what eq "file") {
            # we support it but have no server!
        }
        elsif($what eq "https") {
            if(!$stunnel || !$ssl_version) {
                # we can't run https tests without stunnel
                # or if libcurl is SSL-less
                return 1;
            }
            if(!$run{'http'}) {
                $pid = runhttpserver($verbose);
                if($pid <= 0) {
                    return 2; # problems starting server
                }
                printf ("* pid http => %-5d\n", $pid) if($verbose);
                $run{'http'}=$pid;
            }
            if(!$run{'https'}) {
                $pid = runhttpsserver($verbose);
                if($pid <= 0) {
                    return 2;
                }
                printf ("* pid https => %-5d\n", $pid) if($verbose);
                $run{'https'}=$pid;
            }
        }
        elsif($what eq "none") {
            print "* starts no server\n" if ($verbose);
        }
        else {
            warn "we don't support a server for $what";
        }
    }
    return 0;
}

##############################################################################
# This function makes sure the right set of server is running for the
# specified test case. This is a useful design when we run single tests as not
# all servers need to run then!
#
# Returns:
# 100 if this is not a test case
# 99  if this test case has no servers specified
# 3   if this test is skipped due to no FTPS server
# 2   if one of the required servers couldn't be started
# 1   if this test is skipped due to no HTTPS server

sub serverfortest {
    my ($testnum)=@_;

    # load the test case file definition
    if(loadtest("${TESTDIR}/test${testnum}")) {
        if($verbose) {
            # this is not a test
            print "$testnum doesn't look like a test case!\n";
        }
        return 100;
    }

    my @what = getpart("client", "server");

    if(!$what[0]) {
        warn "Test case $testnum has no server(s) specified!";
        return 99;
    }

    return &startservers(@what);
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
    elsif($ARGV[0] eq "-n") {
        # no valgrind
        undef $valgrind;
    }
    elsif($ARGV[0] =~ /^-t(.*)/) {
        # torture
        $torture=1;
        my $xtra = $1;

        if($xtra =~ s/(\d+)$//) {
            $tortalloc = $1;
        }
        # we undef valgrind to make this fly in comparison
        undef $valgrind;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-p") {
        $postmortem=1;
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
  -n       No valgrind
  -p       Print log file contents when a test fails
  -s       short output
  -t       torture
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

if($valgrind) {
    # we have found valgrind on the host, use it

    # verify that we can invoke it fine
    my $code = system("valgrind >/dev/null 2>&1");

    if(($code>>8) != 1) {
        #print "Valgrind failure, disable it\n";
        undef $valgrind;
    }
}

#######################################################################
# Output curl version and host info being tested
#

if(!$listonly) {
    checkcurl();
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

sub displaylogcontent {
    my ($file)=@_;
    open(SINGLE, "<$file");
    while(<SINGLE>) {
        print " $_";
    }
    close(SINGLE);
}

sub displaylogs {
    my ($testnum)=@_;
    opendir(DIR, "$LOGDIR") ||
        die "can't open dir: $!";
    my @logs = readdir(DIR);
    closedir DIR;
    my $log;

    print "== Contents of files in the log/ dir after test $testnum\n";
    foreach $log (sort @logs) {
        # the log file is not "." or ".." and contains more than zero bytes
        if(($log !~ /\.(\.|)$/) && -s "$LOGDIR/$log") {
            print "== Start of file $log\n";
            displaylogcontent("$LOGDIR/$log");
            print "== End of file $log\n";
        }
    }
}

#######################################################################
# The main test-loop
#

my $failed;
my $testnum;
my $ok=0;
my $total=0;
my $lasttest;

foreach $testnum (split(" ", $TESTCASES)) {

    $lasttest = $testnum if($testnum > $lasttest);

    my $error = singletest($testnum);
    if($error < 0) {
        # not a test we can run
        next;
    }

    $total++; # number of tests we've run

    if($error>0) {
        $failed.= "$testnum ";
        if($postmortem) {
            # display all files in log/ in a nice way
            displaylogs($testnum);
        }
        if(!$anyway) {
            # a test failed, abort
            print "\n - abort tests\n";
            last;
        }
    }
    elsif(!$error) {
        $ok++; # successful test counter
    }

    # loop for next test
}

#######################################################################
# Close command log
#
close(CMDLOG);


# Tests done, stop the servers
stopservers();

my $all = $total + $skipped;

if($total) {
    printf("TESTDONE: $ok tests out of $total reported OK: %d%%\n",
           $ok/$total*100);

    if($ok != $total) {
        print "TESTFAIL: These test cases failed: $failed\n";
    }
}
else {
    print "TESTFAIL: No tests were performed!\n";
}

if($all) {
    print "TESTDONE: $all tests were considered.\n";
}

if($skipped) {
    my $s=0;
    print "TESTINFO: $skipped tests were skipped due to these restraints:\n";

    for(keys %skipped) {
        my $r = $_;
        printf "TESTINFO: \"%s\" %d times (", $r, $skipped{$_};

        # now show all test case numbers that had this reason for being
        # skipped
        my $c=0;
        for(0 .. $lasttest) {
            my $t = $_;
            if($teststat[$_] eq $r) {
                print ", " if($c);
                print $_;
                $c++;
            }
        }
        print ")\n";
    }
}
if($total && ($ok != $total)) {
    exit 1;
}
