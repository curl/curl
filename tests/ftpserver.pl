#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# This is the FTP server designed for the curl test suite.
#
# It is meant to exercise curl, it is not meant to be a fully working
# or even very standard compliant server.
#
# You may optionally specify port on the command line, otherwise it'll
# default to port 8921.
#
# All socket/network/TCP related stuff is done by the 'sockfilt' program.
#

use strict;
use IPC::Open2;
#use Time::HiRes qw( gettimeofday ); # not available in perl 5.6

require "getpart.pm";
require "ftp.pm";


my $ftpdnum="";

# open and close each time to allow removal at any time
sub logmsg {
 # if later than perl 5.6 is used
 #   my ($seconds, $microseconds) = gettimeofday;
    my $seconds = time();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
        localtime($seconds);
    open(FTPLOG, ">>log/ftpd$ftpdnum.log");
    printf FTPLOG ("%02d:%02d:%02d ", $hour, $min, $sec);
    print FTPLOG @_;
    close(FTPLOG);
}

sub ftpmsg {
  # append to the server.input file
  open(INPUT, ">>log/server$ftpdnum.input") ||
    logmsg "failed to open log/server$ftpdnum.input\n";

  print INPUT @_;
  close(INPUT);

  # use this, open->print->close system only to make the file
  # open as little as possible, to make the test suite run
  # better on windows/cygwin
}

my $verbose=0; # set to 1 for debugging
my $pasvbadip=0;
my $retrweirdo=0;
my $retrnosize=0;
my $srcdir=".";
my $nosave=0;
my $controldelay=0; # set to 1 to delay the control connect data sending to
 # test that curl deals with that nicely
my $slavepid; # for the DATA connection sockfilt slave process
my $ipv6;
my $ext; # append to log/pid file names
my $grok_eprt;
my $port = 8921; # just a default
my $pidfile = ".ftpd.pid"; # a default, use --pidfile

do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-s") {
        $srcdir=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "--id") {
        $ftpdnum=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "--pidfile") {
        $pidfile=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "--ipv6") {
        $ipv6="--ipv6";
        $ext="ipv6";
        $grok_eprt = 1;
    }
    elsif($ARGV[0] eq "--port") {
        $port = $ARGV[1];
        shift @ARGV;
    }
} while(shift @ARGV);

sub catch_zap {
    my $signame = shift;
    print STDERR "ftpserver.pl received SIG$signame, exiting\n";
    ftpkillslaves(1);
    die "Somebody sent me a SIG$signame";
}
$SIG{INT} = \&catch_zap;
$SIG{KILL} = \&catch_zap;

my $sfpid;

local(*SFREAD, *SFWRITE);

sub sysread_or_die {
    my $FH     = shift;
    my $scalar = shift;
    my $length = shift;
    my $fcaller;
    my $lcaller;
    my $result;

    $result = sysread($$FH, $$scalar, $length);

    if(not defined $result) {
        ($fcaller, $lcaller) = (caller)[1,2];
        logmsg "Failed to read input\n";
        logmsg "Error: ftp$ftpdnum$ext sysread error: $!\n";
        kill(9, $sfpid);
        die "Died in sysread_or_die() at $fcaller " .
            "line $lcaller. ftp$ftpdnum$ext sysread error: $!\n";
    }
    elsif($result == 0) {
        ($fcaller, $lcaller) = (caller)[1,2];
        logmsg "Failed to read input\n";
        logmsg "Error: ftp$ftpdnum$ext read zero\n";
        kill(9, $sfpid);
        die "Died in sysread_or_die() at $fcaller " .
            "line $lcaller. ftp$ftpdnum$ext read zero\n";
    }

    return $result;
}

sub startsf {
    my $cmd="./server/sockfilt --port $port --logfile log/sockctrl$ftpdnum$ext.log --pidfile .sockfilt$ftpdnum$ext.pid $ipv6";
    $sfpid = open2(*SFREAD, *SFWRITE, $cmd);

    print STDERR "$cmd\n" if($verbose);

    print SFWRITE "PING\n";
    my $pong;
    sysread SFREAD, $pong, 5;

    if($pong !~ /^PONG/) {
        logmsg "Failed sockfilt command: $cmd\n";
        kill(9, $sfpid);
        die "Failed to start sockfilt!";
    }
}

# remove the file here so that if startsf() fails, it is very noticable 
unlink($pidfile);

startsf();

logmsg sprintf("FTP server listens on port IPv%d/$port\n", $ipv6?6:4);
open(PID, ">$pidfile");
print PID $$."\n";
close(PID);

logmsg("logged pid $$ in $pidfile\n");

sub sockfilt {
    my $l;
    foreach $l (@_) {
        printf SFWRITE "DATA\n%04x\n", length($l);
        print SFWRITE $l;
    }
}


# Send data to the client on the control stream, which happens to be plain
# stdout.

sub sendcontrol {
    if(!$controldelay) {
        # spit it all out at once
        sockfilt @_;
    }
    else {
        my $a = join("", @_);
        my @a = split("", $a);

        for(@a) {
            sockfilt $_;
            select(undef, undef, undef, 0.01);
        }
    }
    my $log;
    foreach $log (@_) {
        my $l = $log;
        $l =~ s/[\r\n]//g;
        logmsg "> \"$l\"\n";
    }
}

# Send data to the client on the data stream

sub senddata {
    my $l;
    foreach $l (@_) {
        printf DWRITE "DATA\n%04x\n", length($l);
        print DWRITE $l;
    }
}

# USER is ok in fresh state
my %commandok = (
                 'USER' => 'fresh|passwd',
                 'PASS' => 'passwd',
                 'PASV' => 'loggedin|twosock',
                 'EPSV' => 'loggedin|twosock',
                 'PORT' => 'loggedin|twosock',
                 'EPRT' => 'loggedin|twosock',
                 'TYPE' => 'loggedin|twosock',
                 'LIST' => 'twosock',
                 'NLST' => 'twosock',
                 'RETR' => 'twosock',
                 'STOR' => 'twosock',
                 'APPE' => 'twosock',
                 'REST' => 'twosock',
                 'ACCT' => 'loggedin',
                 'CWD'  => 'loggedin|twosock',
                 'SYST' => 'loggedin',
                 'SIZE' => 'loggedin|twosock',
                 'PWD'  => 'loggedin|twosock',
                 'MKD'  => 'loggedin|twosock',
                 'QUIT'  => 'loggedin|twosock',
                 'RNFR'  => 'loggedin|twosock',
                 'RNTO'  => 'loggedin|twosock',
                 'DELE' => 'loggedin|twosock',
                 'MDTM' => 'loggedin|twosock',
                 'NOOP' => 'loggedin|twosock',
                 );

# initially, we're in 'fresh' state
my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'twosock',   # PORT goes to twosock
                    'EPRT' => 'twosock',   # EPRT goes to twosock
                    'PASV' => 'twosock',   # PASV goes to twosock
                    'EPSV' => 'twosock',   # EPSV goes to twosock
                    );

# this text is shown before the function specified below is run
my %displaytext = ('USER' => '331 We are happy you popped in!',
                   'PASS' => '230 Welcome you silly person',
                   'PORT' => '200 You said PORT - I say FINE',
                   'TYPE' => '200 I modify TYPE as you wanted',
                   'LIST' => '150 here comes a directory',
                   'NLST' => '150 here comes a directory',
                   'CWD'  => '250 CWD command successful.',
                   'SYST' => '215 UNIX Type: L8', # just fake something
                   'QUIT' => '221 bye bye baby', # just reply something
                   'PWD'  => '257 "/nowhere/anywhere" is current directory',
                   'MKD'  => '257 Created your requested directory',
                   'REST' => '350 Yeah yeah we set it there for you',
                   'DELE' => '200 OK OK OK whatever you say',
                   'RNFR' => '350 Received your order. Please provide more',
                   'RNTO' => '250 Ok, thanks. File renaming completed.',
                   'NOOP' => '200 Yes, I\'m very good at doing nothing.',
                   );

# callback functions for certain commands
my %commandfunc = ( 'PORT' => \&PORT_command,
                    'EPRT' => \&PORT_command,
                    'LIST' => \&LIST_command,
                    'NLST' => \&NLST_command,
                    'PASV' => \&PASV_command,
                    'EPSV' => \&PASV_command,
                    'RETR' => \&RETR_command,   
                    'SIZE' => \&SIZE_command,
                    'REST' => \&REST_command,
                    'STOR' => \&STOR_command,
                    'APPE' => \&STOR_command, # append looks like upload
                    'MDTM' => \&MDTM_command,
                    );


sub close_dataconn {
    my ($closed)=@_; # non-zero if already disconnected

    if(!$closed) {
        logmsg "* disconnect data connection\n";
        print DWRITE "DISC\n";
        my $i;
        sysread DREAD, $i, 5;
    }
    else {
        logmsg "data connection already disconnected\n";
    }
    logmsg "=====> Closed data connection\n";

    logmsg "* quit sockfilt for data (pid $slavepid)\n";
    print DWRITE "QUIT\n";
    waitpid $slavepid, 0;
    $slavepid=0;
}

my $rest=0;
sub REST_command {
    $rest = $_[0];
    logmsg "Set REST position to $rest\n"
}

sub LIST_command {
  #  print "150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes)\r\n";

# this is a built-in fake-dir ;-)
my @ftpdir=("total 20\r\n",
"drwxr-xr-x   8 98       98           512 Oct 22 13:06 .\r\n",
"drwxr-xr-x   8 98       98           512 Oct 22 13:06 ..\r\n",
"drwxr-xr-x   2 98       98           512 May  2  1996 .NeXT\r\n",
"-r--r--r--   1 0        1             35 Jul 16  1996 README\r\n",
"lrwxrwxrwx   1 0        1              7 Dec  9  1999 bin -> usr/bin\r\n",
"dr-xr-xr-x   2 0        1            512 Oct  1  1997 dev\r\n",
"drwxrwxrwx   2 98       98           512 May 29 16:04 download.html\r\n",
"dr-xr-xr-x   2 0        1            512 Nov 30  1995 etc\r\n",
"drwxrwxrwx   2 98       1            512 Oct 30 14:33 pub\r\n",
"dr-xr-xr-x   5 0        1            512 Oct  1  1997 usr\r\n");

    logmsg "pass LIST data on data connection\n";
    for(@ftpdir) {
        senddata $_;
    }
    close_dataconn(0);
    sendcontrol "226 ASCII transfer complete\r\n";
    return 0;
}

sub NLST_command {
    my @ftpdir=("file", "with space", "fake", "..", " ..", "funny", "README");
    logmsg "pass NLST data on data connection\n";
    for(@ftpdir) {
        senddata "$_\r\n";
    }
    close_dataconn(0);
    sendcontrol "226 ASCII transfer complete\r\n";
    return 0;
}

sub MDTM_command {
    my $testno = $_[0];

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "mdtm");

    my $reply = $data[0];
    chomp $reply;

    if($reply <0) {
        sendcontrol "550 $testno: no such file.\r\n";
    }
    elsif($reply) {
        sendcontrol "$reply\r\n";
    }
    else {
        sendcontrol "500 MDTM: no such command.\r\n";
    }
    return 0;
}

sub SIZE_command {
    my $testno = $_[0];

    loadtest("$srcdir/data/test$testno");

    if($testno eq "verifiedserver") {
        my $response = "WE ROOLZ: $$\r\n";
        my $size = length($response);
        sendcontrol "213 $size\r\n";
        return 0;
    }

    my @data = getpart("reply", "size");

    my $size = $data[0];

    if($size) {
        if($size > -1) {
            sendcontrol "213 $size\r\n";
        }
        else {
            sendcontrol "550 $testno: No such file or directory.\r\n";
        }
    }
    else {
        $size=0;
        @data = getpart("reply", "data");
        for(@data) {
            $size += length($_);
        }
        if($size) {
            sendcontrol "213 $size\r\n";
        }
        else {
            sendcontrol "550 $testno: No such file or directory.\r\n";
        }
    }
    return 0;
}

sub RETR_command {
    my ($testno) = @_;

    if($testno =~ /^verifiedserver$/) {
        # this is the secret command that verifies that this actually is
        # the curl test server
        my $response = "WE ROOLZ: $$\r\n";
        my $len = length($response);
        sendcontrol "150 Binary junk ($len bytes).\r\n";
        senddata "WE ROOLZ: $$\r\n";
        close_dataconn(0);
        sendcontrol "226 File transfer complete\r\n";
        if($verbose) {
            print STDERR "FTPD: We returned proof we are the test server\n";
        }
        return 0;
    }

    $testno =~ s/^([^0-9]*)//;

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "data");

    my $size=0;
    for(@data) {
        $size += length($_);
    }

    my %hash = getpartattr("reply", "data");

    if($size || $hash{'sendzero'}) {
    
        if($rest) {
            # move read pointer forward
            $size -= $rest;
            logmsg "REST $rest was removed from size, makes $size left\n";
            $rest = 0; # reset REST offset again
        }
        if($retrweirdo) {
            sendcontrol "150 Binary data connection for $testno () ($size bytes).\r\n",
            "226 File transfer complete\r\n";

            for(@data) {
                my $send = $_;
                senddata $send;
            }
            close_dataconn(0);
            $retrweirdo=0; # switch off the weirdo again!
        }
        else {
            my $sz = "($size bytes)";
            if($retrnosize) {
                $sz = "size?";
            }

            sendcontrol "150 Binary data connection for $testno () $sz.\r\n";

            for(@data) {
                my $send = $_;
                senddata $send;
            }
            close_dataconn(0);
            sendcontrol "226 File transfer complete\r\n";
        }
    }
    else {
        sendcontrol "550 $testno: No such file or directory.\r\n";
    }
    return 0;
}

sub STOR_command {
    my $testno=$_[0];

    my $filename = "log/upload.$testno";

    logmsg "STOR test number $testno in $filename\n";

    sendcontrol "125 Gimme gimme gimme!\r\n";

    open(FILE, ">$filename") ||
        return 0; # failed to open output

    my $line;
    my $ulsize=0;
    my $disc=0;
    while (5 == (sysread DREAD, $line, 5)) {
        if($line eq "DATA\n") {
            my $i;
            sysread DREAD, $i, 5;

            #print STDERR "  GOT: $i";

            my $size = hex($i);
            sysread DREAD, $line, $size;
            
            #print STDERR "  GOT: $size bytes\n";

            $ulsize += $size;
            print FILE $line if(!$nosave);
            logmsg "> Appending $size bytes to file\n";
        }
        elsif($line eq "DISC\n") {
            # disconnect!
            $disc=1;
            last;
        }
        else {
            logmsg "No support for: $line";
            last;
        }
    }
    if($nosave) {
        print FILE "$ulsize bytes would've been stored here\n";
    }
    close(FILE);
    close_dataconn($disc);
    logmsg "received $ulsize bytes upload\n";
    sendcontrol "226 File transfer complete\r\n";
    return 0;
}

sub PASV_command {
    my ($arg, $cmd)=@_;
    my $pasvport;
    my $pidf=".sockdata$ftpdnum$ext.pid";

    my $prev = checkserver($pidf);
    if($prev > 0) {
        print "kill existing server: $prev\n" if($verbose);
        kill(9, $prev);
    }

    # We fire up a new sockfilt to do the data tranfer for us.
    $slavepid = open2(\*DREAD, \*DWRITE,
                      "./server/sockfilt --port 0 --logfile log/sockdata$ftpdnum$ext.log --pidfile $pidf $ipv6");

    print DWRITE "PING\n";
    my $pong;

    sysread_or_die(\*DREAD, \$pong, 5);

    if($pong !~ /^PONG/) {
        kill(9, $slavepid);
        sendcontrol "500 no free ports!\r\n";
        logmsg "failed to run sockfilt for data connection\n";
        return 0;
    }

    logmsg "Run sockfilt for data on pid $slavepid\n";

    # Find out what port we listen on
    my $i;
    print DWRITE "PORT\n";
        
    # READ the response code
    sysread_or_die(\*DREAD, \$i, 5);

    # READ the response size
    sysread_or_die(\*DREAD, \$i, 5);

    my $size = hex($i);
        
    # READ the response data
    sysread_or_die(\*DREAD, \$i, $size);
        
    # The data is in the format
    # IPvX/NNN

    if($i =~ /IPv(\d)\/(\d+)/) {
        # FIX: deal with IP protocol version
        $pasvport = $2;
    }

    if($cmd ne "EPSV") {
        # PASV reply
        my $p="127,0,0,1";
        if($pasvbadip) {
            $p="1,2,3,4";
        }
        sendcontrol sprintf("227 Entering Passive Mode ($p,%d,%d)\n",
                            ($pasvport/256), ($pasvport%256));
    }
    else {
        # EPSV reply
        sendcontrol sprintf("229 Entering Passive Mode (|||%d|)\n", $pasvport);
    }

    eval {
        local $SIG{ALRM} = sub { die "alarm\n" };

	# assume swift operations unless explicitly slow
	alarm ($controldelay?20:5);

        # Wait for 'CNCT'
	my $input;

        while(sysread(DREAD, $input, 5)) {

	    if($input !~ /^CNCT/) {
		# we wait for a connected client
		logmsg "Odd, we got $input from client\n";
		next;
	    }
	    logmsg "====> Client DATA connect\n";
	    last;
	}
        alarm 0;
    };
    if ($@) {
        # timed out

        print DWRITE "QUIT\n";
        waitpid $slavepid, 0;
        logmsg "accept failed\n";
        $slavepid=0;
        return;
    }
    else {
        logmsg "data connection setup on port $pasvport\n";
    }

    return;
}

# Support both PORT and EPRT here. Consider LPRT too.

sub PORT_command {
    my ($arg, $cmd) = @_;
    my $port;

    # We always ignore the given IP and use localhost.

    if($cmd eq "PORT") {
        if($arg !~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/) {
            logmsg "bad PORT-line: $arg\n";
            sendcontrol "500 silly you, go away\r\n";
            return 0;
        }
        $port = ($5<<8)+$6;
    }
    # EPRT |2|::1|49706|
    elsif(($cmd eq "EPRT") && ($grok_eprt)) {
        if($arg !~ /(\d+)\|([^\|]+)\|(\d+)/) {
            sendcontrol "500 silly you, go away\r\n";
            return 0;
        }
        sendcontrol "200 Thanks for dropping by. We contact you later\r\n";
        $port = $3;
    }
    else {
        sendcontrol "500 we don't like $cmd now\r\n";
        return 0;
    }

    if(!$port || $port > 65535) {
        print STDERR "very illegal PORT number: $port\n";
        return 1;
    }

    # We fire up a new sockfilt to do the data tranfer for us.
    # FIX: make it use IPv6 if need be
    $slavepid = open2(\*DREAD, \*DWRITE,
                      "./server/sockfilt --connect $port --logfile log/sockdata$ftpdnum$ext.log --pidfile .sockdata$ftpdnum$ext.pid $ipv6");

    print DWRITE "PING\n";
    my $pong;
    sysread DREAD, $pong, 5;

    if($pong !~ /^PONG/) {
        logmsg "Failed sockfilt for data connection\n";
        kill(9, $slavepid);
    }

    logmsg "====> Client DATA connect to port $port\n";

    return;
}

my %customreply;
my %customcount;
my %delayreply;
sub customize {
    undef %customreply;

    $nosave = 0; # default is to save as normal
    $controldelay = 0; # default is no delaying the responses

    open(CUSTOM, "<log/ftpserver.cmd") ||
        return 1;

    logmsg "FTPD: Getting commands from log/ftpserver.cmd\n";

    while(<CUSTOM>) {
        if($_ =~ /REPLY ([A-Z]+) (.*)/) {
            $customreply{$1}=$2;
            logmsg "FTPD: set custom reply for $1\n";
        }
        if($_ =~ /COUNT ([A-Z]+) (.*)/) {
            # we blank the customreply for this command when having
            # been used this number of times
            $customcount{$1}=$2;
            logmsg "FTPD: blank custom reply for $1 after $2 uses\n";
        }
        elsif($_ =~ /DELAY ([A-Z]+) (\d*)/) {
            $delayreply{$1}=$2;
            logmsg "FTPD: delay reply for $1 with $2 seconds\n";
        }
        elsif($_ =~ /SLOWDOWN/) {
            $controldelay=1;
            logmsg "FTPD: send response with 0.1 sec delay between each byte\n";
        }
        elsif($_ =~ /RETRWEIRDO/) {
            logmsg "FTPD: instructed to use RETRWEIRDO\n";
            $retrweirdo=1;
        }
        elsif($_ =~ /RETRNOSIZE/) {
            logmsg "FTPD: instructed to use RETRNOSIZE\n";
            $retrnosize=1;
        }
        elsif($_ =~ /PASVBADIP/) {
            logmsg "FTPD: instructed to use PASVBADIP\n";
            $pasvbadip=1;
        }
        elsif($_ =~ /NOSAVE/) {
            # don't actually store the file we upload - to be used when
            # uploading insanely huge amounts
            $nosave = 1;
            logmsg "FTPD: NOSAVE prevents saving of uploaded data\n";
        }
    }
    close(CUSTOM);
}

my @welcome=(
            '220-        _   _ ____  _     '."\r\n",
            '220-    ___| | | |  _ \| |    '."\r\n",
            '220-   / __| | | | |_) | |    '."\r\n",
            '220-  | (__| |_| |  _ <| |___ '."\r\n",
            '220    \___|\___/|_| \_\_____|'."\r\n");


while(1) {
    #
    # We read 'sockfilt' commands.
    # 
    my $input;

    logmsg "Awaiting input\n";
    sysread_or_die(\*SFREAD, \$input, 5);

    if($input !~ /^CNCT/) {
        # we wait for a connected client
        logmsg "sockfilt said: $input";
        next;
    }
    logmsg "====> Client connect\n";

    # flush data:
    $| = 1;

    kill(9, $slavepid) if($slavepid);
    $slavepid=0;
        
    &customize(); # read test control instructions

    sendcontrol @welcome;
    if($verbose) {
        for(@welcome) {
            print STDERR "OUT: $_";
        }
    }
    my $state="fresh";

    while(1) {
        my $i;

        # Now we expect to read DATA\n[hex size]\n[prot], where the [prot]
        # part only is FTP lingo.

        # COMMAND
        sysread_or_die(\*SFREAD, \$i, 5);

        if($i !~ /^DATA/) {
            logmsg "sockfilt said $i";
            if($i =~ /^DISC/) {
                # disconnect
                last;
            }
            next;
        }

        # SIZE of data
        sysread_or_die(\*SFREAD, \$i, 5);

        my $size = hex($i);

        # data
        sysread SFREAD, $_, $size;
        
        ftpmsg $_;
        
        # Remove trailing CRLF.
        s/[\n\r]+$//;

        unless (m/^([A-Z]{3,4})\s?(.*)/i) {
            sendcontrol "500 '$_': command not understood.\r\n";
            last;
        }
        my $FTPCMD=$1;
        my $FTPARG=$2;
        my $full=$_;
                 
        logmsg "< \"$full\"\n";

        if($verbose) {
            print STDERR "IN: $full\n";
        }

        my $ok = $commandok{$FTPCMD};
        if($ok !~ /$state/) {
            sendcontrol "500 $FTPCMD not OK in state: $state!\r\n";
            next;
        }

        my $newstate=$statechange{$FTPCMD};
        if($newstate eq "") {
            # remain in the same state
        }
        else {
            
            if($state != $newstate) {
                logmsg "switch to state $state\n";
            }
            $state = $newstate;
        }

        my $delay = $delayreply{$FTPCMD};
        if($delay) {
            # just go sleep this many seconds!
            logmsg("Sleep for $delay seconds\n");
            sleep($delay);
        }

        my $text;
        $text = $customreply{$FTPCMD};
        my $fake = $text;
        if($text eq "") {
            $text = $displaytext{$FTPCMD};
        }
        else {
            if($customcount{$FTPCMD} && (!--$customcount{$FTPCMD})) {
                # used enough number of times, now blank the customreply
                $customreply{$FTPCMD}="";
            }
        }
        if($text) {
            sendcontrol "$text\r\n";
        }

        if($fake eq "") {
            # only perform this if we're not faking a reply
            # see if the new state is a function caller.
            my $func = $commandfunc{$FTPCMD};
            if($func) {
                # it is!
                &$func($FTPARG, $FTPCMD);
            }
        }
            
    } # while(1)
    logmsg "====> Client disconnected\n";
}

print SFWRITE "QUIT\n";
waitpid $sfpid, 0;
exit;
