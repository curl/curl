#!/usr/bin/perl
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

# This is the FTP server designed for the curl test suite.
#
# It is meant to exercise curl, it is not meant to be a fully working
# or even very standard compliant server.
#
# You may optionally specify port on the command line, otherwise it'll
# default to port 8921.
#

use Socket;
use FileHandle;

use strict;

require "getpart.pm";

# open and close each time to allow removal at any time
sub logmsg {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
        localtime(time);
    open(FTPLOG, ">>log/ftpd.log");
    printf FTPLOG ("%02d:%02d:%02d ", $hour, $min, $sec);
    print FTPLOG @_;
    close(FTPLOG);
}

sub ftpmsg {
  # append to the server.input file
  open(INPUT, ">>log/server.input") ||
    logmsg "failed to open log/server.input\n";

  INPUT->autoflush(1);
  print INPUT @_;
  close(INPUT);

  # use this, open->print->close system only to make the file
  # open as little as possible, to make the test suite run
  # better on windows/cygwin
}

my $verbose=0; # set to 1 for debugging
my $retrweirdo=0;
my $retrnosize=0;
my $srcdir=".";

my $port = 8921; # just a default
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-s") {
        $srcdir=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
} while(shift @ARGV);

my $proto = getprotobyname('tcp') || 6;

socket(Server, PF_INET, SOCK_STREAM, $proto)|| die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
           pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))|| die "bind: $!";
listen(Server,SOMAXCONN) || die "listen: $!";

#print "FTP server started on port $port\n";

open(PID, ">.ftp.pid");
print PID $$;
close(PID);

my $waitedpid = 0;
my $paddr;

sub REAPER {
    $waitedpid = wait;
    $SIG{CHLD} = \&REAPER;  # loathe sysV
    logmsg "reaped $waitedpid" . ($? ? " with exit $?\n" : "\n");
}

# USER is ok in fresh state
my %commandok = (
                 'USER' => 'fresh',
                 'PASS' => 'passwd',
                 'PASV' => 'loggedin|twosock',
                 'EPSV' => 'loggedin|twosock',
                 'PORT' => 'loggedin|twosock',
                 'TYPE' => 'loggedin|twosock',
                 'LIST' => 'twosock',
                 'NLST' => 'twosock',
                 'RETR' => 'twosock',
                 'STOR' => 'twosock',
                 'APPE' => 'twosock',
                 'REST' => 'twosock',
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
                 );

# initially, we're in 'fresh' state
my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'twosock',   # PORT goes to twosock
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
                   );

# callback functions for certain commands
my %commandfunc = ( 'PORT' => \&PORT_command,
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
    close(SOCK);
    logmsg "Closed data connection\n";
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
        print SOCK $_;
    }
    close_dataconn();
    logmsg "done passing data\n";

    print "226 ASCII transfer complete\r\n";
    return 0;
}

sub NLST_command {
    my @ftpdir=("file", "with space", "fake", "..", " ..", "funny", "README");
    logmsg "pass NLST data on data connection\n";
    for(@ftpdir) {
        print SOCK "$_\r\n";
    }
    close_dataconn();
    print "226 ASCII transfer complete\r\n";
    return 0;
}

sub MDTM_command {
    my $testno = $_[0];

    loadtest("$srcdir/data/test$testno");

    logmsg "MDTM $testno\n";

    my @data = getpart("reply", "mdtm");

    my $reply = $data[0];
    chomp $reply;

    if($reply <0) {
        print "550 $testno: no such file.\r\n";
        logmsg "MDTM $testno: no such file\n";
    }
    elsif($reply) {
        print "$reply\r\n";
        logmsg "MDTM $testno returned $reply\n";
    }
    else {
        print "500 MDTM: no such command.\r\n";
        logmsg "MDTM: no such command\n";
    }
    return 0;
}

sub SIZE_command {
    my $testno = $_[0];

    loadtest("$srcdir/data/test$testno");

    logmsg "SIZE file \"$testno\"\n";

    my @data = getpart("reply", "size");

    my $size = $data[0];

    if($size) {
        if($size > -1) {
            print "213 $size\r\n";
            logmsg "SIZE $testno returned $size\n";
        }
        else {
            print "550 $testno: No such file or directory.\r\n";
            logmsg "SIZE $testno: no such file\n";
        }
    }
    else {
        $size=0;
        @data = getpart("reply", "data");
        for(@data) {
            $size += length($_);
        }
        if($size) {
            print "213 $size\r\n";
            logmsg "SIZE $testno returned $size\n";
        }
        else {
            print "550 $testno: No such file or directory.\r\n";
            logmsg "SIZE $testno: no such file\n";
        }
    }
    return 0;
}

sub RETR_command {
    my $testno = $_[0];

    logmsg "RETR file \"$testno\"\n";

    if($testno =~ /^verifiedserver$/) {
        # this is the secret command that verifies that this actually is
        # the curl test server
        my $response = "WE ROOLZ: $$\r\n";
        my $len = length($response);
        print "150 Binary junk ($len bytes).\r\n";
        logmsg "pass our pid on the data connection\n";
        print SOCK "WE ROOLZ: $$\r\n";
        close_dataconn();
        print "226 File transfer complete\r\n";
        if($verbose) {
            print STDERR "FTPD: We returned proof we are the test server\n";
        }
        logmsg "we returned proof that we are the test server\n";
        return 0;
    }

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "data");

    my $size=0;
    for(@data) {
        $size += length($_);
    }

    if($size) {
    
        if($rest) {
            # move read pointer forward
            $size -= $rest;
            logmsg "REST $rest was removed from size, makes $size left\n";
            $rest = 0; # reset REST offset again
        }
        if($retrweirdo) {
            print "150 Binary data connection for $testno () ($size bytes).\r\n",
            "226 File transfer complete\r\n";
            logmsg "150+226 in one shot!\n";

            logmsg "pass RETR data on data connection\n";
            for(@data) {
                my $send = $_;
                print SOCK $send;
            }
            close_dataconn();
            $retrweirdo=0; # switch off the weirdo again!
        }
        else {
            my $sz = "($size bytes)";
            if($retrnosize) {
                $sz = "size?";
            }

            print "150 Binary data connection for $testno () $sz.\r\n";
            logmsg "150 Binary data connection for $testno () $sz.\n";

            logmsg "pass RETR data on data connection\n";
            for(@data) {
                my $send = $_;
                print SOCK $send;
            }
            close_dataconn();
            print "226 File transfer complete\r\n";
        }
    }
    else {
        print "550 $testno: No such file or directory.\r\n";
        logmsg "550 $testno: no such file\n";
    }
    return 0;
}

sub STOR_command {
    my $testno=$_[0];

    my $filename = "log/upload.$testno";

    logmsg "STOR test number $testno in $filename\n";

    print "125 Gimme gimme gimme!\r\n";

    logmsg "retrieve STOR data on data connection\n";

    open(FILE, ">$filename") ||
        return 0; # failed to open output

    my $line;
    my $ulsize=0;
    while (defined($line = <SOCK>)) {
        $ulsize += length($line);
        print FILE $line;
    }
    close(FILE);
    close_dataconn();

    logmsg "received $ulsize bytes upload\n";

    print "226 File transfer complete\r\n";
    return 0;
}

my $pasvport=9000;
sub PASV_command {
    my ($arg, $cmd)=@_;

    socket(Server2, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
    setsockopt(Server2, SOL_SOCKET, SO_REUSEADDR,
               pack("l", 1)) || die "setsockopt: $!";

    my $ok=0;

    $pasvport++; # don't reuse the previous
    for(1 .. 10) {
        if($pasvport > 65535) {
            $pasvport = 1025;
        }
        if(bind(Server2, sockaddr_in($pasvport, INADDR_ANY))) {
            $ok=1;
            last;
        }
        $pasvport+= 3; # try another port please
    }
    if(!$ok) {
        print "500 no free ports!\r\n";
        logmsg "couldn't find free port\n";
        return 0;
    }
    listen(Server2,SOMAXCONN) || die "listen: $!";

    if($cmd ne "EPSV") {
        # PASV reply
        logmsg "replying to a $cmd command\n";
        printf("227 Entering Passive Mode (127,0,0,1,%d,%d)\n",
               ($pasvport/256), ($pasvport%256));
    }
    else {
        # EPSV reply
        logmsg "replying to a $cmd command\n";
        printf("229 Entering Passive Mode (|||%d|)\n", $pasvport);
    }


    my $paddr;
    eval {
        local $SIG{ALRM} = sub { die "alarm\n" };
        alarm 2; # assume swift operations!
        $paddr = accept(SOCK, Server2);
        alarm 0;
    };
    if ($@) {
        # timed out
        
        close(Server2);
        logmsg "accept failed\n";
        return;
    }
    else {
        logmsg "accept worked\n";

        my($iport,$iaddr) = sockaddr_in($paddr);
        my $name = gethostbyaddr($iaddr,AF_INET);

        close(Server2); # close the listener when its served its purpose!

        logmsg "data connection from $name [", inet_ntoa($iaddr),
        "] at port $iport\n";
    }

    return;
}


sub PORT_command {
    my $arg = $_[0];

    if($arg !~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/) {
        logmsg "bad PORT-line: $arg\n";
        print "500 silly you, go away\r\n";
        return 0;
    }
    my $iaddr = inet_aton("$1.$2.$3.$4");

    my $port = ($5<<8)+$6;

    if(!$port || $port > 65535) {
        print STDERR "very illegal PORT number: $port\n";
        return 1;
    }

    my $paddr = sockaddr_in($port, $iaddr);
    my $proto   = getprotobyname('tcp') || 6;

    socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "major failure";
    connect(SOCK, $paddr)    || return 1;

    return \&SOCK;
}

$SIG{CHLD} = \&REAPER;

my %customreply;
my %customcount;
my %delayreply;
sub customize {
    undef %customreply;
    open(CUSTOM, "<log/ftpserver.cmd") ||
        return 1;

    logmsg "FTPD: Getting commands from log/ftpserver.cmd\n";

    while(<CUSTOM>) {
        if($_ =~ /REPLY ([A-Z]+) (.*)/) {
            $customreply{$1}=$2;
        }
        if($_ =~ /COUNT ([A-Z]+) (.*)/) {
            # we blank the customreply for this command when having
            # been used this number of times
            $customcount{$1}=$2;
        }
        elsif($_ =~ /DELAY ([A-Z]+) (\d*)/) {
            $delayreply{$1}=$2;
        }
        elsif($_ =~ /RETRWEIRDO/) {
            print "instructed to use RETRWEIRDO\n";
            $retrweirdo=1;
        }
        elsif($_ =~ /RETRNOSIZE/) {
            print "instructed to use RETRNOSIZE\n";
            $retrnosize=1;
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

for ( $waitedpid = 0;
      ($paddr = accept(Client,Server)) || $waitedpid;
        $waitedpid = 0, close Client)
{
    next if $waitedpid and not $paddr;
    my($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);

    # flush data:
    $| = 1;
        
    logmsg "connection from $name [", inet_ntoa($iaddr), "] at port $port\n";
    
    open(STDIN,  "<&Client")   || die "can't dup client to stdin";
    open(STDOUT, ">&Client")   || die "can't dup client to stdout";
    
    &customize(); # read test control instructions

    print @welcome;
    if($verbose) {
        for(@welcome) {
            print STDERR "OUT: $_";
        }
    }
    my $state="fresh";

    while(1) {

        last unless defined ($_ = <STDIN>);
        
        ftpmsg $_;
        
        # Remove trailing CRLF.
        s/[\n\r]+$//;

        unless (m/^([A-Z]{3,4})\s?(.*)/i) {
            print "500 '$_': command not understood.\r\n";
            logmsg "unknown crap received, bailing out hard\n";
            last;
        }
        my $FTPCMD=$1;
        my $FTPARG=$2;
        my $full=$_;
                 
        logmsg "Received \"$full\"\n";

        if($verbose) {
            print STDERR "IN: $full\n";
        }

        my $ok = $commandok{$FTPCMD};
        if($ok !~ /$state/) {
            print "500 $FTPCMD not OK in state: $state!\r\n";
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
            logmsg "$FTPCMD made to send '$text'\n";
        }
        if($text) {
            print "$text\r\n";
        }

        if($fake eq "") {
            # only perform this if we're not faking a reply
            # see if the new state is a function caller.
            my $func = $commandfunc{$FTPCMD};
            if($func) {
                # it is!
                \&$func($FTPARG, $FTPCMD);
            }
        }
            
    } # while(1)
    close(Client);
}
