#!/usr/bin/perl
#
# $Id$
# This is the FTP server designed for the curl test suite.
#
# It is meant to excersive curl, it is not meant to become a fully working
# or even very standard compliant server.
#
# You may optionally specify port on the command line, otherwise it'll
# default to port 8921.
#

use Socket;
use Carp;
use FileHandle;

use strict;

require "getpart.pm";

open(FTPLOG, ">log/ftpd.log") ||
    print STDERR "failed to open log file, runs without logging\n";

sub logmsg { print FTPLOG "$$: "; print FTPLOG @_; }

sub ftpmsg { print INPUT @_; }

my $verbose=0; # set to 1 for debugging

my $port = 8921; # just a default
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
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
                 'QUIT'  => 'loggedin|twosock',
                 'DELE' => 'loggedin|twosock'
                 );

# initially, we're in 'fresh' state
my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'twosock',   # PORT goes to twosock
                    'PASV' => 'twosock',   # PASV goes to twosock
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
                   'REST' => '350 Yeah yeah we set it there for you',
                   'DELE' => '200 OK OK OK whatever you say'
                   );

# callback functions for certain commands
my %commandfunc = ( 'PORT' => \&PORT_command,
                    'LIST' => \&LIST_command,
                    'NLST' => \&NLST_command,
                    'PASV' => \&PASV_command,
                    'RETR' => \&RETR_command,   
                    'SIZE' => \&SIZE_command,
                    'REST' => \&REST_command,
                    'STOR' => \&STOR_command,
                    'APPE' => \&STOR_command, # append looks like upload
                    );

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

my $rest=0;
sub REST_command {
    $rest = $_[0];
}

sub LIST_command {
  #  print "150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes)\r\n";

    logmsg "$$: pass data to child pid\n";
    for(@ftpdir) {
        print SOCK $_;
    }
    close(SOCK);
    logmsg "$$: done passing data to child pid\n";

    print "226 ASCII transfer complete\r\n";
    return 0;
}

sub NLST_command {
    my @ftpdir=("file", "with space", "fake", "..", " ..", "funny", "README");
    for(@ftpdir) {
        print SOCK "$_\r\n";
    }
    close(SOCK);
    print "226 ASCII transfer complete\r\n";
    return 0;
}

sub SIZE_command {
    my $testno = $_[0];

    logmsg "SIZE number $testno\n";

    my $filename = "data/reply$testno.txt";

    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
        $atime,$mtime,$ctime,$blksize,$blocks)
        = stat($filename);

    if($size) {
        print "213 $size\r\n";
    }
    else {
        print "550 $testno: No such file or directory.\r\n";
    }
    return 0;
}

sub RETR_command {
    my $testno = $_[0];

    logmsg "RETR test number $testno\n";

    if($testno =~ /^verifiedserver$/) {
        # this is the secret command that verifies that this actually is
        # the curl test server
        print "150 Binary junk (10 bytes).\r\n";
        print SOCK "WE ROOLZ\r\n";
        close(SOCK);
        print "226 File transfer complete\r\n";
        return 0;
    }

    loadtest("data/test$testno");

    my @data = getpart("reply", "data");

    my $size=0;
    for(@data) {
        $size =+ length($_);
    }

    if($size) {
    
        if($rest) {
            # move read pointer forward
            $size -= $rest;
        }
        print "150 Binary data connection for $testno () ($size bytes).\r\n";
        $rest=0; # reset rest again

        for(@data) {
            print SOCK $_;
        }
        close(SOCK);

        print "226 File transfer complete\r\n";
    }
    else {
        print "550 $testno: No such file or directory.\r\n";
    }
    return 0;
}

sub STOR_command {
    my $testno=$_[0];

    logmsg "STOR test number $testno\n";

    my $filename = "log/upload.$testno";

    print "125 Gimme gimme gimme!\r\n";

    open(FILE, ">$filename") ||
        return 0; # failed to open output

    my $line;
    my $ulsize=0;
    while (defined($line = <SOCK>)) {
        $ulsize += length($line);
        print FILE $line;
    }
    close(FILE);
    close(SOCK);

    logmsg "received $ulsize bytes upload\n";

    print "226 File transfer complete\r\n";
    return 0;
}

sub PASV_command {
    socket(Server2, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
    setsockopt(Server2, SOL_SOCKET, SO_REUSEADDR,
               pack("l", 1)) || die "setsockopt: $!";
    while($port < 11000) {
        if(bind(Server2, sockaddr_in($port, INADDR_ANY))) {
            last;
        }
        $port++; # try next port please
    }
    if(11000 == $port) {
        print "500 no free ports!\r\n";
        logmsg "couldn't find free port\n";
        return 0;
    }
    listen(Server2,SOMAXCONN) || die "listen: $!";

    printf("227 Entering Passive Mode (127,0,0,1,%d,%d)\n",
           ($port/256), ($port%256));

    my $waitedpid;
    my $paddr;

    $paddr = accept(SOCK, Server2);
    my($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);

    logmsg "$$: data connection from $name [", inet_ntoa($iaddr), "] at port $port\n";

    return \&SOCK;
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
sub customize {
    undef %customreply;
    open(CUSTOM, "<log/ftpserver.cmd") ||
        return 1;

    if($verbose) {
        print STDERR "FTPD: Getting commands from log/ftpserver.cmd\n";
    }

    while(<CUSTOM>) {
        if($_ =~ /REPLY ([A-Z]+) (.*)/) {
            $customreply{$1}=$2;
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
    
    open(INPUT, ">log/server.input") ||
        logmsg "failed to open log/server.input\n";

    FTPLOG->autoflush(1);
    INPUT->autoflush(1);

    &customize(); # read test control instructions

    print @welcome;
    if($verbose) {
        print STDERR "OUT:\n";
        print STDERR @welcome;
    }
    my $state="fresh";

    while(1) {

        last unless defined ($_ = <STDIN>);
        
        ftpmsg $_;
        
        # Remove trailing CRLF.
        s/[\n\r]+$//;

        unless (m/^([A-Z]{3,4})\s?(.*)/i) {
            print "500 '$_': command not understood.\r\n";
            next;
        }
        my $FTPCMD=$1;
        my $FTPARG=$2;
        my $full=$_;
                 
        logmsg "GOT: ($1) $_\n";

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
            $state = $newstate;
        }

        my $text;
        $text = $customreply{$FTPCMD};
        my $fake = $text;
        if($text eq "") {
            $text = $displaytext{$FTPCMD};
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
                \&$func($FTPARG);
            }
        }

        logmsg "set to state $state\n";
            
    } # while(1)
    close(Client);
    close(Client2);
    close(Server2);
}
