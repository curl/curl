#!/usr/bin/perl
use Socket;
use Carp;
use FileHandle;

use strict;

sub spawn;  # forward declaration

open(FTPLOG, ">log/ftpd.log") ||
    print STDERR "failed to open log file, runs without logging\n";

sub logmsg { print FTPLOG @_; }

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

my $ftp_sendfile=""; # set to a file name when the file should be sent

socket(Server, PF_INET, SOCK_STREAM, $proto)|| die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
           pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))|| die "bind: $!";
listen(Server,SOMAXCONN) || die "listen: $!";

print "FTP server started on port $port\n";

open(PID, ">.ftpserver.pid");
print PID $$;
close(PID);

my $waitedpid = 0;
my $paddr;

sub REAPER {
    $waitedpid = wait;
    $SIG{CHLD} = \&REAPER;  # loathe sysV
  #  logmsg "reaped $waitedpid" . ($? ? " with exit $?" : '');
}

# USER is ok in fresh state
my %commandok = ( "USER" => "fresh",
                  "PASS" => "passwd",
                  "PASV" => "loggedin",
                  "PORT" => "loggedin",
                  "TYPE" => "loggedin|twosock",
                  "LIST" => "twosock",
                  );

# initially, we're in 'fresh' state
my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'twosock',   # PORT goes to twosock
                    'PASV' => 'twosock',   # PASV goes to twosock
                    );

my %displaytext = ('USER' => '331 We are happy you popped in!', # output FTP line
                   'PASS' => '230 Welcome you silly person',
                   'PORT' => '200 You said PORT - I say FINE',
                   'TYPE' => '200 I modify TYPE as you wanted',
                   'LIST' => '150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes)', #150 Here comes a directory your way',
                   );

# callback functions for certain commands
my %commandfunc = ( 'PORT', \&PORT_command,
                    'LIST', \&LIST_command,
                    'PASV', \&PASV_command);

my $pid;

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


sub LIST_command {
  #  print "150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes)\r\n";

    for(@ftpdir) {
        print KID_TO_WRITE $_;
        # print STDERR "PASS: $_";
    }
    close(KID_TO_WRITE);

    print "226 ASCII transfer complete\r\n";
    return 0;
}

# < 220 pm1 FTP server (SunOS 5.7) ready.
# > USER anonymous
# < 331 Guest login ok, send ident as password.
# > PASS curl_by_daniel@haxx.se
# < 230 Guest login ok, access restrictions apply.
# * We have successfully logged in
# * Connected to 127.0.0.1 (127.0.0.1)
# > PASV
# < 227 Entering Passive Mode (127,0,0,1,210,112)
# * Connecting to localhost (127.0.0.1) port 53872
# * Connected the data stream!
# > TYPE A
# < 200 Type set to A.
# > LIST
# < 150 ASCII data connection for /bin/ls (127.0.0.1,53873) (0 bytes).
#

sub PASV_command {
    $pid = open(KID_TO_WRITE, "|-");
    $SIG{ALRM} = sub { die "whoops, pipe broke" };

    if(0 == $pid) {
        # the child process runs the child function
    }
    else {
        # parent continues
 #       print STDERR "parent after fork!\n";
        return; # continue please
    }

    my $port = 10000;
    socket(Server2, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
    setsockopt(Server2, SOL_SOCKET, SO_REUSEADDR,
               pack("l", 1)) || die "setsockopt: $!";
    while($port < 11000) {
        if(bind(Server2, sockaddr_in($port, INADDR_ANY))) {
            last;
        }
        $port++; # try next port please
    }
    listen(Server2,SOMAXCONN) || die "listen: $!";

    printf("227 Entering Passive Mode (127,0,0,1,%d,%d)\n",
           ($port/256), ($port%256));

    my $waitedpid;
    my $paddr;

    $paddr = accept(Client2, Server2);
    my($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);

    logmsg "connection from $name [", inet_ntoa($iaddr), "] at port $port\n";

    open(STDOUT, ">&Client2")   || die "can't dup client to stdout";

 #   print STDERR "#### CONN\n";

    while(<STDIN>) {
        print $_;
   #     print STDERR "SEND: $_";
    }
    close(SOCK);

    close(Client2);

    exit;

}

sub PORT_command {
    my $arg = $_[0];
 #   print STDERR "fooo: $arg\n";

    $pid = open(KID_TO_WRITE, "|-");
    $SIG{ALRM} = sub { die "whoops, pipe broke" };

    if(0 == $pid) {
        # the child process runs the child function
    }
    else {
        # parent continues
  #      print STDERR "parent after fork!\n";
        return; # continue please
    }

   # open(STDOUT, ">&Client")   || die "can't dup client to stdout";

    if($arg !~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/) {
        logmsg "bad PORT-line: $arg\n";
        print "314 silly you, go away\r\n";
        return 1;
    }
    my $iaddr = inet_aton("$1.$2.$3.$4");
    my $paddr = sockaddr_in(($5<<8)+$6, $iaddr);
    my $proto   = getprotobyname('tcp') || 6;

    socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "major failure";
 #   print STDERR "socket()\n";

    connect(SOCK, $paddr)    || return 1;
 #    print STDERR "connect()\n";

    #while (defined($line = <SOCK>)) {
    #print STDERR $line;
    #}
 #   print STDERR "sending stdin to client\n";
    while(<STDIN>) {
        print SOCK $_;
 #       print STDERR "SEND: $_";
    }
    close(SOCK);

  #  print STDERR "close(SOCK)\n";

    exit; # we're a chiuld process who dies!
}

$SIG{CHLD} = \&REAPER;

for ( $waitedpid = 0;
      ($paddr = accept(Client,Server)) || $waitedpid;
        $waitedpid = 0, close Client)
{
    next if $waitedpid and not $paddr;
    my($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);

    logmsg "connection from $name [", inet_ntoa($iaddr), "] at port $port\n";

    # this code is forked and run
    spawn sub {
        # < 220 pm1 FTP server (SunOS 5.7) ready.
        # > USER anonymous
        # < 331 Guest login ok, send ident as password.
        # > PASS curl_by_daniel@haxx.se
        # < 230 Guest login ok, access restrictions apply.
        # * We have successfully logged in
        # * Connected to pm1 (193.15.23.1)
        # > PASV
        # < 227 Entering Passive Mode (193,15,23,1,231,59)
        # * Connecting to pm1 (193.15.23.1) port 59195
        # > TYPE A
        # < 200 Type set to A.
        # > LIST
        # < 150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes).
        # * Getting file with size: -1

        # flush data:
        $| = 1;
        
        print "220-running the curl suite test server\r\n",
        "220-running the curl suite test server\r\n",
        "220 running the curl suite test server\r\n";
        
        my $state="fresh";

        while(1) {

            last unless defined ($_ = <STDIN>);

            # Remove trailing CRLF.
            s/[\n\r]+$//;

            unless (m/^([A-Z]{3,4})\s?(.*)/i) {
                print STDERR
                    "badly formed command received: ".$_;
                exit 0;
            }
            my $FTPCMD=$1;
            my $FTPARG=$2;
            my $full=$_;
                 
            logmsg "GOT: ($1) $_\n";

            my $ok = $commandok{$FTPCMD};
            if($ok !~ /$state/) {
                print "314 $FTPCMD not OK ($ok) in state: $state!\r\n";
                exit;
            }

            my $newstate=$statechange{$FTPCMD};
            if($newstate eq "") {
                # remain in the same state
                #print "314 Wwwwweeeeird internal error state: $state\r\n";
                #exit;
            }
            else {
                $state = $newstate;
            }

            my $text = $displaytext{$FTPCMD};
            if($text) {
                print "$text\r\n";
            }

            # see if the new state is a function caller.
            my $func = $commandfunc{$FTPCMD};
            if($func) {
                # it is!
                \&$func($FTPARG);
            }

            logmsg "gone to state $state\n";

        }
        exit;
        #   print "Hello there, $name, it's now ", scalar localtime, "\r\n";
    };
}


sub spawn {
    my $coderef = shift;


    unless (@_ == 0 && $coderef && ref($coderef) eq 'CODE') {
        confess "usage: spawn CODEREF";
    }


    my $pid;
    if (!defined($pid = fork)) {
        logmsg "cannot fork: $!\n";
        return;
    } elsif ($pid) {
        logmsg "begat $pid\n";
        return; # I'm the parent
    }
    # else I'm the child -- go spawn


    open(STDIN,  "<&Client")   || die "can't dup client to stdin";
    open(STDOUT, ">&Client")   || die "can't dup client to stdout";
    ## open(STDERR, ">&STDOUT") || die "can't dup stdout to stderr";
    exit &$coderef();
}
