#!/usr/bin/perl
use Socket;
use Carp;
use FileHandle;

use strict;

sub spawn;  # forward declaration
sub logmsg { #print "$0 $$: @_ at ", scalar localtime, "\n"
 }

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

my $protocol;
my $ftp_sendfile=""; # set to a file name when the file should be sent

socket(Server, PF_INET, SOCK_STREAM, $proto)|| die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
           pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))|| die "bind: $!";
listen(Server,SOMAXCONN) || die "listen: $!";

print "$protocol server started on port $port\n";

open(PID, ">.ftpserver.pid");
print PID $$;
close(PID);

my $waitedpid = 0;
my $paddr;

sub REAPER {
    $waitedpid = wait;
    $SIG{CHLD} = \&REAPER;  # loathe sysV
    logmsg "reaped $waitedpid" . ($? ? " with exit $?" : '');
}

# USER is ok in fresh state
my %commandok = ( "USER" => "fresh",
                  "PASS" => "passwd",
                  # "PASV" => "loggedin", we can't handle PASV yet
                  "PORT" => "loggedin",
                  "TYPE" => "loggedin|twosock",
                  "LIST" => "twosock",
                  );

# initially, we're in 'fresh' state
my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'twosock',    # PORT goes to twosock
                    );

my %displaytext = ('USER' => '331 We are happy you popped in!', # output FTP line
                   'PASS' => '230 Welcome you silly person',
                   'PORT' => '200 You said PORT - I say FINE',
                   'TYPE' => '200 I modify TYPE as you wanted',
                   'LIST' => '150 Here comes a directory your way',
                   );

my %commandfunc = ( 'PORT', \&PORT_command,
                    'LIST', \&LIST_command);

sub LIST_command {
    $ftp_sendfile="ftptest"; # send this now
    return 0;
}

sub PORT_command {
    my $arg = $_[0];
    print STDERR "fooo: $arg\n";

    # "193,15,23,1,172,201"

    my $pid;
    if (!defined($pid = fork)) {
        logmsg "cannot fork: $!";
        return 1;
    } elsif ($pid) {
        logmsg "begat $pid";
        print STDERR "dasdasd a\n";
        return 0;
    }
    # else I'm the child -- go spawn

    if($arg !~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/) {
        print STDERR "bad PORT-line: $arg\n";
        print "314 silly you, go away\r\n";
        return 1;
    }
    my $iaddr = inet_aton("$1.$2.$3.$4");
    my $paddr = sockaddr_in(($5<<8)+$6, $iaddr);
    my $proto   = getprotobyname('tcp') || 6;

    socket(SOCK, PF_INET, SOCK_STREAM, $proto) || die "major failure";
    print STDERR "socket()\n";

    connect(SOCK, $paddr)    || return 1;
    print STDERR "connect()\n";

    my $line;

    while($ftp_sendfile eq "") {
        sleep 1;
    }
    open(SEND, "<$ftp_sendfile") ||
        print STDERR "couldn't open file to send";

    #while (defined($line = <SOCK>)) {
    #print STDERR $line;
    #}
    while(<SEND>) {
        print $_;
    }
    close(SEND);
    close(SOCK);

    $ftp_sendfile="";

    print STDERR "close()\n";

}

$SIG{CHLD} = \&REAPER;

for ( $waitedpid = 0;
      ($paddr = accept(Client,Server)) || $waitedpid;
        $waitedpid = 0, close Client)
{
    next if $waitedpid and not $paddr;
    my($port,$iaddr) = sockaddr_in($paddr);
    my $name = gethostbyaddr($iaddr,AF_INET);

    logmsg "connection from $name [", inet_ntoa($iaddr), "] at port $port";

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
                 
            print STDERR "GOT: ($1) $_\n";

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

            # see if the new state is a function caller.
            my $func = $commandfunc{$FTPCMD};
            if($func) {
                # it is!
                \&$func($FTPARG);
                print STDERR "MOOOOOOOOO\n";
            }

            print STDERR "gone to state $state\n";

            my $text = $displaytext{$FTPCMD};
            print "$text\r\n";
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
        logmsg "cannot fork: $!";
        return;
    } elsif ($pid) {
        logmsg "begat $pid";
        return; # I'm the parent
    }
    # else I'm the child -- go spawn


    open(STDIN,  "<&Client")   || die "can't dup client to stdin";
    open(STDOUT, ">&Client")   || die "can't dup client to stdout";
    ## open(STDERR, ">&STDOUT") || die "can't dup stdout to stderr";
    exit &$coderef();
}
