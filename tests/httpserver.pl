#!/usr/bin/perl
use Socket;
use Carp;
use FileHandle;

use strict;

sub spawn;  # forward declaration
sub logmsg { #print "$0 $$: @_ at ", scalar localtime, "\n"
 }

my $port = $ARGV[0];
my $proto = getprotobyname('tcp') || 6;
$port = $1 if $port =~ /(\d+)/; # untaint port number

my $protocol;
if($ARGV[1] =~ /^ftp$/i) {
    $protocol="FTP";
}
else {
    $protocol="HTTP";
}

my $verbose=0; # set to 1 for debugging

socket(Server, PF_INET, SOCK_STREAM, $proto)|| die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
           pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))|| die "bind: $!";
listen(Server,SOMAXCONN) || die "listen: $!";

print "$protocol server started on port $port\n";

open(PID, ">.server.pid");
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
                  );

my %statechange = ( 'USER' => 'passwd',    # USER goes to passwd state
                    'PASS' => 'loggedin',  # PASS goes to loggedin state
                    'PORT' => 'ported',    # PORT goes to ported
                    );

my %displaytext = ('USER' => '331 We are happy you popped in!', # output FTP line
                   'PASS' => '230 Welcome you silly person',
                   );

my %commandfunc = ( 'PORT', \&PORT_command );

sub PORT_command {
    my $arg = $_[0];
    print STDERR "fooo: $arg\n";

    # "193,15,23,1,172,201"

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
    while (defined($line = <SOCK>)) {
        print STDERR $line;
    }

    close(SOCK);
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
        my ($request, $path, $ver, $left, $cl);

        if($protocol eq "FTP") {

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

                unless (m/^([A-Z]{3,4})\s?(.*)/i)
                {
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

                $state=$statechange{$FTPCMD};
                if($state eq "") {
                    print "314 Wwwwweeeeird internal error state: $state\r\n";
                    exit;
                }

                # see if the new state is a function caller.
                my $func = $commandfunc{$FTPCMD};
                if($func) {
                    # it is!
                    spawn \&$func($FTPARG);
                }

                print STDERR "gone to state $state\n";

                my $text = $displaytext{$FTPCMD};
                print "$text\r\n";
            }
            exit;
        }
        # otherwise, we're doing HTTP

        my @headers;
        while(<STDIN>) {
            if($_ =~ /([A-Z]*) (.*) HTTP\/1.(\d)/) {
                $request=$1;
                $path=$2;
                $ver=$3;
            }
            elsif($_ =~ /^Content-Length: (\d*)/) {
                $cl=$1;
            }

            if($verbose) {
                print STDERR "IN: $_";
            }
            
            push @headers, $_;

            if($left > 0) {
                $left -= length($_);
                if($left == 0) {
                    $left = -1; # just to force a loop break here
                }
            }
            # print STDERR "RCV ($left): $_";

            if(!$left &&
               ($_ eq "\r\n") or ($_ eq "")) {
                if($request =~ /^(POST|PUT)$/) {
                    $left=$cl;
                }
                else {
                    $left = -1; # force abort
                }
            }
            if($left < 0) {
                last;
            }
        }

        if($path =~ /verifiedserver/) {
            # this is a hard-coded query-string for the test script
            # to verify that this is the server actually running!
            print "HTTP/1.1 999 WE ROOLZ\r\n";
            exit;
        }
        else {

            #
            # we always start the path with a number, this is the
            # test number that this server will use to know what
            # contents to pass back to the client
            #
            my $testnum;
            if($path =~ /.*\/(\d*)/) {
                $testnum=$1;
            }
            else {
                print STDERR "UKNOWN TEST CASE\n";
                exit;
            }
            open(INPUT, ">log/server.input");
            for(@headers) {
                print INPUT $_;
            }
            close(INPUT);
            
            # send a reply to the client
            open(DATA, "<data/reply$testnum.txt");
            while(<DATA>) {
                print $_;
            }
            close(DATA);
        }
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
