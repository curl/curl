#!/usr/bin/perl
use Socket;
use Carp;
use FileHandle;

sub spawn;  # forward declaration
sub logmsg { #print "$0 $$: @_ at ", scalar localtime, "\n"
 }

my $port = $ARGV[0];
my $proto = getprotobyname('tcp');
$port = $1 if $port =~ /(\d+)/; # untaint port number

if($ARGV[1] =~ /^ftp$/i) {
    $protocol="FTP";
}
else {
    $protocol="HTTP";
}


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

$commandok{ USER => 'fresh'}; # USER is ok in fresh state

print "TEST: ".$commandok{"USER"}."\n";


$statechange{ 'USER' => 'passwd'}; # USER goes to passwd state

$displaytext{'USER' => '331 We are happy you arrived!'}; # output FTP line

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

            $state="fresh";

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
                $FTPCMD=$1;
                $full=$_;
                 
                print STDERR "GOT: ($1) $_\n";

                $ok = $commandok{$FTPCMD};
                if($ok !~ /$state/) {
                    print "314 $FTPCMD not OK ($ok) in state: $state!\r\n";
                    exit;
                }

                $state=$statechange{$FTPCMD};
                if($command{$1} eq "") {
                    print "314 Wwwwweeeeird internal error\r\n";
                    exit
                }
                $text = $displaytext{$FTPCMD};
                print "$text\r\n";
            }
            exit;
        }
        # otherwise, we're doing HTTP

        while(<STDIN>) {
            if($_ =~ /([A-Z]*) (.*) HTTP\/1.(\d)/) {
                $request=$1;
                $path=$2;
                $ver=$3;
            }
            elsif($_ =~ /^Content-Length: (\d*)/) {
                $cl=$1;
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
