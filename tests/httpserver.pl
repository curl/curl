#!/usr/bin/perl
use Socket;
use Carp;

sub spawn;  # forward declaration
sub logmsg { #print "$0 $$: @_ at ", scalar localtime, "\n"
 }

my $port = shift || $ARGV[0];
my $proto = getprotobyname('tcp');
$port = $1 if $port =~ /(\d+)/; # untaint port number

socket(Server, PF_INET, SOCK_STREAM, $proto)|| die "socket: $!";
    setsockopt(Server, SOL_SOCKET, SO_REUSEADDR,
               pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))|| die "bind: $!";
listen(Server,SOMAXCONN) || die "listen: $!";

logmsg "server started on port $port";

open(PID, ">log/server.pid");
print PID $$;
close(PID);

my $waitedpid = 0;
my $paddr;

sub REAPER {
    $waitedpid = wait;
    $SIG{CHLD} = \&REAPER;  # loathe sysV
    logmsg "reaped $waitedpid" . ($? ? " with exit $?" : '');
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
        while(<STDIN>) {
            if($_ =~ /(GET|POST|HEAD) (.*) HTTP\/1.(\d)/) {
                $request=$1;
                $path=$2;
                $ver=$3;
            }
            elsif($_ =~ /^Content-Length: (\d*)/) {
                $cl=$1;
            }
            # print "RCV: $_";

            push @headers, $_;

            if($left > 0) {
                $left -= length($_);
            }

            if(($_ eq "\r\n") or ($_ eq "")) {
                if($request eq "POST") {
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

        #
        # we always start the path with a number, this is the
        # test number that this server will use to know what
        # contents to pass back to the client
        #
        if($path =~ /^\/(\d*)/) {
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
