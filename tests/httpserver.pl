#!/usr/bin/perl
use Socket;
use Carp;
use FileHandle;

use strict;

sub spawn;  # forward declaration
sub logmsg { #print "$0 $$: @_ at ", scalar localtime, "\n"
 }

my $verbose=0; # set to 1 for debugging

my $port = 8999; # just a default
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

if($verbose) {
    print "HTTP server started on port $port\n";
}

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

        my @headers;

      stdin:
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

                if($verbose) {
                    print STDERR "OUT: sending reply $testnum\n";
                }
            }
            else {
                $testnum=0;
            }
            open(INPUT, ">>log/server.input");
            for(@headers) {
                print INPUT $_;
            }
            close(INPUT);
            
            if(0 == $testnum ) {
                print "HTTP/1.1 200 OK\r\n",
                "header: yes\r\n",
                "\r\n",
                "You must enter a test number to get good data back\r\n";
            }
            else {
                # send a custom reply to the client
                open(DATA, "<data/reply$testnum.txt");
                while(<DATA>) {
                    print $_;
                    if($verbose) {
                        print STDERR "OUT: $_";
                    }
                }
                close(DATA);
            }
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
