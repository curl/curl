#!/usr/bin/perl
#
# runserv.pl - run a dumb tcp server on a port for the curl test suite
# derived from 'ftproxy' by Björn Stenberg/Linus Nielsen that was
# derived from "fwdport.pl" by Tom Christiansen

use FileHandle;
use Net::hostent;      # Example 17-8    # by-name interface for host info
use IO::Socket;             # for creating server and client sockets
use POSIX ":sys_wait_h";    # for reaping our dead children

my $localip = $ARGV[0];
my $localport = $ARGV[1];

if(($localip eq "") ||
   ($localport eq "")) {
    print "Usage: runserv.pl <ip> <port>\n";
    exit;
}

my (
    %Children,              # hash of outstanding child processes
    $proxy_server,          # the socket we accept() from
    $ME,                    # basename of this program
);

($ME = $0) =~ s,.*/,,;      # retain just basename of script name

start_server();             # launch our own server
service_clients();          # wait for incoming
print "[TCP server exited]\n";
exit;

# begin our server 
sub start_server {
    $proxy_server = IO::Socket::INET->new(Listen    => 5,
                                          LocalAddr => $localip,
                                          LocalPort => $localport,
                                          Proto     => 'tcp',
                                          Reuse     => 1)
        or die "can't open socket";

#    print "[TCP server initialized";
#    print " on " . $proxy_server->sockhost() . ":" . 
#        $proxy_server->sockport() . "]\n";
}

sub service_clients { 
    my (
        $local_client,              # someone internal wanting out
        $lc_info,                   # local client's name/port information
        @rs_config,                 # temp array for remote socket options
        $rs_info,                   # remote server's name/port information
        $kidpid,                    # spawned child for each connection
        $file,
        $request,
        @headers
    );

    $SIG{CHLD} = \&REAPER;          # harvest the moribund

#    print "Listening...\n";

    while ($local_client = $proxy_server->accept()) {
        $lc_info = peerinfo($local_client);
        printf "[Connect from $lc_info]\n";

        $kidpid = fork();
        die "Cannot fork" unless defined $kidpid;
        if ($kidpid) {
            $Children{$kidpid} = time();            # remember his start time
            close $local_client;                    # likewise
            next;                                   # go get another client
        } 

        # now, read the data from the client
        # and pass back what we want it to have

        undef $request;
        undef $path;
        undef $ver;
        undef @headers;
        $cl=0;
        $left=0;
        while(<$local_client>) {
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
     #   print "Request: $request\n",
     #   "Path: $path\n",
     #   "Version: $ver\n";

        #
        # we always start the path with a number, this is the
        # test number that this server will use to know what
        # contents to pass back to the client
        #
        if($path =~ /^\/(\d*)/) {
            $testnum=$1;
        }
        else {
            print "UKNOWN TEST CASE\n";
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
            print $local_client $_;
        }
        close(DATA);

        exit; # whoever's still alive bites it
    }
}

# helper function to produce a nice string in the form HOST:PORT
sub peerinfo {
    my $sock = shift;
    my $hostinfo = gethostbyaddr($sock->peeraddr);
    return sprintf("%s:%s", 
                    $hostinfo->name || $sock->peerhost, 
                    $sock->peerport);
} 

# somebody just died.  keep harvesting the dead until 
# we run out of them.  check how long they ran.
sub REAPER { 
    my $child;
    my $start;
    while (($child = waitpid(-1,WNOHANG)) > 0) {
        if ($start = $Children{$child}) {
            my $runtime = time() - $start;
          #  printf "Child $child ran %dm%ss\n", 
          #  $runtime / 60, $runtime % 60;
            delete $Children{$child};
        } else {
          #  print "Unknown child process $child exited $?\n";
        } 
    }
    # If I had to choose between System V and 4.2, I'd resign. --Peter Honeyman
    $SIG{CHLD} = \&REAPER; 
};



