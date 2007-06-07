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
# These should be the only variables that might be needed to get edited:

use strict;
#use Time::HiRes qw( gettimeofday );
#use warnings;

@INC=(@INC, $ENV{'srcdir'}, ".");

require "getpart.pm"; # array functions
require "valgrind.pm"; # valgrind report parser
require "ftp.pm";

my $srcdir = $ENV{'srcdir'} || '.';
my $HOSTIP="127.0.0.1";
my $HOST6IP="[::1]";

my $base = 8990; # base port number

my $HTTPPORT; # HTTP server port
my $HTTP6PORT; # HTTP IPv6 server port
my $HTTPSPORT; # HTTPS server port
my $FTPPORT; # FTP server port
my $FTP2PORT; # FTP server 2 port
my $FTPSPORT; # FTPS server port
my $FTP6PORT; # FTP IPv6 server port
my $TFTPPORT; # TFTP
my $TFTP6PORT; # TFTP
my $SSHPORT; # SCP/SFTP
my $SOCKSPORT; # SOCKS4/5 port

my $CURL="../src/curl"; # what curl executable to run on the tests
my $DBGCURL=$CURL; #"../src/.libs/curl";  # alternative for debugging
my $LOGDIR="log";
my $TESTDIR="$srcdir/data";
my $LIBDIR="./libtest";
my $SERVERIN="$LOGDIR/server.input"; # what curl sent the server
my $SERVER2IN="$LOGDIR/server2.input"; # what curl sent the second server
my $CURLLOG="$LOGDIR/curl.log"; # all command lines run
my $FTPDCMD="$LOGDIR/ftpserver.cmd"; # copy ftp server instructions here

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

my $HTTPPIDFILE=".http.pid";
my $HTTP6PIDFILE=".http6.pid";
my $HTTPSPIDFILE=".https.pid";
my $FTPPIDFILE=".ftp.pid";
my $FTP6PIDFILE=".ftp6.pid";
my $FTP2PIDFILE=".ftp2.pid";
my $FTPSPIDFILE=".ftps.pid";
my $TFTPPIDFILE=".tftpd.pid";
my $TFTP6PIDFILE=".tftp6.pid";
my $SSHPIDFILE=".ssh.pid";
my $SOCKSPIDFILE=".socks.pid";

# invoke perl like this:
my $perl="perl -I$srcdir";
my $server_response_maxtime=13;

# this gets set if curl is compiled with debugging:
my $curl_debug=0;
my $libtool;

# name of the file that the memory debugging creates:
my $memdump="$LOGDIR/memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="$perl $srcdir/memanalyze.pl";

my $stunnel = checkcmd("stunnel4") || checkcmd("stunnel");
my $valgrind = checkcmd("valgrind");
my $valgrind_logfile="--logfile";
my $start;
my $forkserver=0;
my $ftpchecktime; # time it took to verify our test FTP server

my $valgrind_tool;
if($valgrind) {
    # since valgrind 2.1.x, '--tool' option is mandatory
    # use it, if it is supported by the version installed on the system
    system("valgrind --help 2>&1 | grep -- --tool > /dev/null 2>&1");
    if (($? >> 8)==0) {
        $valgrind_tool="--tool=memcheck ";
    }
    open(C, "<", $CURL);
    my $l = <C>;
    if($l =~ /^\#\!/) {
        # The first line starts with "#!" which implies a shell-script.
        # This means libcurl is built shared and curl is a wrapper-script
        # Disable valgrind in this setup
        $valgrind=0;
    }
    close(C);

    # valgrind 3 renamed the --logfile option to --log-file!!!
    my $ver=`valgrind --version`;
    # cut off all but digits and dots
    $ver =~ s/[^0-9.]//g;

    if($ver >= 3) {
        $valgrind_logfile="--log-file";
    }
}

my $gdb = checkcmd("gdb");

my $ssl_version; # set if libcurl is built with SSL support
my $large_file;  # set if libcurl is built with large file support
my $has_idn;     # set if libcurl is built with IDN support
my $http_ipv6;   # set if HTTP server has IPv6 support
my $ftp_ipv6;    # set if FTP server has IPv6 support
my $tftp_ipv6;   # set if TFTP server has IPv6 support
my $has_ipv6;    # set if libcurl is built with IPv6 support
my $has_libz;    # set if libcurl is built with libz support
my $has_getrlimit;  # set if system has getrlimit()
my $has_ntlm;    # set if libcurl is built with NTLM support

my $has_openssl; # built with a lib using an OpenSSL-like API
my $has_gnutls;  # built with GnuTLS
my $has_nss;     # built with NSS
my $has_yassl;   # built with yassl

my $ssllib;      # name of the lib we use (for human presentation)
my $has_crypto;  # set if libcurl is built with cryptographic support
my $has_textaware; # set if running on a system that has a text mode concept
  # on files. Windows for example
my @protocols;   # array of supported protocols

my $skipped=0;  # number of tests skipped; reported in main loop
my %skipped;    # skipped{reason}=counter, reasons for skip
my @teststat;   # teststat[testnum]=reason, reasons for skip

#######################################################################
# variables the command line options may set
#

my $short;
my $verbose;
my $debugprotocol;
my $anyway;
my $gdbthis;      # run test case with gdb debugger
my $keepoutfiles; # keep stdout and stderr files after tests
my $listonly;     # only list the tests
my $postmortem;   # display detailed info about failed tests

my $pwd;          # current working directory

my %run;	  # running server

# torture test variables
my $torture;
my $tortnum;
my $tortalloc;

# open and close each time to allow removal at any time
sub logmsg {
# uncomment the Time::HiRes usage for this
#    my ($seconds, $microseconds) = gettimeofday;
#    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
#        localtime($seconds);
    my $t;
    if(1) {
#        $t = sprintf ("%02d:%02d:%02d.%06d ", $hour, $min, $sec,
#                      $microseconds);
    }
    for(@_) {
        print "${t}$_";
    }
}

chomp($pwd = `pwd`);

# get the name of the current user
my $USER = $ENV{USER};	# Linux
if (!$USER) {
    $USER = $ENV{USERNAME};	# Windows
    if (!$USER) {
        $USER = $ENV{LOGNAME};	# Some UNIX (I think)
    }
}

# enable memory debugging if curl is compiled with it
$ENV{'CURL_MEMDEBUG'} = $memdump;
$ENV{'HOME'}=$pwd;

sub catch_zap {
    my $signame = shift;
    logmsg "runtests.pl received SIG$signame, exiting\n";
    stopservers(1);
    die "Somebody sent me a SIG$signame";
}
$SIG{INT} = \&catch_zap;
$SIG{KILL} = \&catch_zap;

##########################################################################
# Clear all possible '*_proxy' environment variables for various protocols
# to prevent them to interfere with our testing!

my $protocol;
foreach $protocol (('ftp', 'http', 'ftps', 'https', 'no')) {
    my $proxy = "${protocol}_proxy";
    # clear lowercase version
    $ENV{$proxy}=undef;
    # clear uppercase version
    $ENV{uc($proxy)}=undef;
}

# make sure we don't get affected by other variables that control our
# behaviour

$ENV{'SSL_CERT_DIR'}=undef;
$ENV{'SSL_CERT_PATH'}=undef;
$ENV{'CURL_CA_BUNDLE'}=undef;

#######################################################################
# Check if a given child process has just died. Reaps it if so.
#
sub checkdied {
    use POSIX ":sys_wait_h";
    my $pid = $_[0];
    my $rc = waitpid($pid, &WNOHANG);
    return $rc == $pid;
}

#######################################################################
# Start a new thread/process and run the given command line in there.
# Return the pids (yes plural) of the new child process to the parent.
#
sub startnew {
    my ($cmd, $pidfile,$fake)=@_;

    logmsg "startnew: $cmd\n" if ($verbose);

    my $child = fork();
    my $pid2;

    if(not defined $child) {
        logmsg "fork() failure detected\n";
        return (-1,-1);
    }

    if(0 == $child) {
        # Here we are the child. Run the given command.

        # Calling exec() within a pseudo-process actually spawns the requested
        # executable in a separate process and waits for it to complete before
        # exiting with the same exit status as that process.  This means that
        # the process ID reported within the running executable will be
        # different from what the earlier Perl fork() might have returned.

        # exec() should never return back here to this process. We protect
        # ourselfs calling die() just in case something goes really bad.

        exec($cmd) || die "Can't exec() $cmd: $!";

        die "error: exec() has returned";
    }


    # Ugly hack but ssh doesn't support pid files
    if ($fake) {
        logmsg "$pidfile faked with pid=$child\n" if($verbose);
        open(OUT, ">", $pidfile);
        print OUT $child;
        close(OUT);
	# could/should do a while connect fails sleep a bit and loop
	sleep 1;
        if (checkdied($child)) {
            logmsg "startnew: Warning: child process has failed to start\n" if($verbose);
            return (-1,-1);
        }
    }
    my $count=12;
    while($count--) {
        if(-f $pidfile) {
            open(PID, "<", $pidfile);
            $pid2 = 0 + <PID>;
            close(PID);
            if($pid2 && kill(0, $pid2)) {
                # if $pid2 is valid, then make sure this pid is alive, as
                # otherwise it is just likely to be the _previous_ pidfile or
                # similar!
                last;
            }
        }
        if (checkdied($child)) {
            logmsg "startnew: Warning: child process has died\n" if($verbose);
            # We can't just abort waiting for the server with a
            # return (-1,-1);
            # because the server might have forked and could still start
            # up normally. Instead, just reduce the amount of time we remain
            # waiting.
            $count >>= 2;
        }
        sleep(1);
    }

    return ($child, $pid2);
}


#######################################################################
# Check for a command in the PATH.
#
sub checkcmd {
    my ($cmd)=@_;
    my @paths=("/usr/sbin", "/usr/local/sbin", "/sbin", "/usr/bin",
               "/usr/local/bin", split(":", $ENV{'PATH'}));
    for(@paths) {
        if( -x "$_/$cmd") {
            return "$_/$cmd";
        }
    }
}

#######################################################################
# Memory allocation test and failure torture testing.
#
sub torture {
    my $testcmd = shift;
    my $gdbline = shift;

    # remove memdump first to be sure we get a new nice and clean one
    unlink($memdump);

    # First get URL from test server, ignore the output/result
    system($testcmd);

    logmsg " CMD: $testcmd\n" if($verbose);

    # memanalyze -v is our friend, get the number of allocations made
    my $count=0;
    my @out = `$memanalyze -v $memdump`;
    for(@out) {
        if(/^Allocations: (\d+)/) {
            $count = $1;
            last;
        }
    }
    if(!$count) {
        logmsg " found no allocs to make fail\n";
        return 0;
    }

    logmsg " $count allocations to make fail\n";

    for ( 1 .. $count ) {
        my $limit = $_;
        my $fail;
        my $dumped_core;

        if($tortalloc && ($tortalloc != $limit)) {
            next;
        }

        logmsg "Fail alloc no: $limit\r" if($verbose);

        # make the memory allocation function number $limit return failure
        $ENV{'CURL_MEMLIMIT'} = $limit;

        # remove memdump first to be sure we get a new nice and clean one
        unlink($memdump);

        logmsg "**> Alloc number $limit is now set to fail <**\n" if($gdbthis);

        my $ret;
        if($gdbthis) {
            system($gdbline)
        }
        else {
            $ret = system($testcmd);
        }

        # Now clear the variable again
        $ENV{'CURL_MEMLIMIT'} = undef;

        if(-r "core") {
            # there's core file present now!
            logmsg " core dumped\n";
            $dumped_core = 1;
            $fail = 2;
        }

        # verify that it returns a proper error code, doesn't leak memory
        # and doesn't core dump
        if($ret & 255) {
            logmsg " system() returned $ret\n";
            $fail=1;
        }
        else {
            my @memdata=`$memanalyze $memdump`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                logmsg "** MEMORY FAILURE\n";
                logmsg @memdata;
                logmsg `$memanalyze -l $memdump`;
                $fail = 1;
            }
        }
        if($fail) {
            logmsg " Failed on alloc number $limit in test.\n",
            " invoke with -t$limit to repeat this single case.\n";
            stopservers($verbose);
            return 1;
        }
    }

    logmsg "torture OK\n";
    return 0;
}

#######################################################################
# stop the given test server (pid)
#
sub stopserver {
    my ($pid) = @_;

    if(not defined $pid || $pid <= 0) {
        return; # whad'da'ya wanna'da with no pid ?
    }

    # It might be more than one pid
    # Send each one a SIGTERM to gracefully kill it

    my @killed;
    my @pids = split(/\s+/, $pid);
    for (@pids) {
        chomp($_);
        if($_ =~ /^(\d+)$/) {
            if(($1 > 0) && kill(0, $1)) {
                if($verbose) {
                    logmsg "RUN: Test server pid $1 signalled to die\n";
                }
                kill(15, $1); # die!
                push @killed, $1;
            }
        }
    }

    # Give each process killed up to a few seconds to die, then send
    # a SIGKILL to finish it off for good.
    for (@killed) {
        my $count = 5; # wait for this many seconds for server to die
	while($count--) {
            if (!kill(0, $_) || checkdied($_)) {
                last;
            }
            sleep(1);
        }
        if ($count < 0) {
            logmsg "RUN: forcing pid $_ to die with SIGKILL\n";
            kill(9, $_); # die!
        }
    }
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address" #

sub verifyhttp {
    my ($proto, $ip, $port) = @_;
    my $cmd = "$CURL -m$server_response_maxtime -o log/verifiedserver -ksvg \"$proto://$ip:$port/verifiedserver\" 2>log/verifyhttp";
    my $pid;

    # verify if our/any server is running on this port
    logmsg "CMD; $cmd\n" if ($verbose);
    my $res = system($cmd);

    $res >>= 8; # rotate the result
    my $data;

    if($res && $verbose) {
        open(ERR, "<log/verifyhttp");
        my @e = <ERR>;
        close(ERR);
        logmsg "RUN: curl command returned $res\n";
        for(@e) {
            if($_ !~ /^([ \t]*)$/) {
                logmsg "RUN: $_";
            }
        }
    }
    open(FILE, "<", "log/verifiedserver");
    my @file=<FILE>;
    close(FILE);
    $data=$file[0]; # first line

    if ( $data =~ /WE ROOLZ: (\d+)/ ) {
        $pid = 0+$1;
    }
    elsif($res == 6) {
        # curl: (6) Couldn't resolve host '::1'
        logmsg "RUN: failed to resolve host\n";
        return 0;
    }
    elsif($data || ($res != 7)) {
        logmsg "RUN: Unknown server is running on port $port\n";
        return 0;
    }
    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address" #

sub verifyftp {
    my ($proto, $ip, $port) = @_;
    my $pid;
    my $time=time();
    my $extra;
    if($proto eq "ftps") {
    	$extra = "-k --ftp-ssl-control ";
    }
    my $cmd="$CURL -m$server_response_maxtime --silent -vg $extra\"$proto://$ip:$port/verifiedserver\" 2>log/verifyftp";
    # check if this is our server running on this port:
    my @data=`$cmd`;
    logmsg "RUN: $cmd\n" if($verbose);
    my $line;

    foreach $line (@data) {
        if ( $line =~ /WE ROOLZ: (\d+)/ ) {
            # this is our test server with a known pid!
            $pid = 0+$1;
            last;
        }
    }
    if($pid <= 0 && $data[0]) {
        # this is not a known server
        logmsg "RUN: Unknown server on our FTP port: $port\n";
        return 0;
    }
    # we can/should use the time it took to verify the FTP server as a measure
    # on how fast/slow this host/FTP is.
    my $took = time()-$time;

    if($verbose) {
        logmsg "RUN: Verifying our test FTP server took $took seconds\n";
    }
    $ftpchecktime = $took?$took:1; # make sure it never is zero

    return $pid;
}

#######################################################################
# STUB for verifying scp/sftp

sub verifyssh {
    my ($proto, $ip, $port) = @_;
    open(FILE, "<" . $SSHPIDFILE);
    my $pid=0+<FILE>;
    close(FILE);
    return $pid;
}

#######################################################################
# STUB for verifying socks

sub verifysocks {
    my ($proto, $ip, $port) = @_;
    open(FILE, "<" . $SOCKSPIDFILE);
    my $pid=0+<FILE>;
    close(FILE);
    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.
# Retry during 5 seconds before giving up.
#

my %protofunc = ('http' => \&verifyhttp,
                 'https' => \&verifyhttp,
                 'ftp' => \&verifyftp,
                 'ftps' => \&verifyftp,
                 'tftp' => \&verifyftp,
                 'ssh' => \&verifyssh,
                 'socks' => \&verifysocks);

sub verifyserver {
    my ($proto, $ip, $port) = @_;

    my $count = 5; # try for this many seconds
    my $pid;

    while($count--) {
        my $fun = $protofunc{$proto};

        $pid = &$fun($proto, $ip, $port);

        if($pid) {
            last;
        }
        sleep(1);
    }
    return $pid;
}



#######################################################################
# start the http server
#
sub runhttpserver {
    my ($verbose, $ipv6) = @_;
    my $RUNNING;
    my $pid;
    my $pidfile = $HTTPPIDFILE;
    my $port = $HTTPPORT;
    my $ip = $HOSTIP;
    my $nameext;
    my $fork = $forkserver?"--fork":"";

    if($ipv6) {
        # if IPv6, use a different setup
        $pidfile = $HTTP6PIDFILE;
        $port = $HTTP6PORT;
        $ip = $HOST6IP;
        $nameext="-ipv6";
    }

    $pid = checkserver($pidfile);

    if($pid > 0) {
        stopserver($pid);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $dir=$ENV{'srcdir'};
    if($dir) {
        $flag .= "-d \"$dir\" ";
    }

    my $cmd="$perl $srcdir/httpserver.pl -p $pidfile $fork$flag $port $ipv6";
    my ($httppid, $pid2) =
        startnew($cmd, $pidfile,0); # start the server in a new process

    if(!kill(0, $httppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the HTTP server\n";
        stopservers($verbose);
        return (0,0);
    }

    # Server is up. Verify that we can speak to it.
    if(!verifyserver("http", $ip, $port)) {
        logmsg "RUN: HTTP$nameext server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$httppid $pid2");
        return (0,0);
    }

    if($verbose) {
        logmsg "RUN: HTTP$nameext server is now running PID $httppid\n";
    }

    sleep(1);

    return ($httppid, $pid2);
}

#######################################################################
# start the https server (or rather, tunnel)
#
sub runhttpsserver {
    my ($verbose, $ipv6) = @_;
    my $STATUS;
    my $RUNNING;
    my $ip = $HOSTIP;

    if(!$stunnel) {
        return 0;
    }

    if($ipv6) {
        # not complete yet
        $ip = $HOST6IP;
    }

    my $pid=checkserver($HTTPSPIDFILE);

    if($pid > 0) {
        # kill previous stunnel!
        stopserver($pid);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/httpsserver.pl $flag -p https -s \"$stunnel\" -d $srcdir -r $HTTPPORT $HTTPSPORT";

    my ($httpspid, $pid2) = startnew($cmd, $HTTPSPIDFILE,0);

    if(!kill(0, $httpspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the HTTPS server\n";
        stopservers($verbose);
        return(0,0);
    }

    # Server is up. Verify that we can speak to it.
    if(!verifyserver("https", $ip, $HTTPSPORT)) {
        logmsg "RUN: HTTPS server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$httpspid $pid2");
        return (0,0);
    }

    if($verbose) {
        logmsg "RUN: HTTPS server is now running PID $httpspid\n";
    }

    sleep(1);

    return ($httpspid, $pid2);
}

#######################################################################
# start the ftp server
#
sub runftpserver {
    my ($id, $verbose, $ipv6) = @_;
    my $STATUS;
    my $RUNNING;
    my $port = $id?$FTP2PORT:$FTPPORT;
    # check for pidfile
    my $pidfile = $id?$FTP2PIDFILE:$FTPPIDFILE;
    my $ip=$HOSTIP;
    my $nameext;
    my $cmd;

    if($ipv6) {
        # if IPv6, use a different setup
        $pidfile = $FTP6PIDFILE;
        $port = $FTP6PORT;
        $ip = $HOST6IP;
        $nameext="-ipv6";
    }

    my $pid = checkserver($pidfile);
    if($pid >= 0) {
        stopserver($pid);
    }

    # start our server:
    my $flag=$debugprotocol?"-v ":"";
    $flag .= "-s \"$srcdir\" ";
    if($id) {
        $flag .="--id $id ";
    }
    if($ipv6) {
        $flag .="--ipv6 ";
    }
    $cmd="$perl $srcdir/ftpserver.pl --pidfile $pidfile $flag --port $port";

    unlink($pidfile);

    my ($ftppid, $pid2) = startnew($cmd, $pidfile,0);

    if(!$ftppid || !kill(0, $ftppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the FTP$id$nameext server\n";
        return -1;
    }

    # Server is up. Verify that we can speak to it.
    if(!verifyserver("ftp", $ip, $port)) {
        logmsg "RUN: FTP$id$nameext server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$ftppid $pid2");
        return (0,0);
    }

    if($verbose) {
        logmsg "RUN: FTP$id$nameext server is now running PID $ftppid\n";
    }

    sleep(1);

    return ($pid2, $ftppid);
}

#######################################################################
# start the ftps server (or rather, tunnel)
#
sub runftpsserver {
    my ($verbose, $ipv6) = @_;
    my $STATUS;
    my $RUNNING;
    my $ip = $HOSTIP;

    if(!$stunnel) {
        return 0;
    }

    if($ipv6) {
        # not complete yet
        $ip = $HOST6IP;
    }

    my $pid=checkserver($FTPSPIDFILE);

    if($pid > 0) {
        # kill previous stunnel!
        stopserver($pid);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/httpsserver.pl $flag -p ftps -s \"$stunnel\" -d $srcdir -r $FTPPORT $FTPSPORT";

    my ($ftpspid, $pid2) = startnew($cmd, $FTPSPIDFILE,0);

    if(!kill(0, $ftpspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the FTPS server\n";
        stopservers($verbose);
        return(0,0);
    }

    # Server is up. Verify that we can speak to it.
    if(!verifyserver("ftps", $ip, $FTPSPORT)) {
        logmsg "RUN: FTPS server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$ftpspid $pid2");
        return (0,0);
    }

    if($verbose) {
        logmsg "RUN: FTPS server is now running PID $ftpspid\n";
    }

    sleep(1);

    return ($ftpspid, $pid2);
}

#######################################################################
# start the tftp server
#
sub runtftpserver {
    my ($id, $verbose, $ipv6) = @_;
    my $STATUS;
    my $RUNNING;
    my $port = $TFTPPORT;
    # check for pidfile
    my $pidfile = $TFTPPIDFILE;
    my $ip=$HOSTIP;
    my $nameext;
    my $cmd;

    if($ipv6) {
        # if IPv6, use a different setup
        $pidfile = $TFTP6PIDFILE;
        $port = $TFTP6PORT;
        $ip = $HOST6IP;
        $nameext="-ipv6";
    }

    my $pid = checkserver($pidfile);
    if($pid >= 0) {
        stopserver($pid);
    }

    # start our server:
    my $flag=$debugprotocol?"-v ":"";
    $flag .= "-s \"$srcdir\" ";
    if($id) {
        $flag .="--id $id ";
    }
    if($ipv6) {
        $flag .="--ipv6 ";
    }
    $cmd="./server/tftpd --pidfile $pidfile $flag $port";

    unlink($pidfile);

    my ($tftppid, $pid2) = startnew($cmd, $pidfile,0);

    if(!$tftppid || !kill(0, $tftppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the FTP$id$nameext server\n";
        return -1;
    }

    # Server is up. Verify that we can speak to it.
    if(!verifyserver("tftp", $ip, $port)) {
        logmsg "RUN: TFTP$id$nameext server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$tftppid $pid2");
        return (0,0);
    }

    if($verbose) {
        logmsg "RUN: TFTP$id$nameext server is now running PID $tftppid\n";
    }

    sleep(1);

    return ($pid2, $tftppid);
}


#######################################################################
# Start the scp/sftp server
#
sub runsshserver {
    my ($id, $verbose, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $port = $SSHPORT;
    my $pidfile = $SSHPIDFILE;

    my $pid = checkserver($pidfile);
    if($pid > 0) {
        stopserver($pid);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="$perl $srcdir/sshserver.pl $flag-u $USER -d $srcdir $port";
    my ($sshpid, $pid2) =
        startnew($cmd, $pidfile,0); # start the server in a new process

    if(!$sshpid || !kill(0, $sshpid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the SSH server\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$sshpid $pid2");
        return -1;
    }

    if (!verifyserver('ssh',$ip,$port)) {
        logmsg "RUN: SSH server failed verification\n";
        return (0,0);
    }
    if($verbose) {
        logmsg "RUN: SSH server is now running PID $sshpid\n";
    }

    return ($pid2, $sshpid);
}

#######################################################################
# Start the socks server
#
sub runsocksserver {
    my ($id, $verbose, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $port = $SOCKSPORT;
    my $pidfile = $SOCKSPIDFILE;

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="ssh -D ${HOSTIP}:$SOCKSPORT -N -F curl_ssh_config ${USER}\@${HOSTIP} -p ${SSHPORT} >log/ssh.log 2>&1";
    my ($sshpid, $pid2) =
        startnew($cmd, $pidfile,1); # start the server in a new process

    if($sshpid <= 0 || !kill(0, $sshpid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the SOCKS server\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver("$sshpid $pid2");
        return (0,0);
    }

    # Ugly hack but ssh doesn't support pid files
    if (!verifyserver('socks',$ip,$port)) {
        logmsg "RUN: SOCKS server failed verification\n";
        return (0,0);
    }
    if($verbose) {
        logmsg "RUN: SOCKS server is now running PID $sshpid\n";
    }

    return ($pid2, $sshpid);
}

#######################################################################
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $count;
    my $file;

    # Get all files
    opendir(DIR, $dir) ||
        return 0; # can't open dir
    while($file = readdir(DIR)) {
        if($file !~ /^\./) {
            unlink("$dir/$file");
            $count++;
        }
    }
    closedir DIR;
    return $count;
}

#######################################################################
# filter out the specified pattern from the given input file and store the
# results in the given output file
#
sub filteroff {
    my $infile=$_[0];
    my $filter=$_[1];
    my $ofile=$_[2];

    open(IN, "<", $infile)
        || return 1;

    open(OUT, ">", $ofile)
        || return 1;

    # logmsg "FILTER: off $filter from $infile to $ofile\n";

    while(<IN>) {
        $_ =~ s/$filter//;
        print OUT $_;
    }
    close(IN);
    close(OUT);
    return 0;
}

#######################################################################
# compare test results with the expected output, we might filter off
# some pattern that is allowed to differ, output test results
#

sub compare {
    # filter off patterns _before_ this comparison!
    my ($subject, $firstref, $secondref)=@_;

    my $result = compareparts($firstref, $secondref);

    if($result) {
        if(!$short) {
            logmsg "\n $subject FAILED:\n";
            logmsg showdiff($LOGDIR, $firstref, $secondref);
        }
        else {
            logmsg "FAILED\n";
        }
    }
    return $result;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub checksystem {

    unlink($memdump); # remove this if there was one left

    my $feat;
    my $curl;
    my $libcurl;
    my $versretval;
    my $versnoexec;
    my @version=();

    my $curlverout="$LOGDIR/curlverout.log";
    my $curlvererr="$LOGDIR/curlvererr.log";
    my $versioncmd="$CURL --version 1>$curlverout 2>$curlvererr";

    unlink($curlverout);
    unlink($curlvererr);

    $versretval = system($versioncmd);
    $versnoexec = $!;

    open(VERSOUT, "<", $curlverout);
    @version = <VERSOUT>;
    close(VERSOUT);

    for(@version) {
        chomp;

        if($_ =~ /^curl/) {
            $curl = $_;
            $curl =~ s/^(.*)(libcurl.*)/$1/g;

            $libcurl = $2;
            if($curl =~ /mingw32/) {
                # This is a windows minw32 build, we need to translate the
                # given path to the "actual" windows path.

                my @m = `mount`;
                my $matchlen;
                my $bestmatch;
                my $mount;

# example mount output:
# C:\DOCUME~1\Temp on /tmp type user (binmode,noumount)
# c:\ActiveState\perl on /perl type user (binmode)
# C:\msys\1.0\bin on /usr/bin type user (binmode,cygexec,noumount)
# C:\msys\1.0\bin on /bin type user (binmode,cygexec,noumount)

                foreach $mount (@m) {
                    if( $mount =~ /(.*) on ([^ ]*) type /) {
                        my ($mingw, $real)=($2, $1);
                        if($pwd =~ /^$mingw/) {
                            # the path we got from pwd starts with the path
                            # we found on this line in the mount output

                            my $len = length($real);
                            if($len > $matchlen) {
                                # we remember the match that is the longest
                                $matchlen = $len;
                                $bestmatch = $real;
                            }
                        }
                    }
                }
                if(!$matchlen) {
                    logmsg "Serious error, can't find our \"real\" path\n";
                }
                else {
                    # now prepend the prefix from the mount command to build
                    # our "actual path"
                    $pwd = "$bestmatch$pwd";
                }
                $pwd =~ s#\\#/#g;
            }
            elsif ($curl =~ /win32/) {
               # Native Windows builds don't understand the
               # output of cygwin's pwd.  It will be
               # something like /cygdrive/c/<some path>.
               #
               # Use the cygpath utility to convert the
               # working directory to a Windows friendly
               # path.  The -m option converts to use drive
               # letter:, but it uses / instead \.  Forward
               # slashes (/) are easier for us.  We don't
               # have to escape them to get them to curl
               # through a shell.
               chomp($pwd = `cygpath -m $pwd`);
           }
           elsif ($libcurl =~ /openssl/i) {
               $has_openssl=1;
               $ssllib="OpenSSL";
           }
           elsif ($libcurl =~ /gnutls/i) {
               $has_gnutls=1;
               $ssllib="GnuTLS";
           }
           elsif ($libcurl =~ /nss/i) {
               $has_nss=1;
               $ssllib="NSS";
           }
           elsif ($libcurl =~ /yassl/i) {
               $has_yassl=1;
               $has_openssl=1;
               $ssllib="yassl";
           }
        }
        elsif($_ =~ /^Protocols: (.*)/i) {
            # these are the protocols compiled in to this libcurl
            @protocols = split(' ', $1);

            # Generate a "proto-ipv6" version of each protocol to match the
            # IPv6 <server> name. This works even if IPv6 support isn't
            # compiled in because the <features> test will fail.
            push @protocols, map($_ . "-ipv6", @protocols);

            # 'none' is used in test cases to mean no server
            push @protocols, ('none');
        }
        elsif($_ =~ /^Features: (.*)/i) {
            $feat = $1;
            if($feat =~ /debug/i) {
                # debug is a listed "feature", use that knowledge
                $curl_debug = 1;
                # set the NETRC debug env
                $ENV{'CURL_DEBUG_NETRC'} = 'log/netrc';
            }
            if($feat =~ /SSL/i) {
                # ssl enabled
                $ssl_version=1;
            }
            if($feat =~ /Largefile/i) {
                # large file support
                $large_file=1;
            }
            if($feat =~ /IDN/i) {
                # IDN support
                $has_idn=1;
            }
            if($feat =~ /IPv6/i) {
                $has_ipv6 = 1;
            }
            if($feat =~ /libz/i) {
                $has_libz = 1;
            }
            if($feat =~ /NTLM/i) {
                # NTLM enabled
                $has_ntlm=1;
            }
        }
    }
    if(!$curl) {
        logmsg "unable to get curl's version, further details are:\n";
        logmsg "issued command: \n";
        logmsg "$versioncmd \n";
        if ($versretval == -1) {
            logmsg "command failed with: \n";
            logmsg "$versnoexec \n";
        }
        elsif ($versretval & 127) {
            logmsg sprintf("command died with signal %d, and %s coredump.\n",
                           ($versretval & 127), ($versretval & 128)?"a":"no");
        }
        else {
            logmsg sprintf("command exited with value %d \n", $versretval >> 8);
        }
        logmsg "contents of $curlverout: \n";
        displaylogcontent("$curlverout");
        logmsg "contents of $curlvererr: \n";
        displaylogcontent("$curlvererr");
        die "couldn't get curl's version";
    }

    if(-r "../lib/config.h") {
        open(CONF, "<", "../lib/config.h");
        while(<CONF>) {
            if($_ =~ /^\#define HAVE_GETRLIMIT/) {
                $has_getrlimit = 1;
            }
        }
        close(CONF);
    }

    if($has_ipv6) {
        # client has ipv6 support

        # check if the HTTP server has it!
        my @sws = `server/sws --version`;
        if($sws[0] =~ /IPv6/) {
            # HTTP server has ipv6 support!
            $http_ipv6 = 1;
        }

        # check if the FTP server has it!
        @sws = `server/sockfilt --version`;
        if($sws[0] =~ /IPv6/) {
            # FTP server has ipv6 support!
            $ftp_ipv6 = 1;
        }
    }

    if(!$curl_debug && $torture) {
        die "can't run torture tests since curl was not build with debug";
    }

    # curl doesn't list cryptographic support separately, so assume it's
    # always available
    $has_crypto=1;

    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    logmsg ("********* System characteristics ******** \n",
    "* $curl\n",
    "* $libcurl\n",
    "* Features: $feat\n",
    "* Host: $hostname",
    "* System: $hosttype");

    logmsg sprintf("* Server SSL:     %s\n", $stunnel?"ON":"OFF");
    logmsg sprintf("* libcurl SSL:    %s\n", $ssl_version?"ON":"OFF");
    logmsg sprintf("* libcurl debug:  %s\n", $curl_debug?"ON":"OFF");
    logmsg sprintf("* valgrind:       %s\n", $valgrind?"ON":"OFF");
    logmsg sprintf("* HTTP IPv6       %s\n", $http_ipv6?"ON":"OFF");
    logmsg sprintf("* FTP IPv6        %s\n", $ftp_ipv6?"ON":"OFF");

    logmsg sprintf("* HTTP port:      %d\n", $HTTPPORT);
    logmsg sprintf("* FTP port:       %d\n", $FTPPORT);
    logmsg sprintf("* FTP port 2:     %d\n", $FTP2PORT);
    if($stunnel) {
        logmsg sprintf("* FTPS port:      %d\n", $FTPSPORT);
        logmsg sprintf("* HTTPS port:     %d\n", $HTTPSPORT);
    }
    if($http_ipv6) {
        logmsg sprintf("* HTTP IPv6 port: %d\n", $HTTP6PORT);
    }
    if($ftp_ipv6) {
        logmsg sprintf("* FTP IPv6 port:  %d\n", $FTP6PORT);
    }
    logmsg sprintf("* TFTP port:      %d\n", $TFTPPORT);
    if($tftp_ipv6) {
        logmsg sprintf("* TFTP IPv6 port: %d\n", $TFTP6PORT);
    }
    logmsg sprintf("* SCP/SFTP port:  %d\n", $SSHPORT);
    logmsg sprintf("* SOCKS port:     %d\n", $SOCKSPORT);

    if($ssl_version) {
        logmsg sprintf("* SSL library:    %s\n", $ssllib);
    }

    $has_textaware = ($^O eq 'MSWin32') || ($^O eq 'msys');

    logmsg sprintf("* Libtool lib:    %s\n", $libtool?"ON":"OFF");
    logmsg "***************************************** \n";
}

#######################################################################
# substitute the variable stuff into either a joined up file or
# a command, in either case passed by reference
#
sub subVariables {
  my ($thing) = @_;
  $$thing =~ s/%HOSTIP/$HOSTIP/g;
  $$thing =~ s/%HTTPPORT/$HTTPPORT/g;
  $$thing =~ s/%HOST6IP/$HOST6IP/g;
  $$thing =~ s/%HTTP6PORT/$HTTP6PORT/g;
  $$thing =~ s/%HTTPSPORT/$HTTPSPORT/g;
  $$thing =~ s/%FTPPORT/$FTPPORT/g;
  $$thing =~ s/%FTP6PORT/$FTP6PORT/g;
  $$thing =~ s/%FTP2PORT/$FTP2PORT/g;
  $$thing =~ s/%FTPSPORT/$FTPSPORT/g;
  $$thing =~ s/%SRCDIR/$srcdir/g;
  $$thing =~ s/%PWD/$pwd/g;
  $$thing =~ s/%TFTPPORT/$TFTPPORT/g;
  $$thing =~ s/%TFTP6PORT/$TFTP6PORT/g;
  $$thing =~ s/%SSHPORT/$SSHPORT/g;
  $$thing =~ s/%SOCKSPORT/$SOCKSPORT/g;
  $$thing =~ s/%CURL/$CURL/g;
  $$thing =~ s/%USER/$USER/g;

  # The purpose of FTPTIME2 and FTPTIME3 is to provide times that can be
  # used for time-out tests and that whould work on most hosts as these
  # adjust for the startup/check time for this particular host. We needed
  # to do this to make the test suite run better on very slow hosts.

  my $ftp2 = $ftpchecktime * 2;
  my $ftp3 = $ftpchecktime * 3;

  $$thing =~ s/%FTPTIME2/$ftp2/g;
  $$thing =~ s/%FTPTIME3/$ftp3/g;
}

sub fixarray {
    my @in = @_;

    for(@in) {
        subVariables \$_;
    }
    return @in;
}

#######################################################################
# Run a single specified test case
#

sub singletest {
    my ($testnum, $count, $total)=@_;

    my @what;
    my $why;
    my %feature;
    my $cmd;

    # load the test case file definition
    if(loadtest("${TESTDIR}/test${testnum}")) {
        if($verbose) {
            # this is not a test
            logmsg "RUN: $testnum doesn't look like a test case\n";
        }
        $why = "no test";
    }
    else {
        @what = getpart("client", "features");
    }

    for(@what) {
        my $f = $_;
        $f =~ s/\s//g;

        $feature{$f}=$f; # we require this feature

        if($f eq "SSL") {
            if($ssl_version) {
                next;
            }
        }
        elsif($f eq "OpenSSL") {
            if($has_openssl) {
                next;
            }
        }
        elsif($f eq "GnuTLS") {
            if($has_gnutls) {
                next;
            }
        }
        elsif($f eq "NSS") {
            if($has_nss) {
                next;
            }
        }
        elsif($f eq "netrc_debug") {
            if($curl_debug) {
                next;
            }
        }
        elsif($f eq "large_file") {
            if($large_file) {
                next;
            }
        }
        elsif($f eq "idn") {
            if($has_idn) {
                next;
            }
        }
        elsif($f eq "ipv6") {
            if($has_ipv6) {
                next;
            }
        }
        elsif($f eq "libz") {
            if($has_libz) {
                next;
            }
        }
        elsif($f eq "NTLM") {
            if($has_ntlm) {
                next;
            }
        }
        elsif($f eq "getrlimit") {
            if($has_getrlimit) {
                next;
            }
        }
        elsif($f eq "crypto") {
            if($has_crypto) {
                next;
            }
        }
        elsif($f eq "socks") {
            next;
        }
        # See if this "feature" is in the list of supported protocols
        elsif (grep /^$f$/, @protocols) {
            next;
        }

        $why = "curl lacks $f support";
        last;
    }

    if(!$why) {
        $why = serverfortest($testnum);
    }

    if(!$why) {
        my @precheck = getpart("client", "precheck");
        $cmd = $precheck[0];
        chomp $cmd;
        subVariables \$cmd;
        if($cmd) {
            my @o = `$cmd 2>/dev/null`;
            if($o[0]) {
                $why = $o[0];
                chomp $why;
            }
            logmsg "prechecked $cmd\n" if($verbose);
        }
    }

    if($why) {
        # there's a problem, count it as "skipped"
        $skipped++;
        $skipped{$why}++;
        $teststat[$testnum]=$why; # store reason for this test case

        if(!$short) {
            printf "test %03d SKIPPED: $why\n", $testnum;
        }

        return -1;
    }
    logmsg sprintf("test %03d...", $testnum);

    # extract the reply data
    my @reply = getpart("reply", "data");
    my @replycheck = getpart("reply", "datacheck");

    if (@replycheck) {
        # we use this file instead to check the final output against

        my %hash = getpartattr("reply", "datacheck");
        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the datacheck
            chomp($replycheck[$#replycheck]);
        }

        @reply=@replycheck;
    }

    # curl command to run
    my @curlcmd= fixarray ( getpart("client", "command") );

    # this is the valid protocol blurb curl should generate
    my @protocol= fixarray ( getpart("verify", "protocol") );

    # redirected stdout/stderr to these files
    $STDOUT="$LOGDIR/stdout$testnum";
    $STDERR="$LOGDIR/stderr$testnum";

    # if this section exists, we verify that the stdout contained this:
    my @validstdout = fixarray ( getpart("verify", "stdout") );

    # if this section exists, we verify upload
    my @upload = getpart("verify", "upload");

    # if this section exists, it might be FTP server instructions:
    my @ftpservercmd = getpart("reply", "servercmd");

    my $CURLOUT="$LOGDIR/curl$testnum.out"; # curl output if not stdout

    # name of the test
    my @testname= getpart("client", "name");

    if(!$short) {
        my $name = $testname[0];
        $name =~ s/\n//g;
        logmsg "[$name]\n";
    }

    if($listonly) {
        return 0; # look successful
    }

    my @codepieces = getpart("client", "tool");

    my $tool="";
    if(@codepieces) {
        $tool = $codepieces[0];
        chomp $tool;
    }

    # remove server output logfiles
    unlink($SERVERIN);
    unlink($SERVER2IN);

    if(@ftpservercmd) {
        # write the instructions to file
        writearray($FTPDCMD, \@ftpservercmd);
    }

    my (@setenv)= getpart("client", "setenv");
    my @envs;

    my $s;
    for $s (@setenv) {
        chomp $s; # cut off the newline

        subVariables \$s;

        if($s =~ /([^=]*)=(.*)/) {
            my ($var, $content)=($1, $2);
            $ENV{$var}=$content;
            # remember which, so that we can clear them afterwards!
            push @envs, $var;
        }
    }

    # get the command line options to use
    my @blaha;
    ($cmd, @blaha)= getpart("client", "command");

    # make some nice replace operations
    $cmd =~ s/\n//g; # no newlines please

    # substitute variables in the command line
    subVariables \$cmd;

    if($curl_debug) {
        unlink($memdump);
    }

    my @inputfile=getpart("client", "file");
    if(@inputfile) {
        # we need to generate a file before this test is invoked
        my %fileattr = getpartattr("client", "file");

        my $filename=$fileattr{'name'};

        if(!$filename) {
            logmsg "ERROR: section client=>file has no name attribute\n";
            return -1;
        }
        my $fileContent = join('', @inputfile);
        subVariables \$fileContent;
#        logmsg "DEBUG: writing file " . $filename . "\n";
        open(OUTFILE, ">", $filename);
        binmode OUTFILE; # for crapage systems, use binary
        print OUTFILE $fileContent;
        close(OUTFILE);
    }

    my %cmdhash = getpartattr("client", "command");

    my $out="";

    if($cmdhash{'option'} !~ /no-output/) {
        #We may slap on --output!
        if (!@validstdout) {
            $out=" --output $CURLOUT ";
        }
    }

    my $cmdargs;
    if(!$tool) {
        # run curl, add -v for debug information output
        $cmdargs ="$out --include -v --trace-time $cmd";
    }
    else {
        $cmdargs = " $cmd"; # $cmd is the command line for the test file
        $CURLOUT = $STDOUT; # sends received data to stdout
    }

    my @stdintest = getpart("client", "stdin");

    if(@stdintest) {
        my $stdinfile="$LOGDIR/stdin-for-$testnum";
        writearray($stdinfile, \@stdintest);

        $cmdargs .= " <$stdinfile";
    }
    my $CMDLINE;

    if(!$tool) {
        $CMDLINE="$CURL";
    }
    else {
        $CMDLINE="$LIBDIR/$tool";
        if(! -f $CMDLINE) {
            print "The tool set in the test case for this: '$tool' does not exist\n";
            return -1;
        }
        $DBGCURL=$CMDLINE;
    }

    if($valgrind) {
        $CMDLINE = "valgrind ".$valgrind_tool."--leak-check=yes --num-callers=16 ${valgrind_logfile}=log/valgrind$testnum $CMDLINE";
    }

    $CMDLINE .= "$cmdargs >>$STDOUT 2>>$STDERR";

    if($verbose) {
        logmsg "$CMDLINE\n";
    }

    print CMDLOG "$CMDLINE\n";

    unlink("core");

    my $dumped_core;
    my $cmdres;

    # Apr 2007: precommand isn't being used and could be removed
    my @precommand= getpart("client", "precommand");
    if($precommand[0]) {
        # this is pure perl to eval!
        my $code = join("", @precommand);
        eval $code;
        if($@) {
            logmsg "perl: $code\n";
            logmsg "precommand: $@";
            stopservers($verbose);
            return -1;
        }
    }

    if($gdbthis) {
        open(GDBCMD, ">", "log/gdbcmd");
        print GDBCMD "set args $cmdargs\n";
        print GDBCMD "show args\n";
        close(GDBCMD);
    }
    # run the command line we built
    if ($torture) {
        $cmdres = torture($CMDLINE,
                       "$gdb --directory libtest $DBGCURL -x log/gdbcmd");
    }
    elsif($gdbthis) {
        system("$gdb --directory libtest $DBGCURL -x log/gdbcmd");
        $cmdres=0; # makes it always continue after a debugged run
    }
    else {
        $cmdres = system("$CMDLINE");
        my $signal_num  = $cmdres & 127;
        $dumped_core = $cmdres & 128;

        if(!$anyway && ($signal_num || $dumped_core)) {
            $cmdres = 1000;
        }
        else {
            $cmdres /= 256;
        }
    }
    if(!$dumped_core) {
        if(-r "core") {
            # there's core file present now!
            $dumped_core = 1;
        }
    }

    if($dumped_core) {
        logmsg "core dumped\n";
        if(0 && $gdb) {
            logmsg "running gdb for post-mortem analysis:\n";
            open(GDBCMD, ">", "log/gdbcmd2");
            print GDBCMD "bt\n";
            close(GDBCMD);
            system("$gdb --directory libtest -x log/gdbcmd2 -batch $DBGCURL core ");
     #       unlink("log/gdbcmd2");
        }
    }

    # run the postcheck command
    my @postcheck= getpart("client", "postcheck");
    $cmd = $postcheck[0];
    chomp $cmd;
    subVariables \$cmd;
    if($cmd) {
	my $rc = system("$cmd");
	if($rc != 0) {
	    logmsg "postcheck failure\n";
	    return 1;
	}
	logmsg "postchecked $cmd\n" if($verbose);
    }

    # remove the special FTP command file after each test!
    unlink($FTPDCMD);

    my $e;
    for $e (@envs) {
        $ENV{$e}=""; # clean up
    }

    # Skip all the verification on torture tests
    if ($torture) {
	if(!$cmdres && !$keepoutfiles) {
	    cleardir($LOGDIR);
	}
        return $cmdres;
    }

    my @err = getpart("verify", "errorcode");
    my $errorcode = $err[0] || "0";
    my $ok="";
    my $res;
    if (@validstdout) {
        # verify redirected stdout
        my @actual = loadarray($STDOUT);

        # get all attributes
        my %hash = getpartattr("verify", "stdout");

        # get the mode attribute
        my $filemode=$hash{'mode'};
        if(($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            map s/\r\n/\n/g, @actual;
        }

        $res = compare("stdout", \@actual, \@validstdout);
        if($res) {
            return 1;
        }
        $ok .= "s";
    }
    else {
        $ok .= "-"; # stdout not checked
    }

    my %replyattr = getpartattr("reply", "data");
    if(!$replyattr{'nocheck'} && (@reply || $replyattr{'sendzero'})) {
        # verify the received data
        my @out = loadarray($CURLOUT);
        my %hash = getpartattr("reply", "data");
        # get the mode attribute
        my $filemode=$hash{'mode'};
        if(($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            map s/\r\n/\n/g, @out;
        }

        $res = compare("data", \@out, \@reply);
        if ($res) {
            return 1;
        }
        $ok .= "d";
    }
    else {
        $ok .= "-"; # data not checked
    }

    if(@upload) {
        # verify uploaded data
        my @out = loadarray("$LOGDIR/upload.$testnum");
        $res = compare("upload", \@out, \@upload);
        if ($res) {
            return 1;
        }
        $ok .= "u";
    }
    else {
        $ok .= "-"; # upload not checked
    }

    if(@protocol) {
        my @out;
        my $retry = 5;

        # Verify the sent request. Sometimes, like in test 513 on some hosts,
        # curl will return back faster than the server writes down the request
        # to its file, so we might need to wait here for a while to see if the
        # file gets written a bit later.

        while($retry--) {
            @out = loadarray($SERVERIN);

            if(!$out[0]) {
                # nothing there yet, wait a while and try again
                sleep(1);
            }
        }

        # what to cut off from the live protocol sent by curl
        my @strip = getpart("verify", "strip");

        my @protstrip=@protocol;

        # check if there's any attributes on the verify/protocol section
        my %hash = getpartattr("verify", "protocol");

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($protstrip[$#protstrip]);
        }

        for(@strip) {
            # strip off all lines that match the patterns from both arrays
            chomp $_;
            @out = striparray( $_, \@out);
            @protstrip= striparray( $_, \@protstrip);
        }

        # what parts to cut off from the protocol
        my @strippart = getpart("verify", "strippart");
        my $strip;
        for $strip (@strippart) {
            chomp $strip;
            for(@out) {
                eval $strip;
            }
        }

        $res = compare("protocol", \@out, \@protstrip);
        if($res) {
            return 1;
        }

        $ok .= "p";

    }
    else {
        $ok .= "-"; # protocol not checked
    }

    my @outfile=getpart("verify", "file");
    if(@outfile) {
        # we're supposed to verify a dynamicly generated file!
        my %hash = getpartattr("verify", "file");

        my $filename=$hash{'name'};
        if(!$filename) {
            logmsg "ERROR: section verify=>file has no name attribute\n";
            stopservers($verbose);
            return -1;
        }
        my @generated=loadarray($filename);

        # what parts to cut off from the file
        my @stripfile = getpart("verify", "stripfile");

        my $filemode=$hash{'mode'};
        if(($filemode eq "text") && $has_textaware) {
            # text mode when running on windows means adding an extra
            # strip expression
            push @stripfile, "s/\r\n/\n/";
        }

        my $strip;
        for $strip (@stripfile) {
            chomp $strip;
            for(@generated) {
                eval $strip;
            }
        }

        $res = compare("output", \@generated, \@outfile);
        if($res) {
            return 1;
        }

        $ok .= "o";
    }
    else {
        $ok .= "-"; # output not checked
    }

    # accept multiple comma-separated error codes
    my @splerr = split(/ *, */, $errorcode);
    my $errok;
    foreach $e (@splerr) {
        if($e == $cmdres) {
            # a fine error code
            $errok = 1;
            last;
        }
    }

    if($errok) {
        $ok .= "e";
    }
    else {
        if(!$short) {
            printf "\ncurl returned $cmdres, %s was expected\n", $errorcode;
        }
        logmsg " exit FAILED\n";
        return 1;
    }

    @what = getpart("client", "killserver");
    for(@what) {
        my $serv = $_;
        chomp $serv;
        if($serv =~ /^ftp(\d*)(-ipv6|)/) {
            my ($id, $ext) = ($1, $2);
            #print STDERR "SERV $serv $id $ext\n";
            ftpkillslave($id, $ext, $verbose);
        }
        if($run{$serv}) {
            stopserver($run{$serv}); # the pid file is in the hash table
            $run{$serv}=0; # clear pid
        }
        else {
            logmsg "RUN: The $serv server is not running\n";
        }
    }

    if($curl_debug) {
        if(! -f $memdump) {
            logmsg "\n** ALERT! memory debugging with no output file?\n";
        }
        else {
            my @memdata=`$memanalyze $memdump`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                logmsg "\n** MEMORY FAILURE\n";
                logmsg @memdata;
                return 1;
            }
            else {
                $ok .= "m";
            }
        }
    }
    else {
        $ok .= "-"; # memory not checked
    }

    if($valgrind) {
        # this is the valid protocol blurb curl should generate
        my @disable= getpart("verify", "valgrind");

        if($disable[0] !~ /disable/) {

            opendir(DIR, "log") ||
                return 0; # can't open log dir
            my @files = readdir(DIR);
            closedir(DIR);
            my $f;
            my $l;
            foreach $f (@files) {
                if($f =~ /^valgrind$testnum\.pid/) {
                    $l = $f;
                    last;
                }
            }
            my $src=$ENV{'srcdir'};
            if(!$src) {
                $src=".";
            }
            my @e = valgrindparse($src, $feature{'SSL'}, "log/$l");
            if($e[0]) {
                logmsg " valgrind ERROR ";
                logmsg @e;
                return 1;
            }
            $ok .= "v";
        }
        else {
            if(!$short) {
                logmsg " valgrind SKIPPED";
            }
            $ok .= "-"; # skipped
        }
    }
    else {
        $ok .= "-"; # valgrind not checked
    }

    logmsg "$ok " if(!$short);

    my $sofar= time()-$start;
    my $esttotal = $sofar/$count * $total;
    my $estleft = $esttotal - $sofar;
    my $left=sprintf("remaining: %02d:%02d",
                     $estleft/60,
                     $estleft%60);
    printf "OK (%-3d out of %-3d, %s)\n", $count, $total, $left;

    # the test succeeded, remove all log files
    if(!$keepoutfiles) {
        cleardir($LOGDIR);
    }

    unlink($FTPDCMD); # remove the instructions for this test

    return 0;
}

#######################################################################
# Stop all running test servers
sub stopservers {
    my ($verbose)=@_;
    for(keys %run) {
        my $server = $_;
        my $pids=$run{$server};
        my $pid;
        my $prev;

        foreach $pid (split(" ", $pids)) {
            if($pid != $prev) {
                # no need to kill same pid twice!
                logmsg sprintf("* kill pid for %s => %d\n",
                               $server, $pid) if($verbose);
                stopserver($pid);
            }
            $prev = $pid;
        }
    }
    ftpkillslaves($verbose);
}

#######################################################################
# startservers() starts all the named servers
#
# Returns: string with error reason or blank for success

sub startservers {
    my @what = @_;
    my ($pid, $pid2);
    for(@what) {
        my $what = lc($_);
        $what =~ s/[^a-z0-9-]//g;
        if($what eq "ftp") {
            if(!$run{'ftp'}) {
                ($pid, $pid2) = runftpserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting FTP server";
                }
                printf ("* pid ftp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ftp'}="$pid $pid2";
            }
        }
        elsif($what eq "ftp2") {
            if(!$run{'ftp2'}) {
                ($pid, $pid2) = runftpserver("2", $verbose);
                if($pid <= 0) {
                    return "failed starting FTP2 server";
                }
                printf ("* pid ftp2 => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ftp2'}="$pid $pid2";
            }
        }
        elsif($what eq "ftp-ipv6") {
            if(!$run{'ftp-ipv6'}) {
                ($pid, $pid2) = runftpserver("", $verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting FTP-IPv6 server";
                }
                logmsg sprintf("* pid ftp-ipv6 => %d %d\n", $pid,
                       $pid2) if($verbose);
                $run{'ftp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "http") {
            if(!$run{'http'}) {
                ($pid, $pid2) = runhttpserver($verbose);
                if($pid <= 0) {
                    return "failed starting HTTP server";
                }
                printf ("* pid http => %d %d\n", $pid, $pid2) if($verbose);
                $run{'http'}="$pid $pid2";
            }
        }
        elsif($what eq "http-ipv6") {
            if(!$run{'http-ipv6'}) {
                ($pid, $pid2) = runhttpserver($verbose, "IPv6");
                if($pid <= 0) {
                    return "failed starting HTTP-IPv6 server";
                }
                logmsg sprintf("* pid http-ipv6 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "ftps") {
            if(!$stunnel) {
                # we can't run ftps tests without stunnel
                return "no stunnel";
            }
            if(!$ssl_version) {
                # we can't run ftps tests if libcurl is SSL-less
                return "curl lacks SSL support";
            }

            if(!$run{'ftp'}) {
                ($pid, $pid2) = runftpserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting FTP server";
                }
                printf ("* pid ftp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ftp'}="$pid $pid2";
            }
            if(!$run{'ftps'}) {
                ($pid, $pid2) = runftpsserver($verbose);
                if($pid <= 0) {
                    return "failed starting FTPS server (stunnel)";
                }
                logmsg sprintf("* pid ftps => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'ftps'}="$pid $pid2";
            }
        }
        elsif($what eq "file") {
            # we support it but have no server!
        }
        elsif($what eq "https") {
            if(!$stunnel) {
                # we can't run ftps tests without stunnel
                return "no stunnel";
            }
            if(!$ssl_version) {
                # we can't run ftps tests if libcurl is SSL-less
                return "curl lacks SSL support";
            }

            if(!$run{'http'}) {
                ($pid, $pid2) = runhttpserver($verbose);
                if($pid <= 0) {
                    return "failed starting HTTP server";
                }
                printf ("* pid http => %d %d\n", $pid, $pid2) if($verbose);
                $run{'http'}="$pid $pid2";
            }
            if(!$run{'https'}) {
                ($pid, $pid2) = runhttpsserver($verbose);
                if($pid <= 0) {
                    return "failed starting HTTPS server (stunnel)";
                }
                logmsg sprintf("* pid https => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'https'}="$pid $pid2";
            }
        }
        elsif($what eq "tftp") {
            if(!$run{'tftp'}) {
                ($pid, $pid2) = runtftpserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting TFTP server";
                }
                printf ("* pid tftp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp'}="$pid $pid2";
            }
        }
        elsif($what eq "tftp-ipv6") {
            if(!$run{'tftp-ipv6'}) {
                ($pid, $pid2) = runtftpserver("", $verbose, "IPv6");
                if($pid <= 0) {
                    return "failed starting TFTP-IPv6 server";
                }
                printf("* pid tftp-ipv6 => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "sftp" || $what eq "scp" || $what eq "socks4" || $what eq "socks5" ) {
            if(!$run{'ssh'}) {
                ($pid, $pid2) = runsshserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting SSH server";
                }
                printf ("* pid ssh => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ssh'}="$pid $pid2";
            }
	    if ($what eq "socks4" || $what eq "socks5") {
                if (!checkcmd("ssh")) {
                   return "failed to find SSH client for socks support";
		}
                if ($what eq "socks5") {
		   my $sshversion=`ssh -V 2>&1`;
                   if ($sshversion =~ /SSH_(\d+)\.(\d+)/i) {
                       if ($1*10+$2 < 37) {
		       # need 3.7 for socks5 - http://www.openssh.com/txt/release-3.7
                           return "ssh version ($1.$2) insufficient; need at least 3.7";
		       }
                   } else {
                       return "Unsupported ssh client\n";
                   }
		}
            	if(!$run{'socks'}) {
                    ($pid, $pid2) = runsocksserver("", $verbose);
                    if($pid <= 0) {
                        return "failed starting socks server";
                    }
                    printf ("* pid socks => %d %d\n", $pid, $pid2) if($verbose);
                    $run{'socks'}="$pid $pid2";
		}
	    }
        }
        elsif($what eq "none") {
            logmsg "* starts no server\n" if ($verbose);
        }
        else {
            warn "we don't support a server for $what";
            return "no server for $what";
        }
    }
    return 0;
}

##############################################################################
# This function makes sure the right set of server is running for the
# specified test case. This is a useful design when we run single tests as not
# all servers need to run then!
#
# Returns: a string, blank if everything is fine or a reason why it failed
#

sub serverfortest {
    my ($testnum)=@_;

    # load the test case file definition
    if(loadtest("${TESTDIR}/test${testnum}")) {
        if($verbose) {
            # this is not a test
            logmsg "$testnum doesn't look like a test case\n";
        }
        return "no test";
    }

    my @what = getpart("client", "server");

    if(!$what[0]) {
        warn "Test case $testnum has no server(s) specified";
        return "no server specified";
    }

    my $proto = lc($what[0]);
    chomp $proto;
    if (! grep /^$proto$/, @protocols) {
        if (substr($proto,0,5) ne "socks") {
		return "curl lacks any $proto support";
        }
    }

    return &startservers(@what);
}

#######################################################################
# Check options to this test program
#

my $number=0;
my $fromnum=-1;
my @testthis;
my %disabled;
do {
    if ($ARGV[0] eq "-v") {
        # verbose output
        $verbose=1;
    }
    elsif($ARGV[0] =~ /^-b(.*)/) {
        my $portno=$1;
        if($portno =~ s/(\d+)$//) {
            $base = int $1;
        }
    }
    elsif ($ARGV[0] eq "-c") {
        # use this path to curl instead of default
        $DBGCURL=$CURL=$ARGV[1];
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-d") {
        # have the servers display protocol output
        $debugprotocol=1;
    }
    elsif ($ARGV[0] eq "-f") {
        # run fork-servers, which makes the server fork for all new
        # connections This is NOT what you wanna do without knowing exactly
        # why and for what
        $forkserver=1;
    }
    elsif ($ARGV[0] eq "-g") {
        # run this test with gdb
        $gdbthis=1;
    }
    elsif($ARGV[0] eq "-s") {
        # short output
        $short=1;
    }
    elsif($ARGV[0] eq "-n") {
        # no valgrind
        undef $valgrind;
    }
    elsif($ARGV[0] =~ /^-t(.*)/) {
        # torture
        $torture=1;
        my $xtra = $1;

        if($xtra =~ s/(\d+)$//) {
            $tortalloc = $1;
        }
        # we undef valgrind to make this fly in comparison
        undef $valgrind;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-p") {
        $postmortem=1;
    }
    elsif($ARGV[0] eq "-l") {
        # lists the test case names only
        $listonly=1;
    }
    elsif($ARGV[0] eq "-k") {
        # keep stdout and stderr files after tests
        $keepoutfiles=1;
    }
    elsif($ARGV[0] eq "-h") {
        # show help text
        print <<EOHELP
Usage: runtests.pl [options] [test number(s)]
  -a       continue even if a test fails
  -bN      use base port number N for test servers (default $base)
  -c path  use this curl executable
  -d       display server debug info
  -g       run the test case with gdb
  -h       this help text
  -k       keep stdout and stderr files present after tests
  -l       list all test case names/descriptions
  -n       no valgrind
  -p       print log file contents when a test fails
  -s       short output
  -t[N]    torture (simulate memory alloc failures); N means fail Nth alloc
  -v       verbose output
  [num]    like "5 6 9" or " 5 to 22 " to run those tests only
  [!num]   like "!5 !6 !9" to disable those tests
EOHELP
    ;
        exit;
    }
    elsif($ARGV[0] =~ /^(\d+)/) {
        $number = $1;
        if($fromnum >= 0) {
            for($fromnum .. $number) {
                push @testthis, $_;
            }
            $fromnum = -1;
        }
        else {
            push @testthis, $1;
        }
    }
    elsif($ARGV[0] =~ /^to$/i) {
        $fromnum = $number+1;
    }
    elsif($ARGV[0] =~ /^!(\d+)/) {
        $fromnum = -1;
        $disabled{$1}=$1;
    }
} while(shift @ARGV);

if($testthis[0] ne "") {
    $TESTCASES=join(" ", @testthis);
}

if($valgrind) {
    # we have found valgrind on the host, use it

    # verify that we can invoke it fine
    my $code = system("valgrind >/dev/null 2>&1");

    if(($code>>8) != 1) {
        #logmsg "Valgrind failure, disable it\n";
        undef $valgrind;
    }
}

# open the executable curl and read the first 4 bytes of it
open(CHECK, "<", $CURL);
my $c;
sysread CHECK, $c, 4;
close(CHECK);
if($c eq "#! /") {
    # A shell script. This is typically when built with libtool,
    $libtool = 1;
    $gdb = "libtool --mode=execute gdb";
}

$HTTPPORT =  $base + 0; # HTTP server port
$HTTPSPORT = $base + 1; # HTTPS server port
$FTPPORT =   $base + 2; # FTP server port
$FTPSPORT =  $base + 3; # FTPS server port
$HTTP6PORT = $base + 4; # HTTP IPv6 server port (different IP protocol
                        # but we follow the same port scheme anyway)
$FTP2PORT =  $base + 5; # FTP server 2 port
$FTP6PORT =  $base + 6; # FTP IPv6 port
$TFTPPORT =  $base + 7; # TFTP (UDP) port
$TFTP6PORT =  $base + 8; # TFTP IPv6 (UDP) port
$SSHPORT =   $base + 9; # SSH (SCP/SFTP) port
$SOCKSPORT =   $base + 10; # SOCKS port

#######################################################################
# clear and create logging directory:
#

cleardir($LOGDIR);
mkdir($LOGDIR, 0777);

#######################################################################
# Output curl version and host info being tested
#

if(!$listonly) {
    checksystem();
}

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^test([0-9]+)$/ && -f "$TESTDIR/$_" } readdir(DIR);
    closedir(DIR);

    open(D, "$TESTDIR/DISABLED");
    while(<D>) {
        if(/^ *\#/) {
            # allow comments
            next;
        }
        if($_ =~ /(\d+)/) {
            $disabled{$1}=$1; # disable this test number
        }
    }
    close(D);

    $TESTCASES=""; # start with no test cases

    # cut off everything but the digits
    for(@cmds) {
        $_ =~ s/[a-z\/\.]*//g;
    }
    # the the numbers from low to high
    foreach my $n (sort { $a <=> $b } @cmds) {
        if($disabled{$n}) {
            # skip disabled test cases
            my $why = "configured as DISABLED";
            $skipped++;
            $skipped{$why}++;
            $teststat[$n]=$why; # store reason for this test case
            next;
        }
        $TESTCASES .= " $n";
    }
}

#######################################################################
# Start the command line log
#
open(CMDLOG, ">", $CURLLOG) ||
    logmsg "can't log command lines to $CURLLOG\n";

#######################################################################

# Display the contents of the given file.  Line endings are canonicalized
# and excessively long files are truncated
sub displaylogcontent {
    my ($file)=@_;
    if(open(SINGLE, "<$file")) {
        my $lfcount;
        my $linecount = 0;
        my $truncate;
        my @tail;
        while(my $string = <SINGLE>) {
            $string =~ s/\r\n/\n/g;
            $string =~ s/[\r\f\032]/\n/g;
            $string .= "\n" unless ($string =~ /\n$/);
            $lfcount = $string =~ tr/\n//;
            if($lfcount == 1) {
                $string =~ s/\n//;
                $string =~ s/\s*\!$//;
                $linecount++;
                if ($truncate) {
                    push @tail, " $string\n";
                } else {
                    logmsg " $string\n";
                }
            }
            else {
                for my $line (split("\n", $string)) {
                    $line =~ s/\s*\!$//;
                    $linecount++;
                    if ($truncate) {
                        push @tail, " $line\n";
                    } else {
                        logmsg " $line\n";
		    }
                }
            }
            $truncate = $linecount > 1000;
        }
        if (@tail) {
            logmsg "=== File too long: lines here were removed\n";
            # This won't work properly if time stamps are enabled in logmsg
            logmsg join('',@tail[$#tail-200..$#tail]);
        }
        close(SINGLE);
    }
}

sub displaylogs {
    my ($testnum)=@_;
    opendir(DIR, "$LOGDIR") ||
        die "can't open dir: $!";
    my @logs = readdir(DIR);
    closedir(DIR);

    logmsg "== Contents of files in the log/ dir after test $testnum\n";
    foreach my $log (sort @logs) {
        if($log =~ /\.(\.|)$/) {
            next; # skip "." and ".."
        }
        if($log =~ /^\.nfs/) {
            next; # skip ".nfs"
        }
        if(($log eq "memdump") || ($log eq "core")) {
            next; # skip "memdump" and  "core"
        }
        if((-d "$LOGDIR/$log") || (! -s "$LOGDIR/$log")) {
            next; # skip directory and empty files
        }
        if(($log =~ /^stdout\d+/) && ($log !~ /^stdout$testnum/)) {
            next; # skip stdoutNnn of other tests
        }
        if(($log =~ /^stderr\d+/) && ($log !~ /^stderr$testnum/)) {
            next; # skip stderrNnn of other tests
        }
        if(($log =~ /^upload\d+/) && ($log !~ /^upload$testnum/)) {
            next; # skip uploadNnn of other tests
        }
        if(($log =~ /^curl\d+\.out/) && ($log !~ /^curl$testnum\.out/)) {
            next; # skip curlNnn.out of other tests
        }
        if(($log =~ /^test\d+\.txt/) && ($log !~ /^test$testnum\.txt/)) {
            next; # skip testNnn.txt of other tests
        }
        if(($log =~ /^file\d+\.txt/) && ($log !~ /^file$testnum\.txt/)) {
            next; # skip fileNnn.txt of other tests
        }
        logmsg "=== Start of file $log\n";
        displaylogcontent("$LOGDIR/$log");
        logmsg "=== End of file $log\n";
    }
}

#######################################################################
# The main test-loop
#

my $failed;
my $testnum;
my $ok=0;
my $total=0;
my $lasttest;
my @at = split(" ", $TESTCASES);
my $count=0;

$start = time();

foreach $testnum (@at) {

    $lasttest = $testnum if($testnum > $lasttest);
    $count++;

    my $error = singletest($testnum, $count, scalar(@at));
    if($error < 0) {
        # not a test we can run
        next;
    }

    $total++; # number of tests we've run

    if($error>0) {
        $failed.= "$testnum ";
        if($postmortem) {
            # display all files in log/ in a nice way
            displaylogs($testnum);
        }
        if(!$anyway) {
            # a test failed, abort
            logmsg "\n - abort tests\n";
            last;
        }
    }
    elsif(!$error) {
        $ok++; # successful test counter
    }

    # loop for next test
}

#######################################################################
# Close command log
#
close(CMDLOG);

# Tests done, stop the servers
stopservers($verbose);

my $all = $total + $skipped;

if($total) {
    logmsg sprintf("TESTDONE: $ok tests out of $total reported OK: %d%%\n",
                   $ok/$total*100);

    if($ok != $total) {
        logmsg "TESTFAIL: These test cases failed: $failed\n";
    }
}
else {
    logmsg "TESTFAIL: No tests were performed\n";
}

if($all) {
    my $sofar = time()-$start;
    logmsg "TESTDONE: $all tests were considered during $sofar seconds.\n";
}

if($skipped) {
    my $s=0;
    logmsg "TESTINFO: $skipped tests were skipped due to these restraints:\n";

    for(keys %skipped) {
        my $r = $_;
        printf "TESTINFO: \"%s\" %d times (", $r, $skipped{$_};

        # now show all test case numbers that had this reason for being
        # skipped
        my $c=0;
        for(0 .. scalar @teststat) {
            my $t = $_;
            if($teststat[$_] eq $r) {
                logmsg ", " if($c);
                logmsg $_;
                $c++;
            }
        }
        logmsg ")\n";
    }
}
if($total && ($ok != $total)) {
    exit 1;
}
