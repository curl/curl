#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

# This module contains functions that are useful for managing the lifecycle of
# test servers required when running tests. It is not intended for use within
# those servers, but rather for starting and stopping them.

package servers;

use IO::Socket;
use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = (
        # variables
        qw(
            $SOCKSIN
            $err_unexpected
            $debugprotocol
            $stunnel
        ),

        # functions
        qw(
            initserverconfig
        )
    );

    our @EXPORT_OK = (
        # functions
        qw(
            checkcmd
            clearlocks
            serverfortest
            stopserver
            stopservers
            subvariables
        ),

        # for debugging only
        qw(
            protoport
        )
    );
}

use serverhelp qw(
    serverfactors
    servername_id
    servername_str
    servername_canon
    server_pidfilename
    server_portfilename
    server_logfilename
    );

use sshhelp qw(
    $hstpubmd5f
    $hstpubsha256f
    $sshexe
    $sftpexe
    $sftpconfig
    $sshdlog
    $sftplog
    $sftpcmds
    display_sshdconfig
    display_sftpconfig
    display_sshdlog
    display_sftplog
    find_sshd
    find_ssh
    find_sftp
    find_httptlssrv
    sshversioninfo
    );

use pathhelp qw(
    exe_ext
    os_is_win
    sys_native_abs_path
    );

use processhelp;
use globalconfig;
use testutil qw(
    logmsg
    runclient
    runclientoutput
    );


my %serverpidfile; # all server pid file names, identified by server id
my %serverportfile;# all server port file names, identified by server id
my $sshdvernum;  # for socks server, ssh daemon version number
my $sshdverstr;  # for socks server, ssh daemon version string
my $sshderror;   # for socks server, ssh daemon version error
my %doesntrun;    # servers that don't work, identified by pidfile
my %PORT = (nolisten => 47); # port we use for a local non-listening service
my $server_response_maxtime=13;
my $httptlssrv = find_httptlssrv();
my %run;          # running server
my %runcert;      # cert file currently in use by an ssl running server
my $CLIENTIP="127.0.0.1";  # address which curl uses for incoming connections
my $CLIENT6IP="[::1]";     # address which curl uses for incoming connections
my $posix_pwd=$pwd;        # current working directory
my $h2cver = "h2c"; # this version is decided by the nghttp2 lib being used
my $portrange = 999;       # space from which to choose a random port
                           # don't increase without making sure generated port
                           # numbers will always be valid (<=65535)
my $HOSTIP="127.0.0.1";    # address on which the test server listens
my $HOST6IP="[::1]";       # address on which the test server listens
my $HTTPUNIXPATH;          # HTTP server Unix domain socket path
my $SOCKSUNIXPATH;         # socks server Unix domain socket path
my $SSHSRVMD5 = "[uninitialized]";    # MD5 of ssh server public key
my $SSHSRVSHA256 = "[uninitialized]"; # SHA256 of ssh server public key
my $USER;                  # name of the current user
my $sshdid;                # for socks server, ssh daemon version id
my $ftpchecktime=1;        # time it took to verify our test FTP server

# Variables shared with runtests.pl
our $SOCKSIN="socksd-request.log"; # what curl sent to the SOCKS proxy
our $err_unexpected; # error instead of warning on server unexpectedly alive
our $debugprotocol;  # nonzero for verbose server logs
our $stunnel;        # path to stunnel command


#######################################################################
# Check for a command in the PATH of the test server.
#
sub checkcmd {
    my ($cmd, @extrapaths)=@_;
    my @paths=(split(m/[:]/, $ENV{'PATH'}), "/usr/sbin", "/usr/local/sbin",
               "/sbin", "/usr/bin", "/usr/local/bin", @extrapaths);
    for(@paths) {
        if( -x "$_/$cmd" && ! -d "$_/$cmd") {
            # executable bit but not a directory!
            return "$_/$cmd";
        }
    }
    return "";
}

#######################################################################
# Create a server socket on a random (unused) port, then close it and
# return the port number
#
sub getfreeport {
    my ($ipnum) = @_;
    my $server = IO::Socket->new(LocalPort => 0,
                                 Domain => $ipnum == 6 ? AF_INET6 : AF_INET,
                                 Type      => SOCK_STREAM,
                                 Reuse     => 1,
                                 Listen    => 10 )
        or die "Couldn't create tcp server socket: $@\n";

    return $server->sockport();
}

use File::Temp qw/ tempfile/;

#######################################################################
# Initialize configuration variables
sub initserverconfig {
    my ($fh, $socks) = tempfile("/tmp/curl-socksd-XXXXXXXX");
    close($fh);
    unlink($socks);
    my ($f2, $http) = tempfile("/tmp/curl-http-XXXXXXXX");
    close($f2);
    unlink($http);
    $SOCKSUNIXPATH = $socks; # SOCKS Unix domain socket
    $HTTPUNIXPATH = $http;   # HTTP Unix domain socket
    $stunnel = checkcmd("stunnel4") || checkcmd("tstunnel") || checkcmd("stunnel");

    # get the name of the current user
    $USER = $ENV{USER};          # Linux
    if (!$USER) {
        $USER = $ENV{USERNAME};     # Windows
        if (!$USER) {
            $USER = $ENV{LOGNAME};  # Some Unix (I think)
        }
    }
    init_serverpidfile_hash();
}

#######################################################################
# Load serverpidfile and serverportfile hashes with file names for all
# possible servers.
#
sub init_serverpidfile_hash {
  for my $proto (('ftp', 'gopher', 'http', 'imap', 'pop3', 'smtp', 'http/2', 'http/3')) {
    for my $ssl (('', 's')) {
      for my $ipvnum ((4, 6)) {
        for my $idnum ((1, 2, 3)) {
          my $serv = servername_id("$proto$ssl", $ipvnum, $idnum);
          my $pidf = server_pidfilename("$LOGDIR/$PIDDIR", "$proto$ssl",
                                        $ipvnum, $idnum);
          $serverpidfile{$serv} = $pidf;
          my $portf = server_portfilename("$LOGDIR/$PIDDIR", "$proto$ssl",
                                          $ipvnum, $idnum);
          $serverportfile{$serv} = $portf;
        }
      }
    }
  }
  for my $proto (('tftp', 'sftp', 'socks', 'ssh', 'rtsp', 'httptls',
                  'dict', 'smb', 'smbs', 'telnet', 'mqtt')) {
    for my $ipvnum ((4, 6)) {
      for my $idnum ((1, 2)) {
        my $serv = servername_id($proto, $ipvnum, $idnum);
        my $pidf = server_pidfilename("$LOGDIR/$PIDDIR", $proto, $ipvnum,
                                      $idnum);
        $serverpidfile{$serv} = $pidf;
        my $portf = server_portfilename("$LOGDIR/$PIDDIR", $proto, $ipvnum,
                                        $idnum);
        $serverportfile{$serv} = $portf;
      }
    }
  }
  for my $proto (('http', 'imap', 'pop3', 'smtp', 'http/2', 'http/3')) {
    for my $ssl (('', 's')) {
      my $serv = servername_id("$proto$ssl", "unix", 1);
      my $pidf = server_pidfilename("$LOGDIR/$PIDDIR", "$proto$ssl",
                                    "unix", 1);
      $serverpidfile{$serv} = $pidf;
      my $portf = server_portfilename("$LOGDIR/$PIDDIR", "$proto$ssl",
                                      "unix", 1);
      $serverportfile{$serv} = $portf;
    }
  }
}


#######################################################################
# Kill the processes that still have lock files in a directory
#
sub clearlocks {
    my $dir = $_[0];
    my $done = 0;

    if(os_is_win()) {
        $dir = sys_native_abs_path($dir);
        $dir =~ s/\//\\\\/g;
        my $handle = "handle.exe";
        if($ENV{"PROCESSOR_ARCHITECTURE"} =~ /64$/) {
            $handle = "handle64.exe";
        }
        my @handles = `$handle $dir -accepteula -nobanner`;
        for my $tryhandle (@handles) {
            if($tryhandle =~ /^(\S+)\s+pid:\s+(\d+)\s+type:\s+(\w+)\s+([0-9A-F]+):\s+(.+)\r\r/) {
                logmsg "Found $3 lock of '$5' ($4) by $1 ($2)\n";
                # Ignore stunnel since we cannot do anything about its locks
                if("$3" eq "File" && "$1" ne "tstunnel.exe") {
                    logmsg "Killing IMAGENAME eq $1 and PID eq $2\n";
                    system("taskkill.exe -f -fi \"IMAGENAME eq $1\" -fi \"PID eq $2\" >nul 2>&1");
                    $done = 1;
                }
            }
        }
    }
    return $done;
}

#######################################################################
# Check if a given child process has just died. Reaps it if so.
#
sub checkdied {
    my $pid = $_[0];
    if((not defined $pid) || $pid <= 0) {
        return 0;
    }
    use POSIX ":sys_wait_h";
    my $rc = pidwait($pid, &WNOHANG);
    return ($rc == $pid)?1:0;
}


##############################################################################
# This function makes sure the right set of server is running for the
# specified test case. This is a useful design when we run single tests as not
# all servers need to run then!
#
# Returns: a string, blank if everything is fine or a reason why it failed, and
#          an integer:
#          0 for success
#          1 for an error starting the server
#          2 for not the first time getting an error starting the server
#          3 for a failure to stop a server in order to restart it
#          4 for an unsupported server type
#
sub serverfortest {
    my (@what)=@_;

    for(my $i = scalar(@what) - 1; $i >= 0; $i--) {
        my $srvrline = $what[$i];
        chomp $srvrline if($srvrline);
        if($srvrline =~ /^(\S+)((\s*)(.*))/) {
            my $server = "${1}";
            my $lnrest = "${2}";
            my $tlsext;
            if($server =~ /^(httptls)(\+)(ext|srp)(\d*)(-ipv6|)$/) {
                $server = "${1}${4}${5}";
                $tlsext = uc("TLS-${3}");
            }
            if(! grep /^\Q$server\E$/, @protocols) {
                if(substr($server,0,5) ne "socks") {
                    if($tlsext) {
                        return ("curl lacks $tlsext support", 4);
                    }
                    else {
                        return ("curl lacks $server server support", 4);
                    }
                }
            }
            $what[$i] = "$server$lnrest" if($tlsext);
        }
    }

    return &startservers(@what);
}


#######################################################################
# Start a new thread/process and run the given command line in there.
# Return the pids (yes plural) of the new child process to the parent.
#
sub startnew {
    my ($cmd, $pidfile, $timeout, $fakepidfile)=@_;

    logmsg "startnew: $cmd\n" if ($verbose);

    my $child = fork();

    if(not defined $child) {
        logmsg "startnew: fork() failure detected\n";
        return (-1,-1);
    }

    if(0 == $child) {
        # Here we are the child. Run the given command.

        # Flush output.
        $| = 1;

        # Put an "exec" in front of the command so that the child process
        # keeps this child's process ID.
        exec("exec $cmd") || die "Can't exec() $cmd: $!";

        # exec() should never return back here to this process. We protect
        # ourselves by calling die() just in case something goes really bad.
        die "error: exec() has returned";
    }

    # Ugly hack but ssh client and gnutls-serv don't support pid files
    if ($fakepidfile) {
        if(open(my $out, ">", "$pidfile")) {
            print $out $child . "\n";
            close($out) || die "Failure writing pidfile";
            logmsg "startnew: $pidfile faked with pid=$child\n" if($verbose);
        }
        else {
            logmsg "startnew: failed to write fake $pidfile with pid=$child\n";
        }
        # could/should do a while connect fails sleep a bit and loop
        portable_sleep($timeout);
        if (checkdied($child)) {
            logmsg "startnew: child process has failed to start\n" if($verbose);
            return (-1,-1);
        }
    }

    my $pid2 = 0;
    my $count = $timeout;
    while($count--) {
        $pid2 = pidfromfile($pidfile);
        if(($pid2 > 0) && pidexists($pid2)) {
            # if $pid2 is valid, then make sure this pid is alive, as
            # otherwise it is just likely to be the _previous_ pidfile or
            # similar!
            last;
        }
        if (checkdied($child)) {
            logmsg "startnew: child process has died, server might start up\n"
                if($verbose);
            # We can't just abort waiting for the server with a
            # return (-1,-1);
            # because the server might have forked and could still start
            # up normally. Instead, just reduce the amount of time we remain
            # waiting.
            $count >>= 2;
        }
        sleep(1);
    }

    # Return two PIDs, the one for the child process we spawned and the one
    # reported by the server itself (in case it forked again on its own).
    # Both (potentially) need to be killed at the end of the test.
    return ($child, $pid2);
}


#######################################################################
# Return the port to use for the given protocol.
#
sub protoport {
    my ($proto) = @_;
    return $PORT{$proto} || "[not running]";
}


#######################################################################
# Stop a test server along with pids which aren't in the %run hash yet.
# This also stops all servers which are relative to the given one.
#
sub stopserver {
    my ($server, $pidlist) = @_;

    #
    # kill sockfilter processes for pingpong relative server
    #
    if($server =~ /^(ftp|imap|pop3|smtp)s?(\d*)(-ipv6|)$/) {
        my $proto  = $1;
        my $idnum  = ($2 && ($2 > 1)) ? $2 : 1;
        my $ipvnum = ($3 && ($3 =~ /6$/)) ? 6 : 4;
        killsockfilters("$LOGDIR/$PIDDIR", $proto, $ipvnum, $idnum, $verbose);
    }
    #
    # All servers relative to the given one must be stopped also
    #
    my @killservers;
    if($server =~ /^(ftp|http|imap|pop3|smtp)s((\d*)(-ipv6|-unix|))$/) {
        # given a stunnel based ssl server, also kill non-ssl underlying one
        push @killservers, "${1}${2}";
    }
    elsif($server =~ /^(ftp|http|imap|pop3|smtp)((\d*)(-ipv6|-unix|))$/) {
        # given a non-ssl server, also kill stunnel based ssl piggybacking one
        push @killservers, "${1}s${2}";
    }
    elsif($server =~ /^(socks)((\d*)(-ipv6|))$/) {
        # given a socks server, also kill ssh underlying one
        push @killservers, "ssh${2}";
    }
    elsif($server =~ /^(ssh)((\d*)(-ipv6|))$/) {
        # given a ssh server, also kill socks piggybacking one
        push @killservers, "socks${2}";
    }
    if($server eq "http" or $server eq "https") {
        # since the http2+3 server is a proxy that needs to know about the
        # dynamic http port it too needs to get restarted when the http server
        # is killed
        push @killservers, "http/2";
        push @killservers, "http/3";
    }
    push @killservers, $server;
    #
    # kill given pids and server relative ones clearing them in %run hash
    #
    foreach my $server (@killservers) {
        if($run{$server}) {
            # we must prepend a space since $pidlist may already contain a pid
            $pidlist .= " $run{$server}";
            $run{$server} = 0;
        }
        $runcert{$server} = 0 if($runcert{$server});
    }
    killpid($verbose, $pidlist);
    #
    # cleanup server pid files
    #
    my $result = 0;
    foreach my $server (@killservers) {
        my $pidfile = $serverpidfile{$server};
        my $pid = processexists($pidfile);
        if($pid > 0) {
            if($err_unexpected) {
                logmsg "ERROR: ";
                $result = -1;
            }
            else {
                logmsg "Warning: ";
            }
            logmsg "$server server unexpectedly alive\n";
            killpid($verbose, $pid);
        }
        unlink($pidfile) if(-f $pidfile);
    }

    return $result;
}


#######################################################################
# Return flags to let curl use an external HTTP proxy
#
sub getexternalproxyflags {
    return " --proxy $proxy_address ";
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address")
#
sub verifyhttp {
    my ($proto, $ipvnum, $idnum, $ip, $port_or_path) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $bonus="";
    # $port_or_path contains a path for Unix sockets, sws ignores the port
    my $port = ($ipvnum eq "unix") ? 80 : $port_or_path;

    my $verifyout = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.out';
    unlink($verifyout) if(-f $verifyout);

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    if($proto eq "gopher") {
        # gopher is funny
        $bonus="1/";
    }

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--output $verifyout ";
    $flags .= "--silent ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    $flags .= "--unix-socket '$port_or_path' " if $ipvnum eq "unix";
    $flags .= "--insecure " if($proto eq 'https');
    if($proxy_address) {
        $flags .= getexternalproxyflags();
    }
    $flags .= "\"$proto://$ip:$port/${bonus}verifiedserver\"";

    my $cmd = "$VCURL $flags 2>$verifylog";

    # verify if our/any server is running on this port
    logmsg "RUN: $cmd\n" if($verbose);
    my $res = runclient($cmd);

    $res >>= 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    if($res && $verbose) {
        logmsg "RUN: curl command returned $res\n";
        if(open(my $file, "<", "$verifylog")) {
            while(my $string = <$file>) {
                logmsg "RUN: $string" if($string !~ /^([ \t]*)$/);
            }
            close($file);
        }
    }

    my $data;
    if(open(my $file, "<", "$verifyout")) {
        while(my $string = <$file>) {
            $data = $string;
            last; # only want first line
        }
        close($file);
    }

    my $pid = 0;
    if($data && ($data =~ /WE ROOLZ: (\d+)/)) {
        $pid = 0+$1;
    }
    elsif($res == 6) {
        # curl: (6) Couldn't resolve host '::1'
        logmsg "RUN: failed to resolve host ($proto://$ip:$port/verifiedserver)\n";
        return -1;
    }
    elsif($data || ($res && ($res != 7))) {
        logmsg "RUN: Unknown server on our $server port: $port ($res)\n";
        return -1;
    }
    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address")
#
sub verifyftp {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $time=time();
    my $extra="";

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    if($proto eq "ftps") {
        $extra .= "--insecure --ftp-ssl-control ";
    }

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--silent ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    $flags .= $extra;
    if($proxy_address) {
        $flags .= getexternalproxyflags();
    }
    $flags .= "\"$proto://$ip:$port/verifiedserver\"";

    my $cmd = "$VCURL $flags 2>$verifylog";

    # check if this is our server running on this port:
    logmsg "RUN: $cmd\n" if($verbose);
    my @data = runclientoutput($cmd);

    my $res = $? >> 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    my $pid = 0;
    foreach my $line (@data) {
        if($line =~ /WE ROOLZ: (\d+)/) {
            # this is our test server with a known pid!
            $pid = 0+$1;
            last;
        }
    }
    if($pid <= 0 && @data && $data[0]) {
        # this is not a known server
        logmsg "RUN: Unknown server on our $server port: $port\n";
        return 0;
    }
    # we can/should use the time it took to verify the FTP server as a measure
    # on how fast/slow this host/FTP is.
    my $took = int(0.5+time()-$time);

    if($verbose) {
        logmsg "RUN: Verifying our test $server server took $took seconds\n";
    }
    $ftpchecktime = $took>=1?$took:1; # make sure it never is below 1

    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address")
#
sub verifyrtsp {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);

    my $verifyout = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.out';
    unlink($verifyout) if(-f $verifyout);

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--output $verifyout ";
    $flags .= "--silent ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    if($proxy_address) {
        $flags .= getexternalproxyflags();
    }
    # currently verification is done using http
    $flags .= "\"http://$ip:$port/verifiedserver\"";

    my $cmd = "$VCURL $flags 2>$verifylog";

    # verify if our/any server is running on this port
    logmsg "RUN: $cmd\n" if($verbose);
    my $res = runclient($cmd);

    $res >>= 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    if($res && $verbose) {
        logmsg "RUN: curl command returned $res\n";
        if(open(my $file, "<", "$verifylog")) {
            while(my $string = <$file>) {
                logmsg "RUN: $string" if($string !~ /^[ \t]*$/);
            }
            close($file);
        }
    }

    my $data;
    if(open(my $file, "<", "$verifyout")) {
        while(my $string = <$file>) {
            $data = $string;
            last; # only want first line
        }
        close($file);
    }

    my $pid = 0;
    if($data && ($data =~ /RTSP_SERVER WE ROOLZ: (\d+)/)) {
        $pid = 0+$1;
    }
    elsif($res == 6) {
        # curl: (6) Couldn't resolve host '::1'
        logmsg "RUN: failed to resolve host ($proto://$ip:$port/verifiedserver)\n";
        return -1;
    }
    elsif($data || ($res != 7)) {
        logmsg "RUN: Unknown server on our $server port: $port\n";
        return -1;
    }
    return $pid;
}

#######################################################################
# Verify that the ssh server has written out its pidfile, recovering
# the pid from the file and returning it if a process with that pid is
# actually alive, or a negative value if the process is dead.
#
sub verifyssh {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $pidfile = server_pidfilename("$LOGDIR/$PIDDIR", $proto, $ipvnum,
                                     $idnum);
    my $pid = processexists($pidfile);
    if($pid < 0) {
        logmsg "RUN: SSH server has died after starting up\n";
    }
    return $pid;
}

#######################################################################
# Verify that we can connect to the sftp server, properly authenticate
# with generated config and key files and run a simple remote pwd.
#
sub verifysftp {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $verified = 0;
    # Find out sftp client canonical file name
    my $sftp = find_sftp();
    if(!$sftp) {
        logmsg "RUN: SFTP server cannot find $sftpexe\n";
        return -1;
    }
    # Find out ssh client canonical file name
    my $ssh = find_ssh();
    if(!$ssh) {
        logmsg "RUN: SFTP server cannot find $sshexe\n";
        return -1;
    }
    # Connect to sftp server, authenticate and run a remote pwd
    # command using our generated configuration and key files
    my $cmd = "\"$sftp\" -b $LOGDIR/$PIDDIR/$sftpcmds -F $LOGDIR/$PIDDIR/$sftpconfig -S \"$ssh\" $ip > $sftplog 2>&1";
    my $res = runclient($cmd);
    # Search for pwd command response in log file
    if(open(my $sftplogfile, "<", "$sftplog")) {
        while(<$sftplogfile>) {
            if(/^Remote working directory: /) {
                $verified = 1;
                last;
            }
        }
        close($sftplogfile);
    }
    return $verified;
}

#######################################################################
# Verify that the non-stunnel HTTP TLS extensions capable server that runs
# on $ip, $port is our server.  This also implies that we can speak with it,
# as there might be occasions when the server runs fine but we cannot talk
# to it ("Failed to connect to ::1: Can't assign requested address")
#
sub verifyhttptls {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $pidfile = server_pidfilename("$LOGDIR/$PIDDIR", $proto, $ipvnum,
                                     $idnum);

    my $verifyout = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.out';
    unlink($verifyout) if(-f $verifyout);

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--output $verifyout ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    $flags .= "--insecure ";
    $flags .= "--tlsauthtype SRP ";
    $flags .= "--tlsuser jsmith ";
    $flags .= "--tlspassword abc ";
    if($proxy_address) {
        $flags .= getexternalproxyflags();
    }
    $flags .= "\"https://$ip:$port/verifiedserver\"";

    my $cmd = "$VCURL $flags 2>$verifylog";

    # verify if our/any server is running on this port
    logmsg "RUN: $cmd\n" if($verbose);
    my $res = runclient($cmd);

    $res >>= 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    if($res && $verbose) {
        logmsg "RUN: curl command returned $res\n";
        if(open(my $file, "<", "$verifylog")) {
            while(my $string = <$file>) {
                logmsg "RUN: $string" if($string !~ /^([ \t]*)$/);
            }
            close($file);
        }
    }

    my $data;
    if(open(my $file, "<", "$verifyout")) {
        while(my $string = <$file>) {
            $data .= $string;
        }
        close($file);
    }

    my $pid = 0;
    if($data && ($data =~ /(GNUTLS|GnuTLS)/) && ($pid = processexists($pidfile))) {
        if($pid < 0) {
            logmsg "RUN: $server server has died after starting up\n";
        }
        return $pid;
    }
    elsif($res == 6) {
        # curl: (6) Couldn't resolve host '::1'
        logmsg "RUN: failed to resolve host (https://$ip:$port/verifiedserver)\n";
        return -1;
    }
    elsif($data || ($res && ($res != 7))) {
        logmsg "RUN: Unknown server on our $server port: $port ($res)\n";
        return -1;
    }
    return $pid;
}

#######################################################################
# STUB for verifying socks
#
sub verifysocks {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $pidfile = server_pidfilename("$LOGDIR/$PIDDIR", $proto, $ipvnum,
                                     $idnum);
    my $pid = processexists($pidfile);
    if($pid < 0) {
        logmsg "RUN: SOCKS server has died after starting up\n";
    }
    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address")
#
sub verifysmb {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $time=time();
    my $extra="";

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--silent ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    $flags .= "-u 'curltest:curltest' ";
    $flags .= $extra;
    $flags .= "\"$proto://$ip:$port/SERVER/verifiedserver\"";

    my $cmd = "$VCURL $flags 2>$verifylog";

    # check if this is our server running on this port:
    logmsg "RUN: $cmd\n" if($verbose);
    my @data = runclientoutput($cmd);

    my $res = $? >> 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    my $pid = 0;
    foreach my $line (@data) {
        if($line =~ /WE ROOLZ: (\d+)/) {
            # this is our test server with a known pid!
            $pid = 0+$1;
            last;
        }
    }
    if($pid <= 0 && @data && $data[0]) {
        # this is not a known server
        logmsg "RUN: Unknown server on our $server port: $port\n";
        return 0;
    }
    # we can/should use the time it took to verify the server as a measure
    # on how fast/slow this host is.
    my $took = int(0.5+time()-$time);

    if($verbose) {
        logmsg "RUN: Verifying our test $server server took $took seconds\n";
    }

    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.  This also
# implies that we can speak with it, as there might be occasions when the
# server runs fine but we cannot talk to it ("Failed to connect to ::1: Can't
# assign requested address")
#
sub verifytelnet {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $time=time();
    my $extra="";

    my $verifylog = "$LOGDIR/".
        servername_canon($proto, $ipvnum, $idnum) .'_verify.log';
    unlink($verifylog) if(-f $verifylog);

    my $flags = "--max-time $server_response_maxtime ";
    $flags .= "--silent ";
    $flags .= "--verbose ";
    $flags .= "--globoff ";
    $flags .= "--upload-file - ";
    $flags .= $extra;
    $flags .= "\"$proto://$ip:$port\"";

    my $cmd = "echo 'verifiedserver' | $VCURL $flags 2>$verifylog";

    # check if this is our server running on this port:
    logmsg "RUN: $cmd\n" if($verbose);
    my @data = runclientoutput($cmd);

    my $res = $? >> 8; # rotate the result
    if($res & 128) {
        logmsg "RUN: curl command died with a coredump\n";
        return -1;
    }

    my $pid = 0;
    foreach my $line (@data) {
        if($line =~ /WE ROOLZ: (\d+)/) {
            # this is our test server with a known pid!
            $pid = 0+$1;
            last;
        }
    }
    if($pid <= 0 && @data && $data[0]) {
        # this is not a known server
        logmsg "RUN: Unknown server on our $server port: $port\n";
        return 0;
    }
    # we can/should use the time it took to verify the server as a measure
    # on how fast/slow this host is.
    my $took = int(0.5+time()-$time);

    if($verbose) {
        logmsg "RUN: Verifying our test $server server took $took seconds\n";
    }

    return $pid;
}

#######################################################################
# Verify that the server that runs on $ip, $port is our server.
# Retry over several seconds before giving up.  The ssh server in
# particular can take a long time to start if it needs to generate
# keys on a slow or loaded host.
#
# Just for convenience, test harness uses 'https' and 'httptls' literals
# as values for 'proto' variable in order to differentiate different
# servers. 'https' literal is used for stunnel based https test servers,
# and 'httptls' is used for non-stunnel https test servers.
#

my %protofunc = ('http' => \&verifyhttp,
                 'https' => \&verifyhttp,
                 'rtsp' => \&verifyrtsp,
                 'ftp' => \&verifyftp,
                 'pop3' => \&verifyftp,
                 'imap' => \&verifyftp,
                 'smtp' => \&verifyftp,
                 'ftps' => \&verifyftp,
                 'pop3s' => \&verifyftp,
                 'imaps' => \&verifyftp,
                 'smtps' => \&verifyftp,
                 'tftp' => \&verifyftp,
                 'ssh' => \&verifyssh,
                 'socks' => \&verifysocks,
                 'socks5unix' => \&verifysocks,
                 'gopher' => \&verifyhttp,
                 'httptls' => \&verifyhttptls,
                 'dict' => \&verifyftp,
                 'smb' => \&verifysmb,
                 'telnet' => \&verifytelnet);

sub verifyserver {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;

    my $count = 30; # try for this many seconds
    my $pid;

    while($count--) {
        my $fun = $protofunc{$proto};

        $pid = &$fun($proto, $ipvnum, $idnum, $ip, $port);

        if($pid > 0) {
            last;
        }
        elsif($pid < 0) {
            # a real failure, stop trying and bail out
            return 0;
        }
        sleep(1);
    }
    return $pid;
}

#######################################################################
# Single shot server responsiveness test. This should only be used
# to verify that a server present in %run hash is still functional
#
sub responsiveserver {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $prev_verbose = $verbose;

    $verbose = 0;
    my $fun = $protofunc{$proto};
    my $pid = &$fun($proto, $ipvnum, $idnum, $ip, $port);
    $verbose = $prev_verbose;

    if($pid > 0) {
        return 1; # responsive
    }

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    logmsg " server precheck FAILED (unresponsive $srvrname server)\n";
    return 0;
}


#######################################################################
# start the http server
#
sub runhttpserver {
    my ($proto, $verb, $alt, $port_or_path) = @_;
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $exe = "$perl $srcdir/http-server.pl";
    my $verbose_flag = "--verbose ";
    my $keepalive_secs = 30; # forwarded to sws, was 5 by default which
                             # led to pukes in CI jobs

    if($alt eq "ipv6") {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }
    elsif($alt eq "proxy") {
        # basically the same, but another ID
        $idnum = 2;
    }
    elsif($alt eq "unix") {
        # IP (protocol) is mutually exclusive with Unix sockets
        $ipvnum = "unix";
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $portfile = $serverportfile{$server};

    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--gopher " if($proto eq "gopher");
    $flags .= "--connect $HOSTIP " if($alt eq "proxy");
    $flags .= "--keepalive $keepalive_secs ";
    $flags .= $verbose_flag if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--portfile $portfile ";
    $flags .= "--config $LOGDIR/$SERVERCMD ";
    $flags .= "--id $idnum " if($idnum > 1);
    if($ipvnum eq "unix") {
        $flags .= "--unix-socket '$port_or_path' ";
    } else {
        $flags .= "--ipv$ipvnum --port 0 ";
    }
    $flags .= "--srcdir \"$srcdir\"";

    my $cmd = "$exe $flags";
    my ($httppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($httppid <= 0 || !pidexists($httppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }

    # where is it?
    my $port = 0;
    if(!$port_or_path) {
        $port = $port_or_path = pidfromfile($portfile);
    }

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port_or_path);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$httppid $pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }
    $pid2 = $pid3;

    if($verb) {
        logmsg "RUN: $srvrname server is on PID $httppid port $port_or_path\n";
    }

    return (0, $httppid, $pid2, $port);
}


#######################################################################
# start the http2 server
#
sub runhttp2server {
    my ($verb) = @_;
    my $proto="http/2";
    my $ipvnum = 4;
    my $idnum = 0;
    my $exe = "$perl $srcdir/http2-server.pl";
    my $verbose_flag = "--verbose ";

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--nghttpx \"$ENV{'NGHTTPX'}\" ";
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--connect $HOSTIP:" . protoport("http") . " ";
    $flags .= $verbose_flag if($debugprotocol);

    my $port = getfreeport($ipvnum);
    my $port2 = getfreeport($ipvnum);
    my $aflags = "--port $port --port2 $port2 $flags";
    my $cmd = "$exe $aflags";
    my ($http2pid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($http2pid <= 0 || !pidexists($http2pid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $http2pid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $http2pid ".
            "http-port $port https-port $port2 ".
            "backend $HOSTIP:" . protoport("http") . "\n";
    }

    return (0+!$http2pid, $http2pid, $pid2, $port, $port2);
}

#######################################################################
# start the http3 server
#
sub runhttp3server {
    my ($verb, $cert) = @_;
    my $proto="http/3";
    my $ipvnum = 4;
    my $idnum = 0;
    my $exe = "$perl $srcdir/http3-server.pl";
    my $verbose_flag = "--verbose ";

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--nghttpx \"$ENV{'NGHTTPX'}\" ";
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--connect $HOSTIP:" . protoport("http") . " ";
    $flags .= "--cert \"$cert\" " if($cert);
    $flags .= $verbose_flag if($debugprotocol);

    my $port = getfreeport($ipvnum);
    my $aflags = "--port $port $flags";
    my $cmd = "$exe $aflags";
    my ($http3pid, $pid3) = startnew($cmd, $pidfile, 15, 0);

    if($http3pid <= 0 || !pidexists($http3pid)) {
        # it is NOT alive
        stopserver($server, "$pid3");
        $doesntrun{$pidfile} = 1;
        $http3pid = $pid3 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $http3pid port $port\n";
    }

    return (0+!$http3pid, $http3pid, $pid3, $port);
}

#######################################################################
# start the https stunnel based server
#
sub runhttpsserver {
    my ($verb, $proto, $proxy, $certfile) = @_;
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($proxy eq "proxy") {
        # the https-proxy runs as https2
        $idnum = 2;
    }

    if(!$stunnel) {
        return (4, 0, 0, 0);
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    $certfile = 'stunnel.pem' unless($certfile);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --proto $proto ";
    $flags .= "--certfile \"$certfile\" " if($certfile ne 'stunnel.pem');
    $flags .= "--stunnel \"$stunnel\" --srcdir \"$srcdir\" ";
    if($proto eq "gophers") {
        $flags .= "--connect " . protoport("gopher");
    }
    elsif(!$proxy) {
        $flags .= "--connect " . protoport("http");
    }
    else {
        # for HTTPS-proxy we connect to the HTTP proxy
        $flags .= "--connect " . protoport("httpproxy");
    }

    my $port = getfreeport($ipvnum);
    my $options = "$flags --accept $port";
    my $cmd = "$perl $srcdir/secureserver.pl $options";
    my ($httpspid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($httpspid <= 0 || !pidexists($httpspid)) {
        # it is NOT alive
        # don't call stopserver since that will also kill the dependent
        # server that has already been started properly
        $doesntrun{$pidfile} = 1;
        $httpspid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }

    $doesntrun{$pidfile} = 0;
    # we have a server!
    if($verb) {
        logmsg "RUN: $srvrname server is PID $httpspid port $port\n";
    }

    $runcert{$server} = $certfile;

    return (0+!$httpspid, $httpspid, $pid2, $port);
}

#######################################################################
# start the non-stunnel HTTP TLS extensions capable server
#
sub runhttptlsserver {
    my ($verb, $ipv6) = @_;
    my $proto = "httptls";
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = 1;

    if(!$httptlssrv) {
        return (4, 0, 0);
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--http ";
    $flags .= "--debug 1 " if($debugprotocol);
    $flags .= "--priority NORMAL:+SRP ";
    $flags .= "--srppasswd $srcdir/certs/srp-verifier-db ";
    $flags .= "--srppasswdconf $srcdir/certs/srp-verifier-conf";

    my $port = getfreeport($ipvnum);
    my $allflags = "--port $port $flags";
    my $cmd = "$httptlssrv $allflags > $logfile 2>&1";
    my ($httptlspid, $pid2) = startnew($cmd, $pidfile, 10, 1);

    if($httptlspid <= 0 || !pidexists($httptlspid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $httptlspid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $httptlspid port $port\n";
    }
    return (0+!$httptlspid, $httptlspid, $pid2, $port);
}

#######################################################################
# start the pingpong server (FTP, POP3, IMAP, SMTP)
#
sub runpingpongserver {
    my ($proto, $id, $verb, $ipv6) = @_;

    # Check the requested server
    if($proto !~ /^(?:ftp|imap|pop3|smtp)$/) {
        logmsg "Unsupported protocol $proto!!\n";
        return (4, 0, 0);
    }

    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--portfile \"$portfile\" ";
    $flags .= "--srcdir \"$srcdir\" --proto $proto ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --port 0 --addr \"$ip\"";

    my $cmd = "$perl $srcdir/ftpserver.pl $flags";
    my ($ftppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($ftppid <= 0 || !pidexists($ftppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0);
    }

    # where is it?
    my $port = pidfromfile($portfile);

    logmsg "PINGPONG runs on port $port ($portfile)\n" if($verb);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$ftppid $pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0);
    }
    $pid2 = $pid3;

    logmsg "RUN: $srvrname server is PID $ftppid port $port\n" if($verb);

    # Assign the correct port variable!
    $PORT{$proto . ($ipvnum == 6? '6': '')} = $port;

    return (0, $pid2, $ftppid);
}

#######################################################################
# start the ftps/imaps/pop3s/smtps server (or rather, tunnel)
#
sub runsecureserver {
    my ($verb, $ipv6, $certfile, $proto, $clearport) = @_;
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = 1;

    if(!$stunnel) {
        return (4, 0, 0, 0);
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    $certfile = 'stunnel.pem' unless($certfile);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --proto $proto ";
    $flags .= "--certfile \"$certfile\" " if($certfile ne 'stunnel.pem');
    $flags .= "--stunnel \"$stunnel\" --srcdir \"$srcdir\" ";
    $flags .= "--connect $clearport";

    my $port = getfreeport($ipvnum);
    my $options = "$flags --accept $port";

    my $cmd = "$perl $srcdir/secureserver.pl $options";
    my ($protospid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($protospid <= 0 || !pidexists($protospid)) {
        # it is NOT alive
        # don't call stopserver since that will also kill the dependent
        # server that has already been started properly
        $doesntrun{$pidfile} = 1;
        $protospid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }

    $doesntrun{$pidfile} = 0;
    $runcert{$server} = $certfile;

    if($verb) {
        logmsg "RUN: $srvrname server is PID $protospid port $port\n";
    }

    return (0+!$protospid, $protospid, $pid2, $port);
}

#######################################################################
# start the tftp server
#
sub runtftpserver {
    my ($id, $verb, $ipv6) = @_;
    my $ip = $HOSTIP;
    my $proto = 'tftp';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $portfile = $serverportfile{$server};
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ";
    $flags .= "--portfile \"$portfile\" ";
    $flags .= "--logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --port 0 --srcdir \"$srcdir\"";

    my $cmd = "$perl $srcdir/tftpserver.pl $flags";
    my ($tftppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($tftppid <= 0 || !pidexists($tftppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$tftppid $pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }
    $pid2 = $pid3;

    if($verb) {
        logmsg "RUN: $srvrname server on PID $tftppid port $port\n";
    }

    return (0, $pid2, $tftppid, $port);
}


#######################################################################
# start the rtsp server
#
sub runrtspserver {
    my ($verb, $ipv6) = @_;
    my $ip = $HOSTIP;
    my $proto = 'rtsp';
    my $ipvnum = 4;
    my $idnum = 1;

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ";
    $flags .= "--portfile \"$portfile\" ";
    $flags .= "--logfile \"$logfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --port 0 --srcdir \"$srcdir\"";

    my $cmd = "$perl $srcdir/rtspserver.pl $flags";
    my ($rtsppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($rtsppid <= 0 || !pidexists($rtsppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$rtsppid $pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }
    $pid2 = $pid3;

    if($verb) {
        logmsg "RUN: $srvrname server PID $rtsppid port $port\n";
    }

    return (0, $rtsppid, $pid2, $port);
}


#######################################################################
# Start the ssh (scp/sftp) server
#
sub runsshserver {
    my ($id, $verb, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $proto = 'ssh';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    if(!$USER) {
        logmsg "Can't start ssh server due to lack of USER name\n";
        return (4, 0, 0, 0);
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $sshd = find_sshd();
    if($sshd) {
        ($sshdid,$sshdvernum,$sshdverstr,$sshderror) = sshversioninfo($sshd);
        logmsg $sshderror if($sshderror);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($verb);
    $flags .= "--debugprotocol " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ";
    $flags .= "--logdir \"$LOGDIR\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --addr \"$ip\" ";
    $flags .= "--user \"$USER\"";

    my @tports;
    my $port = getfreeport($ipvnum);

    push @tports, $port;

    my $options = "$flags --sshport $port";

    my $cmd = "$perl $srcdir/sshserver.pl $options";
    my ($sshpid, $pid2) = startnew($cmd, $pidfile, 60, 0);

    # on loaded systems sshserver start up can take longer than the
    # timeout passed to startnew, when this happens startnew completes
    # without being able to read the pidfile and consequently returns a
    # zero pid2 above.
    if($sshpid <= 0 || !pidexists($sshpid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $sshpid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server on $port\n";
        return (3, 0, 0, 0);
    }

    # once it is known that the ssh server is alive, sftp server
    # verification is performed actually connecting to it, authenticating
    # and performing a very simple remote command.  This verification is
    # tried only one time.

    $sshdlog = server_logfilename($LOGDIR, 'ssh', $ipvnum, $idnum);
    $sftplog = server_logfilename($LOGDIR, 'sftp', $ipvnum, $idnum);

    if(verifysftp('sftp', $ipvnum, $idnum, $ip, $port) < 1) {
        logmsg "RUN: SFTP server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        display_sftplog();
        display_sftpconfig();
        display_sshdlog();
        display_sshdconfig();
        stopserver($server, "$sshpid $pid2");
        $doesntrun{$pidfile} = 1;
        $sshpid = $pid2 = 0;
        logmsg "RUN: failed to verify the $srvrname server on $port\n";
        return (5, 0, 0, 0);
    }
    # we're happy, no need to loop anymore!
    $doesntrun{$pidfile} = 0;

    my $hostfile;
    if(!open($hostfile, "<", "$LOGDIR/$PIDDIR/$hstpubmd5f") ||
       (read($hostfile, $SSHSRVMD5, 32) != 32) ||
       !close($hostfile) ||
       ($SSHSRVMD5 !~ /^[a-f0-9]{32}$/i))
    {
        my $msg = "Fatal: $srvrname pubkey md5 missing : \"$hstpubmd5f\" : $!";
        logmsg "$msg\n";
        stopservers($verb);
        die $msg;
    }

    if(!open($hostfile, "<", "$LOGDIR/$PIDDIR/$hstpubsha256f") ||
       (read($hostfile, $SSHSRVSHA256, 48) == 0) ||
       !close($hostfile))
    {
        my $msg = "Fatal: $srvrname pubkey sha256 missing : \"$hstpubsha256f\" : $!";
        logmsg "$msg\n";
        stopservers($verb);
        die $msg;
    }

    logmsg "RUN: $srvrname on PID $pid2 port $port\n" if($verb);

    return (0, $pid2, $sshpid, $port);
}

#######################################################################
# Start the MQTT server
#
sub runmqttserver {
    my ($id, $verb, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $proto = 'mqtt';
    my $port = protoport($proto);
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    my $server = servername_id($proto, $ipvnum, $idnum);
    my $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    # start our MQTT server - on a random port!
    my $cmd="server/mqttd".exe_ext('SRV').
        " --port 0 ".
        " --pidfile $pidfile".
        " --portfile $portfile".
        " --config $LOGDIR/$SERVERCMD".
        " --logfile $logfile".
        " --logdir $LOGDIR";
    my ($sockspid, $pid2) = startnew($cmd, $pidfile, 30, 0);

    if($sockspid <= 0 || !pidexists($sockspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0);
    }

    my $mqttport = pidfromfile($portfile);
    $PORT{"mqtt"} = $mqttport;

    if($verb) {
        logmsg "RUN: $srvrname server is now running PID $pid2 on PORT $mqttport\n";
    }

    return (0, $pid2, $sockspid);
}

#######################################################################
# Start the socks server
#
sub runsocksserver {
    my ($id, $verb, $ipv6, $is_unix) = @_;
    my $ip=$HOSTIP;
    my $proto = 'socks';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $portfile = $serverportfile{$server};
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    # start our socks server, get commands from the FTP cmd file
    my $cmd="";
    if($is_unix) {
        $cmd="server/socksd".exe_ext('SRV').
            " --pidfile $pidfile".
            " --reqfile $LOGDIR/$SOCKSIN".
            " --logfile $logfile".
            " --unix-socket $SOCKSUNIXPATH".
            " --backend $HOSTIP".
            " --config $LOGDIR/$SERVERCMD";
    } else {
        $cmd="server/socksd".exe_ext('SRV').
            " --port 0 ".
            " --pidfile $pidfile".
            " --portfile $portfile".
            " --reqfile $LOGDIR/$SOCKSIN".
            " --logfile $logfile".
            " --backend $HOSTIP".
            " --config $LOGDIR/$SERVERCMD";
    }
    my ($sockspid, $pid2) = startnew($cmd, $pidfile, 30, 0);

    if($sockspid <= 0 || !pidexists($sockspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (1, 0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    if($verb) {
        logmsg "RUN: $srvrname server is now running PID $pid2\n";
    }

    return (0, $pid2, $sockspid, $port);
}

#######################################################################
# start the dict server
#
sub rundictserver {
    my ($verb, $alt) = @_;
    my $proto = "dict";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($alt eq "ipv6") {
        # No IPv6
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\" ";
    $flags .= "--host $HOSTIP";

    my $port = getfreeport($ipvnum);
    my $aflags = "--port $port $flags";
    my $cmd = "$srcdir/dictserver.py $aflags";
    my ($dictpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($dictpid <= 0 || !pidexists($dictpid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $dictpid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $dictpid port $port\n";
    }

    return (0+!$dictpid, $dictpid, $pid2, $port);
}

#######################################################################
# start the SMB server
#
sub runsmbserver {
    my ($verb, $alt) = @_;
    my $proto = "smb";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($alt eq "ipv6") {
        # No IPv6
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\" ";
    $flags .= "--host $HOSTIP";

    my $port = getfreeport($ipvnum);
    my $aflags = "--port $port $flags";
    my $cmd = "$srcdir/smbserver.py $aflags";
    my ($smbpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($smbpid <= 0 || !pidexists($smbpid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $smbpid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $smbpid port $port\n";
    }

    return (0+!$smbpid, $smbpid, $pid2, $port);
}

#######################################################################
# start the telnet server
#
sub runnegtelnetserver {
    my ($verb, $alt) = @_;
    my $proto = "telnet";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($alt eq "ipv6") {
        # No IPv6
    }

    my $server = servername_id($proto, $ipvnum, $idnum);

    my $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (2, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    my $srvrname = servername_str($proto, $ipvnum, $idnum);
    my $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\"";

    my $port = getfreeport($ipvnum);
    my $aflags = "--port $port $flags";
    my $cmd = "$srcdir/negtelnetserver.py $aflags";
    my ($ntelpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($ntelpid <= 0 || !pidexists($ntelpid)) {
        # it is NOT alive
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        $ntelpid = $pid2 = 0;
        logmsg "RUN: failed to start the $srvrname server\n";
        return (3, 0, 0, 0);
    }
    $doesntrun{$pidfile} = 0;

    if($verb) {
        logmsg "RUN: $srvrname server PID $ntelpid port $port\n";
    }

    return (0+!$ntelpid, $ntelpid, $pid2, $port);
}




#######################################################################
# Single shot http and gopher server responsiveness test. This should only
# be used to verify that a server present in %run hash is still functional
#
sub responsive_http_server {
    my ($proto, $verb, $alt, $port_or_path) = @_;
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($alt eq "ipv6") {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }
    elsif($alt eq "proxy") {
        $idnum = 2;
    }
    elsif($alt eq "unix") {
        # IP (protocol) is mutually exclusive with Unix sockets
        $ipvnum = "unix";
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port_or_path);
}

#######################################################################
# Single shot pingpong server responsiveness test. This should only be
# used to verify that a server present in %run hash is still functional
#
sub responsive_pingpong_server {
    my ($proto, $id, $verb, $ipv6) = @_;
    my $port;
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $protoip = $proto . ($ipvnum == 6? '6': '');

    if($proto =~ /^(?:ftp|imap|pop3|smtp)$/) {
        $port = protoport($protoip);
    }
    else {
        logmsg "Unsupported protocol $proto!!\n";
        return 0;
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port);
}

#######################################################################
# Single shot rtsp server responsiveness test. This should only be
# used to verify that a server present in %run hash is still functional
#
sub responsive_rtsp_server {
    my ($verb, $ipv6) = @_;
    my $proto = 'rtsp';
    my $port = protoport($proto);
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $port = protoport('rtsp6');
        $ip = $HOST6IP;
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port);
}

#######################################################################
# Single shot tftp server responsiveness test. This should only be
# used to verify that a server present in %run hash is still functional
#
sub responsive_tftp_server {
    my ($id, $verb, $ipv6) = @_;
    my $proto = 'tftp';
    my $port = protoport($proto);
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $port = protoport('tftp6');
        $ip = $HOST6IP;
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port);
}

#######################################################################
# Single shot non-stunnel HTTP TLS extensions capable server
# responsiveness test. This should only be used to verify that a
# server present in %run hash is still functional
#
sub responsive_httptls_server {
    my ($verb, $ipv6) = @_;
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $proto = "httptls";
    my $port = protoport($proto);
    my $ip = "$HOSTIP";
    my $idnum = 1;

    if ($ipvnum == 6) {
        $port = protoport("httptls6");
        $ip = "$HOST6IP";
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port);
}

#######################################################################
# startservers() starts all the named servers
#
# Returns: string with error reason or blank for success, and an integer:
#          0 for success
#          1 for an error starting the server
#          2 for not the first time getting an error starting the server
#          3 for a failure to stop a server in order to restart it
#          4 for an unsupported server type
#
sub startservers {
    my @what = @_;
    my ($pid, $pid2);
    my $serr;  # error while starting a server (as as the return enumerations)
    for(@what) {
        my (@whatlist) = split(/\s+/,$_);
        my $what = lc($whatlist[0]);
        $what =~ s/[^a-z0-9\/-]//g;

        my $certfile;
        if($what =~ /^(ftp|gopher|http|imap|pop3|smtp)s((\d*)(-ipv6|-unix|))$/) {
            $certfile = ($whatlist[1]) ? $whatlist[1] : 'stunnel.pem';
        }

        if(($what eq "pop3") ||
           ($what eq "ftp") ||
           ($what eq "imap") ||
           ($what eq "smtp")) {
            if($torture && $run{$what} &&
               !responsive_pingpong_server($what, "", $verbose)) {
                if(stopserver($what)) {
                    return ("failed stopping unresponsive ".uc($what)." server", 3);
                }
            }
            if(!$run{$what}) {
                ($serr, $pid, $pid2) = runpingpongserver($what, "", $verbose);
                if($pid <= 0) {
                    return ("failed starting ". uc($what) ." server", $serr);
                }
                logmsg sprintf("* pid $what => %d %d\n", $pid, $pid2) if($verbose);
                $run{$what}="$pid $pid2";
            }
        }
        elsif($what eq "ftp-ipv6") {
            if($torture && $run{'ftp-ipv6'} &&
               !responsive_pingpong_server("ftp", "", $verbose, "ipv6")) {
                if(stopserver('ftp-ipv6')) {
                    return ("failed stopping unresponsive FTP-IPv6 server", 3);
                }
            }
            if(!$run{'ftp-ipv6'}) {
                ($serr, $pid, $pid2) = runpingpongserver("ftp", "", $verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting FTP-IPv6 server", $serr);
                }
                logmsg sprintf("* pid ftp-ipv6 => %d %d\n", $pid,
                       $pid2) if($verbose);
                $run{'ftp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "gopher") {
            if($torture && $run{'gopher'} &&
               !responsive_http_server("gopher", $verbose, 0,
                                       protoport("gopher"))) {
                if(stopserver('gopher')) {
                    return ("failed stopping unresponsive GOPHER server", 3);
                }
            }
            if(!$run{'gopher'}) {
                ($serr, $pid, $pid2, $PORT{'gopher'}) =
                    runhttpserver("gopher", $verbose, 0);
                if($pid <= 0) {
                    return ("failed starting GOPHER server", $serr);
                }
                logmsg sprintf ("* pid gopher => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'gopher'}="$pid $pid2";
            }
        }
        elsif($what eq "gopher-ipv6") {
            if($torture && $run{'gopher-ipv6'} &&
               !responsive_http_server("gopher", $verbose, "ipv6",
                                       protoport("gopher"))) {
                if(stopserver('gopher-ipv6')) {
                    return ("failed stopping unresponsive GOPHER-IPv6 server", 3);
                }
            }
            if(!$run{'gopher-ipv6'}) {
                ($serr, $pid, $pid2, $PORT{"gopher6"}) =
                    runhttpserver("gopher", $verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting GOPHER-IPv6 server", $serr);
                }
                logmsg sprintf("* pid gopher-ipv6 => %d %d\n", $pid,
                               $pid2) if($verbose);
                $run{'gopher-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "http/3") {
            if(!$run{'http/3'}) {
                ($serr, $pid, $pid2, $PORT{"http3"}) = runhttp3server($verbose);
                if($pid <= 0) {
                    return ("failed starting HTTP/3 server", $serr);
                }
                logmsg sprintf ("* pid http/3 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http/3'}="$pid $pid2";
            }
        }
        elsif($what eq "http/2") {
            if(!$run{'http/2'}) {
                ($serr, $pid, $pid2, $PORT{"http2"}, $PORT{"http2tls"}) =
                    runhttp2server($verbose);
                if($pid <= 0) {
                    return ("failed starting HTTP/2 server", $serr);
                }
                logmsg sprintf ("* pid http/2 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http/2'}="$pid $pid2";
            }
        }
        elsif($what eq "http") {
            if($torture && $run{'http'} &&
               !responsive_http_server("http", $verbose, 0, protoport('http'))) {
                if(stopserver('http')) {
                    return ("failed stopping unresponsive HTTP server", 3);
                }
            }
            if(!$run{'http'}) {
                ($serr, $pid, $pid2, $PORT{'http'}) =
                    runhttpserver("http", $verbose, 0);
                if($pid <= 0) {
                    return ("failed starting HTTP server", $serr);
                }
                logmsg sprintf ("* pid http => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http'}="$pid $pid2";
            }
        }
        elsif($what eq "http-proxy") {
            if($torture && $run{'http-proxy'} &&
               !responsive_http_server("http", $verbose, "proxy",
                                       protoport("httpproxy"))) {
                if(stopserver('http-proxy')) {
                    return ("failed stopping unresponsive HTTP-proxy server", 3);
                }
            }
            if(!$run{'http-proxy'}) {
                ($serr, $pid, $pid2, $PORT{"httpproxy"}) =
                    runhttpserver("http", $verbose, "proxy");
                if($pid <= 0) {
                    return ("failed starting HTTP-proxy server", $serr);
                }
                logmsg sprintf ("* pid http-proxy => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http-proxy'}="$pid $pid2";
            }
        }
        elsif($what eq "http-ipv6") {
            if($torture && $run{'http-ipv6'} &&
               !responsive_http_server("http", $verbose, "ipv6",
                                       protoport("http6"))) {
                if(stopserver('http-ipv6')) {
                    return ("failed stopping unresponsive HTTP-IPv6 server", 3);
                }
            }
            if(!$run{'http-ipv6'}) {
                ($serr, $pid, $pid2, $PORT{"http6"}) =
                    runhttpserver("http", $verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting HTTP-IPv6 server", $serr);
                }
                logmsg sprintf("* pid http-ipv6 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "rtsp") {
            if($torture && $run{'rtsp'} &&
               !responsive_rtsp_server($verbose)) {
                if(stopserver('rtsp')) {
                    return ("failed stopping unresponsive RTSP server", 3);
                }
            }
            if(!$run{'rtsp'}) {
                ($serr, $pid, $pid2, $PORT{'rtsp'}) = runrtspserver($verbose);
                if($pid <= 0) {
                    return ("failed starting RTSP server", $serr);
                }
                logmsg sprintf("* pid rtsp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'rtsp'}="$pid $pid2";
            }
        }
        elsif($what eq "rtsp-ipv6") {
            if($torture && $run{'rtsp-ipv6'} &&
               !responsive_rtsp_server($verbose, "ipv6")) {
                if(stopserver('rtsp-ipv6')) {
                    return ("failed stopping unresponsive RTSP-IPv6 server", 3);
                }
            }
            if(!$run{'rtsp-ipv6'}) {
                ($serr, $pid, $pid2, $PORT{'rtsp6'}) = runrtspserver($verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting RTSP-IPv6 server", $serr);
                }
                logmsg sprintf("* pid rtsp-ipv6 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'rtsp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what =~ /^(ftp|imap|pop3|smtp)s$/) {
            my $cproto = $1;
            if(!$stunnel) {
                # we can't run ftps tests without stunnel
                return ("no stunnel", 4);
            }
            if($runcert{$what} && ($runcert{$what} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver($what)) {
                    return ("failed stopping $what server with different cert", 3);
                }
            }
            if($torture && $run{$cproto} &&
               !responsive_pingpong_server($cproto, "", $verbose)) {
                if(stopserver($cproto)) {
                    return ("failed stopping unresponsive $cproto server", 3);
                }
            }
            if(!$run{$cproto}) {
                ($serr, $pid, $pid2) = runpingpongserver($cproto, "", $verbose);
                if($pid <= 0) {
                    return ("failed starting $cproto server", $serr);
                }
                logmsg sprintf("* pid $cproto => %d %d\n", $pid, $pid2) if($verbose);
                $run{$cproto}="$pid $pid2";
            }
            if(!$run{$what}) {
                ($serr, $pid, $pid2, $PORT{$what}) =
                    runsecureserver($verbose, "", $certfile, $what,
                                    protoport($cproto));
                if($pid <= 0) {
                    return ("failed starting $what server (stunnel)", $serr);
                }
                logmsg sprintf("* pid $what => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{$what}="$pid $pid2";
            }
        }
        elsif($what eq "file") {
            # we support it but have no server!
        }
        elsif($what eq "https") {
            if(!$stunnel) {
                # we can't run https tests without stunnel
                return ("no stunnel", 4);
            }
            if($runcert{'https'} && ($runcert{'https'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('https')) {
                    return ("failed stopping HTTPS server with different cert", 3);
                }
            }
            if($torture && $run{'http'} &&
               !responsive_http_server("http", $verbose, 0,
                                       protoport('http'))) {
                if(stopserver('http')) {
                    return ("failed stopping unresponsive HTTP server", 3);
                }
            }
            if(!$run{'http'}) {
                ($serr, $pid, $pid2, $PORT{'http'}) =
                    runhttpserver("http", $verbose, 0);
                if($pid <= 0) {
                    return ("failed starting HTTP server", $serr);
                }
                logmsg sprintf("* pid http => %d %d\n", $pid, $pid2) if($verbose);
                $run{'http'}="$pid $pid2";
            }
            if(!$run{'https'}) {
                ($serr, $pid, $pid2, $PORT{'https'}) =
                    runhttpsserver($verbose, "https", "", $certfile);
                if($pid <= 0) {
                    return ("failed starting HTTPS server (stunnel)", $serr);
                }
                logmsg sprintf("* pid https => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'https'}="$pid $pid2";
            }
        }
        elsif($what eq "gophers") {
            if(!$stunnel) {
                # we can't run TLS tests without stunnel
                return ("no stunnel", 4);
            }
            if($runcert{'gophers'} && ($runcert{'gophers'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('gophers')) {
                    return ("failed stopping GOPHERS server with different cert", 3);
                }
            }
            if($torture && $run{'gopher'} &&
               !responsive_http_server("gopher", $verbose, 0,
                                       protoport('gopher'))) {
                if(stopserver('gopher')) {
                    return ("failed stopping unresponsive GOPHER server", 3);
                }
            }
            if(!$run{'gopher'}) {
                my $port;
                ($serr, $pid, $pid2, $port) =
                    runhttpserver("gopher", $verbose, 0);
                $PORT{'gopher'} = $port;
                if($pid <= 0) {
                    return ("failed starting GOPHER server", $serr);
                }
                logmsg sprintf("* pid gopher => %d %d\n", $pid, $pid2) if($verbose);
                logmsg "GOPHERPORT => $port\n" if($verbose);
                $run{'gopher'}="$pid $pid2";
            }
            if(!$run{'gophers'}) {
                my $port;
                ($serr, $pid, $pid2, $port) =
                    runhttpsserver($verbose, "gophers", "", $certfile);
                $PORT{'gophers'} = $port;
                if($pid <= 0) {
                    return ("failed starting GOPHERS server (stunnel)", $serr);
                }
                logmsg sprintf("* pid gophers => %d %d\n", $pid, $pid2)
                    if($verbose);
                logmsg "GOPHERSPORT => $port\n" if($verbose);
                $run{'gophers'}="$pid $pid2";
            }
        }
        elsif($what eq "https-proxy") {
            if(!$stunnel) {
                # we can't run https-proxy tests without stunnel
                return ("no stunnel", 4);
            }
            if($runcert{'https-proxy'} &&
               ($runcert{'https-proxy'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('https-proxy')) {
                    return ("failed stopping HTTPS-proxy with different cert", 3);
                }
            }

            # we front the http-proxy with stunnel so we need to make sure the
            # proxy runs as well
            my ($f, $e) = startservers("http-proxy");
            if($f) {
                return ($f, $e);
            }

            if(!$run{'https-proxy'}) {
                ($serr, $pid, $pid2, $PORT{"httpsproxy"}) =
                    runhttpsserver($verbose, "https", "proxy", $certfile);
                if($pid <= 0) {
                    return ("failed starting HTTPS-proxy (stunnel)", $serr);
                }
                logmsg sprintf("* pid https-proxy => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'https-proxy'}="$pid $pid2";
            }
        }
        elsif($what eq "httptls") {
            if(!$httptlssrv) {
                # for now, we can't run http TLS-EXT tests without gnutls-serv
                return ("no gnutls-serv (with SRP support)", 4);
            }
            if($torture && $run{'httptls'} &&
               !responsive_httptls_server($verbose, "IPv4")) {
                if(stopserver('httptls')) {
                    return ("failed stopping unresponsive HTTPTLS server", 3);
                }
            }
            if(!$run{'httptls'}) {
                ($serr, $pid, $pid2, $PORT{'httptls'}) =
                    runhttptlsserver($verbose, "IPv4");
                if($pid <= 0) {
                    return ("failed starting HTTPTLS server (gnutls-serv)", $serr);
                }
                logmsg sprintf("* pid httptls => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'httptls'}="$pid $pid2";
            }
        }
        elsif($what eq "httptls-ipv6") {
            if(!$httptlssrv) {
                # for now, we can't run http TLS-EXT tests without gnutls-serv
                return ("no gnutls-serv", 4);
            }
            if($torture && $run{'httptls-ipv6'} &&
               !responsive_httptls_server($verbose, "ipv6")) {
                if(stopserver('httptls-ipv6')) {
                    return ("failed stopping unresponsive HTTPTLS-IPv6 server", 3);
                }
            }
            if(!$run{'httptls-ipv6'}) {
                ($serr, $pid, $pid2, $PORT{"httptls6"}) =
                    runhttptlsserver($verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting HTTPTLS-IPv6 server (gnutls-serv)", $serr);
                }
                logmsg sprintf("* pid httptls-ipv6 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'httptls-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "tftp") {
            if($torture && $run{'tftp'} &&
               !responsive_tftp_server("", $verbose)) {
                if(stopserver('tftp')) {
                    return ("failed stopping unresponsive TFTP server", 3);
                }
            }
            if(!$run{'tftp'}) {
                ($serr, $pid, $pid2, $PORT{'tftp'}) =
                    runtftpserver("", $verbose);
                if($pid <= 0) {
                    return ("failed starting TFTP server", $serr);
                }
                logmsg sprintf("* pid tftp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp'}="$pid $pid2";
            }
        }
        elsif($what eq "tftp-ipv6") {
            if($torture && $run{'tftp-ipv6'} &&
               !responsive_tftp_server("", $verbose, "ipv6")) {
                if(stopserver('tftp-ipv6')) {
                    return ("failed stopping unresponsive TFTP-IPv6 server", 3);
                }
            }
            if(!$run{'tftp-ipv6'}) {
                ($serr, $pid, $pid2, $PORT{'tftp6'}) =
                    runtftpserver("", $verbose, "ipv6");
                if($pid <= 0) {
                    return ("failed starting TFTP-IPv6 server", $serr);
                }
                logmsg sprintf("* pid tftp-ipv6 => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "sftp" || $what eq "scp") {
            if(!$run{'ssh'}) {
                ($serr, $pid, $pid2, $PORT{'ssh'}) = runsshserver("", $verbose);
                if($pid <= 0) {
                    return ("failed starting SSH server", $serr);
                }
                logmsg sprintf("* pid ssh => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ssh'}="$pid $pid2";
            }
        }
        elsif($what eq "socks4" || $what eq "socks5" ) {
            if(!$run{'socks'}) {
                ($serr, $pid, $pid2, $PORT{"socks"}) = runsocksserver("", $verbose);
                if($pid <= 0) {
                    return ("failed starting socks server", $serr);
                }
                logmsg sprintf("* pid socks => %d %d\n", $pid, $pid2) if($verbose);
                $run{'socks'}="$pid $pid2";
            }
        }
        elsif($what eq "socks5unix") {
            if(!$run{'socks5unix'}) {
                ($serr, $pid, $pid2) = runsocksserver("2", $verbose, "", "unix");
                if($pid <= 0) {
                    return ("failed starting socks5unix server", $serr);
                }
                logmsg sprintf("* pid socks5unix => %d %d\n", $pid, $pid2) if($verbose);
                $run{'socks5unix'}="$pid $pid2";
            }
        }
        elsif($what eq "mqtt" ) {
            if(!$run{'mqtt'}) {
                ($serr, $pid, $pid2) = runmqttserver("", $verbose);
                if($pid <= 0) {
                    return ("failed starting mqtt server", $serr);
                }
                logmsg sprintf("* pid mqtt => %d %d\n", $pid, $pid2) if($verbose);
                $run{'mqtt'}="$pid $pid2";
            }
        }
        elsif($what eq "http-unix") {
            if($torture && $run{'http-unix'} &&
               !responsive_http_server("http", $verbose, "unix", $HTTPUNIXPATH)) {
                if(stopserver('http-unix')) {
                    return ("failed stopping unresponsive HTTP-unix server", 3);
                }
            }
            if(!$run{'http-unix'}) {
                my $unused;
                ($serr, $pid, $pid2, $unused) =
                    runhttpserver("http", $verbose, "unix", $HTTPUNIXPATH);
                if($pid <= 0) {
                    return ("failed starting HTTP-unix server", $serr);
                }
                logmsg sprintf("* pid http-unix => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http-unix'}="$pid $pid2";
            }
        }
        elsif($what eq "dict") {
            if(!$run{'dict'}) {
                ($serr, $pid, $pid2, $PORT{"dict"}) = rundictserver($verbose, "");
                if($pid <= 0) {
                    return ("failed starting DICT server", $serr);
                }
                logmsg sprintf ("* pid DICT => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'dict'}="$pid $pid2";
            }
        }
        elsif($what eq "smb") {
            if(!$run{'smb'}) {
                ($serr, $pid, $pid2, $PORT{"smb"}) = runsmbserver($verbose, "");
                if($pid <= 0) {
                    return ("failed starting SMB server", $serr);
                }
                logmsg sprintf ("* pid SMB => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'smb'}="$pid $pid2";
            }
        }
        elsif($what eq "telnet") {
            if(!$run{'telnet'}) {
                ($serr, $pid, $pid2, $PORT{"telnet"}) =
                    runnegtelnetserver($verbose, "");
                if($pid <= 0) {
                    return ("failed starting neg TELNET server", $serr);
                }
                logmsg sprintf ("* pid neg TELNET => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'telnet'}="$pid $pid2";
            }
        }
        elsif($what eq "none") {
            logmsg "* starts no server\n" if ($verbose);
        }
        else {
            warn "we don't support a server for $what";
            return ("no server for $what", 4);
        }
    }
    return ("", 0);
}

#######################################################################
# Stop all running test servers
#
sub stopservers {
    my $verb = $_[0];
    #
    # kill sockfilter processes for all pingpong servers
    #
    killallsockfilters("$LOGDIR/$PIDDIR", $verb);
    #
    # kill all server pids from %run hash clearing them
    #
    my $pidlist;
    foreach my $server (keys %run) {
        if($run{$server}) {
            if($verb) {
                my $prev = 0;
                my $pids = $run{$server};
                foreach my $pid (split(' ', $pids)) {
                    if($pid != $prev) {
                        logmsg sprintf("* kill pid for %s => %d\n",
                            $server, $pid);
                        $prev = $pid;
                    }
                }
            }
            $pidlist .= "$run{$server} ";
            $run{$server} = 0;
        }
        $runcert{$server} = 0 if($runcert{$server});
    }
    killpid($verb, $pidlist);
    #
    # cleanup all server pid files
    #
    my $result = 0;
    foreach my $server (keys %serverpidfile) {
        my $pidfile = $serverpidfile{$server};
        my $pid = processexists($pidfile);
        if($pid > 0) {
            if($err_unexpected) {
                logmsg "ERROR: ";
                $result = -1;
            }
            else {
                logmsg "Warning: ";
            }
            logmsg "$server server unexpectedly alive\n";
            killpid($verb, $pid);
        }
        unlink($pidfile) if(-f $pidfile);
    }

    return $result;
}


#######################################################################
# substitute the variable stuff into either a joined up file or
# a command, in either case passed by reference
#
sub subvariables {
    my ($thing, $testnum, $prefix) = @_;
    my $port;

    if(!$prefix) {
        $prefix = "%";
    }

    # test server ports
    # Substitutes variables like %HTTPPORT and %SMTP6PORT with the server ports
    foreach my $proto ('DICT',
                       'FTP', 'FTP6', 'FTPS',
                       'GOPHER', 'GOPHER6', 'GOPHERS',
                       'HTTP', 'HTTP6', 'HTTPS',
                       'HTTPSPROXY', 'HTTPTLS', 'HTTPTLS6',
                       'HTTP2', 'HTTP2TLS',
                       'HTTP3',
                       'IMAP', 'IMAP6', 'IMAPS',
                       'MQTT',
                       'NOLISTEN',
                       'POP3', 'POP36', 'POP3S',
                       'RTSP', 'RTSP6',
                       'SMB', 'SMBS',
                       'SMTP', 'SMTP6', 'SMTPS',
                       'SOCKS',
                       'SSH',
                       'TELNET',
                       'TFTP', 'TFTP6') {
        $port = protoport(lc $proto);
        $$thing =~ s/${prefix}(?:$proto)PORT/$port/g;
    }
    # Special case: for PROXYPORT substitution, use httpproxy.
    $port = protoport('httpproxy');
    $$thing =~ s/${prefix}PROXYPORT/$port/g;

    # server Unix domain socket paths
    $$thing =~ s/${prefix}HTTPUNIXPATH/$HTTPUNIXPATH/g;
    $$thing =~ s/${prefix}SOCKSUNIXPATH/$SOCKSUNIXPATH/g;

    # client IP addresses
    $$thing =~ s/${prefix}CLIENT6IP/$CLIENT6IP/g;
    $$thing =~ s/${prefix}CLIENTIP/$CLIENTIP/g;

    # server IP addresses
    $$thing =~ s/${prefix}HOST6IP/$HOST6IP/g;
    $$thing =~ s/${prefix}HOSTIP/$HOSTIP/g;

    # misc
    $$thing =~ s/${prefix}CURL/$CURL/g;
    $$thing =~ s/${prefix}LOGDIR/$LOGDIR/g;
    $$thing =~ s/${prefix}PWD/$pwd/g;
    $$thing =~ s/${prefix}POSIX_PWD/$posix_pwd/g;
    $$thing =~ s/${prefix}VERSION/$CURLVERSION/g;
    $$thing =~ s/${prefix}TESTNUMBER/$testnum/g;

    my $file_pwd = $pwd;
    if($file_pwd !~ /^\//) {
        $file_pwd = "/$file_pwd";
    }
    my $ssh_pwd = $posix_pwd;
    # this only works after the SSH server has been started
    # TODO: call sshversioninfo early and store $sshdid so this substitution
    # always works
    if ($sshdid && $sshdid =~ /OpenSSH-Windows/) {
        $ssh_pwd = $file_pwd;
    }

    $$thing =~ s/${prefix}FILE_PWD/$file_pwd/g;
    $$thing =~ s/${prefix}SSH_PWD/$ssh_pwd/g;
    $$thing =~ s/${prefix}SRCDIR/$srcdir/g;
    $$thing =~ s/${prefix}USER/$USER/g;

    $$thing =~ s/${prefix}SSHSRVMD5/$SSHSRVMD5/g;
    $$thing =~ s/${prefix}SSHSRVSHA256/$SSHSRVSHA256/g;

    # The purpose of FTPTIME2 and FTPTIME3 is to provide times that can be
    # used for time-out tests and that would work on most hosts as these
    # adjust for the startup/check time for this particular host. We needed to
    # do this to make the test suite run better on very slow hosts.
    my $ftp2 = $ftpchecktime * 8;
    my $ftp3 = $ftpchecktime * 12;

    $$thing =~ s/${prefix}FTPTIME2/$ftp2/g;
    $$thing =~ s/${prefix}FTPTIME3/$ftp3/g;

    # HTTP2
    $$thing =~ s/${prefix}H2CVER/$h2cver/g;
}


1;
