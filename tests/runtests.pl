#!/usr/bin/env perl
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

# Experimental hooks are available to run tests remotely on machines that
# are able to run curl but are unable to run the test harness.
# The following sections need to be modified:
#
#  $HOSTIP, $HOST6IP - Set to the address of the host running the test suite
#  $CLIENTIP, $CLIENT6IP - Set to the address of the host running curl
#  runclient, runclientoutput - Modify to copy all the files in the log/
#    directory to the system running curl, run the given command remotely
#    and save the return code or returned stdout (respectively), then
#    copy all the files from the remote system's log/ directory back to
#    the host running the test suite.  This can be done a few ways, such
#    as using scp & ssh, rsync & telnet, or using a NFS shared directory
#    and ssh.
#
# 'make && make test' needs to be done on both machines before making the
# above changes and running runtests.pl manually.  In the shared NFS case,
# the contents of the tests/server/ directory must be from the host
# running the test suite, while the rest must be from the host running curl.
#
# Note that even with these changes a number of tests will still fail (mainly
# to do with cookies, those that set environment variables, or those that
# do more than touch the file system in a <precheck> or <postcheck>
# section). These can be added to the $TESTCASES line below,
# e.g. $TESTCASES="!8 !31 !63 !cookies..."
#
# Finally, to properly support -g and -n, checktestcmd needs to change
# to check the remote system's PATH, and the places in the code where
# the curl binary is read directly to determine its type also need to be
# fixed. As long as the -g option is never given, and the -n is always
# given, this won't be a problem.


# These should be the only variables that might be needed to get edited:

BEGIN {
    # Define srcdir to the location of the tests source directory. This is
    # usually set by the Makefile, but for out-of-tree builds with direct
    # invocation of runtests.pl, it may not be set.
    if(!defined $ENV{'srcdir'}) {
        use File::Basename;
        $ENV{'srcdir'} = dirname(__FILE__);
    }
    push(@INC, $ENV{'srcdir'});
    # run time statistics needs Time::HiRes
    eval {
        no warnings "all";
        require Time::HiRes;
        import  Time::HiRes qw( time );
    }
}

use strict;
# Promote all warnings to fatal
use warnings FATAL => 'all';
use Cwd;
use Digest::MD5 qw(md5);
use MIME::Base64;

# Subs imported from serverhelp module
use serverhelp qw(
    serverfactors
    servername_id
    servername_str
    servername_canon
    server_pidfilename
    server_portfilename
    server_logfilename
    );

# Variables and subs imported from sshhelp module
use sshhelp qw(
    $sshdexe
    $sshexe
    $sftpexe
    $sshconfig
    $sftpconfig
    $sshdlog
    $sshlog
    $sftplog
    $sftpcmds
    display_sshdconfig
    display_sshconfig
    display_sftpconfig
    display_sshdlog
    display_sshlog
    display_sftplog
    exe_ext
    find_sshd
    find_ssh
    find_sftp
    find_httptlssrv
    sshversioninfo
    );

use pathhelp;

require "getpart.pm"; # array functions
require "valgrind.pm"; # valgrind report parser
require "ftp.pm";
require "azure.pm";
require "appveyor.pm";

my $HOSTIP="127.0.0.1";   # address on which the test server listens
my $HOST6IP="[::1]";      # address on which the test server listens
my $CLIENTIP="127.0.0.1"; # address which curl uses for incoming connections
my $CLIENT6IP="[::1]";    # address which curl uses for incoming connections

my %PORT = (nolisten => 47); # port we use for a local non-listening service
my $HTTPUNIXPATH;        # HTTP server Unix domain socket path
my $SOCKSUNIXPATH;       # socks server Unix domain socket path

my $use_external_proxy = 0;
my $proxy_address;
my %custom_skip_reasons;

my $SSHSRVMD5 = "[uninitialized]"; # MD5 of ssh server public key
my $SSHSRVSHA256 = "[uninitialized]"; # SHA256 of ssh server public key
my $VERSION="";          # curl's reported version number

my $srcdir = $ENV{'srcdir'} || '.';
my $CURL="../src/curl".exe_ext('TOOL'); # what curl binary to run on the tests
my $VCURL=$CURL;   # what curl binary to use to verify the servers with
                   # VCURL is handy to set to the system one when the one you
                   # just built hangs or crashes and thus prevent verification
my $ACURL=$VCURL;  # what curl binary to use to talk to APIs (relevant for CI)
                   # ACURL is handy to set to the system one for reliability
my $DBGCURL=$CURL; #"../src/.libs/curl";  # alternative for debugging
my $LOGDIR="log";
my $TESTDIR="$srcdir/data";
my $LIBDIR="./libtest";
my $UNITDIR="./unit";
# TODO: change this to use server_inputfilename()
my $SERVERIN="$LOGDIR/server.input"; # what curl sent the server
my $SERVER2IN="$LOGDIR/server2.input"; # what curl sent the second server
my $PROXYIN="$LOGDIR/proxy.input"; # what curl sent the proxy
my $SOCKSIN="$LOGDIR/socksd-request.log"; # what curl sent to the SOCKS proxy
my $CURLLOG="commands.log"; # all command lines run
my $FTPDCMD="$LOGDIR/ftpserver.cmd"; # copy server instructions here
my $SERVERLOGS_LOCK="$LOGDIR/serverlogs.lock"; # server logs advisor read lock
my $CURLCONFIG="../curl-config"; # curl-config from current build

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

# invoke perl like this:
my $perl="perl -I$srcdir";
my $server_response_maxtime=13;

my $debug_build=0;          # built debug enabled (--enable-debug)
my $has_memory_tracking=0;  # built with memory tracking (--enable-curldebug)
my $libtool;
my $repeat = 0;

# name of the file that the memory debugging creates:
my $memdump="$LOGDIR/memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="$perl $srcdir/memanalyze.pl";

my $pwd = getcwd();          # current working directory
my $posix_pwd = $pwd;

my $start;
my $ftpchecktime=1; # time it took to verify our test FTP server
my $scrambleorder;
my $stunnel = checkcmd("stunnel4") || checkcmd("tstunnel") || checkcmd("stunnel");
my $valgrind = checktestcmd("valgrind");
my $valgrind_logfile="--logfile";
my $valgrind_tool;
my $gdb = checktestcmd("gdb");
my $httptlssrv = find_httptlssrv();

my $uname_release = `uname -r`;
my $is_wsl = $uname_release =~ /Microsoft$/;

my $has_ssl;        # set if libcurl is built with SSL support
my $has_largefile;  # set if libcurl is built with large file support
my $has_idn;        # set if libcurl is built with IDN support
my $http_ipv6;      # set if HTTP server has IPv6 support
my $http_unix;      # set if HTTP server has Unix sockets support
my $ftp_ipv6;       # set if FTP server has IPv6 support
my $tftp_ipv6;      # set if TFTP server has IPv6 support
my $gopher_ipv6;    # set if Gopher server has IPv6 support
my $has_ipv6;       # set if libcurl is built with IPv6 support
my $has_unix;       # set if libcurl is built with Unix sockets support
my $has_libz;       # set if libcurl is built with libz support
my $has_brotli;     # set if libcurl is built with brotli support
my $has_zstd;       # set if libcurl is built with zstd support
my $has_getrlimit;  # set if system has getrlimit()
my $has_ntlm;       # set if libcurl is built with NTLM support
my $has_ntlm_wb;    # set if libcurl is built with NTLM delegation to winbind
my $has_sspi;       # set if libcurl is built with Windows SSPI
my $has_gssapi;     # set if libcurl is built with a GSS-API library
my $has_kerberos;   # set if libcurl is built with Kerberos support
my $has_spnego;     # set if libcurl is built with SPNEGO support
my $has_charconv;   # set if libcurl is built with CharConv support
my $has_tls_srp;    # set if libcurl is built with TLS-SRP support
my $has_http2;      # set if libcurl is built with HTTP2 support
my $has_h2c;        # set if libcurl is built with h2c support
my $has_http3;      # set if libcurl is built with HTTP3 support
my $has_httpsproxy; # set if libcurl is built with HTTPS-proxy support
my $has_crypto;     # set if libcurl is built with cryptographic support
my $has_cares;      # set if built with c-ares
my $has_threadedres;# set if built with threaded resolver
my $has_psl;        # set if libcurl is built with PSL support
my $has_altsvc;     # set if libcurl is built with alt-svc support
my $has_hsts;       # set if libcurl is built with HSTS support
my $has_ldpreload;  # set if built for systems supporting LD_PRELOAD
my $has_multissl;   # set if build with MultiSSL support
my $has_manual;     # set if built with built-in manual
my $has_win32;      # set if built for Windows
my $has_mingw;      # set if built with MinGW (as opposed to MinGW-w64)
my $has_hyper = 0;  # set if built with Hyper
my $has_libssh2;    # set if built with libssh2
my $has_libssh;     # set if built with libssh
my $has_oldlibssh;  # set if built with libssh < 0.9.4
my $has_wolfssh;    # set if built with wolfssh
my $has_unicode;    # set if libcurl is built with Unicode support
my $has_threadsafe; # set if libcurl is built with thread-safety support

# this version is decided by the particular nghttp2 library that is being used
my $h2cver = "h2c";

my $has_rustls;     # built with rustls
my $has_openssl;    # built with a lib using an OpenSSL-like API
my $has_gnutls;     # built with GnuTLS
my $has_nss;        # built with NSS
my $has_wolfssl;    # built with wolfSSL
my $has_bearssl;    # built with BearSSL
my $has_schannel;   # built with Schannel
my $has_sectransp;  # built with Secure Transport
my $has_boringssl;  # built with BoringSSL
my $has_libressl;   # built with libressl
my $has_mbedtls;    # built with mbedTLS

my $has_sslpinning; # built with a TLS backend that supports pinning

my $has_shared = "unknown";  # built shared

my $resolver;       # name of the resolver backend (for human presentation)

my $has_textaware;  # set if running on a system that has a text mode concept
                    # on files. Windows for example
my @protocols;   # array of lowercase supported protocol servers

my $skipped=0;  # number of tests skipped; reported in main loop
my %skipped;    # skipped{reason}=counter, reasons for skip
my @teststat;   # teststat[testnum]=reason, reasons for skip
my %disabled_keywords;  # key words of tests to skip
my %ignored_keywords;   # key words of tests to ignore results
my %enabled_keywords;   # key words of tests to run
my %disabled;           # disabled test cases
my %ignored;            # ignored results of test cases
my $sshdid;      # for socks server, ssh daemon version id
my $sshdvernum;  # for socks server, ssh daemon version number
my $sshdverstr;  # for socks server, ssh daemon version string
my $sshderror;   # for socks server, ssh daemon version error

my $defserverlogslocktimeout = 2; # timeout to await server logs lock removal
my $defpostcommanddelay = 0; # delay between command and postcheck sections

my $timestats;   # time stamping and stats generation
my $fullstats;   # show time stats for every single test
my %timeprepini; # timestamp for each test preparation start
my %timesrvrini; # timestamp for each test required servers verification start
my %timesrvrend; # timestamp for each test required servers verification end
my %timetoolini; # timestamp for each test command run starting
my %timetoolend; # timestamp for each test command run stopping
my %timesrvrlog; # timestamp for each test server logs lock removal
my %timevrfyend; # timestamp for each test result verification end

my $testnumcheck; # test number, set in singletest sub.
my %oldenv;
my %feature;      # array of enabled features
my %keywords;     # array of keywords from the test spec

#######################################################################
# variables that command line options may set
#

my $short;
my $automakestyle;
my $verbose;
my $debugprotocol;
my $no_debuginfod;
my $anyway;
my $gdbthis;      # run test case with gdb debugger
my $gdbxwin;      # use windowed gdb when using gdb
my $keepoutfiles; # keep stdout and stderr files after tests
my $clearlocks;   # force removal of files by killing locking processes
my $listonly;     # only list the tests
my $postmortem;   # display detailed info about failed tests
my $err_unexpected; # error instead of warning on server unexpectedly alive
my $run_event_based; # run curl with --test-event to test the event API
my $run_disabeled; # run the specific tests even if listed in DISABLED

my %run;          # running server
my %doesntrun;    # servers that don't work, identified by pidfile
my %serverpidfile;# all server pid file names, identified by server id
my %serverportfile;# all server port file names, identified by server id
my %runcert;      # cert file currently in use by an ssl running server

# torture test variables
my $torture;
my $tortnum;
my $tortalloc;
my $shallow;
my $randseed = 0;

# Azure Pipelines specific variables
my $AZURE_RUN_ID = 0;
my $AZURE_RESULT_ID = 0;

#######################################################################
# logmsg is our general message logging subroutine.
#
sub logmsg {
    for(@_) {
        my $line = $_;
        if ($is_wsl) {
            # use \r\n for WSL shell
            $line =~ s/\r?\n$/\r\n/g;
        }
        print "$line";
    }
}

# get the name of the current user
my $USER = $ENV{USER};          # Linux
if (!$USER) {
    $USER = $ENV{USERNAME};     # Windows
    if (!$USER) {
        $USER = $ENV{LOGNAME};  # Some Unix (I think)
    }
}

# enable memory debugging if curl is compiled with it
$ENV{'CURL_MEMDEBUG'} = $memdump;
$ENV{'CURL_ENTROPY'}="12345678";
$ENV{'CURL_FORCETIME'}=1; # for debug NTLM magic
$ENV{'CURL_GLOBAL_INIT'}=1; # debug curl_global_init/cleanup use
$ENV{'HOME'}=$pwd;
$ENV{'CURL_HOME'}=$ENV{'HOME'};
$ENV{'XDG_CONFIG_HOME'}=$ENV{'HOME'};
$ENV{'COLUMNS'}=79; # screen width!

sub catch_zap {
    my $signame = shift;
    logmsg "runtests.pl received SIG$signame, exiting\n";
    stopservers($verbose);
    die "Somebody sent me a SIG$signame";
}
$SIG{INT} = \&catch_zap;
$SIG{TERM} = \&catch_zap;

##########################################################################
# Clear all possible '*_proxy' environment variables for various protocols
# to prevent them to interfere with our testing!

my $protocol;
foreach $protocol (('ftp', 'http', 'ftps', 'https', 'no', 'all')) {
    my $proxy = "${protocol}_proxy";
    # clear lowercase version
    delete $ENV{$proxy} if($ENV{$proxy});
    # clear uppercase version
    delete $ENV{uc($proxy)} if($ENV{uc($proxy)});
}

# make sure we don't get affected by other variables that control our
# behavior

delete $ENV{'SSL_CERT_DIR'} if($ENV{'SSL_CERT_DIR'});
delete $ENV{'SSL_CERT_PATH'} if($ENV{'SSL_CERT_PATH'});
delete $ENV{'CURL_CA_BUNDLE'} if($ENV{'CURL_CA_BUNDLE'});

# provide defaults from our config file for ENV vars not explicitly
# set by the caller
if (open(my $fd, "< config")) {
    while(my $line = <$fd>) {
        next if ($line =~ /^#/);
        chomp $line;
        my ($name, $val) = split(/\s*:\s*/, $line, 2);
        $ENV{$name} = $val if(!$ENV{$name});
    }
    close($fd);
}

# Check if we have nghttpx available and if it talks http/3
my $nghttpx_h3 = 0;
if (!$ENV{"NGHTTPX"}) {
    $ENV{"NGHTTPX"} = checktestcmd("nghttpx");
}
if ($ENV{"NGHTTPX"}) {
    my $nghttpx_version=join(' ', runclientoutput("$ENV{'NGHTTPX'} -v"));
    $nghttpx_h3 = $nghttpx_version =~ /nghttp3\//;
    chomp $nghttpx_h3;
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
          my $pidf = server_pidfilename("$proto$ssl", $ipvnum, $idnum);
          $serverpidfile{$serv} = $pidf;
          my $portf = server_portfilename("$proto$ssl", $ipvnum, $idnum);
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
        my $pidf = server_pidfilename($proto, $ipvnum, $idnum);
        $serverpidfile{$serv} = $pidf;
        my $portf = server_portfilename($proto, $ipvnum, $idnum);
        $serverportfile{$serv} = $portf;
      }
    }
  }
  for my $proto (('http', 'imap', 'pop3', 'smtp', 'http/2', 'http/3')) {
    for my $ssl (('', 's')) {
      my $serv = servername_id("$proto$ssl", "unix", 1);
      my $pidf = server_pidfilename("$proto$ssl", "unix", 1);
      $serverpidfile{$serv} = $pidf;
      my $portf = server_portfilename("$proto$ssl", "unix", 1);
      $serverportfile{$serv} = $portf;
    }
  }
}

#######################################################################
# Check if a given child process has just died. Reaps it if so.
#
sub checkdied {
    use POSIX ":sys_wait_h";
    my $pid = $_[0];
    if((not defined $pid) || $pid <= 0) {
        return 0;
    }
    my $rc = pidwait($pid, &WNOHANG);
    return ($rc == $pid)?1:0;
}

#######################################################################
# Start a new thread/process and run the given command line in there.
# Return the pids (yes plural) of the new child process to the parent.
#
sub startnew {
    my ($cmd, $pidfile, $timeout, $fake)=@_;

    logmsg "startnew: $cmd\n" if ($verbose);

    my $child = fork();
    my $pid2 = 0;

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
    if ($fake) {
        if(open(OUT, ">$pidfile")) {
            print OUT $child . "\n";
            close(OUT);
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

    my $count = $timeout;
    while($count--) {
        if(-f $pidfile && -s $pidfile && open(PID, "<$pidfile")) {
            $pid2 = 0 + <PID>;
            close(PID);
            if(($pid2 > 0) && pidexists($pid2)) {
                # if $pid2 is valid, then make sure this pid is alive, as
                # otherwise it is just likely to be the _previous_ pidfile or
                # similar!
                last;
            }
            # invalidate $pid2 if not actually alive
            $pid2 = 0;
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
# Check for a command in the PATH of the test server.
#
sub checkcmd {
    my ($cmd)=@_;
    my @paths=(split(":", $ENV{'PATH'}), "/usr/sbin", "/usr/local/sbin",
               "/sbin", "/usr/bin", "/usr/local/bin",
               "$LIBDIR/.libs", "$LIBDIR");
    for(@paths) {
        if( -x "$_/$cmd" && ! -d "$_/$cmd") {
            # executable bit but not a directory!
            return "$_/$cmd";
        }
    }
}

#######################################################################
# Get the list of tests that the tests/data/Makefile.am knows about!
#
my $disttests = "";
sub get_disttests {
    # If a non-default $TESTDIR is being used there may not be any
    # Makefile.inc in which case there's nothing to do.
    open(D, "<$TESTDIR/Makefile.inc") or return;
    while(<D>) {
        chomp $_;
        if(($_ =~ /^#/) ||($_ !~ /test/)) {
            next;
        }
        $disttests .= $_;
    }
    close(D);
}

#######################################################################
# Check for a command in the PATH of the machine running curl.
#
sub checktestcmd {
    my ($cmd)=@_;
    return checkcmd($cmd);
}

#######################################################################
# Run the application under test and return its return code
#
sub runclient {
    my ($cmd)=@_;
    my $ret = system($cmd);
    print "CMD ($ret): $cmd\n" if($verbose && !$torture);
    return $ret;

# This is one way to test curl on a remote machine
#    my $out = system("ssh $CLIENTIP cd \'$pwd\' \\; \'$cmd\'");
#    sleep 2;    # time to allow the NFS server to be updated
#    return $out;
}

#######################################################################
# Run the application under test and return its stdout
#
sub runclientoutput {
    my ($cmd)=@_;
    return `$cmd 2>/dev/null`;

# This is one way to test curl on a remote machine
#    my @out = `ssh $CLIENTIP cd \'$pwd\' \\; \'$cmd\'`;
#    sleep 2;    # time to allow the NFS server to be updated
#    return @out;
 }

#######################################################################
# Memory allocation test and failure torture testing.
#
sub torture {
    my ($testcmd, $testnum, $gdbline) = @_;

    # remove memdump first to be sure we get a new nice and clean one
    unlink($memdump);

    # First get URL from test server, ignore the output/result
    runclient($testcmd);

    logmsg " CMD: $testcmd\n" if($verbose);

    # memanalyze -v is our friend, get the number of allocations made
    my $count=0;
    my @out = `$memanalyze -v $memdump`;
    for(@out) {
        if(/^Operations: (\d+)/) {
            $count = $1;
            last;
        }
    }
    if(!$count) {
        logmsg " found no functions to make fail\n";
        return 0;
    }

    my @ttests = (1 .. $count);
    if($shallow && ($shallow < $count)) {
        my $discard = scalar(@ttests) - $shallow;
        my $percent = sprintf("%.2f%%", $shallow * 100 / scalar(@ttests));
        logmsg " $count functions found, but only fail $shallow ($percent)\n";
        while($discard) {
            my $rm;
            do {
                # find a test to discard
                $rm = rand(scalar(@ttests));
            } while(!$ttests[$rm]);
            $ttests[$rm] = undef;
            $discard--;
        }
    }
    else {
        logmsg " $count functions to make fail\n";
    }

    for (@ttests) {
        my $limit = $_;
        my $fail;
        my $dumped_core;

        if(!defined($limit)) {
            # --shallow can undefine them
            next;
        }
        if($tortalloc && ($tortalloc != $limit)) {
            next;
        }

        if($verbose) {
            my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
                localtime(time());
            my $now = sprintf("%02d:%02d:%02d ", $hour, $min, $sec);
            logmsg "Fail function no: $limit at $now\r";
        }

        # make the memory allocation function number $limit return failure
        $ENV{'CURL_MEMLIMIT'} = $limit;

        # remove memdump first to be sure we get a new nice and clean one
        unlink($memdump);

        my $cmd = $testcmd;
        if($valgrind && !$gdbthis) {
            my @valgrindoption = getpart("verify", "valgrind");
            if((!@valgrindoption) || ($valgrindoption[0] !~ /disable/)) {
                my $valgrindcmd = "$valgrind ";
                $valgrindcmd .= "$valgrind_tool " if($valgrind_tool);
                $valgrindcmd .= "--quiet --leak-check=yes ";
                $valgrindcmd .= "--suppressions=$srcdir/valgrind.supp ";
                # $valgrindcmd .= "--gen-suppressions=all ";
                $valgrindcmd .= "--num-callers=16 ";
                $valgrindcmd .= "${valgrind_logfile}=$LOGDIR/valgrind$testnum";
                $cmd = "$valgrindcmd $testcmd";
            }
        }
        logmsg "*** Function number $limit is now set to fail ***\n" if($gdbthis);

        my $ret = 0;
        if($gdbthis) {
            runclient($gdbline);
        }
        else {
            $ret = runclient($cmd);
        }
        #logmsg "$_ Returned " . ($ret >> 8) . "\n";

        # Now clear the variable again
        delete $ENV{'CURL_MEMLIMIT'} if($ENV{'CURL_MEMLIMIT'});

        if(-r "core") {
            # there's core file present now!
            logmsg " core dumped\n";
            $dumped_core = 1;
            $fail = 2;
        }

        if($valgrind) {
            my @e = valgrindparse("$LOGDIR/valgrind$testnum");
            if(@e && $e[0]) {
                if($automakestyle) {
                    logmsg "FAIL: torture $testnum - valgrind\n";
                }
                else {
                    logmsg " valgrind ERROR ";
                    logmsg @e;
                }
                $fail = 1;
            }
        }

        # verify that it returns a proper error code, doesn't leak memory
        # and doesn't core dump
        if(($ret & 255) || ($ret >> 8) >= 128) {
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
            logmsg " Failed on function number $limit in test.\n",
            " invoke with \"-t$limit\" to repeat this single case.\n";
            stopservers($verbose);
            return 1;
        }
    }

    logmsg "torture OK\n";
    return 0;
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
        killsockfilters($proto, $ipvnum, $idnum, $verbose);
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
    my $pid = 0;
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
    if($use_external_proxy) {
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
        if(open(FILE, "<$verifylog")) {
            while(my $string = <FILE>) {
                logmsg "RUN: $string" if($string !~ /^([ \t]*)$/);
            }
            close(FILE);
        }
    }

    my $data;
    if(open(FILE, "<$verifyout")) {
        while(my $string = <FILE>) {
            $data = $string;
            last; # only want first line
        }
        close(FILE);
    }

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
    my $pid = 0;
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
    if($use_external_proxy) {
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
    my $pid = 0;

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
    if($use_external_proxy) {
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
        if(open(FILE, "<$verifylog")) {
            while(my $string = <FILE>) {
                logmsg "RUN: $string" if($string !~ /^([ \t]*)$/);
            }
            close(FILE);
        }
    }

    my $data;
    if(open(FILE, "<$verifyout")) {
        while(my $string = <FILE>) {
            $data = $string;
            last; # only want first line
        }
        close(FILE);
    }

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
# actually alive.
#
sub verifyssh {
    my ($proto, $ipvnum, $idnum, $ip, $port) = @_;
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $pidfile = server_pidfilename($proto, $ipvnum, $idnum);
    my $pid = 0;
    if(open(FILE, "<$pidfile")) {
        $pid=0+<FILE>;
        close(FILE);
    }
    if($pid > 0) {
        # if we have a pid it is actually our ssh server,
        # since runsshserver() unlinks previous pidfile
        if(!pidexists($pid)) {
            logmsg "RUN: SSH server has died after starting up\n";
            checkdied($pid);
            unlink($pidfile);
            $pid = -1;
        }
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
    my $cmd = "\"$sftp\" -b $sftpcmds -F $sftpconfig -S \"$ssh\" $ip > $sftplog 2>&1";
    my $res = runclient($cmd);
    # Search for pwd command response in log file
    if(open(SFTPLOGFILE, "<$sftplog")) {
        while(<SFTPLOGFILE>) {
            if(/^Remote working directory: /) {
                $verified = 1;
                last;
            }
        }
        close(SFTPLOGFILE);
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
    my $pidfile = server_pidfilename($proto, $ipvnum, $idnum);
    my $pid = 0;

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
    if($use_external_proxy) {
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
        if(open(FILE, "<$verifylog")) {
            while(my $string = <FILE>) {
                logmsg "RUN: $string" if($string !~ /^([ \t]*)$/);
            }
            close(FILE);
        }
    }

    my $data;
    if(open(FILE, "<$verifyout")) {
        while(my $string = <FILE>) {
            $data .= $string;
        }
        close(FILE);
    }

    if($data && ($data =~ /(GNUTLS|GnuTLS)/) && open(FILE, "<$pidfile")) {
        $pid=0+<FILE>;
        close(FILE);
        if($pid > 0) {
            # if we have a pid it is actually our httptls server,
            # since runhttptlsserver() unlinks previous pidfile
            if(!pidexists($pid)) {
                logmsg "RUN: $server server has died after starting up\n";
                checkdied($pid);
                unlink($pidfile);
                $pid = -1;
            }
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
    my $server = servername_id($proto, $ipvnum, $idnum);
    my $pidfile = server_pidfilename($proto, $ipvnum, $idnum);
    my $pid = 0;
    if(open(FILE, "<$pidfile")) {
        $pid=0+<FILE>;
        close(FILE);
    }
    if($pid > 0) {
        # if we have a pid it is actually our socks server,
        # since runsocksserver() unlinks previous pidfile
        if(!pidexists($pid)) {
            logmsg "RUN: SOCKS server has died after starting up\n";
            checkdied($pid);
            unlink($pidfile);
            $pid = -1;
        }
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
    my $pid = 0;
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
    $ftpchecktime = $took>=1?$took:1; # make sure it never is below 1

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
    my $pid = 0;
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
# start the http2 server
#
sub runhttp2server {
    my ($verbose) = @_;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";
    my $proto="http/2";
    my $ipvnum = 4;
    my $idnum = 0;
    my $exe = "$perl $srcdir/http2-server.pl";
    my $verbose_flag = "--verbose ";

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--nghttpx \"$ENV{'NGHTTPX'}\" ";
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--connect $HOSTIP:" . protoport("http") . " ";
    $flags .= $verbose_flag if($debugprotocol);

    my ($http2pid, $pid2);
    my $port = 23113;
    my $port2 = 23114;
    for(1 .. 10) {
        $port += int(rand(900));
        $port2 += int(rand(900));
        my $aflags = "--port $port --port2 $port2 $flags";

        my $cmd = "$exe $aflags";
        ($http2pid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($http2pid <= 0 || !pidexists($http2pid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            $doesntrun{$pidfile} = 1;
            $http2pid = $pid2 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $http2pid ".
                   "http-port $port https-port $port2 ".
                   "backend $HOSTIP:" . protoport("http") . "\n";
        }
        last;
    }

    logmsg "RUN: failed to start the $srvrname server\n" if(!$http2pid);

    return ($http2pid, $pid2, $port, $port2);
}

#######################################################################
# start the http3 server
#
sub runhttp3server {
    my ($verbose, $cert) = @_;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";
    my $proto="http/3";
    my $ipvnum = 4;
    my $idnum = 0;
    my $exe = "$perl $srcdir/http3-server.pl";
    my $verbose_flag = "--verbose ";

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--nghttpx \"$ENV{'NGHTTPX'}\" ";
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--connect $HOSTIP:" . protoport("http") . " ";
    $flags .= "--cert \"$cert\" " if($cert);
    $flags .= $verbose_flag if($debugprotocol);

    my ($http3pid, $pid3);
    my $port = 24113;
    for(1 .. 10) {
        $port += int(rand(900));
        my $aflags = "--port $port $flags";

        my $cmd = "$exe $aflags";
        ($http3pid, $pid3) = startnew($cmd, $pidfile, 15, 0);

        if($http3pid <= 0 || !pidexists($http3pid)) {
            # it is NOT alive
            stopserver($server, "$pid3");
            $doesntrun{$pidfile} = 1;
            $http3pid = $pid3 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $http3pid port $port\n";
        }
        last;
    }

    logmsg "RUN: failed to start the $srvrname server\n" if(!$http3pid);

    return ($http3pid, $pid3, $port);
}

#######################################################################
# start the http server
#
sub runhttpserver {
    my ($proto, $verbose, $alt, $port_or_path) = @_;
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";
    my $exe = "$perl $srcdir/http-server.pl";
    my $verbose_flag = "--verbose ";

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

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--gopher " if($proto eq "gopher");
    $flags .= "--connect $HOSTIP " if($alt eq "proxy");
    $flags .= $verbose_flag if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--portfile $portfile ";
    $flags .= "--id $idnum " if($idnum > 1);
    if($ipvnum eq "unix") {
        $flags .= "--unix-socket '$port_or_path' ";
    } else {
        $flags .= "--ipv$ipvnum --port 0 ";
    }
    $flags .= "--srcdir \"$TESTDIR/..\"";

    my $cmd = "$exe $flags";
    my ($httppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($httppid <= 0 || !pidexists($httppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
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
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }
    $pid2 = $pid3;

    if($verbose) {
        logmsg "RUN: $srvrname server is on PID $httppid port $port_or_path\n";
    }

    return ($httppid, $pid2, $port);
}

#######################################################################
# start the https stunnel based server
#
sub runhttpsserver {
    my ($verbose, $proto, $proxy, $certfile) = @_;
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($proxy eq "proxy") {
        # the https-proxy runs as https2
        $idnum = 2;
    }

    if(!$stunnel) {
        return (0, 0, 0);
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $certfile = 'stunnel.pem' unless($certfile);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
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

    my $pid2;
    my $httpspid;
    my $port = 24512; # start attempt
    for (1 .. 10) {
        $port += int(rand(600));
        my $options = "$flags --accept $port";

        my $cmd = "$perl $srcdir/secureserver.pl $options";
        ($httpspid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($httpspid <= 0 || !pidexists($httpspid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $httpspid = $pid2 = 0;
            next;
        }
        # we have a server!
        if($verbose) {
            logmsg "RUN: $srvrname server is PID $httpspid port $port\n";
        }
        last;
    }
    $runcert{$server} = $certfile;
    logmsg "RUN: failed to start the $srvrname server\n" if(!$httpspid);

    return ($httpspid, $pid2, $port);
}

#######################################################################
# start the non-stunnel HTTP TLS extensions capable server
#
sub runhttptlsserver {
    my ($verbose, $ipv6) = @_;
    my $proto = "httptls";
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if(!$httptlssrv) {
        return (0,0);
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--http ";
    $flags .= "--debug 1 " if($debugprotocol);
    $flags .= "--priority NORMAL:+SRP ";
    $flags .= "--srppasswd $srcdir/certs/srp-verifier-db ";
    $flags .= "--srppasswdconf $srcdir/certs/srp-verifier-conf";

    my $port = 24367;
    my ($httptlspid, $pid2);
    for (1 .. 10) {
        $port += int(rand(800));
        my $allflags = "--port $port $flags";

        my $cmd = "$httptlssrv $allflags > $logfile 2>&1";
        ($httptlspid, $pid2) = startnew($cmd, $pidfile, 10, 1);

        if($httptlspid <= 0 || !pidexists($httptlspid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $httptlspid = $pid2 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $httptlspid port $port\n";
        }
        last;
    }
    logmsg "RUN: failed to start the $srvrname server\n" if(!$httptlspid);
    return ($httptlspid, $pid2, $port);
}

#######################################################################
# start the pingpong server (FTP, POP3, IMAP, SMTP)
#
sub runpingpongserver {
    my ($proto, $id, $verbose, $ipv6) = @_;
    my $port;
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0,0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
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
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0,0);
    }

    # where is it?
    $port = pidfromfile($portfile);

    logmsg "PINGPONG runs on port $port ($portfile)\n" if($verbose);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$ftppid $pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0,0);
    }
    $pid2 = $pid3;

    logmsg "RUN: $srvrname server is PID $ftppid port $port\n" if($verbose);

    # Assign the correct port variable!
    if($proto =~ /^(?:ftp|imap|pop3|smtp)$/) {
        $PORT{$proto . ($ipvnum == 6? '6': '')} = $port;
    }
    else {
        print STDERR "Unsupported protocol $proto!!\n";
        return (0,0);
    }

    return ($pid2, $ftppid);
}

#######################################################################
# start the ftps/imaps/pop3s/smtps server (or rather, tunnel)
#
sub runsecureserver {
    my ($verbose, $ipv6, $certfile, $proto, $clearport) = @_;
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if(!$stunnel) {
        return (0,0);
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $certfile = 'stunnel.pem' unless($certfile);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --proto $proto ";
    $flags .= "--certfile \"$certfile\" " if($certfile ne 'stunnel.pem');
    $flags .= "--stunnel \"$stunnel\" --srcdir \"$srcdir\" ";
    $flags .= "--connect $clearport";

    my $protospid;
    my $pid2;
    my $port = 26713 + ord $proto;
    my %usedports = reverse %PORT;
    for (1 .. 10) {
        $port += int(rand(700));
        next if exists $usedports{$port};
        my $options = "$flags --accept $port";
        my $cmd = "$perl $srcdir/secureserver.pl $options";
        ($protospid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($protospid <= 0 || !pidexists($protospid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $protospid = $pid2 = 0;
            next;
        }

        $doesntrun{$pidfile} = 0;
        $runcert{$server} = $certfile;

        if($verbose) {
            logmsg "RUN: $srvrname server is PID $protospid port $port\n";
        }
        last;
    }

    logmsg "RUN: failed to start the $srvrname server\n" if(!$protospid);

    return ($protospid, $pid2, $port);
}

#######################################################################
# start the tftp server
#
sub runtftpserver {
    my ($id, $verbose, $ipv6) = @_;
    my $ip = $HOSTIP;
    my $proto = 'tftp';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ".
        "--portfile \"$portfile\" ".
        "--logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --port 0 --srcdir \"$srcdir\"";

    my $cmd = "$perl $srcdir/tftpserver.pl $flags";
    my ($tftppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($tftppid <= 0 || !pidexists($tftppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$tftppid $pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }
    $pid2 = $pid3;

    if($verbose) {
        logmsg "RUN: $srvrname server on PID $tftppid port $port\n";
    }

    return ($pid2, $tftppid, $port);
}


#######################################################################
# start the rtsp server
#
sub runrtspserver {
    my ($verbose, $ipv6) = @_;
    my $ip = $HOSTIP;
    my $proto = 'rtsp';
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($ipv6) {
        # if IPv6, use a different setup
        $ipvnum = 6;
        $ip = $HOST6IP;
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ".
         "--portfile \"$portfile\" ".
        "--logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --port 0 --srcdir \"$srcdir\"";

    my $cmd = "$perl $srcdir/rtspserver.pl $flags";
    my ($rtsppid, $pid2) = startnew($cmd, $pidfile, 15, 0);

    if($rtsppid <= 0 || !pidexists($rtsppid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    # Server is up. Verify that we can speak to it.
    my $pid3 = verifyserver($proto, $ipvnum, $idnum, $ip, $port);
    if(!$pid3) {
        logmsg "RUN: $srvrname server failed verification\n";
        # failed to talk to it properly. Kill the server and return failure
        stopserver($server, "$rtsppid $pid2");
        displaylogs($testnumcheck);
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }
    $pid2 = $pid3;

    if($verbose) {
        logmsg "RUN: $srvrname server PID $rtsppid port $port\n";
    }

    return ($rtsppid, $pid2, $port);
}


#######################################################################
# Start the ssh (scp/sftp) server
#
sub runsshserver {
    my ($id, $verbose, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $proto = 'ssh';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $port = 20000; # no lower port

    if(!$USER) {
        logmsg "Can't start ssh server due to lack of USER name";
        return (0,0,0);
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $sshd = find_sshd();
    if($sshd) {
        ($sshdid,$sshdvernum,$sshdverstr,$sshderror) = sshversioninfo($sshd);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    my $flags = "";
    $flags .= "--verbose " if($verbose);
    $flags .= "--debugprotocol " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--ipv$ipvnum --addr \"$ip\" ";
    $flags .= "--user \"$USER\"";

    my $sshpid;
    my $pid2;

    my $wport = 0,
    my @tports;
    for(1 .. 10) {

        # sshd doesn't have a way to pick an unused random port number, so
        # instead we iterate over possible port numbers to use until we find
        # one that works
        $port += int(rand(500));
        push @tports, $port;

        my $options = "$flags --sshport $port";

        my $cmd = "$perl $srcdir/sshserver.pl $options";
        ($sshpid, $pid2) = startnew($cmd, $pidfile, 60, 0);

        # on loaded systems sshserver start up can take longer than the
        # timeout passed to startnew, when this happens startnew completes
        # without being able to read the pidfile and consequently returns a
        # zero pid2 above.
        if($sshpid <= 0 || !pidexists($sshpid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            $doesntrun{$pidfile} = 1;
            $sshpid = $pid2 = 0;
            next;
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
            next;
        }
        # we're happy, no need to loop anymore!
        $doesntrun{$pidfile} = 0;
        $wport = $port;
        last;
    }
    logmsg "RUN: failed to start the $srvrname server on $port\n" if(!$sshpid);

    if(!$wport) {
        logmsg "RUN: couldn't start $srvrname. Tried these ports:";
        logmsg "RUN: ".join(", ", @tports);
        return (0,0,0);
    }

    my $hstpubmd5f = "curl_host_rsa_key.pub_md5";
    if(!open(PUBMD5FILE, "<", $hstpubmd5f) ||
       (read(PUBMD5FILE, $SSHSRVMD5, 32) != 32) ||
       !close(PUBMD5FILE) ||
       ($SSHSRVMD5 !~ /^[a-f0-9]{32}$/i))
    {
        my $msg = "Fatal: $srvrname pubkey md5 missing : \"$hstpubmd5f\" : $!";
        logmsg "$msg\n";
        stopservers($verbose);
        die $msg;
    }

    my $hstpubsha256f = "curl_host_rsa_key.pub_sha256";
    if(!open(PUBSHA256FILE, "<", $hstpubsha256f) ||
       (read(PUBSHA256FILE, $SSHSRVSHA256, 48) == 0) ||
       !close(PUBSHA256FILE))
    {
        my $msg = "Fatal: $srvrname pubkey sha256 missing : \"$hstpubsha256f\" : $!";
        logmsg "$msg\n";
        stopservers($verbose);
        die $msg;
    }

    logmsg "RUN: $srvrname on PID $pid2 port $wport\n" if($verbose);

    return ($pid2, $sshpid, $wport);
}

#######################################################################
# Start the MQTT server
#
sub runmqttserver {
    my ($id, $verbose, $ipv6) = @_;
    my $ip=$HOSTIP;
    my $proto = 'mqtt';
    my $port = protoport($proto);
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $portfile;
    my $logfile;
    my $flags = "";

    $server = servername_id($proto, $ipvnum, $idnum);
    $pidfile = $serverpidfile{$server};
    $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0,0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    # start our MQTT server - on a random port!
    my $cmd="server/mqttd".exe_ext('SRV').
        " --port 0 ".
        " --pidfile $pidfile".
        " --portfile $portfile".
        " --config $FTPDCMD";
    my ($sockspid, $pid2) = startnew($cmd, $pidfile, 30, 0);

    if($sockspid <= 0 || !pidexists($sockspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (0,0);
    }

    my $mqttport = pidfromfile($portfile);
    $PORT{"mqtt"} = $mqttport;

    if($verbose) {
        logmsg "RUN: $srvrname server is now running PID $pid2 on PORT $mqttport\n";
    }

    return ($pid2, $sockspid);
}

#######################################################################
# Start the socks server
#
sub runsocksserver {
    my ($id, $verbose, $ipv6, $is_unix) = @_;
    my $ip=$HOSTIP;
    my $proto = 'socks';
    my $ipvnum = 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};
    my $portfile = $serverportfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    # start our socks server, get commands from the FTP cmd file
    my $cmd="";
    if($is_unix) {
        $cmd="server/socksd".exe_ext('SRV').
            " --pidfile $pidfile".
            " --unix-socket $SOCKSUNIXPATH".
            " --backend $HOSTIP".
            " --config $FTPDCMD";
    } else {
        $cmd="server/socksd".exe_ext('SRV').
            " --port 0 ".
            " --pidfile $pidfile".
            " --portfile $portfile".
            " --backend $HOSTIP".
            " --config $FTPDCMD";
    }
    my ($sockspid, $pid2) = startnew($cmd, $pidfile, 30, 0);

    if($sockspid <= 0 || !pidexists($sockspid)) {
        # it is NOT alive
        logmsg "RUN: failed to start the $srvrname server\n";
        stopserver($server, "$pid2");
        $doesntrun{$pidfile} = 1;
        return (0, 0, 0);
    }

    my $port = pidfromfile($portfile);

    if($verbose) {
        logmsg "RUN: $srvrname server is now running PID $pid2\n";
    }

    return ($pid2, $sockspid, $port);
}

#######################################################################
# start the dict server
#
sub rundictserver {
    my ($verbose, $alt) = @_;
    my $proto = "dict";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($alt eq "ipv6") {
        # No IPv6
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\" ";
    $flags .= "--host $HOSTIP";

    my $port = 29000;
    my ($dictpid, $pid2);
    for(1 .. 10) {
        $port += int(rand(900));
        my $aflags = "--port $port $flags";
        my $cmd = "$srcdir/dictserver.py $aflags";
        ($dictpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($dictpid <= 0 || !pidexists($dictpid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $dictpid = $pid2 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $dictpid port $port\n";
        }
        last;
    }
    logmsg "RUN: failed to start the $srvrname server\n" if(!$dictpid);

    return ($dictpid, $pid2, $port);
}

#######################################################################
# start the SMB server
#
sub runsmbserver {
    my ($verbose, $alt) = @_;
    my $proto = "smb";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($alt eq "ipv6") {
        # No IPv6
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\" ";
    $flags .= "--host $HOSTIP";

    my ($smbpid, $pid2);
    my $port = 31923;
    for(1 .. 10) {
        $port += int(rand(760));
        my $aflags = "--port $port $flags";
        my $cmd = "$srcdir/smbserver.py $aflags";
        ($smbpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($smbpid <= 0 || !pidexists($smbpid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $smbpid = $pid2 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $smbpid port $port\n";
        }
        last;
    }
    logmsg "RUN: failed to start the $srvrname server\n" if(!$smbpid);

    return ($smbpid, $pid2, $port);
}

#######################################################################
# start the telnet server
#
sub runnegtelnetserver {
    my ($verbose, $alt) = @_;
    my $proto = "telnet";
    my $ip = $HOSTIP;
    my $ipvnum = 4;
    my $idnum = 1;
    my $server;
    my $srvrname;
    my $pidfile;
    my $logfile;
    my $flags = "";

    if($alt eq "ipv6") {
        # No IPv6
    }

    $server = servername_id($proto, $ipvnum, $idnum);

    $pidfile = $serverpidfile{$server};

    # don't retry if the server doesn't work
    if ($doesntrun{$pidfile}) {
        return (0, 0, 0);
    }

    my $pid = processexists($pidfile);
    if($pid > 0) {
        stopserver($server, "$pid");
    }
    unlink($pidfile) if(-f $pidfile);

    $srvrname = servername_str($proto, $ipvnum, $idnum);

    $logfile = server_logfilename($LOGDIR, $proto, $ipvnum, $idnum);

    $flags .= "--verbose 1 " if($debugprotocol);
    $flags .= "--pidfile \"$pidfile\" --logfile \"$logfile\" ";
    $flags .= "--id $idnum " if($idnum > 1);
    $flags .= "--srcdir \"$srcdir\"";

    my ($ntelpid, $pid2);
    my $port = 32000;
    for(1 .. 10) {
        $port += int(rand(800));
        my $aflags = "--port $port $flags";
        my $cmd = "$srcdir/negtelnetserver.py $aflags";
        ($ntelpid, $pid2) = startnew($cmd, $pidfile, 15, 0);

        if($ntelpid <= 0 || !pidexists($ntelpid)) {
            # it is NOT alive
            stopserver($server, "$pid2");
            displaylogs($testnumcheck);
            $doesntrun{$pidfile} = 1;
            $ntelpid = $pid2 = 0;
            next;
        }
        $doesntrun{$pidfile} = 0;

        if($verbose) {
            logmsg "RUN: $srvrname server PID $ntelpid port $port\n";
        }
        last;
    }
    logmsg "RUN: failed to start the $srvrname server\n" if(!$ntelpid);

    return ($ntelpid, $pid2, $port);
}


#######################################################################
# Single shot http and gopher server responsiveness test. This should only
# be used to verify that a server present in %run hash is still functional
#
sub responsive_http_server {
    my ($proto, $verbose, $alt, $port_or_path) = @_;
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
    my ($proto, $id, $verbose, $ipv6) = @_;
    my $port;
    my $ip = ($ipv6 && ($ipv6 =~ /6$/)) ? "$HOST6IP" : "$HOSTIP";
    my $ipvnum = ($ipv6 && ($ipv6 =~ /6$/)) ? 6 : 4;
    my $idnum = ($id && ($id =~ /^(\d+)$/) && ($id > 1)) ? $id : 1;
    my $protoip = $proto . ($ipvnum == 6? '6': '');

    if($proto =~ /^(?:ftp|imap|pop3|smtp)$/) {
        $port = protoport($protoip);
    }
    else {
        print STDERR "Unsupported protocol $proto!!\n";
        return 0;
    }

    return &responsiveserver($proto, $ipvnum, $idnum, $ip, $port);
}

#######################################################################
# Single shot rtsp server responsiveness test. This should only be
# used to verify that a server present in %run hash is still functional
#
sub responsive_rtsp_server {
    my ($verbose, $ipv6) = @_;
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
    my ($id, $verbose, $ipv6) = @_;
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
    my ($verbose, $ipv6) = @_;
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
# Kill the processes that still lock files in a directory
#
sub clearlocks {
    my $dir = $_[0];
    my $done = 0;

    if(pathhelp::os_is_win()) {
        $dir = pathhelp::sys_native_abs_path($dir);
        $dir =~ s/\//\\\\/g;
        my $handle = "handle.exe";
        if($ENV{"PROCESSOR_ARCHITECTURE"} =~ /64$/) {
            $handle = "handle64.exe";
        }
        my @handles = `$handle $dir -accepteula -nobanner`;
        for $handle (@handles) {
            if($handle =~ /^(\S+)\s+pid:\s+(\d+)\s+type:\s+(\w+)\s+([0-9A-F]+):\s+(.+)\r\r/) {
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
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $done = 1;
    my $file;

    # Get all files
    opendir(my $dh, $dir) ||
        return 0; # can't open dir
    while($file = readdir($dh)) {
        if(($file !~ /^(\.|\.\.)\z/)) {
            if(-d "$dir/$file") {
                if(!cleardir("$dir/$file")) {
                    $done = 0;
                }
                if(!rmdir("$dir/$file")) {
                    $done = 0;
                }
            }
            else {
                # Ignore stunnel since we cannot do anything about its locks
                if(!unlink("$dir/$file") && "$file" !~ /_stunnel\.log$/) {
                    $done = 0;
                }
            }
        }
    }
    closedir $dh;
    return $done;
}

#######################################################################
# compare test results with the expected output, we might filter off
# some pattern that is allowed to differ, output test results
#
sub compare {
    my ($testnum, $testname, $subject, $firstref, $secondref)=@_;

    my $result = compareparts($firstref, $secondref);

    if($result) {
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();

        if(!$short) {
            logmsg "\n $testnum: $subject FAILED:\n";
            logmsg showdiff($LOGDIR, $firstref, $secondref);
        }
        elsif(!$automakestyle) {
            logmsg "FAILED\n";
        }
        else {
            # automakestyle
            logmsg "FAIL: $testnum - $testname - $subject\n";
        }
    }
    return $result;
}

sub setupfeatures {
    $feature{"alt-svc"} = $has_altsvc;
    $feature{"bearssl"} = $has_bearssl;
    $feature{"brotli"} = $has_brotli;
    $feature{"c-ares"} = $has_cares;
    $feature{"crypto"} = $has_crypto;
    $feature{"debug"} = $debug_build;
    $feature{"getrlimit"} = $has_getrlimit;
    $feature{"GnuTLS"} = $has_gnutls;
    $feature{"GSS-API"} = $has_gssapi;
    $feature{"h2c"} = $has_h2c;
    $feature{"HSTS"} = $has_hsts;
    $feature{"http/2"} = $has_http2;
    $feature{"http/3"} = $has_http3;
    $feature{"https-proxy"} = $has_httpsproxy;
    $feature{"hyper"} = $has_hyper;
    $feature{"idn"} = $has_idn;
    $feature{"ipv6"} = $has_ipv6;
    $feature{"Kerberos"} = $has_kerberos;
    $feature{"large_file"} = $has_largefile;
    $feature{"ld_preload"} = ($has_ldpreload && !$debug_build);
    $feature{"libssh"} = $has_libssh;
    $feature{"libssh2"} = $has_libssh2;
    $feature{"libz"} = $has_libz;
    $feature{"manual"} = $has_manual;
    $feature{"MinGW"} = $has_mingw;
    $feature{"MultiSSL"} = $has_multissl;
    $feature{"mbedtls"} = $has_mbedtls;
    $feature{"NSS"} = $has_nss;
    $feature{"NTLM"} = $has_ntlm;
    $feature{"NTLM_WB"} = $has_ntlm_wb;
    $feature{"oldlibssh"} = $has_oldlibssh;
    $feature{"OpenSSL"} = $has_openssl || $has_libressl || $has_boringssl;
    $feature{"PSL"} = $has_psl;
    $feature{"rustls"} = $has_rustls;
    $feature{"Schannel"} = $has_schannel;
    $feature{"sectransp"} = $has_sectransp;
    $feature{"SPNEGO"} = $has_spnego;
    $feature{"SSL"} = $has_ssl;
    $feature{"SSLpinning"} = $has_sslpinning;
    $feature{"SSPI"} = $has_sspi;
    $feature{"threaded-resolver"} = $has_threadedres;
    $feature{"threadsafe"} = $has_threadsafe;
    $feature{"TLS-SRP"} = $has_tls_srp;
    $feature{"TrackMemory"} = $has_memory_tracking;
    $feature{"Unicode"} = $has_unicode;
    $feature{"unittest"} = $debug_build;
    $feature{"unix-sockets"} = $has_unix;
    $feature{"win32"} = $has_win32;
    $feature{"wolfssh"} = $has_wolfssh;
    $feature{"wolfssl"} = $has_wolfssl;
    $feature{"zstd"} = $has_zstd;

    # make each protocol an enabled "feature"
    for my $p (@protocols) {
        $feature{$p} = 1;
    }
    # 'socks' was once here but is now removed

    #
    # strings that must match the names used in server/disabled.c
    #
    $feature{"cookies"} = 1;
    $feature{"DoH"} = 1;
    $feature{"HTTP-auth"} = 1;
    $feature{"Mime"} = 1;
    $feature{"netrc"} = 1;
    $feature{"parsedate"} = 1;
    $feature{"proxy"} = 1;
    $feature{"shuffle-dns"} = 1;
    $feature{"typecheck"} = 1;
    $feature{"verbose-strings"} = 1;
    $feature{"wakeup"} = 1;
    $feature{"headers-api"} = 1;
    $feature{"xattr"} = 1;
    $feature{"nghttpx"} = !!$ENV{'NGHTTPX'};
    $feature{"nghttpx-h3"} = !!$nghttpx_h3;
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
    my @disabled;
    my $dis = "";

    my $curlverout="$LOGDIR/curlverout.log";
    my $curlvererr="$LOGDIR/curlvererr.log";
    my $versioncmd="$CURL --version 1>$curlverout 2>$curlvererr";

    unlink($curlverout);
    unlink($curlvererr);

    $versretval = runclient($versioncmd);
    $versnoexec = $!;

    open(VERSOUT, "<$curlverout");
    @version = <VERSOUT>;
    close(VERSOUT);

    open(DISABLED, "server/disabled".exe_ext('TOOL')."|");
    @disabled = <DISABLED>;
    close(DISABLED);

    if($disabled[0]) {
        map s/[\r\n]//g, @disabled;
        $dis = join(", ", @disabled);
    }

    $resolver="stock";
    for(@version) {
        chomp;

        if($_ =~ /^curl ([^ ]*)/) {
            $curl = $_;
            $VERSION = $1;
            $curl =~ s/^(.*)(libcurl.*)/$1/g;

            $libcurl = $2;
            if($curl =~ /linux|bsd|solaris/) {
                $has_ldpreload = 1;
            }
            if($curl =~ /win32|Windows|mingw(32|64)/) {
                # This is a Windows MinGW build or native build, we need to use
                # Win32-style path.
                $pwd = pathhelp::sys_native_current_path();
                $has_textaware = 1;
                $has_win32 = 1;
                $has_mingw = 1 if ($curl =~ /-pc-mingw32/);
            }
           if ($libcurl =~ /\s(winssl|schannel)\b/i) {
               $has_schannel=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\sopenssl\b/i) {
               $has_openssl=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\sgnutls\b/i) {
               $has_gnutls=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\srustls-ffi\b/i) {
               $has_rustls=1;
           }
           elsif ($libcurl =~ /\snss\b/i) {
               $has_nss=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\swolfssl\b/i) {
               $has_wolfssl=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\sbearssl\b/i) {
               $has_bearssl=1;
           }
           elsif ($libcurl =~ /\ssecuretransport\b/i) {
               $has_sectransp=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\sBoringSSL\b/i) {
               $has_boringssl=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\slibressl\b/i) {
               $has_libressl=1;
               $has_sslpinning=1;
           }
           elsif ($libcurl =~ /\smbedTLS\b/i) {
               $has_mbedtls=1;
               $has_sslpinning=1;
           }
           if ($libcurl =~ /ares/i) {
               $has_cares=1;
               $resolver="c-ares";
           }
           if ($libcurl =~ /Hyper/i) {
               $has_hyper=1;
           }
            if ($libcurl =~ /nghttp2/i) {
                # nghttp2 supports h2c, hyper does not
                $has_h2c=1;
            }
            if ($libcurl =~ /libssh2/i) {
                $has_libssh2=1;
            }
            if ($libcurl =~ /libssh\/([0-9.]*)\//i) {
                $has_libssh=1;
                if($1 =~ /(\d+)\.(\d+).(\d+)/) {
                    my $v = $1 * 100 + $2 * 10 + $3;
                    if($v < 94) {
                        # before 0.9.4
                        $has_oldlibssh = 1;
                    }
                }
            }
            if ($libcurl =~ /wolfssh/i) {
                $has_wolfssh=1;
            }
        }
        elsif($_ =~ /^Protocols: (.*)/i) {
            # these are the protocols compiled in to this libcurl
            @protocols = split(' ', lc($1));

            # Generate a "proto-ipv6" version of each protocol to match the
            # IPv6 <server> name and a "proto-unix" to match the variant which
            # uses Unix domain sockets. This works even if support isn't
            # compiled in because the <features> test will fail.
            push @protocols, map(("$_-ipv6", "$_-unix"), @protocols);

            # 'http-proxy' is used in test cases to do CONNECT through
            push @protocols, 'http-proxy';

            # 'none' is used in test cases to mean no server
            push @protocols, 'none';
        }
        elsif($_ =~ /^Features: (.*)/i) {
            $feat = $1;
            if($feat =~ /TrackMemory/i) {
                # built with memory tracking support (--enable-curldebug)
                $has_memory_tracking = 1;
            }
            if($feat =~ /debug/i) {
                # curl was built with --enable-debug
                $debug_build = 1;
            }
            if($feat =~ /SSL/i) {
                # ssl enabled
                $has_ssl=1;
            }
            if($feat =~ /MultiSSL/i) {
                # multiple ssl backends available.
                $has_multissl=1;
            }
            if($feat =~ /Largefile/i) {
                # large file support
                $has_largefile=1;
            }
            if($feat =~ /IDN/i) {
                # IDN support
                $has_idn=1;
            }
            if($feat =~ /IPv6/i) {
                $has_ipv6 = 1;
            }
            if($feat =~ /UnixSockets/i) {
                $has_unix = 1;
            }
            if($feat =~ /libz/i) {
                $has_libz = 1;
            }
            if($feat =~ /brotli/i) {
                $has_brotli = 1;
            }
            if($feat =~ /zstd/i) {
                $has_zstd = 1;
            }
            if($feat =~ /NTLM/i) {
                # NTLM enabled
                $has_ntlm=1;

                # Use this as a proxy for any cryptographic authentication
                $has_crypto=1;
            }
            if($feat =~ /NTLM_WB/i) {
                # NTLM delegation to winbind daemon ntlm_auth helper enabled
                $has_ntlm_wb=1;
            }
            if($feat =~ /SSPI/i) {
                # SSPI enabled
                $has_sspi=1;
            }
            if($feat =~ /GSS-API/i) {
                # GSS-API enabled
                $has_gssapi=1;
            }
            if($feat =~ /Kerberos/i) {
                # Kerberos enabled
                $has_kerberos=1;

                # Use this as a proxy for any cryptographic authentication
                $has_crypto=1;
            }
            if($feat =~ /SPNEGO/i) {
                # SPNEGO enabled
                $has_spnego=1;

                # Use this as a proxy for any cryptographic authentication
                $has_crypto=1;
            }
            if($feat =~ /CharConv/i) {
                # CharConv enabled
                $has_charconv=1;
            }
            if($feat =~ /TLS-SRP/i) {
                # TLS-SRP enabled
                $has_tls_srp=1;
            }
            if($feat =~ /PSL/i) {
                # PSL enabled
                $has_psl=1;
            }
            if($feat =~ /alt-svc/i) {
                # alt-svc enabled
                $has_altsvc=1;
            }
            if($feat =~ /HSTS/i) {
                $has_hsts=1;
            }
            if($feat =~ /AsynchDNS/i) {
                if(!$has_cares) {
                    # this means threaded resolver
                    $has_threadedres=1;
                    $resolver="threaded";
                }
            }
            if($feat =~ /HTTP2/) {
                # http2 enabled
                $has_http2=1;

                push @protocols, 'http/2';
            }
            if($feat =~ /HTTP3/) {
                # http3 enabled
                $has_http3=1;

                push @protocols, 'http/3';
            }
            if($feat =~ /HTTPS-proxy/) {
                $has_httpsproxy=1;

                # 'https-proxy' is used as "server" so consider it a protocol
                push @protocols, 'https-proxy';
            }
            if($feat =~ /Unicode/i) {
                $has_unicode = 1;
            }
            if($feat =~ /threadsafe/i) {
                $has_threadsafe = 1;
            }
        }
        #
        # Test harness currently uses a non-stunnel server in order to
        # run HTTP TLS-SRP tests required when curl is built with https
        # protocol support and TLS-SRP feature enabled. For convenience
        # 'httptls' may be included in the test harness protocols array
        # to differentiate this from classic stunnel based 'https' test
        # harness server.
        #
        if($has_tls_srp) {
            my $add_httptls;
            for(@protocols) {
                if($_ =~ /^https(-ipv6|)$/) {
                    $add_httptls=1;
                    last;
                }
            }
            if($add_httptls && (! grep /^httptls$/, @protocols)) {
                push @protocols, 'httptls';
                push @protocols, 'httptls-ipv6';
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

    if(-r "../lib/curl_config.h") {
        open(CONF, "<../lib/curl_config.h");
        while(<CONF>) {
            if($_ =~ /^\#define HAVE_GETRLIMIT/) {
                $has_getrlimit = 1;
            }
        }
        close(CONF);
    }

    if($has_ipv6) {
        # client has IPv6 support

        # check if the HTTP server has it!
        my $cmd = "server/sws".exe_ext('SRV')." --version";
        my @sws = `$cmd`;
        if($sws[0] =~ /IPv6/) {
            # HTTP server has IPv6 support!
            $http_ipv6 = 1;
            $gopher_ipv6 = 1;
        }

        # check if the FTP server has it!
        $cmd = "server/sockfilt".exe_ext('SRV')." --version";
        @sws = `$cmd`;
        if($sws[0] =~ /IPv6/) {
            # FTP server has IPv6 support!
            $ftp_ipv6 = 1;
        }
    }

    if($has_unix) {
        # client has Unix sockets support, check whether the HTTP server has it
        my $cmd = "server/sws".exe_ext('SRV')." --version";
        my @sws = `$cmd`;
        $http_unix = 1 if($sws[0] =~ /unix/);
    }

    if(!$has_memory_tracking && $torture) {
        die "can't run torture tests since curl was built without ".
            "TrackMemory feature (--enable-curldebug)";
    }

    open(M, "$CURL -M 2>&1|");
    while(my $s = <M>) {
        if($s =~ /built-in manual was disabled at build-time/) {
            $has_manual = 0;
            last;
        }
        $has_manual = 1;
        last;
    }
    close(M);

    $has_shared = `sh $CURLCONFIG --built-shared`;
    chomp $has_shared;

    my $hostname=join(' ', runclientoutput("hostname"));
    my $hosttype=join(' ', runclientoutput("uname -a"));
    my $hostos=$^O;

    logmsg ("********* System characteristics ******** \n",
            "* $curl\n",
            "* $libcurl\n",
            "* Features: $feat\n",
            "* Disabled: $dis\n",
            "* Host: $hostname",
            "* System: $hosttype",
            "* OS: $hostos\n");

    if($has_memory_tracking && $has_threadedres) {
        $has_memory_tracking = 0;
        logmsg("*\n",
               "*** DISABLES memory tracking when using threaded resolver\n",
               "*\n");
    }

    logmsg sprintf("* Servers: %s", $stunnel?"SSL ":"");
    logmsg sprintf("%s", $http_ipv6?"HTTP-IPv6 ":"");
    logmsg sprintf("%s", $http_unix?"HTTP-unix ":"");
    logmsg sprintf("%s\n", $ftp_ipv6?"FTP-IPv6 ":"");

    logmsg sprintf("* Env: %s%s%s", $valgrind?"Valgrind ":"",
                   $run_event_based?"event-based ":"",
                   $nghttpx_h3);
    logmsg sprintf("%s\n", $libtool?"Libtool ":"");
    logmsg ("* Seed: $randseed\n");

    if($verbose) {
        if($has_unix) {
            logmsg "* Unix socket paths:\n";
            if($http_unix) {
                logmsg sprintf("*   HTTP-Unix:%s\n", $HTTPUNIXPATH);
                logmsg sprintf("*   Socks-Unix:%s\n", $SOCKSUNIXPATH);
            }
        }
    }

    logmsg "***************************************** \n";

    setupfeatures();
    # toggle off the features that were disabled in the build
    for my $d(@disabled) {
        $feature{$d} = 0;
    }
}

#######################################################################
# substitute the variable stuff into either a joined up file or
# a command, in either case passed by reference
#
sub subVariables {
    my ($thing, $testnum, $prefix) = @_;
    my $port;

    if(!$prefix) {
        $prefix = "%";
    }

    # test server ports
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
    $$thing =~ s/${prefix}PWD/$pwd/g;
    $$thing =~ s/${prefix}POSIX_PWD/$posix_pwd/g;
    $$thing =~ s/${prefix}VERSION/$VERSION/g;
    $$thing =~ s/${prefix}TESTNUMBER/$testnum/g;

    my $file_pwd = $pwd;
    if($file_pwd !~ /^\//) {
        $file_pwd = "/$file_pwd";
    }
    my $ssh_pwd = $posix_pwd;
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
    my $ftp2 = $ftpchecktime * 2;
    my $ftp3 = $ftpchecktime * 3;

    $$thing =~ s/${prefix}FTPTIME2/$ftp2/g;
    $$thing =~ s/${prefix}FTPTIME3/$ftp3/g;

    # HTTP2
    $$thing =~ s/${prefix}H2CVER/$h2cver/g;
}

sub subBase64 {
    my ($thing) = @_;

    # cut out the base64 piece
    if($$thing =~ s/%b64\[(.*)\]b64%/%%B64%%/i) {
        my $d = $1;
        # encode %NN characters
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $enc = encode_base64($d, "");
        # put the result into there
        $$thing =~ s/%%B64%%/$enc/;
    }
    # hex decode
    if($$thing =~ s/%hex\[(.*)\]hex%/%%HEX%%/i) {
        # decode %NN characters
        my $d = $1;
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $$thing =~ s/%%HEX%%/$d/;
    }
    if($$thing =~ s/%repeat\[(\d+) x (.*)\]%/%%REPEAT%%/i) {
        # decode %NN characters
        my ($d, $n) = ($2, $1);
        $d =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        my $all = $d x $n;
        $$thing =~ s/%%REPEAT%%/$all/;
    }
}

my $prevupdate;
sub subNewlines {
    my ($force, $thing) = @_;

    if($force) {
        # enforce CRLF newline
        $$thing =~ s/\x0d*\x0a/\x0d\x0a/;
        return;
    }

    # When curl is built with Hyper, it gets all response headers delivered as
    # name/value pairs and curl "invents" the newlines when it saves the
    # headers. Therefore, curl will always save headers with CRLF newlines
    # when built to use Hyper. By making sure we deliver all tests using CRLF
    # as well, all test comparisons will survive without knowing about this
    # little quirk.

    if(($$thing =~ /^HTTP\/(1.1|1.0|2|3) [1-5][^\x0d]*\z/) ||
       ($$thing =~ /^(GET|POST|PUT|DELETE) \S+ HTTP\/\d+(\.\d+)?/) ||
       (($$thing =~ /^[a-z0-9_-]+: [^\x0d]*\z/i) &&
        # skip curl error messages
        ($$thing !~ /^curl: \(\d+\) /))) {
        # enforce CRLF newline
        $$thing =~ s/\x0d*\x0a/\x0d\x0a/;
        $prevupdate = 1;
    }
    else {
        if(($$thing =~ /^\n\z/) && $prevupdate) {
            # if there's a blank link after a line we update, we hope it is
            # the empty line following headers
            $$thing =~ s/\x0a/\x0d\x0a/;
        }
        $prevupdate = 0;
    }
}

#######################################################################
# Provide time stamps for single test skipped events
#
sub timestampskippedevents {
    my $testnum = $_[0];

    return if((not defined($testnum)) || ($testnum < 1));

    if($timestats) {

        if($timevrfyend{$testnum}) {
            return;
        }
        elsif($timesrvrlog{$testnum}) {
            $timevrfyend{$testnum} = $timesrvrlog{$testnum};
            return;
        }
        elsif($timetoolend{$testnum}) {
            $timevrfyend{$testnum} = $timetoolend{$testnum};
            $timesrvrlog{$testnum} = $timetoolend{$testnum};
        }
        elsif($timetoolini{$testnum}) {
            $timevrfyend{$testnum} = $timetoolini{$testnum};
            $timesrvrlog{$testnum} = $timetoolini{$testnum};
            $timetoolend{$testnum} = $timetoolini{$testnum};
        }
        elsif($timesrvrend{$testnum}) {
            $timevrfyend{$testnum} = $timesrvrend{$testnum};
            $timesrvrlog{$testnum} = $timesrvrend{$testnum};
            $timetoolend{$testnum} = $timesrvrend{$testnum};
            $timetoolini{$testnum} = $timesrvrend{$testnum};
        }
        elsif($timesrvrini{$testnum}) {
            $timevrfyend{$testnum} = $timesrvrini{$testnum};
            $timesrvrlog{$testnum} = $timesrvrini{$testnum};
            $timetoolend{$testnum} = $timesrvrini{$testnum};
            $timetoolini{$testnum} = $timesrvrini{$testnum};
            $timesrvrend{$testnum} = $timesrvrini{$testnum};
        }
        elsif($timeprepini{$testnum}) {
            $timevrfyend{$testnum} = $timeprepini{$testnum};
            $timesrvrlog{$testnum} = $timeprepini{$testnum};
            $timetoolend{$testnum} = $timeprepini{$testnum};
            $timetoolini{$testnum} = $timeprepini{$testnum};
            $timesrvrend{$testnum} = $timeprepini{$testnum};
            $timesrvrini{$testnum} = $timeprepini{$testnum};
        }
    }
}

#
# 'prepro' processes the input array and replaces %-variables in the array
# etc. Returns the processed version of the array

sub prepro {
    my $testnum = shift;
    my (@entiretest) = @_;
    my $show = 1;
    my @out;
    my $data_crlf;
    for my $s (@entiretest) {
        my $f = $s;
        if($s =~ /^ *%if (.*)/) {
            my $cond = $1;
            my $rev = 0;

            if($cond =~ /^!(.*)/) {
                $cond = $1;
                $rev = 1;
            }
            $rev ^= $feature{$cond} ? 1 : 0;
            $show = $rev;
            next;
        }
        elsif($s =~ /^ *%else/) {
            $show ^= 1;
            next;
        }
        elsif($s =~ /^ *%endif/) {
            $show = 1;
            next;
        }
        if($show) {
            # The processor does CRLF replacements in the <data*> sections if
            # necessary since those parts might be read by separate servers.
            if($s =~ /^ *<data(.*)\>/) {
                if($1 =~ /crlf="yes"/ ||
                   ($has_hyper && ($keywords{"HTTP"} || $keywords{"HTTPS"}))) {
                    $data_crlf = 1;
                }
            }
            elsif(($s =~ /^ *<\/data/) && $data_crlf) {
                $data_crlf = 0;
            }
            subVariables(\$s, $testnum, "%");
            subBase64(\$s);
            subNewlines(0, \$s) if($data_crlf);
            push @out, $s;
        }
    }
    return @out;
}

#######################################################################
# Run a single specified test case
#
sub singletest {
    my ($evbased, # 1 means switch on if possible (and "curl" is tested)
                  # returns "not a test" if it can't be used for this test
        $testnum,
        $count,
        $total)=@_;

    my @what;
    my $why;
    my $cmd;
    my $disablevalgrind;
    my $errorreturncode = 1; # 1 means normal error, 2 means ignored error

    # fist, remove all lingering log files
    if(!cleardir($LOGDIR) && $clearlocks) {
        clearlocks($LOGDIR);
        cleardir($LOGDIR);
    }

    # copy test number to a global scope var, this allows
    # testnum checking when starting test harness servers.
    $testnumcheck = $testnum;

    # timestamp test preparation start
    $timeprepini{$testnum} = Time::HiRes::time();

    if($disttests !~ /test$testnum(\W|\z)/ ) {
        logmsg "Warning: test$testnum not present in tests/data/Makefile.inc\n";
    }
    if($disabled{$testnum}) {
        if(!$run_disabeled) {
            $why = "listed in DISABLED";
        }
        else {
            logmsg "Warning: test$testnum is explicitly disabled\n";
        }
    }
    if($ignored{$testnum}) {
        logmsg "Warning: test$testnum result is ignored\n";
        $errorreturncode = 2;
    }

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

    # We require a feature to be present
    for(@what) {
        my $f = $_;
        $f =~ s/\s//g;

        if($f =~ /^([^!].*)$/) {
            if($feature{$1}) {
                next;
            }

            $why = "curl lacks $1 support";
            last;
        }
    }

    # We require a feature to not be present
    if(!$why) {
        for(@what) {
            my $f = $_;
            $f =~ s/\s//g;

            if($f =~ /^!(.*)$/) {
                if(!$feature{$1}) {
                    next;
                }
            }
            else {
                next;
            }

            $why = "curl has $1 support";
            last;
        }
    }

    if(!$why) {
        my @info_keywords = getpart("info", "keywords");
        my $match;
        my $k;

        # Clear the list of keywords from the last test
        %keywords = ();

        if(!$info_keywords[0]) {
            $why = "missing the <keywords> section!";
        }

        for $k (@info_keywords) {
            chomp $k;
            if ($disabled_keywords{lc($k)}) {
                $why = "disabled by keyword";
            } elsif ($enabled_keywords{lc($k)}) {
                $match = 1;
            }
            if ($ignored_keywords{lc($k)}) {
                logmsg "Warning: test$testnum result is ignored due to $k\n";
                $errorreturncode = 2;
            }

            $keywords{$k} = 1;
        }

        if(!$why && !$match && %enabled_keywords) {
            $why = "disabled by missing keyword";
        }
    }

    if (!$why && defined $custom_skip_reasons{test}{$testnum}) {
        $why = $custom_skip_reasons{test}{$testnum};
    }

    if (!$why && defined $custom_skip_reasons{tool}) {
        foreach my $tool (getpart("client", "tool")) {
            foreach my $tool_skip_pattern (keys %{$custom_skip_reasons{tool}}) {
                if ($tool =~ /$tool_skip_pattern/i) {
                    $why = $custom_skip_reasons{tool}{$tool_skip_pattern};
                }
            }
        }
    }

    if (!$why && defined $custom_skip_reasons{keyword}) {
        foreach my $keyword (getpart("info", "keywords")) {
            foreach my $keyword_skip_pattern (keys %{$custom_skip_reasons{keyword}}) {
                if ($keyword =~ /$keyword_skip_pattern/i) {
                    $why = $custom_skip_reasons{keyword}{$keyword_skip_pattern};
                }
            }
        }
    }


    # test definition may instruct to (un)set environment vars
    # this is done this early, so that the precheck can use environment
    # variables and still bail out fine on errors

    # restore environment variables that were modified in a previous run
    foreach my $var (keys %oldenv) {
        if($oldenv{$var} eq 'notset') {
            delete $ENV{$var} if($ENV{$var});
        }
        else {
            $ENV{$var} = $oldenv{$var};
        }
        delete $oldenv{$var};
    }

    # get the name of the test early
    my @testname= getpart("client", "name");
    my $testname = $testname[0];
    $testname =~ s/\n//g;

    # create test result in CI services
    if(azure_check_environment() && $AZURE_RUN_ID) {
        $AZURE_RESULT_ID = azure_create_test_result($ACURL, $AZURE_RUN_ID, $testnum, $testname);
    }
    elsif(appveyor_check_environment()) {
        appveyor_create_test_result($ACURL, $testnum, $testname);
    }

    # remove test server commands file before servers are started/verified
    unlink($FTPDCMD) if(-f $FTPDCMD);

    # timestamp required servers verification start
    $timesrvrini{$testnum} = Time::HiRes::time();

    if(!$why) {
        $why = serverfortest($testnum);
    }

    # Save a preprocessed version of the entire test file. This allows more
    # "basic" test case readers to enjoy variable replacements.
    my @entiretest = fulltest();
    my $otest = "log/test$testnum";

    @entiretest = prepro($testnum, @entiretest);

    # save the new version
    open(D, ">$otest");
    foreach my $bytes (@entiretest) {
        print D pack('a*', $bytes) or die "Failed to print '$bytes': $!";
    }
    close(D);

    # in case the process changed the file, reload it
    loadtest("log/test${testnum}");

    # timestamp required servers verification end
    $timesrvrend{$testnum} = Time::HiRes::time();

    my @setenv = getpart("client", "setenv");
    if(@setenv) {
        foreach my $s (@setenv) {
            chomp $s;
            if($s =~ /([^=]*)=(.*)/) {
                my ($var, $content) = ($1, $2);
                # remember current setting, to restore it once test runs
                $oldenv{$var} = ($ENV{$var})?"$ENV{$var}":'notset';
                # set new value
                if(!$content) {
                    delete $ENV{$var} if($ENV{$var});
                }
                else {
                    if($var =~ /^LD_PRELOAD/) {
                        if(exe_ext('TOOL') && (exe_ext('TOOL') eq '.exe')) {
                            # print "Skipping LD_PRELOAD due to lack of OS support\n";
                            next;
                        }
                        if($debug_build || ($has_shared ne "yes")) {
                            # print "Skipping LD_PRELOAD due to no release shared build\n";
                            next;
                        }
                    }
                    $ENV{$var} = "$content";
                    print "setenv $var = $content\n" if($verbose);
                }
            }
        }
    }
    if($use_external_proxy) {
        $ENV{http_proxy} = $proxy_address;
        $ENV{HTTPS_PROXY} = $proxy_address;
    }

    if(!$why) {
        my @precheck = getpart("client", "precheck");
        if(@precheck) {
            $cmd = $precheck[0];
            chomp $cmd;
            if($cmd) {
                my @p = split(/ /, $cmd);
                if($p[0] !~ /\//) {
                    # the first word, the command, does not contain a slash so
                    # we will scan the "improved" PATH to find the command to
                    # be able to run it
                    my $fullp = checktestcmd($p[0]);

                    if($fullp) {
                        $p[0] = $fullp;
                    }
                    $cmd = join(" ", @p);
                }

                my @o = `$cmd 2>log/precheck-$testnum`;
                if($o[0]) {
                    $why = $o[0];
                    chomp $why;
                } elsif($?) {
                    $why = "precheck command error";
                }
                logmsg "prechecked $cmd\n" if($verbose);
            }
        }
    }

    if($why && !$listonly) {
        # there's a problem, count it as "skipped"
        $skipped++;
        $skipped{$why}++;
        $teststat[$testnum]=$why; # store reason for this test case

        if(!$short) {
            if($skipped{$why} <= 3) {
                # show only the first three skips for each reason
                logmsg sprintf("test %04d SKIPPED: $why\n", $testnum);
            }
        }

        timestampskippedevents($testnum);
        return -1;
    }
    logmsg sprintf("test %04d...", $testnum) if(!$automakestyle);

    my %replyattr = getpartattr("reply", "data");
    my @reply;
    if (partexists("reply", "datacheck")) {
        for my $partsuffix (('', '1', '2', '3', '4')) {
            my @replycheckpart = getpart("reply", "datacheck".$partsuffix);
            if(@replycheckpart) {
                my %replycheckpartattr = getpartattr("reply", "datacheck".$partsuffix);
                # get the mode attribute
                my $filemode=$replycheckpartattr{'mode'};
                if($filemode && ($filemode eq "text") && $has_textaware) {
                    # text mode when running on windows: fix line endings
                    map s/\r\n/\n/g, @replycheckpart;
                    map s/\n/\r\n/g, @replycheckpart;
                }
                if($replycheckpartattr{'nonewline'}) {
                    # Yes, we must cut off the final newline from the final line
                    # of the datacheck
                    chomp($replycheckpart[$#replycheckpart]);
                }
                if($replycheckpartattr{'crlf'} ||
                   ($has_hyper && ($keywords{"HTTP"}
                                   || $keywords{"HTTPS"}))) {
                    map subNewlines(0, \$_), @replycheckpart;
                }
                push(@reply, @replycheckpart);
            }
        }
    }
    else {
        # check against the data section
        @reply = getpart("reply", "data");
        if(@reply) {
            my %hash = getpartattr("reply", "data");
            if($hash{'nonewline'}) {
                # cut off the final newline from the final line of the data
                chomp($reply[$#reply]);
            }
        }
        # get the mode attribute
        my $filemode=$replyattr{'mode'};
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            map s/\r\n/\n/g, @reply;
            map s/\n/\r\n/g, @reply;
        }
        if($replyattr{'crlf'} ||
           ($has_hyper && ($keywords{"HTTP"}
                           || $keywords{"HTTPS"}))) {
            map subNewlines(0, \$_), @reply;
        }
    }

    # this is the valid protocol blurb curl should generate
    my @protocol= getpart("verify", "protocol");

    # this is the valid protocol blurb curl should generate to a proxy
    my @proxyprot = getpart("verify", "proxy");

    # redirected stdout/stderr to these files
    $STDOUT="$LOGDIR/stdout$testnum";
    $STDERR="$LOGDIR/stderr$testnum";

    # if this section exists, we verify that the stdout contained this:
    my @validstdout = getpart("verify", "stdout");
    my @validstderr = getpart("verify", "stderr");

    # if this section exists, we verify upload
    my @upload = getpart("verify", "upload");
    if(@upload) {
      my %hash = getpartattr("verify", "upload");
      if($hash{'nonewline'}) {
          # cut off the final newline from the final line of the upload data
          chomp($upload[$#upload]);
      }
    }

    # if this section exists, it might be FTP server instructions:
    my @ftpservercmd = getpart("reply", "servercmd");

    my $CURLOUT="$LOGDIR/curl$testnum.out"; # curl output if not stdout

    # name of the test
    logmsg "[$testname]\n" if(!$short);

    if($listonly) {
        timestampskippedevents($testnum);
        return 0; # look successful
    }

    my @codepieces = getpart("client", "tool");

    my $tool="";
    if(@codepieces) {
        $tool = $codepieces[0];
        chomp $tool;
        $tool .= exe_ext('TOOL');
    }

    # remove server output logfile
    unlink($SERVERIN);
    unlink($SERVER2IN);
    unlink($PROXYIN);

    push @ftpservercmd, "Testnum $testnum\n";
    # write the instructions to file
    writearray($FTPDCMD, \@ftpservercmd);

    # get the command line options to use
    my @blaha;
    ($cmd, @blaha)= getpart("client", "command");

    if($cmd) {
        # make some nice replace operations
        $cmd =~ s/\n//g; # no newlines please
        # substitute variables in the command line
    }
    else {
        # there was no command given, use something silly
        $cmd="-";
    }
    if($has_memory_tracking) {
        unlink($memdump);
    }

    # create (possibly-empty) files before starting the test
    for my $partsuffix (('', '1', '2', '3', '4')) {
        my @inputfile=getpart("client", "file".$partsuffix);
        my %fileattr = getpartattr("client", "file".$partsuffix);
        my $filename=$fileattr{'name'};
        if(@inputfile || $filename) {
            if(!$filename) {
                logmsg "ERROR: section client=>file has no name attribute\n";
                timestampskippedevents($testnum);
                return -1;
            }
            my $fileContent = join('', @inputfile);

            # make directories if needed
            my $path = $filename;
            # cut off the file name part
            $path =~ s/^(.*)\/[^\/]*/$1/;
            my @parts = split(/\//, $path);
            if($parts[0] eq "log") {
                # the file is in log/
                my $d = shift @parts;
                for(@parts) {
                    $d .= "/$_";
                    mkdir $d; # 0777
                }
            }
            open(OUTFILE, ">$filename");
            binmode OUTFILE; # for crapage systems, use binary
            if($fileattr{'nonewline'}) {
                # cut off the final newline
                chomp($fileContent);
            }
            print OUTFILE $fileContent;
            close(OUTFILE);
        }
    }

    my %cmdhash = getpartattr("client", "command");

    my $out="";

    if((!$cmdhash{'option'}) || ($cmdhash{'option'} !~ /no-output/)) {
        #We may slap on --output!
        if (!@validstdout ||
                ($cmdhash{'option'} && $cmdhash{'option'} =~ /force-output/)) {
            $out=" --output $CURLOUT ";
        }
    }

    my $serverlogslocktimeout = $defserverlogslocktimeout;
    if($cmdhash{'timeout'}) {
        # test is allowed to override default server logs lock timeout
        if($cmdhash{'timeout'} =~ /(\d+)/) {
            $serverlogslocktimeout = $1 if($1 >= 0);
        }
    }

    my $postcommanddelay = $defpostcommanddelay;
    if($cmdhash{'delay'}) {
        # test is allowed to specify a delay after command is executed
        if($cmdhash{'delay'} =~ /(\d+)/) {
            $postcommanddelay = $1 if($1 > 0);
        }
    }

    my $CMDLINE;
    my $cmdargs;
    my $cmdtype = $cmdhash{'type'} || "default";
    my $fail_due_event_based = $evbased;
    if($cmdtype eq "perl") {
        # run the command line prepended with "perl"
        $cmdargs ="$cmd";
        $CMDLINE = "$perl ";
        $tool=$CMDLINE;
        $disablevalgrind=1;
    }
    elsif($cmdtype eq "shell") {
        # run the command line prepended with "/bin/sh"
        $cmdargs ="$cmd";
        $CMDLINE = "/bin/sh ";
        $tool=$CMDLINE;
        $disablevalgrind=1;
    }
    elsif(!$tool && !$keywords{"unittest"}) {
        # run curl, add suitable command line options
        my $inc="";
        if((!$cmdhash{'option'}) || ($cmdhash{'option'} !~ /no-include/)) {
            $inc = " --include";
        }
        $cmdargs = "$out$inc ";

        if($cmdhash{'option'} && ($cmdhash{'option'} =~ /binary-trace/)) {
            $cmdargs .= "--trace log/trace$testnum ";
        }
        else {
            $cmdargs .= "--trace-ascii log/trace$testnum ";
        }
        $cmdargs .= "--trace-time ";
        if($evbased) {
            $cmdargs .= "--test-event ";
            $fail_due_event_based--;
        }
        $cmdargs .= $cmd;
        if ($use_external_proxy) {
            $cmdargs .= " --proxy $proxy_address ";
        }
    }
    else {
        $cmdargs = " $cmd"; # $cmd is the command line for the test file
        $CURLOUT = $STDOUT; # sends received data to stdout

        # Default the tool to a unit test with the same name as the test spec
        if($keywords{"unittest"} && !$tool) {
            $tool="unit$testnum";
        }

        if($tool =~ /^lib/) {
            $CMDLINE="$LIBDIR/$tool";
        }
        elsif($tool =~ /^unit/) {
            $CMDLINE="$UNITDIR/$tool";
        }

        if(! -f $CMDLINE) {
            logmsg "The tool set in the test case for this: '$tool' does not exist\n";
            timestampskippedevents($testnum);
            return -1;
        }
        $DBGCURL=$CMDLINE;
    }

    if($fail_due_event_based) {
        logmsg "This test cannot run event based\n";
        timestampskippedevents($testnum);
        return -1;
    }

    if($gdbthis) {
        # gdb is incompatible with valgrind, so disable it when debugging
        # Perhaps a better approach would be to run it under valgrind anyway
        # with --db-attach=yes or --vgdb=yes.
        $disablevalgrind=1;
    }

    my @stdintest = getpart("client", "stdin");

    if(@stdintest) {
        my $stdinfile="$LOGDIR/stdin-for-$testnum";

        my %hash = getpartattr("client", "stdin");
        if($hash{'nonewline'}) {
            # cut off the final newline from the final line of the stdin data
            chomp($stdintest[$#stdintest]);
        }

        writearray($stdinfile, \@stdintest);

        $cmdargs .= " <$stdinfile";
    }

    if(!$tool) {
        $CMDLINE="$CURL";
    }

    my $usevalgrind;
    if($valgrind && !$disablevalgrind) {
        my @valgrindoption = getpart("verify", "valgrind");
        if((!@valgrindoption) || ($valgrindoption[0] !~ /disable/)) {
            $usevalgrind = 1;
            my $valgrindcmd = "$valgrind ";
            $valgrindcmd .= "$valgrind_tool " if($valgrind_tool);
            $valgrindcmd .= "--quiet --leak-check=yes ";
            $valgrindcmd .= "--suppressions=$srcdir/valgrind.supp ";
           # $valgrindcmd .= "--gen-suppressions=all ";
            $valgrindcmd .= "--num-callers=16 ";
            $valgrindcmd .= "${valgrind_logfile}=$LOGDIR/valgrind$testnum";
            $CMDLINE = "$valgrindcmd $CMDLINE";
        }
    }

    $CMDLINE .= "$cmdargs >$STDOUT 2>$STDERR";

    if($verbose) {
        logmsg "$CMDLINE\n";
    }

    open(CMDLOG, ">", "$LOGDIR/$CURLLOG");
    print CMDLOG "$CMDLINE\n";
    close(CMDLOG);

    unlink("core");

    my $dumped_core;
    my $cmdres;

    if($gdbthis) {
        my $gdbinit = "$TESTDIR/gdbinit$testnum";
        open(GDBCMD, ">$LOGDIR/gdbcmd");
        print GDBCMD "set args $cmdargs\n";
        print GDBCMD "show args\n";
        print GDBCMD "source $gdbinit\n" if -e $gdbinit;
        close(GDBCMD);
    }

    # Flush output.
    $| = 1;

    # timestamp starting of test command
    $timetoolini{$testnum} = Time::HiRes::time();

    # run the command line we built
    if ($torture) {
        $cmdres = torture($CMDLINE,
                          $testnum,
                          "$gdb --directory $LIBDIR $DBGCURL -x $LOGDIR/gdbcmd");
    }
    elsif($gdbthis) {
        my $GDBW = ($gdbxwin) ? "-w" : "";
        runclient("$gdb --directory $LIBDIR $DBGCURL $GDBW -x $LOGDIR/gdbcmd");
        $cmdres=0; # makes it always continue after a debugged run
    }
    else {
        $cmdres = runclient("$CMDLINE");
        my $signal_num  = $cmdres & 127;
        $dumped_core = $cmdres & 128;

        if(!$anyway && ($signal_num || $dumped_core)) {
            $cmdres = 1000;
        }
        else {
            $cmdres >>= 8;
            $cmdres = (2000 + $signal_num) if($signal_num && !$cmdres);
        }
    }

    # timestamp finishing of test command
    $timetoolend{$testnum} = Time::HiRes::time();

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
            open(GDBCMD, ">$LOGDIR/gdbcmd2");
            print GDBCMD "bt\n";
            close(GDBCMD);
            runclient("$gdb --directory libtest -x $LOGDIR/gdbcmd2 -batch $DBGCURL core ");
     #       unlink("$LOGDIR/gdbcmd2");
        }
    }

    # If a server logs advisor read lock file exists, it is an indication
    # that the server has not yet finished writing out all its log files,
    # including server request log files used for protocol verification.
    # So, if the lock file exists the script waits here a certain amount
    # of time until the server removes it, or the given time expires.

    if($serverlogslocktimeout) {
        my $lockretry = $serverlogslocktimeout * 20;
        while((-f $SERVERLOGS_LOCK) && $lockretry--) {
            portable_sleep(0.05);
        }
        if(($lockretry < 0) &&
           ($serverlogslocktimeout >= $defserverlogslocktimeout)) {
            logmsg "Warning: server logs lock timeout ",
                   "($serverlogslocktimeout seconds) expired\n";
        }
    }

    # Test harness ssh server does not have this synchronization mechanism,
    # this implies that some ssh server based tests might need a small delay
    # once that the client command has run to avoid false test failures.
    #
    # gnutls-serv also lacks this synchronization mechanism, so gnutls-serv
    # based tests might need a small delay once that the client command has
    # run to avoid false test failures.

    portable_sleep($postcommanddelay) if($postcommanddelay);

    # timestamp removal of server logs advisor read lock
    $timesrvrlog{$testnum} = Time::HiRes::time();

    # test definition might instruct to stop some servers
    # stop also all servers relative to the given one

    my @killtestservers = getpart("client", "killserver");
    if(@killtestservers) {
        foreach my $server (@killtestservers) {
            chomp $server;
            if(stopserver($server)) {
                return 1; # normal error if asked to fail on unexpected alive
            }
        }
    }

    # run the postcheck command
    my @postcheck= getpart("client", "postcheck");
    if(@postcheck) {
        $cmd = join("", @postcheck);
        chomp $cmd;
        if($cmd) {
            logmsg "postcheck $cmd\n" if($verbose);
            my $rc = runclient("$cmd");
            # Must run the postcheck command in torture mode in order
            # to clean up, but the result can't be relied upon.
            if($rc != 0 && !$torture) {
                logmsg " postcheck FAILED\n";
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return $errorreturncode;
            }
        }
    }

    # restore environment variables that were modified
    if(%oldenv) {
        foreach my $var (keys %oldenv) {
            if($oldenv{$var} eq 'notset') {
                delete $ENV{$var} if($ENV{$var});
            }
            else {
                $ENV{$var} = "$oldenv{$var}";
            }
        }
    }

    # Skip all the verification on torture tests
    if ($torture) {
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();
        return $cmdres;
    }

    my @err = getpart("verify", "errorcode");
    my $errorcode = $err[0] || "0";
    my $ok="";
    my $res;
    chomp $errorcode;
    if (@validstdout) {
        # verify redirected stdout
        my @actual = loadarray($STDOUT);

        # what parts to cut off from stdout
        my @stripfile = getpart("verify", "stripfile");

        foreach my $strip (@stripfile) {
            chomp $strip;
            my @newgen;
            for(@actual) {
                eval $strip;
                if($_) {
                    push @newgen, $_;
                }
            }
            # this is to get rid of array entries that vanished (zero
            # length) because of replacements
            @actual = @newgen;
        }

        # get all attributes
        my %hash = getpartattr("verify", "stdout");

        # get the mode attribute
        my $filemode=$hash{'mode'};
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            map s/\r\n/\n/g, @validstdout;
            map s/\n/\r\n/g, @validstdout;
        }

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($validstdout[$#validstdout]);
        }

        if($hash{'crlf'} ||
           ($has_hyper && ($keywords{"HTTP"}
                           || $keywords{"HTTPS"}))) {
            map subNewlines(0, \$_), @validstdout;
        }

        $res = compare($testnum, $testname, "stdout", \@actual, \@validstdout);
        if($res) {
            return $errorreturncode;
        }
        $ok .= "s";
    }
    else {
        $ok .= "-"; # stdout not checked
    }

    if (@validstderr) {
        # verify redirected stderr
        my @actual = loadarray($STDERR);

        # what parts to cut off from stderr
        my @stripfile = getpart("verify", "stripfile");

        foreach my $strip (@stripfile) {
            chomp $strip;
            my @newgen;
            for(@actual) {
                eval $strip;
                if($_) {
                    push @newgen, $_;
                }
            }
            # this is to get rid of array entries that vanished (zero
            # length) because of replacements
            @actual = @newgen;
        }

        # get all attributes
        my %hash = getpartattr("verify", "stderr");

        # get the mode attribute
        my $filemode=$hash{'mode'};
        if($filemode && ($filemode eq "text") && $has_hyper) {
            # text mode check in hyper-mode. Sometimes necessary if the stderr
            # data *looks* like HTTP and thus has gotten CRLF newlines
            # mistakenly
            map s/\r\n/\n/g, @validstderr;
        }
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            map s/\r\n/\n/g, @validstderr;
            map s/\n/\r\n/g, @validstderr;
        }

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($validstderr[$#validstderr]);
        }

        $res = compare($testnum, $testname, "stderr", \@actual, \@validstderr);
        if($res) {
            return $errorreturncode;
        }
        $ok .= "r";
    }
    else {
        $ok .= "-"; # stderr not checked
    }

    if(@protocol) {
        # Verify the sent request
        my @out = loadarray($SERVERIN);

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

        if($hash{'crlf'}) {
            map subNewlines(1, \$_), @protstrip;
        }

        if((!$out[0] || ($out[0] eq "")) && $protstrip[0]) {
            logmsg "\n $testnum: protocol FAILED!\n".
                " There was no content at all in the file $SERVERIN.\n".
                " Server glitch? Total curl failure? Returned: $cmdres\n";
            return $errorreturncode;
        }

        $res = compare($testnum, $testname, "protocol", \@out, \@protstrip);
        if($res) {
            return $errorreturncode;
        }

        $ok .= "p";

    }
    else {
        $ok .= "-"; # protocol not checked
    }

    if(!$replyattr{'nocheck'} && (@reply || $replyattr{'sendzero'})) {
        # verify the received data
        my @out = loadarray($CURLOUT);
        $res = compare($testnum, $testname, "data", \@out, \@reply);
        if ($res) {
            return $errorreturncode;
        }
        $ok .= "d";
    }
    else {
        $ok .= "-"; # data not checked
    }

    if(@upload) {
        # verify uploaded data
        my @out = loadarray("$LOGDIR/upload.$testnum");

        # what parts to cut off from the upload
        my @strippart = getpart("verify", "strippart");
        my $strip;
        for $strip (@strippart) {
            chomp $strip;
            for(@out) {
                eval $strip;
            }
        }

        $res = compare($testnum, $testname, "upload", \@out, \@upload);
        if ($res) {
            return $errorreturncode;
        }
        $ok .= "u";
    }
    else {
        $ok .= "-"; # upload not checked
    }

    if(@proxyprot) {
        # Verify the sent proxy request
        my @out = loadarray($PROXYIN);

        # what to cut off from the live protocol sent by curl, we use the
        # same rules as for <protocol>
        my @strip = getpart("verify", "strip");

        my @protstrip=@proxyprot;

        # check if there's any attributes on the verify/protocol section
        my %hash = getpartattr("verify", "proxy");

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

        if($hash{'crlf'} ||
           ($has_hyper && ($keywords{"HTTP"} || $keywords{"HTTPS"}))) {
            map subNewlines(0, \$_), @protstrip;
        }

        $res = compare($testnum, $testname, "proxy", \@out, \@protstrip);
        if($res) {
            return $errorreturncode;
        }

        $ok .= "P";

    }
    else {
        $ok .= "-"; # protocol not checked
    }

    my $outputok;
    for my $partsuffix (('', '1', '2', '3', '4')) {
        my @outfile=getpart("verify", "file".$partsuffix);
        if(@outfile || partexists("verify", "file".$partsuffix) ) {
            # we're supposed to verify a dynamically generated file!
            my %hash = getpartattr("verify", "file".$partsuffix);

            my $filename=$hash{'name'};
            if(!$filename) {
                logmsg "ERROR: section verify=>file$partsuffix ".
                       "has no name attribute\n";
                stopservers($verbose);
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return -1;
            }
            my @generated=loadarray($filename);

            # what parts to cut off from the file
            my @stripfile = getpart("verify", "stripfile".$partsuffix);

            my $filemode=$hash{'mode'};
            if($filemode && ($filemode eq "text") && $has_textaware) {
                # text mode when running on windows: fix line endings
                map s/\r\n/\n/g, @outfile;
                map s/\n/\r\n/g, @outfile;
            }
            if($hash{'crlf'} ||
               ($has_hyper && ($keywords{"HTTP"}
                               || $keywords{"HTTPS"}))) {
                map subNewlines(0, \$_), @outfile;
            }

            my $strip;
            for $strip (@stripfile) {
                chomp $strip;
                my @newgen;
                for(@generated) {
                    eval $strip;
                    if($_) {
                        push @newgen, $_;
                    }
                }
                # this is to get rid of array entries that vanished (zero
                # length) because of replacements
                @generated = @newgen;
            }

            $res = compare($testnum, $testname, "output ($filename)",
                           \@generated, \@outfile);
            if($res) {
                return $errorreturncode;
            }

            $outputok = 1; # output checked
        }
    }
    $ok .= ($outputok) ? "o" : "-"; # output checked or not

    # verify SOCKS proxy details
    my @socksprot = getpart("verify", "socks");
    if(@socksprot) {
        # Verify the sent SOCKS proxy details
        my @out = loadarray($SOCKSIN);
        $res = compare($testnum, $testname, "socks", \@out, \@socksprot);
        if($res) {
            return $errorreturncode;
        }
    }

    # accept multiple comma-separated error codes
    my @splerr = split(/ *, */, $errorcode);
    my $errok;
    foreach my $e (@splerr) {
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
            logmsg sprintf("\n%s returned $cmdres, when expecting %s\n",
                           (!$tool)?"curl":$tool, $errorcode);
        }
        logmsg " exit FAILED\n";
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();
        return $errorreturncode;
    }

    if($has_memory_tracking) {
        if(! -f $memdump) {
            logmsg "\n** ALERT! memory tracking with no output file?\n"
                if(!$cmdtype eq "perl");
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
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return $errorreturncode;
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
        if($usevalgrind) {
            unless(opendir(DIR, "$LOGDIR")) {
                logmsg "ERROR: unable to read $LOGDIR\n";
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return $errorreturncode;
            }
            my @files = readdir(DIR);
            closedir(DIR);
            my $vgfile;
            foreach my $file (@files) {
                if($file =~ /^valgrind$testnum(\..*|)$/) {
                    $vgfile = $file;
                    last;
                }
            }
            if(!$vgfile) {
                logmsg "ERROR: valgrind log file missing for test $testnum\n";
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return $errorreturncode;
            }
            my @e = valgrindparse("$LOGDIR/$vgfile");
            if(@e && $e[0]) {
                if($automakestyle) {
                    logmsg "FAIL: $testnum - $testname - valgrind\n";
                }
                else {
                    logmsg " valgrind ERROR ";
                    logmsg @e;
                }
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return $errorreturncode;
            }
            $ok .= "v";
        }
        else {
            if($verbose && !$disablevalgrind) {
                logmsg " valgrind SKIPPED\n";
            }
            $ok .= "-"; # skipped
        }
    }
    else {
        $ok .= "-"; # valgrind not checked
    }
    # add 'E' for event-based
    $ok .= $evbased ? "E" : "-";

    logmsg "$ok " if(!$short);

    # timestamp test result verification end
    $timevrfyend{$testnum} = Time::HiRes::time();

    my $sofar= time()-$start;
    my $esttotal = $sofar/$count * $total;
    my $estleft = $esttotal - $sofar;
    my $left=sprintf("remaining: %02d:%02d",
                     $estleft/60,
                     $estleft%60);
    my $took = $timevrfyend{$testnum} - $timeprepini{$testnum};
    my $duration = sprintf("duration: %02d:%02d",
                           $sofar/60, $sofar%60);
    if(!$automakestyle) {
        logmsg sprintf("OK (%-3d out of %-3d, %s, took %.3fs, %s)\n",
                       $count, $total, $left, $took, $duration);
    }
    else {
        logmsg "PASS: $testnum - $testname\n";
    }

    if($errorreturncode==2) {
        logmsg "Warning: test$testnum result is ignored, but passed!\n";
    }

    return 0;
}

#######################################################################
# Stop all running test servers
#
sub stopservers {
    my $verbose = $_[0];
    #
    # kill sockfilter processes for all pingpong servers
    #
    killallsockfilters($verbose);
    #
    # kill all server pids from %run hash clearing them
    #
    my $pidlist;
    foreach my $server (keys %run) {
        if($run{$server}) {
            if($verbose) {
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
    killpid($verbose, $pidlist);
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
            killpid($verbose, $pid);
        }
        unlink($pidfile) if(-f $pidfile);
    }

    return $result;
}

#######################################################################
# startservers() starts all the named servers
#
# Returns: string with error reason or blank for success
#
sub startservers {
    my @what = @_;
    my ($pid, $pid2);
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
                    return "failed stopping unresponsive ".uc($what)." server";
                }
            }
            if(!$run{$what}) {
                ($pid, $pid2) = runpingpongserver($what, "", $verbose);
                if($pid <= 0) {
                    return "failed starting ". uc($what) ." server";
                }
                printf ("* pid $what => %d %d\n", $pid, $pid2) if($verbose);
                $run{$what}="$pid $pid2";
            }
        }
        elsif($what eq "ftp-ipv6") {
            if($torture && $run{'ftp-ipv6'} &&
               !responsive_pingpong_server("ftp", "", $verbose, "ipv6")) {
                if(stopserver('ftp-ipv6')) {
                    return "failed stopping unresponsive FTP-IPv6 server";
                }
            }
            if(!$run{'ftp-ipv6'}) {
                ($pid, $pid2) = runpingpongserver("ftp", "", $verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting FTP-IPv6 server";
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
                    return "failed stopping unresponsive GOPHER server";
                }
            }
            if(!$run{'gopher'}) {
                ($pid, $pid2, $PORT{'gopher'}) =
                    runhttpserver("gopher", $verbose, 0);
                if($pid <= 0) {
                    return "failed starting GOPHER server";
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
                    return "failed stopping unresponsive GOPHER-IPv6 server";
                }
            }
            if(!$run{'gopher-ipv6'}) {
                ($pid, $pid2, $PORT{"gopher6"}) =
                    runhttpserver("gopher", $verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting GOPHER-IPv6 server";
                }
                logmsg sprintf("* pid gopher-ipv6 => %d %d\n", $pid,
                               $pid2) if($verbose);
                $run{'gopher-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "http/3") {
            if(!$run{'http/3'}) {
                ($pid, $pid2, $PORT{"http3"}) = runhttp3server($verbose);
                if($pid <= 0) {
                    return "failed starting HTTP/3 server";
                }
                logmsg sprintf ("* pid http/3 => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http/3'}="$pid $pid2";
            }
        }
        elsif($what eq "http/2") {
            if(!$run{'http/2'}) {
                ($pid, $pid2, $PORT{"http2"}, $PORT{"http2tls"}) =
                    runhttp2server($verbose);
                if($pid <= 0) {
                    return "failed starting HTTP/2 server";
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
                    return "failed stopping unresponsive HTTP server";
                }
            }
            if(!$run{'http'}) {
                ($pid, $pid2, $PORT{'http'}) =
                    runhttpserver("http", $verbose, 0);
                if($pid <= 0) {
                    return "failed starting HTTP server";
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
                    return "failed stopping unresponsive HTTP-proxy server";
                }
            }
            if(!$run{'http-proxy'}) {
                ($pid, $pid2, $PORT{"httpproxy"}) =
                    runhttpserver("http", $verbose, "proxy");
                if($pid <= 0) {
                    return "failed starting HTTP-proxy server";
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
                    return "failed stopping unresponsive HTTP-IPv6 server";
                }
            }
            if(!$run{'http-ipv6'}) {
                ($pid, $pid2, $PORT{"http6"}) =
                    runhttpserver("http", $verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting HTTP-IPv6 server";
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
                    return "failed stopping unresponsive RTSP server";
                }
            }
            if(!$run{'rtsp'}) {
                ($pid, $pid2, $PORT{'rtsp'}) = runrtspserver($verbose);
                if($pid <= 0) {
                    return "failed starting RTSP server";
                }
                printf ("* pid rtsp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'rtsp'}="$pid $pid2";
            }
        }
        elsif($what eq "rtsp-ipv6") {
            if($torture && $run{'rtsp-ipv6'} &&
               !responsive_rtsp_server($verbose, "ipv6")) {
                if(stopserver('rtsp-ipv6')) {
                    return "failed stopping unresponsive RTSP-IPv6 server";
                }
            }
            if(!$run{'rtsp-ipv6'}) {
                ($pid, $pid2, $PORT{'rtsp6'}) = runrtspserver($verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting RTSP-IPv6 server";
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
                return "no stunnel";
            }
            if($runcert{$what} && ($runcert{$what} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver($what)) {
                    return "failed stopping $what server with different cert";
                }
            }
            if($torture && $run{$cproto} &&
               !responsive_pingpong_server($cproto, "", $verbose)) {
                if(stopserver($cproto)) {
                    return "failed stopping unresponsive $cproto server";
                }
            }
            if(!$run{$cproto}) {
                ($pid, $pid2) = runpingpongserver($cproto, "", $verbose);
                if($pid <= 0) {
                    return "failed starting $cproto server";
                }
                printf ("* pid $cproto => %d %d\n", $pid, $pid2) if($verbose);
                $run{$cproto}="$pid $pid2";
            }
            if(!$run{$what}) {
                ($pid, $pid2, $PORT{$what}) =
                    runsecureserver($verbose, "", $certfile, $what,
                                    protoport($cproto));
                if($pid <= 0) {
                    return "failed starting $what server (stunnel)";
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
                return "no stunnel";
            }
            if($runcert{'https'} && ($runcert{'https'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('https')) {
                    return "failed stopping HTTPS server with different cert";
                }
            }
            if($torture && $run{'http'} &&
               !responsive_http_server("http", $verbose, 0,
                                       protoport('http'))) {
                if(stopserver('http')) {
                    return "failed stopping unresponsive HTTP server";
                }
            }
            if(!$run{'http'}) {
                ($pid, $pid2, $PORT{'http'}) =
                    runhttpserver("http", $verbose, 0);
                if($pid <= 0) {
                    return "failed starting HTTP server";
                }
                printf ("* pid http => %d %d\n", $pid, $pid2) if($verbose);
                $run{'http'}="$pid $pid2";
            }
            if(!$run{'https'}) {
                ($pid, $pid2, $PORT{'https'}) =
                    runhttpsserver($verbose, "https", "", $certfile);
                if($pid <= 0) {
                    return "failed starting HTTPS server (stunnel)";
                }
                logmsg sprintf("* pid https => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'https'}="$pid $pid2";
            }
        }
        elsif($what eq "gophers") {
            if(!$stunnel) {
                # we can't run TLS tests without stunnel
                return "no stunnel";
            }
            if($runcert{'gophers'} && ($runcert{'gophers'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('gophers')) {
                    return "failed stopping GOPHERS server with different crt";
                }
            }
            if($torture && $run{'gopher'} &&
               !responsive_http_server("gopher", $verbose, 0,
                                       protoport('gopher'))) {
                if(stopserver('gopher')) {
                    return "failed stopping unresponsive GOPHER server";
                }
            }
            if(!$run{'gopher'}) {
                my $port;
                ($pid, $pid2, $port) =
                    runhttpserver("gopher", $verbose, 0);
                $PORT{'gopher'} = $port;
                if($pid <= 0) {
                    return "failed starting GOPHER server";
                }
                printf ("* pid gopher => %d %d\n", $pid, $pid2) if($verbose);
                print "GOPHERPORT => $port\n" if($verbose);
                $run{'gopher'}="$pid $pid2";
            }
            if(!$run{'gophers'}) {
                my $port;
                ($pid, $pid2, $port) =
                    runhttpsserver($verbose, "gophers", "", $certfile);
                $PORT{'gophers'} = $port;
                if($pid <= 0) {
                    return "failed starting GOPHERS server (stunnel)";
                }
                logmsg sprintf("* pid gophers => %d %d\n", $pid, $pid2)
                    if($verbose);
                print "GOPHERSPORT => $port\n" if($verbose);
                $run{'gophers'}="$pid $pid2";
            }
        }
        elsif($what eq "https-proxy") {
            if(!$stunnel) {
                # we can't run https-proxy tests without stunnel
                return "no stunnel";
            }
            if($runcert{'https-proxy'} &&
               ($runcert{'https-proxy'} ne $certfile)) {
                # stop server when running and using a different cert
                if(stopserver('https-proxy')) {
                    return "failed stopping HTTPS-proxy with different cert";
                }
            }

            # we front the http-proxy with stunnel so we need to make sure the
            # proxy runs as well
            my $f = startservers("http-proxy");
            if($f) {
                return $f;1
            }

            if(!$run{'https-proxy'}) {
                ($pid, $pid2, $PORT{"httpsproxy"}) =
                    runhttpsserver($verbose, "https", "proxy", $certfile);
                if($pid <= 0) {
                    return "failed starting HTTPS-proxy (stunnel)";
                }
                logmsg sprintf("* pid https-proxy => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'https-proxy'}="$pid $pid2";
            }
        }
        elsif($what eq "httptls") {
            if(!$httptlssrv) {
                # for now, we can't run http TLS-EXT tests without gnutls-serv
                return "no gnutls-serv (with SRP support)";
            }
            if($torture && $run{'httptls'} &&
               !responsive_httptls_server($verbose, "IPv4")) {
                if(stopserver('httptls')) {
                    return "failed stopping unresponsive HTTPTLS server";
                }
            }
            if(!$run{'httptls'}) {
                ($pid, $pid2, $PORT{'httptls'}) =
                    runhttptlsserver($verbose, "IPv4");
                if($pid <= 0) {
                    return "failed starting HTTPTLS server (gnutls-serv)";
                }
                logmsg sprintf("* pid httptls => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'httptls'}="$pid $pid2";
            }
        }
        elsif($what eq "httptls-ipv6") {
            if(!$httptlssrv) {
                # for now, we can't run http TLS-EXT tests without gnutls-serv
                return "no gnutls-serv";
            }
            if($torture && $run{'httptls-ipv6'} &&
               !responsive_httptls_server($verbose, "ipv6")) {
                if(stopserver('httptls-ipv6')) {
                    return "failed stopping unresponsive HTTPTLS-IPv6 server";
                }
            }
            if(!$run{'httptls-ipv6'}) {
                ($pid, $pid2, $PORT{"httptls6"}) =
                    runhttptlsserver($verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting HTTPTLS-IPv6 server (gnutls-serv)";
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
                    return "failed stopping unresponsive TFTP server";
                }
            }
            if(!$run{'tftp'}) {
                ($pid, $pid2, $PORT{'tftp'}) =
                    runtftpserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting TFTP server";
                }
                printf ("* pid tftp => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp'}="$pid $pid2";
            }
        }
        elsif($what eq "tftp-ipv6") {
            if($torture && $run{'tftp-ipv6'} &&
               !responsive_tftp_server("", $verbose, "ipv6")) {
                if(stopserver('tftp-ipv6')) {
                    return "failed stopping unresponsive TFTP-IPv6 server";
                }
            }
            if(!$run{'tftp-ipv6'}) {
                ($pid, $pid2, $PORT{'tftp6'}) =
                    runtftpserver("", $verbose, "ipv6");
                if($pid <= 0) {
                    return "failed starting TFTP-IPv6 server";
                }
                printf("* pid tftp-ipv6 => %d %d\n", $pid, $pid2) if($verbose);
                $run{'tftp-ipv6'}="$pid $pid2";
            }
        }
        elsif($what eq "sftp" || $what eq "scp") {
            if(!$run{'ssh'}) {
                ($pid, $pid2, $PORT{'ssh'}) = runsshserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting SSH server";
                }
                printf ("* pid ssh => %d %d\n", $pid, $pid2) if($verbose);
                $run{'ssh'}="$pid $pid2";
            }
        }
        elsif($what eq "socks4" || $what eq "socks5" ) {
            if(!$run{'socks'}) {
                ($pid, $pid2, $PORT{"socks"}) = runsocksserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting socks server";
                }
                printf ("* pid socks => %d %d\n", $pid, $pid2) if($verbose);
                $run{'socks'}="$pid $pid2";
            }
        }
        elsif($what eq "socks5unix") {
            if(!$run{'socks5unix'}) {
                ($pid, $pid2) = runsocksserver("2", $verbose, "", "unix");
                if($pid <= 0) {
                    return "failed starting socks5unix server";
                }
                printf ("* pid socks5unix => %d %d\n", $pid, $pid2) if($verbose);
                $run{'socks5unix'}="$pid $pid2";
            }
        }
        elsif($what eq "mqtt" ) {
            if(!$run{'mqtt'}) {
                ($pid, $pid2) = runmqttserver("", $verbose);
                if($pid <= 0) {
                    return "failed starting mqtt server";
                }
                printf ("* pid mqtt => %d %d\n", $pid, $pid2) if($verbose);
                $run{'mqtt'}="$pid $pid2";
            }
        }
        elsif($what eq "http-unix") {
            if($torture && $run{'http-unix'} &&
               !responsive_http_server("http", $verbose, "unix", $HTTPUNIXPATH)) {
                if(stopserver('http-unix')) {
                    return "failed stopping unresponsive HTTP-unix server";
                }
            }
            if(!$run{'http-unix'}) {
                my $unused;
                ($pid, $pid2, $unused) =
                    runhttpserver("http", $verbose, "unix", $HTTPUNIXPATH);
                if($pid <= 0) {
                    return "failed starting HTTP-unix server";
                }
                logmsg sprintf("* pid http-unix => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'http-unix'}="$pid $pid2";
            }
        }
        elsif($what eq "dict") {
            if(!$run{'dict'}) {
                ($pid, $pid2, $PORT{"dict"}) = rundictserver($verbose, "");
                if($pid <= 0) {
                    return "failed starting DICT server";
                }
                logmsg sprintf ("* pid DICT => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'dict'}="$pid $pid2";
            }
        }
        elsif($what eq "smb") {
            if(!$run{'smb'}) {
                ($pid, $pid2, $PORT{"smb"}) = runsmbserver($verbose, "");
                if($pid <= 0) {
                    return "failed starting SMB server";
                }
                logmsg sprintf ("* pid SMB => %d %d\n", $pid, $pid2)
                    if($verbose);
                $run{'smb'}="$pid $pid2";
            }
        }
        elsif($what eq "telnet") {
            if(!$run{'telnet'}) {
                ($pid, $pid2, $PORT{"telnet"}) =
                    runnegtelnetserver($verbose, "");
                if($pid <= 0) {
                    return "failed starting neg TELNET server";
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

    my @what = getpart("client", "server");

    if(!$what[0]) {
        warn "Test case $testnum has no server(s) specified";
        return "no server specified";
    }

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
                        return "curl lacks $tlsext support";
                    }
                    else {
                        return "curl lacks $server server support";
                    }
                }
            }
            $what[$i] = "$server$lnrest" if($tlsext);
        }
    }

    return &startservers(@what);
}

#######################################################################
# runtimestats displays test-suite run time statistics
#
sub runtimestats {
    my $lasttest = $_[0];

    return if(not $timestats);

    logmsg "\nTest suite total running time breakdown per task...\n\n";

    my @timesrvr;
    my @timeprep;
    my @timetool;
    my @timelock;
    my @timevrfy;
    my @timetest;
    my $timesrvrtot = 0.0;
    my $timepreptot = 0.0;
    my $timetooltot = 0.0;
    my $timelocktot = 0.0;
    my $timevrfytot = 0.0;
    my $timetesttot = 0.0;
    my $counter;

    for my $testnum (1 .. $lasttest) {
        if($timesrvrini{$testnum}) {
            $timesrvrtot += $timesrvrend{$testnum} - $timesrvrini{$testnum};
            $timepreptot +=
                (($timetoolini{$testnum} - $timeprepini{$testnum}) -
                 ($timesrvrend{$testnum} - $timesrvrini{$testnum}));
            $timetooltot += $timetoolend{$testnum} - $timetoolini{$testnum};
            $timelocktot += $timesrvrlog{$testnum} - $timetoolend{$testnum};
            $timevrfytot += $timevrfyend{$testnum} - $timesrvrlog{$testnum};
            $timetesttot += $timevrfyend{$testnum} - $timeprepini{$testnum};
            push @timesrvr, sprintf("%06.3f  %04d",
                $timesrvrend{$testnum} - $timesrvrini{$testnum}, $testnum);
            push @timeprep, sprintf("%06.3f  %04d",
                ($timetoolini{$testnum} - $timeprepini{$testnum}) -
                ($timesrvrend{$testnum} - $timesrvrini{$testnum}), $testnum);
            push @timetool, sprintf("%06.3f  %04d",
                $timetoolend{$testnum} - $timetoolini{$testnum}, $testnum);
            push @timelock, sprintf("%06.3f  %04d",
                $timesrvrlog{$testnum} - $timetoolend{$testnum}, $testnum);
            push @timevrfy, sprintf("%06.3f  %04d",
                $timevrfyend{$testnum} - $timesrvrlog{$testnum}, $testnum);
            push @timetest, sprintf("%06.3f  %04d",
                $timevrfyend{$testnum} - $timeprepini{$testnum}, $testnum);
        }
    }

    {
        no warnings 'numeric';
        @timesrvr = sort { $b <=> $a } @timesrvr;
        @timeprep = sort { $b <=> $a } @timeprep;
        @timetool = sort { $b <=> $a } @timetool;
        @timelock = sort { $b <=> $a } @timelock;
        @timevrfy = sort { $b <=> $a } @timevrfy;
        @timetest = sort { $b <=> $a } @timetest;
    }

    logmsg "Spent ". sprintf("%08.3f ", $timesrvrtot) .
           "seconds starting and verifying test harness servers.\n";
    logmsg "Spent ". sprintf("%08.3f ", $timepreptot) .
           "seconds reading definitions and doing test preparations.\n";
    logmsg "Spent ". sprintf("%08.3f ", $timetooltot) .
           "seconds actually running test tools.\n";
    logmsg "Spent ". sprintf("%08.3f ", $timelocktot) .
           "seconds awaiting server logs lock removal.\n";
    logmsg "Spent ". sprintf("%08.3f ", $timevrfytot) .
           "seconds verifying test results.\n";
    logmsg "Spent ". sprintf("%08.3f ", $timetesttot) .
           "seconds doing all of the above.\n";

    $counter = 25;
    logmsg "\nTest server starting and verification time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timesrvr) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    $counter = 10;
    logmsg "\nTest definition reading and preparation time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timeprep) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    $counter = 25;
    logmsg "\nTest tool execution time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timetool) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    $counter = 15;
    logmsg "\nTest server logs lock removal time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timelock) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    $counter = 10;
    logmsg "\nTest results verification time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timevrfy) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    $counter = 50;
    logmsg "\nTotal time per test ".
        sprintf("(%s)...\n\n", (not $fullstats)?"top $counter":"full");
    logmsg "-time-  test\n";
    logmsg "------  ----\n";
    foreach my $txt (@timetest) {
        last if((not $fullstats) && (not $counter--));
        logmsg "$txt\n";
    }

    logmsg "\n";
}

#######################################################################
# Check options to this test program
#

# Special case for CMake: replace '$TFLAGS' by the contents of the
# environment variable (if any).
if(@ARGV && $ARGV[-1] eq '$TFLAGS') {
    pop @ARGV;
    push(@ARGV, split(' ', $ENV{'TFLAGS'})) if defined($ENV{'TFLAGS'});
}

my $number=0;
my $fromnum=-1;
my @testthis;
while(@ARGV) {
    if ($ARGV[0] eq "-v") {
        # verbose output
        $verbose=1;
    }
    elsif ($ARGV[0] eq "-c") {
        # use this path to curl instead of default
        $DBGCURL=$CURL="\"$ARGV[1]\"";
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-vc") {
        # use this path to a curl used to verify servers

        # Particularly useful when you introduce a crashing bug somewhere in
        # the development version as then it won't be able to run any tests
        # since it can't verify the servers!

        $VCURL="\"$ARGV[1]\"";
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-ac") {
        # use this curl only to talk to APIs (currently only CI test APIs)
        $ACURL="\"$ARGV[1]\"";
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-d") {
        # have the servers display protocol output
        $debugprotocol=1;
    }
    elsif($ARGV[0] eq "-e") {
        # run the tests cases event based if possible
        $run_event_based=1;
    }
    elsif($ARGV[0] eq "-f") {
        # force - run the test case even if listed in DISABLED
        $run_disabeled=1;
    }
    elsif($ARGV[0] eq "-E") {
        # load additional reasons to skip tests
        shift @ARGV;
        my $exclude_file = $ARGV[0];
        open(my $fd, "<", $exclude_file) or die "Couldn't open '$exclude_file': $!";
        while(my $line = <$fd>) {
            next if ($line =~ /^#/);
            chomp $line;
            my ($type, $patterns, $skip_reason) = split(/\s*:\s*/, $line, 3);

            die "Unsupported type: $type\n" if($type !~ /^keyword|test|tool$/);

            foreach my $pattern (split(/,/, $patterns)) {
                if($type =~ /^test$/) {
                    # Strip leading zeros in the test number
                    $pattern = int($pattern);
                }
                $custom_skip_reasons{$type}{$pattern} = $skip_reason;
            }
        }
        close($fd);
    }
    elsif ($ARGV[0] eq "-g") {
        # run this test with gdb
        $gdbthis=1;
    }
    elsif ($ARGV[0] eq "-gw") {
        # run this test with windowed gdb
        $gdbthis=1;
        $gdbxwin=1;
    }
    elsif($ARGV[0] eq "-s") {
        # short output
        $short=1;
    }
    elsif($ARGV[0] eq "-am") {
        # automake-style output
        $short=1;
        $automakestyle=1;
    }
    elsif($ARGV[0] eq "-n") {
        # no valgrind
        undef $valgrind;
    }
    elsif($ARGV[0] eq "--no-debuginfod") {
        # disable the valgrind debuginfod functionality
        $no_debuginfod = 1;
    }
    elsif ($ARGV[0] eq "-R") {
        # execute in scrambled order
        $scrambleorder=1;
    }
    elsif($ARGV[0] =~ /^-t(.*)/) {
        # torture
        $torture=1;
        my $xtra = $1;

        if($xtra =~ s/(\d+)$//) {
            $tortalloc = $1;
        }
    }
    elsif($ARGV[0] =~ /--shallow=(\d+)/) {
        # Fail no more than this amount per tests when running
        # torture.
        my ($num)=($1);
        $shallow=$num;
    }
    elsif($ARGV[0] =~ /--repeat=(\d+)/) {
        # Repeat-run the given tests this many times
        $repeat = $1;
    }
    elsif($ARGV[0] =~ /--seed=(\d+)/) {
        # Set a fixed random seed (used for -R and --shallow)
        $randseed = $1;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-o") {
        shift @ARGV;
        if ($ARGV[0] =~ /^(\w+)=([\w.:\/\[\]-]+)$/) {
            my ($variable, $value) = ($1, $2);
            eval "\$$variable='$value'" or die "Failed to set \$$variable to $value: $@";
        } else {
            die "Failed to parse '-o $ARGV[0]'. May contain unexpected characters.\n";
        }
    }
    elsif($ARGV[0] eq "-p") {
        $postmortem=1;
    }
    elsif($ARGV[0] eq "-P") {
        shift @ARGV;
        $use_external_proxy=1;
        $proxy_address=$ARGV[0];
    }
    elsif($ARGV[0] eq "-L") {
        # require additional library file
        shift @ARGV;
        require $ARGV[0];
    }
    elsif($ARGV[0] eq "-l") {
        # lists the test case names only
        $listonly=1;
    }
    elsif($ARGV[0] eq "-k") {
        # keep stdout and stderr files after tests
        $keepoutfiles=1;
    }
    elsif($ARGV[0] eq "-r") {
        # run time statistics needs Time::HiRes
        if($Time::HiRes::VERSION) {
            keys(%timeprepini) = 1000;
            keys(%timesrvrini) = 1000;
            keys(%timesrvrend) = 1000;
            keys(%timetoolini) = 1000;
            keys(%timetoolend) = 1000;
            keys(%timesrvrlog) = 1000;
            keys(%timevrfyend) = 1000;
            $timestats=1;
            $fullstats=0;
        }
    }
    elsif($ARGV[0] eq "-rf") {
        # run time statistics needs Time::HiRes
        if($Time::HiRes::VERSION) {
            keys(%timeprepini) = 1000;
            keys(%timesrvrini) = 1000;
            keys(%timesrvrend) = 1000;
            keys(%timetoolini) = 1000;
            keys(%timetoolend) = 1000;
            keys(%timesrvrlog) = 1000;
            keys(%timevrfyend) = 1000;
            $timestats=1;
            $fullstats=1;
        }
    }
    elsif($ARGV[0] eq "-rm") {
        # force removal of files by killing locking processes
        $clearlocks=1;
    }
    elsif($ARGV[0] eq "-u") {
        # error instead of warning on server unexpectedly alive
        $err_unexpected=1;
    }
    elsif(($ARGV[0] eq "-h") || ($ARGV[0] eq "--help")) {
        # show help text
        print <<EOHELP
Usage: runtests.pl [options] [test selection(s)]
  -a       continue even if a test fails
  -ac path use this curl only to talk to APIs (currently only CI test APIs)
  -am      automake style output PASS/FAIL: [number] [name]
  -c path  use this curl executable
  -d       display server debug info
  -e       event-based execution
  -E file  load the specified file to exclude certain tests
  -f       forcibly run even if disabled
  -g       run the test case with gdb
  -gw      run the test case with gdb as a windowed application
  -h       this help text
  -k       keep stdout and stderr files present after tests
  -L path  require an additional perl library file to replace certain functions
  -l       list all test case names/descriptions
  -n       no valgrind
  --no-debuginfod disable the valgrind debuginfod functionality
  -o variable=value set internal variable to the specified value
  -P proxy use the specified proxy
  -p       print log file contents when a test fails
  -R       scrambled order (uses the random seed, see --seed)
  -r       run time statistics
  -rf      full run time statistics
  -rm      force removal of files by killing locking processes (Windows only)
  --repeat=[num] run the given tests this many times
  -s       short output
  --seed=[num] set the random seed to a fixed number
  --shallow=[num] randomly makes the torture tests "thinner"
  -t[N]    torture (simulate function failures); N means fail Nth function
  -u       error instead of warning on server unexpectedly alive
  -v       verbose output
  -vc path use this curl only to verify the existing servers
  [num]    like "5 6 9" or " 5 to 22 " to run those tests only
  [!num]   like "!5 !6 !9" to disable those tests
  [~num]   like "~5 ~6 ~9" to ignore the result of those tests
  [keyword] like "IPv6" to select only tests containing the key word
  [!keyword] like "!cookies" to disable any tests containing the key word
  [~keyword] like "~cookies" to ignore results of tests containing key word
EOHELP
    ;
        exit;
    }
    elsif($ARGV[0] =~ /^(\d+)/) {
        $number = $1;
        if($fromnum >= 0) {
            for my $n ($fromnum .. $number) {
                push @testthis, $n;
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
    elsif($ARGV[0] =~ /^~(\d+)/) {
        $fromnum = -1;
        $ignored{$1}=$1;
    }
    elsif($ARGV[0] =~ /^!(.+)/) {
        $disabled_keywords{lc($1)}=$1;
    }
    elsif($ARGV[0] =~ /^~(.+)/) {
        $ignored_keywords{lc($1)}=$1;
    }
    elsif($ARGV[0] =~ /^([-[{a-zA-Z].*)/) {
        $enabled_keywords{lc($1)}=$1;
    }
    else {
        print "Unknown option: $ARGV[0]\n";
        exit;
    }
    shift @ARGV;
}

delete $ENV{'DEBUGINFOD_URLS'} if($ENV{'DEBUGINFOD_URLS'} && $no_debuginfod);

if(!$randseed) {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
        localtime(time);
    # seed of the month. December 2019 becomes 201912
    $randseed = ($year+1900)*100 + $mon+1;
    open(C, "$CURL --version 2>/dev/null|");
    my @c = <C>;
    close(C);
    # use the first line of output and get the md5 out of it
    my $str = md5($c[0]);
    $randseed += unpack('S', $str);  # unsigned 16 bit value
}
srand $randseed;

if(@testthis && ($testthis[0] ne "")) {
    $TESTCASES=join(" ", @testthis);
}

if($valgrind) {
    # we have found valgrind on the host, use it

    # verify that we can invoke it fine
    my $code = runclient("valgrind >/dev/null 2>&1");

    if(($code>>8) != 1) {
        #logmsg "Valgrind failure, disable it\n";
        undef $valgrind;
    } else {

        # since valgrind 2.1.x, '--tool' option is mandatory
        # use it, if it is supported by the version installed on the system
        runclient("valgrind --help 2>&1 | grep -- --tool > /dev/null 2>&1");
        if (($? >> 8)==0) {
            $valgrind_tool="--tool=memcheck";
        }
        open(C, "<$CURL");
        my $l = <C>;
        if($l =~ /^\#\!/) {
            # A shell script. This is typically when built with libtool,
            $valgrind="../libtool --mode=execute $valgrind";
        }
        close(C);

        # valgrind 3 renamed the --logfile option to --log-file!!!
        my $ver=join(' ', runclientoutput("valgrind --version"));
        # cut off all but digits and dots
        $ver =~ s/[^0-9.]//g;

        if($ver =~ /^(\d+)/) {
            $ver = $1;
            if($ver >= 3) {
                $valgrind_logfile="--log-file";
            }
        }
    }
}

if ($gdbthis) {
    # open the executable curl and read the first 4 bytes of it
    open(CHECK, "<$CURL");
    my $c;
    sysread CHECK, $c, 4;
    close(CHECK);
    if($c eq "#! /") {
        # A shell script. This is typically when built with libtool,
        $libtool = 1;
        $gdb = "../libtool --mode=execute gdb";
    }
}

$HTTPUNIXPATH    = "http$$.sock"; # HTTP server Unix domain socket path
$SOCKSUNIXPATH    = $pwd."/socks$$.sock"; # HTTP server Unix domain socket path, absolute path

#######################################################################
# clear and create logging directory:
#

cleardir($LOGDIR);
mkdir($LOGDIR, 0777);

#######################################################################
# initialize some variables
#

get_disttests();
init_serverpidfile_hash();

#######################################################################
# Output curl version and host info being tested
#

if(!$listonly) {
    checksystem();
}

# globally disabled tests
disabledtests("$TESTDIR/DISABLED");

#######################################################################
# Fetch all disabled tests, if there are any
#

sub disabledtests {
    my ($file) = @_;
    my @input;

    if(open(D, "<$file")) {
        while(<D>) {
            if(/^ *\#/) {
                # allow comments
                next;
            }
            push @input, $_;
        }
        close(D);

        # preprocess the input to make conditionally disabled tests depending
        # on variables
        my @pp = prepro(0, @input);
        for my $t (@pp) {
            if($t =~ /(\d+)/) {
                my ($n) = $1;
                $disabled{$n}=$n; # disable this test number
                if(! -f "$srcdir/data/test$n") {
                    print STDERR "WARNING! Non-existing test $n in $file!\n";
                    # fail hard to make user notice
                    exit 1;
                }
                logmsg "DISABLED: test $n\n" if ($verbose);
            }
            else {
                print STDERR "$file: rubbish content: $t\n";
                exit 2;
            }
        }
    }
}

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^test([0-9]+)$/ && -f "$TESTDIR/$_" } readdir(DIR);
    closedir(DIR);

    $TESTCASES=""; # start with no test cases

    # cut off everything but the digits
    for(@cmds) {
        $_ =~ s/[a-z\/\.]*//g;
    }
    # sort the numbers from low to high
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
else {
    my $verified="";
    map {
        if (-e "$TESTDIR/test$_") {
            $verified.="$_ ";
        }
    } split(" ", $TESTCASES);
    if($verified eq "") {
        print "No existing test cases were specified\n";
        exit;
    }
    $TESTCASES = $verified;
}
if($repeat) {
    my $s;
    for(1 .. $repeat) {
        $s .= $TESTCASES;
    }
    $TESTCASES = $s;
}

if($scrambleorder) {
    # scramble the order of the test cases
    my @rand;
    while($TESTCASES) {
        my @all = split(/ +/, $TESTCASES);
        if(!$all[0]) {
            # if the first is blank, shift away it
            shift @all;
        }
        my $r = rand @all;
        push @rand, $all[$r];
        $all[$r]="";
        $TESTCASES = join(" ", @all);
    }
    $TESTCASES = join(" ", @rand);
}

# Display the contents of the given file.  Line endings are canonicalized
# and excessively long files are elided
sub displaylogcontent {
    my ($file)=@_;
    if(open(SINGLE, "<$file")) {
        my $linecount = 0;
        my $truncate;
        my @tail;
        while(my $string = <SINGLE>) {
            $string =~ s/\r\n/\n/g;
            $string =~ s/[\r\f\032]/\n/g;
            $string .= "\n" unless ($string =~ /\n$/);
            $string =~ tr/\n//;
            for my $line (split("\n", $string)) {
                $line =~ s/\s*\!$//;
                if ($truncate) {
                    push @tail, " $line\n";
                } else {
                    logmsg " $line\n";
                }
                $linecount++;
                $truncate = $linecount > 1000;
            }
        }
        if(@tail) {
            my $tailshow = 200;
            my $tailskip = 0;
            my $tailtotal = scalar @tail;
            if($tailtotal > $tailshow) {
                $tailskip = $tailtotal - $tailshow;
                logmsg "=== File too long: $tailskip lines omitted here\n";
            }
            for($tailskip .. $tailtotal-1) {
                logmsg "$tail[$_]";
            }
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

    logmsg "== Contents of files in the $LOGDIR/ dir after test $testnum\n";
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
        if(($log =~ /^netrc\d+/) && ($log !~ /^netrc$testnum/)) {
            next; # skip netrcNnn of other tests
        }
        if(($log =~ /^trace\d+/) && ($log !~ /^trace$testnum/)) {
            next; # skip traceNnn of other tests
        }
        if(($log =~ /^valgrind\d+/) && ($log !~ /^valgrind$testnum(\..*|)$/)) {
            next; # skip valgrindNnn of other tests
        }
        if(($log =~ /^test$testnum$/)) {
            next; # skip test$testnum since it can be very big
        }
        logmsg "=== Start of file $log\n";
        displaylogcontent("$LOGDIR/$log");
        logmsg "=== End of file $log\n";
    }
}

#######################################################################
# Setup Azure Pipelines Test Run (if running in Azure DevOps)
#

if(azure_check_environment()) {
    $AZURE_RUN_ID = azure_create_test_run($ACURL);
    logmsg "Azure Run ID: $AZURE_RUN_ID\n" if ($verbose);
}

#######################################################################
# The main test-loop
#

my $failed;
my $failedign;
my $testnum;
my $ok=0;
my $ign=0;
my $total=0;
my $lasttest=0;
my @at = split(" ", $TESTCASES);
my $count=0;

$start = time();

foreach $testnum (@at) {

    $lasttest = $testnum if($testnum > $lasttest);
    $count++;

    my $error = singletest($run_event_based, $testnum, $count, scalar(@at));

    # update test result in CI services
    if(azure_check_environment() && $AZURE_RUN_ID && $AZURE_RESULT_ID) {
        $AZURE_RESULT_ID = azure_update_test_result($ACURL, $AZURE_RUN_ID, $AZURE_RESULT_ID, $testnum, $error,
                                                    $timeprepini{$testnum}, $timevrfyend{$testnum});
    }
    elsif(appveyor_check_environment()) {
        appveyor_update_test_result($ACURL, $testnum, $error, $timeprepini{$testnum}, $timevrfyend{$testnum});
    }

    if($error < 0) {
        # not a test we can run
        next;
    }

    $total++; # number of tests we've run

    if($error>0) {
        if($error==2) {
            # ignored test failures
            $failedign .= "$testnum ";
        }
        else {
            $failed.= "$testnum ";
        }
        if($postmortem) {
            # display all files in log/ in a nice way
            displaylogs($testnum);
        }
        if($error==2) {
            $ign++; # ignored test result counter
        }
        elsif(!$anyway) {
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

my $sofar = time() - $start;

#######################################################################
# Finish Azure Pipelines Test Run (if running in Azure DevOps)
#

if(azure_check_environment() && $AZURE_RUN_ID) {
    $AZURE_RUN_ID = azure_update_test_run($ACURL, $AZURE_RUN_ID);
}

# Tests done, stop the servers
my $unexpected = stopservers($verbose);

my $all = $total + $skipped;

runtimestats($lasttest);

if($all) {
    logmsg "TESTDONE: $all tests were considered during ".
        sprintf("%.0f", $sofar) ." seconds.\n";
}

if($skipped && !$short) {
    my $s=0;
    # Temporary hash to print the restraints sorted by the number
    # of their occurrences
    my %restraints;
    logmsg "TESTINFO: $skipped tests were skipped due to these restraints:\n";

    for(keys %skipped) {
        my $r = $_;
        my $skip_count = $skipped{$r};
        my $log_line = sprintf("TESTINFO: \"%s\" %d time%s (", $r, $skip_count,
                           ($skip_count == 1) ? "" : "s");

        # now gather all test case numbers that had this reason for being
        # skipped
        my $c=0;
        my $max = 9;
        for(0 .. scalar @teststat) {
            my $t = $_;
            if($teststat[$t] && ($teststat[$t] eq $r)) {
                if($c < $max) {
                    $log_line .= ", " if($c);
                    $log_line .= $t;
                }
                $c++;
            }
        }
        if($c > $max) {
            $log_line .= " and ".($c-$max)." more";
        }
        $log_line .= ")\n";
        $restraints{$log_line} = $skip_count;
    }
    foreach my $log_line (sort {$restraints{$b} <=> $restraints{$a}} keys %restraints) {
        logmsg $log_line;
    }
}

if($total) {
    if($failedign) {
        logmsg "IGNORED: failed tests: $failedign\n";
    }
    logmsg sprintf("TESTDONE: $ok tests out of $total reported OK: %d%%\n",
                   $ok/$total*100);

    if($failed && ($ok != $total)) {
        logmsg "\nTESTFAIL: These test cases failed: $failed\n\n";
    }
}
else {
    logmsg "\nTESTFAIL: No tests were performed\n\n";
    if(scalar(keys %enabled_keywords)) {
        logmsg "TESTFAIL: Nothing matched these keywords: ";
        for(keys %enabled_keywords) {
            logmsg "$_ ";
        }
        logmsg "\n";
    }
}

if(($total && (($ok+$ign) != $total)) || !$total || $unexpected) {
    exit 1;
}
