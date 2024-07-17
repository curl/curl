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

# For documentation, run `man ./runtests.1` and see README.md.

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

use strict;
# Promote all warnings to fatal
use warnings FATAL => 'all';
use 5.006;
use POSIX qw(strftime);

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

use Digest::MD5 qw(md5);
use List::Util 'sum';

use pathhelp qw(
    exe_ext
    sys_native_current_path
    );
use processhelp qw(
    portable_sleep
    );

use appveyor;
use azure;
use getpart;   # array functions
use servers;
use valgrind;  # valgrind report parser
use globalconfig;
use runner;
use testutil;

my %custom_skip_reasons;

my $ACURL=$VCURL;  # what curl binary to use to talk to APIs (relevant for CI)
                   # ACURL is handy to set to the system one for reliability
my $CURLCONFIG="../curl-config"; # curl-config from current build

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

my $libtool;
my $repeat = 0;

my $start;          # time at which testing started

my $uname_release = `uname -r`;
my $is_wsl = $uname_release =~ /Microsoft$/;

my $http_ipv6;      # set if HTTP server has IPv6 support
my $http_unix;      # set if HTTP server has Unix sockets support
my $ftp_ipv6;       # set if FTP server has IPv6 support

my $resolver;       # name of the resolver backend (for human presentation)

my $has_textaware;  # set if running on a system that has a text mode concept
                    # on files. Windows for example

my %skipped;    # skipped{reason}=counter, reasons for skip
my @teststat;   # teststat[testnum]=reason, reasons for skip
my %disabled_keywords;  # key words of tests to skip
my %ignored_keywords;   # key words of tests to ignore results
my %enabled_keywords;   # key words of tests to run
my %disabled;           # disabled test cases
my %ignored;            # ignored results of test cases
my %ignoretestcodes;    # if test results are to be ignored

my $timestats;   # time stamping and stats generation
my $fullstats;   # show time stats for every single test
my %timeprepini; # timestamp for each test preparation start
my %timesrvrini; # timestamp for each test required servers verification start
my %timesrvrend; # timestamp for each test required servers verification end
my %timetoolini; # timestamp for each test command run starting
my %timetoolend; # timestamp for each test command run stopping
my %timesrvrlog; # timestamp for each test server logs lock removal
my %timevrfyend; # timestamp for each test result verification end
my $globalabort; # flag signalling program abort

# values for $singletest_state
use constant {
    ST_INIT => 0,
    ST_CLEARLOCKS => 1,
    ST_INITED => 2,
    ST_PREPROCESS => 3,
    ST_RUN => 4,
};
my %singletest_state;  # current state of singletest() by runner ID
my %singletest_logs;   # log messages while in singletest array ref by runner
my $singletest_bufferedrunner; # runner ID which is buffering logs
my %runnerids;         # runner IDs by number
my @runnersidle;       # runner IDs idle and ready to execute a test
my %countforrunner;    # test count by runner ID
my %runnersrunning;    # tests currently running by runner ID

#######################################################################
# variables that command line options may set
#
my $short;
my $no_debuginfod;
my $keepoutfiles; # keep stdout and stderr files after tests
my $clearlocks;   # force removal of files by killing locking processes
my $postmortem;   # display detailed info about failed tests
my $run_disabled; # run the specific tests even if listed in DISABLED
my $scrambleorder;
my $jobs = 0;

# Azure Pipelines specific variables
my $AZURE_RUN_ID = 0;
my $AZURE_RESULT_ID = 0;

#######################################################################
# logmsg is our general message logging subroutine.
#
sub logmsg {
    if($singletest_bufferedrunner) {
        # Logs are currently being buffered
        return singletest_logmsg(@_);
    }
    for(@_) {
        my $line = $_;
        if(!$line) {
            next;
        }
        if ($is_wsl) {
            # use \r\n for WSL shell
            $line =~ s/\r?\n$/\r\n/g;
        }
        print "$line";
    }
}

#######################################################################
# enable logmsg buffering for the given runner ID
#
sub logmsg_bufferfortest {
    my ($runnerid)=@_;
    if($jobs) {
        # Only enable buffering in multiprocess mode
        $singletest_bufferedrunner = $runnerid;
    }
}
#######################################################################
# Store a log message in a buffer for this test
# The messages can then be displayed all at once at the end of the test
# which prevents messages from different tests from being interleaved.
sub singletest_logmsg {
    if(!exists $singletest_logs{$singletest_bufferedrunner}) {
        # initialize to a reference to an empty anonymous array
        $singletest_logs{$singletest_bufferedrunner} = [];
    }
    my $logsref = $singletest_logs{$singletest_bufferedrunner};
    push @$logsref, @_;
}

#######################################################################
# Stop buffering log messages, but don't touch them
sub singletest_unbufferlogs {
    undef $singletest_bufferedrunner;
}

#######################################################################
# Clear the buffered log messages & stop buffering after returning them
sub singletest_dumplogs {
    if(!defined $singletest_bufferedrunner) {
        # probably not multiprocess mode and logs weren't buffered
        return undef;
    }
    my $logsref = $singletest_logs{$singletest_bufferedrunner};
    my $msg = join("", @$logsref);
    delete $singletest_logs{$singletest_bufferedrunner};
    singletest_unbufferlogs();
    return $msg;
}

sub catch_zap {
    my $signame = shift;
    print "runtests.pl received SIG$signame, exiting\r\n";
    $globalabort = 1;
}
$SIG{INT} = \&catch_zap;
$SIG{TERM} = \&catch_zap;

sub catch_usr1 {
    print "runtests.pl internal state:\r\n";
    print scalar(%runnersrunning) . " busy test runner(s) of " . scalar(keys %runnerids) . "\r\n";
    foreach my $rid (sort(keys(%runnersrunning))) {
        my $runnernum = "unknown";
        foreach my $rnum (keys %runnerids) {
            if($runnerids{$rnum} == $rid) {
                $runnernum = $rnum;
                last;
            }
        }
        print "Runner $runnernum (id $rid) running test $runnersrunning{$rid} in state $singletest_state{$rid}\r\n";
    }
}

eval {
    # some msys2 perl versions don't define SIGUSR1
    $SIG{USR1} = \&catch_usr1;
};
$SIG{PIPE} = 'IGNORE';  # these errors are captured in the read/write calls

##########################################################################
# Clear all possible '*_proxy' environment variables for various protocols
# to prevent them to interfere with our testing!

foreach my $protocol (('ftp', 'http', 'ftps', 'https', 'no', 'all')) {
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
if (open(my $fd, "<", "config")) {
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
    my $nghttpx_version=join(' ', `"$ENV{'NGHTTPX'}" -v 2>/dev/null`);
    $nghttpx_h3 = $nghttpx_version =~ /nghttp3\//;
    chomp $nghttpx_h3;
}


#######################################################################
# Get the list of tests that the tests/data/Makefile.am knows about!
#
my $disttests = "";
sub get_disttests {
    # If a non-default $TESTDIR is being used there may not be any
    # Makefile.inc in which case there's nothing to do.
    open(my $dh, "<", "$TESTDIR/Makefile.inc") or return;
    while(<$dh>) {
        chomp $_;
        if(($_ =~ /^#/) ||($_ !~ /test/)) {
            next;
        }
        $disttests .= $_;
    }
    close($dh);
}


#######################################################################
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $done = 1;  # success
    my $file;

    # Get all files
    opendir(my $dh, $dir) ||
        return 0; # can't open dir
    while($file = readdir($dh)) {
        # Don't clear the $PIDDIR or $LOCKDIR since those need to live beyond
        # one test
        if(($file !~ /^(\.|\.\.)\z/) &&
            "$file" ne $PIDDIR && "$file" ne $LOCKDIR) {
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
# Given two array references, this function will store them in two temporary
# files, run 'diff' on them, store the result and return the diff output!
sub showdiff {
    my ($logdir, $firstref, $secondref)=@_;

    my $file1="$logdir/check-generated";
    my $file2="$logdir/check-expected";

    open(my $temp, ">", "$file1") || die "Failure writing diff file";
    for(@$firstref) {
        my $l = $_;
        $l =~ s/\r/[CR]/g;
        $l =~ s/\n/[LF]/g;
        $l =~ s/([^\x20-\x7f])/sprintf "%%%02x", ord $1/eg;
        print $temp $l;
        print $temp "\n";
    }
    close($temp) || die "Failure writing diff file";

    open($temp, ">", "$file2") || die "Failure writing diff file";
    for(@$secondref) {
        my $l = $_;
        $l =~ s/\r/[CR]/g;
        $l =~ s/\n/[LF]/g;
        $l =~ s/([^\x20-\x7f])/sprintf "%%%02x", ord $1/eg;
        print $temp $l;
        print $temp "\n";
    }
    close($temp) || die "Failure writing diff file";
    my @out = `diff -u $file2 $file1 2>/dev/null`;

    if(!$out[0]) {
        @out = `diff -c $file2 $file1 2>/dev/null`;
    }

    return @out;
}


#######################################################################
# compare test results with the expected output, we might filter off
# some pattern that is allowed to differ, output test results
#
sub compare {
    my ($runnerid, $testnum, $testname, $subject, $firstref, $secondref)=@_;

    my $result = compareparts($firstref, $secondref);

    if($result) {
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();

        if(!$short) {
            logmsg "\n $testnum: $subject FAILED:\n";
            my $logdir = getrunnerlogdir($runnerid);
            logmsg showdiff($logdir, $firstref, $secondref);
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

#######################################################################
# Numeric-sort words in a string
sub numsortwords {
    my ($string)=@_;
    return join(' ', sort { $a <=> $b } split(' ', $string));
}

#######################################################################
# Parse and store the protocols in curl's Protocols: line
sub parseprotocols {
    my ($line)=@_;

    @protocols = split(' ', lc($line));

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


#######################################################################
# Check & display information about curl and the host the test suite runs on.
# Information to do with servers is displayed in displayserverfeatures, after
# the server initialization is performed.
sub checksystemfeatures {
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
    my $versioncmd=shell_quote($CURL) . " --version 1>$curlverout 2>$curlvererr";

    unlink($curlverout);
    unlink($curlvererr);

    $versretval = runclient($versioncmd);
    $versnoexec = $!;

    my $current_time = int(time());
    $ENV{'SOURCE_DATE_EPOCH'} = $current_time;
    $DATE = strftime "%Y-%m-%d", gmtime($current_time);

    open(my $versout, "<", "$curlverout");
    @version = <$versout>;
    close($versout);

    open(my $disabledh, "-|", "server/disabled".exe_ext('TOOL'));
    @disabled = <$disabledh>;
    close($disabledh);

    if($disabled[0]) {
        s/[\r\n]//g for @disabled;
        $dis = join(", ", @disabled);
    }

    $resolver="stock";
    for(@version) {
        chomp;

        if($_ =~ /^curl ([^ ]*)/) {
            $curl = $_;
            $CURLVERSION = $1;
            $CURLVERNUM = $CURLVERSION;
            $CURLVERNUM =~ s/^([0-9.]+)(.*)/$1/; # leading dots and numbers
            $curl =~ s/^(.*)(libcurl.*)/$1/g || die "Failure determining curl binary version";

            $libcurl = $2;
            if($curl =~ /linux|bsd|solaris/) {
                # system support LD_PRELOAD; may be disabled later
                $feature{"ld_preload"} = 1;
            }
            if($curl =~ /win32|Windows|mingw(32|64)/) {
                # This is a Windows MinGW build or native build, we need to use
                # Win32-style path.
                $pwd = sys_native_current_path();
                $has_textaware = 1;
                $feature{"win32"} = 1;
                # set if built with MinGW (as opposed to MinGW-w64)
                $feature{"MinGW"} = 1 if ($curl =~ /-pc-mingw32/);
            }
           if ($libcurl =~ /\s(winssl|schannel)\b/i) {
               $feature{"Schannel"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\sopenssl\b/i) {
               $feature{"OpenSSL"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\sgnutls\b/i) {
               $feature{"GnuTLS"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\srustls-ffi\b/i) {
               $feature{"rustls"} = 1;
           }
           elsif ($libcurl =~ /\swolfssl\b/i) {
               $feature{"wolfssl"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\sbearssl\b/i) {
               $feature{"bearssl"} = 1;
           }
           elsif ($libcurl =~ /\ssecuretransport\b/i) {
               $feature{"sectransp"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\sBoringSSL\b/i) {
               # OpenSSL compatible API
               $feature{"OpenSSL"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\slibressl\b/i) {
               # OpenSSL compatible API
               $feature{"OpenSSL"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           elsif ($libcurl =~ /\smbedTLS\b/i) {
               $feature{"mbedtls"} = 1;
               $feature{"SSLpinning"} = 1;
           }
           if ($libcurl =~ /ares/i) {
               $feature{"c-ares"} = 1;
               $resolver="c-ares";
           }
           if ($libcurl =~ /Hyper/i) {
               $feature{"hyper"} = 1;
           }
            if ($libcurl =~ /nghttp2/i) {
                # nghttp2 supports h2c, hyper does not
                $feature{"h2c"} = 1;
            }
            if ($libcurl =~ /libssh2/i) {
                $feature{"libssh2"} = 1;
            }
            if ($libcurl =~ /libssh\/([0-9.]*)\//i) {
                $feature{"libssh"} = 1;
                if($1 =~ /(\d+)\.(\d+).(\d+)/) {
                    my $v = $1 * 100 + $2 * 10 + $3;
                    if($v < 94) {
                        # before 0.9.4
                        $feature{"oldlibssh"} = 1;
                    }
                }
            }
            if ($libcurl =~ /wolfssh/i) {
                $feature{"wolfssh"} = 1;
            }
        }
        elsif($_ =~ /^Protocols: (.*)/i) {
            # these are the protocols compiled in to this libcurl
            parseprotocols($1);
        }
        elsif($_ =~ /^Features: (.*)/i) {
            $feat = $1;

            # built with memory tracking support (--enable-curldebug); may be disabled later
            $feature{"TrackMemory"} = $feat =~ /TrackMemory/i;
            # curl was built with --enable-debug
            $feature{"Debug"} = $feat =~ /Debug/i;
            # ssl enabled
            $feature{"SSL"} = $feat =~ /SSL/i;
            # multiple ssl backends available.
            $feature{"MultiSSL"} = $feat =~ /MultiSSL/i;
            # large file support
            $feature{"Largefile"} = $feat =~ /Largefile/i;
            # IDN support
            $feature{"IDN"} = $feat =~ /IDN/i;
            # IPv6 support
            $feature{"IPv6"} = $feat =~ /IPv6/i;
            # Unix sockets support
            $feature{"UnixSockets"} = $feat =~ /UnixSockets/i;
            # libz compression
            $feature{"libz"} = $feat =~ /libz/i;
            # Brotli compression
            $feature{"brotli"} = $feat =~ /brotli/i;
            # Zstd compression
            $feature{"zstd"} = $feat =~ /zstd/i;
            # NTLM enabled
            $feature{"NTLM"} = $feat =~ /NTLM/i;
            # NTLM delegation to winbind daemon ntlm_auth helper enabled
            $feature{"NTLM_WB"} = $feat =~ /NTLM_WB/i;
            # SSPI enabled
            $feature{"SSPI"} = $feat =~ /SSPI/i;
            # GSS-API enabled
            $feature{"GSS-API"} = $feat =~ /GSS-API/i;
            # Kerberos enabled
            $feature{"Kerberos"} = $feat =~ /Kerberos/i;
            # SPNEGO enabled
            $feature{"SPNEGO"} = $feat =~ /SPNEGO/i;
            # TLS-SRP enabled
            $feature{"TLS-SRP"} = $feat =~ /TLS-SRP/i;
            # PSL enabled
            $feature{"PSL"} = $feat =~ /PSL/i;
            # alt-svc enabled
            $feature{"alt-svc"} = $feat =~ /alt-svc/i;
            # HSTS support
            $feature{"HSTS"} = $feat =~ /HSTS/i;
            if($feat =~ /AsynchDNS/i) {
                if(!$feature{"c-ares"}) {
                    # this means threaded resolver
                    $feature{"threaded-resolver"} = 1;
                    $resolver="threaded";
                }
            }
            # http2 enabled
            $feature{"http/2"} = $feat =~ /HTTP2/;
            if($feature{"http/2"}) {
                push @protocols, 'http/2';
            }
            # http3 enabled
            $feature{"http/3"} = $feat =~ /HTTP3/;
            if($feature{"http/3"}) {
                push @protocols, 'http/3';
            }
            # https proxy support
            $feature{"HTTPS-proxy"} = $feat =~ /HTTPS-proxy/;
            if($feature{"HTTPS-proxy"}) {
                # 'https-proxy' is used as "server" so consider it a protocol
                push @protocols, 'https-proxy';
            }
            # UNICODE support
            $feature{"Unicode"} = $feat =~ /Unicode/i;
            # Thread-safe init
            $feature{"threadsafe"} = $feat =~ /threadsafe/i;
        }
        #
        # Test harness currently uses a non-stunnel server in order to
        # run HTTP TLS-SRP tests required when curl is built with https
        # protocol support and TLS-SRP feature enabled. For convenience
        # 'httptls' may be included in the test harness protocols array
        # to differentiate this from classic stunnel based 'https' test
        # harness server.
        #
        if($feature{"TLS-SRP"}) {
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
        open(my $conf, "<", "../lib/curl_config.h");
        while(<$conf>) {
            if($_ =~ /^\#define HAVE_GETRLIMIT/) {
                # set if system has getrlimit()
                $feature{"getrlimit"} = 1;
            }
        }
        close($conf);
    }

    # allow this feature only if debug mode is disabled
    $feature{"ld_preload"} = $feature{"ld_preload"} && !$feature{"Debug"};

    if($feature{"IPv6"}) {
        # client has IPv6 support

        # check if the HTTP server has it!
        my $cmd = "server/sws".exe_ext('SRV')." --version";
        my @sws = `$cmd`;
        if($sws[0] =~ /IPv6/) {
            # HTTP server has IPv6 support!
            $http_ipv6 = 1;
        }

        # check if the FTP server has it!
        $cmd = "server/sockfilt".exe_ext('SRV')." --version";
        @sws = `$cmd`;
        if($sws[0] =~ /IPv6/) {
            # FTP server has IPv6 support!
            $ftp_ipv6 = 1;
        }
    }

    if($feature{"UnixSockets"}) {
        # client has Unix sockets support, check whether the HTTP server has it
        my $cmd = "server/sws".exe_ext('SRV')." --version";
        my @sws = `$cmd`;
        $http_unix = 1 if($sws[0] =~ /unix/);
    }

    open(my $manh, "-|", shell_quote($CURL) . " -M 2>&1");
    while(my $s = <$manh>) {
        if($s =~ /built-in manual was disabled at build-time/) {
            $feature{"manual"} = 0;
            last;
        }
        $feature{"manual"} = 1;
        last;
    }
    close($manh);

    $feature{"unittest"} = $feature{"Debug"};
    $feature{"nghttpx"} = !!$ENV{'NGHTTPX'};
    $feature{"nghttpx-h3"} = !!$nghttpx_h3;

    #
    # strings that must exactly match the names used in server/disabled.c
    #
    $feature{"cookies"} = 1;
    # Use this as a proxy for any cryptographic authentication
    $feature{"crypto"} = $feature{"NTLM"} || $feature{"Kerberos"} || $feature{"SPNEGO"};
    $feature{"DoH"} = 1;
    $feature{"HTTP-auth"} = 1;
    $feature{"Mime"} = 1;
    $feature{"form-api"} = 1;
    $feature{"netrc"} = 1;
    $feature{"parsedate"} = 1;
    $feature{"proxy"} = 1;
    $feature{"shuffle-dns"} = 1;
    $feature{"typecheck"} = 1;
    $feature{"verbose-strings"} = 1;
    $feature{"wakeup"} = 1;
    $feature{"headers-api"} = 1;
    $feature{"xattr"} = 1;
    $feature{"large-time"} = 1;
    $feature{"sha512-256"} = 1;

    # make each protocol an enabled "feature"
    for my $p (@protocols) {
        $feature{$p} = 1;
    }
    # 'socks' was once here but is now removed

    $has_shared = `sh $CURLCONFIG --built-shared`;
    chomp $has_shared;
    $has_shared = $has_shared eq "yes";

    if(!$feature{"TrackMemory"} && $torture) {
        die "can't run torture tests since curl was built without ".
            "TrackMemory feature (--enable-curldebug)";
    }

    my $hostname=join(' ', runclientoutput("hostname"));
    my $hosttype=join(' ', runclientoutput("uname -a"));
    my $hostos=$^O;

    # display summary information about curl and the test host
    logmsg ("********* System characteristics ******** \n",
            "* $curl\n",
            "* $libcurl\n",
            "* Features: $feat\n",
            "* Disabled: $dis\n",
            "* Host: $hostname",
            "* System: $hosttype",
            "* OS: $hostos\n");

    if($jobs) {
        # Only show if not the default for now
        logmsg "* Jobs: $jobs\n";
    }
    if($feature{"TrackMemory"} && $feature{"threaded-resolver"}) {
        logmsg("*\n",
               "*** DISABLES memory tracking when using threaded resolver\n",
               "*\n");
    }

    logmsg sprintf("* Env: %s%s%s", $valgrind?"Valgrind ":"",
                   $run_event_based?"event-based ":"",
                   $nghttpx_h3);
    logmsg sprintf("%s\n", $libtool?"Libtool ":"");
    logmsg ("* Seed: $randseed\n");

    # Disable memory tracking when using threaded resolver
    $feature{"TrackMemory"} = $feature{"TrackMemory"} && !$feature{"threaded-resolver"};

    # toggle off the features that were disabled in the build
    for my $d(@disabled) {
        $feature{$d} = 0;
    }
}

#######################################################################
# display information about server features
#
sub displayserverfeatures {
    logmsg sprintf("* Servers: %s", $stunnel?"SSL ":"");
    logmsg sprintf("%s", $http_ipv6?"HTTP-IPv6 ":"");
    logmsg sprintf("%s", $http_unix?"HTTP-unix ":"");
    logmsg sprintf("%s\n", $ftp_ipv6?"FTP-IPv6 ":"");
    logmsg "***************************************** \n";
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


# Setup CI Test Run
sub citest_starttestrun {
    if(azure_check_environment()) {
        $AZURE_RUN_ID = azure_create_test_run($ACURL);
        logmsg "Azure Run ID: $AZURE_RUN_ID\n" if ($verbose);
    }
    # Appveyor doesn't require anything here
}


# Register the test case with the CI runner
sub citest_starttest {
    my $testnum = $_[0];

    # get the name of the test early
    my $testname= (getpart("client", "name"))[0];
    chomp $testname;

    # create test result in CI services
    if(azure_check_environment() && $AZURE_RUN_ID) {
        $AZURE_RESULT_ID = azure_create_test_result($ACURL, $AZURE_RUN_ID, $testnum, $testname);
    }
    elsif(appveyor_check_environment()) {
        appveyor_create_test_result($ACURL, $testnum, $testname);
    }
}


# Submit the test case result with the CI runner
sub citest_finishtest {
    my ($testnum, $error) = @_;
    # update test result in CI services
    if(azure_check_environment() && $AZURE_RUN_ID && $AZURE_RESULT_ID) {
        $AZURE_RESULT_ID = azure_update_test_result($ACURL, $AZURE_RUN_ID, $AZURE_RESULT_ID, $testnum, $error,
                                                    $timeprepini{$testnum}, $timevrfyend{$testnum});
    }
    elsif(appveyor_check_environment()) {
        appveyor_update_test_result($ACURL, $testnum, $error, $timeprepini{$testnum}, $timevrfyend{$testnum});
    }
}

# Complete CI test run
sub citest_finishtestrun {
    if(azure_check_environment() && $AZURE_RUN_ID) {
        $AZURE_RUN_ID = azure_update_test_run($ACURL, $AZURE_RUN_ID);
    }
    # Appveyor doesn't require anything here
}


# add one set of test timings from the runner to global set
sub updatetesttimings {
    my ($testnum, %testtimings)=@_;

    if(defined $testtimings{"timeprepini"}) {
        $timeprepini{$testnum} = $testtimings{"timeprepini"};
    }
    if(defined $testtimings{"timesrvrini"}) {
        $timesrvrini{$testnum} = $testtimings{"timesrvrini"};
    }
    if(defined $testtimings{"timesrvrend"}) {
        $timesrvrend{$testnum} = $testtimings{"timesrvrend"};
    }
    if(defined $testtimings{"timetoolini"}) {
        $timetoolini{$testnum} = $testtimings{"timetoolini"};
    }
    if(defined $testtimings{"timetoolend"}) {
        $timetoolend{$testnum} = $testtimings{"timetoolend"};
    }
    if(defined $testtimings{"timesrvrlog"}) {
        $timesrvrlog{$testnum} = $testtimings{"timesrvrlog"};
    }
}


#######################################################################
# Return the log directory for the given test runner
sub getrunnernumlogdir {
    my $runnernum = $_[0];
    return $jobs > 1 ? "$LOGDIR/$runnernum" : $LOGDIR;
}

#######################################################################
# Return the log directory for the given test runner ID
sub getrunnerlogdir {
    my $runnerid = $_[0];
    if($jobs <= 1) {
        return $LOGDIR;
    }
    # TODO: speed up this O(n) operation
    for my $runnernum (keys %runnerids) {
        if($runnerid eq $runnerids{$runnernum}) {
            return "$LOGDIR/$runnernum";
        }
    }
    die "Internal error: runner ID $runnerid not found";
}


#######################################################################
# Verify that this test case should be run
sub singletest_shouldrun {
    my $testnum = $_[0];
    my $why;   # why the test won't be run
    my $errorreturncode = 1; # 1 means normal error, 2 means ignored error
    my @what;  # what features are needed

    if($disttests !~ /test$testnum(\W|\z)/ ) {
        logmsg "Warning: test$testnum not present in tests/data/Makefile.inc\n";
    }
    if($disabled{$testnum}) {
        if(!$run_disabled) {
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

    my @info_keywords;
    if(!$why) {
        @info_keywords = getpart("info", "keywords");

        if(!$info_keywords[0]) {
            $why = "missing the <keywords> section!";
        }

        my $match;
        for my $k (@info_keywords) {
            chomp $k;
            if ($disabled_keywords{lc($k)}) {
                $why = "disabled by keyword";
            }
            elsif ($enabled_keywords{lc($k)}) {
                $match = 1;
            }
            if ($ignored_keywords{lc($k)}) {
                logmsg "Warning: test$testnum result is ignored due to $k\n";
                $errorreturncode = 2;
            }
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
        foreach my $keyword (@info_keywords) {
            foreach my $keyword_skip_pattern (keys %{$custom_skip_reasons{keyword}}) {
                if ($keyword =~ /$keyword_skip_pattern/i) {
                    $why = $custom_skip_reasons{keyword}{$keyword_skip_pattern};
                }
            }
        }
    }

    return ($why, $errorreturncode);
}


#######################################################################
# Print the test name and count tests
sub singletest_count {
    my ($testnum, $why) = @_;

    if($why && !$listonly) {
        # there's a problem, count it as "skipped"
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

    # At this point we've committed to run this test
    logmsg sprintf("test %04d...", $testnum) if(!$automakestyle);

    # name of the test
    my $testname= (getpart("client", "name"))[0];
    chomp $testname;
    logmsg "[$testname]\n" if(!$short);

    if($listonly) {
        timestampskippedevents($testnum);
    }
    return 0;
}


#######################################################################
# Verify test succeeded
sub singletest_check {
    my ($runnerid, $testnum, $cmdres, $CURLOUT, $tool, $usedvalgrind)=@_;

    # Skip all the verification on torture tests
    if ($torture) {
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();
        return -2;
    }

    my $logdir = getrunnerlogdir($runnerid);
    my @err = getpart("verify", "errorcode");
    my $errorcode = $err[0] || "0";
    my $ok="";
    my $res;
    chomp $errorcode;
    my $testname= (getpart("client", "name"))[0];
    chomp $testname;
    # what parts to cut off from stdout/stderr
    my @stripfile = getpart("verify", "stripfile");

    my @validstdout = getpart("verify", "stdout");
    # get all attributes
    my %hash = getpartattr("verify", "stdout");

    my $loadfile = $hash{'loadfile'};
    if ($loadfile) {
        open(my $tmp, "<", "$loadfile") || die "Cannot open file $loadfile: $!";
        @validstdout = <$tmp>;
        close($tmp);

        # Enforce LF newlines on load
        s/\r\n/\n/g for @validstdout;
    }

    if (@validstdout) {
        # verify redirected stdout
        my @actual = loadarray(stdoutfilename($logdir, $testnum));

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

        # get the mode attribute
        my $filemode=$hash{'mode'};
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            s/\r\n/\n/g for @validstdout;
            s/\n/\r\n/g for @validstdout;
            s/\r\n/\n/g for @actual;
            s/\n/\r\n/g for @actual;
        }

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($validstdout[-1]);
        }

        if($hash{'crlf'} ||
           ($feature{"hyper"} && ($keywords{"HTTP"}
                           || $keywords{"HTTPS"}))) {
            subnewlines(0, \$_) for @validstdout;
        }

        $res = compare($runnerid, $testnum, $testname, "stdout", \@actual, \@validstdout);
        if($res) {
            return -1;
        }
        $ok .= "s";
    }
    else {
        $ok .= "-"; # stdout not checked
    }

    my @validstderr = getpart("verify", "stderr");
    if (@validstderr) {
        # verify redirected stderr
        my @actual = loadarray(stderrfilename($logdir, $testnum));

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
        if($filemode && ($filemode eq "text") && $feature{"hyper"}) {
            # text mode check in hyper-mode. Sometimes necessary if the stderr
            # data *looks* like HTTP and thus has gotten CRLF newlines
            # mistakenly
            s/\r\n/\n/g for @validstderr;
        }
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            s/\r\n/\n/g for @validstderr;
            s/\n/\r\n/g for @validstderr;
        }

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($validstderr[-1]);
        }

        if($hash{'crlf'}) {
            subnewlines(0, \$_) for @validstderr;
        }

        $res = compare($runnerid, $testnum, $testname, "stderr", \@actual, \@validstderr);
        if($res) {
            return -1;
        }
        $ok .= "r";
    }
    else {
        $ok .= "-"; # stderr not checked
    }

    # what to cut off from the live protocol sent by curl
    my @strip = getpart("verify", "strip");

    # what parts to cut off from the protocol & upload
    my @strippart = getpart("verify", "strippart");

    # this is the valid protocol blurb curl should generate
    my @protocol= getpart("verify", "protocol");
    if(@protocol) {
        # Verify the sent request
        my @out = loadarray("$logdir/$SERVERIN");

        # check if there's any attributes on the verify/protocol section
        my %hash = getpartattr("verify", "protocol");

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($protocol[-1]);
        }

        for(@strip) {
            # strip off all lines that match the patterns from both arrays
            chomp $_;
            @out = striparray( $_, \@out);
            @protocol= striparray( $_, \@protocol);
        }

        for my $strip (@strippart) {
            chomp $strip;
            for(@out) {
                eval $strip;
            }
        }

        if($hash{'crlf'}) {
            subnewlines(1, \$_) for @protocol;
        }

        if((!$out[0] || ($out[0] eq "")) && $protocol[0]) {
            logmsg "\n $testnum: protocol FAILED!\n".
                " There was no content at all in the file $logdir/$SERVERIN.\n".
                " Server glitch? Total curl failure? Returned: $cmdres\n";
            # timestamp test result verification end
            $timevrfyend{$testnum} = Time::HiRes::time();
            return -1;
        }

        $res = compare($runnerid, $testnum, $testname, "protocol", \@out, \@protocol);
        if($res) {
            return -1;
        }

        $ok .= "p";

    }
    else {
        $ok .= "-"; # protocol not checked
    }

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
                    s/\r\n/\n/g for @replycheckpart;
                    s/\n/\r\n/g for @replycheckpart;
                }
                if($replycheckpartattr{'nonewline'}) {
                    # Yes, we must cut off the final newline from the final line
                    # of the datacheck
                    chomp($replycheckpart[-1]);
                }
                if($replycheckpartattr{'crlf'} ||
                   ($feature{"hyper"} && ($keywords{"HTTP"}
                                   || $keywords{"HTTPS"}))) {
                    subnewlines(0, \$_) for @replycheckpart;
                }
                push(@reply, @replycheckpart);
            }
        }
    }
    else {
        # check against the data section
        @reply = getpart("reply", "data");
        if(@reply) {
            if($replyattr{'nonewline'}) {
                # cut off the final newline from the final line of the data
                chomp($reply[-1]);
            }
        }
        # get the mode attribute
        my $filemode=$replyattr{'mode'};
        if($filemode && ($filemode eq "text") && $has_textaware) {
            # text mode when running on windows: fix line endings
            s/\r\n/\n/g for @reply;
            s/\n/\r\n/g for @reply;
        }
        if($replyattr{'crlf'} ||
           ($feature{"hyper"} && ($keywords{"HTTP"}
                           || $keywords{"HTTPS"}))) {
            subnewlines(0, \$_) for @reply;
        }
    }

    if(!$replyattr{'nocheck'} && (@reply || $replyattr{'sendzero'})) {
        # verify the received data
        my @out = loadarray($CURLOUT);
        $res = compare($runnerid, $testnum, $testname, "data", \@out, \@reply);
        if ($res) {
            return -1;
        }
        $ok .= "d";
    }
    else {
        $ok .= "-"; # data not checked
    }

    # if this section exists, we verify upload
    my @upload = getpart("verify", "upload");
    if(@upload) {
        my %hash = getpartattr("verify", "upload");
        if($hash{'nonewline'}) {
            # cut off the final newline from the final line of the upload data
            chomp($upload[-1]);
        }
        for my $line (@upload) {
            subbase64(\$line);
        }

        # verify uploaded data
        my @out = loadarray("$logdir/upload.$testnum");
        for my $strip (@strippart) {
            chomp $strip;
            for(@out) {
                eval $strip;
            }
        }

        $res = compare($runnerid, $testnum, $testname, "upload", \@out, \@upload);
        if ($res) {
            return -1;
        }
        $ok .= "u";
    }
    else {
        $ok .= "-"; # upload not checked
    }

    # this is the valid protocol blurb curl should generate to a proxy
    my @proxyprot = getpart("verify", "proxy");
    if(@proxyprot) {
        # Verify the sent proxy request
        # check if there's any attributes on the verify/protocol section
        my %hash = getpartattr("verify", "proxy");

        if($hash{'nonewline'}) {
            # Yes, we must cut off the final newline from the final line
            # of the protocol data
            chomp($proxyprot[-1]);
        }

        my @out = loadarray("$logdir/$PROXYIN");
        for(@strip) {
            # strip off all lines that match the patterns from both arrays
            chomp $_;
            @out = striparray( $_, \@out);
            @proxyprot= striparray( $_, \@proxyprot);
        }

        for my $strip (@strippart) {
            chomp $strip;
            for(@out) {
                eval $strip;
            }
        }

        if($hash{'crlf'} ||
           ($feature{"hyper"} && ($keywords{"HTTP"} || $keywords{"HTTPS"}))) {
            subnewlines(0, \$_) for @proxyprot;
        }

        $res = compare($runnerid, $testnum, $testname, "proxy", \@out, \@proxyprot);
        if($res) {
            return -1;
        }

        $ok .= "P";

    }
    else {
        $ok .= "-"; # proxy not checked
    }

    my $outputok;
    for my $partsuffix (('', '1', '2', '3', '4')) {
        my @outfile=getpart("verify", "file".$partsuffix);
        if(@outfile || partexists("verify", "file".$partsuffix) ) {
            # we're supposed to verify a dynamically generated file!
            my %hash = getpartattr("verify", "file".$partsuffix);

            my $filename=$hash{'name'};
            if(!$filename) {
                logmsg " $testnum: IGNORED: section verify=>file$partsuffix ".
                       "has no name attribute\n";
                if (runnerac_stopservers($runnerid)) {
                    logmsg "ERROR: runner $runnerid seems to have died\n";
                } else {

                    # TODO: this is a blocking call that will stall the controller,
                    if($verbose) {
                        logmsg "WARNING: blocking call in async function\n";
                    }
                    # but this error condition should never happen except during
                    # development.
                    my ($rid, $unexpected, $logs) = runnerar($runnerid);
                    if(!$rid) {
                        logmsg "ERROR: runner $runnerid seems to have died\n";
                    } else {
                        logmsg $logs;
                    }
                }
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return -1;
            }
            my @generated=loadarray($filename);

            # what parts to cut off from the file
            my @stripfilepar = getpart("verify", "stripfile".$partsuffix);

            my $filemode=$hash{'mode'};
            if($filemode && ($filemode eq "text") && $has_textaware) {
                # text mode when running on windows: fix line endings
                s/\r\n/\n/g for @outfile;
                s/\n/\r\n/g for @outfile;
            }
            if($hash{'crlf'} ||
               ($feature{"hyper"} && ($keywords{"HTTP"}
                               || $keywords{"HTTPS"}))) {
                subnewlines(0, \$_) for @outfile;
            }

            for my $strip (@stripfilepar) {
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

            if($hash{'nonewline'}) {
                # cut off the final newline from the final line of the
                # output data
                chomp($outfile[-1]);
            }

            $res = compare($runnerid, $testnum, $testname, "output ($filename)",
                           \@generated, \@outfile);
            if($res) {
                return -1;
            }

            $outputok = 1; # output checked
        }
    }
    $ok .= ($outputok) ? "o" : "-"; # output checked or not

    # verify SOCKS proxy details
    my @socksprot = getpart("verify", "socks");
    if(@socksprot) {
        # Verify the sent SOCKS proxy details
        my @out = loadarray("$logdir/$SOCKSIN");
        $res = compare($runnerid, $testnum, $testname, "socks", \@out, \@socksprot);
        if($res) {
            return -1;
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
        logmsg " $testnum: exit FAILED\n";
        # timestamp test result verification end
        $timevrfyend{$testnum} = Time::HiRes::time();
        return -1;
    }

    if($feature{"TrackMemory"}) {
        if(! -f "$logdir/$MEMDUMP") {
            my %cmdhash = getpartattr("client", "command");
            my $cmdtype = $cmdhash{'type'} || "default";
            logmsg "\n** ALERT! memory tracking with no output file?\n"
                if(!$cmdtype eq "perl");
            $ok .= "-"; # problem with memory checking
        }
        else {
            my @memdata=`$memanalyze "$logdir/$MEMDUMP"`;
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
                return -1;
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
        if($usedvalgrind) {
            if(!opendir(DIR, "$logdir")) {
                logmsg "ERROR: unable to read $logdir\n";
                # timestamp test result verification end
                $timevrfyend{$testnum} = Time::HiRes::time();
                return -1;
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
                return -1;
            }
            my @e = valgrindparse("$logdir/$vgfile");
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
                return -1;
            }
            $ok .= "v";
        }
        else {
            if($verbose) {
                logmsg " valgrind SKIPPED\n";
            }
            $ok .= "-"; # skipped
        }
    }
    else {
        $ok .= "-"; # valgrind not checked
    }
    # add 'E' for event-based
    $ok .= $run_event_based ? "E" : "-";

    logmsg "$ok " if(!$short);

    # timestamp test result verification end
    $timevrfyend{$testnum} = Time::HiRes::time();

    return 0;
}


#######################################################################
# Report a successful test
sub singletest_success {
    my ($testnum, $count, $total, $errorreturncode)=@_;

    my $sofar= time()-$start;
    my $esttotal = $sofar/$count * $total;
    my $estleft = $esttotal - $sofar;
    my $timeleft=sprintf("remaining: %02d:%02d",
                     $estleft/60,
                     $estleft%60);
    my $took = $timevrfyend{$testnum} - $timeprepini{$testnum};
    my $duration = sprintf("duration: %02d:%02d",
                           $sofar/60, $sofar%60);
    if(!$automakestyle) {
        logmsg sprintf("OK (%-3d out of %-3d, %s, took %.3fs, %s)\n",
                       $count, $total, $timeleft, $took, $duration);
    }
    else {
        my $testname= (getpart("client", "name"))[0];
        chomp $testname;
        logmsg "PASS: $testnum - $testname\n";
    }

    if($errorreturncode==2) {
        logmsg "Warning: test$testnum result is ignored, but passed!\n";
    }
}

#######################################################################
# Run a single specified test case
# This is structured as a state machine which changes state after an
# asynchronous call is made that awaits a response. The function returns with
# an error code and a flag that indicates if the state machine has completed,
# which means (if not) the function must be called again once the response has
# arrived.
#
sub singletest {
    my ($runnerid, $testnum, $count, $total)=@_;

    # start buffering logmsg; stop it on return
    logmsg_bufferfortest($runnerid);
    if(!exists $singletest_state{$runnerid}) {
        # First time in singletest() for this test
        $singletest_state{$runnerid} = ST_INIT;
    }

    if($singletest_state{$runnerid} == ST_INIT) {
        my $logdir = getrunnerlogdir($runnerid);
        # first, remove all lingering log & lock files
        if((!cleardir($logdir) || !cleardir("$logdir/$LOCKDIR"))
            && $clearlocks) {
            # On Windows, lock files can't be deleted when the process still
            # has them open, so kill those processes first
            if(runnerac_clearlocks($runnerid, "$logdir/$LOCKDIR")) {
                logmsg "ERROR: runner $runnerid seems to have died\n";
                $singletest_state{$runnerid} = ST_INIT;
                return (-1, 0);
            }
            $singletest_state{$runnerid} = ST_CLEARLOCKS;
        } else {
            $singletest_state{$runnerid} = ST_INITED;
            # Recursively call the state machine again because there is no
            # event expected that would otherwise trigger a new call.
            return singletest(@_);
        }

    } elsif($singletest_state{$runnerid} == ST_CLEARLOCKS) {
        my ($rid, $logs) = runnerar($runnerid);
        if(!$rid) {
            logmsg "ERROR: runner $runnerid seems to have died\n";
            $singletest_state{$runnerid} = ST_INIT;
            return (-1, 0);
        }
        logmsg $logs;
        my $logdir = getrunnerlogdir($runnerid);
        cleardir($logdir);
        $singletest_state{$runnerid} = ST_INITED;
        # Recursively call the state machine again because there is no
        # event expected that would otherwise trigger a new call.
        return singletest(@_);

    } elsif($singletest_state{$runnerid} == ST_INITED) {
        ###################################################################
        # Restore environment variables that were modified in a previous run.
        # Test definition may instruct to (un)set environment vars.
        # This is done this early so that leftover variables don't affect
        # starting servers or CI registration.
        # restore_test_env(1);

        ###################################################################
        # Load test file so CI registration can get the right data before the
        # runner is called
        loadtest("${TESTDIR}/test${testnum}");

        ###################################################################
        # Register the test case with the CI environment
        citest_starttest($testnum);

        if(runnerac_test_preprocess($runnerid, $testnum)) {
            logmsg "ERROR: runner $runnerid seems to have died\n";
            $singletest_state{$runnerid} = ST_INIT;
            return (-1, 0);
        }
        $singletest_state{$runnerid} = ST_PREPROCESS;

    } elsif($singletest_state{$runnerid} == ST_PREPROCESS) {
        my ($rid, $why, $error, $logs, $testtimings) = runnerar($runnerid);
        if(!$rid) {
            logmsg "ERROR: runner $runnerid seems to have died\n";
            $singletest_state{$runnerid} = ST_INIT;
            return (-1, 0);
        }
        logmsg $logs;
        updatetesttimings($testnum, %$testtimings);
        if($error == -2) {
            if($postmortem) {
                # Error indicates an actual problem starting the server, so
                # display the server logs
                displaylogs($rid, $testnum);
            }
        }

        #######################################################################
        # Load test file for this test number
        my $logdir = getrunnerlogdir($runnerid);
        loadtest("${logdir}/test${testnum}");

        #######################################################################
        # Print the test name and count tests
        $error = singletest_count($testnum, $why);
        if($error) {
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $error);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            return ($error, 0);
        }

        #######################################################################
        # Execute this test number
        my $cmdres;
        my $CURLOUT;
        my $tool;
        my $usedvalgrind;
        if(runnerac_test_run($runnerid, $testnum)) {
            logmsg "ERROR: runner $runnerid seems to have died\n";
            $singletest_state{$runnerid} = ST_INIT;
            return (-1, 0);
        }
        $singletest_state{$runnerid} = ST_RUN;

    } elsif($singletest_state{$runnerid} == ST_RUN) {
        my ($rid, $error, $logs, $testtimings, $cmdres, $CURLOUT, $tool, $usedvalgrind) = runnerar($runnerid);
        if(!$rid) {
            logmsg "ERROR: runner $runnerid seems to have died\n";
            $singletest_state{$runnerid} = ST_INIT;
            return (-1, 0);
        }
        logmsg $logs;
        updatetesttimings($testnum, %$testtimings);
        if($error == -1) {
            # no further verification will occur
            $timevrfyend{$testnum} = Time::HiRes::time();
            my $err = ignoreresultcode($testnum);
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $err);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            # return a test failure, either to be reported or to be ignored
            return ($err, 0);
        }
        elsif($error == -2) {
            # fill in the missing timings on error
            timestampskippedevents($testnum);
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $error);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            return ($error, 0);
        }
        elsif($error > 0) {
            # no further verification will occur
            $timevrfyend{$testnum} = Time::HiRes::time();
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $error);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            return ($error, 0);
        }

        #######################################################################
        # Verify that the test succeeded
        #
        # Load test file for this test number
        my $logdir = getrunnerlogdir($runnerid);
        loadtest("${logdir}/test${testnum}");
        readtestkeywords();

        $error = singletest_check($runnerid, $testnum, $cmdres, $CURLOUT, $tool, $usedvalgrind);
        if($error == -1) {
            my $err = ignoreresultcode($testnum);
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $err);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            # return a test failure, either to be reported or to be ignored
            return ($err, 0);
        }
        elsif($error == -2) {
            # torture test; there is no verification, so the run result holds the
            # test success code
            # Submit the test case result with the CI environment
            citest_finishtest($testnum, $cmdres);
            $singletest_state{$runnerid} = ST_INIT;
            logmsg singletest_dumplogs();
            return ($cmdres, 0);
        }


        #######################################################################
        # Report a successful test
        singletest_success($testnum, $count, $total, ignoreresultcode($testnum));

        # Submit the test case result with the CI environment
        citest_finishtest($testnum, 0);
        $singletest_state{$runnerid} = ST_INIT;

        logmsg singletest_dumplogs();
        return (0, 0);  # state machine is finished
    }
    singletest_unbufferlogs();
    return (0, 1);  # state machine must be called again on event
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
# returns code indicating why a test was skipped
# 0=unknown test, 1=use test result, 2=ignore test result
#
sub ignoreresultcode {
    my ($testnum)=@_;
    if(defined $ignoretestcodes{$testnum}) {
        return $ignoretestcodes{$testnum};
    }
    return 0;
}

#######################################################################
# Put the given runner ID onto the queue of runners ready for a new task
#
sub runnerready {
    my ($runnerid)=@_;
    push @runnersidle, $runnerid;
}

#######################################################################
# Create test runners
#
sub createrunners {
    my ($numrunners)=@_;
    if(! $numrunners) {
        $numrunners++;
    }
    # create $numrunners runners with minimum 1
    for my $runnernum (1..$numrunners) {
        my $dir = getrunnernumlogdir($runnernum);
        cleardir($dir);
        mkdir($dir, 0777);
        $runnerids{$runnernum} = runner_init($dir, $jobs);
        runnerready($runnerids{$runnernum});
    }
}

#######################################################################
# Pick a test runner for the given test
#
sub pickrunner {
    my ($testnum)=@_;
    scalar(@runnersidle) || die "No runners available";

    return pop @runnersidle;
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

$valgrind = checktestcmd("valgrind");
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
        $DBGCURL=$CURL=$ARGV[1];
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-vc") {
        # use this path to a curl used to verify servers

        # Particularly useful when you introduce a crashing bug somewhere in
        # the development version as then it won't be able to run any tests
        # since it can't verify the servers!

        $VCURL=shell_quote($ARGV[1]);
        shift @ARGV;
    }
    elsif ($ARGV[0] eq "-ac") {
        # use this curl only to talk to APIs (currently only CI test APIs)
        $ACURL=shell_quote($ARGV[1]);
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
        $run_disabled=1;
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
                if($type eq "test") {
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
    elsif ($ARGV[0] eq "-gl") {
        # run this test with lldb
        $gdbthis=2;
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
    elsif($ARGV[0] =~ /^-j(.*)/) {
        # parallel jobs
        $jobs=1;
        my $xtra = $1;
        if($xtra =~ s/(\d+)$//) {
            $jobs = $1;
        }
    }
    elsif($ARGV[0] eq "-k") {
        # keep stdout and stderr files after tests
        $keepoutfiles=1;
    }
    elsif($ARGV[0] eq "-r") {
        # run time statistics needs Time::HiRes
        if($Time::HiRes::VERSION) {
            # presize hashes appropriately to hold an entire test run
            keys(%timeprepini) = 2000;
            keys(%timesrvrini) = 2000;
            keys(%timesrvrend) = 2000;
            keys(%timetoolini) = 2000;
            keys(%timetoolend) = 2000;
            keys(%timesrvrlog) = 2000;
            keys(%timevrfyend) = 2000;
            $timestats=1;
            $fullstats=0;
        }
    }
    elsif($ARGV[0] eq "-rf") {
        # run time statistics needs Time::HiRes
        if($Time::HiRes::VERSION) {
            # presize hashes appropriately to hold an entire test run
            keys(%timeprepini) = 2000;
            keys(%timesrvrini) = 2000;
            keys(%timesrvrend) = 2000;
            keys(%timetoolini) = 2000;
            keys(%timetoolend) = 2000;
            keys(%timesrvrlog) = 2000;
            keys(%timevrfyend) = 2000;
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
        print <<"EOHELP"
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
  -j[N]    spawn this number of processes to run tests (default 0)
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
    print "Using curl: $CURL\n";
    open(my $curlvh, "-|", shell_quote($CURL) . " --version 2>/dev/null") ||
        die "could not get curl version!";
    my @c = <$curlvh>;
    close($curlvh) || die "could not get curl version!";
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
        # (this happened in 2003, so we could probably don't need to care about
        # that old version any longer and just delete this check)
        runclient("valgrind --help 2>&1 | grep -- --tool > /dev/null 2>&1");
        if (($? >> 8)) {
            $valgrind_tool="";
        }
        open(my $curlh, "<", "$CURL");
        my $l = <$curlh>;
        if($l =~ /^\#\!/) {
            # A shell script. This is typically when built with libtool,
            $valgrind="../libtool --mode=execute $valgrind";
        }
        close($curlh);

        # valgrind 3 renamed the --logfile option to --log-file!!!
        # (this happened in 2005, so we could probably don't need to care about
        # that old version any longer and just delete this check)
        my $ver=join(' ', runclientoutput("valgrind --version"));
        # cut off all but digits and dots
        $ver =~ s/[^0-9.]//g;

        if($ver =~ /^(\d+)/) {
            $ver = $1;
            if($ver < 3) {
                $valgrind_logfile="--logfile";
            }
        }
    }
}

if ($gdbthis) {
    # open the executable curl and read the first 4 bytes of it
    open(my $check, "<", "$CURL");
    my $c;
    sysread $check, $c, 4;
    close($check);
    if($c eq "#! /") {
        # A shell script. This is typically when built with libtool,
        $libtool = 1;
        $gdb = "../libtool --mode=execute gdb";
    }
}

#######################################################################
# clear and create logging directory:
#

# TODO: figure how to get around this. This dir is needed for checksystemfeatures()
# Maybe create & use & delete a temporary directory in that function
cleardir($LOGDIR);
mkdir($LOGDIR, 0777);
mkdir("$LOGDIR/$LOCKDIR", 0777);

#######################################################################
# initialize some variables
#

get_disttests();
if(!$jobs) {
    # Disable buffered logging with only one test job
    setlogfunc(\&logmsg);
}

#######################################################################
# Output curl version and host info being tested
#

if(!$listonly) {
    checksystemfeatures();
}

#######################################################################
# initialize configuration needed to set up servers
# TODO: rearrange things so this can be called only in runner_init()
#
initserverconfig();

if(!$listonly) {
    # these can only be displayed after initserverconfig() has been called
    displayserverfeatures();

    # globally disabled tests
    disabledtests("$TESTDIR/DISABLED");
}

#######################################################################
# Fetch all disabled tests, if there are any
#

sub disabledtests {
    my ($file) = @_;
    my @input;

    if(open(my $disabledh, "<", "$file")) {
        while(<$disabledh>) {
            if(/^ *\#/) {
                # allow comments
                next;
            }
            push @input, $_;
        }
        close($disabledh);

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
            $skipped{$why}++;
            $teststat[$n]=$why; # store reason for this test case
            next;
        }
        $TESTCASES .= " $n";
    }
}
else {
    my $verified="";
    for(split(" ", $TESTCASES)) {
        if (-e "$TESTDIR/test$_") {
            $verified.="$_ ";
        }
    }
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
    if(open(my $single, "<", "$file")) {
        my $linecount = 0;
        my $truncate;
        my @tail;
        while(my $string = <$single>) {
            $string =~ s/\r\n/\n/g;
            $string =~ s/[\r\f\032]/\n/g;
            $string .= "\n" unless ($string =~ /\n$/);
            $string =~ tr/\n//;
            for my $line (split(m/\n/, $string)) {
                $line =~ s/\s*\!$//;
                if ($truncate) {
                    push @tail, " $line\n";
                } else {
                    logmsg " $line\n";
                }
                $linecount++;
                $truncate = $linecount > 1200;
            }
        }
        close($single);
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
    }
}

sub displaylogs {
    my ($runnerid, $testnum)=@_;
    my $logdir = getrunnerlogdir($runnerid);
    opendir(DIR, "$logdir") ||
        die "can't open dir: $!";
    my @logs = readdir(DIR);
    closedir(DIR);

    logmsg "== Contents of files in the $logdir/ dir after test $testnum\n";
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
        if((-d "$logdir/$log") || (! -s "$logdir/$log")) {
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
        if(($log =~ /^valgrind\d+/) && ($log !~ /^valgrind$testnum(?:\..*)?$/)) {
            next; # skip valgrindNnn of other tests
        }
        if(($log =~ /^test$testnum$/)) {
            next; # skip test$testnum since it can be very big
        }
        logmsg "=== Start of file $log\n";
        displaylogcontent("$logdir/$log");
        logmsg "=== End of file $log\n";
    }
}

#######################################################################
# Scan tests to find suitable candidates
#

my $failed;
my $failedign;
my $ok=0;
my $ign=0;
my $total=0;
my $lasttest=0;
my @at = split(" ", $TESTCASES);
my $count=0;
my $endwaitcnt=0;

$start = time();

# scan all tests to find ones we should try to run
my @runtests;
foreach my $testnum (@at) {
    $lasttest = $testnum if($testnum > $lasttest);
    my ($why, $errorreturncode) = singletest_shouldrun($testnum);
    if($why || $listonly) {
        # Display test name now--test will be completely skipped later
        my $error = singletest_count($testnum, $why);
        next;
    }
    $ignoretestcodes{$testnum} = $errorreturncode;
    push(@runtests, $testnum);
}
my $totaltests = scalar(@runtests);

if($listonly) {
    exit(0);
}

#######################################################################
# Setup CI Test Run
citest_starttestrun();

#######################################################################
# Start test runners
#
my $numrunners = $jobs < scalar(@runtests) ? $jobs : scalar(@runtests);
createrunners($numrunners);

#######################################################################
# The main test-loop
#
# Every iteration through the loop consists of these steps:
#   - if the global abort flag is set, exit the loop; we are done
#   - if a runner is idle, start a new test on it
#   - if all runners are idle, exit the loop; we are done
#   - if a runner has a response for us, process the response

# run through each candidate test and execute it
while () {
    # check the abort flag
    if($globalabort) {
        logmsg singletest_dumplogs();
        logmsg "Aborting tests\n";
        logmsg "Waiting for " . scalar((keys %runnersrunning)) . " outstanding test(s) to finish...\n";
        # Wait for the last requests to complete and throw them away so
        # that IPC calls & responses stay in sync
        # TODO: send a signal to the runners to interrupt a long test
        foreach my $rid (keys %runnersrunning) {
            runnerar($rid);
            delete $runnersrunning{$rid};
            logmsg ".";
            $| = 1;
        }
        logmsg "\n";
        last;
    }

    # Start a new test if possible
    if(scalar(@runnersidle) && scalar(@runtests)) {
        # A runner is ready to run a test, and tests are still available to run
        # so start a new test.
        $count++;
        my $testnum = shift(@runtests);

        # pick a runner for this new test
        my $runnerid = pickrunner($testnum);
        $countforrunner{$runnerid} = $count;

        # Start the test
        my ($error, $again) = singletest($runnerid, $testnum, $countforrunner{$runnerid}, $totaltests);
        if($again) {
            # this runner is busy running a test
            $runnersrunning{$runnerid} = $testnum;
        } else {
            runnerready($runnerid);
            if($error >= 0) {
                # We make this simplifying assumption to avoid having to handle
                # $error properly here, but we must handle the case of runner
                # death without abending here.
                die "Internal error: test must not complete on first call";
            }
        }
    }

    # See if we've completed all the tests
    if(!scalar(%runnersrunning)) {
        # No runners are running; we must be done
        scalar(@runtests) && die 'Internal error: still have tests to run';
        last;
    }

    # See if a test runner needs attention
    # If we could be running more tests, don't wait so we can schedule a new
    # one immediately. If all runners are busy, wait a fraction of a second
    # for one to finish so we can still loop around to check the abort flag.
    my $runnerwait = scalar(@runnersidle) && scalar(@runtests) ? 0 : 0.5;
    my ($ridready, $riderror) = runnerar_ready($runnerwait);
    if($ridready && ! defined $runnersrunning{$ridready}) {
        # On Linux, a closed pipe still shows up as ready instead of error.
        # Detect this here by seeing if we are expecting it to be ready and
        # treat it as an error if not.
        logmsg "ERROR: Runner $ridready is unexpectedly ready; is probably actually dead\n";
        $riderror = $ridready;
        undef $ridready;
    }
    if($ridready) {
        # This runner is ready to be serviced
        my $testnum = $runnersrunning{$ridready};
        defined $testnum ||  die "Internal error: test for runner $ridready unknown";
        delete $runnersrunning{$ridready};
        my ($error, $again) = singletest($ridready, $testnum, $countforrunner{$ridready}, $totaltests);
        if($again) {
            # this runner is busy running a test
            $runnersrunning{$ridready} = $testnum;
        } else {
            # Test is complete
            runnerready($ridready);

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
                    # display all files in $LOGDIR/ in a nice way
                    displaylogs($ridready, $testnum);
                }
                if($error==2) {
                    $ign++; # ignored test result counter
                }
                elsif(!$anyway) {
                    # a test failed, abort
                    logmsg "\n - abort tests\n";
                    undef @runtests;  # empty out the remaining tests
                }
            }
            elsif(!$error) {
                $ok++; # successful test counter
            }
        }
    }
    if($riderror) {
        logmsg "ERROR: runner $riderror is dead! aborting test run\n";
        delete $runnersrunning{$riderror} if(defined $runnersrunning{$riderror});
        $globalabort = 1;
    }
    if(!scalar(@runtests) && ++$endwaitcnt == (240 + $jobs)) {
        # Once all tests have been scheduled on a runner at the end of a test
        # run, we just wait for their results to come in. If we're still
        # waiting after a couple of minutes ($endwaitcnt multiplied by
        # $runnerwait, plus $jobs because that number won't time out), display
        # the same test runner status as we give with a SIGUSR1. This will
        # likely point to a single test that has hung.
        logmsg "Hmmm, the tests are taking a while to finish. Here is the status:\n";
        catch_usr1();
    }
}

my $sofar = time() - $start;

#######################################################################
# Finish CI Test Run
citest_finishtestrun();

# Tests done, stop the servers
foreach my $runnerid (values %runnerids) {
    runnerac_stopservers($runnerid);
}

# Wait for servers to stop
my $unexpected;
foreach my $runnerid (values %runnerids) {
    my ($rid, $unexpect, $logs) = runnerar($runnerid);
    $unexpected ||= $unexpect;
    logmsg $logs;
}

# Kill the runners
# There is a race condition here since we don't know exactly when the runners
# have each finished shutting themselves down, but we're about to exit so it
# doesn't make much difference.
foreach my $runnerid (values %runnerids) {
    runnerac_shutdown($runnerid);
    sleep 0;  # give runner a context switch so it can shut itself down
}

my $numskipped = %skipped ? sum values %skipped : 0;
my $all = $total + $numskipped;

runtimestats($lasttest);

if($all) {
    logmsg "TESTDONE: $all tests were considered during ".
        sprintf("%.0f", $sofar) ." seconds.\n";
}

if(%skipped && !$short) {
    my $s=0;
    # Temporary hash to print the restraints sorted by the number
    # of their occurrences
    my %restraints;
    logmsg "TESTINFO: $numskipped tests were skipped due to these restraints:\n";

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

sub testnumdetails {
    my ($desc, $numlist) = @_;
    foreach my $testnum (split(' ', $numlist)) {
        if(!loadtest("${TESTDIR}/test${testnum}")) {
            my @info_keywords = getpart("info", "keywords");
            my $testname = (getpart("client", "name"))[0];
            chomp $testname;
            logmsg "$desc $testnum: '$testname'";
            my $first = 1;
            for my $k (@info_keywords) {
                chomp $k;
                my $sep = ($first == 1) ? " " : ", ";
                logmsg "$sep$k";
                $first = 0;
            }
            logmsg "\n";
        }
    }
}

if($total) {
    if($failedign) {
        my $failedignsorted = numsortwords($failedign);
        testnumdetails("FAIL-IGNORED", $failedignsorted);
        logmsg "IGNORED: failed tests: $failedignsorted\n";
    }
    logmsg sprintf("TESTDONE: $ok tests out of $total reported OK: %d%%\n",
                   $ok/$total*100);

    if($failed && ($ok != $total)) {
        my $failedsorted = numsortwords($failed);
        logmsg "\n";
        testnumdetails("FAIL", $failedsorted);
        logmsg "\nTESTFAIL: These test cases failed: $failedsorted\n\n";
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
