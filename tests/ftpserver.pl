#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################

# This is a server designed for the curl test suite.
#
# In December 2009 we started remaking the server to support more protocols
# that are similar in spirit. Like POP3, IMAP and SMTP in addition to the FTP
# it already supported since a long time. Note that it still only supports one
# protocol per invoke. You need to start mulitple servers to support multiple
# protocols simultaneously.
#
# It is meant to exercise curl, it is not meant to be a fully working
# or even very standard compliant server.
#
# You may optionally specify port on the command line, otherwise it'll
# default to port 8921.
#
# All socket/network/TCP related stuff is done by the 'sockfilt' program.
#

BEGIN {
    @INC=(@INC, $ENV{'srcdir'}, '.');
    # sub second timestamping needs Time::HiRes
    eval {
        no warnings "all";
        require Time::HiRes;
        import  Time::HiRes qw( gettimeofday );
    }
}

use strict;
use warnings;
use IPC::Open2;

require "getpart.pm";
require "ftp.pm";

use serverhelp qw(
    servername_str
    server_pidfilename
    server_logfilename
    mainsockf_pidfilename
    mainsockf_logfilename
    datasockf_pidfilename
    datasockf_logfilename
    );

#**********************************************************************
# global vars...
#
my $verbose = 0;    # set to 1 for debugging
my $idstr = "";     # server instance string
my $idnum = 1;      # server instance number
my $ipvnum = 4;     # server IPv number (4 or 6)
my $proto = 'ftp';  # default server protocol
my $srcdir;         # directory where ftpserver.pl is located
my $srvrname;       # server name for presentation purposes
my $grok_eprt;

my $path   = '.';
my $logdir = $path .'/log';

#**********************************************************************
# global vars used for server address and primary listener port
#
my $port = 8921;               # default primary listener port
my $listenaddr = '127.0.0.1';  # default address for listener port

#**********************************************************************
# global vars used for file names
#
my $pidfile;            # server pid file name
my $logfile;            # server log file name
my $mainsockf_pidfile;  # pid file for primary connection sockfilt process
my $mainsockf_logfile;  # log file for primary connection sockfilt process
my $datasockf_pidfile;  # pid file for secondary connection sockfilt process
my $datasockf_logfile;  # log file for secondary connection sockfilt process

#**********************************************************************
# global vars used for server logs advisor read lock handling
#
my $SERVERLOGS_LOCK = 'log/serverlogs.lock';
my $serverlogslocked = 0;

#**********************************************************************
# global vars used for child processes PID tracking
#
my $sfpid;        # PID for primary connection sockfilt process
my $slavepid;     # PID for secondary connection sockfilt process

#**********************************************************************
# global typeglob filehandle vars to read/write from/to sockfilters
#
local *SFREAD;    # used to read from primary connection
local *SFWRITE;   # used to write to primary connection
local *DREAD;     # used to read from secondary connection
local *DWRITE;    # used to write to secondary connection

#**********************************************************************
# global vars which depend on server protocol selection
#
my %commandfunc;  # protocol command specific function callbacks
my %displaytext;  # text returned to client before callback runs
my @welcome;      # text returned to client upon connection

#**********************************************************************
# global vars customized for each test from the server commands file
#
my $ctrldelay;    # set if server should throttle ctrl stream
my $datadelay;    # set if server should throttle data stream
my $retrweirdo;   # set if ftp server should use RETRWEIRDO
my $retrnosize;   # set if ftp server should use RETRNOSIZE
my $pasvbadip;    # set if ftp server should use PASVBADIP
my $nosave;       # set if ftp server should not save uploaded data
my %customreply;  #
my %customcount;  #
my %delayreply;   #

#**********************************************************************
# global vars used for signal handling
#
my $got_exit_signal = 0; # set if program should finish execution ASAP
my $exit_signal;         # first signal handled in exit_signal_handler

#**********************************************************************
# exit_signal_handler will be triggered to indicate that the program
# should finish its execution in a controlled way as soon as possible.
# For now, program will also terminate from within this handler.
#
sub exit_signal_handler {
    my $signame = shift;
    # For now, simply mimic old behavior.
    killsockfilters($proto, $ipvnum, $idnum, $verbose);
    unlink($pidfile);
    if($serverlogslocked) {
        $serverlogslocked = 0;
        clear_advisor_read_lock($SERVERLOGS_LOCK);
    }
    exit;
}

#**********************************************************************
# logmsg is general message logging subroutine for our test servers.
#
sub logmsg {
    my $now;
    # sub second timestamping needs Time::HiRes
    if($Time::HiRes::VERSION) {
        my ($seconds, $usec) = gettimeofday();
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
            localtime($seconds);
        $now = sprintf("%02d:%02d:%02d.%06d ", $hour, $min, $sec, $usec);
    }
    else {
        my $seconds = time();
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
            localtime($seconds);
        $now = sprintf("%02d:%02d:%02d ", $hour, $min, $sec);
    }
    if(open(LOGFILEFH, ">>$logfile")) {
        print LOGFILEFH $now;
        print LOGFILEFH @_;
        close(LOGFILEFH);
    }
}

sub ftpmsg {
  # append to the server.input file
  open(INPUT, ">>log/server$idstr.input") ||
    logmsg "failed to open log/server$idstr.input\n";

  print INPUT @_;
  close(INPUT);

  # use this, open->print->close system only to make the file
  # open as little as possible, to make the test suite run
  # better on windows/cygwin
}


sub sysread_or_die {
    my $FH     = shift;
    my $scalar = shift;
    my $length = shift;
    my $fcaller;
    my $lcaller;
    my $result;

    $result = sysread($$FH, $$scalar, $length);

    if(not defined $result) {
        ($fcaller, $lcaller) = (caller)[1,2];
        logmsg "Failed to read input\n";
        logmsg "Error: $srvrname server, sysread error: $!\n";
        logmsg "Exited from sysread_or_die() at $fcaller " .
               "line $lcaller. $srvrname server, sysread error: $!\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose);
        unlink($pidfile);
        if($serverlogslocked) {
            $serverlogslocked = 0;
            clear_advisor_read_lock($SERVERLOGS_LOCK);
        }
        exit;
    }
    elsif($result == 0) {
        ($fcaller, $lcaller) = (caller)[1,2];
        logmsg "Failed to read input\n";
        logmsg "Error: $srvrname server, read zero\n";
        logmsg "Exited from sysread_or_die() at $fcaller " .
               "line $lcaller. $srvrname server, read zero\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose);
        unlink($pidfile);
        if($serverlogslocked) {
            $serverlogslocked = 0;
            clear_advisor_read_lock($SERVERLOGS_LOCK);
        }
        exit;
    }

    return $result;
}

sub startsf {
    my $mainsockfcmd = "./server/sockfilt " .
        "--ipv$ipvnum --port $port " .
        "--pidfile \"$mainsockf_pidfile\" " .
        "--logfile \"$mainsockf_logfile\"";
    $sfpid = open2(*SFREAD, *SFWRITE, $mainsockfcmd);

    print STDERR "$mainsockfcmd\n" if($verbose);

    print SFWRITE "PING\n";
    my $pong;
    sysread_or_die(\*SFREAD, \$pong, 5);

    if($pong !~ /^PONG/) {
        logmsg "Failed sockfilt command: $mainsockfcmd\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose);
        unlink($pidfile);
        if($serverlogslocked) {
            $serverlogslocked = 0;
            clear_advisor_read_lock($SERVERLOGS_LOCK);
        }
        die "Failed to start sockfilt!";
    }
}


sub sockfilt {
    my $l;
    foreach $l (@_) {
        printf SFWRITE "DATA\n%04x\n", length($l);
        print SFWRITE $l;
    }
}


sub sockfiltsecondary {
    my $l;
    foreach $l (@_) {
        printf DWRITE "DATA\n%04x\n", length($l);
        print DWRITE $l;
    }
}


# Send data to the client on the control stream, which happens to be plain
# stdout.

sub sendcontrol {
    if(!$ctrldelay) {
        # spit it all out at once
        sockfilt @_;
    }
    else {
        my $a = join("", @_);
        my @a = split("", $a);

        for(@a) {
            sockfilt $_;
            select(undef, undef, undef, 0.01);
        }
    }
    my $log;
    foreach $log (@_) {
        my $l = $log;
        $l =~ s/[\r\n]//g;
        logmsg "> \"$l\"\n";
    }
}

# Send data to the client on the data stream

sub senddata {
    my $l;
    foreach $l (@_) {
      if(!$datadelay) {
        # spit it all out at once
        sockfiltsecondary $l;
      }
      else {
          # pause between each byte
          for (split(//,$l)) {
              sockfiltsecondary $_;
              select(undef, undef, undef, 0.01);
          }
      }
    }
}

#**********************************************************************
# protocolsetup initializes the 'displaytext' and 'commandfunc' hashes
# for the given protocol. References to protocol command callbacks are
# stored in 'commandfunc' hash, and text which will be returned to the
# client before the command callback runs is stored in 'displaytext'.
#
sub protocolsetup {
    my $proto = $_[0];

    if($proto eq 'ftp') {
        %commandfunc = (
            'PORT' => \&PORT_ftp,
            'EPRT' => \&PORT_ftp,
            'LIST' => \&LIST_ftp,
            'NLST' => \&NLST_ftp,
            'PASV' => \&PASV_ftp,
            'EPSV' => \&PASV_ftp,
            'RETR' => \&RETR_ftp,
            'SIZE' => \&SIZE_ftp,
            'REST' => \&REST_ftp,
            'STOR' => \&STOR_ftp,
            'APPE' => \&STOR_ftp, # append looks like upload
            'MDTM' => \&MDTM_ftp,
        );
        %displaytext = (
            'USER' => '331 We are happy you popped in!',
            'PASS' => '230 Welcome you silly person',
            'PORT' => '200 You said PORT - I say FINE',
            'TYPE' => '200 I modify TYPE as you wanted',
            'LIST' => '150 here comes a directory',
            'NLST' => '150 here comes a directory',
            'CWD'  => '250 CWD command successful.',
            'SYST' => '215 UNIX Type: L8', # just fake something
            'QUIT' => '221 bye bye baby', # just reply something
            'PWD'  => '257 "/nowhere/anywhere" is current directory',
            'MKD'  => '257 Created your requested directory',
            'REST' => '350 Yeah yeah we set it there for you',
            'DELE' => '200 OK OK OK whatever you say',
            'RNFR' => '350 Received your order. Please provide more',
            'RNTO' => '250 Ok, thanks. File renaming completed.',
            'NOOP' => '200 Yes, I\'m very good at doing nothing.',
            'PBSZ' => '500 PBSZ not implemented',
            'PROT' => '500 PROT not implemented',
        );
        @welcome = (
            '220-        _   _ ____  _     '."\r\n",
            '220-    ___| | | |  _ \| |    '."\r\n",
            '220-   / __| | | | |_) | |    '."\r\n",
            '220-  | (__| |_| |  _ <| |___ '."\r\n",
            '220    \___|\___/|_| \_\_____|'."\r\n"
        );
    }
    elsif($proto eq 'pop3') {
        %commandfunc = (
            'RETR' => \&RETR_pop3,
        );
        %displaytext = (
            'USER' => '+OK We are happy you popped in!',
            'PASS' => '+OK Access granted',
            'QUIT' => '+OK byebye',
        );
        @welcome = (
            '        _   _ ____  _     '."\r\n",
            '    ___| | | |  _ \| |    '."\r\n",
            '   / __| | | | |_) | |    '."\r\n",
            '  | (__| |_| |  _ <| |___ '."\r\n",
            '   \___|\___/|_| \_\_____|'."\r\n",
            '+OK cURL POP3 server ready to serve'."\r\n"
        );
    }
    elsif($proto eq 'imap') {
        %commandfunc = (
            'FETCH'  => \&FETCH_imap,
            'SELECT' => \&SELECT_imap,
        );
        %displaytext = (
            'LOGIN'  => ' OK We are happy you popped in!',
            'SELECT' => ' OK selection done',
            'LOGOUT' => ' OK thanks for the fish',
        );
        @welcome = (
            '        _   _ ____  _     '."\r\n",
            '    ___| | | |  _ \| |    '."\r\n",
            '   / __| | | | |_) | |    '."\r\n",
            '  | (__| |_| |  _ <| |___ '."\r\n",
            '   \___|\___/|_| \_\_____|'."\r\n",
            '* OK cURL IMAP server ready to serve'."\r\n"
        );
    }
    elsif($proto eq 'smtp') {
        %commandfunc = (
            'DATA' => \&DATA_smtp,
            'RCPT' => \&RCPT_smtp,
        );
        %displaytext = (
            'EHLO' => '230 We are happy you popped in!',
            'MAIL' => '200 Note taken',
            'RCPT' => '200 Receivers accepted',
            'QUIT' => '200 byebye',
        );
        @welcome = (
            '220-        _   _ ____  _     '."\r\n",
            '220-    ___| | | |  _ \| |    '."\r\n",
            '220-   / __| | | | |_) | |    '."\r\n",
            '220-  | (__| |_| |  _ <| |___ '."\r\n",
            '220    \___|\___/|_| \_\_____|'."\r\n"
        );
    }
}

sub close_dataconn {
    my ($closed)=@_; # non-zero if already disconnected

    my $datapid = processexists($datasockf_pidfile);

    if(!$closed) {
        logmsg "* disconnect data connection\n";
        if($datapid > 0) {
            print DWRITE "DISC\n";
            my $i;
            sysread DREAD, $i, 5;
        }
    }
    else {
        logmsg "data connection already disconnected\n";
    }
    logmsg "=====> Closed data connection\n";

    logmsg "* quit sockfilt for data (pid $datapid)\n";
    if($datapid > 0) {
        print DWRITE "QUIT\n";
        waitpid($datapid, 0);
        unlink($datasockf_pidfile) if(-f $datasockf_pidfile);
    }
}

################
################ SMTP commands
################

# what set by "RCPT"
my $smtp_rcpt;

sub DATA_smtp {
    my $testno;

    if($smtp_rcpt =~ /^TO:(.*)/) {
        $testno = $1;
    }
    else {
        return; # failure
    }

    if($testno eq "<verifiedserver>") {
        sendcontrol "554 WE ROOLZ: $$\r\n";
        return 0; # don't wait for data now
    }
    else {
        $testno =~ s/^([^0-9]*)([0-9]+).*/$2/;
        sendcontrol "354 Show me the mail\r\n";
    }

    logmsg "===> rcpt $testno was $smtp_rcpt\n";

    my $filename = "log/upload.$testno";

    logmsg "Store test number $testno in $filename\n";

    open(FILE, ">$filename") ||
        return 0; # failed to open output

    my $line;
    my $ulsize=0;
    my $disc=0;
    my $raw;
    while (5 == (sysread \*SFREAD, $line, 5)) {
        if($line eq "DATA\n") {
            my $i;
            my $eob;
            sysread \*SFREAD, $i, 5;

            my $size = 0;
            if($i =~ /^([0-9a-fA-F]{4})\n/) {
                $size = hex($1);
            }

            sysread \*SFREAD, $line, $size;

            $ulsize += $size;
            print FILE $line if(!$nosave);

            $raw .= $line;
            if($raw =~ /\x0d\x0a\x2e\x0d\x0a/) {
                # end of data marker!
                $eob = 1;
            }
            logmsg "> Appending $size bytes to file\n";
            if($eob) {
                logmsg "Found SMTP EOB marker\n";
                last;
            }
        }
        elsif($line eq "DISC\n") {
            # disconnect!
            $disc=1;
            last;
        }
        else {
            logmsg "No support for: $line";
            last;
        }
    }
    if($nosave) {
        print FILE "$ulsize bytes would've been stored here\n";
    }
    close(FILE);
    sendcontrol "250 OK, data received!\r\n";
    logmsg "received $ulsize bytes upload\n";

}

sub RCPT_smtp {
    my ($args) = @_;

    $smtp_rcpt = $args;
}

################
################ IMAP commands
################

# global to allow the command functions to read it
my $cmdid;

# what was picked by SELECT
my $selected;

sub SELECT_imap {
    my ($testno) = @_;
    my @data;
    my $size;

    logmsg "SELECT_imap got test $testno\n";

    $selected = $testno;

    return 0;
}


sub FETCH_imap {
     my ($testno) = @_;
     my @data;
     my $size;

     logmsg "FETCH_imap got test $testno\n";

     $testno = $selected;

     if($testno =~ /^verifiedserver$/) {
         # this is the secret command that verifies that this actually is
         # the curl test server
         my $response = "WE ROOLZ: $$\r\n";
         if($verbose) {
             print STDERR "FTPD: We returned proof we are the test server\n";
         }
         $data[0] = $response;
         logmsg "return proof we are we\n";
     }
     else {
         logmsg "retrieve a mail\n";

         $testno =~ s/^([^0-9]*)//;
         my $testpart = "";
         if ($testno > 10000) {
             $testpart = $testno % 10000;
             $testno = int($testno / 10000);
         }

         # send mail content
         loadtest("$srcdir/data/test$testno");

         @data = getpart("reply", "data$testpart");
     }

     for (@data) {
         $size += length($_);
     }

     sendcontrol "* FETCH starts {$size}\r\n";

     for my $d (@data) {
         sendcontrol $d;
     }

     sendcontrol "$cmdid OK FETCH completed\r\n";

     return 0;
}

################
################ POP3 commands
################

sub RETR_pop3 {
     my ($testno) = @_;
     my @data;

     if($testno =~ /^verifiedserver$/) {
         # this is the secret command that verifies that this actually is
         # the curl test server
         my $response = "WE ROOLZ: $$\r\n";
         if($verbose) {
             print STDERR "FTPD: We returned proof we are the test server\n";
         }
         $data[0] = $response;
         logmsg "return proof we are we\n";
     }
     else {
         logmsg "retrieve a mail\n";

         $testno =~ s/^([^0-9]*)//;
         my $testpart = "";
         if ($testno > 10000) {
             $testpart = $testno % 10000;
             $testno = int($testno / 10000);
         }

         # send mail content
         loadtest("$srcdir/data/test$testno");

         @data = getpart("reply", "data$testpart");
     }

     sendcontrol "+OK Mail transfer starts\r\n";

     for my $d (@data) {
         sendcontrol $d;
     }

     # end with the magic 5-byte end of mail marker
     sendcontrol "\r\n.\r\n";

     return 0;
}

################
################ FTP commands
################
my $rest=0;
sub REST_ftp {
    $rest = $_[0];
    logmsg "Set REST position to $rest\n"
}

sub LIST_ftp {
  #  print "150 ASCII data connection for /bin/ls (193.15.23.1,59196) (0 bytes)\r\n";

# this is a built-in fake-dir ;-)
my @ftpdir=("total 20\r\n",
"drwxr-xr-x   8 98       98           512 Oct 22 13:06 .\r\n",
"drwxr-xr-x   8 98       98           512 Oct 22 13:06 ..\r\n",
"drwxr-xr-x   2 98       98           512 May  2  1996 .NeXT\r\n",
"-r--r--r--   1 0        1             35 Jul 16  1996 README\r\n",
"lrwxrwxrwx   1 0        1              7 Dec  9  1999 bin -> usr/bin\r\n",
"dr-xr-xr-x   2 0        1            512 Oct  1  1997 dev\r\n",
"drwxrwxrwx   2 98       98           512 May 29 16:04 download.html\r\n",
"dr-xr-xr-x   2 0        1            512 Nov 30  1995 etc\r\n",
"drwxrwxrwx   2 98       1            512 Oct 30 14:33 pub\r\n",
"dr-xr-xr-x   5 0        1            512 Oct  1  1997 usr\r\n");

    logmsg "pass LIST data on data connection\n";
    for(@ftpdir) {
        senddata $_;
    }
    close_dataconn(0);
    sendcontrol "226 ASCII transfer complete\r\n";
    return 0;
}

sub NLST_ftp {
    my @ftpdir=("file", "with space", "fake", "..", " ..", "funny", "README");
    logmsg "pass NLST data on data connection\n";
    for(@ftpdir) {
        senddata "$_\r\n";
    }
    close_dataconn(0);
    sendcontrol "226 ASCII transfer complete\r\n";
    return 0;
}

sub MDTM_ftp {
    my $testno = $_[0];
    my $testpart = "";
    if ($testno > 10000) {
        $testpart = $testno % 10000;
        $testno = int($testno / 10000);
    }

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "mdtm");

    my $reply = $data[0];
    chomp $reply if($reply);

    if($reply && ($reply =~ /^[+-]?\d+$/) && ($reply < 0)) {
        sendcontrol "550 $testno: no such file.\r\n";
    }
    elsif($reply) {
        sendcontrol "$reply\r\n";
    }
    else {
        sendcontrol "500 MDTM: no such command.\r\n";
    }
    return 0;
}

sub SIZE_ftp {
    my $testno = $_[0];

    if($testno =~ /^verifiedserver$/) {
        my $response = "WE ROOLZ: $$\r\n";
        my $size = length($response);
        sendcontrol "213 $size\r\n";
        return 0;
    }

    if($testno =~ /(\d+)\/?$/) {
        $testno = $1;
    }
    else {
        print STDERR "SIZE_ftp: invalid test number: $testno\n";
        return 1;
    }

    my $testpart = "";
    if($testno > 10000) {
        $testpart = $testno % 10000;
        $testno = int($testno / 10000);
    }

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "size");

    my $size = $data[0];

    if($size) {
        if($size > -1) {
            sendcontrol "213 $size\r\n";
        }
        else {
            sendcontrol "550 $testno: No such file or directory.\r\n";
        }
    }
    else {
        $size=0;
        @data = getpart("reply", "data$testpart");
        for(@data) {
            $size += length($_);
        }
        if($size) {
            sendcontrol "213 $size\r\n";
        }
        else {
            sendcontrol "550 $testno: No such file or directory.\r\n";
        }
    }
    return 0;
}

sub RETR_ftp {
    my ($testno) = @_;

    if($testno =~ /^verifiedserver$/) {
        # this is the secret command that verifies that this actually is
        # the curl test server
        my $response = "WE ROOLZ: $$\r\n";
        my $len = length($response);
        sendcontrol "150 Binary junk ($len bytes).\r\n";
        senddata "WE ROOLZ: $$\r\n";
        close_dataconn(0);
        sendcontrol "226 File transfer complete\r\n";
        if($verbose) {
            print STDERR "FTPD: We returned proof we are the test server\n";
        }
        return 0;
    }

    $testno =~ s/^([^0-9]*)//;
    my $testpart = "";
    if ($testno > 10000) {
        $testpart = $testno % 10000;
        $testno = int($testno / 10000);
    }

    loadtest("$srcdir/data/test$testno");

    my @data = getpart("reply", "data$testpart");

    my $size=0;
    for(@data) {
        $size += length($_);
    }

    my %hash = getpartattr("reply", "data$testpart");

    if($size || $hash{'sendzero'}) {

        if($rest) {
            # move read pointer forward
            $size -= $rest;
            logmsg "REST $rest was removed from size, makes $size left\n";
            $rest = 0; # reset REST offset again
        }
        if($retrweirdo) {
            sendcontrol "150 Binary data connection for $testno () ($size bytes).\r\n",
            "226 File transfer complete\r\n";

            for(@data) {
                my $send = $_;
                senddata $send;
            }
            close_dataconn(0);
            $retrweirdo=0; # switch off the weirdo again!
        }
        else {
            my $sz = "($size bytes)";
            if($retrnosize) {
                $sz = "size?";
            }

            sendcontrol "150 Binary data connection for $testno () $sz.\r\n";

            for(@data) {
                my $send = $_;
                senddata $send;
            }
            close_dataconn(0);
            sendcontrol "226 File transfer complete\r\n";
        }
    }
    else {
        sendcontrol "550 $testno: No such file or directory.\r\n";
    }
    return 0;
}

sub STOR_ftp {
    my $testno=$_[0];

    my $filename = "log/upload.$testno";

    logmsg "STOR test number $testno in $filename\n";

    sendcontrol "125 Gimme gimme gimme!\r\n";

    open(FILE, ">$filename") ||
        return 0; # failed to open output

    my $line;
    my $ulsize=0;
    my $disc=0;
    while (5 == (sysread DREAD, $line, 5)) {
        if($line eq "DATA\n") {
            my $i;
            sysread DREAD, $i, 5;

            my $size = 0;
            if($i =~ /^([0-9a-fA-F]{4})\n/) {
                $size = hex($1);
            }

            sysread DREAD, $line, $size;

            #print STDERR "  GOT: $size bytes\n";

            $ulsize += $size;
            print FILE $line if(!$nosave);
            logmsg "> Appending $size bytes to file\n";
        }
        elsif($line eq "DISC\n") {
            # disconnect!
            $disc=1;
            last;
        }
        else {
            logmsg "No support for: $line";
            last;
        }
    }
    if($nosave) {
        print FILE "$ulsize bytes would've been stored here\n";
    }
    close(FILE);
    close_dataconn($disc);
    logmsg "received $ulsize bytes upload\n";
    sendcontrol "226 File transfer complete\r\n";
    return 0;
}

sub PASV_ftp {
    my ($arg, $cmd)=@_;
    my $pasvport;

    # kill previous data connection sockfilt when alive
    killsockfilters($proto, $ipvnum, $idnum, $verbose, 'data');

    # We fire up a new sockfilt to do the data transfer for us.
    my $datasockfcmd = "./server/sockfilt " .
        "--ipv$ipvnum --port 0 " .
        "--pidfile \"$datasockf_pidfile\" " .
        "--logfile \"$datasockf_logfile\"";
    $slavepid = open2(\*DREAD, \*DWRITE, $datasockfcmd);

    print DWRITE "PING\n";
    my $pong;
    sysread_or_die(\*DREAD, \$pong, 5);

    if($pong !~ /^PONG/) {
        logmsg "failed to run sockfilt for data connection\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose, 'data');
        sendcontrol "500 no free ports!\r\n";
        return 0;
    }

    logmsg "Run sockfilt for data on pid $slavepid\n";

    # Find out what port we listen on
    my $i;
    print DWRITE "PORT\n";

    # READ the response code
    sysread_or_die(\*DREAD, \$i, 5);

    # READ the response size
    sysread_or_die(\*DREAD, \$i, 5);

    my $size = 0;
    if($i =~ /^([0-9a-fA-F]{4})\n/) {
        $size = hex($1);
    }

    # READ the response data
    sysread_or_die(\*DREAD, \$i, $size);

    # The data is in the format
    # IPvX/NNN

    if($i =~ /IPv(\d)\/(\d+)/) {
        # FIX: deal with IP protocol version
        $pasvport = $2;
    }

    if($cmd ne "EPSV") {
        # PASV reply
        my $p=$listenaddr;
        $p =~ s/\./,/g;
        if($pasvbadip) {
            $p="1,2,3,4";
        }
        sendcontrol sprintf("227 Entering Passive Mode ($p,%d,%d)\n",
                            ($pasvport/256), ($pasvport%256));
    }
    else {
        # EPSV reply
        sendcontrol sprintf("229 Entering Passive Mode (|||%d|)\n", $pasvport);
    }

    eval {
        local $SIG{ALRM} = sub { die "alarm\n" };

        # assume swift operations unless explicitly slow
        alarm ($datadelay?20:10);

        # Wait for 'CNCT'
        my $input;

        while(sysread(DREAD, $input, 5)) {

            if($input !~ /^CNCT/) {
                # we wait for a connected client
                logmsg "Odd, we got $input from client\n";
                next;
            }
            logmsg "====> Client DATA connect\n";
            last;
        }
        alarm 0;
    };
    if ($@) {
        # timed out
        logmsg "$srvrname server timed out awaiting data connection ".
            "on port $pasvport\n";
        logmsg "accept failed or connection not even attempted\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose, 'data');
        return;
    }
    else {
        logmsg "data connection setup on port $pasvport\n";
    }

    return;
}

# Support both PORT and EPRT here. Consider LPRT too.

sub PORT_ftp {
    my ($arg, $cmd) = @_;
    my $port;
    my $addr;

    # We always ignore the given IP and use localhost.

    if($cmd eq "PORT") {
        if($arg !~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/) {
            logmsg "bad PORT-line: $arg\n";
            sendcontrol "500 silly you, go away\r\n";
            return 0;
        }
        $port = ($5<<8)+$6;
        $addr = "$1.$2.$3.$4";
    }
    # EPRT |2|::1|49706|
    elsif(($cmd eq "EPRT") && ($grok_eprt)) {
        if($arg !~ /(\d+)\|([^\|]+)\|(\d+)/) {
            sendcontrol "500 silly you, go away\r\n";
            return 0;
        }
        sendcontrol "200 Thanks for dropping by. We contact you later\r\n";
        $port = $3;
        $addr = $2;
    }
    else {
        sendcontrol "500 we don't like $cmd now\r\n";
        return 0;
    }

    if(!$port || $port > 65535) {
        print STDERR "very illegal PORT number: $port\n";
        return 1;
    }

    # We fire up a new sockfilt to do the data transfer for us.
    my $datasockfcmd = "./server/sockfilt " .
        "--ipv$ipvnum --connect $port --addr \"$addr\" " .
        "--pidfile \"$datasockf_pidfile\" " .
        "--logfile \"$datasockf_logfile\"";
    $slavepid = open2(\*DREAD, \*DWRITE, $datasockfcmd);

    print STDERR "$datasockfcmd\n" if($verbose);

    print DWRITE "PING\n";
    my $pong;
    sysread_or_die(\*DREAD, \$pong, 5);

    if($pong !~ /^PONG/) {
        logmsg "Failed sockfilt for data connection\n";
        killsockfilters($proto, $ipvnum, $idnum, $verbose, 'data');
    }

    logmsg "====> Client DATA connect to port $port\n";

    return;
}

#**********************************************************************
# customize configures test server operation for each curl test, reading
# configuration commands/parameters from server commands file each time
# a new client control connection is established with the test server.
# On success returns 1, otherwise zero.
#
sub customize {
    $ctrldelay = 0;    # default is no throttling of the ctrl stream
    $datadelay = 0;    # default is no throttling of the data stream
    $retrweirdo = 0;   # default is no use of RETRWEIRDO
    $retrnosize = 0;   # default is no use of RETRNOSIZE
    $pasvbadip = 0;    # default is no use of PASVBADIP
    $nosave = 0;       # default is to actually save uploaded data to file
    %customreply = (); #
    %customcount = (); #
    %delayreply = ();  #

    open(CUSTOM, "<log/ftpserver.cmd") ||
        return 1;

    logmsg "FTPD: Getting commands from log/ftpserver.cmd\n";

    while(<CUSTOM>) {
        if($_ =~ /REPLY ([A-Z]+) (.*)/) {
            $customreply{$1}=eval "qq{$2}";
            logmsg "FTPD: set custom reply for $1\n";
        }
        if($_ =~ /COUNT ([A-Z]+) (.*)/) {
            # we blank the customreply for this command when having
            # been used this number of times
            $customcount{$1}=$2;
            logmsg "FTPD: blank custom reply for $1 after $2 uses\n";
        }
        elsif($_ =~ /DELAY ([A-Z]+) (\d*)/) {
            $delayreply{$1}=$2;
            logmsg "FTPD: delay reply for $1 with $2 seconds\n";
        }
        elsif($_ =~ /SLOWDOWN/) {
            $ctrldelay=1;
            $datadelay=1;
            logmsg "FTPD: send response with 0.01 sec delay between each byte\n";
        }
        elsif($_ =~ /RETRWEIRDO/) {
            logmsg "FTPD: instructed to use RETRWEIRDO\n";
            $retrweirdo=1;
        }
        elsif($_ =~ /RETRNOSIZE/) {
            logmsg "FTPD: instructed to use RETRNOSIZE\n";
            $retrnosize=1;
        }
        elsif($_ =~ /PASVBADIP/) {
            logmsg "FTPD: instructed to use PASVBADIP\n";
            $pasvbadip=1;
        }
        elsif($_ =~ /NOSAVE/) {
            # don't actually store the file we upload - to be used when
            # uploading insanely huge amounts
            $nosave = 1;
            logmsg "FTPD: NOSAVE prevents saving of uploaded data\n";
        }
    }
    close(CUSTOM);
}

#----------------------------------------------------------------------
#----------------------------------------------------------------------
#---------------------------  END OF SUBS  ----------------------------
#----------------------------------------------------------------------
#----------------------------------------------------------------------

#**********************************************************************
# Parse command line options
#
# Options:
#
# --verbose   # verbose
# --srcdir    # source directory
# --id        # server instance number
# --proto     # server protocol
# --pidfile   # server pid file
# --logfile   # server log file
# --ipv4      # server IP version 4
# --ipv6      # server IP version 6
# --port      # server listener port
# --addr      # server address for listener port binding
#
while(@ARGV) {
    if($ARGV[0] eq '--verbose') {
        $verbose = 1;
    }
    elsif($ARGV[0] eq '--srcdir') {
        if($ARGV[1]) {
            $srcdir = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--id') {
        if($ARGV[1] && ($ARGV[1] =~ /^(\d+)$/)) {
            $idnum = $1 if($1 > 0);
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--proto') {
        if($ARGV[1] && ($ARGV[1] =~ /^(ftp|imap|pop3|smtp)$/)) {
            $proto = $1;
            shift @ARGV;
        }
        else {
            die "unsupported protocol $ARGV[1]";
        }
    }
    elsif($ARGV[0] eq '--pidfile') {
        if($ARGV[1]) {
            $pidfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--logfile') {
        if($ARGV[1]) {
            $logfile = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--ipv4') {
        $ipvnum = 4;
        $listenaddr = '127.0.0.1' if($listenaddr eq '::1');
        $grok_eprt = 0;
    }
    elsif($ARGV[0] eq '--ipv6') {
        $ipvnum = 6;
        $listenaddr = '::1' if($listenaddr eq '127.0.0.1');
        $grok_eprt = 1;
    }
    elsif($ARGV[0] eq '--port') {
        if($ARGV[1] && ($ARGV[1] =~ /^(\d+)$/)) {
            $port = $1 if($1 > 1024);
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--addr') {
        if($ARGV[1]) {
            my $tmpstr = $ARGV[1];
            if($tmpstr =~ /^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/) {
                $listenaddr = "$1.$2.$3.$4" if($ipvnum == 4);
            }
            elsif($ipvnum == 6) {
                $listenaddr = $tmpstr;
                $listenaddr =~ s/^\[(.*)\]$/$1/;
            }
            shift @ARGV;
        }
    }
    else {
        print STDERR "\nWarning: ftpserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

#***************************************************************************
# Initialize command line option dependant variables
#

if(!$srcdir) {
    $srcdir = $ENV{'srcdir'} || '.';
}
if(!$pidfile) {
    $pidfile = "$path/". server_pidfilename($proto, $ipvnum, $idnum);
}
if(!$logfile) {
    $logfile = server_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$mainsockf_pidfile = "$path/".
    mainsockf_pidfilename($proto, $ipvnum, $idnum);
$mainsockf_logfile =
    mainsockf_logfilename($logdir, $proto, $ipvnum, $idnum);

if($proto eq 'ftp') {
    $datasockf_pidfile = "$path/".
        datasockf_pidfilename($proto, $ipvnum, $idnum);
    $datasockf_logfile =
        datasockf_logfilename($logdir, $proto, $ipvnum, $idnum);
}

$srvrname = servername_str($proto, $ipvnum, $idnum);

$idstr = "$idnum" if($idnum > 1);

protocolsetup($proto);

$SIG{INT} = \&exit_signal_handler;
$SIG{TERM} = \&exit_signal_handler;

startsf();

logmsg sprintf("%s server listens on port IPv${ipvnum}/${port}\n", uc($proto));

open(PID, ">$pidfile");
print PID $$."\n";
close(PID);

logmsg("logged pid $$ in $pidfile\n");


while(1) {
    #
    # We read 'sockfilt' commands.
    #
    my $input;

    logmsg "Awaiting input\n";
    sysread_or_die(\*SFREAD, \$input, 5);

    if($input !~ /^CNCT/) {
        # we wait for a connected client
        logmsg "sockfilt said: $input";
        next;
    }
    logmsg "====> Client connect\n";

    set_advisor_read_lock($SERVERLOGS_LOCK);
    $serverlogslocked = 1;

    # flush data:
    $| = 1;

    killsockfilters($proto, $ipvnum, $idnum, $verbose, 'data');

    &customize(); # read test control instructions

    sendcontrol @welcome;
    if($verbose) {
        for(@welcome) {
            print STDERR "OUT: $_";
        }
    }

    while(1) {
        my $i;

        # Now we expect to read DATA\n[hex size]\n[prot], where the [prot]
        # part only is FTP lingo.

        # COMMAND
        sysread_or_die(\*SFREAD, \$i, 5);

        if($i !~ /^DATA/) {
            logmsg "sockfilt said $i";
            if($i =~ /^DISC/) {
                # disconnect
                last;
            }
            next;
        }

        # SIZE of data
        sysread_or_die(\*SFREAD, \$i, 5);

        my $size = 0;
        if($i =~ /^([0-9a-fA-F]{4})\n/) {
            $size = hex($1);
        }

        # data
        sysread SFREAD, $_, $size;

        ftpmsg $_;

        # Remove trailing CRLF.
        s/[\n\r]+$//;

        my $FTPCMD;
        my $FTPARG;
        my $full=$_;
        if($proto eq "imap") {
            # IMAP is different with its identifier first on the command line
            unless (m/^([^ ]+) ([^ ]+) (.*)/ ||
                    m/^([^ ]+) ([^ ]+)/) {
                sendcontrol "$1 '$_': command not understood.\r\n";
                last;
            }
            $cmdid=$1; # set the global variable
            $FTPCMD=$2;
            $FTPARG=$3;
        }
        else {
            unless (m/^([A-Z]{3,4})\s?(.*)/i) {
                sendcontrol "500 '$_': command not understood.\r\n";
                last;
            }
            $FTPCMD=$1;
            $FTPARG=$2;
        }

        logmsg "< \"$full\"\n";

        if($verbose) {
            print STDERR "IN: $full\n";
        }

        my $delay = $delayreply{$FTPCMD};
        if($delay) {
            # just go sleep this many seconds!
            logmsg("Sleep for $delay seconds\n");
            my $twentieths = $delay * 20;
            while($twentieths--) {
                select(undef, undef, undef, 0.05) unless($got_exit_signal);
            }
        }

        my $text;
        $text = $customreply{$FTPCMD};
        my $fake = $text;

        if($text && ($text ne "")) {
            if($customcount{$FTPCMD} && (!--$customcount{$FTPCMD})) {
                # used enough number of times, now blank the customreply
                $customreply{$FTPCMD}="";
            }
        }
        else {
            $text = $displaytext{$FTPCMD};
        }
        my $check;
        if($text && ($text ne "")) {
            if($cmdid && ($cmdid ne "")) {
                sendcontrol "$cmdid$text\r\n";
            }
            else {
                sendcontrol "$text\r\n";
            }
        }
        else {
            $check=1; # no response yet
        }

        unless($fake && ($fake ne "")) {
            # only perform this if we're not faking a reply
            my $func = $commandfunc{$FTPCMD};
            if($func) {
                &$func($FTPARG, $FTPCMD);
                $check=0; # taken care of
            }
        }

        if($check) {
            logmsg "$FTPCMD wasn't handled!\n";
            sendcontrol "500 $FTPCMD is not dealt with!\r\n";
        }

    } # while(1)
    logmsg "====> Client disconnected\n";

    if($serverlogslocked) {
        $serverlogslocked = 0;
        clear_advisor_read_lock($SERVERLOGS_LOCK);
    }
}

killsockfilters($proto, $ipvnum, $idnum, $verbose);
unlink($pidfile);
if($serverlogslocked) {
    $serverlogslocked = 0;
    clear_advisor_read_lock($SERVERLOGS_LOCK);
}

exit;
