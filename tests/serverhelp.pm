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
#***************************************************************************

# This perl module contains functions useful in writing test servers.

package serverhelp;

use strict;
use warnings;

use Time::HiRes;

BEGIN {
    use base qw(Exporter);

    our @EXPORT_OK = qw(
        logmsg
        $logfile
        serverfactors
        servername_id
        servername_str
        servername_canon
        server_pidfilename
        server_portfilename
        server_logfilename
        server_cmdfilename
        server_inputfilename
        server_outputfilename
        server_exe
        server_exe_args
        mainsockf_pidfilename
        mainsockf_logfilename
        datasockf_pidfilename
        datasockf_logfilename
    );
}

use globalconfig;
use pathhelp qw(
    exe_ext
    );
use testutil qw(
    exerunner
    );

our $logfile;  # server log file name, for logmsg

#***************************************************************************
# Just for convenience, test harness uses 'https' and 'httptls' literals as
# values for 'proto' variable in order to differentiate different servers.
# 'https' literal is used for stunnel based https test servers, and 'httptls'
# is used for non-stunnel https test servers.

#**********************************************************************
# logmsg is general message logging subroutine for our test servers.
#
sub logmsg {
    my ($seconds, $usec) = Time::HiRes::gettimeofday();
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
        localtime($seconds);
    my $now = sprintf("%02d:%02d:%02d.%06d ", $hour, $min, $sec, $usec);
    # we see warnings on Windows run that $logfile is used uninitialized
    # TODO: not found yet where this comes from
    $logfile = "serverhelp_uninitialized.log" if(!$logfile);
    if(open(my $logfilefh, ">>", "$logfile")) {
        print $logfilefh $now;
        print $logfilefh @_;
        close($logfilefh);
    }
}


#***************************************************************************
# Return server characterization factors given a server id string.
#
sub serverfactors {
    my $server = $_[0];
    my $proto;
    my $ipvnum;
    my $idnum;

    if($server =~
        /^((ftp|http|imap|pop3|smtp)s?)(\d*)(-ipv6|)$/) {
        $proto  = $1;
        $idnum  = ($3 && ($3 > 1)) ? $3 : 1;
        $ipvnum = ($4 && ($4 =~ /6$/)) ? 6 : 4;
    }
    elsif($server =~
        /^(dns|tftp|sftp|socks|ssh|rtsp|gopher|httptls)(\d*)(-ipv6|)$/) {
        $proto  = $1;
        $idnum  = ($2 && ($2 > 1)) ? $2 : 1;
        $ipvnum = ($3 && ($3 =~ /6$/)) ? 6 : 4;
    }
    else {
        die "invalid server id: '$server'"
    }
    return($proto, $ipvnum, $idnum);
}


#***************************************************************************
# Return server name string formatted for presentation purposes
#
sub servername_str {
    my ($proto, $ipver, $idnum) = @_;

    $proto = uc($proto) if($proto);
    die "unsupported protocol: '$proto'" unless($proto &&
        ($proto =~ /^(((DNS|FTP|HTTP|HTTP\/2|HTTP\/3|IMAP|POP3|GOPHER|SMTP|HTTPS-MTLS)S?)|(TFTP|SFTP|SOCKS|SSH|RTSP|HTTPTLS|DICT|SMB|SMBS|TELNET|MQTT))$/));

    $ipver = (not $ipver) ? 'ipv4' : lc($ipver);
    die "unsupported IP version: '$ipver'" unless($ipver &&
        ($ipver =~ /^(4|6|ipv4|ipv6|-ipv4|-ipv6|unix)$/));
    $ipver = ($ipver =~ /6$/) ? '-IPv6' : (($ipver =~ /unix$/) ? '-unix' : '');

    $idnum = 1 if(not $idnum);
    die "unsupported ID number: '$idnum'" unless($idnum &&
        ($idnum =~ /^(\d+)$/));
    $idnum = '' if($idnum <= 1);

    return "${proto}${idnum}${ipver}";
}


#***************************************************************************
# Return server name string formatted for identification purposes
#
sub servername_id {
    my ($proto, $ipver, $idnum) = @_;
    return lc(servername_str($proto, $ipver, $idnum));
}


#***************************************************************************
# Return server name string formatted for file name purposes
#
sub servername_canon {
    my ($proto, $ipver, $idnum) = @_;
    my $string = lc(servername_str($proto, $ipver, $idnum));
    $string =~ tr/-/_/;
    $string =~ s/\//_v/;
    return $string;
}


#***************************************************************************
# Return file name for server pid file.
#
sub server_pidfilename {
    my ($piddir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.pid';
    return "${piddir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}

#***************************************************************************
# Return file name for server port file.
#
sub server_portfilename {
    my ($piddir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.port';
    return "${piddir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for server log file.
#
sub server_logfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.log';
    $trailer = '_stunnel.log' if(lc($proto) =~ /^(ftp|http|imap|pop3|smtp)s$/);
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for server commands file.
#
sub server_cmdfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.cmd';
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for server input file.
#
sub server_inputfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.input';
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for server output file.
#
sub server_outputfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    my $trailer = '_server.output';
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return filename for a server executable
#
sub server_exe {
    my ($name, $ext) = @_;
    if(!defined $ext) {
        $ext = 'SRV';
    }
    return exerunner() . $SRVDIR . "servers" . exe_ext($ext) . " $name";
}


#***************************************************************************
# Return filename for a server executable as an argument list
#
sub server_exe_args {
    my ($name, $ext) = @_;
    if(!defined $ext) {
        $ext = 'SRV';
    }
    my @cmd = ($SRVDIR . "servers" . exe_ext($ext), $name);
    if($ENV{'CURL_TEST_EXE_RUNNER'}) {
        unshift @cmd, $ENV{'CURL_TEST_EXE_RUNNER'};
    }
    return @cmd;
}


#***************************************************************************
# Return file name for main or primary sockfilter pid file.
#
sub mainsockf_pidfilename {
    my ($piddir, $proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^(ftp|imap|pop3|smtp)s?$/));
    my $trailer = (lc($proto) =~ /^ftps?$/) ? '_sockctrl.pid':'_sockfilt.pid';
    return "${piddir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for main or primary sockfilter log file.
#
sub mainsockf_logfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^(ftp|imap|pop3|smtp)s?$/));
    my $trailer = (lc($proto) =~ /^ftps?$/) ? '_sockctrl.log':'_sockfilt.log';
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for data or secondary sockfilter pid file.
#
sub datasockf_pidfilename {
    my ($piddir, $proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^ftps?$/));
    my $trailer = '_sockdata.pid';
    return "${piddir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# Return file name for data or secondary sockfilter log file.
#
sub datasockf_logfilename {
    my ($logdir, $proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^ftps?$/));
    my $trailer = '_sockdata.log';
    return "${logdir}/". servername_canon($proto, $ipver, $idnum) ."$trailer";
}


#***************************************************************************
# End of library
1;
