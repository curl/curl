#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

package serverhelp;

use strict;
use warnings;
use Exporter;


#***************************************************************************
# Global symbols allowed without explicit package name
#
use vars qw(
    @ISA
    @EXPORT_OK
    );


#***************************************************************************
# Inherit Exporter's capabilities
#
@ISA = qw(Exporter);


#***************************************************************************
# Global symbols this module will export upon request
#
@EXPORT_OK = qw(
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
    mainsockf_pidfilename
    mainsockf_logfilename
    datasockf_pidfilename
    datasockf_logfilename
    );


#***************************************************************************
# Just for convenience, test harness uses 'https' and 'httptls' literals as
# values for 'proto' variable in order to differentiate different servers.
# 'https' literal is used for stunnel based https test servers, and 'httptls'
# is used for non-stunnel https test servers.


#***************************************************************************
# Return server characterization factors given a server id string.
#
sub serverfactors {
    my $server = $_[0];
    my $proto;
    my $ipvnum;
    my $idnum;

    if($server =~
        /^((ftp|http|imap|pop3|smtp|http-pipe)s?)(\d*)(-ipv6|)$/) {
        $proto  = $1;
        $idnum  = ($3 && ($3 > 1)) ? $3 : 1;
        $ipvnum = ($4 && ($4 =~ /6$/)) ? 6 : 4;
    }
    elsif($server =~
        /^(tftp|sftp|socks|ssh|rtsp|gopher|httptls)(\d*)(-ipv6|)$/) {
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
        ($proto =~ /^(((FTP|HTTP|HTTP\/2|HTTP\/3|IMAP|POP3|GOPHER|SMTP|HTTP-PIPE)S?)|(TFTP|SFTP|SOCKS|SSH|RTSP|HTTPTLS|DICT|SMB|SMBS|TELNET|MQTT))$/));

    $ipver = (not $ipver) ? 'ipv4' : lc($ipver);
    die "unsupported IP version: '$ipver'" unless($ipver &&
        ($ipver =~ /^(4|6|ipv4|ipv6|-ipv4|-ipv6|unix)$/));
    $ipver = ($ipver =~ /6$/) ? '-IPv6' : (($ipver =~ /unix$/) ? '-unix' : '');

    $idnum = 1 if(not $idnum);
    die "unsupported ID number: '$idnum'" unless($idnum &&
        ($idnum =~ /^(\d+)$/));
    $idnum = '' unless($idnum > 1);

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
    my ($proto, $ipver, $idnum) = @_;
    my $trailer = '_server.pid';
    return '.'. servername_canon($proto, $ipver, $idnum) ."$trailer";
}

#***************************************************************************
# Return file name for server port file.
#
sub server_portfilename {
    my ($proto, $ipver, $idnum) = @_;
    my $trailer = '_server.port';
    return '.'. servername_canon($proto, $ipver, $idnum) ."$trailer";
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
# Return file name for main or primary sockfilter pid file.
#
sub mainsockf_pidfilename {
    my ($proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^(ftp|imap|pop3|smtp)s?$/));
    my $trailer = (lc($proto) =~ /^ftps?$/) ? '_sockctrl.pid':'_sockfilt.pid';
    return '.'. servername_canon($proto, $ipver, $idnum) ."$trailer";
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
    my ($proto, $ipver, $idnum) = @_;
    die "unsupported protocol: '$proto'" unless($proto &&
        (lc($proto) =~ /^ftps?$/));
    my $trailer = '_sockdata.pid';
    return '.'. servername_canon($proto, $ipver, $idnum) ."$trailer";
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
