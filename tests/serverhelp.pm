#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
    servername_id
    servername_str
    servername_canon
    );


#***************************************************************************
# Return server name string formatted for presentation purposes
#
sub servername_str {
    my ($proto, $ipver, $idnum) = @_;

    $proto = uc($proto) if($proto);
    die "unsupported protocol: $proto" unless($proto &&
        ($proto =~ /^(((FTP|HTTP|IMAP|POP3|SMTP|TFTP)S?)|(SOCKS|SSH))$/));

    $ipver = (not $ipver) ? 'ipv4' : lc($ipver);
    die "unsupported IP version: $ipver" unless($ipver &&
        ($ipver =~ /^(4|6|ipv4|ipv6|-ipv4|-ipv6)$/));
    $ipver = ($ipver =~ /6$/) ? '-IPv6' : '';

    $idnum = 1 if(not $idnum);
    die "unsupported ID number: $idnum" unless($idnum &&
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
    return $string;
}


#***************************************************************************
# End of library
1;

