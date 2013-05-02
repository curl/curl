#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2011, 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#***************************************************************************

# Starts sshd for use in the SCP, SFTP and SOCKS curl test harness tests.
# Also creates the ssh configuration files needed for these tests.

use strict;
use warnings;
use Cwd;

#***************************************************************************
# Variables and subs imported from sshhelp module
#
use sshhelp qw(
    $sshdexe
    $sshexe
    $sftpsrvexe
    $sftpexe
    $sshkeygenexe
    $sshdconfig
    $sshconfig
    $sftpconfig
    $knownhosts
    $sshdlog
    $sshlog
    $sftplog
    $sftpcmds
    $hstprvkeyf
    $hstpubkeyf
    $cliprvkeyf
    $clipubkeyf
    display_sshdconfig
    display_sshconfig
    display_sftpconfig
    display_sshdlog
    display_sshlog
    display_sftplog
    dump_array
    find_sshd
    find_ssh
    find_sftpsrv
    find_sftp
    find_sshkeygen
    logmsg
    sshversioninfo
    );

#***************************************************************************
# Subs imported from serverhelp module
#
use serverhelp qw(
    server_pidfilename
    server_logfilename
    );


#***************************************************************************

my $verbose = 0;              # set to 1 for debugging
my $debugprotocol = 0;        # set to 1 for protocol debugging
my $port = 8999;              # our default SCP/SFTP server port
my $socksport = $port + 1;    # our default SOCKS4/5 server port
my $listenaddr = '127.0.0.1'; # default address on which to listen
my $ipvnum = 4;               # default IP version of listener address
my $idnum = 1;                # dafault ssh daemon instance number
my $proto = 'ssh';            # protocol the ssh daemon speaks
my $path = getcwd();          # current working directory
my $logdir = $path .'/log';   # directory for log files
my $username = $ENV{USER};    # default user
my $pidfile;                  # ssh daemon pid file

my $error;
my @cfgarr;


#***************************************************************************
# Parse command line options
#
while(@ARGV) {
    if($ARGV[0] eq '--verbose') {
        $verbose = 1;
    }
    elsif($ARGV[0] eq '--debugprotocol') {
        $verbose = 1;
        $debugprotocol = 1;
    }
    elsif($ARGV[0] eq '--user') {
        if($ARGV[1]) {
            $username = $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--id') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $idnum = $1 if($1 > 0);
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--ipv4') {
        $ipvnum = 4;
        $listenaddr = '127.0.0.1' if($listenaddr eq '::1');
    }
    elsif($ARGV[0] eq '--ipv6') {
        $ipvnum = 6;
        $listenaddr = '::1' if($listenaddr eq '127.0.0.1');
    }
    elsif($ARGV[0] eq '--addr') {
        if($ARGV[1]) {
            my $tmpstr = $ARGV[1];
            if($tmpstr =~ /^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/) {
                $listenaddr = "$1.$2.$3.$4" if($ipvnum == 4);
                shift @ARGV;
            }
            elsif($ipvnum == 6) {
                $listenaddr = $tmpstr;
                $listenaddr =~ s/^\[(.*)\]$/$1/;
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--pidfile') {
        if($ARGV[1]) {
            $pidfile = "$path/". $ARGV[1];
            shift @ARGV;
        }
    }
    elsif($ARGV[0] eq '--sshport') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $port = $1;
                shift @ARGV;
            }
        }
    }
    elsif($ARGV[0] eq '--socksport') {
        if($ARGV[1]) {
            if($ARGV[1] =~ /^(\d+)$/) {
                $socksport = $1;
                shift @ARGV;
            }
        }
    }
    else {
        print STDERR "\nWarning: sshserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}


#***************************************************************************
# Default ssh daemon pid file name
#
if(!$pidfile) {
    $pidfile = "$path/". server_pidfilename($proto, $ipvnum, $idnum);
}


#***************************************************************************
# ssh, socks and sftp server log file names
#
$sshdlog = server_logfilename($logdir, 'ssh', $ipvnum, $idnum);
$sftplog = server_logfilename($logdir, 'sftp', $ipvnum, $idnum);
$sshlog  = server_logfilename($logdir, 'socks', $ipvnum, $idnum);


#***************************************************************************
# Logging level for ssh server and client
#
my $loglevel = $debugprotocol?'DEBUG3':'DEBUG2';


#***************************************************************************
# Validate username
#
if(!$username) {
    $error = 'Will not run ssh server without a user name';
}
elsif($username eq 'root') {
    $error = 'Will not run ssh server as root to mitigate security risks';
}
if($error) {
    logmsg $error;
    exit 1;
}


#***************************************************************************
# Find out ssh daemon canonical file name
#
my $sshd = find_sshd();
if(!$sshd) {
    logmsg "cannot find $sshdexe";
    exit 1;
}


#***************************************************************************
# Find out ssh daemon version info
#
my ($sshdid, $sshdvernum, $sshdverstr, $sshderror) = sshversioninfo($sshd);
if(!$sshdid) {
    # Not an OpenSSH or SunSSH ssh daemon
    logmsg $sshderror if($verbose);
    logmsg 'SCP, SFTP and SOCKS tests require OpenSSH 2.9.9 or later';
    exit 1;
}
logmsg "ssh server found $sshd is $sshdverstr" if($verbose);


#***************************************************************************
#  ssh daemon command line options we might use and version support
#
#  -e:  log stderr           : OpenSSH 2.9.0 and later
#  -f:  sshd config file     : OpenSSH 1.2.1 and later
#  -D:  no daemon forking    : OpenSSH 2.5.0 and later
#  -o:  command-line option  : OpenSSH 3.1.0 and later
#  -t:  test config file     : OpenSSH 2.9.9 and later
#  -?:  sshd version info    : OpenSSH 1.2.1 and later
#
#  -e:  log stderr           : SunSSH 1.0.0 and later
#  -f:  sshd config file     : SunSSH 1.0.0 and later
#  -D:  no daemon forking    : SunSSH 1.0.0 and later
#  -o:  command-line option  : SunSSH 1.0.0 and later
#  -t:  test config file     : SunSSH 1.0.0 and later
#  -?:  sshd version info    : SunSSH 1.0.0 and later


#***************************************************************************
# Verify minimum ssh daemon version
#
if((($sshdid =~ /OpenSSH/) && ($sshdvernum < 299)) ||
   (($sshdid =~ /SunSSH/)  && ($sshdvernum < 100))) {
    logmsg 'SCP, SFTP and SOCKS tests require OpenSSH 2.9.9 or later';
    exit 1;
}


#***************************************************************************
# Find out sftp server plugin canonical file name
#
my $sftpsrv = find_sftpsrv();
if(!$sftpsrv) {
    logmsg "cannot find $sftpsrvexe";
    exit 1;
}
logmsg "sftp server plugin found $sftpsrv" if($verbose);


#***************************************************************************
# Find out sftp client canonical file name
#
my $sftp = find_sftp();
if(!$sftp) {
    logmsg "cannot find $sftpexe";
    exit 1;
}
logmsg "sftp client found $sftp" if($verbose);


#***************************************************************************
# Find out ssh keygen canonical file name
#
my $sshkeygen = find_sshkeygen();
if(!$sshkeygen) {
    logmsg "cannot find $sshkeygenexe";
    exit 1;
}
logmsg "ssh keygen found $sshkeygen" if($verbose);


#***************************************************************************
# Find out ssh client canonical file name
#
my $ssh = find_ssh();
if(!$ssh) {
    logmsg "cannot find $sshexe";
    exit 1;
}


#***************************************************************************
# Find out ssh client version info
#
my ($sshid, $sshvernum, $sshverstr, $ssherror) = sshversioninfo($ssh);
if(!$sshid) {
    # Not an OpenSSH or SunSSH ssh client
    logmsg $ssherror if($verbose);
    logmsg 'SCP, SFTP and SOCKS tests require OpenSSH 2.9.9 or later';
    exit 1;
}
logmsg "ssh client found $ssh is $sshverstr" if($verbose);


#***************************************************************************
#  ssh client command line options we might use and version support
#
#  -D:  dynamic app port forwarding  : OpenSSH 2.9.9 and later
#  -F:  ssh config file              : OpenSSH 2.9.9 and later
#  -N:  no shell/command             : OpenSSH 2.1.0 and later
#  -p:  connection port              : OpenSSH 1.2.1 and later
#  -v:  verbose messages             : OpenSSH 1.2.1 and later
# -vv:  increase verbosity           : OpenSSH 2.3.0 and later
#  -V:  ssh version info             : OpenSSH 1.2.1 and later
#
#  -D:  dynamic app port forwarding  : SunSSH 1.0.0 and later
#  -F:  ssh config file              : SunSSH 1.0.0 and later
#  -N:  no shell/command             : SunSSH 1.0.0 and later
#  -p:  connection port              : SunSSH 1.0.0 and later
#  -v:  verbose messages             : SunSSH 1.0.0 and later
# -vv:  increase verbosity           : SunSSH 1.0.0 and later
#  -V:  ssh version info             : SunSSH 1.0.0 and later


#***************************************************************************
# Verify minimum ssh client version
#
if((($sshid =~ /OpenSSH/) && ($sshvernum < 299)) ||
   (($sshid =~ /SunSSH/)  && ($sshvernum < 100))) {
    logmsg 'SCP, SFTP and SOCKS tests require OpenSSH 2.9.9 or later';
    exit 1;
}


#***************************************************************************
#  ssh keygen command line options we actually use and version support
#
#  -C:  identity comment : OpenSSH 1.2.1 and later
#  -f:  key filename     : OpenSSH 1.2.1 and later
#  -N:  new passphrase   : OpenSSH 1.2.1 and later
#  -q:  quiet keygen     : OpenSSH 1.2.1 and later
#  -t:  key type         : OpenSSH 2.5.0 and later
#
#  -C:  identity comment : SunSSH 1.0.0 and later
#  -f:  key filename     : SunSSH 1.0.0 and later
#  -N:  new passphrase   : SunSSH 1.0.0 and later
#  -q:  quiet keygen     : SunSSH 1.0.0 and later
#  -t:  key type         : SunSSH 1.0.0 and later


#***************************************************************************
# Generate host and client key files for curl's tests
#
if((! -e $hstprvkeyf) || (! -s $hstprvkeyf) ||
   (! -e $hstpubkeyf) || (! -s $hstpubkeyf) ||
   (! -e $cliprvkeyf) || (! -s $cliprvkeyf) ||
   (! -e $clipubkeyf) || (! -s $clipubkeyf)) {
    # Make sure all files are gone so ssh-keygen doesn't complain
    unlink($hstprvkeyf, $hstpubkeyf, $cliprvkeyf, $clipubkeyf);
    logmsg 'generating host keys...' if($verbose);
    if(system "$sshkeygen -q -t dsa -f $hstprvkeyf -C 'curl test server' -N ''") {
        logmsg 'Could not generate host key';
        exit 1;
    }
    logmsg 'generating client keys...' if($verbose);
    if(system "$sshkeygen -q -t dsa -f $cliprvkeyf -C 'curl test client' -N ''") {
        logmsg 'Could not generate client key';
        exit 1;
    }
}


#***************************************************************************
#  ssh daemon configuration file options we might use and version support
#
#  AFSTokenPassing                  : OpenSSH 1.2.1 and later [1]
#  AcceptEnv                        : OpenSSH 3.9.0 and later
#  AddressFamily                    : OpenSSH 4.0.0 and later
#  AllowGroups                      : OpenSSH 1.2.1 and later
#  AllowTcpForwarding               : OpenSSH 2.3.0 and later
#  AllowUsers                       : OpenSSH 1.2.1 and later
#  AuthorizedKeysFile               : OpenSSH 2.9.9 and later
#  AuthorizedKeysFile2              : OpenSSH 2.9.9 and later
#  Banner                           : OpenSSH 2.5.0 and later
#  ChallengeResponseAuthentication  : OpenSSH 2.5.0 and later
#  Ciphers                          : OpenSSH 2.1.0 and later [3]
#  ClientAliveCountMax              : OpenSSH 2.9.0 and later
#  ClientAliveInterval              : OpenSSH 2.9.0 and later
#  Compression                      : OpenSSH 3.3.0 and later
#  DenyGroups                       : OpenSSH 1.2.1 and later
#  DenyUsers                        : OpenSSH 1.2.1 and later
#  ForceCommand                     : OpenSSH 4.4.0 and later [3]
#  GatewayPorts                     : OpenSSH 2.1.0 and later
#  GSSAPIAuthentication             : OpenSSH 3.7.0 and later [1]
#  GSSAPICleanupCredentials         : OpenSSH 3.8.0 and later [1]
#  GSSAPIKeyExchange                :  SunSSH 1.0.0 and later [1]
#  GSSAPIStoreDelegatedCredentials  :  SunSSH 1.0.0 and later [1]
#  GSSCleanupCreds                  :  SunSSH 1.0.0 and later [1]
#  GSSUseSessionCredCache           :  SunSSH 1.0.0 and later [1]
#  HostbasedAuthentication          : OpenSSH 2.9.0 and later
#  HostbasedUsesNameFromPacketOnly  : OpenSSH 2.9.0 and later
#  HostKey                          : OpenSSH 1.2.1 and later
#  IgnoreRhosts                     : OpenSSH 1.2.1 and later
#  IgnoreUserKnownHosts             : OpenSSH 1.2.1 and later
#  KbdInteractiveAuthentication     : OpenSSH 2.3.0 and later
#  KeepAlive                        : OpenSSH 1.2.1 and later
#  KerberosAuthentication           : OpenSSH 1.2.1 and later [1]
#  KerberosGetAFSToken              : OpenSSH 3.8.0 and later [1]
#  KerberosOrLocalPasswd            : OpenSSH 1.2.1 and later [1]
#  KerberosTgtPassing               : OpenSSH 1.2.1 and later [1]
#  KerberosTicketCleanup            : OpenSSH 1.2.1 and later [1]
#  KeyRegenerationInterval          : OpenSSH 1.2.1 and later
#  ListenAddress                    : OpenSSH 1.2.1 and later
#  LoginGraceTime                   : OpenSSH 1.2.1 and later
#  LogLevel                         : OpenSSH 1.2.1 and later
#  LookupClientHostnames            :  SunSSH 1.0.0 and later
#  MACs                             : OpenSSH 2.5.0 and later [3]
#  Match                            : OpenSSH 4.4.0 and later [3]
#  MaxAuthTries                     : OpenSSH 3.9.0 and later
#  MaxStartups                      : OpenSSH 2.2.0 and later
#  PAMAuthenticationViaKbdInt       : OpenSSH 2.9.0 and later [2]
#  PasswordAuthentication           : OpenSSH 1.2.1 and later
#  PermitEmptyPasswords             : OpenSSH 1.2.1 and later
#  PermitOpen                       : OpenSSH 4.4.0 and later [3]
#  PermitRootLogin                  : OpenSSH 1.2.1 and later
#  PermitTunnel                     : OpenSSH 4.3.0 and later
#  PermitUserEnvironment            : OpenSSH 3.5.0 and later
#  PidFile                          : OpenSSH 2.1.0 and later
#  Port                             : OpenSSH 1.2.1 and later
#  PrintLastLog                     : OpenSSH 2.9.0 and later
#  PrintMotd                        : OpenSSH 1.2.1 and later
#  Protocol                         : OpenSSH 2.1.0 and later
#  PubkeyAuthentication             : OpenSSH 2.5.0 and later
#  RhostsAuthentication             : OpenSSH 1.2.1 and later
#  RhostsRSAAuthentication          : OpenSSH 1.2.1 and later
#  RSAAuthentication                : OpenSSH 1.2.1 and later
#  ServerKeyBits                    : OpenSSH 1.2.1 and later
#  SkeyAuthentication               : OpenSSH 1.2.1 and later [1]
#  StrictModes                      : OpenSSH 1.2.1 and later
#  Subsystem                        : OpenSSH 2.2.0 and later
#  SyslogFacility                   : OpenSSH 1.2.1 and later
#  TCPKeepAlive                     : OpenSSH 3.8.0 and later
#  UseDNS                           : OpenSSH 3.7.0 and later
#  UseLogin                         : OpenSSH 1.2.1 and later
#  UsePAM                           : OpenSSH 3.7.0 and later [1][2]
#  UsePrivilegeSeparation           : OpenSSH 3.2.2 and later
#  VerifyReverseMapping             : OpenSSH 3.1.0 and later
#  X11DisplayOffset                 : OpenSSH 1.2.1 and later [3]
#  X11Forwarding                    : OpenSSH 1.2.1 and later
#  X11UseLocalhost                  : OpenSSH 3.1.0 and later
#  XAuthLocation                    : OpenSSH 2.1.1 and later [3]
#
#  [1] Option only available if activated at compile time
#  [2] Option specific for portable versions
#  [3] Option not used in our ssh server config file


#***************************************************************************
# Initialize sshd config with options actually supported in OpenSSH 2.9.9
#
logmsg 'generating ssh server config file...' if($verbose);
@cfgarr = ();
push @cfgarr, '# This is a generated file.  Do not edit.';
push @cfgarr, "# $sshdverstr sshd configuration file for curl testing";
push @cfgarr, '#';
push @cfgarr, "DenyUsers !$username";
push @cfgarr, "AllowUsers $username";
push @cfgarr, 'DenyGroups';
push @cfgarr, 'AllowGroups';
push @cfgarr, '#';
push @cfgarr, "AuthorizedKeysFile $path/$clipubkeyf";
push @cfgarr, "AuthorizedKeysFile2 $path/$clipubkeyf";
push @cfgarr, "HostKey $path/$hstprvkeyf";
push @cfgarr, "PidFile $pidfile";
push @cfgarr, '#';
push @cfgarr, "Port $port";
push @cfgarr, "ListenAddress $listenaddr";
push @cfgarr, 'Protocol 2';
push @cfgarr, '#';
push @cfgarr, 'AllowTcpForwarding yes';
push @cfgarr, 'Banner none';
push @cfgarr, 'ChallengeResponseAuthentication no';
push @cfgarr, 'ClientAliveCountMax 3';
push @cfgarr, 'ClientAliveInterval 0';
push @cfgarr, 'GatewayPorts no';
push @cfgarr, 'HostbasedAuthentication no';
push @cfgarr, 'HostbasedUsesNameFromPacketOnly no';
push @cfgarr, 'IgnoreRhosts yes';
push @cfgarr, 'IgnoreUserKnownHosts yes';
push @cfgarr, 'KeyRegenerationInterval 0';
push @cfgarr, 'LoginGraceTime 30';
push @cfgarr, "LogLevel $loglevel";
push @cfgarr, 'MaxStartups 5';
push @cfgarr, 'PasswordAuthentication no';
push @cfgarr, 'PermitEmptyPasswords no';
push @cfgarr, 'PermitRootLogin no';
push @cfgarr, 'PrintLastLog no';
push @cfgarr, 'PrintMotd no';
push @cfgarr, 'PubkeyAuthentication yes';
push @cfgarr, 'RhostsRSAAuthentication no';
push @cfgarr, 'RSAAuthentication no';
push @cfgarr, 'ServerKeyBits 768';
push @cfgarr, 'StrictModes no';
push @cfgarr, "Subsystem sftp $sftpsrv";
push @cfgarr, 'SyslogFacility AUTH';
push @cfgarr, 'UseLogin no';
push @cfgarr, 'X11Forwarding no';
push @cfgarr, '#';


#***************************************************************************
# Write out initial sshd configuration file for curl's tests
#
$error = dump_array($sshdconfig, @cfgarr);
if($error) {
    logmsg $error;
    exit 1;
}


#***************************************************************************
# Verifies at run time if sshd supports a given configuration file option
#
sub sshd_supports_opt {
    my ($option, $value) = @_;
    my $err;
    #
    if((($sshdid =~ /OpenSSH/) && ($sshdvernum >= 310)) ||
        ($sshdid =~ /SunSSH/)) {
        # ssh daemon supports command line options -t -f and -o
        $err = grep /((Unsupported)|(Bad configuration)|(Deprecated)) option.*$option/,
                    qx($sshd -t -f $sshdconfig -o $option=$value 2>&1);
        return !$err;
    }
    if(($sshdid =~ /OpenSSH/) && ($sshdvernum >= 299)) {
        # ssh daemon supports command line options -t and -f
        $err = dump_array($sshdconfig, (@cfgarr, "$option $value"));
        if($err) {
            logmsg $err;
            return 0;
        }
        $err = grep /((Unsupported)|(Bad configuration)|(Deprecated)) option.*$option/,
                    qx($sshd -t -f $sshdconfig 2>&1);
        unlink $sshdconfig;
        return !$err;
    }
    return 0;
}


#***************************************************************************
# Kerberos Authentication support may have not been built into sshd
#
if(sshd_supports_opt('KerberosAuthentication','no')) {
    push @cfgarr, 'KerberosAuthentication no';
}
if(sshd_supports_opt('KerberosGetAFSToken','no')) {
    push @cfgarr, 'KerberosGetAFSToken no';
}
if(sshd_supports_opt('KerberosOrLocalPasswd','no')) {
    push @cfgarr, 'KerberosOrLocalPasswd no';
}
if(sshd_supports_opt('KerberosTgtPassing','no')) {
    push @cfgarr, 'KerberosTgtPassing no';
}
if(sshd_supports_opt('KerberosTicketCleanup','yes')) {
    push @cfgarr, 'KerberosTicketCleanup yes';
}


#***************************************************************************
# Andrew File System support may have not been built into sshd
#
if(sshd_supports_opt('AFSTokenPassing','no')) {
    push @cfgarr, 'AFSTokenPassing no';
}


#***************************************************************************
# S/Key authentication support may have not been built into sshd
#
if(sshd_supports_opt('SkeyAuthentication','no')) {
    push @cfgarr, 'SkeyAuthentication no';
}


#***************************************************************************
# GSSAPI Authentication support may have not been built into sshd
#
my $sshd_builtwith_GSSAPI;
if(sshd_supports_opt('GSSAPIAuthentication','no')) {
    push @cfgarr, 'GSSAPIAuthentication no';
    $sshd_builtwith_GSSAPI = 1;
}
if(sshd_supports_opt('GSSAPICleanupCredentials','yes')) {
    push @cfgarr, 'GSSAPICleanupCredentials yes';
}
if(sshd_supports_opt('GSSAPIKeyExchange','no')) {
    push @cfgarr, 'GSSAPIKeyExchange no';
}
if(sshd_supports_opt('GSSAPIStoreDelegatedCredentials','no')) {
    push @cfgarr, 'GSSAPIStoreDelegatedCredentials no';
}
if(sshd_supports_opt('GSSCleanupCreds','yes')) {
    push @cfgarr, 'GSSCleanupCreds yes';
}
if(sshd_supports_opt('GSSUseSessionCredCache','no')) {
    push @cfgarr, 'GSSUseSessionCredCache no';
}
push @cfgarr, '#';


#***************************************************************************
# Options that might be supported or not in sshd OpenSSH 2.9.9 and later
#
if(sshd_supports_opt('AcceptEnv','')) {
    push @cfgarr, 'AcceptEnv';
}
if(sshd_supports_opt('AddressFamily','any')) {
    # Address family must be specified before ListenAddress
    splice @cfgarr, 14, 0, 'AddressFamily any';
}
if(sshd_supports_opt('Compression','no')) {
    push @cfgarr, 'Compression no';
}
if(sshd_supports_opt('KbdInteractiveAuthentication','no')) {
    push @cfgarr, 'KbdInteractiveAuthentication no';
}
if(sshd_supports_opt('KeepAlive','no')) {
    push @cfgarr, 'KeepAlive no';
}
if(sshd_supports_opt('LookupClientHostnames','no')) {
    push @cfgarr, 'LookupClientHostnames no';
}
if(sshd_supports_opt('MaxAuthTries','10')) {
    push @cfgarr, 'MaxAuthTries 10';
}
if(sshd_supports_opt('PAMAuthenticationViaKbdInt','no')) {
    push @cfgarr, 'PAMAuthenticationViaKbdInt no';
}
if(sshd_supports_opt('PermitTunnel','no')) {
    push @cfgarr, 'PermitTunnel no';
}
if(sshd_supports_opt('PermitUserEnvironment','no')) {
    push @cfgarr, 'PermitUserEnvironment no';
}
if(sshd_supports_opt('RhostsAuthentication','no')) {
    push @cfgarr, 'RhostsAuthentication no';
}
if(sshd_supports_opt('TCPKeepAlive','no')) {
    push @cfgarr, 'TCPKeepAlive no';
}
if(sshd_supports_opt('UseDNS','no')) {
    push @cfgarr, 'UseDNS no';
}
if(sshd_supports_opt('UsePAM','no')) {
    push @cfgarr, 'UsePAM no';
}

if($sshdid =~ /OpenSSH/) {
    # http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6492415
    if(sshd_supports_opt('UsePrivilegeSeparation','no')) {
        push @cfgarr, 'UsePrivilegeSeparation no';
    }
}

if(sshd_supports_opt('VerifyReverseMapping','no')) {
    push @cfgarr, 'VerifyReverseMapping no';
}
if(sshd_supports_opt('X11UseLocalhost','yes')) {
    push @cfgarr, 'X11UseLocalhost yes';
}
push @cfgarr, '#';


#***************************************************************************
# Write out resulting sshd configuration file for curl's tests
#
$error = dump_array($sshdconfig, @cfgarr);
if($error) {
    logmsg $error;
    exit 1;
}


#***************************************************************************
# Verify that sshd actually supports our generated configuration file
#
if(system "$sshd -t -f $sshdconfig > $sshdlog 2>&1") {
    logmsg "sshd configuration file $sshdconfig failed verification";
    display_sshdlog();
    display_sshdconfig();
    exit 1;
}


#***************************************************************************
# Generate ssh client host key database file for curl's tests
#
if((! -e $knownhosts) || (! -s $knownhosts)) {
    logmsg 'generating ssh client known hosts file...' if($verbose);
    unlink($knownhosts);
    if(open(DSAKEYFILE, "<$hstpubkeyf")) {
        my @dsahostkey = do { local $/ = ' '; <DSAKEYFILE> };
        if(close(DSAKEYFILE)) {
            if(open(KNOWNHOSTS, ">$knownhosts")) {
                print KNOWNHOSTS "$listenaddr ssh-dss $dsahostkey[1]\n";
                if(!close(KNOWNHOSTS)) {
                    $error = "Error: cannot close file $knownhosts";
                }
            }
            else {
                $error = "Error: cannot write file $knownhosts";
            }
        }
        else {
            $error = "Error: cannot close file $hstpubkeyf";
        }
    }
    else {
        $error = "Error: cannot read file $hstpubkeyf";
    }
    if($error) {
        logmsg $error;
        exit 1;
    }
}


#***************************************************************************
#  ssh client configuration file options we might use and version support
#
#  AddressFamily                     : OpenSSH 3.7.0 and later
#  BatchMode                         : OpenSSH 1.2.1 and later
#  BindAddress                       : OpenSSH 2.9.9 and later
#  ChallengeResponseAuthentication   : OpenSSH 2.5.0 and later
#  CheckHostIP                       : OpenSSH 1.2.1 and later
#  Cipher                            : OpenSSH 1.2.1 and later [3]
#  Ciphers                           : OpenSSH 2.1.0 and later [3]
#  ClearAllForwardings               : OpenSSH 2.9.9 and later
#  Compression                       : OpenSSH 1.2.1 and later
#  CompressionLevel                  : OpenSSH 1.2.1 and later [3]
#  ConnectionAttempts                : OpenSSH 1.2.1 and later
#  ConnectTimeout                    : OpenSSH 3.7.0 and later
#  ControlMaster                     : OpenSSH 3.9.0 and later
#  ControlPath                       : OpenSSH 3.9.0 and later
#  DisableBanner                     :  SunSSH 1.2.0 and later
#  DynamicForward                    : OpenSSH 2.9.0 and later
#  EnableSSHKeysign                  : OpenSSH 3.6.0 and later
#  EscapeChar                        : OpenSSH 1.2.1 and later [3]
#  ExitOnForwardFailure              : OpenSSH 4.4.0 and later
#  ForwardAgent                      : OpenSSH 1.2.1 and later
#  ForwardX11                        : OpenSSH 1.2.1 and later
#  ForwardX11Trusted                 : OpenSSH 3.8.0 and later
#  GatewayPorts                      : OpenSSH 1.2.1 and later
#  GlobalKnownHostsFile              : OpenSSH 1.2.1 and later
#  GSSAPIAuthentication              : OpenSSH 3.7.0 and later [1]
#  GSSAPIDelegateCredentials         : OpenSSH 3.7.0 and later [1]
#  HashKnownHosts                    : OpenSSH 4.0.0 and later
#  Host                              : OpenSSH 1.2.1 and later
#  HostbasedAuthentication           : OpenSSH 2.9.0 and later
#  HostKeyAlgorithms                 : OpenSSH 2.9.0 and later [3]
#  HostKeyAlias                      : OpenSSH 2.5.0 and later [3]
#  HostName                          : OpenSSH 1.2.1 and later
#  IdentitiesOnly                    : OpenSSH 3.9.0 and later
#  IdentityFile                      : OpenSSH 1.2.1 and later
#  IgnoreIfUnknown                   :  SunSSH 1.2.0 and later
#  KeepAlive                         : OpenSSH 1.2.1 and later
#  KbdInteractiveAuthentication      : OpenSSH 2.3.0 and later
#  KbdInteractiveDevices             : OpenSSH 2.3.0 and later [3]
#  LocalCommand                      : OpenSSH 4.3.0 and later [3]
#  LocalForward                      : OpenSSH 1.2.1 and later [3]
#  LogLevel                          : OpenSSH 1.2.1 and later
#  MACs                              : OpenSSH 2.5.0 and later [3]
#  NoHostAuthenticationForLocalhost  : OpenSSH 3.0.0 and later
#  NumberOfPasswordPrompts           : OpenSSH 1.2.1 and later
#  PasswordAuthentication            : OpenSSH 1.2.1 and later
#  PermitLocalCommand                : OpenSSH 4.3.0 and later
#  Port                              : OpenSSH 1.2.1 and later
#  PreferredAuthentications          : OpenSSH 2.5.2 and later
#  Protocol                          : OpenSSH 2.1.0 and later
#  ProxyCommand                      : OpenSSH 1.2.1 and later [3]
#  PubkeyAuthentication              : OpenSSH 2.5.0 and later
#  RekeyLimit                        : OpenSSH 3.7.0 and later
#  RemoteForward                     : OpenSSH 1.2.1 and later [3]
#  RhostsRSAAuthentication           : OpenSSH 1.2.1 and later
#  RSAAuthentication                 : OpenSSH 1.2.1 and later
#  SendEnv                           : OpenSSH 3.9.0 and later
#  ServerAliveCountMax               : OpenSSH 3.8.0 and later
#  ServerAliveInterval               : OpenSSH 3.8.0 and later
#  SmartcardDevice                   : OpenSSH 2.9.9 and later [1][3]
#  StrictHostKeyChecking             : OpenSSH 1.2.1 and later
#  TCPKeepAlive                      : OpenSSH 3.8.0 and later
#  Tunnel                            : OpenSSH 4.3.0 and later
#  TunnelDevice                      : OpenSSH 4.3.0 and later [3]
#  UsePAM                            : OpenSSH 3.7.0 and later [1][2][3]
#  UsePrivilegedPort                 : OpenSSH 1.2.1 and later
#  User                              : OpenSSH 1.2.1 and later
#  UserKnownHostsFile                : OpenSSH 1.2.1 and later
#  VerifyHostKeyDNS                  : OpenSSH 3.8.0 and later
#  XAuthLocation                     : OpenSSH 2.1.1 and later [3]
#
#  [1] Option only available if activated at compile time
#  [2] Option specific for portable versions
#  [3] Option not used in our ssh client config file


#***************************************************************************
# Initialize ssh config with options actually supported in OpenSSH 2.9.9
#
logmsg 'generating ssh client config file...' if($verbose);
@cfgarr = ();
push @cfgarr, '# This is a generated file.  Do not edit.';
push @cfgarr, "# $sshverstr ssh client configuration file for curl testing";
push @cfgarr, '#';
push @cfgarr, 'Host *';
push @cfgarr, '#';
push @cfgarr, "Port $port";
push @cfgarr, "HostName $listenaddr";
push @cfgarr, "User $username";
push @cfgarr, 'Protocol 2';
push @cfgarr, '#';
push @cfgarr, "BindAddress $listenaddr";
push @cfgarr, "DynamicForward $socksport";
push @cfgarr, '#';
push @cfgarr, "IdentityFile $path/curl_client_key";
push @cfgarr, "UserKnownHostsFile $path/$knownhosts";
push @cfgarr, '#';
push @cfgarr, 'BatchMode yes';
push @cfgarr, 'ChallengeResponseAuthentication no';
push @cfgarr, 'CheckHostIP no';
push @cfgarr, 'ClearAllForwardings no';
push @cfgarr, 'Compression no';
push @cfgarr, 'ConnectionAttempts 3';
push @cfgarr, 'ForwardAgent no';
push @cfgarr, 'ForwardX11 no';
push @cfgarr, 'GatewayPorts no';
push @cfgarr, 'GlobalKnownHostsFile /dev/null';
push @cfgarr, 'HostbasedAuthentication no';
push @cfgarr, 'KbdInteractiveAuthentication no';
push @cfgarr, "LogLevel $loglevel";
push @cfgarr, 'NumberOfPasswordPrompts 0';
push @cfgarr, 'PasswordAuthentication no';
push @cfgarr, 'PreferredAuthentications publickey';
push @cfgarr, 'PubkeyAuthentication yes';
push @cfgarr, 'RhostsRSAAuthentication no';
push @cfgarr, 'RSAAuthentication no';

# Disabled StrictHostKeyChecking since it makes the tests fail on my
# OpenSSH_6.0p1 on Debian Linux / Daniel
push @cfgarr, 'StrictHostKeyChecking no';
push @cfgarr, 'UsePrivilegedPort no';
push @cfgarr, '#';


#***************************************************************************
# Options supported in ssh client newer than OpenSSH 2.9.9
#

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 370)) {
    push @cfgarr, 'AddressFamily any';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 370)) ||
   (($sshid =~ /SunSSH/) && ($sshvernum >= 120))) {
    push @cfgarr, 'ConnectTimeout 30';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 390)) {
    push @cfgarr, 'ControlMaster no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 420)) {
    push @cfgarr, 'ControlPath none';
}

if(($sshid =~ /SunSSH/) && ($sshvernum >= 120)) {
    push @cfgarr, 'DisableBanner yes';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 360)) {
    push @cfgarr, 'EnableSSHKeysign no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 440)) {
    push @cfgarr, 'ExitOnForwardFailure yes';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 380)) ||
   (($sshid =~ /SunSSH/) && ($sshvernum >= 120))) {
    push @cfgarr, 'ForwardX11Trusted no';
}

if(($sshd_builtwith_GSSAPI) && ($sshdid eq $sshid) &&
   ($sshdvernum == $sshvernum)) {
    push @cfgarr, 'GSSAPIAuthentication no';
    push @cfgarr, 'GSSAPIDelegateCredentials no';
    if($sshid =~ /SunSSH/) {
        push @cfgarr, 'GSSAPIKeyExchange no';
    }
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 400)) ||
   (($sshid =~ /SunSSH/) && ($sshvernum >= 120))) {
    push @cfgarr, 'HashKnownHosts no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 390)) {
    push @cfgarr, 'IdentitiesOnly yes';
}

if(($sshid =~ /SunSSH/) && ($sshvernum >= 120)) {
    push @cfgarr, 'IgnoreIfUnknown no';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum < 380)) ||
    ($sshid =~ /SunSSH/)) {
    push @cfgarr, 'KeepAlive no';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 300)) ||
    ($sshid =~ /SunSSH/)) {
    push @cfgarr, 'NoHostAuthenticationForLocalhost no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 430)) {
    push @cfgarr, 'PermitLocalCommand no';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 370)) ||
   (($sshid =~ /SunSSH/) && ($sshvernum >= 120))) {
    push @cfgarr, 'RekeyLimit 1G';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 390)) {
    push @cfgarr, 'SendEnv';
}

if((($sshid =~ /OpenSSH/) && ($sshvernum >= 380)) ||
   (($sshid =~ /SunSSH/) && ($sshvernum >= 120))) {
    push @cfgarr, 'ServerAliveCountMax 3';
    push @cfgarr, 'ServerAliveInterval 0';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 380)) {
    push @cfgarr, 'TCPKeepAlive no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 430)) {
    push @cfgarr, 'Tunnel no';
}

if(($sshid =~ /OpenSSH/) && ($sshvernum >= 380)) {
    push @cfgarr, 'VerifyHostKeyDNS no';
}

push @cfgarr, '#';


#***************************************************************************
# Write out resulting ssh client configuration file for curl's tests
#
$error = dump_array($sshconfig, @cfgarr);
if($error) {
    logmsg $error;
    exit 1;
}


#***************************************************************************
# Initialize client sftp config with options actually supported.
#
logmsg 'generating sftp client config file...' if($verbose);
splice @cfgarr, 1, 1, "# $sshverstr sftp client configuration file for curl testing";
#
for(my $i = scalar(@cfgarr) - 1; $i > 0; $i--) {
    if($cfgarr[$i] =~ /^DynamicForward/) {
        splice @cfgarr, $i, 1;
        next;
    }
    if($cfgarr[$i] =~ /^ClearAllForwardings/) {
        splice @cfgarr, $i, 1, "ClearAllForwardings yes";
        next;
    }
}


#***************************************************************************
# Write out resulting sftp client configuration file for curl's tests
#
$error = dump_array($sftpconfig, @cfgarr);
if($error) {
    logmsg $error;
    exit 1;
}
@cfgarr = ();


#***************************************************************************
# Generate client sftp commands batch file for sftp server verification
#
logmsg 'generating sftp client commands file...' if($verbose);
push @cfgarr, 'pwd';
push @cfgarr, 'quit';
$error = dump_array($sftpcmds, @cfgarr);
if($error) {
    logmsg $error;
    exit 1;
}
@cfgarr = ();


#***************************************************************************
# Start the ssh server daemon without forking it
#
logmsg "SCP/SFTP server listening on port $port" if($verbose);
my $rc = system "$sshd -e -D -f $sshdconfig > $sshdlog 2>&1";
if($rc == -1) {
    logmsg "$sshd failed with: $!";
}
elsif($rc & 127) {
    logmsg sprintf("$sshd died with signal %d, and %s coredump",
                   ($rc & 127), ($rc & 128)?'a':'no');
}
elsif($verbose && ($rc >> 8)) {
    logmsg sprintf("$sshd exited with %d", $rc >> 8);
}


#***************************************************************************
# Clean up once the server has stopped
#
unlink($hstprvkeyf, $hstpubkeyf, $cliprvkeyf, $clipubkeyf, $knownhosts);
unlink($sshdconfig, $sshconfig, $sftpconfig);


exit 0;
