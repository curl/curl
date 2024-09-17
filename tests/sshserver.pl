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
#***************************************************************************

# Starts sshd for use in the SCP and SFTP curl test harness tests.
# Also creates the ssh configuration files needed for these tests.

use strict;
use warnings;
use Cwd;
use Cwd 'abs_path';
use Digest::MD5;
use Digest::MD5 'md5_hex';
use Digest::SHA;
use Digest::SHA 'sha256_base64';
use MIME::Base64;
use File::Basename;

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
    $hstpubmd5f
    $hstpubsha256f
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
    sshversioninfo
    );

#***************************************************************************
# Subs imported from serverhelp module
#
use serverhelp qw(
    $logfile
    server_pidfilename
    server_logfilename
    );

use pathhelp;

#***************************************************************************

my $verbose = 0;              # set to 1 for debugging
my $debugprotocol = 0;        # set to 1 for protocol debugging
my $port = 8999;              # our default SCP/SFTP server port
my $listenaddr = '127.0.0.1'; # default address on which to listen
my $ipvnum = 4;               # default IP version of listener address
my $idnum = 1;                # default ssh daemon instance number
my $proto = 'ssh';            # protocol the ssh daemon speaks
my $path = getcwd();          # current working directory
my $logdir = $path .'/log';   # directory for log files
my $piddir;                   # directory for server config files
my $username = $ENV{USER};    # default user
my $pidfile;                  # ssh daemon pid file
my $identity = 'curl_client_key'; # default identity file

my $error;
my @cfgarr;

#***************************************************************************
# Returns a path of the given file name in the log directory (PiddirPath)
#
sub pp {
    my $file = $_[0];
    return "$piddir/$file";
    # TODO: do Windows path conversion here
}

#***************************************************************************
# Save the message to the log and print it
sub logmsg {
    my $msg = $_[0];
    serverhelp::logmsg $msg;
    print $msg;
}

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
    elsif($ARGV[0] eq '--logdir') {
        if($ARGV[1]) {
            $logdir = "$path/". $ARGV[1];
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
    else {
        print STDERR "\nWarning: sshserver.pl unknown parameter: $ARGV[0]\n";
    }
    shift @ARGV;
}

#***************************************************************************
# Initialize command line option dependent variables
#

#***************************************************************************
# Default ssh daemon pid file name & directory
#
if($pidfile) {
    # Use our pidfile directory to store server config files
    $piddir = dirname($pidfile);
}
else {
    # Use the current directory to store server config files
    $piddir = $path;
    $pidfile = server_pidfilename($piddir, $proto, $ipvnum, $idnum);
}

#***************************************************************************
# ssh and sftp server log file names
#
$sshdlog = server_logfilename($logdir, 'ssh', $ipvnum, $idnum);
$sftplog = server_logfilename($logdir, 'sftp', $ipvnum, $idnum);
$logfile = "$logdir/sshserver.log";  # used by logmsg

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
    logmsg "$error\n";
    exit 1;
}


#***************************************************************************
# Find out ssh daemon canonical file name
#
my $sshd = find_sshd();
if(!$sshd) {
    logmsg "cannot find $sshdexe\n";
    exit 1;
}


#***************************************************************************
# Find out ssh daemon version info
#
my ($sshdid, $sshdvernum, $sshdverstr, $sshderror) = sshversioninfo($sshd);
if(!$sshdid) {
    # Not an OpenSSH or SunSSH ssh daemon
    logmsg "$sshderror\n" if($verbose);
    logmsg "SCP and SFTP tests require OpenSSH 2.9.9 or later\n";
    exit 1;
}
logmsg "ssh server found $sshd is $sshdverstr\n" if($verbose);


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
    logmsg "SCP and SFTP tests require OpenSSH 2.9.9 or later\n";
    exit 1;
}


#***************************************************************************
# Find out sftp server plugin canonical file name
#
my $sftpsrv = find_sftpsrv();
if(!$sftpsrv) {
    logmsg "cannot find $sftpsrvexe\n";
    exit 1;
}
logmsg "sftp server plugin found $sftpsrv\n" if($verbose);


#***************************************************************************
# Find out sftp client canonical file name
#
my $sftp = find_sftp();
if(!$sftp) {
    logmsg "cannot find $sftpexe\n";
    exit 1;
}
logmsg "sftp client found $sftp\n" if($verbose);


#***************************************************************************
# Find out ssh keygen canonical file name
#
my $sshkeygen = find_sshkeygen();
if(!$sshkeygen) {
    logmsg "cannot find $sshkeygenexe\n";
    exit 1;
}
logmsg "ssh keygen found $sshkeygen\n" if($verbose);


#***************************************************************************
# Find out ssh client canonical file name
#
my $ssh = find_ssh();
if(!$ssh) {
    logmsg "cannot find $sshexe\n";
    exit 1;
}


#***************************************************************************
# Find out ssh client version info
#
my ($sshid, $sshvernum, $sshverstr, $ssherror) = sshversioninfo($ssh);
if(!$sshid) {
    # Not an OpenSSH or SunSSH ssh client
    logmsg "$ssherror\n" if($verbose);
    logmsg "SCP and SFTP tests require OpenSSH 2.9.9 or later\n";
    exit 1;
}
logmsg "ssh client found $ssh is $sshverstr\n" if($verbose);


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
    logmsg "SCP and SFTP tests require OpenSSH 2.9.9 or later\n";
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

$sshdconfig = pp($sshdconfig);
$sshconfig = pp($sshconfig);
$sftpconfig = pp($sftpconfig);

#***************************************************************************
# Generate host and client key files for curl's tests
#
if((! -e pp($hstprvkeyf)) || (! -s pp($hstprvkeyf)) ||
   (! -e pp($hstpubkeyf)) || (! -s pp($hstpubkeyf)) ||
   (! -e pp($hstpubmd5f)) || (! -s pp($hstpubmd5f)) ||
   (! -e pp($hstpubsha256f)) || (! -s pp($hstpubsha256f)) ||
   (! -e pp($cliprvkeyf)) || (! -s pp($cliprvkeyf)) ||
   (! -e pp($clipubkeyf)) || (! -s pp($clipubkeyf))) {
    # Make sure all files are gone so ssh-keygen doesn't complain
    unlink(pp($hstprvkeyf), pp($hstpubkeyf), pp($hstpubmd5f),
           pp($hstpubsha256f), pp($cliprvkeyf), pp($clipubkeyf));
    logmsg "generating host keys...\n" if($verbose);
    if(system "\"$sshkeygen\" -q -t rsa -f " . pp($hstprvkeyf) . " -C 'curl test server' -N ''") {
        logmsg "Could not generate host key\n";
        exit 1;
    }
    logmsg "generating client keys...\n" if($verbose);
    if(system "\"$sshkeygen\" -q -t rsa -f " . pp($cliprvkeyf) . " -C 'curl test client' -N ''") {
        logmsg "Could not generate client key\n";
        exit 1;
    }
    # Make sure that permissions are restricted so openssh doesn't complain
    system "chmod 600 " . pp($hstprvkeyf);
    system "chmod 600 " . pp($cliprvkeyf);
    if(pathhelp::os_is_win()) {
      # https://ss64.com/nt/icacls.html
      $ENV{'MSYS2_ARG_CONV_EXCL'} = '/reset';
      system("icacls \"" . pathhelp::sys_native_abs_path(pp($hstprvkeyf)) . "\" /reset");
      system("icacls \"" . pathhelp::sys_native_abs_path(pp($hstprvkeyf)) . "\" /grant:r \"$username:(R)\"");
      system("icacls \"" . pathhelp::sys_native_abs_path(pp($hstprvkeyf)) . "\" /inheritance:r");
    }
    # Save md5 and sha256 hashes of public host key
    open(my $rsakeyfile, "<", pp($hstpubkeyf));
    my @rsahostkey = do { local $/ = ' '; <$rsakeyfile> };
    close($rsakeyfile);
    if(!$rsahostkey[1]) {
        logmsg "Failed parsing base64 encoded RSA host key\n";
        exit 1;
    }
    open(my $pubmd5file, ">", pp($hstpubmd5f));
    print $pubmd5file md5_hex(decode_base64($rsahostkey[1]));
    close($pubmd5file);
    if((! -e pp($hstpubmd5f)) || (! -s pp($hstpubmd5f))) {
        logmsg "Failed writing md5 hash of RSA host key\n";
        exit 1;
    }
    open(my $pubsha256file, ">", pp($hstpubsha256f));
    print $pubsha256file sha256_base64(decode_base64($rsahostkey[1]));
    close($pubsha256file);
    if((! -e pp($hstpubsha256f)) || (! -s pp($hstpubsha256f))) {
        logmsg "Failed writing sha256 hash of RSA host key\n";
        exit 1;
    }
}


#***************************************************************************
# Convert paths for curl's tests running on Windows with Cygwin/MSYS OpenSSH
#
my $clipubkeyf_config;
my $hstprvkeyf_config;
my $pidfile_config;
my $sftpsrv_config;
my $sshdconfig_abs;
if ($sshdid =~ /OpenSSH-Windows/) {
    # Ensure to use native Windows paths with OpenSSH for Windows
    $clipubkeyf_config = pathhelp::sys_native_abs_path(pp($clipubkeyf));
    $hstprvkeyf_config = pathhelp::sys_native_abs_path(pp($hstprvkeyf));
    $pidfile_config = pathhelp::sys_native_abs_path($pidfile);
    $sftpsrv_config = pathhelp::sys_native_abs_path($sftpsrv);
    $sshdconfig_abs = pathhelp::sys_native_abs_path($sshdconfig);
}
elsif (pathhelp::os_is_win()) {
    # Ensure to use MinGW/Cygwin paths
    $clipubkeyf_config = pathhelp::build_sys_abs_path(pp($clipubkeyf));
    $hstprvkeyf_config = pathhelp::build_sys_abs_path(pp($hstprvkeyf));
    $pidfile_config = pathhelp::build_sys_abs_path($pidfile);
    $sftpsrv_config = "internal-sftp";
    $sshdconfig_abs = pathhelp::build_sys_abs_path($sshdconfig);
}
else {
    $clipubkeyf_config = abs_path(pp($clipubkeyf));
    $hstprvkeyf_config = abs_path(pp($hstprvkeyf));
    $pidfile_config = $pidfile;
    $sftpsrv_config = $sftpsrv;
    $sshdconfig_abs = abs_path($sshdconfig);
}

#***************************************************************************
#  ssh daemon configuration file options we might use and version support
#
#  AFSTokenPassing                  : OpenSSH 1.2.1 and later [1]
#  AddressFamily                    : OpenSSH 4.0.0 and later
#  AllowTcpForwarding               : OpenSSH 2.3.0 and later
#  AllowUsers                       : OpenSSH 1.2.1 and later
#  AuthorizedKeysFile               : OpenSSH 2.9.9 and later
#  AuthorizedKeysFile2              : OpenSSH 2.9.9 till 5.9
#  Banner                           : OpenSSH 2.5.0 and later
#  ChallengeResponseAuthentication  : OpenSSH 2.5.0 and later
#  Ciphers                          : OpenSSH 2.1.0 and later [3]
#  ClientAliveCountMax              : OpenSSH 2.9.0 and later
#  ClientAliveInterval              : OpenSSH 2.9.0 and later
#  Compression                      : OpenSSH 3.3.0 and later
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
#  KeyRegenerationInterval          : OpenSSH 1.2.1 till 7.3
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
#  RhostsRSAAuthentication          : OpenSSH 1.2.1 till 7.3
#  RSAAuthentication                : OpenSSH 1.2.1 till 7.3
#  ServerKeyBits                    : OpenSSH 1.2.1 till 7.3
#  SkeyAuthentication               : OpenSSH 1.2.1 and later [1]
#  StrictModes                      : OpenSSH 1.2.1 and later
#  Subsystem                        : OpenSSH 2.2.0 and later
#  SyslogFacility                   : OpenSSH 1.2.1 and later
#  TCPKeepAlive                     : OpenSSH 3.8.0 and later
#  UseDNS                           : OpenSSH 3.7.0 and later
#  UseLogin                         : OpenSSH 1.2.1 till 7.3
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
logmsg "generating ssh server config file...\n" if($verbose);
@cfgarr = ();
push @cfgarr, '# This is a generated file.  Do not edit.';
push @cfgarr, "# $sshdverstr sshd configuration file for curl testing";
push @cfgarr, '#';

# AllowUsers and DenyUsers options should use lowercase on Windows
# and do not support quotes around values for some unknown reason.
if ($sshdid =~ /OpenSSH-Windows/) {
    my $username_lc = lc $username;
    push @cfgarr, "AllowUsers " . $username_lc =~ s/ /\?/gr;
    if (exists $ENV{USERDOMAIN}) {
        my $userdomain_lc = lc $ENV{USERDOMAIN};
        $username_lc = "$userdomain_lc\\$username_lc";
        $username_lc =~ s/ /\?/g; # replace space with ?
        push @cfgarr, "AllowUsers " . $username_lc =~ s/ /\?/gr;
    }
} else {
    push @cfgarr, "AllowUsers $username";
}

push @cfgarr, "AuthorizedKeysFile $clipubkeyf_config";
if(!($sshdid =~ /OpenSSH/) || ($sshdvernum <= 730)) {
    push @cfgarr, "AuthorizedKeysFile2 $clipubkeyf_config";
}
push @cfgarr, "HostKey $hstprvkeyf_config";
if ($sshdid !~ /OpenSSH-Windows/) {
    push @cfgarr, "PidFile $pidfile_config";
    push @cfgarr, '#';
}
if(($sshdid =~ /OpenSSH/) && ($sshdvernum >= 880)) {
    push @cfgarr, 'HostKeyAlgorithms +ssh-rsa';
    push @cfgarr, 'PubkeyAcceptedKeyTypes +ssh-rsa';
}
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
push @cfgarr, 'LoginGraceTime 30';
push @cfgarr, "LogLevel $loglevel";
push @cfgarr, 'MaxStartups 5';
push @cfgarr, 'PasswordAuthentication no';
push @cfgarr, 'PermitEmptyPasswords no';
push @cfgarr, 'PermitRootLogin no';
push @cfgarr, 'PrintLastLog no';
push @cfgarr, 'PrintMotd no';
push @cfgarr, 'PubkeyAuthentication yes';
push @cfgarr, 'StrictModes no';
push @cfgarr, "Subsystem sftp \"$sftpsrv_config\"";
push @cfgarr, 'SyslogFacility AUTH';
if(!($sshdid =~ /OpenSSH/) || ($sshdvernum <= 730)) {
    push @cfgarr, 'KeyRegenerationInterval 0';
    push @cfgarr, 'RhostsRSAAuthentication no';
    push @cfgarr, 'RSAAuthentication no';
    push @cfgarr, 'ServerKeyBits 768';
    push @cfgarr, 'UseLogin no';
}
push @cfgarr, 'X11Forwarding no';
push @cfgarr, '#';


#***************************************************************************
# Write out initial sshd configuration file for curl's tests
#
$error = dump_array($sshdconfig, @cfgarr);
if($error) {
    logmsg "$error\n";
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
                    `\"$sshd\" -t -f $sshdconfig_abs -o \"$option=$value\" 2>&1`;
        return !$err;
    }
    if(($sshdid =~ /OpenSSH/) && ($sshdvernum >= 299)) {
        # ssh daemon supports command line options -t and -f
        $err = dump_array($sshdconfig, (@cfgarr, "$option $value"));
        if($err) {
            logmsg "$err\n";
            return 0;
        }
        $err = grep /((Unsupported)|(Bad configuration)|(Deprecated)) option.*$option/,
                    `\"$sshd\" -t -f $sshdconfig_abs 2>&1`;
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
if(sshd_supports_opt('AddressFamily','any')) {
    # Address family must be specified before ListenAddress
    splice @cfgarr, 11, 0, 'AddressFamily any';
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
    logmsg "$error\n";
    exit 1;
}


#***************************************************************************
# Verify that sshd actually supports our generated configuration file
#
if(system "\"$sshd\" -t -f $sshdconfig_abs > $sshdlog 2>&1") {
    logmsg "sshd configuration file $sshdconfig failed verification\n";
    display_sshdlog();
    display_sshdconfig();
    exit 1;
}


#***************************************************************************
# Generate ssh client host key database file for curl's tests
#
if((! -e pp($knownhosts)) || (! -s pp($knownhosts))) {
    logmsg "generating ssh client known hosts file...\n" if($verbose);
    unlink(pp($knownhosts));
    if(open(my $rsakeyfile, "<", pp($hstpubkeyf))) {
        my @rsahostkey = do { local $/ = ' '; <$rsakeyfile> };
        if(close($rsakeyfile)) {
            if(open(my $knownhostsh, ">", pp($knownhosts))) {
                print $knownhostsh "$listenaddr ssh-rsa $rsahostkey[1]\n";
                if(!close($knownhostsh)) {
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
        logmsg "$error\n";
        exit 1;
    }
}


#***************************************************************************
# Convert paths for curl's tests running on Windows using Cygwin OpenSSH
#
my $identity_config;
my $knownhosts_config;
if ($sshdid =~ /OpenSSH-Windows/) {
    # Ensure to use native Windows paths with OpenSSH for Windows
    $identity_config = pathhelp::sys_native_abs_path(pp($identity));
    $knownhosts_config = pathhelp::sys_native_abs_path(pp($knownhosts));
}
elsif (pathhelp::os_is_win()) {
    # Ensure to use MinGW/Cygwin paths
    $identity_config = pathhelp::build_sys_abs_path(pp($identity));
    $knownhosts_config = pathhelp::build_sys_abs_path(pp($knownhosts));
}
else {
    $identity_config = abs_path(pp($identity));
    $knownhosts_config = abs_path(pp($knownhosts));
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
logmsg "generating ssh client config file...\n" if($verbose);
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

# BindAddress option is not supported by OpenSSH for Windows
if (!($sshdid =~ /OpenSSH-Windows/)) {
    push @cfgarr, "BindAddress $listenaddr";
}

push @cfgarr, '#';
push @cfgarr, "IdentityFile $identity_config";
push @cfgarr, "UserKnownHostsFile $knownhosts_config";
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

# RSA authentication options are not supported by OpenSSH for Windows
if (!($sshdid =~ /OpenSSH-Windows/ || pathhelp::os_is_win())) {
    push @cfgarr, 'RhostsRSAAuthentication no';
    push @cfgarr, 'RSAAuthentication no';
}

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
    logmsg "$error\n";
    exit 1;
}

#***************************************************************************
# Initialize client sftp config with options actually supported.
#
logmsg "generating sftp client config file...\n" if($verbose);
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
    logmsg "$error\n";
    exit 1;
}
@cfgarr = ();


#***************************************************************************
# Generate client sftp commands batch file for sftp server verification
#
logmsg "generating sftp client commands file...\n" if($verbose);
push @cfgarr, 'pwd';
push @cfgarr, 'quit';
$error = dump_array(pp($sftpcmds), @cfgarr);
if($error) {
    logmsg "$error\n";
    exit 1;
}
@cfgarr = ();

#***************************************************************************
# Prepare command line of ssh server daemon
#
my $cmd = "\"$sshd\" -e -D -f $sshdconfig_abs > $sshdlog 2>&1";
logmsg "SCP/SFTP server listening on port $port\n" if($verbose);
logmsg "RUN: $cmd\n" if($verbose);

#***************************************************************************
# Start the ssh server daemon on Windows without forking it
#
if ($sshdid =~ /OpenSSH-Windows/) {
    # Fake pidfile for ssh server on Windows.
    if(open(my $out, ">", "$pidfile")) {
        print $out $$ . "\n";
        close($out);
    }

    # Flush output.
    $| = 1;

    # Put an "exec" in front of the command so that the child process
    # keeps this child's process ID by being tied to the spawned shell.
    exec("exec $cmd") || die "Can't exec() $cmd: $!";
    # exec() will create a new process, but ties the existence of the
    # new process to the parent waiting perl.exe and sh.exe processes.

    # exec() should never return back here to this process. We protect
    # ourselves by calling die() just in case something goes really bad.
    die "error: exec() has returned";
}

#***************************************************************************
# Start the ssh server daemon without forking it
#
# "exec" avoids the shell process sticking around
my $rc = system("exec " . $cmd);
if($rc == -1) {
    logmsg "\"$sshd\" failed with: $!\n";
}
elsif($rc & 127) {
    logmsg sprintf("\"$sshd\" died with signal %d, and %s coredump\n",
                   ($rc & 127), ($rc & 128)?'a':'no');
}
elsif($verbose && ($rc >> 8)) {
    logmsg sprintf("\"$sshd\" exited with %d\n", $rc >> 8);
}


#***************************************************************************
# Clean up once the server has stopped
#
unlink(pp($hstprvkeyf), pp($hstpubkeyf), pp($hstpubmd5f), pp($hstpubsha256f),
       pp($cliprvkeyf), pp($clipubkeyf), pp($knownhosts),
       $sshdconfig, $sshconfig, $sftpconfig);

exit 0;
