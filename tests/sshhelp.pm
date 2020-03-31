#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
#***************************************************************************

package sshhelp;

use strict;
use warnings;
use Exporter;
use File::Spec;


#***************************************************************************
# Global symbols allowed without explicit package name
#
use vars qw(
    @ISA
    @EXPORT_OK
    $sshdexe
    $sshexe
    $sftpsrvexe
    $sftpexe
    $sshkeygenexe
    $httptlssrvexe
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
    $cliprvkeyf
    $clipubkeyf
    @sftppath
    @httptlssrvpath
    );


#***************************************************************************
# Inherit Exporter's capabilities
#
@ISA = qw(Exporter);


#***************************************************************************
# Global symbols this module will export upon request
#
@EXPORT_OK = qw(
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
    $cliprvkeyf
    $clipubkeyf
    display_sshdconfig
    display_sshconfig
    display_sftpconfig
    display_sshdlog
    display_sshlog
    display_sftplog
    dump_array
    exe_ext
    find_sshd
    find_ssh
    find_sftpsrv
    find_sftp
    find_sshkeygen
    find_httptlssrv
    logmsg
    sshversioninfo
    );


#***************************************************************************
# Global variables initialization
#
$sshdexe         = 'sshd'        .exe_ext('SSH'); # base name and ext of ssh daemon
$sshexe          = 'ssh'         .exe_ext('SSH'); # base name and ext of ssh client
$sftpsrvexe      = 'sftp-server' .exe_ext('SSH'); # base name and ext of sftp-server
$sftpexe         = 'sftp'        .exe_ext('SSH'); # base name and ext of sftp client
$sshkeygenexe    = 'ssh-keygen'  .exe_ext('SSH'); # base name and ext of ssh-keygen
$httptlssrvexe   = 'gnutls-serv' .exe_ext('SSH'); # base name and ext of gnutls-serv
$sshdconfig      = 'curl_sshd_config';       # ssh daemon config file
$sshconfig       = 'curl_ssh_config';        # ssh client config file
$sftpconfig      = 'curl_sftp_config';       # sftp client config file
$sshdlog         = undef;                    # ssh daemon log file
$sshlog          = undef;                    # ssh client log file
$sftplog         = undef;                    # sftp client log file
$sftpcmds        = 'curl_sftp_cmds';         # sftp client commands batch file
$knownhosts      = 'curl_client_knownhosts'; # ssh knownhosts file
$hstprvkeyf      = 'curl_host_rsa_key';      # host private key file
$hstpubkeyf      = 'curl_host_rsa_key.pub';  # host public key file
$hstpubmd5f      = 'curl_host_rsa_key.pub_md5';  # md5 hash of host public key
$cliprvkeyf      = 'curl_client_key';        # client private key file
$clipubkeyf      = 'curl_client_key.pub';    # client public key file


#***************************************************************************
# Absolute paths where to look for sftp-server plugin, when not in PATH
#
@sftppath = qw(
    /usr/lib/openssh
    /usr/libexec/openssh
    /usr/libexec
    /usr/local/libexec
    /opt/local/libexec
    /usr/lib/ssh
    /usr/libexec/ssh
    /usr/sbin
    /usr/lib
    /usr/lib/ssh/openssh
    /usr/lib64/ssh
    /usr/lib64/misc
    /usr/lib/misc
    /usr/local/sbin
    /usr/freeware/bin
    /usr/freeware/sbin
    /usr/freeware/libexec
    /opt/ssh/sbin
    /opt/ssh/libexec
    );


#***************************************************************************
# Absolute paths where to look for httptlssrv (gnutls-serv), when not in PATH
#
@httptlssrvpath = qw(
    /usr/sbin
    /usr/libexec
    /usr/lib
    /usr/lib/misc
    /usr/lib64/misc
    /usr/local/bin
    /usr/local/sbin
    /usr/local/libexec
    /opt/local/bin
    /opt/local/sbin
    /opt/local/libexec
    /usr/freeware/bin
    /usr/freeware/sbin
    /usr/freeware/libexec
    /opt/gnutls/bin
    /opt/gnutls/sbin
    /opt/gnutls/libexec
    );


#***************************************************************************
# Return file extension for executable files on this operating system
#
sub exe_ext {
    my ($component, @arr) = @_;
    if ($ENV{'CURL_TEST_EXE_EXT'}) {
        return $ENV{'CURL_TEST_EXE_EXT'};
    }
    if ($ENV{'CURL_TEST_EXE_EXT_'.$component}) {
        return $ENV{'CURL_TEST_EXE_EXT_'.$component};
    }
    if ($^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys' ||
        $^O eq 'dos' || $^O eq 'os2') {
        return '.exe';
    }
}


#***************************************************************************
# Create or overwrite the given file with lines from an array of strings
#
sub dump_array {
    my ($filename, @arr) = @_;
    my $error;

    if(!$filename) {
        $error = 'Error: Missing argument 1 for dump_array()';
    }
    elsif(open(TEXTFH, ">$filename")) {
        foreach my $line (@arr) {
            $line .= "\n" unless($line =~ /\n$/);
            print TEXTFH $line;
        }
        if(!close(TEXTFH)) {
            $error = "Error: cannot close file $filename";
        }
    }
    else {
        $error = "Error: cannot write file $filename";
    }
    return $error;
}


#***************************************************************************
# Display a message
#
sub logmsg {
    my ($line) = @_;
    chomp $line if($line);
    $line .= "\n";
    print "$line";
}


#***************************************************************************
# Display contents of the given file
#
sub display_file {
    my $filename = $_[0];
    print "=== Start of file $filename\n";
    if(open(DISPLAYFH, "<$filename")) {
        while(my $line = <DISPLAYFH>) {
            print "$line";
        }
        close DISPLAYFH;
    }
    print "=== End of file $filename\n";
}


#***************************************************************************
# Display contents of the ssh daemon config file
#
sub display_sshdconfig {
    display_file($sshdconfig);
}


#***************************************************************************
# Display contents of the ssh client config file
#
sub display_sshconfig {
    display_file($sshconfig);
}


#***************************************************************************
# Display contents of the sftp client config file
#
sub display_sftpconfig {
    display_file($sftpconfig);
}


#***************************************************************************
# Display contents of the ssh daemon log file
#
sub display_sshdlog {
    die "error: \$sshdlog uninitialized" if(not defined $sshdlog);
    display_file($sshdlog);
}


#***************************************************************************
# Display contents of the ssh client log file
#
sub display_sshlog {
    die "error: \$sshlog uninitialized" if(not defined $sshlog);
    display_file($sshlog);
}


#***************************************************************************
# Display contents of the sftp client log file
#
sub display_sftplog {
    die "error: \$sftplog uninitialized" if(not defined $sftplog);
    display_file($sftplog);
}


#***************************************************************************
# Find a file somewhere in the given path
#
sub find_file {
    my $fn = $_[0];
    shift;
    my @path = @_;
    foreach (@path) {
        my $file = File::Spec->catfile($_, $fn);
        if(-e $file && ! -d $file) {
            return $file;
        }
    }
}


#***************************************************************************
# Find an executable file somewhere in the given path
#
sub find_exe_file {
    my $fn = $_[0];
    shift;
    my @path = @_;
    my $xext = exe_ext('SSH');
    foreach (@path) {
        my $file = File::Spec->catfile($_, $fn);
        if(-e $file && ! -d $file) {
            return $file if(-x $file);
            return $file if(($xext) && (lc($file) =~ /\Q$xext\E$/));
        }
    }
}


#***************************************************************************
# Find a file in environment path or in our sftppath
#
sub find_file_spath {
    my $filename = $_[0];
    my @spath;
    push(@spath, File::Spec->path());
    push(@spath, @sftppath);
    return find_file($filename, @spath);
}


#***************************************************************************
# Find an executable file in environment path or in our httptlssrvpath
#
sub find_exe_file_hpath {
    my $filename = $_[0];
    my @hpath;
    push(@hpath, File::Spec->path());
    push(@hpath, @httptlssrvpath);
    return find_exe_file($filename, @hpath);
}


#***************************************************************************
# Find ssh daemon and return canonical filename
#
sub find_sshd {
    return find_file_spath($sshdexe);
}


#***************************************************************************
# Find ssh client and return canonical filename
#
sub find_ssh {
    return find_file_spath($sshexe);
}


#***************************************************************************
# Find sftp-server plugin and return canonical filename
#
sub find_sftpsrv {
    return find_file_spath($sftpsrvexe);
}


#***************************************************************************
# Find sftp client and return canonical filename
#
sub find_sftp {
    return find_file_spath($sftpexe);
}


#***************************************************************************
# Find ssh-keygen and return canonical filename
#
sub find_sshkeygen {
    return find_file_spath($sshkeygenexe);
}


#***************************************************************************
# Find httptlssrv (gnutls-serv) and return canonical filename
#
sub find_httptlssrv {
    return find_exe_file_hpath($httptlssrvexe);
}


#***************************************************************************
# Return version info for the given ssh client or server binaries
#
sub sshversioninfo {
    my $sshbin = $_[0]; # canonical filename
    my $major;
    my $minor;
    my $patch;
    my $sshid;
    my $versnum;
    my $versstr;
    my $error;

    if(!$sshbin) {
        $error = 'Error: Missing argument 1 for sshversioninfo()';
    }
    elsif(! -x $sshbin) {
        $error = "Error: cannot read or execute $sshbin";
    }
    else {
        my $cmd = ($sshbin =~ /$sshdexe$/) ? "\"$sshbin\" -?" : "\"$sshbin\" -V";
        $error = "$cmd\n";
        foreach my $tmpstr (qx($cmd 2>&1)) {
            if($tmpstr =~ /OpenSSH[_-](\d+)\.(\d+)(\.(\d+))*/i) {
                $major = $1;
                $minor = $2;
                $patch = $4?$4:0;
                $sshid = 'OpenSSH';
                $versnum = (100*$major) + (10*$minor) + $patch;
                $versstr = "$sshid $major.$minor.$patch";
                $error = undef;
                last;
            }
            if($tmpstr =~ /OpenSSH[_-]for[_-]Windows[_-](\d+)\.(\d+)(\.(\d+))*/i) {
                $major = $1;
                $minor = $2;
                $patch = $4?$4:0;
                $sshid = 'OpenSSH-Windows';
                $versnum = (100*$major) + (10*$minor) + $patch;
                $versstr = "$sshid $major.$minor.$patch";
                $error = undef;
                last;
            }
            if($tmpstr =~ /Sun[_-]SSH[_-](\d+)\.(\d+)(\.(\d+))*/i) {
                $major = $1;
                $minor = $2;
                $patch = $4?$4:0;
                $sshid = 'SunSSH';
                $versnum = (100*$major) + (10*$minor) + $patch;
                $versstr = "$sshid $major.$minor.$patch";
                $error = undef;
                last;
            }
            $error .= $tmpstr;
        }
        chomp $error if($error);
    }
    return ($sshid, $versnum, $versstr, $error);
}


#***************************************************************************
# End of library
1;
