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

package sshhelp;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT_OK = qw(
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
        find_httptlssrv
        sshversioninfo
    );
}

use File::Spec;

use pathhelp qw(
    exe_ext
    );

#***************************************************************************
# Global variables initialization
#
our $sshdexe         = 'sshd'        .exe_ext('SSH'); # base name and ext of ssh daemon
our $sshexe          = 'ssh'         .exe_ext('SSH'); # base name and ext of ssh client
our $sftpsrvexe      = 'sftp-server' .exe_ext('SSH'); # base name and ext of sftp-server
our $sftpexe         = 'sftp'        .exe_ext('SSH'); # base name and ext of sftp client
our $sshkeygenexe    = 'ssh-keygen'  .exe_ext('SSH'); # base name and ext of ssh-keygen
our $httptlssrvexe   = 'gnutls-serv' .exe_ext('SSH'); # base name and ext of gnutls-serv
our $sshdconfig      = 'curl_sshd_config';       # ssh daemon config file
our $sshconfig       = 'curl_ssh_config';        # ssh client config file
our $sftpconfig      = 'curl_sftp_config';       # sftp client config file
our $sshdlog         = undef;                    # ssh daemon log file
our $sshlog          = undef;                    # ssh client log file
our $sftplog         = undef;                    # sftp client log file
our $sftpcmds        = 'curl_sftp_cmds';         # sftp client commands batch file
our $knownhosts      = 'curl_client_knownhosts'; # ssh knownhosts file
our $hstprvkeyf      = 'curl_host_rsa_key';      # host private key file
our $hstpubkeyf      = 'curl_host_rsa_key.pub';  # host public key file
our $hstpubmd5f      = 'curl_host_rsa_key.pub_md5';  # md5 hash of host public key
our $hstpubsha256f   = 'curl_host_rsa_key.pub_sha256';  # sha256 hash of host public key
our $cliprvkeyf      = 'curl_client_key';        # client private key file
our $clipubkeyf      = 'curl_client_key.pub';    # client public key file


#***************************************************************************
# Absolute paths where to look for sftp-server plugin, when not in PATH
#
our @sftppath = qw(
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
our @httptlssrvpath = qw(
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
# Create or overwrite the given file with lines from an array of strings
#
sub dump_array {
    my ($filename, @arr) = @_;
    my $error;

    if(!$filename) {
        $error = 'Error: Missing argument 1 for dump_array()';
    }
    elsif(open(my $textfh, ">", $filename)) {
        foreach my $line (@arr) {
            $line .= "\n" if($line !~ /\n$/);
            print $textfh $line;
        }
        if(!close($textfh)) {
            $error = "Error: cannot close file $filename";
        }
    }
    else {
        $error = "Error: cannot write file $filename";
    }
    return $error;
}


#***************************************************************************
# Display contents of the given file
#
sub display_file {
    my $filename = $_[0];
    print "=== Start of file $filename\n";
    if(open(my $displayfh, "<", "$filename")) {
        while(my $line = <$displayfh>) {
            print "$line";
        }
        close $displayfh;
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
    return "";
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
    return "";
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
    my $p = find_exe_file_hpath($httptlssrvexe);
    if($p) {
        my @o = `"$p" -l`;
        my $found;
        for(@o) {
            if(/Key exchange: SRP/) {
                $found = 1;
                last;
            }
        }
        return $p if($found);
    }
    return "";
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
