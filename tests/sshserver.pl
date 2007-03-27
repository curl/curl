#/usr/bin/env perl
# $Id$
# Start sshd for use in the SCP and SFTP curl test harness tests

# Options:
# -u user
# -v
# target_port

use strict;
use File::Spec;

my $verbose=0; # set to 1 for debugging

my $port = 8999;        # just our default, weird enough

my $path = `pwd`;
chomp $path;

my $exeext;
if ($^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys' || $^O eq 'dos' || $^O eq 'os2') {
    $exeext = '.exe';
}

# Where to look for sftp-server
my @sftppath=qw(/usr/lib/openssh /usr/libexec/openssh /usr/libexec /usr/local/libexec /opt/local/libexec /usr/lib/ssh /usr/libexec/ssh /usr/sbin /usr/lib /usr/lib/ssh/openssh /usr/lib64/ssh);

my $username = $ENV{USER};

# Find a file somewhere in the given path
sub searchpath {
  my $fn = $_[0] . $exeext;
  shift;
  my @path = @_;
  foreach (@path) {
	my $file = File::Spec->catfile($_, $fn);
	if (-e $file) {
		return $file;
	}
  }
}

# Parse options
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-u") {
        $username=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
} while(shift @ARGV);

my $conffile="curl_sshd_config";	# sshd configuration data

# Search the PATH for sshd.  sshd insists on being called with an absolute
# path for some reason.
my $sshd = searchpath("sshd", File::Spec->path());
if (!$sshd) {
	print "sshd is not available\n";
	exit 1;
}
if ($verbose) {
	print STDERR "SSH server found at $sshd\n";
}

my $sftp = searchpath("sftp-server", @sftppath);
if (!$sftp) {
	print "Could not find sftp-server plugin\n";
	exit 1;
}
if ($verbose) {
	print STDERR "SFTP server plugin found at $sftp\n";
}

if (! -e "curl_client_key.pub") {
	if ($verbose) {
		print STDERR "Generating host and client keys...\n";
	}
	# Make sure all files are gone so ssh-keygen doesn't complain
	unlink("curl_host_dsa_key", "curl_client_key","curl_host_dsa_key.pub", "curl_client_key.pub"); 
	system "ssh-keygen -q -t dsa -f curl_host_dsa_key -C 'curl test server' -N ''" and die "Could not generate key";
        system "ssh-keygen -q -t dsa -f curl_client_key -C 'curl test client' -N ''" and die "Could not generate key";
}

open(FILE, ">$conffile") || die "Could not write $conffile";
print FILE <<EOF
# This is a generated file!  Do not edit!
# OpenSSH sshd configuration file for curl testing
AllowUsers $username
DenyUsers
DenyGroups
AuthorizedKeysFile $path/curl_client_key.pub
HostKey $path/curl_host_dsa_key
PidFile $path/.ssh.pid
Port $port
ListenAddress localhost
Protocol 2
AllowTcpForwarding no
GatewayPorts no
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
KeepAlive no
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PrintLastLog no
PrintMotd no
StrictModes no
Subsystem sftp $sftp
UseLogin no
X11Forwarding no
UsePrivilegeSeparation no
# Newer OpenSSH options
UsePam no
UseDNS no
ChallengeResponseAuthentication no
EOF
;
close FILE;

if (system "$sshd -t -q -f $conffile") {
	# This is likely due to missing support for UsePam
	print "$sshd is too old and is not supported\n";
	unlink $conffile;
	exit 1;
}

# Start the server
my $rc = system "$sshd -e -f $conffile > log/ssh.log 2>&1";
$rc >>= 8;
if($rc) {
    print STDERR "$sshd exited with $rc!\n";
}

unlink $conffile;

exit $rc;
