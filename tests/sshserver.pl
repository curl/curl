#/usr/bin/env perl
# $Id$
# Starts sshd for use in the SCP, SFTP and SOCKS curl test harness tests.
# Also creates the ssh configuration files (this could be moved to a
# separate script).

# Options:
# -u user
# -v
# target_port

use strict;
use File::Spec;
use Cwd;

my $verbose=1; # set to 1 for debugging
my $showfiles=0;

my $port = 8999;        # just our default, weird enough
my $listenaddr = "127.0.0.1"; # address on which to listen

my $conffile="curl_sshd_config";    # sshd configuration data
my $conffile_ssh="curl_ssh_config";    # ssh configuration data
my $knownhostsfile="curl_client_knownhosts";    # ssh knownhosts file

my $path = getcwd();

my $exeext;
if ($^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys' || $^O eq 'dos' || $^O eq 'os2') {
    $exeext = '.exe';
}

# Where to look for sftp-server
my @sftppath = qw(
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
    /opt/ssh/sbin
    /opt/ssh/libexec
    );

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

# Display contents of the given file.
sub displayfile {
    my ($file) = @_;
    print "=== Start of file $file\n";
    if(open(SINGLE, "<$file")) {
        while(my $string = <SINGLE>) {
            print "$string";
        }
        close(SINGLE);
    }
    print "=== End of file $file\n";
}

# Append a string to sshd config file
sub set_sshd_option {
    my ($string) = @_;
    if (open(FILE, ">>$conffile")) {
        print FILE "$string\n";
        close FILE;
    }
}

# Append a string to ssh config file
sub set_ssh_option {
    my ($string) = @_;
    if (open(FILE, ">>$conffile_ssh")) {
        print FILE "$string\n";
        close FILE;
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
    elsif($ARGV[0] eq "-l") {
        $listenaddr=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
} while(shift @ARGV);

# Searching for sshd and sftp-server will be done first
# in the PATH and afterwards in other common locations.
my @spath;
push(@spath, File::Spec->path()); 
push(@spath, @sftppath); 

# sshd insists on being called with an absolute path.
my $sshd = searchpath("sshd", @spath);
if (!$sshd) {
    print "sshd$exeext not found\n";
    exit 1;
}
if ($verbose) {
    print "SSH server found is $sshd\n";
}

my $sftp = searchpath("sftp-server", @spath);
if (!$sftp) {
    print "Could not find sftp-server$exeext plugin\n";
    exit 1;
}
if ($verbose) {
    print "SFTP server plugin found is $sftp\n";
}

if ($username eq "root") {
    print "Will not run ssh daemon as root to mitigate security risks\n";
    exit 1;
}

# Find out sshd version.
my $tmpstr;
my $ssh_daemon;
my $ssh_ver_major;
my $ssh_ver_minor;
my $ssh_ver_patch;
my $ssh_version;
foreach $tmpstr (qx($sshd -V 2>&1)) {
    if($tmpstr =~ /OpenSSH[_-](\d+)\.(\d+)(\.(\d+))*/i) {
        ($ssh_ver_major, $ssh_ver_minor, $ssh_ver_patch) = ($1, $2, $4);
        $ssh_daemon = 'OpenSSH';
        $ssh_version = 10 * $ssh_ver_major + $ssh_ver_minor;
        if($ssh_version == 36) {
            $showfiles=1;
        }
        last;
    }
    if($tmpstr =~ /Sun[_-]SSH[_-](\d+)\.(\d+)/i) {
        ($ssh_ver_major, $ssh_ver_minor) = ($1, $2);
        $ssh_daemon = 'SunSSH';
        $ssh_version = 10 * $ssh_ver_major + $ssh_ver_minor;
        if($ssh_version == 11) {
            $showfiles=1;
        }
        last;
    }
}

# Verify minimum SSH daemon version.
my $sshd_ver_ok = 1;
if(!$ssh_daemon) {
    if($verbose) {
        print "unsupported SSH server daemon found\n";
        chomp($tmpstr = qx($sshd -V 2>&1));
        print "$tmpstr\n";
    }
    $sshd_ver_ok = 0;
}
elsif(($ssh_daemon =~ /OpenSSH/) && ($ssh_version < 36)) {
    if($verbose) {
        print "sshd found is $ssh_daemon $ssh_ver_major.$ssh_ver_minor\n";
    }
    $sshd_ver_ok = 0;
}
elsif(($ssh_daemon =~ /SunSSH/) && ($ssh_version < 11)) {
    if($verbose) {
        print "sshd found is $ssh_daemon $ssh_ver_major.$ssh_ver_minor\n";
    }
    $sshd_ver_ok = 0;
}
if(!$sshd_ver_ok) {
    print "SCP, SFTP and SOCKS tests require OpenSSH 3.7 or later\n";
    exit 1;
}

# Initialize sshd configuration file for curl's tests.
open(CONF, ">$conffile") || die "Could not write $conffile";
print CONF "# This is a generated file!  Do not edit!\n";
print CONF "# $ssh_daemon $ssh_ver_major.$ssh_ver_minor sshd configuration file for curl testing\n";
close CONF;

# Support for some options might have not been built into sshd.  On some
# platforms specifying an unsupported option prevents sshd from starting.
# Check here for possible unsupported options, avoiding its use in sshd.
sub sshd_supports_opt($) {
    my ($option) = @_;
    my $err = grep /((Unsupported)|(Bad configuration)|(Deprecated)) option.*$option/,
                    qx($sshd -t -f $conffile -o $option=no 2>&1);
    return !$err;
}

my $supports_UsePAM = sshd_supports_opt('UsePAM');
my $supports_UseDNS = sshd_supports_opt('UseDNS');
my $supports_ChReAu = sshd_supports_opt('ChallengeResponseAuthentication');

if (! -e "curl_client_key.pub") {
    if ($verbose) {
        print "Generating host and client keys...\n";
    }
    # Make sure all files are gone so ssh-keygen doesn't complain
    unlink("curl_host_dsa_key", "curl_client_key","curl_host_dsa_key.pub", "curl_client_key.pub"); 
    system "ssh-keygen -q -t dsa -f curl_host_dsa_key -C 'curl test server' -N ''" and die "Could not generate host key";
    system "ssh-keygen -q -t dsa -f curl_client_key -C 'curl test client' -N ''" and die "Could not generate client key";
}

open(FILE, ">>$conffile") || die "Could not write $conffile";
print FILE <<EOFSSHD
AllowUsers $username
DenyUsers
DenyGroups
AuthorizedKeysFile $path/curl_client_key.pub
HostKey $path/curl_host_dsa_key
PidFile $path/.ssh.pid
Port $port
ListenAddress $listenaddr
Protocol 2
AllowTcpForwarding yes
GatewayPorts no
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
KeepAlive no
PasswordAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
PermitRootLogin no
PrintLastLog no
PrintMotd no
StrictModes no
Subsystem sftp $sftp
UseLogin no
PrintLastLog no
X11Forwarding no
UsePrivilegeSeparation no
# Newer OpenSSH options
EOFSSHD
;
close FILE ||  die "Could not close $conffile";

if ($supports_UsePAM) {
    set_sshd_option('UsePAM no');
}
if ($supports_UseDNS) {
    set_sshd_option('UseDNS no');
}
if ($supports_ChReAu) {
    set_sshd_option('ChallengeResponseAuthentication no');
}


# Now, set up some configuration files for the ssh client
open(DSAKEYFILE, "<curl_host_dsa_key.pub") || die 'Could not read curl_host_dsa_key.pub';
my @dsahostkey = do { local $/ = ' '; <DSAKEYFILE> };
close DSAKEYFILE || die "Could not close DSAKEYFILE";

open(KNOWNHOSTS, ">$knownhostsfile") || die "Could not write $knownhostsfile";
print KNOWNHOSTS "[$listenaddr]:$port ssh-dss $dsahostkey[1]\n" || die 'Could not write to KNOWNHOSTS';
close KNOWNHOSTS || die "Could not close KNOWNHOSTS";

open(SSHFILE, ">$conffile_ssh") || die "Could not write $conffile_ssh";
print SSHFILE <<EOFSSH
IdentityFile $path/curl_client_key
UserKnownHostsFile $path/$knownhostsfile
StrictHostKeyChecking no
Protocol 2
BatchMode yes
CheckHostIP no
Compression no
ForwardX11 no
GatewayPorts no
HostbasedAuthentication yes
NoHostAuthenticationForLocalhost no
# Newer OpenSSH options
#SetupTimeOut 20
EOFSSH
;
close SSHFILE ||  die "Could not close $conffile_ssh";

if(($ssh_daemon =~ /OpenSSH/) && ($ssh_version >= 37)) {
    set_ssh_option('ConnectTimeout 20'); # Supported in OpenSSH 3.7 and later
}


# Verify that sshd supports our configuration file
if (system "$sshd -t -f $conffile > log/sshd.log 2>&1") {
    print "sshd configuration file failed verification\n";
    displayfile("log/sshd.log");
    displayfile("$conffile");
    unlink "log/sshd.log";
    unlink $conffile;
    exit 1;
}

# Start the server
my $rc = system "$sshd -e -D -f $conffile > log/sshd.log 2>&1";
if($rc == -1) {
    print "$sshd failed with: $!\n";
    $showfiles=1;
}
elsif($rc & 127) {
    printf("$sshd died with signal %d, and %s coredump.\n",
           ($rc & 127), ($rc & 128)?"a":"no");
    $showfiles=1;
}
elsif($verbose && ($rc >> 8)) {
    printf("$sshd exited with %d \n", $rc >> 8);
}

if($showfiles) {
    displayfile("log/sshd.log");
    displayfile("$conffile");
}

unlink "log/sshd.log";
unlink $conffile;

exit $rc >> 8;
