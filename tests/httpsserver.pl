#!/usr/bin/env perl
#
# $Id$
# This is the HTTPS and FTPS server designed for the curl test suite.
#
# It is actually just a layer that runs stunnel properly.

use strict;
use Cwd;

my $stunnel = "stunnel";

my $verbose=0; # set to 1 for debugging

my $port = 8991;        # just our default, weird enough
my $target_port = 8999; # default test http-server port

my $path = getcwd();

my $srcdir=$path;

my $proto='https';

my $stuncert;

my $ver_major;
my $ver_minor;
my $stunnel_version;
my $socketopt;
my $cmd;

#***************************************************************************
# Process command line options
#
while(@ARGV) {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    if($ARGV[0] eq "-w") {
        return 0; # return success, means we have stunnel working!
    }
    elsif($ARGV[0] eq "-p") {
        $proto=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-r") {
        $target_port=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-s") {
        $stunnel=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-d") {
        $srcdir=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-c") {
        $stuncert=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
    shift @ARGV;
};

my $conffile="$path/stunnel.conf";	# stunnel configuration data
my $certfile="$srcdir/" 
            . ($stuncert?"certs/$stuncert":"stunnel.pem");	# stunnel server certificate

my $pidfile="$path/.$proto.pid";	# stunnel process pid file
my $logfile="$path/log/${proto}_stunnel.log";    # stunnel log file
my $loglevel=5;

my $ssltext = uc($proto) ." SSL/TLS:";

#***************************************************************************
# Find out version info for the given stunnel binary
#
foreach my $veropt (('-version', '-V')) {
    foreach my $verstr (qx($stunnel $veropt 2>&1)) {
        if($verstr =~ /^stunnel (\d+)\.(\d+) on /) {
            $ver_major = $1;
            $ver_minor = $2;
            last;
        }
    }
    last if($ver_major);
}
if((!$ver_major) || (!$ver_minor)) {
    if(-x "$stunnel" && ! -d "$stunnel") {
        print "$ssltext Unknown stunnel version\n";
    }
    else {
        print "$ssltext No stunnel\n";
    }
    exit 1;
}
$stunnel_version = (100*$ver_major) + $ver_minor;

#***************************************************************************
# Verify minimmum stunnel required version
#
if($stunnel_version < 310) {
    print "$ssltext Unsupported stunnel version $ver_major.$ver_minor\n";
}

#***************************************************************************
# Build command to execute for stunnel 3.X versions
#
if($stunnel_version < 400) {
    if($stunnel_version >= 319) {
        $socketopt = "-O a:SO_REUSEADDR=1";
    }
    $cmd  = "$stunnel -p $certfile -P $pidfile ";
    $cmd .= "-d $port -r $target_port -f -D $loglevel ";
    $cmd .= ($socketopt) ? "$socketopt " : "";
    $cmd .= ">$logfile 2>&1";
    if($verbose) {
        print uc($proto) ." server (stunnel $ver_major.$ver_minor)\n";
        print "cmd: $cmd\n";
        print "pem cert file: $certfile\n";
        print "pid file: $pidfile\n";
        print "log file: $logfile\n";
        print "log level: $loglevel\n";
        print "listen on port: $port\n";
        print "connect to port: $target_port\n";
    }
}

#***************************************************************************
# Build command to execute for stunnel 4.00 and newer
#
if($stunnel_version >= 400) {
    $socketopt = "a:SO_REUSEADDR=1";
    $cmd  = "$stunnel $conffile ";
    $cmd .= ">$logfile 2>&1";
    # stunnel configuration file
    if(open(STUNCONF, ">$conffile")) {
	print STUNCONF "
	CApath = $path
	cert = $certfile
	pid = $pidfile
	debug = $loglevel
	output = $logfile
	socket = $socketopt
	foreground = yes
	
	[curltest]
	accept = $port
	connect = $target_port
	";
        if(!close(STUNCONF)) {
            print "$ssltext Error closing file $conffile\n";
            exit 1;
        }
    }
    else {
        print "$ssltext Error writing file $conffile\n";
        exit 1;
    }
    if($verbose) {
        print uc($proto) ." server (stunnel $ver_major.$ver_minor)\n";
        print "cmd: $cmd\n";
        print "CApath = $path\n";
        print "cert = $certfile\n";
        print "pid = $pidfile\n";
        print "debug = $loglevel\n";
        print "output = $logfile\n";
        print "socket = $socketopt\n";
        print "foreground = yes\n";
        print "\n";
        print "[curltest]\n";
        print "accept = $port\n";
        print "connect = $target_port\n";
    }
}

#***************************************************************************
# Set file permissions on certificate pem file.
#
chmod(0600, $certfile) if(-f $certfile);

#***************************************************************************
# Run stunnel.
#
my $rc = system($cmd);

$rc >>= 8;
#if($rc) {
#    print "stunnel exited with $rc!\n";
#}

unlink $conffile;

exit $rc;
