#!/usr/bin/perl
#
# $Id$
# This is the HTTPS server designed for the curl test suite.
#
# It is actually just a layer that runs stunnel properly.

use strict;

use stunnel;

my $stunnel = &checkstunnel;

if(!$stunnel) {
    exit;
}

#
# -p pemfile
# -P pid dir
# -d listen port
# -r target port

my $verbose=0; # set to 1 for debugging

my $port = 8821; # just our default, weird enough
my $ftp = 8921; # test ftp-server port
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-r") {
        $ftp=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
} while(shift @ARGV);

my $path = `pwd`;
chomp $path;
my $cmd = "$stunnel -p $path/stunnel.pem -P $path/.ftps.pid -d $port -r $ftp";

if($verbose) {
    print "FTPS server: $cmd\n";
}
system($cmd);
