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

my $port = 8433; # just a default
my $http = 8999; # http-port
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    if($ARGV[0] eq "-w") {
        return 0; # return success, means we have stunnel working!
    }
    elsif($ARGV[0] eq "-r") {
        $http=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
} while(shift @ARGV);

my $path = `pwd`;
chomp $path;
my $cmd = "$stunnel -p $path/data/stunnel.pem -P $path/.https.pid -d $port -r $http";

if($verbose) {
    print "$cmd\n";
}
system($cmd);
