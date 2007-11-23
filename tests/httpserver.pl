#!/usr/bin/env perl

use strict;

my $verbose=0; # set to 1 for debugging

my $dir=".";
my $port = 8999; # just a default
my $ipv6;
my $pid=".http.pid"; # name of the pidfile
my $fork;
do {
    if($ARGV[0] eq "-v") {
        $verbose=1;
    }
    elsif($ARGV[0] eq "-d") {
        $dir=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "-p") {
        $pid=$ARGV[1];
        shift @ARGV;
    }
    elsif($ARGV[0] eq "--fork") {
        $fork = $ARGV[0];
        shift @ARGV;
    }
    elsif($ARGV[0] =~ /^(\d+)$/) {
        $port = $1;
    }
    elsif($ARGV[0] =~ /^ipv6/i) {
        $ipv6="--ipv6 ";
    }
} while(shift @ARGV);

exec("server/sws --pidfile $pid$fork $ipv6$port $dir");
