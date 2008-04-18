#!/usr/bin/env perl
# sleep for a number of seconds
if ( $#ARGV != 0 )
{
    print "Usage: $0 seconds\n";
    exit 1;
}
if ( $ARGV[0] =~ /(\d+)/ ) {
    sleep $1;
    exit 0;
}
else {
    print "Usage: $0 seconds\n";
    exit 1;
}

