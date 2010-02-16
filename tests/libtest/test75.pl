#!/usr/bin/env perl
# Check that the length of a given URL is correct
if ( $#ARGV != 1 )
{
    print "Usage: $0 string length\n";
    exit 3;
}
if (length(@ARGV[0]) != @ARGV[1])
{
    print "Given host IP and port not supported\n";
    exit 1;
}
exit 0;
