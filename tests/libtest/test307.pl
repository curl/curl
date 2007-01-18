#!/usr/bin/env perl
# Determine if the given curl executable supports the 'openssl' SSL engine
if ( $#ARGV != 0 ) 
{
	print "Usage: $0 curl-executable\n";
	exit 3;
}
if (!open(CURL, "@ARGV[0] -s --engine list|"))
{
	print "Can't get SSL engine list\n";
	exit 2;
}
while( <CURL> )
{
    exit 0 if ( /openssl/ );
}
close CURL;
print "openssl engine not supported\n";
exit 1;
