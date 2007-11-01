#!/usr/bin/env perl
# Determine if curl-config --protocols matches the curl --version protocols
if ( $#ARGV != 1 ) 
{
	print "Usage: $0 curl-config-script curl-features-file\n";
	exit 3;
}

my $curl_protocols="";
open(CURL, "@ARGV[1]") || die "Can't get curl protocols list\n";
while( <CURL> )
{
    $curl_protocols = $_ if ( /Protocols:/ );
}
close CURL;

$curl_protocols =~ /Protocols: (.*)$/;
@curl = split / /,$1;
@curl = sort @curl;

my @curl_config;
open(CURLCONFIG, "sh @ARGV[0] --protocols|") || die "Can't get curl-config protocols list\n";
while( <CURLCONFIG> )
{
    chomp;
    push @curl_config, lc($_);
}
close CURLCONFIG;

@curl_config = sort @curl_config;

my $curlproto = join ' ', @curl;
my $curlconfigproto = join ' ', @curl_config;

my $different = $curlproto ne $curlconfigproto;
if ($different) {
	print "Mismatch in protocol lists:\n";
	print "curl:        $curlproto\n";
	print "curl-config: $curlconfigproto\n";
}
exit $different;
