#!/usr/bin/env perl
# Determine if curl-config --protocols/--features matches the
# curl --version protocols/features
if ( $#ARGV != 2 ) 
{
	print "Usage: $0 curl-config-script curl-version-output-file features|protocols\n";
	exit 3;
}

my $what=$ARGV[2];

# Read the output of curl --version
my $curl_protocols="";
open(CURL, "$ARGV[1]") || die "Can't get curl $what list\n";
while( <CURL> )
{
    $curl_protocols = lc($_) if ( /$what:/i );
}
close CURL;

$curl_protocols =~ /\w+: (.*)$/;
@curl = split / /,$1;

# These features are not supported by curl-config
@curl = grep(!/^(Debug|TrackMemory|Largefile|CharConv|GSS-Negotiate|SPNEGO)$/i, @curl);
@curl = sort @curl;

# Read the output of curl-config
my @curl_config;
open(CURLCONFIG, "sh $ARGV[0] --$what|") || die "Can't get curl-config $what list\n";
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
	print "Mismatch in $what lists:\n";
	print "curl:        $curlproto\n";
	print "curl-config: $curlconfigproto\n";
}
exit $different;
