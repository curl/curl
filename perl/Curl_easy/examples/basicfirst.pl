# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

use strict;
use Curl::easy;

my $url = "http://curl.haxx.se/dev/";

print "Testing curl version ",&Curl::easy::version(),"\n";

# Init the curl session
my $curl= Curl::easy::init();
if(!$curl) {
    die "curl init failed!\n";
}

# Follow location headers
 Curl::easy::setopt($curl, CURLOPT_FOLLOWLOCATION, 1);

# Add some additional headers to the http-request:
my @myheaders;
$myheaders[0] = "I-am-a-silly-programmer: yes indeed you are";
$myheaders[1] = "User-Agent: Perl interface for libcURL";
 Curl::easy::setopt($curl, Curl::easy::CURLOPT_HTTPHEADER, \@myheaders);
                                                                        
my $errbuf;
Curl::easy::setopt($curl, CURLOPT_ERRORBUFFER, "errbuf");

Curl::easy::setopt($curl, CURLOPT_URL, $url);

sub body_callback {
    my ($chunk,$handle)=@_;
    push @$handle, $chunk;
    return length($chunk); # OK
}
 Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, \&body_callback);

my @body;
 Curl::easy::setopt($curl, CURLOPT_FILE, \@body);

if (Curl::easy::perform($curl) != 0) {
    print "Failed :$errbuf\n";
};

# Cleanup
 Curl::easy::cleanup($curl);

print @body;
