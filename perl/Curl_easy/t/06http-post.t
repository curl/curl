# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

# Before `make install' is performed this script should be runnable with
# `make t/thisfile.t'. After `make install' it should work as `perl thisfile.t'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
use strict;

BEGIN { $| = 1; print "1..7\n"; }
END {print "not ok 1\n" unless $::loaded;}
use Curl::easy;

$::loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $count=1;

# Read URL to get
my $defurl = "http://localhost/cgi-bin/printenv";
my $url;
if (defined ($ENV{CURL_TEST_URL})) {
	$url=$ENV{CURL_TEST_URL};
} else {
$url = "";
print "Please enter an URL to fetch [$defurl]: ";
$url = <STDIN>;
if ($url =~ /^\s*\n/) {
    $url = $defurl;
}
}

# Init the curl session
my $curl = Curl::easy::init();
if ($curl == 0) {
    print "not ";
}
print "ok ".++$count."\n";

Curl::easy::setopt($curl, CURLOPT_NOPROGRESS, 1);
Curl::easy::setopt($curl, CURLOPT_MUTE, 1);
Curl::easy::setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
Curl::easy::setopt($curl, CURLOPT_TIMEOUT, 30);

open HEAD, ">head.out";
Curl::easy::setopt($curl, CURLOPT_WRITEHEADER, *HEAD);
print "ok ".++$count."\n";

open BODY, ">body.out";
Curl::easy::setopt($curl, CURLOPT_FILE,*BODY);
print "ok ".++$count."\n";

my $errbuf;
Curl::easy::setopt($curl, CURLOPT_ERRORBUFFER, "errbuf");
print "ok ".++$count."\n";

Curl::easy::setopt($curl, CURLOPT_URL, $url);

print "ok ".++$count."\n";

my $read_max=1000;

sub read_callb
{
    my ($maxlen,$sv)=@_;
    print STDERR "\nperl read_callback has been called!\n";
    print STDERR "max data size: $maxlen - need $read_max bytes\n";
	if ($read_max > 0) {
		my $len=int($read_max/3)+1;
		my $data = chr(ord('A')+rand(26))x$len;
		print STDERR "generated max/3=", int($read_max/3)+1, " characters to be uploaded - $data.\n";
		$read_max=$read_max-length($data);
		return $data;
	} else {
		return "";
	}
}  

#
# test post/read callback functions - requires a url which accepts posts, or it fails!
#

Curl::easy::setopt($curl,CURLOPT_READFUNCTION,\&read_callb);
Curl::easy::setopt($curl,CURLOPT_INFILESIZE,$read_max );
Curl::easy::setopt($curl,CURLOPT_UPLOAD,1 );
Curl::easy::setopt($curl,CURLOPT_CUSTOMREQUEST,"POST" );
                                                       
if (Curl::easy::perform($curl) != 0) {
	print "not ";
};
print "ok ".++$count."\n";
