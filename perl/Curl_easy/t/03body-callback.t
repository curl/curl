# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

# Before `make install' is performed this script should be runnable with
# `make t/thisfile.t'. After `make install' it should work as `perl thisfile.t'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
use strict;

BEGIN { $| = 1; print "1..9\n"; }
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

# The header callback will only be called if your libcurl has the
# CURLOPT_HEADERFUNCTION supported, otherwise your headers
# go to CURLOPT_WRITEFUNCTION instead...
#

my $header_called=0;
sub header_callback { print STDERR "header callback called\n"; $header_called=1; return length($_[0])};

# test for sub reference and head callback
Curl::easy::setopt($curl, CURLOPT_HEADERFUNCTION, \&header_callback);

my $body_called=0;
sub body_callback {
	my ($chunk,$handle)=@_;
	print STDERR "body callback called with ",length($chunk)," bytes\n";
	print STDERR "data=$chunk\n";
	$body_called++;
	return length($chunk); # OK
}


# test for ref to sub and body callback
my $body_ref=\&body_callback;
Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, $body_ref);

if (Curl::easy::perform($curl) != 0) {
	print "not ";
};
print "ok ".++$count."\n";


print STDERR "next test will fail on libcurl < 7.7.2\n";
print STDERR "not " if (!$header_called); # ok if you have a libcurl <7.7.2
print "ok ".++$count."\n";

print "not " if (!$body_called);
print "ok ".++$count."\n";
