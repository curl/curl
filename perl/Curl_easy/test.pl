# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..5\n"; }
END {print "not ok 1\n" unless $loaded;}
use Curl::easy;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

# Read URL to get
$defurl = "http://www/";
$url = "";
print "Please enter an URL to fetch [$defurl]: ";
$url = <STDIN>;
if ($url =~ /^\s*\n/) {
    $url = $defurl;
}

# Use this for simple benchmarking
#for ($i=0; $i<1000; $i++) {

# Init the curl session
if (($curl = Curl::easy::curl_easy_init()) != 0) {
    print "ok 2\n";
} else {
    print "ko 2\n";
}

# Set URL to get
if (Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_URL, $url) == 0) {
    print "ok 3\n";
} else {
    print "ko 3\n";
}

# No progress meter please
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_NOPROGRESS, 1);

# Shut up completely
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_MUTE, 1);

# Follow location headers
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_FOLLOWLOCATION, 1);

# Set timeout
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_TIMEOUT, 30);

# Set file where to read cookies from
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_COOKIEFILE, "cookies");

# Set file where to store the header
open HEAD, ">head.out";
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_WRITEHEADER, HEAD);

# Set file where to store the body
open BODY, ">body.out";
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_FILE, BODY);

# Store error messages in variable $errbuf
# NOTE: The name of the variable is passed as a string!
# curl_easy_setopt() creates a perl variable with that name, and
# curl_easy_perform() stores the errormessage into it if an error occurs.
Curl::easy::curl_easy_setopt($curl, Curl::easy::CURLOPT_ERRORBUFFER, "errbuf");

# Go get it
if (Curl::easy::curl_easy_perform($curl) == 0) {
    Curl::easy::curl_easy_getinfo($curl, Curl::easy::CURLINFO_SIZE_DOWNLOAD, $bytes);
    print "ok 4: $bytes bytes read\n";
    print "check out the files head.out and body.out\n";
    print "for the headers and content of the URL you just fetched...\n";
    Curl::easy::curl_easy_getinfo($curl, Curl::easy::CURLINFO_EFFECTIVE_URL, $realurl);
    Curl::easy::curl_easy_getinfo($curl, Curl::easy::CURLINFO_HTTP_CODE, $httpcode);
    print "effective fetched url (http code: $httpcode) was: $url\n";
} else {
    # We can acces the error message in $errbuf here
    print "ko 4: '$errbuf'\n";
}

# Cleanup
close HEAD;
close BODY;
Curl::easy::curl_easy_cleanup($curl);
print "ok 5\n";

# Use this for simple benchmarking
#}

