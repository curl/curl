# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)
use Benchmark;
use strict;

BEGIN { $| = 1; print "1..13\n"; }
END {print "not ok 1\n" unless $::loaded;}
use Curl::easy;

$::loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

print "Testing curl version ",&Curl::easy::version(),"\n";

# Read URL to get
my $defurl = "http://localhost/cgi-bin/printenv";
my $url = "";
print "Please enter an URL to fetch [$defurl]: ";
$url = <STDIN>;
if ($url =~ /^\s*\n/) {
    $url = $defurl;
}

# Init the curl session
my $curl;
if (($curl = Curl::easy::init()) != 0) {
    print "ok 2\n";
} else {
    print "ko 2\n";
}


# No progress meter please
# !! Need this on for all tests, as once disabled, can't re-enable it...
#Curl::easy::setopt($curl, CURLOPT_NOPROGRESS, 1);

# Shut up completely
Curl::easy::setopt($curl, CURLOPT_MUTE, 1);

# Follow location headers
Curl::easy::setopt($curl, CURLOPT_FOLLOWLOCATION, 1);

# Set timeout
Curl::easy::setopt($curl, CURLOPT_TIMEOUT, 30);

# Set file where to read cookies from
Curl::easy::setopt($curl, CURLOPT_COOKIEFILE, "cookies");

# Set file where to store the header
open HEAD, ">head.out";
Curl::easy::setopt($curl, CURLOPT_WRITEHEADER, *HEAD);
print "ok 3\n";

# Set file where to store the body
# Send body to stdout - test difference between FILE * and SV *
#open BODY, ">body.out";
#Curl::easy::setopt($curl, CURLOPT_FILE,*BODY);
print "ok 4\n";

# Add some additional headers to the http-request:
my @myheaders;
$myheaders[0] = "Server: www";
$myheaders[1] = "User-Agent: Perl interface for libcURL";
Curl::easy::setopt($curl, Curl::easy::CURLOPT_HTTPHEADER, \@myheaders);
                                                                        
# Store error messages in variable $errbuf
# NOTE: The name of the variable is passed as a string!
# setopt() creates a perl variable with that name, and
# perform() stores the errormessage into it if an error occurs.
 
Curl::easy::setopt($curl, CURLOPT_ERRORBUFFER, "errbuf");
Curl::easy::setopt($curl, CURLOPT_URL, $url);
print "ok 5\n";

my $bytes;
my $realurl;
my $httpcode;
my $errbuf;

# Go get it
if (Curl::easy::perform($curl) == 0) {
    Curl::easy::getinfo($curl, CURLINFO_SIZE_DOWNLOAD, $bytes);
    print "ok 6: $bytes bytes read\n";
    Curl::easy::getinfo($curl, CURLINFO_EFFECTIVE_URL, $realurl);
    Curl::easy::getinfo($curl, CURLINFO_HTTP_CODE, $httpcode);
    print "effective fetched url (http code: $httpcode) was: $url\n";
} else {
   # We can acces the error message in $errbuf here
    print "not ok 6: '$errbuf'\n";
	die "basic url access failed";
}

# cleanup
#close HEAD;
# test here - BODY is still expected to be the output
# Curl-easy-1.0.2.pm core dumps if we 'perform' with a closed output FD...
#close BODY;
#exit;
#
# The header callback will only be called if your libcurl has the
# CURLOPT_HEADERFUNCTION supported, otherwise your headers
# go to CURLOPT_WRITEFUNCTION instead...
#

my $header_called=0;
sub header_callback { print "header callback called\n"; $header_called=1; return length($_[0])};

# test for sub reference and head callback
Curl::easy::setopt($curl, CURLOPT_HEADERFUNCTION, \&header_callback);
print "ok 7\n"; # so far so good

if (Curl::easy::perform($curl) != 0) {
	print "not ";
};
print "ok 8\n";

print "next test will fail on libcurl < 7.7.2\n";
print "not " if (!$header_called); # ok if you have a libcurl <7.7.2
print "ok 9\n";

my $body_called=0;
sub body_callback {
	my ($chunk,$handle)=@_;
	print "body callback called with ",length($chunk)," bytes\n";
	print "data=$chunk\n";
	$body_called++;
	return length($chunk); # OK
}

# test for ref to sub and body callback
my $body_ref=\&body_callback;
Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, $body_ref);

if (Curl::easy::perform($curl) != 0) {
	print "not ";
};
print "ok 10\n";

print "not " if (!$body_called);
print "ok 11\n";

my $body_abort_called=0;
sub body_abort_callback {
	my ($chunk,$sv)=@_;
	print "body abort callback called with ",length($chunk)," bytes\n";
	$body_abort_called++;
	return  -1; # signal a failure
}

# test we can abort a request mid-way
my $body_abort_ref=\&body_abort_callback;
Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, $body_abort_ref);

if (Curl::easy::perform($curl) == 0) { # reverse test - this should have failed
	print "not ";
};
print "ok 12\n";

print "not " if (!$body_abort_called); # should have been called
print "ok 13\n";

# reset to a working 'write' function for next tests
Curl::easy::setopt($curl,CURLOPT_WRITEFUNCTION, sub { return length($_[0])} );

# inline progress function
# tests for inline subs and progress callback
# - progress callback must return 'true' on each call.
 
my $progress_called=0;
sub prog_callb
{
    my ($clientp,$dltotal,$dlnow,$ultotal,$ulnow)=@_;
    print "\nperl progress_callback has been called!\n";
    print "clientp: $clientp, dltotal: $dltotal, dlnow: $dlnow, ultotal: $ultotal, ";
    print "ulnow: $ulnow\n";
	$progress_called++;
    return 0;
}                        

Curl::easy::setopt($curl, CURLOPT_PROGRESSFUNCTION, \&prog_callb);

# Turn progress meter back on - this doesn't work - once its off, its off.
Curl::easy::setopt($curl, CURLOPT_NOPROGRESS, 0);

if (Curl::easy::perform($curl) != 0) {
	print "not ";
};
print "ok 14\n";

print "not " if (!$progress_called);
print "ok 15\n";

my $read_max=10;

sub read_callb
{
    my ($maxlen,$sv)=@_;
    print "\nperl read_callback has been called!\n";
    print "max data size: $maxlen\n";
	print "(upload needs $read_max bytes)\n";
    print "context: ".$sv."\n";
	if ($read_max > 0) {
		print "\nEnter max ", $read_max, " characters to be uploaded.\n";
		my $data = <STDIN>;
		chomp $data;
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
print "ok 16\n";

sub passwd_callb
{
    my ($clientp,$prompt,$buflen)=@_;
    print "\nperl passwd_callback has been called!\n";
    print "clientp: $clientp, prompt: $prompt, buflen: $buflen\n";
    print "\nEnter max $buflen characters for $prompt ";
    my $data = <STDIN>;
    chomp($data);
    return (0,$data);
}                                                         

Curl::easy::cleanup($curl);

# Now do an ftp upload:

$defurl = "ftp://horn\@localhost//tmp/bla";
print "\n\nPlease enter an URL for ftp upload [$defurl]: ";
$url = <STDIN>;
if ($url =~ /^\s*\n/) {
    $url = $defurl;
}

# Init the curl session
if (($curl = Curl::easy::init()) != 0) {
    print "ok 17\n";
} else {
    print "not ok 17\n";
}

# Set URL to get
if (Curl::easy::setopt($curl, Curl::easy::CURLOPT_URL, $url) == 0) {
    print "ok 18\n";
} else {
    print "not ok 18\n";

}

# Tell libcurl to to an upload
Curl::easy::setopt($curl, Curl::easy::CURLOPT_UPLOAD, 1);

# No progress meter please
#Curl::easy::setopt($curl, Curl::easy::CURLOPT_NOPROGRESS, 1);

# Use our own progress callback
Curl::easy::setopt($curl, Curl::easy::CURLOPT_PROGRESSFUNCTION, \&prog_callb);

# Shut up completely
Curl::easy::setopt($curl, Curl::easy::CURLOPT_MUTE, 1);

# Store error messages in $errbuf
Curl::easy::setopt($curl, Curl::easy::CURLOPT_ERRORBUFFER, "errbuf");

$read_max=10;
# Use perl read callback to read data to be uploaded
Curl::easy::setopt($curl, Curl::easy::CURLOPT_READFUNCTION,
    \&read_callb);

# Use perl passwd callback to read password for login to ftp server
Curl::easy::setopt($curl, Curl::easy::CURLOPT_PASSWDFUNCTION, \&passwd_callb);

print "ok 19\n";

# Go get it
if (Curl::easy::perform($curl) == 0) {
    Curl::easy::getinfo($curl, Curl::easy::CURLINFO_SIZE_UPLOAD, $bytes);
    print "ok 20: $bytes bytes transferred\n\n";
} else {
    # We can acces the error message in $errbuf here
    print "not ok 20: '$errbuf'\n";
}

# Cleanup
Curl::easy::cleanup($curl);
print "ok 21\n";

