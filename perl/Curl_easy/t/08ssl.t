# Test script for Perl extension Curl::easy.
# Check out the file README for more info.

# Before `make install' is performed this script should be runnable with
# `make t/thisfile.t'. After `make install' it should work as `perl thisfile.t'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
use strict;

BEGIN { $| = 1; print "1..20\n"; }
END {print "not ok 1\n" unless $::loaded;}
use Curl::easy;

$::loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $count=1;

# list of tests
# 	site-url,         verifypeer(0,1),  verifyhost(0,2), result(0=ok, 1=fail)
my $url_list=[
	[ 'https://216.168.252.86/',  0, 0, 0 ], # www.awayweb.com
	[ 'https://216.168.252.86/',  0, 2, 1 ], # www.awayweb.com
	[ 'https://www.verisign.com/', 0, 0, 0 ],
	[ 'https://www.verisign.com/', 0, 2, 0 ],
	[ 'https://www.verisign.com/', 1, 2, 0 ], # these fail on openssl0.9.5 - unknown sig
	[ 'https://www.verisign.com/', 1, 2, 0 ], # these fail on openssl0.9.5 - unknown sig
	[ 'https://lc2.law13.hotmail.passport.com/', 0, 0, 0 ],
	[ 'https://lc2.law13.hotmail.passport.com/', 0, 2, 0 ],
	[ 'https://lc2.law13.hotmail.passport.com/', 1, 2, 0 ], # fail on 0.9.5
	[ 'https://lc2.law13.hotmail.passport.com/', 1, 2, 0 ], # fail on 0.9.5
	[ 'https://www.modssl.org/',  0, 0, 0 ],
	[ 'https://www.modssl.org/',  0, 2, 0 ],
	[ 'https://www.modssl.org/',  1, 0, 1 ],
	[ 'https://www.modssl.org/',  1, 2, 1 ],
];

# Init the curl session
my $curl = Curl::easy::init();
if ($curl == 0) {
    print "not ";
}
print "ok ".++$count."\n";


Curl::easy::setopt($curl, CURLOPT_NOPROGRESS, 1);
Curl::easy::setopt($curl, CURLOPT_MUTE, 0);
#Curl::easy::setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
Curl::easy::setopt($curl, CURLOPT_TIMEOUT, 30);

my @myheaders;
$myheaders[1] = "User-Agent: Verifying SSL functions in perl interface for libcURL";
Curl::easy::setopt($curl, CURLOPT_HTTPHEADER, \@myheaders);
                                                                                       
open HEAD, ">head.out";
Curl::easy::setopt($curl, CURLOPT_WRITEHEADER, *HEAD);
print "ok ".++$count."\n";

open BODY, ">body.out";
Curl::easy::setopt($curl, CURLOPT_FILE,*BODY);
print "ok ".++$count."\n";

my $errbuf;
Curl::easy::setopt($curl, CURLOPT_ERRORBUFFER, "errbuf");
print "ok ".++$count."\n";

Curl::easy::setopt($curl, CURLOPT_FORBID_REUSE, 1);


print "ok ".++$count."\n";
Curl::easy::setopt($curl, CURLOPT_CAINFO,"ca-bundle.crt");                       

foreach my $test_list (@$url_list) {
    my ($url,$verifypeer,$verifyhost,$result)=@{$test_list};
    print STDERR "testing $url verify=$verifypeer at level $verifyhost expect ".($result?"fail":"pass")."\n";

    Curl::easy::setopt($curl, CURLOPT_SSL_VERIFYPEER,$verifypeer); # do verify 
    Curl::easy::setopt($curl, CURLOPT_SSL_VERIFYHOST,$verifyhost); # check name
    my $retcode;

    Curl::easy::setopt($curl, CURLOPT_URL, $url);

    $retcode=Curl::easy::perform($curl);
    if ( ($retcode != 0) != $result) {
  	print STDERR "error $retcode $errbuf\n";
	print "not ";
    };
    print "ok ".++$count."\n";

}
