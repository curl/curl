# Makefile.PL for Perl extension Curl::easy.
# Check out the file README for more info.

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Curl::easy',
    'VERSION_FROM' => 'easy.pm', # finds $VERSION
    'LIBS'	=> ['-lcurl '],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
    'clean'	=> {FILES => "head.out body.out"}
);

#
# This utility helper generates the constants function from curl.h
#
# It is normally only used by the maintainer, but if you're curl is older
# or missing some constants, you can delete curlopt-constants.c and re-run 'perl Makefile.PL'
#

if (!open(CONSTANTS,"<curlopt-constants.c")) {
    print "Rebuilding curlopt-constants.c for your libcurl version\n";
    close(CONSTANTS); 

#
# You may need to specify where to find curl.h on your platform
# These are guesses only
#
my $curl_h;
HEADER: foreach my $try (qw(

	curl.h                        
	../../include/curl.h              
	/usr/include/curl/curl.h    
	/usr/local/include/curl/curl.h
	C:\\INCLUDE\\CURL\\CURL.H  

	))
{
    if (-e $try) {
	$curl_h=$try;
	last HEADER;
    }
}

if (!defined($curl_h)) {
	die "Could not rebuild curlopt-constants.c - can't find curl.h\n";
}

print "Found curl.h in $curl_h\n";
open (CURL_H,"<".$curl_h) or die "Can't open curl.h\n";
my %types;
my %codes;
while(<CURL_H>) {
    if ($_ =~ m/CINIT\(/ and $_ !~ m/#/) {
	my ($option,$type,$code)=m/.*CINIT\((\w*)\s*,\s*(\w+)\s*,\s*(\d+).*/;
	$types{$option}=$type;
	$codes{$option}=$code;
    }
}
close(CURL_H);

# some things are ifdefed out...
foreach my $ifdef0 (qw(FLAGS PROGRESSMODE))
{
	delete $types{$ifdef0}; delete $codes{$ifdef0};
}

open(CURL_XS,">curlopt-constants.c") or die "Can't write curlopt-constants.c\n";
foreach my $next_initial ('A'..'Z') {
    print CURL_XS "        case '$next_initial':\n";
    my $count=0;
    foreach my $option (sort keys %types) {
	my $initial=substr($option,0,1);
	if ($next_initial eq $initial) {
	    print CURL_XS "            if (strEQ(name, \"$option\")) return CURLOPT_$option;\n";
	    $count++;
	}
    }    
    if ($count) {
	print CURL_XS "            break;\n";
    }
}
close(CURL_XS);
}
