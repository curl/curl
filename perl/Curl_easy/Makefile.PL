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
