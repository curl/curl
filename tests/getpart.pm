#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

package getpart;

use strict;
use warnings;

BEGIN {
    use base qw(Exporter);

    our @EXPORT = qw(
        compareparts
        fulltest
        getpart
        getpartattr
        loadarray
        loadtest
        partexists
        striparray
        writearray
    );
}

use Memoize;
use MIME::Base64;

my @xml;      # test data file contents
my $xmlfile;  # test data file name

my $warning=0;
my $trace=0;

# Normalize the part function arguments for proper caching. This includes the
# file name in the arguments since that is an implied parameter that affects the
# return value.  Any error messages will only be displayed the first time, but
# those are disabled by default anyway, so should never been seen outside
# development.
sub normalize_part {
    push @_, $xmlfile;
    return join("\t", @_);
}

sub decode_hex {
    my $s = $_;
    # remove everything not hex
    $s =~ s/[^A-Fa-f0-9]//g;
    # encode everything
    $s =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;
    return $s;
}

sub testcaseattr {
    my %hash;
    for(@xml) {
        if(($_ =~ /^ *\<testcase ([^>]*)/)) {
            my $attr=$1;
            while($attr =~ s/ *([^=]*)= *(\"([^\"]*)\"|([^\> ]*))//) {
                my ($var, $cont)=($1, $2);
                $cont =~ s/^\"(.*)\"$/$1/;
                $hash{$var}=$cont;
            }
        }
    }
    return %hash;
}

sub getpartattr {
    # if $part is undefined (ie only one argument) then
    # return the attributes of the section

    my ($section, $part)=@_;

    my %hash;
    my $inside=0;

 #   print "Section: $section, part: $part\n";

    for(@xml) {
 #       print "$inside: $_";
        if(!$inside && ($_ =~ /^ *\<$section/)) {
            $inside++;
        }
        if((1 ==$inside) && ( ($_ =~ /^ *\<$part ([^>]*)/) ||
                              !(defined($part)) )
             ) {
            $inside++;
            my $attr=$1;

            while($attr =~ s/ *([^=]*)= *(\"([^\"]*)\"|([^\> ]*))//) {
                my ($var, $cont)=($1, $2);
                $cont =~ s/^\"(.*)\"$/$1/;
                $hash{$var}=$cont;
            }
            last;
        }
        # detect end of section when part wasn't found
        elsif((1 ==$inside) && ($_ =~ /^ *\<\/$section\>/)) {
            last;
        }
        elsif((2 ==$inside) && ($_ =~ /^ *\<\/$part/)) {
            $inside--;
        }
    }
    return %hash;
}
memoize('getpartattr', NORMALIZER => 'normalize_part');  # cache each result

sub getpart {
    my ($section, $part)=@_;

    my @this;
    my $inside=0;
    my $base64=0;
    my $hex=0;
    my $line;

    for(@xml) {
        $line++;
        if(!$inside && ($_ =~ /^ *\<$section/)) {
            $inside++;
        }
        elsif(($inside >= 1) && ($_ =~ /^ *\<$part[ \>]/)) {
            if($inside > 1) {
                push @this, $_;
            }
            elsif($_ =~ /$part [^>]*base64=/) {
                # attempt to detect our base64 encoded part
                $base64=1;
            }
            elsif($_ =~ /$part [^>]*hex=/) {
                # attempt to detect a hex-encoded part
                $hex=1;
            }
            $inside++;
        }
        elsif(($inside >= 2) && ($_ =~ /^ *\<\/$part[ \>]/)) {
            if($inside > 2) {
                push @this, $_;
            }
            $inside--;
        }
        elsif(($inside >= 1) && ($_ =~ /^ *\<\/$section/)) {
            if($inside > 1) {
                print STDERR "$xmlfile:$line:1: error: missing </$part> tag before </$section>\n";
                @this = ("format error in $xmlfile");
            }
            if($trace && @this) {
                print STDERR "*** getpart.pm: $section/$part returned data!\n";
            }
            if($warning && !@this) {
                print STDERR "*** getpart.pm: $section/$part returned empty!\n";
            }
            if($base64) {
                # decode the whole array before returning it!
                for(@this) {
                    my $decoded = decode_base64($_);
                    $_ = $decoded;
                }
            }
            elsif($hex) {
                # decode the whole array before returning it!
                for(@this) {
                    my $decoded = decode_hex($_);
                    $_ = $decoded;
                }
            }
            return @this;
        }
        elsif($inside >= 2) {
            push @this, $_;
        }
    }
    if($trace && @this) {
        # section/part has data but end of section not detected,
        # end of file implies end of section.
        print STDERR "*** getpart.pm: $section/$part returned data!\n";
    }
    if($warning && !@this) {
        # section/part does not exist or has no data without an end of
        # section; end of file implies end of section.
        print STDERR "*** getpart.pm: $section/$part returned empty!\n";
    }
    return @this;
}
memoize('getpart', NORMALIZER => 'normalize_part');  # cache each result

sub partexists {
    my ($section, $part)=@_;

    my $inside = 0;

    for(@xml) {
        if(!$inside && ($_ =~ /^ *\<$section/)) {
            $inside++;
        }
        elsif((1 == $inside) && ($_ =~ /^ *\<$part[ \>]/)) {
            return 1; # exists
        }
        elsif((1 == $inside) && ($_ =~ /^ *\<\/$section/)) {
            return 0; # does not exist
        }
    }
    return 0; # does not exist
}
# The code currently never calls this more than once per part per file, so
# caching a result that will never be used again just slows things down.
# memoize('partexists', NORMALIZER => 'normalize_part');  # cache each result

sub loadtest {
    my ($file)=@_;

    if(defined $xmlfile && $file eq $xmlfile) {
        # This test is already loaded
        return
    }

    undef @xml;
    $xmlfile = "";

    if(open(my $xmlh, "<", "$file")) {
        binmode $xmlh; # for crapage systems, use binary
        while(<$xmlh>) {
            push @xml, $_;
        }
        close($xmlh);
    }
    else {
        # failure
        if($warning) {
            print STDERR "file $file wouldn't open!\n";
        }
        return 1;
    }
    $xmlfile = $file;
    return 0;
}


# Return entire document as list of lines
sub fulltest {
    return @xml;
}

# write the test to the given file
sub savetest {
    my ($file)=@_;

    if(open(my $xmlh, ">", "$file")) {
        binmode $xmlh; # for crapage systems, use binary
        for(@xml) {
            print $xmlh $_;
        }
        close($xmlh);
    }
    else {
        # failure
        if($warning) {
            print STDERR "file $file wouldn't open!\n";
        }
        return 1;
    }
    return 0;
}

#
# Strip off all lines that match the specified pattern and return
# the new array.
#

sub striparray {
    my ($pattern, $arrayref) = @_;

    my @array;

    for(@$arrayref) {
        if($_ !~ /$pattern/) {
            push @array, $_;
        }
    }
    return @array;
}

#
# pass array *REFERENCES* !
#
sub compareparts {
 my ($firstref, $secondref)=@_;

 my $first = join("", @$firstref);
 my $second = join("", @$secondref);

 # we cannot compare arrays index per index since with the base64 chunks,
 # they may not be "evenly" distributed

 # NOTE: this no longer strips off carriage returns from the arrays. Is that
 # really necessary? It ruins the testing of newlines. I believe it was once
 # added to enable tests on Windows.

 if($first ne $second) {
     return 1;
 }

 return 0;
}

#
# Write a given array to the specified file
#
sub writearray {
    my ($filename, $arrayref)=@_;

    open(my $temp, ">", "$filename") || die "Failure writing file";
    binmode($temp,":raw");  # Cygwin fix by Kevin Roth
    for(@$arrayref) {
        print $temp $_;
    }
    close($temp) || die "Failure writing file";
}

#
# Load a specified file and return it as an array
#
sub loadarray {
    my ($filename)=@_;
    my @array;

    if (open(my $temp, "<", "$filename")) {
        while(<$temp>) {
            push @array, $_;
        }
        close($temp);
    }
    return @array;
}


1;
