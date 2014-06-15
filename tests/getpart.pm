#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

#use strict;

my @xml;

my $warning=0;
my $trace=0;

sub decode_base64 {
  tr:A-Za-z0-9+/::cd;                   # remove non-base64 chars
  tr:A-Za-z0-9+/: -_:;                  # convert to uuencoded format
  my $len = pack("c", 32 + 0.75*length);   # compute length byte
  return unpack("u", $len . $_);         # uudecode and print
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
        if((1 ==$inside) && ( ($_ =~ /^ *\<$part([^>]*)/) ||
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

sub getpart {
    my ($section, $part)=@_;

    my @this;
    my $inside=0;
    my $base64=0;

 #   print "Section: $section, part: $part\n";

    for(@xml) {
 #       print "$inside: $_";
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
            $inside++;
        }
        elsif(($inside >= 2) && ($_ =~ /^ *\<\/$part[ \>]/)) {
            if($inside > 2) {
                push @this, $_;
            }
            $inside--;
        }
        elsif(($inside >= 1) && ($_ =~ /^ *\<\/$section/)) {
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

# Return entire document as list of lines
sub getall {
    return @xml;
}

sub loadtest {
    my ($file)=@_;

    undef @xml;

    if(open(XML, "<$file")) {
        binmode XML; # for crapage systems, use binary
        while(<XML>) {
            push @xml, $_;
        }
        close(XML);
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
 # added to enable tests on win32.

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

    open(TEMP, ">$filename");
    binmode(TEMP,":raw"); # cygwin fix by Kevin Roth
    for(@$arrayref) {
        print TEMP $_;
    }
    close(TEMP);
}

#
# Load a specified file and return it as an array
#
sub loadarray {
    my ($filename)=@_;
    my @array;

    open(TEMP, "<$filename");
    while(<TEMP>) {
        push @array, $_;
    }
    close(TEMP);
    return @array;
}

# Given two array references, this function will store them in two temporary
# files, run 'diff' on them, store the result and return the diff output!

sub showdiff {
    my ($logdir, $firstref, $secondref)=@_;

    my $file1="$logdir/check-generated";
    my $file2="$logdir/check-expected";

    open(TEMP, ">$file1");
    for(@$firstref) {
        my $l = $_;
        $l =~ s/\r/[CR]/g;
        $l =~ s/\n/[LF]/g;
        print TEMP $l;
        print TEMP "\n";
    }
    close(TEMP);

    open(TEMP, ">$file2");
    for(@$secondref) {
        my $l = $_;
        $l =~ s/\r/[CR]/g;
        $l =~ s/\n/[LF]/g;
        print TEMP $l;
        print TEMP "\n";
    }
    close(TEMP);
    my @out = `diff -u $file2 $file1 2>/dev/null`;

    if(!$out[0]) {
        @out = `diff -c $file2 $file1 2>/dev/null`;
    }

    return @out;
}


1;
