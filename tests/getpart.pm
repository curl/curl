
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

            while($attr =~ s/ *([^=]*)= *(\"([^\"]*)\"|([^\"> ]*))//) {
                my ($var, $cont)=($1, $2);
                $cont =~ s/^\"(.*)\"$/$1/;
                $hash{$var}=$cont;
            }
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
        elsif((1 ==$inside) && ($_ =~ /^ *\<$part[ \>]/)) {
            if($_ =~ /$part [^>]*base64=/) {
                # attempt to detect base64 encoded parts
                $base64=1;
            }
            $inside++;
        }
        elsif((2 ==$inside) && ($_ =~ /^ *\<\/$part/)) {
            $inside--;
        }
        elsif((1==$inside) && ($_ =~ /^ *\<\/$section/)) {
            if($trace) {
                print STDERR "*** getpart.pm: $section/$part returned data!\n";
            }
            if(!@this && $warning) {
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
        elsif(2==$inside) {
            push @this, $_;
        }
    }
    if($warning) {
        print STDERR "*** getpart.pm: $section/$part returned empty!\n";
    }
    return @this; #empty!
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
# Load a specified file an return it as an array
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
        print TEMP $_;
    }
    close(TEMP);

    open(TEMP, ">$file2");
    for(@$secondref) {
        print TEMP $_;
    }
    close(TEMP);
    my @out = `diff -u $file2 $file1 2>/dev/null`;

    if(!$out[0]) {
        @out = `diff -c $file2 $file1 2>/dev/null`;
    }

    return @out;
}


1;
