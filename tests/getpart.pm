
#use strict;

my @xml;

my $warning=0;
my $trace=0;

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
            my @p=split("[ \t]", $attr);
            my $assign;

            foreach $assign (@p) {
                # $assign is a 'name="contents"' pair

                if($assign =~ / *([^=]*)=\"([^\"]*)\"/) {
                    # *with* quotes
                    $hash{$1}=$2;
                }
                elsif($assign =~ / *([^=]*)=([^\"]*)/) {
                    # *without* quotes
                    $hash{$1}=$2;
                }
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

 #   print "Section: $section, part: $part\n";

    for(@xml) {
 #       print "$inside: $_";
        if(!$inside && ($_ =~ /^ *\<$section/)) {
            $inside++;
        }
        elsif((1 ==$inside) && ($_ =~ /^ *\<$part[ \>]/)) {
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

 my $sizefirst=scalar(@$firstref);
 my $sizesecond=scalar(@$secondref);

 if($sizefirst != $sizesecond) {
     return -1;
 }

 for(1 .. $sizefirst) {
     my $index = $_ - 1;
     if($firstref->[$index] ne $secondref->[$index]) {
         (my $aa = $firstref->[$index]) =~ s/\r+\n$/\n/;
         (my $bb = $secondref->[$index]) =~ s/\r+\n$/\n/;
         if($aa ne $bb) {
             return 1+$index;
         }
     }
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

#
# Given two array references, this function will store them in two
# temporary files, run 'diff' on them, store the result, remove the
# temp files and return the diff output!
# 
sub showdiff {
    my ($firstref, $secondref)=@_;

    my $file1=".generated";
    my $file2=".expected";
    
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
    my @out = `diff -u $file2 $file1`;

    unlink $file1, $file2;
    return @out;
}


1;
