
use strict;

my @xml;

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
        elsif((1 ==$inside) && ($_ =~ /^ *\<$part/)) {
            $inside++;
        }
        elsif((2 ==$inside) && ($_ =~ /^ *\<\/$part/)) {
            $inside--;
        }
        elsif((1==$inside) && ($_ =~ /^ *\<\/$section/)) {
            return @this;
        }
        elsif(2==$inside) {
            push @this, $_;
        }
    }
    return @this; #empty!
}

sub loadtest {
    my ($file)=@_;

    undef @xml;
    open(XML, "<$file") ||
        return 1; # failure!
    while(<XML>) {
        push @xml, $_;
    }
    close(XML);
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
         return 1+$index;
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

    my $file1=".array1";
    my $file2=".array2";
    
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

    my @out = `diff $file1 $file2`;

    unlink $file1, $file2;
    return @out;
}


1;
