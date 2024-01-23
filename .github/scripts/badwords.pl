#!/usr/bin/perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# bad[:=]correct
#
# If separator is '=', the string will be compared case sensitively.
# If separator is ':', the check is done case insensitively.
#
my $w;
while(<STDIN>) {
    chomp;
    if($_ =~ /^#/) {
        next;
    }
    if($_ =~ /^([^:=]*)([:=])(.*)/) {
        my ($bad, $sep, $better)=($1, $2, $3);
        push @w, $bad;
        $alt{$bad} = $better;
        if($sep eq "=") {
            $exactcase{$bad} = 1;
        }
    }
}

my $errors;

sub file {
    my ($f) = @_;
    my $l = 0;
    open(F, "<$f");
    while(<F>) {
        my $in = $_;
        $l++;
        chomp $in;
        if($in =~ /^    /) {
            next;
        }
        # remove the link part
        $in =~ s/(\[.*\])\(.*\)/$1/g;
        # remove backticked texts
        $in =~ s/\`.*\`//g;
        foreach my $w (@w) {
            my $case = $exactcase{$w};
            if(($in =~ /^(.*)$w/i && !$case) ||
               ($in =~ /^(.*)$w/ && $case) ) {
                my $p = $1;
                my $c = length($p)+1;
                print STDERR  "$f:$l:$c: error: found bad word \"$w\"\n";
                printf STDERR " %4d | $in\n", $l;
                printf STDERR "      | %*s^%s\n", length($p), " ",
                    "~" x (length($w)-1);
                printf STDERR " maybe use \"%s\" instead?\n", $alt{$w};
                $errors++;
            }
        }
    }
    close(F);
}

my @files = @ARGV;

foreach my $each (@files) {
    file($each);
}
exit $errors;
