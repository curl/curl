#!/usr/bin/perl

# git log --pretty=fuller --no-color --date=short

my @mname = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' );

sub nicedate {
    my ($date)=$_;

    if($date =~ /(\d\d\d\d)-(\d\d)-(\d\d)/) {
        return sprintf("%d %s %4d", $3, $mname[$2-1], $1);
    }
    return $date;
}

my $line;
while(<STDIN>) {
    my $l = $_;

    if($l =~/^commit (.*)/) {
        $co = $1;
    }
    elsif($l =~ /^Author: *(.*) +</) {
        $a = $1;
    }
    elsif($l =~ /^Commit: *(.*) +</) {
        $c = $1;
    }
    elsif($l =~ /^CommitDate: (.*)/) {
        $date = nicedate($1);
    }
    elsif($l =~ /^(    )(.*)/) {
        my $extra;
        if($a ne $c) {
            $extra=sprintf("\n- [%s brought this change]\n\n  ", $a);
        }
        else {
            $extra="\n- ";
        }
        if($co ne $oldco) {
            if($c ne $oldc) {
                print "\n$c ($date)$extra";
            }
            else {
                print "$extra";
            }
            $line =0;
        }

        $oldco = $co;
        $oldc = $c;
        $olddate = $date;
        if($line++) {
            print "  ";
        }
        print $2."\n";
    }
}
