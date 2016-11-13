#!/usr/bin/perl

my $some_dir=".";

opendir(my $dh, $some_dir) || die "Can't opendir $some_dir: $!";
my @s = grep { /\.d$/ && -f "$some_dir/$_" } readdir($dh);
closedir $dh;

my %optshort;
my %optlong;

# get the long name version, return the man page string
sub manpageify {
    my ($k)=@_;
    my $l;
    if($optlong{$k} ne "") {
        # both short + long
        $l = "\\fI-".$optlong{$k}.", --$k\\fP";
    }
    else {
        # only long
        $l = "\\fI--$k\\fP";
    }
    return $l;
}

sub printdesc {
    my @desc = @_;
    for my $d (@desc) {
        # skip lines starting with space (examples)
        if($d =~ /^[^ ]/) {
            for my $k (keys %optlong) {
                my $l = manpageify($k);
                $d =~ s/--$k(\s)/$l$1/;
            }
        }
        print $d;
    }
}

sub single {
    my ($f)=@_;
    open(F, "<$f");
    my $short;
    my $long;
    my $tags;
    my $added;
    my $protocols;
    my $arg;
    my $mutexed;
    my $requires;
    my $seealso;
    my $magic; # cmdline special option
    while(<F>) {
        if(/^Short: (.)/i) {
            $short=$1;
        }
        elsif(/^Long: (.*)/i) {
            $long=$1;
        }
        elsif(/^Added: (.*)/i) {
            $added=$1;
        }
        elsif(/^Tags: (.*)/i) {
            $tags=$1;
        }
        elsif(/^Arg: (.*)/i) {
            $arg=$1;
        }
        elsif(/^Magic: (.*)/i) {
            $magic=$1;
        }
        elsif(/^Mutexed: (.*)/i) {
            $mutexed=$1;
        }
        elsif(/^Protocols: (.*)/i) {
            $protocols=$1;
        }
        elsif(/^See-also: (.*)/i) {
            $seealso=$1;
        }
        elsif(/^Requires: (.*)/i) {
            $requires=$1;
        }
        elsif(/^---/) {
            last;
        }
    }
    my @dest;
    while(<F>) {
        push @desc, $_;
    }
    close(F);
    my $opt;
    if(defined($short) && $long) {
        $opt = "-$short, --$long";
    }
    elsif($short && !$long) {
        $opt = "-$short";
    }
    elsif($long && !$short) {
        $opt = "--$long";
    }

    if($arg) {
        $opt .= " $arg";
    }

    print ".IP \"$opt\"\n";
    my $o;
    if($protocols) {
        $o++;
        print "($protocols) ";
    }
    if(!$arg && !$mutexed && !$magic) {
        $o++;
        print "[Boolean] ";
    }
    if($magic) {
        $o++;
        print "[cmdline control] ";
    }

    print "\n" if($o);

    printdesc(@desc);
    undef @desc;

    my @foot;
    if($seealso) {
        my @m=split(/ /, $seealso);
        my $mstr;
        for my $k (@m) {
            my $l = manpageify($k);
            $mstr .= sprintf "%s$l", $mstr?" and ":"";
        }
        push @foot, "See also $mstr. ";
    }
    if($requires) {
        my $l = manpageify($long);
        push @foot, "$l requires that the underlying libcurl".
            " was built to support $requires. ";
    }
    if($mutexed) {
        my @m=split(/ /, $mutexed);
        my $mstr;
        for my $k (@m) {
            my $l = manpageify($k);
            $mstr .= sprintf "%s$l", $mstr?" and ":"";
        }
        push @foot, "This option overrides $mstr. ";
    }
    if($added) {
        push @foot, "Added in $added. ";
    }
    if($foot[0]) {
        print "\n";
        print @foot;
        print "\n";
    }
}

sub getshortlong {
    my ($f)=@_;
    open(F, "<$f");
    my $short;
    my $long;

    while(<F>) {
        if(/^Short: (.)/i) {
            $short=$1;
        }
        elsif(/^Long: (.*)/i) {
            $long=$1;
        }
        elsif(/^---/) {
            last;
        }
    }
    close(F);
    if($short) {
        $optshort{$short}=$long;
    }
    if($long) {
        $optlong{$long}=$short;
    }
}

sub indexoptions {
  foreach my $f (@s) {
    getshortlong($f);
  }
}

sub header {
    open(F, "<page-header");
    my @d;
    while(<F>) {
        push @d, $_;
    }
    close(F);
    printdesc(@d);
}

#------------------------------------------------------------------------

# learn all existing options
indexoptions();

# show the page header
header();

# output docs for all options
foreach my $f (sort @s) {
    single($f);
}
