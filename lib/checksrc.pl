#!/usr/bin/perl

my $file=$ARGV[0];

my $max_column = 79;
my $indent = 2;

my $warnings;
my $errors;

sub checkwarn {
    my ($num, $col, $file, $line, $msg, $error) = @_;

    my $w=$error?"error":"warning";

    if($w) {
        $warnings++;
    }
    else {
        $errors++;
    }

    $col++;
    print "$file:$num:$col: $w: $msg\n";
    print " $line\n";

    if($col < 80) {
        my $pref = (' ' x $col);
        print "${pref}^\n";
    }
}

if(!$file) {
    print "checksrc.pl <single C or H file>\n";
    exit;
}


my $line = 1;
open(R, "<$file") || die;

my $copyright=0;

while(<R>) {
    chomp;
    my $l = $_;
    my $column = 0;

    # check for a copyright statement
    if(!$copyright && ($l =~ /copyright .* \d\d\d\d/i)) {
        $copyright=1;
    }

    # detect long lines
    if(length($l) > $max_column) {
        checkwarn($line, length($l), $file, $l, "Longer than $max_column columns");
    }
    # detect TAB characters
    if($l =~ /^(.*)\t/) {
        checkwarn($line, length($1), $file, $l, "Contains TAB character", 1);
    }
    # detect trailing white space
    if($l =~ /^(\S+)[ \t]+\z/) {
        checkwarn($line, length($1), $file, $l, "Trailing whitespace");
    }

    # detect return statements with parenthesis
    # doesn't really work unless we filter off typecasts
    #if($l =~ /(.*)return \(/) {
    #    checkwarn($line, length($1)+6, $file, $l, "return with paretheses");
    #}

    # check spaces after for/if/while
    if($l =~ /^(.*)(for|if|while) \(/) {
        if($1 =~ / *\#/) {
            # this is a #if, treat it differently
        }
        else {
            checkwarn($line, length($1)+length($2), $file, $l,
                      "$2 with space");
        }
    }
    # check for "} else"
    if($l =~ /^(.*)\} else/) {
        checkwarn($line, length($1), $file, $l, "else after closing brace on same line");
    }
    # check for open brace first on line but not first column
    # only alert if previous line ended with a close paren and wasn't a cpp
    # line
    if((($prevl =~ /\)\z/) && ($prevl !~ /^ *#/)) && ($l =~ /^( +)\{/)) {
        checkwarn($line, length($1), $file, $l, "badly placed open brace");
    }

    # if the previous line starts with if/while/for AND ends with an open
    # brace, check that this line is indented $indent more steps, if not
    # a cpp line
    if($prevl =~ /^( *)(if|while|for)\(.*\{\z/) {
        my $first = length($1);

        # this line has some character besides spaces
        if(($l !~ /^ *#/) && ($l =~ /^( *)[^ ]/)) {
            my $second = length($1);
            my $expect = $first+$indent;
            if($expect != $second) {
                my $diff = $second - $first;
                checkwarn($line, length($1), $file, $l,
                          "not indented $indent steps, uses $diff)");

            }
        }
    }

    # check for // letters, but skip them if a double quote or asterisk was
    # on the same line to avoid strings and comments. Not reliable.
    #if($l =~ /^([^\"*]*)\/\//) {
    #    checkwarn($line, length($1), $file, $l, "non-C89 compliant comment",
    #              1);
    #}

    $line++;
    $prevl = $l;
}

if(!$copyright) {
    checkwarn(1, 0, $file, "", "Missing copyright statement", 1);
}

close(R);

if($errors || $warnings) {
    exit 5; # return failure
}
