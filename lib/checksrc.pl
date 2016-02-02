#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2011 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

my $max_column = 79;
my $indent = 2;

my $warnings;
my $errors;
my $supressed; # whitelisted problems
my $file;
my $dir=".";
my $wlist;
my $windows_os = $^O eq 'MSWin32' || $^O eq 'msys' || $^O eq 'cygwin';

my %whitelist;

sub readwhitelist {
    open(W, "<$dir/checksrc.whitelist");
    my @all=<W>;
    for(@all) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        $whitelist{$_}=1;
    }
    close(W);
}

sub checkwarn {
    my ($num, $col, $file, $line, $msg, $error) = @_;

    if($whitelist{$line}) {
        $supressed++;
        return;
    }
    
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

$file = shift @ARGV;

while(1) {

    if($file =~ /-D(.*)/) {
        $dir = $1;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /-W(.*)/) {
        $wlist .= " $1 ";
        $file = shift @ARGV;
        next;
    }

    last;
}

if(!$file) {
    print "checksrc.pl [option] <file1> [file2] ...\n";
    print " Options:\n";
    print "  -D[DIR]   Directory to prepend file names\n";
    print "  -W[file]  Whitelist the given file - ignore all its flaws\n";
    exit;
}

readwhitelist();

do {
    if("$wlist" !~ / $file /) {
        my $fullname = $file;
        $fullname = "$dir/$file" if ($fullname !~ '^\.?\.?/');
        scanfile($fullname);
    }
    $file = shift @ARGV;

} while($file);


sub scanfile {
    my ($file) = @_;

    my $line = 1;
    my $prevl;
    my $l;
    open(R, "<$file") || die "failed to open $file";

    my $copyright=0;

    while(<R>) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
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
        if($l =~ /^(.*)[ \t]+\z/) {
            checkwarn($line, length($1), $file, $l, "Trailing whitespace");
        }

        # crude attempt to detect // comments without too many false
        # positives
        if($l =~ /^([^"\*]*)[^:"]\/\//) {
            checkwarn($line, length($1), $file, $l, "\/\/ comment");
        }
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

        # check spaces after open paren after for/if/while
        if($l =~ /^(.*)(for|if|while)\( /) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            else {
                checkwarn($line, length($1)+length($2)+1, $file, $l,
                          "$2 with space first in condition");
            }
        }

        # check for "return(" without space
        if($l =~ /^(.*)return\(/) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            else {
                checkwarn($line, length($1)+6, $file, $l,
                          "return without space before paren");
            }
        }

        # check for comma without space
        if($l =~ /^(.*),[^ \n]/) {
            my $pref=$1;
            my $ign=0;
            if($pref =~ / *\#/) {
                # this is a #if, treat it differently
                $ign=1;
            }
            elsif($pref =~ /\/\*/) {
                # this is a comment
                $ign=1;
            }
            elsif($pref =~ /[\"\']/) {
                $ign = 1;
                # There is a quote here, figure out whether the comma is
                # within a string or '' or not.
                if($pref =~ /\"/) {
                    # withing a string
                }
                elsif($pref =~ /\'$/) {
                    # a single letter
                }
                else {
                    $ign = 0;
                }
            }
            if(!$ign) {
                checkwarn($line, length($pref)+1, $file, $l,
                          "comma without following space");
            }
        }
        
        # check for "} else"
        if($l =~ /^(.*)\} *else/) {
            checkwarn($line, length($1), $file, $l, "else after closing brace on same line");
        }
        # check for "){"
        if($l =~ /^(.*)\)\{/) {
            checkwarn($line, length($1)+1, $file, $l, "missing space after close paren");
        }

        # check for space before the semicolon last in a line
        if($l =~ /^(.*[^ ].*) ;$/) {
            checkwarn($line, length($1), $file, $l, "space before last semicolon");
        }

        # scan for use of banned functions
        if($l =~ /^(.*\W)(sprintf|vsprintf|strcat|strncat|gets)\s*\(/) {
            checkwarn($line, length($1), $file, $l,
                      "use of $2 is banned");
        }

        # scan for use of non-binary fopen without the macro
        if($l =~ /^(.*\W)fopen\s*\([^"]*\"([^"]*)/) {
            my $mode = $2;
            if($mode !~ /b/) {
                checkwarn($line, length($1), $file, $l,
                          "use of non-binary fopen without FOPEN_* macro");
            }
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

        $line++;
        $prevl = $l;
    }

    if(!$copyright) {
        checkwarn(1, 0, $file, "", "Missing copyright statement", 1);
    }

    close(R);

}


if($errors || $warnings) {
    printf "checksrc: %d errors and %d warnings\n", $errors, $warnings;
    exit 5; # return failure
}
