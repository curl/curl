#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2011 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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
my $verbose;
my %whitelist;

my %warnings = (
    'LONGLINE' =>         "Line longer than $max_column",
    'TABS' =>             'TAB characters not allowed',
    'TRAILINGSPACE' =>    'Trailing white space on the line',
    'CPPCOMMENTS' =>      '// comment detected',
    'SPACEBEFOREPAREN' => 'space before an open parenthesis',
    'SPACEAFTERPAREN'  => 'space after open parenthesis',
    'SPACEBEFORECLOSE' => 'space before a close parenthesis',
    'SPACEBEFORECOMMA' => 'space before a comma',
    'RETURNNOSPACE'    => 'return without space',
    'COMMANOSPACE'     => 'comma without following space',
    'BRACEELSE'        => '} else on the same line',
    'PARENBRACE'       => '){ without sufficient space',
    'SPACESEMILCOLON'  => 'space before semicolon',
    'BANNEDFUNC'       => 'a banned function was used',
    'FOPENMODE'        => 'fopen needs a macro for the mode string',
    'BRACEPOS'         => 'wrong position for an open brace',
    'INDENTATION'      => 'wrong start column for code',
    'COPYRIGHT'        => 'file missing a copyright statement',
    'BADCOMMAND'       => 'bad !checksrc! instruction',
    'UNUSEDIGNORE'     => 'a warning ignore was not used',
    'OPENCOMMENT'      => 'file ended with a /* comment still "open"',
    'ASTERISKSPACE'    => 'pointer declared with space after asterisk',
    'ASTERISKNOSPACE'  => 'pointer declared without space before asterisk',
    'ASSIGNWITHINCONDITION'  => 'assignment within conditional expression',
    'EQUALSNOSPACE'    => 'equals sign without following space',
    'NOSPACEEQUALS'    => 'equals sign without preceeding space',
    'SEMINOSPACE'      => 'semicolon without following space',
    'MULTISPACE'       => 'multiple spaces used when not suitable',
    );

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
    my ($name, $num, $col, $file, $line, $msg, $error) = @_;

    my $w=$error?"error":"warning";
    my $nowarn=0;

    #if(!$warnings{$name}) {
    #    print STDERR "Dev! there's no description for $name!\n";
    #}

    # checksrc.whitelist
    if($whitelist{$line}) {
        $nowarn = 1;
    }
    # !checksrc! controlled
    elsif($ignore{$name}) {
        $ignore{$name}--;
        $ignore_used{$name}++;
        $nowarn = 1;
        if(!$ignore{$name}) {
            # reached zero, enable again
            enable_warn($name, $line, $file, $l);
        }
    }

    if($nowarn) {
        $supressed++;
        if($w) {
            $swarnings++;
        }
        else {
            $serrors++;
        }
        return;
    }

    if($w) {
        $warnings++;
    }
    else {
        $errors++;
    }

    $col++;
    print "$file:$num:$col: $w: $msg ($name)\n";
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
    elsif($file =~ /^(-h|--help)/) {
        undef $file;
        last;
    }

    last;
}

if(!$file) {
    print "checksrc.pl [option] <file1> [file2] ...\n";
    print " Options:\n";
    print "  -D[DIR]   Directory to prepend file names\n";
    print "  -h        Show help output\n";
    print "  -W[file]  Whitelist the given file - ignore all its flaws\n";
    print "\nDetects and warns for these problems:\n";
    for(sort keys %warnings) {
        printf (" %-18s: %s\n", $_, $warnings{$_});
    }
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

sub checksrc_clear {
    undef %ignore;
    undef %ignore_set;
    undef @ignore_line;
}

sub checksrc_endoffile {
    my ($file) = @_;
    for(keys %ignore_set) {
        if($ignore_set{$_} && !$ignore_used{$_}) {
            checkwarn("UNUSEDIGNORE", $ignore_set{$_},
                      length($_)+11, $file,
                      $ignore_line[$ignore_set{$_}],
                      "Unused ignore: $_");
        }
    }
}

sub enable_warn {
    my ($what, $line, $file, $l) = @_;

    # switch it back on, but warn if not triggered!
    if(!$ignore_used{$what}) {
        checkwarn("UNUSEDIGNORE",
                  $line, length($what) + 11, $file, $l,
                  "No warning was inhibited!");
    }
    $ignore_set{$what}=0;
    $ignore_used{$what}=0;
    $ignore{$what}=0;
}
sub checksrc {
    my ($cmd, $line, $file, $l) = @_;
    if($cmd =~ / *([^ ]*) *(.*)/) {
        my ($enable, $what) = ($1, $2);
        $what =~ s: *\*/$::; # cut off end of C comment
        # print "ENABLE $enable WHAT $what\n";
        if($enable eq "disable") {
            my ($warn, $scope)=($1, $2);
            if($what =~ /([^ ]*) +(.*)/) {
                ($warn, $scope)=($1, $2);
            }
            else {
                $warn = $what;
                $scope = 1;
            }
            # print "IGNORE $warn for SCOPE $scope\n";
            if($scope eq "all") {
                $scope=999999;
            }

            if($ignore_set{$warn}) {
                checkwarn("BADCOMMAND",
                          $line, 0, $file, $l,
                          "$warn already disabled from line $ignore_set{$warn}");
            }
            else {
                $ignore{$warn}=$scope;
                $ignore_set{$warn}=$line;
                $ignore_line[$line]=$l;
            }
        }
        elsif($enable eq "enable") {
            enable_warn($what, $line, $file, $l);
        }
        else {
            checkwarn("BADCOMMAND",
                      $line, 0, $file, $l,
                      "Illegal !checksrc! command");
        }
    }
}

sub nostrings {
    my ($str) = @_;
    $str =~ s/\".*\"//g;
    return $str;
}

sub scanfile {
    my ($file) = @_;

    my $line = 1;
    my $prevl;
    my $l;
    open(R, "<$file") || die "failed to open $file";

    my $incomment=0;
    my $copyright=0;
    checksrc_clear(); # for file based ignores

    while(<R>) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        my $l = $_;
        my $ol = $l; # keep the unmodified line for error reporting
        my $column = 0;

        # check for !checksrc! commands
        if($l =~ /\!checksrc\! (.*)/) {
            my $cmd = $1;
            checksrc($cmd, $line, $file, $l)
        }

        # check for a copyright statement
        if(!$copyright && ($l =~ /copyright .* \d\d\d\d/i)) {
            $copyright=1;
        }

        # detect long lines
        if(length($l) > $max_column) {
            checkwarn("LONGLINE", $line, length($l), $file, $l,
                      "Longer than $max_column columns");
        }
        # detect TAB characters
        if($l =~ /^(.*)\t/) {
            checkwarn("TABS",
                      $line, length($1), $file, $l, "Contains TAB character", 1);
        }
        # detect trailing white space
        if($l =~ /^(.*)[ \t]+\z/) {
            checkwarn("TRAILINGSPACE",
                      $line, length($1), $file, $l, "Trailing whitespace");
        }

        # ------------------------------------------------------------
        # Above this marker, the checks were done on lines *including*
        # comments
        # ------------------------------------------------------------

        # strip off C89 comments

      comment:
        if(!$incomment) {
            if($l =~ s/\/\*.*\*\// /g) {
                # full /* comments */ were removed!
            }
            if($l =~ s/\/\*.*//) {
                # start of /* comment was removed
                $incomment = 1;
            }
        }
        else {
            if($l =~ s/.*\*\///) {
                # end of comment */ was removed
                $incomment = 0;
                goto comment;
            }
            else {
                # still within a comment
                $l="";
            }
        }

        # ------------------------------------------------------------
        # Below this marker, the checks were done on lines *without*
        # comments
        # ------------------------------------------------------------

        # crude attempt to detect // comments without too many false
        # positives
        if($l =~ /^([^"\*]*)[^:"]\/\//) {
            checkwarn("CPPCOMMENTS",
                      $line, length($1), $file, $l, "\/\/ comment");
        }

        my $nostr = nostrings($l);
        # check spaces after for/if/while/function call
        if($nostr =~ /^(.*)(for|if|while| ([a-zA-Z0-9_]+)) \((.)/) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            elsif($3 eq "return") {
                # return must have a space
            }
            elsif($3 eq "case") {
                # case must have a space
            }
            elsif($4 eq "*") {
                # (* beginning makes the space OK!
            }
            elsif($1 =~ / *typedef/) {
                # typedefs can use space-paren
            }
            else {
                checkwarn("SPACEBEFOREPAREN", $line, length($1)+length($2), $file, $l,
                          "$2 with space");
            }
        }

        if($nostr =~ /^((.*)(if) *\()(.*)\)/) {
            my $pos = length($1);
            if($4 =~ / = /) {
                checkwarn("ASSIGNWITHINCONDITION",
                          $line, $pos+1, $file, $l,
                          "assignment within conditional expression");
            }
        }
        # check spaces after open parentheses
        if($l =~ /^(.*[a-z])\( /i) {
            checkwarn("SPACEAFTERPAREN",
                      $line, length($1)+1, $file, $l,
                      "space after open parenthesis");
        }

        # check spaces before close parentheses, unless it was a space or a
        # close parenthesis!
        if($l =~ /(.*[^\) ]) \)/) {
            checkwarn("SPACEBEFORECLOSE",
                      $line, length($1)+1, $file, $l,
                      "space before close parenthesis");
        }

        # check spaces before comma!
        if($l =~ /(.*[^ ]) ,/) {
            checkwarn("SPACEBEFORECOMMA",
                      $line, length($1)+1, $file, $l,
                      "space before comma");
        }

        # check for "return(" without space
        if($l =~ /^(.*)return\(/) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            else {
                checkwarn("RETURNNOSPACE", $line, length($1)+6, $file, $l,
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
                checkwarn("COMMANOSPACE", $line, length($pref)+1, $file, $l,
                          "comma without following space");
            }
        }

        # check for "} else"
        if($l =~ /^(.*)\} *else/) {
            checkwarn("BRACEELSE",
                      $line, length($1), $file, $l, "else after closing brace on same line");
        }
        # check for "){"
        if($l =~ /^(.*)\)\{/) {
            checkwarn("PARENBRACE",
                      $line, length($1)+1, $file, $l, "missing space after close paren");
        }

        # check for space before the semicolon last in a line
        if($l =~ /^(.*[^ ].*) ;$/) {
            checkwarn("SPACESEMILCOLON",
                      $line, length($1), $file, $ol, "space before last semicolon");
        }

        # scan for use of banned functions
        if($l =~ /^(.*\W)
                   (gets|
	            strtok|
                    v?sprintf|
                    (str|_mbs|_tcs|_wcs)n?cat|
                    LoadLibrary(Ex)?(A|W)?)
                   \s*\(
                 /x) {
            checkwarn("BANNEDFUNC",
                      $line, length($1), $file, $ol,
                      "use of $2 is banned");
        }

        # scan for use of non-binary fopen without the macro
        if($l =~ /^(.*\W)fopen\s*\([^,]*, *\"([^"]*)/) {
            my $mode = $2;
            if($mode !~ /b/) {
                checkwarn("FOPENMODE",
                          $line, length($1), $file, $ol,
                          "use of non-binary fopen without FOPEN_* macro: $mode");
            }
        }

        # check for open brace first on line but not first column
        # only alert if previous line ended with a close paren and wasn't a cpp
        # line
        if((($prevl =~ /\)\z/) && ($prevl !~ /^ *#/)) && ($l =~ /^( +)\{/)) {
            checkwarn("BRACEPOS",
                      $line, length($1), $file, $ol, "badly placed open brace");
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
                    checkwarn("INDENTATION", $line, length($1), $file, $ol,
                              "not indented $indent steps, uses $diff)");

                }
            }
        }

        # check for 'char * name'
        if(($l =~ /(^.*(char|int|long|void|curl_slist|CURL|CURLM|CURLMsg|curl_httppost) *(\*+)) (\w+)/) && ($4 ne "const")) {
            checkwarn("ASTERISKNOSPACE",
                      $line, length($1), $file, $ol,
                      "no space after declarative asterisk");
        }
        # check for 'char*'
        if(($l =~ /(^.*(char|int|long|void|curl_slist|CURL|CURLM|CURLMsg|curl_httppost|sockaddr_in|FILE)\*)/)) {
            checkwarn("ASTERISKNOSPACE",
                      $line, length($1)-1, $file, $ol,
                      "no space before asterisk");
        }

        # check for 'void func() {', but avoid false positives by requiring
        # both an open and closed parentheses before the open brace
        if($l =~ /^((\w).*)\{\z/) {
            my $k = $1;
            $k =~ s/const *//;
            $k =~ s/static *//;
            if($k =~ /\(.*\)/) {
                checkwarn("BRACEPOS",
                          $line, length($l)-1, $file, $ol,
                          "wrongly placed open brace");
            }
        }

        # check for equals sign without spaces next to it
        if($nostr =~ /(.*)\=[a-z0-9]/i) {
            checkwarn("EQUALSNOSPACE",
                      $line, length($1)+1, $file, $ol,
                      "no space after equals sign");
        }
        # check for equals sign without spaces before it
        elsif($nostr =~ /(.*)[a-z0-9]\=/i) {
            checkwarn("NOSPACEEQUALS",
                      $line, length($1)+1, $file, $ol,
                      "no space before equals sign");
        }

        # check for plus signs without spaces next to it
        if($nostr =~ /(.*)[^+]\+[a-z0-9]/i) {
            checkwarn("PLUSNOSPACE",
                      $line, length($1)+1, $file, $ol,
                      "no space after plus sign");
        }
        # check for plus sign without spaces before it
        elsif($nostr =~ /(.*)[a-z0-9]\+[^+]/i) {
            checkwarn("NOSPACEPLUS",
                      $line, length($1)+1, $file, $ol,
                      "no space before plus sign");
        }

        # check for semicolons without space next to it
        if($nostr =~ /(.*)\;[a-z0-9]/i) {
            checkwarn("SEMINOSPACE",
                      $line, length($1)+1, $file, $ol,
                      "no space after semilcolon");
        }

        # check for more than one consecutive space before open brace or
        # question mark. Skip lines containing strings since they make it hard
        # due to artificially getting multiple spaces
        if(($l eq $nostr) &&
           $nostr =~ /^(.*(\S)) + [{?]/i) {
            checkwarn("MULTISPACE",
                      $line, length($1)+1, $file, $ol,
                      "multiple space");
            print STDERR "L: $l\n";
            print STDERR "nostr: $nostr\n";
        }

        $line++;
        $prevl = $ol;
    }

    if(!$copyright) {
        checkwarn("COPYRIGHT", 1, 0, $file, "", "Missing copyright statement", 1);
    }
    if($incomment) {
        checkwarn("OPENCOMMENT", 1, 0, $file, "", "Missing closing comment", 1);
    }

    checksrc_endoffile($file);

    close(R);

}


if($errors || $warnings || $verbose) {
    printf "checksrc: %d errors and %d warnings\n", $errors, $warnings;
    if($supressed) {
        printf "checksrc: %d errors and %d warnings suppressed\n",
        $serrors,
        $swarnings;
    }
    exit 5; # return failure
}
