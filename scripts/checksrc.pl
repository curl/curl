#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2011 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

use strict;
use warnings;

my $max_column = 79;
my $indent = 2;

my $warnings = 0;
my $swarnings = 0;
my $errors = 0;
my $serrors = 0;
my $suppressed; # skipped problems
my $file;
my $dir=".";
my $wlist="";
my @alist;
my $windows_os = $^O eq 'MSWin32' || $^O eq 'cygwin' || $^O eq 'msys';
my $verbose;
my %skiplist;

my %ignore;
my %ignore_set;
my %ignore_used;
my @ignore_line;

my %warnings_extended = (
    'COPYRIGHTYEAR'    => 'copyright year incorrect',
    'STRERROR',        => 'strerror() detected',
    );

my %warnings = (
    'LONGLINE'         => "Line longer than $max_column",
    'TABS'             => 'TAB characters not allowed',
    'TRAILINGSPACE'    => 'Trailing whitespace on the line',
    'CPPCOMMENTS'      => '// comment detected',
    'SPACEBEFOREPAREN' => 'space before an open parenthesis',
    'SPACEAFTERPAREN'  => 'space after open parenthesis',
    'SPACEBEFORECLOSE' => 'space before a close parenthesis',
    'SPACEBEFORECOMMA' => 'space before a comma',
    'RETURNNOSPACE'    => 'return without space',
    'COMMANOSPACE'     => 'comma without following space',
    'BRACEELSE'        => '} else on the same line',
    'PARENBRACE'       => '){ without sufficient space',
    'SPACESEMICOLON'   => 'space before semicolon',
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
    'ASSIGNWITHINCONDITION' => 'assignment within conditional expression',
    'EQUALSNOSPACE'    => 'equals sign without following space',
    'NOSPACEEQUALS'    => 'equals sign without preceding space',
    'SEMINOSPACE'      => 'semicolon without following space',
    'MULTISPACE'       => 'multiple spaces used when not suitable',
    'SIZEOFNOPAREN'    => 'use of sizeof without parentheses',
    'SNPRINTF'         => 'use of snprintf',
    'ONELINECONDITION' => 'conditional block on the same line as the if()',
    'TYPEDEFSTRUCT'    => 'typedefed struct',
    'DOBRACE'          => 'A single space between do and open brace',
    'BRACEWHILE'       => 'A single space between open brace and while',
    'EXCLAMATIONSPACE' => 'Whitespace after exclamation mark in expression',
    'EMPTYLINEBRACE'   => 'Empty line before the open brace',
    'EQUALSNULL'       => 'if/while comparison with == NULL',
    'NOTEQUALSZERO',   => 'if/while comparison with != 0',
    );

sub readskiplist {
    open(W, "<$dir/checksrc.skip") or return;
    my @all=<W>;
    for(@all) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        $skiplist{$_}=1;
    }
    close(W);
}

# Reads the .checksrc in $dir for any extended warnings to enable locally.
# Currently there is no support for disabling warnings from the standard set,
# and since that's already handled via !checksrc! commands there is probably
# little use to add it.
sub readlocalfile {
    my $i = 0;

    open(my $rcfile, "<", "$dir/.checksrc") or return;

    while(<$rcfile>) {
        $i++;

        # Lines starting with '#' are considered comments
        if (/^\s*(#.*)/) {
            next;
        }
        elsif (/^\s*enable ([A-Z]+)$/) {
            if(!defined($warnings_extended{$1})) {
                print STDERR "invalid warning specified in .checksrc: \"$1\"\n";
                next;
            }
            $warnings{$1} = $warnings_extended{$1};
        }
        elsif (/^\s*disable ([A-Z]+)$/) {
            if(!defined($warnings{$1})) {
                print STDERR "invalid warning specified in .checksrc: \"$1\"\n";
                next;
            }
            # Accept-list
            push @alist, $1;
        }
        else {
            die "Invalid format in $dir/.checksrc on line $i\n";
        }
    }
    close($rcfile);
}

sub checkwarn {
    my ($name, $num, $col, $file, $line, $msg, $error) = @_;

    my $w=$error?"error":"warning";
    my $nowarn=0;

    #if(!$warnings{$name}) {
    #    print STDERR "Dev! there's no description for $name!\n";
    #}

    # checksrc.skip
    if($skiplist{$line}) {
        $nowarn = 1;
    }
    # !checksrc! controlled
    elsif($ignore{$name}) {
        $ignore{$name}--;
        $ignore_used{$name}++;
        $nowarn = 1;
        if(!$ignore{$name}) {
            # reached zero, enable again
            enable_warn($name, $num, $file, $line);
        }
    }

    if($nowarn) {
        $suppressed++;
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

while(defined $file) {

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
    elsif($file =~ /-A(.+)/) {
        push @alist, $1;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /-i([1-9])/) {
        $indent = $1 + 0;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /-m([0-9]+)/) {
        $max_column = $1 + 0;
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
    print "  -A[rule]  Accept this violation, can be used multiple times\n";
    print "  -D[DIR]   Directory to prepend file names\n";
    print "  -h        Show help output\n";
    print "  -W[file]  Skip the given file - ignore all its flaws\n";
    print "  -i<n>     Indent spaces. Default: 2\n";
    print "  -m<n>     Maximum line length. Default: 79\n";
    print "\nDetects and warns for these problems:\n";
    my @allw = keys %warnings;
    push @allw, keys %warnings_extended;
    for my $w (sort @allw) {
        if($warnings{$w}) {
            printf (" %-18s: %s\n", $w, $warnings{$w});
        }
        else {
            printf (" %-18s: %s[*]\n", $w, $warnings_extended{$w});
        }
    }
    print " [*] = disabled by default\n";
    exit;
}

readskiplist();
readlocalfile();

do {
    if("$wlist" !~ / $file /) {
        my $fullname = $file;
        $fullname = "$dir/$file" if ($fullname !~ '^\.?\.?/');
        scanfile($fullname);
    }
    $file = shift @ARGV;

} while($file);

sub accept_violations {
    for my $r (@alist) {
        if(!$warnings{$r}) {
            print "'$r' is not a warning to accept!\n";
            exit;
        }
        $ignore{$r}=999999;
        $ignore_used{$r}=0;
    }
}

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

            # Comparing for a literal zero rather than the scalar value zero
            # covers the case where $scope contains the ending '*' from the
            # comment. If we use a scalar comparison (==) we induce warnings
            # on non-scalar contents.
            if($scope eq "0") {
                checkwarn("BADCOMMAND",
                          $line, 0, $file, $l,
                          "Disable zero not supported, did you mean to enable?");
            }
            elsif($ignore_set{$warn}) {
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
    my $prevl="";
    my $prevpl="";
    my $l = "";
    my $prep = 0;
    my $prevp = 0;
    open(R, "<$file") || die "failed to open $file";

    my $incomment=0;
    my @copyright=();
    checksrc_clear(); # for file based ignores
    accept_violations();

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

        # check for a copyright statement and save the years
        if($l =~ /\* +copyright .* \d\d\d\d/i) {
            while($l =~ /([\d]{4})/g) {
                push @copyright, {
                  year => $1,
                  line => $line,
                  col => index($l, $1),
                  code => $l
                };
            }
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
        # detect trailing whitespace
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

        # prev line was a preprocessor **and** ended with a backslash
        if($prep && ($prevpl =~ /\\ *\z/)) {
            # this is still a preprocessor line
            $prep = 1;
            goto preproc;
        }
        $prep = 0;

        # crude attempt to detect // comments without too many false
        # positives
        if($l =~ /^(([^"\*]*)[^:"]|)\/\//) {
            checkwarn("CPPCOMMENTS",
                      $line, length($1), $file, $l, "\/\/ comment");
        }

        # detect and strip preprocessor directives
        if($l =~ /^[ \t]*\#/) {
            # preprocessor line
            $prep = 1;
            goto preproc;
        }

        my $nostr = nostrings($l);
        # check spaces after for/if/while/function call
        if($nostr =~ /^(.*)(for|if|while| ([a-zA-Z0-9_]+)) \((.)/) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            elsif(defined $3 && $3 eq "return") {
                # return must have a space
            }
            elsif(defined $3 && $3 eq "case") {
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
        # check for '== NULL' in if/while conditions but not if the thing on
        # the left of it is a function call
        if($nostr =~ /^(.*)(if|while)(\(.*?)([!=]= NULL|NULL [!=]=)/) {
            checkwarn("EQUALSNULL", $line,
                      length($1) + length($2) + length($3),
                      $file, $l, "we prefer !variable instead of \"== NULL\" comparisons");
        }

        # check for '!= 0' in if/while conditions but not if the thing on
        # the left of it is a function call
        if($nostr =~ /^(.*)(if|while)(\(.*[^)]) != 0[^x]/) {
            checkwarn("NOTEQUALSZERO", $line,
                      length($1) + length($2) + length($3),
                      $file, $l, "we prefer if(rc) instead of \"rc != 0\" comparisons");
        }

        # check spaces in 'do {'
        if($nostr =~ /^( *)do( *)\{/ && length($2) != 1) {
            checkwarn("DOBRACE", $line, length($1) + 2, $file, $l, "one space after do before brace");
        }
        # check spaces in 'do {'
        elsif($nostr =~ /^( *)\}( *)while/ && length($2) != 1) {
            checkwarn("BRACEWHILE", $line, length($1) + 2, $file, $l, "one space between brace and while");
        }
        if($nostr =~ /^((.*\s)(if) *\()(.*)\)(.*)/) {
            my $pos = length($1);
            my $postparen = $5;
            my $cond = $4;
            if($cond =~ / = /) {
                checkwarn("ASSIGNWITHINCONDITION",
                          $line, $pos+1, $file, $l,
                          "assignment within conditional expression");
            }
            my $temp = $cond;
            $temp =~ s/\(//g; # remove open parens
            my $openc = length($cond) - length($temp);

            $temp = $cond;
            $temp =~ s/\)//g; # remove close parens
            my $closec = length($cond) - length($temp);
            my $even = $openc == $closec;

            if($l =~ / *\#/) {
                # this is a #if, treat it differently
            }
            elsif($even && $postparen &&
               ($postparen !~ /^ *$/) && ($postparen !~ /^ *[,{&|\\]+/)) {
                checkwarn("ONELINECONDITION",
                          $line, length($l)-length($postparen), $file, $l,
                          "conditional block on the same line");
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

        # check for "sizeof" without parenthesis
        if(($l =~ /^(.*)sizeof *([ (])/) && ($2 ne "(")) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            else {
                checkwarn("SIZEOFNOPAREN", $line, length($1)+6, $file, $l,
                          "sizeof without parenthesis");
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
                    # within a string
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
        # check for "^{" with an empty line before it
        if(($l =~ /^\{/) && ($prevl =~ /^[ \t]*\z/)) {
            checkwarn("EMPTYLINEBRACE",
                      $line, 0, $file, $l, "empty line before open brace");
        }

        # check for space before the semicolon last in a line
        if($l =~ /^(.*[^ ].*) ;$/) {
            checkwarn("SPACESEMICOLON",
                      $line, length($1), $file, $ol, "no space before semicolon");
        }

        # scan for use of banned functions
        if($l =~ /^(.*\W)
                   (gmtime|localtime|
                    gets|
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
        if($warnings{"STRERROR"}) {
            # scan for use of banned strerror. This is not a BANNEDFUNC to
            # allow for individual enable/disable of this warning.
            if($l =~ /^(.*\W)(strerror)\s*\(/x) {
                if($1 !~ /^ *\#/) {
                    # skip preprocessor lines
                    checkwarn("STRERROR",
                              $line, length($1), $file, $ol,
                              "use of $2 is banned");
                }
            }
        }
        # scan for use of snprintf for curl-internals reasons
        if($l =~ /^(.*\W)(v?snprintf)\s*\(/x) {
            checkwarn("SNPRINTF",
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

        # check for open brace first on line but not first column only alert
        # if previous line ended with a close paren and it wasn't a cpp line
        if(($prevl =~ /\)\z/) && ($l =~ /^( +)\{/) && !$prevp) {
            checkwarn("BRACEPOS",
                      $line, length($1), $file, $ol, "badly placed open brace");
        }

        # if the previous line starts with if/while/for AND ends with an open
        # brace, or an else statement, check that this line is indented $indent
        # more steps, if not a cpp line
        if(!$prevp && ($prevl =~ /^( *)((if|while|for)\(.*\{|else)\z/)) {
            my $first = length($1);
            # this line has some character besides spaces
            if($l =~ /^( *)[^ ]/) {
                my $second = length($1);
                my $expect = $first+$indent;
                if($expect != $second) {
                    my $diff = $second - $first;
                    checkwarn("INDENTATION", $line, length($1), $file, $ol,
                              "not indented $indent steps (uses $diff)");

                }
            }
        }

        # check for 'char * name'
        if(($l =~ /(^.*(char|int|long|void|CURL|CURLM|CURLMsg|[cC]url_[A-Za-z_]+|struct [a-zA-Z_]+) *(\*+)) (\w+)/) && ($4 !~ /^(const|volatile)$/)) {
            checkwarn("ASTERISKSPACE",
                      $line, length($1), $file, $ol,
                      "space after declarative asterisk");
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
                      "no space after semicolon");
        }

        # typedef struct ... {
        if($nostr =~ /^(.*)typedef struct.*{/) {
            checkwarn("TYPEDEFSTRUCT",
                      $line, length($1)+1, $file, $ol,
                      "typedef'ed struct");
        }

        if($nostr =~ /(.*)! +(\w|\()/) {
            checkwarn("EXCLAMATIONSPACE",
                      $line, length($1)+1, $file, $ol,
                      "space after exclamation mark");
        }

        # check for more than one consecutive space before open brace or
        # question mark. Skip lines containing strings since they make it hard
        # due to artificially getting multiple spaces
        if(($l eq $nostr) &&
           $nostr =~ /^(.*(\S)) + [{?]/i) {
            checkwarn("MULTISPACE",
                      $line, length($1)+1, $file, $ol,
                      "multiple spaces");
        }
      preproc:
        $line++;
        $prevp = $prep;
        $prevl = $ol if(!$prep);
        $prevpl = $ol if($prep);
    }

    if(!scalar(@copyright)) {
        checkwarn("COPYRIGHT", 1, 0, $file, "", "Missing copyright statement", 1);
    }

    # COPYRIGHTYEAR is a extended warning so we must first see if it has been
    # enabled in .checksrc
    if(defined($warnings{"COPYRIGHTYEAR"})) {
        # The check for updated copyrightyear is overly complicated in order to
        # not punish current hacking for past sins. The copyright years are
        # right now a bit behind, so enforcing copyright year checking on all
        # files would cause hundreds of errors. Instead we only look at files
        # which are tracked in the Git repo and edited in the workdir, or
        # committed locally on the branch without being in upstream master.
        #
        # The simple and naive test is to simply check for the current year,
        # but updating the year even without an edit is against project policy
        # (and it would fail every file on January 1st).
        #
        # A rather more interesting, and correct, check would be to not test
        # only locally committed files but inspect all files wrt the year of
        # their last commit. Removing the `git rev-list origin/master..HEAD`
        # condition below will enforce copyright year checks against the year
        # the file was last committed (and thus edited to some degree).
        my $commityear = undef;
        @copyright = sort {$$b{year} cmp $$a{year}} @copyright;

        # if the file is modified, assume commit year this year
        if(`git status -s -- $file` =~ /^ [MARCU]/) {
            $commityear = (localtime(time))[5] + 1900;
        }
        else {
            # min-parents=1 to ignore wrong initial commit in truncated repos
            my $grl = `git rev-list --max-count=1 --min-parents=1 --timestamp HEAD -- $file`;
            if($grl) {
                chomp $grl;
                $commityear = (localtime((split(/ /, $grl))[0]))[5] + 1900;
            }
        }

        if(defined($commityear) && scalar(@copyright) &&
           $copyright[0]{year} != $commityear) {
            checkwarn("COPYRIGHTYEAR", $copyright[0]{line}, $copyright[0]{col},
                      $file, $copyright[0]{code},
                      "Copyright year out of date, should be $commityear, " .
                      "is $copyright[0]{year}", 1);
        }
    }

    if($incomment) {
        checkwarn("OPENCOMMENT", 1, 0, $file, "", "Missing closing comment", 1);
    }

    checksrc_endoffile($file);

    close(R);

}


if($errors || $warnings || $verbose) {
    printf "checksrc: %d errors and %d warnings\n", $errors, $warnings;
    if($suppressed) {
        printf "checksrc: %d errors and %d warnings suppressed\n",
        $serrors,
        $swarnings;
    }
    exit 5; # return failure
}
