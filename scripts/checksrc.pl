#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

my %banfunc = (
    "gmtime" => 1,
    "localtime" => 1,
    "gets" => 1,
    "strtok" => 1,
    "sprintf" => 1,
    "vsprintf" => 1,
    "strcat" => 1,
    "strncat" => 1,
    "_mbscat" => 1,
    "_mbsncat" => 1,
    "_tcscat" => 1,
    "_tcsncat" => 1,
    "_wcscat" => 1,
    "_wcsncat" => 1,
    "LoadLibrary" => 1,
    "LoadLibraryA" => 1,
    "LoadLibraryW" => 1,
    "LoadLibraryEx" => 1,
    "LoadLibraryExA" => 1,
    "LoadLibraryExW" => 1,
    "_waccess" => 1,
    "_access" => 1,
    "access" => 1,
    );

my %warnings_extended = (
    'COPYRIGHTYEAR'    => 'copyright year incorrect',
    'STDERR',          => 'stderr detected',
    );

my %warnings = (
    'ASSIGNWITHINCONDITION' => 'assignment within conditional expression',
    'ASTERISKNOSPACE'       => 'pointer declared without space before asterisk',
    'ASTERISKSPACE'         => 'pointer declared with space after asterisk',
    'BADCOMMAND'            => 'bad !checksrc! instruction',
    'BANNEDFUNC'            => 'a banned function was used',
    'BANNEDPREPROC'         => 'a banned symbol was used on a preprocessor line',
    'BRACEELSE'             => '} else on the same line',
    'BRACEPOS'              => 'wrong position for an open brace',
    'BRACEWHILE'            => 'A single space between open brace and while',
    'COMMANOSPACE'          => 'comma without following space',
    'COMMENTNOSPACEEND'     => 'no space before */',
    'COMMENTNOSPACESTART'   => 'no space following /*',
    'COPYRIGHT'             => 'file missing a copyright statement',
    'CPPCOMMENTS'           => '// comment detected',
    'DOBRACE'               => 'A single space between do and open brace',
    'EMPTYLINEBRACE'        => 'Empty line before the open brace',
    'EQUALSNOSPACE'         => 'equals sign without following space',
    'EQUALSNULL'            => 'if/while comparison with == NULL',
    'ERRNOVAR'              => 'use of bare errno define',
    'EXCLAMATIONSPACE'      => 'Whitespace after exclamation mark in expression',
    'FOPENMODE'             => 'fopen needs a macro for the mode string',
    'INCLUDEDUP',           => 'same file is included again',
    'INDENTATION'           => 'wrong start column for code',
    'LONGLINE'              => "Line longer than $max_column",
    'SPACEBEFORELABEL'      => 'labels not at the start of the line',
    'MULTISPACE'            => 'multiple spaces used when not suitable',
    'NOSPACEAND'            => 'missing space around Logical AND operator',
    'NOSPACEC'              => 'missing space around ternary colon operator',
    'NOSPACEEQUALS'         => 'equals sign without preceding space',
    'NOSPACEQ'              => 'missing space around ternary question mark operator',
    'NOSPACETHAN'           => 'missing space around less or greater than',
    'NOTEQUALSZERO',        => 'if/while comparison with != 0',
    'ONELINECONDITION'      => 'conditional block on the same line as the if()',
    'OPENCOMMENT'           => 'file ended with a /* comment still "open"',
    'PARENBRACE'            => '){ without sufficient space',
    'RETURNNOSPACE'         => 'return without space',
    'SEMINOSPACE'           => 'semicolon without following space',
    'SIZEOFNOPAREN'         => 'use of sizeof without parentheses',
    'SPACEAFTERPAREN'       => 'space after open parenthesis',
    'SPACEBEFORECLOSE'      => 'space before a close parenthesis',
    'SPACEBEFORECOMMA'      => 'space before a comma',
    'SPACEBEFOREPAREN'      => 'space before an open parenthesis',
    'SPACESEMICOLON'        => 'space before semicolon',
    'SPACESWITCHCOLON'      => 'space before colon of switch label',
    'TABS'                  => 'TAB characters not allowed',
    'TRAILINGSPACE'         => 'Trailing whitespace on the line',
    'TYPEDEFSTRUCT'         => 'typedefed struct',
    'UNUSEDIGNORE'          => 'a warning ignore was not used',
    );

sub readskiplist {
    open(my $W, '<', "$dir/checksrc.skip") or return;
    my @all=<$W>;
    for(@all) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        $skiplist{$_}=1;
    }
    close($W);
}

# Reads the .checksrc in $dir for any extended warnings to enable locally.
# Currently there is no support for disabling warnings from the standard set,
# and since that's already handled via !checksrc! commands there is probably
# little use to add it.
sub readlocalfile {
    my ($file) = @_;
    my $i = 0;
    my $rcfile;

    if(($dir eq ".") && $file =~ /\//) {
        my $ldir;
        if($file =~ /(.*)\//) {
            $ldir = $1;
            open($rcfile, "<", "$dir/$ldir/.checksrc") or return;
        }
    }
    else {
        open($rcfile, "<", "$dir/.checksrc") or return;
    }

    while(<$rcfile>) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        $i++;

        # Lines starting with '#' are considered comments
        if (/^\s*(#.*)/) {
            next;
        }
        elsif (/^enable ([A-Z]+)$/) {
            if(!defined($warnings_extended{$1})) {
                print STDERR "invalid warning specified in .checksrc: \"$1\"\n";
                next;
            }
            $warnings{$1} = $warnings_extended{$1};
        }
        elsif (/^disable ([A-Z]+)$/) {
            if(!defined($warnings{$1})) {
                print STDERR "invalid warning specified in .checksrc: \"$1\"\n";
                next;
            }
            # Accept-list
            push @alist, $1;
        }
        elsif (/^banfunc ([^ ]*)/) {
            $banfunc{$1} = $1;
        }
        elsif (/^allowfunc ([^ ]*)/) {
            undef $banfunc{$1};
        }
        else {
            die "Invalid format in $dir/.checksrc on line $i: $_\n";
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

    if($file =~ /^-D(.*)/) {
        $dir = $1;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-W(.*)/) {
        $wlist .= " $1 ";
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-b(.*)/) {
        $banfunc{$1} = $1;
        print STDERR "ban use of \"$1\"\n";
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-a(.*)/) {
        undef $banfunc{$1};
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-A(.+)/) {
        push @alist, $1;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-i([1-9])/) {
        $indent = $1 + 0;
        $file = shift @ARGV;
        next;
    }
    elsif($file =~ /^-m([0-9]+)/) {
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
    print "  -a[func]  Allow use of this function\n";
    print "  -b[func]  Ban use of this function\n";
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

    print "\nDetects and bans use of these functions:\n";
    for my $f (sort keys %banfunc) {
        printf (" %-18s\n", $f);
    }
    exit;
}

readskiplist();
readlocalfile($file);

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
    open(my $R, '<', $file) || die "failed to open $file";

    my $incomment=0;
    my @copyright=();
    my %includes;
    checksrc_clear(); # for file based ignores
    accept_violations();

    while(<$R>) {
        $windows_os ? $_ =~ s/\r?\n$// : chomp;
        my $l = $_;
        my $ol = $l; # keep the unmodified line for error reporting
        my $column = 0;

        # check for !checksrc! commands
        if($l =~ /\!checksrc\! (.*)/) {
            my $cmd = $1;
            checksrc($cmd, $line, $file, $l)
        }

        if($l =~ /^#line (\d+) \"([^\"]*)\"/) {
            # a #line instruction
            $file = $2;
            $line = $1;
            next;
        }

        # check for a copyright statement and save the years
        if($l =~ /\* +copyright .* (\d\d\d\d|)/i) {
            my $count = 0;
            while($l =~ /([\d]{4})/g) {
                push @copyright, {
                  year => $1,
                  line => $line,
                  col => index($l, $1),
                  code => $l
                };
                $count++;
            }
            if(!$count) {
                # year-less
                push @copyright, {
                    year => -1,
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

        # no space after comment start
        if($l =~ /^(.*)\/\*\w/) {
            checkwarn("COMMENTNOSPACESTART",
                      $line, length($1) + 2, $file, $l,
                      "Missing space after comment start");
        }
        # no space at comment end
        if($l =~ /^(.*)\w\*\//) {
            checkwarn("COMMENTNOSPACEEND",
                      $line, length($1) + 1, $file, $l,
                      "Missing space end comment end");
        }

        if($l =~ /(.*)(FIXME|TODO)/) {
            checkwarn("FIXME",
                      $line, length($1), $file, $l,
                      "Avoid $2 comments. Add to documentation instead");
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

        if($l =~ /^(\#\s*include\s+)([\">].*[>}"])/) {
            my ($pre, $path) = ($1, $2);
            if($includes{$path}) {
                checkwarn("INCLUDEDUP",
                          $line, length($1), $file, $l, "duplicated include");
            }
            $includes{$path} = $l;
        }

        # detect and strip preprocessor directives
        if($l =~ /^[ \t]*\#/) {
            # preprocessor line
            $prep = 1;
            goto preproc;
        }

        my $nostr = nostrings($l);
        # check spaces after for/if/while/function call
        if($nostr =~ /^(.*)(for|if|while|switch| ([a-zA-Z0-9_]+)) \((.)/) {
            my ($leading, $word, $extra, $first)=($1,$2,$3,$4);
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            elsif(defined $3 && $3 eq "return") {
                # return must have a space
            }
            elsif(defined $3 && $3 eq "case") {
                # case must have a space
            }
            elsif(($first eq "*") && ($word !~ /(for|if|while|switch)/)) {
                # A "(*" beginning makes the space OK because it wants to
                # allow function pointer declared
            }
            elsif($1 =~ / *typedef/) {
                # typedefs can use space-paren
            }
            else {
                checkwarn("SPACEBEFOREPAREN", $line, length($leading)+length($word), $file, $l,
                          "$word with space");
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

        # check spaces before Logical AND operator
        if($nostr =~ /^(.*)\w&&/i) {
            checkwarn("NOSPACEAND",
                      $line, length($1)+1, $file, $l,
                      "missing space before Logical AND");
        }

        # check spaces after Logical AND operator
        if($nostr =~ /^(.*&&)\w/i) {
            checkwarn("NOSPACEAND",
                      $line, length($1), $file, $l,
                      "missing space after Logical AND");
        }

        # check spaces before colon
        if($nostr =~ /^(.*[^']\?[^'].*)(\w|\)|\]|')\:/i) {
            my $m = $1;
            my $e = $nostr;
            $e =~ s/'(.)':'(.)'/$1:$2/g; # eliminate chars quotes that surround colon
            $e =~ s/':'//g;              # ignore these
            if($e =~ /^(.*[^']\?[^'].*)(\w|\)|\]|')\:/i) {
                checkwarn("NOSPACEC",
                          $line, length($m)+1, $file, $l,
                          "missing space before colon");
            }
        }
        # check spaces after colon
        if($nostr =~ /^(.*[^'"]\?[^'"].*)\:(\w|\)|\]|')/i) {
            my $m = $1;
            my $e = $nostr;
            $e =~ s/'(.)':'(.)'/$1:$2/g; # eliminate chars quotes that surround colon
            $e =~ s/':'//g;              # ignore these
            if($e =~ /^(.*[^'"]\?[^'"].*)\:(\w|\)|\]|')/i) {
                checkwarn("NOSPACEC",
                          $line, length($m)+1, $file, $l,
                          "missing space after colon");
            }
        }

        # check spaces before question mark
        if($nostr =~ /^(.*)(\w|\)|\]|')\?/i) {
            my $m = $1;
            my $e = $nostr;
            $e =~ s/'?'//g; # ignore these
            if($e =~ /^(.*)(\w|\)|\]|')\?/i) {
                checkwarn("NOSPACEQ",
                          $line, length($m)+1, $file, $l,
                          "missing space before question mark");
            }
        }
        # check spaces after question mark
        if($nostr =~ /^(.*)\?\w/i) {
            checkwarn("NOSPACEQ",
                      $line, length($1)+1, $file, $l,
                      "missing space after question mark");
        }

        # check spaces before less or greater than
        if($nostr =~ /^(.*)(\w|\)|\])[<>]/) {
            checkwarn("NOSPACETHAN",
                      $line, length($1)+1, $file, $l,
                      "missing space before less or greater than");
        }
        # check spaces after less or greater than
        if($nostr =~ /^(.*)[^-][<>](\w|\(|\[)/) {
            checkwarn("NOSPACETHAN",
                      $line, length($1)+1, $file, $l,
                      "missing space after less or greater than");
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
        if($l =~ /^(.*\W)return\(/) {
            if($1 =~ / *\#/) {
                # this is a #if, treat it differently
            }
            else {
                checkwarn("RETURNNOSPACE", $line, length($1)+6, $file, $l,
                          "return without space before paren");
            }
        }

        # check for "return" with parentheses around just a value/name
        if($l =~ /^(.*\W)return \(\w*\);/) {
            checkwarn("RETURNPAREN", $line, length($1)+7, $file, $l,
                      "return with paren");
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

        # check for space before the colon in a switch label
        if($l =~ /^( *(case .+|default)) :/) {
            checkwarn("SPACESWITCHCOLON",
                      $line, length($1), $file, $ol, "no space before colon of switch label");
        }

        if($prevl !~ /\?\z/ && $l =~ /^ +([A-Za-z_][A-Za-z0-9_]*):$/ && $1 ne 'default') {
            checkwarn("SPACEBEFORELABEL",
                      $line, length($1), $file, $ol, "no space before label");
        }

        # scan for use of banned functions
        my $bl = $l;
      again:
        if(($l =~ /^(.*?\W)(\w+)(\s*\()/x) && $banfunc{$2}) {
            my $bad = $2;
            my $prefix = $1;
            my $suff = $3;
            checkwarn("BANNEDFUNC",
                      $line, length($prefix), $file, $ol,
                      "use of $bad is banned");
            my $replace = 'x' x (length($bad) + 1);
            $prefix =~ s/\*/\\*/;
            $suff =~ s/\(/\\(/;
            $l =~ s/$prefix$bad$suff/$prefix$replace/;
            goto again;
      }
        $l = $bl; # restore to pre-bannedfunc content

        if($warnings{"STDERR"}) {
            # scan for use of banned stderr. This is not a BANNEDFUNC to
            # allow for individual enable/disable of this warning.
            if($l =~ /^([^\"-]*\W)(stderr)[^\"_]/x) {
                if($1 !~ /^ *\#/) {
                    # skip preprocessor lines
                    checkwarn("STDERR",
                              $line, length($1), $file, $ol,
                              "use of $2 is banned (use tool_stderr instead)");
                }
            }
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

        # if the previous line starts with if/while/for AND ends with a closed
        # parenthesis and there's an equal number of open and closed
        # parentheses, check that this line is indented $indent more steps, if
        # not a cpp line
        elsif(!$prevp && ($prevl =~ /^( *)(if|while|for)(\(.*\))\z/)) {
            my $first = length($1);
            my $op = $3;
            my $cl = $3;

            $op =~ s/[^(]//g;
            $cl =~ s/[^)]//g;

            if(length($op) == length($cl)) {
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

        if($nostr =~ /(.*)\b(EACCES|EADDRINUSE|EADDRNOTAVAIL|EAFNOSUPPORT|EBADF|ECONNREFUSED|ECONNRESET|EINPROGRESS|EINTR|EINVAL|EISCONN|EMSGSIZE|ENOMEM|ETIMEDOUT|EWOULDBLOCK)\b/) {
            checkwarn("ERRNOVAR",
                      $line, length($1), $file, $ol,
                      "use of bare errno define $2, use SOCK$2");
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
        if($prep) {
          # scan for use of banned symbols on a preprocessor line
          if($l =~ /^(^|.*\W)
                     (WIN32)
                     (\W|$)
                   /x) {
              checkwarn("BANNEDPREPROC",
                        $line, length($1), $file, $ol,
                        "use of $2 is banned from preprocessor lines" .
                        (($2 eq "WIN32") ? ", use _WIN32 instead" : ""));
          }
        }
        $line++;
        $prevp = $prep;
        $prevl = $ol if(!$prep);
        $prevpl = $ol if($prep);
    }

    if(!scalar(@copyright)) {
        checkwarn("COPYRIGHT", 1, 0, $file, "", "Missing copyright statement", 1);
    }

    # COPYRIGHTYEAR is an extended warning so we must first see if it has been
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
        if(`git status -s -- "$file"` =~ /^ [MARCU]/) {
            $commityear = (localtime(time))[5] + 1900;
        }
        else {
            # min-parents=1 to ignore wrong initial commit in truncated repos
            my $grl = `git rev-list --max-count=1 --min-parents=1 --timestamp HEAD -- "$file"`;
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

    close($R);

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
