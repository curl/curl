#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#
# Invoke script in the root of the git checkout. Scans all files in git unless
# given a specific single file.
#
# Usage: copyright.pl [file]
#

# regexes of files to not scan
my @skiplist=(
    '^tests\/data\/test(\d+)$', # test case data
    '^docs\/cmdline-opts\/[a-z]+(.*)\.d$', # curl.1 pieces
    '(\/|^)[A-Z0-9_.-]+$', # all uppercase file name, possibly with dot and dash
    '(\/|^)[A-Z0-9_-]+\.md$', # all uppercase file name with .md extension
    '.gitignore', # wherever they are
    '.gitattributes', # wherever they are
    '^tests/certs/.*', # generated certs
    '^tests/stunnel.pem', # generated cert
    '^tests/valgrind.supp', # valgrind suppressions
    '^projects/Windows/.*.dsw$', # generated MSVC file
    '^projects/Windows/.*.sln$', # generated MSVC file
    '^projects/Windows/.*.tmpl$', # generated MSVC file
    '^projects/Windows/.*.vcxproj.filters$', # generated MSVC file
    '^m4/ax_compile_check_sizeof.m4$', # imported, leave be
    '^.mailmap', # git control file
    '^winbuild/BUILD.WINDOWS.txt$', # instructions
    '\/readme',
    '^.github/', # github instruction files
    '^.dcignore', # deepcode.ai instruction file
    '^.muse/', # muse-CI control files

    # docs/ files we're okay with without copyright
    'INSTALL.cmake',
    'TheArtOfHttpScripting',
    'page-footer',
    'curl_multi_socket_all.3',
    'curl_strnequal.3',
    'symbols-in-versions',
    'options-in-versions',

    # macos-framework files
    '^lib\/libcurl.plist',
    '^lib\/libcurl.vers.in',

    # symbian build files we know little about
    '^packages\/Symbian\/bwins\/libcurlu.def',
    '^packages\/Symbian\/eabi\/libcurlu.def',
    '^packages\/Symbian\/group\/bld.inf',
    '^packages\/Symbian\/group\/curl.iby',
    '^packages\/Symbian\/group\/curl.mmp',
    '^packages\/Symbian\/group\/curl.pkg',
    '^packages\/Symbian\/group\/libcurl.iby',
    '^packages\/Symbian\/group\/libcurl.mmp',
    '^packages\/Symbian\/group\/libcurl.pkg',

    # vms files
    '^packages\/vms\/build_vms.com',
    '^packages\/vms\/curl_release_note_start.txt',
    '^packages\/vms\/curlmsg.sdl',
    '^packages\/vms\/macro32_exactcase.patch',

    # XML junk
    '^projects\/wolfssl_override.props',

    # macos framework generated files
    '^src\/macos\/curl.mcp.xml.sit.hqx',
    '^src\/macos\/src\/curl_GUSIConfig.cpp',

    # checksrc control files
    '\.checksrc$',

    );

sub scanfile {
    my ($f) = @_;
    my $line=1;
    my $found = 0;
    open(F, "<$f") ||
        print ERROR "can't open $f\n";
    while (<F>) {
        chomp;
        my $l = $_;
        # check for a copyright statement and save the years
        if($l =~ /.* +copyright .* *\d\d\d\d/i) {
            while($l =~ /([\d]{4})/g) {
                push @copyright, {
                  year => $1,
                  line => $line,
                  col => index($l, $1),
                  code => $l
                };
                $found++;
            }
        }
        # allow within the first 100 lines
        if(++$line > 100) {
            last;
        }
    }
    close(F);
    return $found;
}

sub checkfile {
    my ($file) = @_;
    my $fine = 0;
    @copyright=();
    my $found = scanfile($file);

    if(!$found) {
        print "$file: missing copyright range\n";
        return 2;
    }

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
        print "$file: copyright year out of date, should be $commityear, " .
            "is $copyright[0]{year}\n";
    }
    else {
        $fine = 1;
    }
    return $fine;
}

my @all;
if($ARGV[0]) {
    push @all, $ARGV[0];
}
else {
    @all = `git ls-files`;
}
for my $f (@all) {
    chomp $f;
    my $skipped = 0;
    for my $skip (@skiplist) {
        #print "$f matches $skip ?\n";
        if($f =~ /$skip/) {
            $skiplisted++;
            $skipped = 1;
            #print "$f: SKIPPED ($skip)\n";
            last;
        }
    }
    if(!$skipped) {
        my $r = checkfile($f);
        $missing++ if($r == 2);
        $wrong++ if(!$r);
    }
}

print STDERR "$missing files have no copyright\n" if($missing);
print STDERR "$wrong files have wrong copyright year\n" if ($wrong);
print STDERR "$skiplisted files are skipped\n" if ($skiplisted);

exit 1 if($missing || $wrong);
