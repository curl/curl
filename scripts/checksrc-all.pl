#!/usr/bin/env perl
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

use strict;
use warnings;

use File::Basename;
use File::Find;
use Cwd 'abs_path';

my @files;
my $is_git = 0;
if(system('git rev-parse --is-inside-work-tree >/dev/null 2>&1') == 0) {
    @files = `git ls-files \"*.[ch]\"`;
    $is_git = 1;
}
else {
    find(sub { if(/\.[ch]$/) { push(@files, $File::Find::name) } }, ('.'));
}
if(@ARGV) {
    find(sub { if(/\.[ch]$/) { push(@files, $File::Find::name) } }, @ARGV);
}

@files = grep !/\/CMakeFiles\//, @files;
@files = grep !/tests\/data\/data.+\.c/, @files;
@files = map { dirname($_) } @files;
my @dirs = sort { $a cmp $b } keys %{{ map { $_ => 1 } @files }};

my $scripts_dir = dirname(abs_path($0));
my $anyfailed = 0;

for my $dir (@dirs) {
    if($is_git) {
        @files = `git ls-files \"$dir/*.[ch]\"`;
        chomp(@files);
    }
    else {
        @files = glob("$dir/*.[ch]");
    }
    if(@files && system("$scripts_dir/checksrc.pl", @files) != 0) {
        $anyfailed = 1;
    }
}

exit $anyfailed;
