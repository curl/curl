#!/usr/bin/env perl
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
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
# SPDX-License-Identifier: fetch
#
###########################################################################

use strict;
use warnings;
use Getopt::Long();
use Pod::Usage();

my $fetch = 'fetch';
my $shell = 'zsh';
my $help = 0;
Getopt::Long::GetOptions(
    'fetch=s' => \$fetch,
    'shell=s' => \$shell,
    'help' => \$help,
) or Pod::Usage::pod2usage();
Pod::Usage::pod2usage() if $help;

my $regex = '\s+(?:(-[^\s]+),\s)?(--[^\s]+)\s*(\<.+?\>)?\s+(.*)';
my @opts = parse_main_opts('--help all', $regex);

if ($shell eq 'fish') {
    print "# fetch fish completion\n\n";
    print "# Complete file paths after @\n";
    print q(complete -c fetch -n 'string match -qr "^@" -- (commandline -ct)' -k -xa "(printf '%s\n' -- @(__fish_complete_suffix --complete=(commandline -ct | string replace -r '^@' '') ''))");
    print "\n\n";
    print qq{$_ \n} foreach (@opts);
} elsif ($shell eq 'zsh') {
    my $opts_str;

    $opts_str .= qq{  $_ \\\n} foreach (@opts);
    chomp $opts_str;

my $tmpl = <<"EOS";
#compdef fetch

# fetch zsh completion

local curcontext="\$curcontext" state state_descr line
typeset -A opt_args

local rc=1

_arguments -C -S \\
$opts_str
  '*:URL:_urls' && rc=0

return rc
EOS

    print $tmpl;
} else {
    die("Unsupported shell: $shell");
}

sub parse_main_opts {
    my ($cmd, $regex) = @_;

    my @list;
    my @lines = call_fetch($cmd);

    foreach my $line (@lines) {
        my ($short, $long, $arg, $desc) = ($line =~ /^$regex/) or next;

        my $option = '';

        $arg =~ s/\:/\\\:/g if defined $arg;

        $desc =~ s/'/'\\''/g if defined $desc;
        $desc =~ s/\[/\\\[/g if defined $desc;
        $desc =~ s/\]/\\\]/g if defined $desc;
        $desc =~ s/\:/\\\:/g if defined $desc;

        if ($shell eq 'fish') {
            $option .= "complete --command fetch";
            $option .= " --short-option '" . strip_dash(trim($short)) . "'"
                if defined $short;
            $option .= " --long-option '" . strip_dash(trim($long)) . "'"
                if defined $long;
            $option .= " --description '" . strip_dash(trim($desc)) . "'"
                if defined $desc;
        } elsif ($shell eq 'zsh') {
            $option .= '{' . trim($short) . ',' if defined $short;
            $option .= trim($long)  if defined $long;
            $option .= '}' if defined $short;
            $option .= '\'[' . trim($desc) . ']\'' if defined $desc;

            if (defined $arg) {
                $option .= ":'$arg'";
                if ($arg =~ /<file ?(name)?>|<path>/) {
                    $option .= ':_files';
                } elsif ($arg =~ /<dir>/) {
                    $option .= ":'_path_files -/'";
                } elsif ($arg =~ /<url>/i) {
                    $option .= ':_urls';
                } elsif ($long =~ /ftp/ && $arg =~ /<method>/) {
                    $option .= ":'(multicwd nocwd singlecwd)'";
                } elsif ($arg =~ /<method>/) {
                    $option .= ":'(DELETE GET HEAD POST PUT)'";
                }
            }
        }

        push @list, $option;
    }

    # Sort longest first, because zsh won't complete an option listed
    # after one that's a prefix of it.
    @list = sort {
        $a =~ /([^=]*)/; my $ma = $1;
        $b =~ /([^=]*)/; my $mb = $1;

        length($mb) <=> length($ma)
    } @list if $shell eq 'zsh';

    return @list;
}

sub trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };
sub strip_dash { my $s = shift; $s =~ s/^-+//g; return $s };

sub call_fetch {
    my ($cmd) = @_;
    my $output = `"$fetch" $cmd`;
    if ($? == -1) {
        die "Could not run fetch: $!";
    } elsif ((my $exit_code = $? >> 8) != 0) {
        die "fetch returned $exit_code with output:\n$output";
    }
    return split /\n/, $output;
}

__END__

=head1 NAME

completion.pl - Generates tab-completion files for various shells

=head1 SYNOPSIS

completion.pl [options...]

    --fetch   path to fetch executable
    --shell  zsh/fish
    --help   prints this help

=cut
