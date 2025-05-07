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
use Getopt::Long();
use Pod::Usage();

my $opts_dir = '../docs/cmdline-opts';
my $shell = 'zsh';
my $help = 0;
Getopt::Long::GetOptions(
    'opts-dir=s' => \$opts_dir,
    'shell=s' => \$shell,
    'help' => \$help,
) or Pod::Usage::pod2usage();
Pod::Usage::pod2usage() if $help;

my @opts = parse_main_opts($opts_dir);

if ($shell eq 'fish') {
    print "# curl fish completion\n\n";
    print "# Complete file paths after @\n";
    print q(complete -c curl -n 'string match -qr "^@" -- (commandline -ct)' -k -xa "(printf '%s\n' -- @(__fish_complete_suffix --complete=(commandline -ct | string replace -r '^@' '') ''))");
    print "\n\n";
    print qq{$_ \n} foreach (@opts);
} elsif ($shell eq 'zsh') {
    my $opts_str;

    $opts_str .= qq{  $_ \\\n} foreach (@opts);
    chomp $opts_str;

    my $tmpl = <<"EOS";
#compdef curl

# curl zsh completion

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
    my ($opts_dir) = @_;

    my (@files, @list);
    my ($dir_handle, $file_content);

    opendir($dir_handle, $opts_dir) || die "Unable to open dir: $opts_dir due to error: $!";
    @files = readdir($dir_handle);
    closedir($dir_handle) || die "Unable to close handle on dir: $opts_dir due to error: $!";

    # We want regular files that end with .md and don't start with an underscore
    # Edge case: MANPAGE.md doesn't start with an underscore but also isn't documentation for an option
    @files = grep { $_ =~ /\.md$/i && !/^_/ && -f "$opts_dir/$_" && $_ ne "MANPAGE.md" } @files;

    for my $file (@files) {
        open(my $doc_handle, '<', "$opts_dir/$file") || die "Unable to open file: $file due to error: $!";
        $file_content = join('', <$doc_handle>);
        close($doc_handle) || die "Unable to close file: $file due to error: $!";

        # Extract the curldown header section demarcated by ---
        $file_content =~ /^---\s*\n(.*?)\n---\s*\n/s || die "Unable to parse file $file";

        $file_content = $1;
        my ($short, $long, $arg, $desc);

        if ($file_content =~ /^Short:\s+(.*)\s*$/im) {$short = "-$1";}
        if ($file_content =~ /^Long:\s+(.*)\s*$/im) {$long = "--$1";}
        if ($file_content =~ /^Arg:\s+(.*)\s*$/im) {$arg = $1;}
        if ($file_content =~ /^Help:\s+(.*)\s*$/im) {$desc = $1;}

        $arg =~ s/\:/\\\:/g if defined $arg;
        $desc =~ s/'/'\\''/g if defined $desc;
        $desc =~ s/\[/\\\[/g if defined $desc;
        $desc =~ s/\]/\\\]/g if defined $desc;
        $desc =~ s/\:/\\\:/g if defined $desc;

        my $option = '';

        if ($shell eq 'fish') {
            $option .= "complete --command curl";
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

        push(@list, $option);
    }

    # Sort longest first, because zsh won't complete an option listed
    # after one that's a prefix of it. When length is equal, fall back
    # to stringwise cmp.
    @list = sort {
        $a =~ /([^=]*)/; my $ma = $1;
        $b =~ /([^=]*)/; my $mb = $1;

        length($mb) <=> length($ma) || $ma cmp $mb
    } @list;

    return @list;
}

sub trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };
sub strip_dash { my $s = shift; $s =~ s/^-+//g; return $s };

__END__

=head1 NAME

completion.pl - Generates tab-completion files for various shells

=head1 SYNOPSIS

completion.pl [options...]

    --opts-dir path to cmdline-opts directory
    --shell    zsh/fish
    --help     prints this help

=cut
