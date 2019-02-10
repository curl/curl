#!/usr/bin/env perl

# Generate ZSH or FISH completion
# Usage: zsh.pl [path to curl] [fish|zsh]

use strict;
use warnings;

my $curl = $ARGV[0] || 'curl';
my $shell = $ARGV[1] || 'zsh';  # zsh or fish

my $regex = '\s+(?:(-[^\s]+),\s)?(--[^\s]+)\s*(\<.+?\>)?\s+(.*)';
my @opts = parse_main_opts('--help', $regex);

if ($shell eq 'fish') {
    print "# curl fish completion\n\n";
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
}

sub parse_main_opts {
    my ($cmd, $regex) = @_;

    my @list;
    my @lines = call_curl($cmd);

    foreach my $line (@lines) {
        my ($short, $long, $arg, $desc) = ($line =~ /^$regex/) or next;

        my $option = '';

        $arg =~ s/\:/\\\:/g if defined $arg;

        $desc =~ s/'/'\\''/g if defined $desc;
        $desc =~ s/\[/\\\[/g if defined $desc;
        $desc =~ s/\]/\\\]/g if defined $desc;
        $desc =~ s/\:/\\\:/g if defined $desc;

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

            $option .= ":'$arg'" if defined $arg;

            $option .= ':_files'
                if defined $arg and ($arg eq '<file>' || $arg eq '<filename>'
                    || $arg eq '<dir>');
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

sub call_curl {
    my ($cmd) = @_;
    my $output = `"$curl" $cmd`;
    if ($? == -1) {
        die "Could not run curl: $!";
    } elsif ((my $exit_code = $? >> 8) != 0) {
        die "curl returned $exit_code with output:\n$output";
    }
    return split /\n/, $output;
}
