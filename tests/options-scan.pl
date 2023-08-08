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
#
#
# - Get all options mentioned in the $cmddir.
# - Make sure they're all mentioned in the $opts document
# - Make usre that the version in $opts matches the version in the file in
#   $cmddir
#

my $opts = $ARGV[0];
my $cmddir = $ARGV[1];

sub cmdfiles {
    my ($dir)=@_;

    opendir(my $dh, $dir) || die "Can't opendir $dir: $!";
    my @opts = grep { /\.d$/ && -f "$dir/$_" } readdir($dh);
    closedir $dh;

    for(@opts) {
        $_ =~ s/\.d$//;
        $file{$_}=1;
    }
    return @opts;
}

sub mentions {
    my ($f) = @_;
    my @options;
    open(my $fh, "<", "$f");
    while(<$fh>) {
        chomp;
        if(/(.*) +([0-9.]+)/) {
            my ($flag, $version)=($1, $2);

            # store the name without the leading dashes
            $flag =~ s/^--//;

            # cut out short option (if present)
            $flag =~ s/ \(-.\)//;

            # store the name without trailing space
            $flag =~ s/ +$//;

            push @options, $flag;

            # options-in-versions says...
            $oiv{$flag} = $version;
        }
    }
    close($fh);
    return @options;
}

sub versioncheck {
    my ($f, $v)=@_;
    open(my $fh, "<", "$cmddir/$f.d");
    while(<$fh>) {
        chomp;
        if(/^Added: ([0-9.]+)/) {
            if($1 ne $v) {
                print STDERR "$f lists $v in doc but $1 in file\n";
                $error++;
            }
            last;
        }
    }
    close($fh);
}

# get all the files
my @cmdopts = cmdfiles($cmddir);

# get all the options mentioned in $o
my @veropts = mentions($opts);

# check if all files are in the doc
for my $c (sort @cmdopts) {
    if($oiv{$c}) {
        # present, but at same version?
        versioncheck($c, $oiv{$c});
    }
    else {
        print STDERR "--$c is in the option directory but not in $opts!\n";
        $error++;
    }
}

# check if the all options in the doc have files
for my $v (sort @veropts) {
    if($file{$v}) {
        # present
    }
    else {
        print STDERR "$v is in the doc but NOT as a file!\n";
        $error++;
    }
}

print STDERR "ok\n" if(!$error);

exit $error;
