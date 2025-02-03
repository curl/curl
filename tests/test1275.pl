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

my $root=$ARGV[0] || "..";

my @m = `git ls-files -- $root`;

my $errors;

my %accepted=('fetch' => 1,
              'libfetch' => 1,
              'macOS' => 1,
              'wolfSSL' => 1,
              'mbedTLS' => 1,
              'rustls' => 1,
              'c-ares' => 1);

sub checkfile {
    my ($f) = @_;
    chomp $f;
    if($f !~ /\.md\z/) {
        return;
    }
    open(my $fh, "<", "$f");
    my $l;
    my $prevl;
    my $ignore = 0;
    my $metadata = 0;
    while(<$fh>) {
        my $line = $_;
        chomp $line;
        $l++;
        if(($l == 1) && ($line =~ /^---/)) {
            # first line is a meta-data divider, skip to the next one
            $metadata = 1;
            next;
        }
        elsif($metadata) {
            if($line !~ /^---/) {
                next;
            }
            $metadata = 0;
            next;
        }
        if($line =~ /^(\`\`\`|\~\~\~)/) {
            # start or stop ignore-mode
            $ignore ^= 1;
        }
        if(!$ignore) {
            if(($prevl =~ /\.\z/) && ($line =~ /^( *)([a-z][A-Za-z-]*)/)) {
                my ($prefix, $word) = ($1, $2);
                if($word =~ /^[a-z]/ && !$accepted{$word}) {
                    my $c = length($prefix);
                    print STDERR
                        "$f:$l:$c:error: lowercase $word after period\n";
                    print STDERR "$line\n";
                    print STDERR ' ' x $c;
                    print STDERR "^\n";
                    $errors++;
                }
            }
            elsif($line =~ /^(.*)\. +([a-z-]+)/) {
                my ($prefix, $word) = ($1, $2);

                if(($prefix =~ /\.\.\z/) ||
                   ($prefix =~ /[0-9]\z/) ||
                   ($prefix =~ /e.g\z/) ||
                   ($prefix =~ /i.e\z/) ||
                   ($prefix =~ /E.g\z/) ||
                   ($prefix =~ /etc\z/) ||
                   ($word !~ /^[a-z]/) ||
                   $accepted{$word}) {
                }
                else {
                    my $c = length($prefix) + 2;
                    print STDERR
                        "$f:$l:$c:error: lowercase $word after period\n";
                    print STDERR "$line\n";
                    print STDERR ' ' x $c;
                    print STDERR "^\n";
                    $errors++;
                }
            }
        }
        $prevl = $line;
    }
    close($fh);
}


for my $f (@m) {
    checkfile($f);
}

if($errors) {
    exit 1;
}
print "ok\n";
