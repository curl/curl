#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

use strict;
use warnings;
use JSON::PP ();
use Digest::SHA ();
use MIME::Base64 qw(encode_base64);
use File::Basename qw(basename);

# The caller captures the source revision before packaging modifies the tree.
my ($commit, $version, $mode, $epoch, $tools, @archives) = @ARGV;
die "Usage: make-provenance.pl COMMIT VERSION MODE EPOCH TOOLS ARCHIVE...\n"
    unless defined($tools) && @archives == 4;
die "Invalid source revision\n"
    unless $commit =~ /\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/;
die "Invalid source epoch\n" unless $epoch =~ /\A[0-9]+\z/;

sub sha256_file {
    my ($file) = @_;
    open(my $fh, '<:raw', $file) or die "Cannot read $file: $!\n";
    my $hash = Digest::SHA->new(256)->addfile($fh)->hexdigest;
    close($fh) or die "Cannot close $file: $!\n";
    return $hash;
}

open(my $tools_fh, '<:raw', $tools) or die "Cannot read $tools: $!\n";
my $tools_content = do { local $/; <$tools_fh> };
close($tools_fh) or die "Cannot close $tools: $!\n";

my $format = 'https://github.com/curl/curl/blob/master/docs/PROVENANCE.md';
my $statement = {
    _type => 'https://in-toto.io/Statement/v1',
    subject => [map {
        { name => basename($_), digest => { sha256 => sha256_file($_) } }
    } @archives],
    predicateType => 'https://slsa.dev/provenance/v1',
    predicate => {
        buildDefinition => {
            buildType => "$format#maketgz-v1",
            externalParameters => {
                version => $version,
                mode => $mode,
                sourceDateEpoch => $epoch,
            },
            resolvedDependencies => [{
                uri => 'git+https://github.com/curl/curl',
                digest => { gitCommit => $commit },
            }],
        },
        runDetails => {
            builder => { id => "$format#local-builder-v1" },
            byproducts => [{
                name => 'docs/RELEASE-TOOLS.md',
                mediaType => 'text/markdown',
                digest => { sha256 => sha256_file($tools) },
                content => encode_base64($tools_content, ''),
            }],
        },
    },
};

# Stable ordering and one JSON record, including proper string escaping.
print JSON::PP->new->canonical->utf8->encode($statement), "\n"
    or die "Cannot write provenance: $!\n";
close(STDOUT) or die "Cannot close provenance: $!\n";
