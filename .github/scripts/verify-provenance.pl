#!/usr/bin/env perl
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

# Check maketgz provenance against its source checkout and release files.

use strict;
use warnings;
use JSON::PP ();
use Digest::SHA ();
use MIME::Base64 qw(decode_base64);
use Getopt::Long qw(GetOptions);

sub read_file {
    my ($file) = @_;
    open(my $fh, '<:raw', $file) or die "Cannot read $file: $!\n";
    my $content = do { local $/; <$fh> };
    close($fh) or die "Cannot close $file: $!\n";
    return $content;
}

sub sha256_file {
    my ($file) = @_;
    open(my $fh, '<:raw', $file) or die "Cannot read $file: $!\n";
    my $digest = Digest::SHA->new(256)->addfile($fh)->hexdigest;
    close($fh) or die "Cannot close $file: $!\n";
    return $digest;
}

sub command_output {
    my (@command) = @_;
    open(my $fh, '-|', @command) or die "Cannot run @command: $!\n";
    my $output = do { local $/; <$fh> };
    close($fh) or die "Command failed: @command\n";
    return $output;
}

sub check_equal {
    my ($actual, $expected, $field) = @_;
    die "Unexpected $field: expected '$expected'\n"
        unless defined($actual) && $actual eq $expected;
}

my $usage = "Usage: verify-provenance.pl VERSION EPOCH [--mode MODE]\n";
my $mode = '';
GetOptions('mode=s' => \$mode) or die $usage;
die $usage unless @ARGV == 2;
my ($version, $epoch) = @ARGV;

my $provenance = "curl-$version.intoto.jsonl";
my $data = read_file($provenance);
die "Expected one JSON Lines record in $provenance\n"
    unless $data =~ /\A[^\n]+\n\z/;
my $json = JSON::PP->new->canonical->utf8;
my $statement = $json->decode($data);

check_equal($statement->{_type}, 'https://in-toto.io/Statement/v1',
            'statement type');
check_equal($statement->{predicateType}, 'https://slsa.dev/provenance/v1',
            'predicate type');

my $definition = $statement->{predicate}{buildDefinition};
my $details = $statement->{predicate}{runDetails};
my $format = 'https://github.com/curl/curl/blob/master/docs/PROVENANCE.md';
check_equal($definition->{buildType}, "$format#maketgz-v1", 'build type');
check_equal($details->{builder}{id}, "$format#local-builder-v1", 'builder');

# Compare the complete object, including the types of the parameter values.
my $parameters = {
    version => $version,
    mode => $mode,
    sourceDateEpoch => $epoch,
};
check_equal($json->encode($definition->{externalParameters}),
            $json->encode($parameters), 'build parameters');

my $commit = command_output('git', 'rev-parse', 'HEAD');
chomp($commit);
check_equal($definition->{resolvedDependencies}[0]{digest}{gitCommit},
            $commit, 'source commit');

my @names = sort map { "curl-$version.$_" }
    ('tar.gz', 'tar.bz2', 'tar.xz', 'zip');
my $subjects = $statement->{subject};
die "Expected four archive subjects\n" unless @$subjects == @names;
my %digests = map { $_->{name} => $_->{digest}{sha256} } @$subjects;
die "Expected four distinct archive subjects\n" unless keys(%digests) == @names;

for my $name (@names) {
    die "Missing archive subject: $name\n" unless exists($digests{$name});
    check_equal($digests{$name}, sha256_file($name), "$name SHA-256 digest");

    # Listing archive entries also checks that each archive can be read.
    my @command = $name =~ /\.zip\z/ ?
        ('unzip', '-Z', '-1', $name) : ('tar', '-tf', $name);
    my $contents = command_output(@command);
    for my $path (split(/\n/, $contents)) {
        die "Provenance included in archive $name: $path\n"
            if $path =~ /\.intoto\.jsonl\z/;
    }
}

my $tools = $details->{byproducts}[0];
my $content = read_file('docs/RELEASE-TOOLS.md.dist');
check_equal(decode_base64($tools->{content}), $content, 'release-tool content');
check_equal($tools->{digest}{sha256}, Digest::SHA::sha256_hex($content),
            'release-tool SHA-256 digest');

print "Verified provenance: $provenance\n";
print "Source commit: $commit\n";
print "Build type: $definition->{buildType}\n";
print "Builder: $details->{builder}{id}\n";
print "Build parameters: ", $json->encode($parameters), "\n";
print "Archive SHA-256 digests:\n";
for my $name (@names) {
    print "  $name: $digests{$name}\n";
}
print "Release-tool metadata:\n";
$content =~ s/\s+\z//;
print "$content\n";
