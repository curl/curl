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

use Digest::SHA qw(hmac_sha1);
use MIME::Base64 qw(encode_base64);

sub errout {
    print $_[0] . "\n";
    exit 1;
}

if(@ARGV != 3) {
    errout "Usage: $0 host-public-key known-hosts-file target";
}

my ($hostkey_file, $knownhosts_file, $target) = @ARGV;
open(my $hostkey, "<", $hostkey_file) or errout "$!";
my $hostkey_line = <$hostkey>;
close($hostkey) or errout "$!";

my ($hostkey_algo, $hostkey_data) = split(/\s+/, $hostkey_line);
if(!$hostkey_algo || !$hostkey_data) {
    errout "Failed parsing SSH host public key";
}

my $rsa_key =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgSyqrUP2xhqLqkyopVapoKeucYIp" .
    "ZXeUqj+Q9WLWyXka5re62Y3R/lxZUXtkJjlpdD2LNMFenNlDQvPaXH5Utllt+c3z" .
    "wOkOLy7RXX5S37SfQFm/0fPkZqoZfMDB6XDcwA4cakjCRn4oZyKs8dWAxoNaTtYc" .
    "nKKMJ6rmc8PttykJw9fwiKAjPyYf21/BMvWIzu9req+TrDA/Jcd2UAug94CikJIX" .
    "uwKmSYleAOo4eJWx8GyujgEgZn05eq+K1LSg9RqRVIxOdqjoE5K3abBfs0rmUuLd" .
    "MFh7nHseTFXYbKzpz46V7iZMfFuoyURrzVsqGUm+/m7dxBM98In12kOm3";
my $ed25519_key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqmXRY8k+W9GtpWxYru6ELAXYHdXq" .
    "jf33ziITGTiJUN";
my $other_key = $hostkey_algo eq "ssh-ed25519" ? $rsa_key : $ed25519_key;

my $salt = "curl-knownhosts-test";
my $salt64 = encode_base64($salt, "");
my $hash64 = encode_base64(hmac_sha1("unrelated.invalid", $salt), "");
my $target_hash64 = encode_base64(hmac_sha1($target, $salt), "");

open(my $knownhosts, ">", $knownhosts_file) or errout "$!";
print $knownhosts "|1|$salt64|$hash64 $other_key\n";
print $knownhosts "|1|$salt64|$target_hash64 $hostkey_algo $hostkey_data\n";
close($knownhosts) or errout "$!";

exit 0;
