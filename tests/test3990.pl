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
# Usage: test3990.pl host-public-key known-hosts-file first-name target-name
# Writes a plain known_hosts file: an entry for first-name with a key of
# another type, then the real host key for target-name.
use strict;
use warnings;
my ($hostkey_file, $out, $first, $target) = @ARGV;
open(my $fh, "<", $hostkey_file) or die "$!";
my ($algo, $data) = split(/\s+/, <$fh>);
close($fh);
my $rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgSyqrUP2xhqLqkyopVapoKeu" .
    "cYIpZXeUqj+Q9WLWyXka5re62Y3R/lxZUXtkJjlpdD2LNMFenNlDQvPaXH5Utllt+c3zw" .
    "OkOLy7RXX5S37SfQFm/0fPkZqoZfMDB6XDcwA4cakjCRn4oZyKs8dWAxoNaTtYcnKKMJ6" .
    "rmc8PttykJw9fwiKAjPyYf21/BMvWIzu9req+TrDA/Jcd2UAug94CikJIXuwKmSYleAOo" .
    "4eJWx8GyujgEgZn05eq+K1LSg9RqRVIxOdqjoE5K3abBfs0rmUuLdMFh7nHseTFXYbKzp" .
    "z46V7iZMfFuoyURrzVsqGUm+/m7dxBM98In12kOm3";
my $ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqmXRY8k+W9GtpWxYru6ELAXYHd" .
    "Xqjf33ziITGTiJUN";
my $other = ($algo eq "ssh-ed25519") ? $rsa : $ed;
open(my $kh, ">", $out) or die "$!";
print $kh "$first $other\n$target $algo $data\n";
close($kh);
