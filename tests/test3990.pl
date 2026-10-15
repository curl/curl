#!/usr/bin/env perl
# Usage: test3990.pl host-public-key known-hosts-file first-name target-name
# Writes a plain known_hosts file: an entry for first-name with a key of
# another type, then the real host key for target-name.
use strict;
use warnings;
my ($hostkey_file, $out, $first, $target) = @ARGV;
open(my $fh, "<", $hostkey_file) or die "$!";
my ($algo, $data) = split(/\s+/, <$fh>);
close($fh);
my $rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgSyqrUP2xhqLqkyopVapoKeucYIpZXeUqj+Q9WLWyXka5re62Y3R/lxZUXtkJjlpdD2LNMFenNlDQvPaXH5Utllt+c3zwOkOLy7RXX5S37SfQFm/0fPkZqoZfMDB6XDcwA4cakjCRn4oZyKs8dWAxoNaTtYcnKKMJ6rmc8PttykJw9fwiKAjPyYf21/BMvWIzu9req+TrDA/Jcd2UAug94CikJIXuwKmSYleAOo4eJWx8GyujgEgZn05eq+K1LSg9RqRVIxOdqjoE5K3abBfs0rmUuLdMFh7nHseTFXYbKzpz46V7iZMfFuoyURrzVsqGUm+/m7dxBM98In12kOm3";
my $ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqmXRY8k+W9GtpWxYru6ELAXYHdXqjf33ziITGTiJUN";
my $other = ($algo eq "ssh-ed25519") ? $rsa : $ed;
open(my $kh, ">", $out) or die "$!";
print $kh "$first $other\n$target $algo $data\n";
close($kh);
