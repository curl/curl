#!/usr/bin/perl

use MIME::Base64 qw(encode_base64);

my $buf;
while(read(STDIN, $buf, 60*57)) {
    my $enc = encode_base64($buf);
    print "$enc";
}
