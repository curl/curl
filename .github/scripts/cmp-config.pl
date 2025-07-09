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

my $autotools = $ARGV[0];
my $cmake = $ARGV[1];

if(!$cmake) {
    print "Usage: cmp-config <config1> <config2.h>\n";
    exit;
}

# this lists complete lines that will be removed from the output if
# matching
my %remove = (
    '#define CURL_EXTERN_SYMBOL' => 1,
    '#define CURL_OS "Linux"' => 1,
    '#define CURL_OS "x86_64-pc-linux-gnu"' => 1,
    '#define GETHOSTNAME_TYPE_ARG2 int' => 1,
    '#define GETHOSTNAME_TYPE_ARG2 size_t' => 1,
    '#define HAVE_BROTLI 1' => 1,
    '#define HAVE_BROTLI_DECODE_H 1' => 1,
    '#define HAVE_DLFCN_H 1' => 1,
    '#define HAVE_GSSAPI_GSSAPI_KRB5_H 1' => 1,
    '#define HAVE_INTTYPES_H 1' => 1,
    '#define HAVE_LDAP_H 1' => 1,
    '#define HAVE_LDAP_SSL 1' => 1,
    '#define HAVE_LIBBROTLIDEC 1' => 1,
    '#define HAVE_LIBPSL_H 1' => 1,
    '#define HAVE_LIBRTMP_RTMP_H 1' => 1,
    '#define HAVE_LIBSOCKET 1' => 1,
    '#define HAVE_LIBSSH' => 1,
    '#define HAVE_LIBSSH2 1' => 1,
    '#define HAVE_LIBSSL 1' => 1,
    '#define HAVE_LIBWOLFSSH' => 1,
    '#define HAVE_LIBZSTD 1' => 1,
    '#define HAVE_NGHTTP2_NGHTTP2_H 1' => 1,
    '#define HAVE_NGHTTP3_NGHTTP3_H 1' => 1,
    '#define HAVE_NGTCP2_NGTCP2_CRYPTO_H 1' => 1,
    '#define HAVE_NGTCP2_NGTCP2_H 1' => 1,
    '#define HAVE_OPENSSL_CRYPTO_H 1' => 1,
    '#define HAVE_OPENSSL_ERR_H 1' => 1,
    '#define HAVE_OPENSSL_PEM_H 1' => 1,
    '#define HAVE_OPENSSL_RSA_H 1' => 1,
    '#define HAVE_OPENSSL_SSL_H 1' => 1,
    '#define HAVE_OPENSSL_X509_H 1' => 1,
    '#define HAVE_QUICHE_H 1' => 1,
    '#define HAVE_SSL_SET_QUIC_TLS_CBS 1' => 1,
    '#define HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT 1' => 1,
    '#define HAVE_STDINT_H 1' => 1,
    '#define HAVE_STDIO_H 1' => 1,
    '#define HAVE_STDLIB_H 1' => 1,
    '#define HAVE_STRING_H 1' => 1,
    '#define HAVE_SYS_STAT_H 1' => 1,
    '#define HAVE_SYS_XATTR_H 1' => 1,
    '#define HAVE_UNICODE_UIDNA_H 1' => 1,
    '#define HAVE_WOLFSSH_SSH_H 1' => 1,
    '#define HAVE_WOLFSSL_SET_QUIC_USE_LEGACY_CODEPOINT 1' => 1,
    '#define HAVE_ZSTD 1' => 1,
    '#define HAVE_ZSTD_H 1' => 1,
    '#define LT_OBJDIR ".libs/"' => 1,
    '#define NEED_LBER_H 1' => 1,
    '#define PACKAGE "curl"' => 1,
    '#define PACKAGE_BUGREPORT "a suitable curl mailing list: https://curl.se/mail/"' => 1,
    '#define PACKAGE_NAME "curl"' => 1,
    '#define PACKAGE_STRING "curl -"' => 1,
    '#define PACKAGE_TARNAME "curl"' => 1,
    '#define PACKAGE_URL ""' => 1,
    '#define PACKAGE_VERSION "-"' => 1,
    '#define SIZEOF_LONG_LONG 8' => 1,
    '#define VERSION "-"' => 1,
    '#define _FILE_OFFSET_BITS 64' => 1,
    );

sub filter {
    my ($line) = @_;
    if(!$remove{$line}) {
        return "$line\n";
    }
    $remove{$line}++;
    return "";
}

sub grepit {
    my ($input, $output) = @_;
    my @defines;
    # first get all the #define lines
    open(F, "<$input");
    while(<F>) {
        if($_ =~ /^#def/) {
            chomp;
            push @defines, $_;
        }
    }
    close(F);

    open(O, ">$output");

    # output the sorted list through the filter
    foreach my $d(sort @defines) {
        print O filter($d);
    }
    close(O);
}

grepit($autotools, "/tmp/autotools");
grepit($cmake, "/tmp/cmake");

foreach my $v (keys %remove) {
    if($remove{$v} == 1) {
        print "Ignored, never matched line: $v\n";
    }
}


# return the exit code from diff
exit system("diff -u /tmp/autotools /tmp/cmake") >> 8;
