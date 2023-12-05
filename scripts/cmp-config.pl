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

my $autotools = $ARGV[0];
my $cmake = $ARGV[1];

if(!$cmake) {
    print "Usage: cmp-config <config1> <config2.h>\n";
    exit;
}

# this lists complete lines that will be removed from the the output if
# matching
my %remove = (
    '#define _FILE_OFFSET_BITS 64' => 1,
    '#define CURL_EXTERN_SYMBOL' => 1,
    '#define CURL_SA_FAMILY_T sa_family_t' => 1,
    '#define GETHOSTNAME_TYPE_ARG2 size_t' => 1,
    '#define HAVE_BROTLI 1' => 1,
    '#define HAVE_BROTLI_DECODE_H 1' => 1,
    '#define HAVE_DECL_GETPWUID_R 1' => 1,
    '#define HAVE_DLFCN_H 1' => 1,
    '#define HAVE_GETHOSTBYNAME 1' => 1,
    '#define HAVE_INTTYPES_H 1' => 1,
    '#define HAVE_IOCTL 1' => 1,
    '#define HAVE_LDAP_SSL 1' => 1,
    '#define HAVE_LIBBROTLIDEC 1' => 1,
    '#define HAVE_LIBSSL 1' => 1,
    '#define HAVE_LIBZSTD 1' => 1,
    '#define HAVE_OPENSSL3 1' => 1,
    '#define HAVE_OPENSSL_CRYPTO_H 1' => 1,
    '#define HAVE_OPENSSL_ERR_H 1' => 1,
    '#define HAVE_OPENSSL_PEM_H 1' => 1,
    '#define HAVE_OPENSSL_RSA_H 1' => 1,
    '#define HAVE_OPENSSL_SSL_H 1' => 1,
    '#define HAVE_OPENSSL_X509_H 1' => 1,
    '#define HAVE_SA_FAMILY_T 1' => 1,
    '#define HAVE_SETJMP_H 1' => 1,
    '#define HAVE_STDINT_H 1' => 1,
    '#define HAVE_STDIO_H 1' => 1,
    '#define HAVE_STDLIB_H 1' => 1,
    '#define HAVE_STRING_H 1' => 1,
    '#define HAVE_SYS_XATTR_H 1' => 1,
    '#define HAVE_ZSTD 1' => 1,
    '#define HAVE_ZSTD_H 1' => 1,
    '#define LT_OBJDIR ".libs/"' => 1,
    '#define OS "Linux"' => 1,
    '#define OS "x86_64-pc-linux-gnu"' => 1,
    '#define PACKAGE "curl"' => 1,
    '#define PACKAGE_BUGREPORT "a suitable curl mailing list: https://curl.se/mail/"' => 1,
    '#define PACKAGE_NAME "curl"' => 1,
    '#define PACKAGE_STRING "curl -"' => 1,
    '#define PACKAGE_TARNAME "curl"' => 1,
    '#define PACKAGE_URL ""' => 1,
    '#define PACKAGE_VERSION "-"' => 1,
    '#define SIZEOF_LONG_LONG 8' => 1,
    '#define USE_MANUAL 1' => 1,
    '#define VERSION "-"' => 1,
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
