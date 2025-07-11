#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) EdelWeb for EdelKey and OpenEvidence
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

use File::Basename;
use File::Spec;

sub opensslfail {
    die "Missing or broken 'openssl' tool. openssl 1.0.2+ is required. ".
        "Without it, this script cannot generate the necessary certificates ".
        "the curl test suite needs for all its TLS related tests.";
}

my $OPENSSL = 'openssl';
if(-f '/usr/local/ssl/bin/openssl') {
    $OPENSSL = '/usr/local/ssl/bin/openssl';
}

my $SRCDIR = dirname(__FILE__);
my $fh;
my $dev_null = File::Spec->devnull();

my $KEYSIZE = 'prime256v1';
my $DURATION;
my $PREFIX;

my $CAPREFIX = shift @ARGV;
if(!$CAPREFIX) {
    print "Usage: genserv.pl <caprefix> [<prefix> ...]\n";
    exit 1;
} elsif(! -f "$CAPREFIX-ca.cacert" ||
        ! -f "$CAPREFIX-ca.key") {

    if($OPENSSL eq basename($OPENSSL)) {  # has no dir component
        # find openssl in PATH
        my $found = 0;
        foreach(File::Spec->path()) {
            my $file = File::Spec->catfile($_, $OPENSSL);
            if(-f $file) {
                $OPENSSL = $file;
                $found = 1;
                last;
            }
        }
        if(!$found) {
            opensslfail();
        }
    }

    print "$OPENSSL\n";
    system("$OPENSSL version");

    $PREFIX = $CAPREFIX;
    $DURATION = 6000;

    if(system("$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$KEYSIZE -pkeyopt ec_param_enc:named_curve " .
        "-out $PREFIX-ca.key -pass pass:secret") != 0) {
        opensslfail();
    }
    system("$OPENSSL req -config $SRCDIR/$PREFIX-ca.prm -new -key $PREFIX-ca.key -out $PREFIX-ca.csr -passin pass:secret 2>$dev_null");
    system("$OPENSSL x509 -sha256 -extfile $SRCDIR/$PREFIX-ca.prm -days $DURATION " .
        "-req -signkey $PREFIX-ca.key -in $PREFIX-ca.csr -out $PREFIX-ca.raw-cacert");
    system("$OPENSSL x509 -in $PREFIX-ca.raw-cacert -text -nameopt multiline > $PREFIX-ca.cacert");
    system("$OPENSSL x509 -in $PREFIX-ca.cacert -outform der -out $PREFIX-ca.der");
    system("$OPENSSL x509 -in $PREFIX-ca.cacert -text -nameopt multiline > $PREFIX-ca.crt");

    print "CA root generated: $PREFIX $DURATION days $KEYSIZE\n";
}

$DURATION = 300;

open($fh, '>>', "$CAPREFIX-ca.db") and close($fh);  # for revoke server cert

while(@ARGV) {
    $PREFIX = shift @ARGV;
    $PREFIX =~ s/\.prm$//;

    # pseudo-secrets
    system("$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$KEYSIZE -pkeyopt ec_param_enc:named_curve " .
        "-out $PREFIX.keyenc -pass pass:secret");
    system("$OPENSSL req -config $SRCDIR/$PREFIX.prm -new -key $PREFIX.keyenc -out $PREFIX.csr -passin pass:secret 2>$dev_null");
    system("$OPENSSL pkey -in $PREFIX.keyenc -out $PREFIX.key -passin pass:secret");

    system("$OPENSSL pkey -in $PREFIX.key -pubout -outform DER -out $PREFIX.pub.der");
    system("$OPENSSL pkey -in $PREFIX.key -pubout -outform PEM -out $PREFIX.pub.pem");
    system("$OPENSSL x509 -sha256 -extfile $SRCDIR/$PREFIX.prm -days $DURATION " .
        "-req -CA $CAPREFIX-ca.cacert -CAkey $CAPREFIX-ca.key -CAcreateserial -in $PREFIX.csr > $PREFIX.crt 2>$dev_null");

    # revoke server cert
    if(open($fh, '>', "$CAPREFIX-ca.cnt")) {
        print $fh '01';
        close($fh);
    }
    system("$OPENSSL ca -config $SRCDIR/$CAPREFIX-ca.cnf -revoke $PREFIX.crt 2>$dev_null");

    # issue CRL
    system("$OPENSSL ca -config $SRCDIR/$CAPREFIX-ca.cnf -gencrl -out $PREFIX.crl 2>$dev_null");
    system("$OPENSSL x509 -in $PREFIX.crt -outform der -out $PREFIX.der");

    # concatenate all together now
    open($fh, '>', "$PREFIX.pem") and close($fh);
    chmod 0600, "$PREFIX.pem";
    if(open($fh, '>>', "$PREFIX.pem")) {
        my $fi;
        print $fh do { local $/; open $fi, '<', $_ and <$fi> } for("$SRCDIR/$PREFIX.prm", "$PREFIX.key", "$PREFIX.crt");
        close($fh);
    }

    print "Certificate generated: CA=$CAPREFIX ${DURATION}days $KEYSIZE $PREFIX\n";
}
