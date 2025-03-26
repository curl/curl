#!/usr/bin/env bash
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

# exit on first fail
set -eu

OPENSSL=openssl
if [ -f /usr/local/ssl/bin/openssl ]; then
  OPENSSL=/usr/local/ssl/bin/openssl
fi

command -v "$OPENSSL"
"$OPENSSL" version

USAGE='echo Usage is genserv.sh <prefix> <caprefix>'

SRCDIR=$(pwd)

GENDIR=${GENDIR:-$SRCDIR/gen}
test -d "$GENDIR" || mkdir "$GENDIR"
cd "$GENDIR"

KEYSIZE=2048
DURATION=300
# The -sha256 option was introduced in OpenSSL 1.0.1
DIGESTALGO=-sha256

REQ=YES
P12=NO

NOTOK=

PREFIX="${1:-}"
if [ -z "$PREFIX" ]; then
  echo 'No configuration prefix'
  NOTOK=1
else
  if [ ! -f "$SRCDIR/$PREFIX.prm" ]; then
    echo "No configuration file $SRCDIR/$PREFIX.prm"
    NOTOK=1
  fi
fi

CAPREFIX="${2:-}"
if [ -z "$CAPREFIX" ]; then
  echo 'No CA prefix'
  NOTOK=1
else
  if [ ! -f "$CAPREFIX-ca.cacert" ]; then
    echo "No CA certificate file $CAPREFIX-ca.cacert"
    NOTOK=1
  fi
  if [ ! -f "$CAPREFIX-ca.key" ]; then
    echo "No $CAPREFIX key"
    NOTOK=1
  fi
fi

if [ -n "$NOTOK" ]; then
  echo 'Sorry, I cannot do that for you.'
  $USAGE
  exit
fi

echo "PREFIX=$PREFIX CAPREFIX=$CAPREFIX DURATION=$DURATION KEYSIZE=$KEYSIZE"

set -x

if [ "$REQ" = YES ]; then
  "$OPENSSL" req -config "$SRCDIR/$PREFIX.prm" -newkey "rsa:$KEYSIZE" -keyout "$PREFIX.key" -out "$PREFIX.csr" -passout fd:0 <<EOF
pass:secret
EOF
fi

"$OPENSSL" rsa -in "$PREFIX.key" -out "$PREFIX.key" -passin fd:0 <<EOF
pass:secret
EOF

echo 'pseudo secrets generated'

"$OPENSSL" rsa -in "$PREFIX.key" -pubout -outform DER -out "$PREFIX.pub.der"
"$OPENSSL" rsa -in "$PREFIX.key" -pubout -outform PEM -out "$PREFIX.pub.pem"
"$OPENSSL" x509 -extfile "$SRCDIR/$PREFIX.prm" -days "$DURATION" -CA "$CAPREFIX-ca.cacert" -CAkey "$CAPREFIX-ca.key" -CAcreateserial -in "$PREFIX.csr" -req -text -nameopt multiline "$DIGESTALGO" > "$PREFIX.crt"

if [ "$P12" = YES ]; then
  "$OPENSSL" pkcs12 -export -des3 -out "$PREFIX.p12" -caname "$CAPREFIX" -name "$PREFIX" -inkey "$PREFIX.key" -in "$PREFIX.crt" -certfile "$CAPREFIX-ca.crt"
fi

"$OPENSSL" x509 -noout -text -hash -in "$PREFIX.crt" -nameopt multiline

# revoke server cert
touch "$CAPREFIX-ca.db"
echo 01 > "$CAPREFIX-ca.cnt"
"$OPENSSL" ca -config "$SRCDIR/$CAPREFIX-ca.cnf" -revoke "$PREFIX.crt"

# issue CRL
"$OPENSSL" ca -config "$SRCDIR/$CAPREFIX-ca.cnf" -gencrl -out "$PREFIX.crl"

"$OPENSSL" x509 -in "$PREFIX.crt" -outform der -out "$PREFIX.der"

# all together now
cat "$SRCDIR/$PREFIX.prm" "$PREFIX.key" "$PREFIX.crt" > "$PREFIX.pem"
chmod o-r "$SRCDIR/$PREFIX.prm"

#for ext in crl crt csr der key pem pub.der pub.pem; do
for ext in crl crt key pem pub.der pub.pem; do
  cp "$PREFIX.$ext" "$SRCDIR"/
done
echo "certificates for $PREFIX generated."
