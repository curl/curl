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

USAGE='echo Usage is genserv.sh <prefix> <caprefix>'

HOME=$(pwd)
cd "$HOME"

KEYSIZE=2048
DURATION=3000
# The -sha256 option was introduced in OpenSSL 1.0.1
DIGESTALGO=-sha256

REQ=YES
P12=NO
DHP=NO

NOTOK=

PREFIX="${1:-}"
if [ -z "$PREFIX" ]; then
  echo 'No configuration prefix'
  NOTOK=1
else
  if [ ! -f "$PREFIX-sv.prm" ]; then
    echo "No configuration file $PREFIX-sv.prm"
    NOTOK=1
  fi
fi

CAPREFIX="${2:-}"
if [ -z "$CAPREFIX" ]; then
  echo No CA prefix
  NOTOK=1
else
  if [ ! -f "$CAPREFIX-ca.cacert" ]; then
    echo "No CA certificate file $CAPREFIX-ca.caert"
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

if [ -z "${SERIAL:-}" ]; then
  SERIAL="$(date +'%s')${RANDOM:(-4)}"
fi

echo "SERIAL=$SERIAL PREFIX=$PREFIX CAPREFIX=$CAPREFIX DURATION=$DURATION KEYSIZE=$KEYSIZE"

set -x

if [ "$DHP" = YES ]; then
  "$OPENSSL" dhparam -2 -out "$PREFIX-sv.dhp" "$KEYSIZE"
fi
if [ "$REQ" = YES ]; then
  "$OPENSSL" req -config "$PREFIX-sv.prm" -newkey "rsa:$KEYSIZE" -keyout "$PREFIX-sv.key" -out "$PREFIX-sv.csr" -passout fd:0 <<EOF
pass:secret
EOF
fi

"$OPENSSL" rsa -in "$PREFIX-sv.key" -out "$PREFIX-sv.key" -passin fd:0 <<EOF
pass:secret
EOF

echo 'pseudo secrets generated'

"$OPENSSL" rsa -in "$PREFIX-sv.key" -pubout -outform DER -out "$PREFIX-sv.pub.der"
"$OPENSSL" rsa -in "$PREFIX-sv.key" -pubout -outform PEM -out "$PREFIX-sv.pub.pem"
"$OPENSSL" x509 -set_serial "$SERIAL" -extfile "$PREFIX-sv.prm" -days "$DURATION" -CA "$CAPREFIX-ca.cacert" -CAkey "$CAPREFIX-ca.key" -in "$PREFIX-sv.csr" -req -text -nameopt multiline "$DIGESTALGO" > "$PREFIX-sv.crt"

if [ "$P12" = YES ]; then
  "$OPENSSL" pkcs12 -export -des3 -out "$PREFIX-sv.p12" -caname "$CAPREFIX" -name "$PREFIX" -inkey "$PREFIX-sv.key" -in "$PREFIX-sv.crt" -certfile "$CAPREFIX-ca.crt"
fi

"$OPENSSL" x509 -noout -text -hash -in "$PREFIX-sv.crt" -nameopt multiline

# revoke server cert
touch "$CAPREFIX-ca.db"
echo 01 > "$CAPREFIX-ca.cnt"
"$OPENSSL" ca -config "$CAPREFIX-ca.cnf" -revoke "$PREFIX-sv.crt"

# issue CRL
"$OPENSSL" ca -config "$CAPREFIX-ca.cnf" -gencrl -out "$PREFIX-sv.crl"

"$OPENSSL" x509 -in "$PREFIX-sv.crt" -outform der -out "$PREFIX-sv.der"

# all together now
touch "$PREFIX-sv.dhp"
cat "$PREFIX-sv.prm" "$PREFIX-sv.key" "$PREFIX-sv.crt" "$PREFIX-sv.dhp" > "$PREFIX-sv.pem"
chmod o-r "$PREFIX-sv.prm"

"$OPENSSL" x509 -in "$PREFIX-sv.pem" -pubkey -noout | \
"$OPENSSL" pkey -pubin -outform der | "$OPENSSL" dgst -sha256 -binary | \
"$OPENSSL" enc -base64 > "$PREFIX-sv.pubkey-pinned"

echo "$PREFIX-sv.pem done"
