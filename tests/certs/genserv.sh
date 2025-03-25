#!/bin/sh
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

USAGE='echo Usage is genserv.sh <caprefix> [<prefix> ...]'

SRCDIR="$(dirname "${0}")"

KEYSIZE=prime256v1

CAPREFIX="${1:-}"
shift
if [ -z "$CAPREFIX" ]; then
  echo 'No CA prefix'
  $USAGE
  exit
elif [ ! -f "$CAPREFIX-ca.cacert" ] || \
     [ ! -f "$CAPREFIX-ca.key" ]; then

  command -v "$OPENSSL"
  "$OPENSSL" version

  # Generating CA root
  PREFIX=$CAPREFIX
  DURATION=6000

  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$KEYSIZE" -pkeyopt ec_param_enc:named_curve \
    -out "$PREFIX-ca.key" -pass 'pass:secret'
  "$OPENSSL" req -config "$SRCDIR/$PREFIX-ca.prm" -new -key "$PREFIX-ca.key" -out "$PREFIX-ca.csr" -passin 'pass:secret' 2>/dev/null
  "$OPENSSL" x509 -sha256 -extfile "$SRCDIR/$PREFIX-ca.prm" -days "$DURATION" \
    -req -signkey "$PREFIX-ca.key" -in "$PREFIX-ca.csr" -out "$PREFIX-ca.raw-cacert"
  "$OPENSSL" x509 -in "$PREFIX-ca.raw-cacert" -text -nameopt multiline > "$PREFIX-ca.cacert"
  "$OPENSSL" x509 -in "$PREFIX-ca.cacert" -outform der -out "$PREFIX-ca.der"
  "$OPENSSL" x509 -in "$PREFIX-ca.cacert" -text -nameopt multiline > "$PREFIX-ca.crt"

  echo "CA root generated: $PREFIX ${DURATION}days $KEYSIZE"
fi

DURATION=300

while [ -n "${1:-}" ]; do

  PREFIX="${1%.prm}"
  shift

  # pseudo-secrets
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$KEYSIZE" -pkeyopt ec_param_enc:named_curve \
    -out "$PREFIX.keyenc" -pass 'pass:secret'
  "$OPENSSL" req -config "$SRCDIR/$PREFIX.prm" -new -key "$PREFIX.keyenc" -out "$PREFIX.csr" -passin 'pass:secret' 2>/dev/null
  "$OPENSSL" pkey -in "$PREFIX.keyenc" -out "$PREFIX.key" -passin 'pass:secret'

  "$OPENSSL" pkey -in "$PREFIX.key" -pubout -outform DER -out "$PREFIX.pub.der"
  "$OPENSSL" pkey -in "$PREFIX.key" -pubout -outform PEM -out "$PREFIX.pub.pem"
  "$OPENSSL" x509 -sha256 -extfile "$SRCDIR/$PREFIX.prm" -days "$DURATION" \
    -req -CA "$CAPREFIX-ca.cacert" -CAkey "$CAPREFIX-ca.key" -CAcreateserial -in "$PREFIX.csr" > "$PREFIX.crt" 2>/dev/null

  # revoke server cert
  touch "$CAPREFIX-ca.db"
  echo 01 > "$CAPREFIX-ca.cnt"
  "$OPENSSL" ca -config "$SRCDIR/$CAPREFIX-ca.cnf" -revoke "$PREFIX.crt" 2>/dev/null

  # issue CRL
  "$OPENSSL" ca -config "$SRCDIR/$CAPREFIX-ca.cnf" -gencrl -out "$PREFIX.crl" 2>/dev/null

  "$OPENSSL" x509 -in "$PREFIX.crt" -outform der -out "$PREFIX.der"

  # all together now
  cat "$SRCDIR/$PREFIX.prm" "$PREFIX.key" "$PREFIX.crt" > "$PREFIX.pem"
  chmod o-r "$SRCDIR/$PREFIX.prm"

  echo "Certificate generated: CA=$CAPREFIX ${DURATION}days $KEYSIZE $PREFIX"
done
