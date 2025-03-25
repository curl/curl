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

SRCDIR=$(pwd)
GENDIR=${GENDIR:-$SRCDIR/gen}
KEYSIZE=prime256v1
DURATION=300

CAPREFIX="${1:-}"
shift
if [ -z "$CAPREFIX" ]; then
  echo 'No CA prefix'
  $USAGE
  exit
elif [ ! -f "$GENDIR/$CAPREFIX-ca.cacert" ] || \
     [ ! -f "$GENDIR/$CAPREFIX-ca.key" ]; then
  "$(dirname "${0}")"/genroot.sh "$CAPREFIX"
fi

test -d "$GENDIR" || mkdir "$GENDIR"
cd "$GENDIR"

while [ -n "${1:-}" ]; do

  PREFIX="$1"
  shift

  # pseudo-secrets
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$KEYSIZE" -pkeyopt ec_param_enc:named_curve -out "$PREFIX.keyenc" -pass 'pass:secret'
  "$OPENSSL" req -config "$SRCDIR/$PREFIX.prm" -new -key "$PREFIX.keyenc" -out "$PREFIX.csr" -passin 'pass:secret' 2>/dev/null
  "$OPENSSL" pkey -in "$PREFIX.keyenc" -out "$PREFIX.key" -passin 'pass:secret'

  "$OPENSSL" pkey -in "$PREFIX.key" -pubout -outform DER -out "$PREFIX.pub.der"
  "$OPENSSL" pkey -in "$PREFIX.key" -pubout -outform PEM -out "$PREFIX.pub.pem"
  "$OPENSSL" x509 -sha256 -extfile "$SRCDIR/$PREFIX.prm" -days "$DURATION" -CA "$CAPREFIX-ca.cacert" -CAkey "$CAPREFIX-ca.key" -CAcreateserial -in "$PREFIX.csr" -req -text -nameopt multiline > "$PREFIX.crt"

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

  for ext in crl crt key pem pub.der pub.pem; do
    cp "$PREFIX.$ext" "$SRCDIR"/
  done

  echo "Certificates generated: PREFIX=$PREFIX CAPREFIX=$CAPREFIX DURATION=$DURATION KEYSIZE=$KEYSIZE"
done
