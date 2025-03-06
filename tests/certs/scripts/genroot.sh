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

USAGE='echo Usage is genroot.sh <name>'

SRCDIR=$(pwd)

GENDIR=${GENDIR:-$SRCDIR/gen}
test -d "$GENDIR" || mkdir "$GENDIR"
cd "$GENDIR"

KEYSIZE=2048
DURATION=6000
# The -sha256 option was introduced in OpenSSL 1.0.1
DIGESTALGO=-sha256

NOTOK=

PREFIX="${1:-}"
if [ -z "$PREFIX" ]; then
  echo 'No configuration prefix'
  NOTOK=1
else
  if [ ! -f "$SRCDIR/$PREFIX-ca.prm" ]; then
    echo "No configuration file $SRCDIR/$PREFIX-ca.prm"
    NOTOK=1
  fi
fi

if [ -n "$NOTOK" ]; then
  echo 'Sorry, I cannot do that for you.'
  $USAGE
  exit
fi

echo "PREFIX=$PREFIX DURATION=$DURATION KEYSIZE=$KEYSIZE"

set -x

"$OPENSSL" genrsa -out "$PREFIX-ca.key" -passout fd:0 "$KEYSIZE" <<EOF
pass:secret
EOF
"$OPENSSL" req -config "$SRCDIR/$PREFIX-ca.prm" -new -key "$PREFIX-ca.key" -out "$PREFIX-ca.csr" -passin fd:0 <<EOF
pass:secret
EOF
"$OPENSSL" x509 -extfile "$SRCDIR/$PREFIX-ca.prm" -days "$DURATION" -req -signkey "$PREFIX-ca.key" -in "$PREFIX-ca.csr" -out "$PREFIX-ca.raw-cacert" "$DIGESTALGO"
"$OPENSSL" x509 -text -in "$PREFIX-ca.raw-cacert" -nameopt multiline > "$PREFIX-ca.cacert"
"$OPENSSL" x509 -in "$PREFIX-ca.cacert" -outform der -out "$PREFIX-ca.der"
"$OPENSSL" x509 -in "$PREFIX-ca.cacert" -text -nameopt multiline > "$PREFIX-ca.crt"

for ext in key cacert crt; do
  cp "$PREFIX-ca.$ext" "$SRCDIR"/
done
echo "ca root $PREFIX generated."
