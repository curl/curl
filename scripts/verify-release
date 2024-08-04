#!/bin/sh

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

# This script remakes a provided curl release and verifies that the newly
# built version is identical to the original file.
#
# It is designed to be invoked in a clean directory with the path to the
# release tarball as an argument.
#

set -eu

tarball="${1:-}"

if [ -z "$tarball" ]; then
    echo "Provide a curl release tarball name as argument"
    exit
fi

i="0"

# shellcheck disable=SC2034
for dl in curl-*; do
    i=$((i + 1))
done

if test "$i" -gt 1; then
    echo "multiple curl-* entries found, disambiguate please"
    exit
fi

mkdir -p _tarballs
rm -rf _tarballs/*

# checksum the original tarball to compare with later
sha256sum "$tarball" >_tarballs/checksum

# extract the release contents
tar xf "$tarball"

curlver=$(grep '#define LIBCURL_VERSION ' curl-*/include/curl/curlver.h | sed 's/[^0-9.]//g')

echo "version $curlver"

timestamp=$(grep -Eo 'SOURCE_DATE_EPOCH=[0-9]*' curl-"$curlver"/docs/RELEASE-TOOLS.md | cut -d= -f2)

pwd=$(pwd)
cd "curl-$curlver"
./configure --without-ssl --without-libpsl
./scripts/dmaketgz "$curlver" "$timestamp"

mv curl-"$curlver"* ../_tarballs/
cd "$pwd"
cd "_tarballs"

# compare the new tarball against the original
sha256sum -c checksum
