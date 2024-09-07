#!/bin/sh
# Script to build release-archives with. Note that this requires a checkout
# from git and you should first run autoreconf -fi and build curl once.
#
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

set -eu

export LC_ALL=C
export TZ=UTC

version="${1:-}"
cmd="${2:-}"

if [ -z "$version" ]; then
  echo "Specify a version number!"
  exit
fi

echo "$cmd"

only=""
if [ "only" = "$cmd" ]; then
  echo "Setup version number only!"
  only=1
fi

commit=""
if [ "commit" = "$cmd" ]; then
  commit=1
fi

libversion="$version"

# we make curl the same version as libcurl
curlversion="$libversion"

major=$(echo "$libversion" | cut -d. -f1 | sed -e "s/[^0-9]//g")
minor=$(echo "$libversion" | cut -d. -f2 | sed -e "s/[^0-9]//g")
patch=$(echo "$libversion" | cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g")

if test -z "$patch"; then
  echo "invalid version number? needs to be z.y.z"
  exit
fi

#
# As a precaution, remove all *.dist files that may be lying around, to reduce
# the risk of old leftovers getting shipped. The root 'Makefile.dist' is the
# exception.
echo "removing all old *.dist files"
find . -name "*.dist" -a ! -name Makefile.dist -exec rm {} \;

numeric="$(printf "%02x%02x%02x\n" "$major" "$minor" "$patch")"

HEADER=include/curl/curlver.h
CHEADER=src/tool_version.h

if test -z "$only"; then
  ext=".dist"
  # when not setting up version numbers locally
  for a in $HEADER $CHEADER; do
    cp "$a" "$a$ext"
  done
  HEADER="$HEADER$ext"
  CHEADER="$CHEADER$ext"
fi

# requires a date command that knows + for format and -d for date input
timestamp=${SOURCE_DATE_EPOCH:-$(date +"%s")}
datestamp=$(date -d "@$timestamp" +"%F")
filestamp=$(date -d "@$timestamp" +"%Y%m%d%H%M.%S")

# Replace version number in header file:
sed -i \
  -e "s/^#define LIBCURL_VERSION .*/#define LIBCURL_VERSION \"$libversion\"/g" \
  -e "s/^#define LIBCURL_VERSION_NUM .*/#define LIBCURL_VERSION_NUM 0x$numeric/g" \
  -e "s/^#define LIBCURL_VERSION_MAJOR .*/#define LIBCURL_VERSION_MAJOR $major/g" \
  -e "s/^#define LIBCURL_VERSION_MINOR .*/#define LIBCURL_VERSION_MINOR $minor/g" \
  -e "s/^#define LIBCURL_VERSION_PATCH .*/#define LIBCURL_VERSION_PATCH $patch/g" \
  -e "s/^#define LIBCURL_TIMESTAMP .*/#define LIBCURL_TIMESTAMP \"$datestamp\"/g" \
  "$HEADER"

# Replace version number in header file:
sed -i "s/#define CURL_VERSION .*/#define CURL_VERSION \"$curlversion\"/g" "$CHEADER"

if test -n "$only"; then
  # done!
  exit
fi

echo "curl version $curlversion"
echo "libcurl version $libversion"
echo "libcurl numerical $numeric"
echo "datestamp $datestamp"

findprog() {
  file="$1"
  for part in $(echo "$PATH" | tr ':' ' '); do
    path="$part/$file"
    if [ -x "$path" ]; then
      # there it is!
      return 1
    fi
  done

  # no such executable
  return 0
}

############################################################################
#
# Enforce a rerun of configure (updates the VERSION)
#

echo "Re-running config.status"
./config.status --recheck >/dev/null

echo "Recreate the built-in manual (with correct version)"
export CURL_MAKETGZ_VERSION="$version"
rm -f docs/cmdline-opts/curl.txt
make -C src

############################################################################
#
# automake is needed to run to make a non-GNU Makefile.in if Makefile.am has
# been modified.
#

if { findprog automake >/dev/null 2>/dev/null; } then
  echo "- Could not find or run automake, I hope you know what you are doing!"
else
  echo "Runs automake --include-deps"
  automake --include-deps Makefile >/dev/null
fi

if test -n "$commit"; then
  echo "produce docs/tarball-commit.txt"
  git rev-parse HEAD >docs/tarball-commit.txt.dist
fi

echo "produce RELEASE-TOOLS.md"
./scripts/release-tools.sh "$timestamp" "$version" "$commit" > docs/RELEASE-TOOLS.md.dist

############################################################################
#
# Now run make dist to generate a tar.gz archive
#

echo "make dist"
targz="curl-$version.tar.gz"
make -sj dist "VERSION=$version"
res=$?

if test "$res" != 0; then
  echo "make dist failed"
  exit 2
fi

retar() {
  tempdir=$1
  rm -rf "$tempdir"
  mkdir "$tempdir"
  cd "$tempdir"
  gzip -dc "../$targz" | tar -xf -
  find curl-* -depth -exec touch -c -t "$filestamp" '{}' +
  tar --create --format=ustar --owner=0 --group=0 --numeric-owner --sort=name curl-* | gzip --best --no-name > out.tar.gz
  mv out.tar.gz ../
  cd ..
  rm -rf "$tempdir"
}

retar ".tarbuild"
echo "replace $targz with out.tar.gz"
mv out.tar.gz "$targz"

############################################################################
#
# Now make a bz2 archive from the tar.gz original
#

bzip2="curl-$version.tar.bz2"
echo "Generating $bzip2"
gzip -dc "$targz" | bzip2 --best > "$bzip2"

############################################################################
#
# Now make an xz archive from the tar.gz original
#

xz="curl-$version.tar.xz"
echo "Generating $xz"
gzip -dc "$targz" | xz -6e - > "$xz"

############################################################################
#
# Now make a zip archive from the tar.gz original
#
makezip() {
  rm -rf "$tempdir"
  mkdir "$tempdir"
  cd "$tempdir"
  gzip -dc "../$targz" | tar -xf -
  find . | sort | zip -9 -X "$zip" -@ >/dev/null
  mv "$zip" ../
  cd ..
  rm -rf "$tempdir"
}

zip="curl-$version.zip"
echo "Generating $zip"
tempdir=".builddir"
makezip

# Set deterministic timestamp
touch -c -t "$filestamp" "$targz" "$bzip2" "$xz" "$zip"

echo "------------------"
echo "maketgz report:"
echo ""
ls -l "$targz" "$bzip2" "$xz" "$zip"
sha256sum "$targz" "$bzip2" "$xz" "$zip"

echo "Run this:"
echo "gpg -b -a '$targz' && gpg -b -a '$bzip2' && gpg -b -a '$xz' && gpg -b -a '$zip'"
