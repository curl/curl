#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2013 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#
# This script shows all mentioned contributors from <hash> until HEAD and
# puts them at the end of the THANKS document on stdout
#

start=$1

if test "$start" = "-h"; then
  echo "Usage: $0 <since this tag/hash>"
  exit
fi
if test -z "$start"; then
  start=`git tag --sort=taggerdate | grep "^curl-" | tail -1`;
fi


# We also include curl-www if possible. Override by setting CURLWWW
if [ -z "$CURLWWW" ] ; then
    CURLWWW=../curl-www
fi

cat ./docs/THANKS

(
 (
  git log --use-mailmap $start..HEAD
  if [ -d "$CURLWWW" ]
  then
   git -C ../curl-www log --use-mailmap $start..HEAD
  fi
 ) | \

egrep -ai '(^Author|^Commit|by):' | \
cut -d: -f2- | \
cut '-d(' -f1 | \
cut '-d<' -f1 | \
tr , '\012' | \
sed 's/ at github/ on github/' | \
sed 's/ and /\n/' | \
sed -e 's/^ //' -e 's/ $//g' -e 's/@users.noreply.github.com$/ on github/'

# grep out the list of names from RELEASE-NOTES
# split on ", "
# remove leading whitespace
grep -a "^  [^ (]" RELEASE-NOTES| \
sed 's/, */\n/g'| \
sed 's/^ *//'

)| \
sed -f ./docs/THANKS-filter | \
grep -a ' ' | \
sort -fu | \
grep -aixvf ./docs/THANKS
