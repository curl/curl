#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2013-2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

#
# This script shows all mentioned contributors from the given <hash>/<tag>
# until HEAD and adds the contributors already mentioned in the existing
# RELEASE-NOTES.
#

start=$1

if test "$start" = "-h"; then
    echo "Usage: $0 <since this tag/hash> [--releasenotes]"
    exit
fi
if test -z "$start"; then
    start=`git tag --sort=taggerdate | tail -1`;
    echo "Since $start:"
fi

# We also include curl-www if possible. Override by setting CURLWWW
if [ -z "$CURLWWW" ] ; then
    CURLWWW=../curl-www
fi

# filter out Author:, Commit: and *by: lines
# cut off the email parts
# split list of names at comma
# split list of names at " and "
# cut off spaces first and last on the line
# filter alternatives through THANKS-filter
# only count names with a space (ie more than one word)
# sort all unique names
# awk them into RELEASE-NOTES format

(
 (
  git log --pretty=full --use-mailmap $start..HEAD
  if [ -d "$CURLWWW" ]
  then
   git -C ../curl-www log --pretty=full --use-mailmap $start..HEAD
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

grep -a "^  [^ \(]" RELEASE-NOTES| \
sed 's/, */\n/g'| \
sed 's/^ *//'

)| \
sed -f ./docs/THANKS-filter | \
grep -a ' ' | \
sort -fu | \
awk '{
 num++;
 n = sprintf("%s%s%s,", n, length(n)?" ":"", $0);
 #print n;
 if(length(n) > 77) {
   printf("  %s\n", p);
   n=sprintf("%s,", $0);
 }
 p=n;

}

 END {
   printf("  %s\n", p);
   printf("  (%d contributors)\n", num);
 }

'
