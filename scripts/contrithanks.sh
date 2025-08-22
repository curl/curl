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

#
# This script updates the docs/THANKS document.
#

set -u

start="${1:-}"

if test "$start" = "-h"; then
  echo "Usage: $0 <since this tag/hash>"
  exit
fi
if test "$start" = "stdout"; then
    # output the names on stdout
    use_stdout="yes"
    start=""
else
    use_stdout="no";
fi
if test -z "$start"; then
  start=$(git tag --sort=taggerdate | grep "^curl-" | tail -1)
fi

# We also include curl-www if possible. Override by setting CURLWWW
CURLWWW="${CURLWWW:-../curl-www}"

rand="./docs/THANKS.$$"

# output the existing list of names with lowercase github
tail -n +7 ./docs/THANKS | sed 's/ github/ github/i'  > $rand

# get new names using git
{
  {
    git log --use-mailmap "$start..HEAD"
    if [ -d "$CURLWWW" ]; then
      git -C "$CURLWWW" log --use-mailmap "$start..HEAD"
    fi
  } | \
  grep -Eai '(^Author|^Commit|by):' | \
  cut -d: -f2- | \
  cut '-d(' -f1 | \
  cut '-d<' -f1 | \
  tr , '\012' | \
  sed 's/ at github/ on github/i' | \
  sed 's/ and /\n/' | \
  sed -e 's/^ //' -e 's/ $//g' -e 's/@users.noreply.github.com$/ on github/i' | \
  sed 's/ github/ github/i'

  # grep out the list of names from RELEASE-NOTES
  # split on ", "
  # remove leading whitespace
  grep -a "^  [^ (]" RELEASE-NOTES| \
  sed 's/, */\n/g'| \
  sed 's/^ *//'
} | \
LC_ALL=C sed -f ./docs/THANKS-filter | \
sort -fu | \
grep -aixvFf ./docs/THANKS >> $rand

if test "$use_stdout" = "no"; then

  # output header
  cat <<EOF >./docs/THANKS
 This project has been alive for many years. Countless people have provided
 feedback that have improved curl. Here follows a list of people that have
 contributed (a-z order).

 If you have contributed but are missing here, please let us know!

EOF
  # append all the names, sorted case insensitively
  grep -v "^ " $rand | sort -f $rand >> ./docs/THANKS
else
  # send all names on stdout
  grep -v "^ " $rand | sort -f $rand
fi

# get rid of the temp file
rm $rand
