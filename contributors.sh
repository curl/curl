#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
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
# This script shows all mentioned contributors from <hash> until HEAD. To aid
# when writing RELEASE-NOTES and THANKS.
#

start=$1

if test -z "$start"; then
  echo "Usage: $0 <since this tag/hash>"
fi

# filter out Author:, Commit: and *by: lines
# cut off the email parts
# cut off spaces first and last on the line
# only count names with a space (ie more than one word)
# sort all unique names
git log $start..HEAD | \
egrep '(Author|Commit|by):' | \
cut -d: -f2- | \
cut '-d<' -f1 | \
sed -e 's/^ //' -e 's/ $//g' | \
grep ' ' | \
sort -u
