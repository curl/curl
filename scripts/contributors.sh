#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2013-2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# Use --releasenotes to also include the names from the existing RELEASE-NOTES
# file, which is handy when we've added names manually in there that should be
# included in an updated list.
#

start=$1

if test -z "$start"; then
    echo "Usage: $0 <since this tag/hash> [--releasenotes]"
    exit
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
git log $start..HEAD | \
egrep -i '(Author|Commit|by):' | \
cut -d: -f2- | \
cut '-d<' -f1 | \
tr , '\012' | \
sed 's/ and /\n/' | \
sed -e 's/^ //' -e 's/ $//g'

if echo "$*" | grep -qw -- '--releasenotes';then
    # if --releasenotes was used
    # grep out the list of names from RELEASE-NOTES
    # split on ", "
    # remove leading white spaces
grep "^  [^ \(]" RELEASE-NOTES| \
sed 's/, */\n/g'| \
sed 's/^ *//'
fi
)| \
sed -f ./docs/THANKS-filter | \
grep ' ' | \
sort -fu | \
awk '{
 num++;
 n = sprintf("%s%s%s,", n, length(n)?" ":"", $0);
 #print n;
 if(length(n) > 78) {
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
