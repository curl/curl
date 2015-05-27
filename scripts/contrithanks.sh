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
# This script shows all mentioned contributors from <hash> until HEAD and
# puts them at the end of the THANKS document on stdout
#

start=$1

if test -z "$start"; then
  echo "Usage: $0 <since this tag/hash>"
fi

cat ./docs/THANKS

(
git log $start..HEAD | \
egrep -i '(Author|Commit|by):' | \
cut -d: -f2- | \
cut '-d<' -f1 | \
tr , '\012' | \
sed 's/ and /\n/' | \
sed -e 's/^ //' -e 's/ $//g'

# grep out the list of names from RELEASE-NOTES
# split on ", "
# remove leading white spaces
grep "^  [^ (]" RELEASE-NOTES| \
sed 's/, */\n/g'| \
sed 's/^ *//'

)| \
sed -f ./docs/THANKS-filter | \
grep ' ' | \
sort -fu | \
grep -xvf ./docs/THANKS 
