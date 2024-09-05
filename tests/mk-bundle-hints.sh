#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats
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

# Look for symbols possibly re-used in multiple sources.
# Misses clashes in sources reused for multiple tests (e.g. lib525, lib526),
# also picks up false-positives:
git grep -E '^ *(static|struct) +' \
  | grep -E '^(libtest|unit)/' \
  | grep -E '\.(c|pl):(static|struct) +' \
  | grep -o -E '[a-zA-Z_][a-zA-Z0-9_]+ *[=;[({]' | tr -d '=;[({ ' \
  | grep -v -E '^(NULL$|CURLE_)' \
  | sort | uniq -c | sort -k 2 | grep -v -E '^ +1 '

echo '---'

# Extract list of macros that may be re-used by multiple tests:
# (may pick up false-positive when the macro is defined to the same
# value everywhere)
git grep -E '^ *# *define +' \
  | grep -E '^(libtest|unit)/' \
  | grep -o -E '.+\.(c|pl): *# *define +[A-Z_][A-Z0-9_]+' | sort -u \
  | grep -o -E '[A-Z_][A-Z0-9_]+' \
  | sort | uniq -c | sort -k 2 | grep -v -E '^ +1 '
