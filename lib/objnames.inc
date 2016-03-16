# ***************************************************************************
# *                                  _   _ ____  _
# *  Project                     ___| | | |  _ \| |
# *                             / __| | | | |_) | |
# *                            | (__| |_| |  _ <| |___
# *                             \___|\___/|_| \_\_____|
# *
# * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
# *
# * This software is licensed as described in the file COPYING, which
# * you should have received as part of this distribution. The terms
# * are also available at https://curl.haxx.se/docs/copyright.html.
# *
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************

#
# This file is sourced from curl/packages/OS400/initscript.sh and
# other Bourne shell scripts. Keep it as portable as possible.
#

#
# curl_10char_object_name
#
# This shell function accepts a single string argument with unspecified
# length representing a (*.c) source file name and returns a string which
# is a transformation of given argument.
#
# The intended purpose of this function is to transliterate a (*.c) source
# file name that may be longer than 10 characters, or not, into a string
# with at most 10 characters which may be used as an OS/400 object name.
#
# This function might not be universally usefull, nor we care about it.
#
# It is intended to be used with libcurl's (*.c) source file names, so
# dependency on libcurl's source file naming scheme is acceptable and
# good enough for its intended use. Specifically it makes use of the fact
# that libcurl's (*.c) source file names which may be longer than 10 chars
# are conformed with underscore '_' separated substrings, or separated by
# other character which does not belong to the [0-9], [a-z] or [A-Z] sets.
#
# This allows repeatable and automatic short object name generation with
# no need for a hardcoded mapping table.
#
# Transformation is done in the following way:
#
# 1) Leading directory components are removed.
# 2) Leftmost dot character and any other char following it are removed.
# 3) Lowercase characters are transliterated to uppercase.
# 4) Characters not in [A-Z] or [0-9] are transliterated to underscore '_'.
# 5) Every sequence of one or more underscores is replaced with a single one.
# 6) Five leftmost substrings which end in an underscore character are
#    replaced by the first character of each substring, while retaining
#    the rest of the string.
# 7) Finally the result is truncated to 10 characters.
#
# Resulting object name may be shorter than 10 characters.
#
# Test case 1221 does unit testng of this function and also verifies
# that it is possible to generate distinct short object names for all
# curl and libcurl *.c source file names.
#

curl_10char_object_name() {
  echo "${1}" | \
  sed -e 's:.*/::' \
   -e 's:[.].*::' \
   -e 'y:abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:' \
   -e 's:[^ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_]:_:g' \
   -e 's:__*:_:g' \
   -e 's:\([^_]\)[^_]*_\(.*\):\1\2:' \
   -e 's:\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4\5:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4\5\6:' \
   -e 's:^\(..........\).*:\1:'
}

#
# curl_8char_object_name
#
# Same as curl_10char_object_name() description and details above, except
# that object name is limited to 8 charcters maximum.
#

curl_8char_object_name() {
  echo "${1}" | \
  sed -e 's:.*/::' \
   -e 's:[.].*::' \
   -e 'y:abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:' \
   -e 's:[^ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_]:_:g' \
   -e 's:__*:_:g' \
   -e 's:\([^_]\)[^_]*_\(.*\):\1\2:' \
   -e 's:\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4\5:' \
   -e 's:\([^_]\)\([^_]\)\([^_]\)\([^_]\)\([^_]\)[^_]*_\(.*\):\1\2\3\4\5\6:' \
   -e 's:^\(........\).*:\1:'
}

# end of objectname.inc
