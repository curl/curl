#!/usr/bin/env bash
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

detect_in_reused_sources=1

if [ "$detect_in_reused_sources" = '1' ]; then
  # Make symlinks for all re-used sources
  grep -E '^(lib|unit)[0-9]+_SOURCES = ' libtest/Makefile.inc unit/Makefile.inc \
    | sed -E 's@^([a-z]+)/[a-zA-Z.]+:(lib|unit)([0-9]+)_SOURCES = (lib|unit)([0-9]+).+@\1 \2 \3 \5@g' | \
  while read -r l; do
    if [[ "${l}" =~ ([a-z]+)\ ([a-z]+)\ ([0-9]+)\ ([0-9]+) ]]; then
      trg="${BASH_REMATCH[3]}"
      src="${BASH_REMATCH[4]}"
      if [ "${trg}" != "${src}" ]; then
        dir="${BASH_REMATCH[1]}"
        pfx="${BASH_REMATCH[2]}"
        ln -s "${pfx}${src}.c" "${dir}/${pfx}${trg}.c"
      fi
    fi
  done
fi

# Look for symbols possibly re-used in multiple sources.
#
# Falsely picks ups symbols in re-used sources, but guarded for a single use.
# Misses shadowed variables.
# shellcheck disable=SC2046
grep -E '^ *(static|struct) +' $(find libtest unit -maxdepth 1 -name 'lib*.c' -o -name 'unit*.c' -o -name 'mk-*.pl') \
  | grep -E '^(libtest|unit)/' \
  | grep -E '\.(c|pl):(static|struct)( +[a-zA-Z_* ]+)? +[a-zA-Z_][a-zA-Z0-9_]+ *' | sort -u \
  | grep -o -E '[a-zA-Z_][a-zA-Z0-9_]+ *[=;[({]' | tr -d '=;[({ ' \
  | grep -v -E '^(NULL$|sizeof$|CURLE_)' \
  | sort | uniq -c | sort -k 2 | grep -v -E '^ +1 ' \
  | awk '{print "    \"" $2 "\","}'

echo '---'

# Extract list of macros that may be re-used by multiple tests.
#
# Picks up false-positive when the macro is defined to the same value everywhere.
# shellcheck disable=SC2046
grep -E '^ *# *define +' $(find libtest unit -maxdepth 1 -name 'lib*.c' -o -name 'unit*.c' -o -name 'mk-*.pl') \
  | grep -E '^(libtest|unit)/' \
  | grep -o -E '.+\.(c|pl): *# *define +[A-Z_][A-Z0-9_]+' | sort -u \
  | grep -o -E '[A-Z_][A-Z0-9_]+' \
  | sort | uniq -c | sort -k 2 | grep -v -E '^ +1 ' \
  | awk '{print "    \"" $2 "\","}'

if [ "$detect_in_reused_sources" = '1' ]; then
  # Delete symlinks for all re-used sources
  find libtest unit -type l -delete
fi
