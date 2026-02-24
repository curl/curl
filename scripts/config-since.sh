#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# List new configuration settings added since the tag passed as argument, e.g.:
#
# $ ./config-since.sh curl-8_16_0

set -eu

cd "$(dirname "$0")"/..

prevtag="${1:-curl-8_18_0}"

fn='lib/curl_config-cmake.h.in'
fo="_config-at-${prevtag}"

if ! git show "${prevtag}:${fn}" > "${fo}" 2>/dev/null; then
  # for compatibility with 8.17.0 and earlier
  if ! git show "${prevtag}:lib/curl_config.h.cmake" > "${fo}"; then
    rm -f "${fo:?}"
    exit 1
  fi
fi

fot="$(mktemp)"
fnt="$(mktemp)"

grep -E '(cmakedefine|{SIZEOF)' "${fo}" | sed -E -e 's/cmake//g' -e 's/ +1//g' | sort > "${fot}"
grep -E '(cmakedefine|{SIZEOF)' "${fn}" | sed -E -e 's/cmake//g' -e 's/ +1//g' | sort > "${fnt}"

echo "New settings at current Git commit since ${prevtag}:"
diff -u "${fot}" "${fnt}" | tail -n +3 | grep '^+' || true
echo '---'

rm -rf "${fot:?}" "${fnt:?}" "${fo:?}"
