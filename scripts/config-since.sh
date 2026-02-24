#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# List new configuration settings added since the tag passed as argument, e.g.:
#
# $ ./config-since.sh curl-8_16_0 [--with-removals]

set -eu

cd "$(dirname "$0")"/..

prevtag="${1:-curl-8_18_0}"

shift
filter='+'
[ "${1:-}" = '--with-removals' ] && filter='[+-]'

fnew='lib/curl_config-cmake.h.in'
fold="_config-at-${prevtag}"

if ! git show "${prevtag}:${fnew}" > "${fold}" 2>/dev/null; then
  # for compatibility with 8.17.0 and earlier
  if ! git show "${prevtag}:lib/curl_config.h.cmake" > "${fold}"; then
    rm -f "${fold:?}"
    exit 1
  fi
fi

foldd="$(mktemp)"
fnewd="$(mktemp)"

grep -E '(cmakedefine|{SIZEOF)' "${fold}" | sed -E -e 's/cmake//g' -e 's/ +1//g' | sort > "${foldd}"
grep -E '(cmakedefine|{SIZEOF)' "${fnew}" | sed -E -e 's/cmake//g' -e 's/ +1//g' | sort > "${fnewd}"

echo "New settings at current Git commit since ${prevtag}:"
diff -u "${foldd}" "${fnewd}" | tail -n +3 | grep "^${filter}" || true
echo '---'

rm -rf "${foldd:?}" "${fnewd:?}" "${fold:?}"
