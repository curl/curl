#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Verify if CMake options are documented

set -eu

cd -- "$(dirname "$0")"/..

anyerr=0
while read -r opt; do
  if ! grep -q -F -- "- \`$opt\`: " docs/INSTALL-CMAKE.md; then
    echo "CMake option missing from documentation: '$opt'"
    anyerr=1
  fi
done < <(
  {
    git grep -o -E 'option\([A-Z][A-Z0-9_]+' ':!tests/cmake' |
      grep -i cmake |
      sed -E -e 's/^.+://g' -e 's/option\(//g'

    git grep -h -o -E 'curl_dependency_option\([A-Z][A-Z0-9_]+' |
      sed -e 's/curl_dependency_option(//g'

    git grep -h -o -E "^# - \`[A-Z0-9_]+\`: " ':CMake/Find**' |
      grep -o -E '[A-Z0-9_]+' |
      grep -v -E '(_FOUND|_VERSION|NGTCP2_CRYPTO_BACKEND)'
  } | sort -u
)

exit "${anyerr}"
