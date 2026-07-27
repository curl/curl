#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Verify if CMake options are documented

set -eu

cd -- "$(dirname "$0")"/..

{
  git grep -o -E 'option\([A-Z][A-Z0-9_]+' ':!tests/cmake' | grep -i cmake | sed -E -e 's/^.+://g' -e 's/option\(//g'
  git grep -h -o -E 'curl_dependency_option\([A-Z][A-Z0-9_]+' | sed -e 's/curl_dependency_option(//g'
  # shellcheck disable=SC2016
  git grep -h -o -E '^# - `[A-Z0-9_]+`: ' ':CMake/Find**' | grep -o -E '[A-Z0-9_]+' | grep -v -E '(_FOUND|_VERSION|NGTCP2_CRYPTO_BACKEND)'
} | sort -u | while read -r opt; do
  if ! grep -q -F -- "$opt" docs/INSTALL-CMAKE.md; then
    echo "CMake option missing from documentation: '$opt'"
  fi
done
