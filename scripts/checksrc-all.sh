#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

{
  git ls-files '*.[ch]'
  [ -n "${1:-}" ] && find "$@" -name '*.[ch]' | grep -v -F '/CMakeFiles/'
} | sed -E 's|/[^/]+$||' | sort -u | while read -r dir; do
  ./scripts/checksrc.pl "${dir}"/*.[ch]
done
