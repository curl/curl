#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

anyfailed=0

while read -r dir; do
  if ! ./scripts/checksrc.pl "${dir}"/*.[ch]; then
    anyfailed=1
  fi
done <<< "$(
{
  git ls-files '*.[ch]'
  [ -n "${1:-}" ] && find "$@" -name '*.[ch]' | grep -v -F '/CMakeFiles/'
} | sed -E 's|/[^/]+$||' | sort -u)"

exit "${anyfailed}"
