#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

dirs="$({
    git ls-files '*.[ch]'
    [ -n "${1:-}" ] && find "$@" -name '*.[ch]' | grep -v -F '/CMakeFiles/'
  } | sed -E 's|/[^/]+$||' | sort -u)"

anyfailed=0

for dir in ${dirs}; do
  if ! ./scripts/checksrc.pl -v "${dir}"/*.[ch]; then
    anyfailed=1
  fi
done

exit "${anyfailed}"
