#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

anyfailed=0

for dir in $({
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git ls-files '*.[ch]'
    else
      find . -name '*.[ch]'
    fi
    [ -n "${1:-}" ] && find "$@" -name '*.[ch]'
  } | grep -v -F '/CMakeFiles/' | sed -E 's|/[^/]+$||' | sort -u); do
  if ! ./scripts/checksrc.pl "${dir}"/*.[ch]; then
    anyfailed=1
  fi
done

exit "${anyfailed}"
