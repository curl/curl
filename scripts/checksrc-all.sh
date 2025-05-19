#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

anyfailed=0

for dir in $({
    git ls-files '*.[ch]' || true
    [ -n "${1:-}" ] && find "$@" -name '*.[ch]' | grep -v -F '/CMakeFiles/'
  } | sed -E 's|/[^/]+$||' | sort -u); do
  if ! ./scripts/checksrc.pl -v "${dir}"/*.[ch]; then
    anyfailed=1
  fi
done

exit "${anyfailed}"
