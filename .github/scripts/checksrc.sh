#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

{
  git ls-files '*.[ch]'
  while [ -n "${1:-}" ]; do
    find "$1" -name '*.[ch]' | grep -v -F '/CMakeFiles/'
    shift
  done
} | sed -E 's|/[^/]+$||g' | sort -u | while read -r dir; do
  ./scripts/checksrc.pl "${dir}"/*.[ch]
done
