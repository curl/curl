#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

for dir in $(git ls-files '*.[ch]' | sed -E 's|/[^/]+$||g' | sort -u); do
  ./scripts/checksrc.pl "${dir}"/*.[ch]
done
