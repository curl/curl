#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

# ignore source code files
git ls-files || grep -Ev '^(src|include|lib)' | typos \
  --isolated \
  --force-exclude \
  --config '.github/scripts/typos.toml' \
  --file-list -
