#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

git ls-files | typos \
  --isolated \
  --force-exclude \
  --config '.github/scripts/typos.toml' \
  --file-list -
