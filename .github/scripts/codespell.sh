#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

# shellcheck disable=SC2046
codespell \
  --skip '*/spellcheck.words' \
  --skip '*/typos.toml' \
  --skip '*/THANKS' \
  --skip '*/mk-ca-bundle.pl' \
  --skip '*/wcurl' \
  --skip '*/tool_hugehelp.c' \
  --skip 'packages/*' \
  --skip '*/test*' \
  --ignore-words '.github/scripts/codespell-ignore.txt' \
  $(git ls-files)
