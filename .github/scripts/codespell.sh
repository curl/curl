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
  --skip 'docs/THANKS' \
  --skip 'scripts/mk-ca-bundle.pl' \
  --skip 'scripts/wcurl' \
  --skip 'src/tool_hugehelp.c' \
  --skip 'packages/*' \
  --skip 'winbuild/*' \
  --skip 'tests/data/test*' \
  --ignore-regex '.*spellchecker:disable-line' \
  --ignore-words '.github/scripts/codespell-ignore.txt' \
  $(git ls-files)
