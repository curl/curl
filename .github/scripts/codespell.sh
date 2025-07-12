#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "${0}")"/../..

# shellcheck disable=SC2046
codespell \
  --skip '.github/scripts/spellcheck.words' \
  --skip '.github/scripts/typos.toml' \
  --skip 'docs/THANKS' \
  --skip 'packages/*' \
  --skip 'scripts/wcurl' \
  --skip 'winbuild/*' \
  --ignore-regex '.*spellchecker:disable-line' \
  --ignore-words '.github/scripts/codespell-ignore.txt' \
  $(git ls-files)
